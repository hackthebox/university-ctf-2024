from itertools import product
from hashlib import sha256
import json
import sys

from pwn import remote, args, process

from Crypto.Util.Padding import pad
from Crypto.Cipher import AES

from helpers import BOB_MR_DERIVATION, KEY_DERIVATION

def search(special_frames, frames, orientation):
    for s, f in product(special_frames, frames):
        super_frame = s + f
        index = [i for i in range(2) if super_frame.count(super_frame[i]) > 1] # 2 iterations instead of 4. A super frame always have 4 elements
        if index:
            if index[0]: yield s, orientation
            else: yield s, orientation[::-1]
            
def z_search(special_frames, z_frames):
    return search(special_frames, z_frames, ("X", "Z"))
            
def x_search(special_frames, x_frames):
    return search(special_frames, x_frames, ("Z", "X"))

def zero_search(recovered_frames, orientations, zero_frames):
    for s, f in product(recovered_frames, zero_frames):
        super_frame = s + f
        index = [i for i in range(2) if super_frame.count(super_frame[i]) > 1] # 2 iterations instead of 4. A super frame always have 4 elements
        if index:
            if index[0]:
                if orientations[s] == ("X", "Z"): yield f, ("Z", "Z")
                else: yield f, ("X", "X")
            else:
                if orientations[s] == ("X", "Z"): yield f, ("X", "X")
                else: yield f, ("Z", "Z")
    
            
def attack(frames, ambiguous_frames, _SS):
    assert len(frames) == len(_SS), "Each frame must have its associated sifting string"
    
    SS             = {}
    key_recovered  = []

    # fill dict
    for i in range(len(frames)):
        if _SS[i] not in SS.keys():
            SS[_SS[i]] = []
        SS[_SS[i]].append(frames[i])
        
    # recover MR of frames fj with SS = 11,11 such that they share a pair with frames fk with SS = 01,XX
    # we define the recovered frames as "Z frames" 
    recovered_z_frames_and_orientations = set(z_search(SS["11,11"], SS["01,01"] + SS["01,10"]))
    
    # recover MR of frames fj with SS = 11,11 such that they share a pair with frames fk with SS = 10,XX
    # we define the recovered frames as "X frames" 
    recovered_x_frames_and_orientations = set(x_search(SS["11,11"], SS["10,01"] + SS["10,10"]))

    # recover MR of frames fj with SS = 00,11 such that they share a pair with frames fk with SS = 01,XX
    # we define the recovered frames as "ZZ frames" 
    recovered_zz_frames_and_orientations = set(search(SS["00,11"], SS["01,01"] + SS["01,10"], ("Z", "Z")))

    # recover MR of frames fj with SS = 00,11 such that they share a pair with frames fk with SS = 10,XX
    # we define the recovered frames as "XX frames" 
    recovered_xx_frames_and_orientations = set(search(SS["00,11"], SS["10,01"] + SS["10,10"], ("X", "X")))
    
    # delete duplicates
    recovered_frames_and_orientations = set(list(recovered_z_frames_and_orientations)  + 
                                            list(recovered_x_frames_and_orientations)  + 
                                            list(recovered_xx_frames_and_orientations) +
                                            list(recovered_zz_frames_and_orientations))
     
    # dict separation
    recovered_frames = [ el[0] for el in recovered_frames_and_orientations ]
    orientations = { el[0]: el[1] for el in recovered_frames_and_orientations }
    
    # recover MR of frames fj with SS = 00,11 such that they share a pair with recovered frames
    # we define the recovered frames as "zero frames" 
    recovered_zero_frames_and_orientations = set(zero_search(recovered_frames, orientations, SS["00,11"]))

    # dict separation
    recovered_zero_frames = [ el[0] for el in recovered_zero_frames_and_orientations ]
    zero_frames_orientations = { el[0]: el[1] for el in recovered_zero_frames_and_orientations }
    
    for i in range(len(frames)):
        if frames[i] in ambiguous_frames:
            continue
        elif frames[i] in recovered_frames:
            measurement_result = BOB_MR_DERIVATION[orientations[frames[i]]]
        elif frames[i] in recovered_zero_frames:
            measurement_result = BOB_MR_DERIVATION[zero_frames_orientations[frames[i]]]
        else:
            key_recovered.append(" ")

        key_recovered.append(KEY_DERIVATION[_SS[i]][measurement_result])
    
    return ''.join(key_recovered)

def encrypt(s, plaintext):
    key = sha256(s.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(plaintext, 16))
    return encrypted

if __name__ == '__main__':
    if args.REMOTE:
        params = sys.argv[1].split(':')
        HOST = params[0]
        PORT = params[1]
        
        r = remote(HOST, PORT, level = 'error')
    else:
        r = process(['python3', '../challenge/server.py'], level = 'debug')

    while True:
        public = json.loads(r.recvline()[:-1])
        print(public)
        
        if "error" in public or "info" in public:
            continue
        else:
            break

    frames = public["frames"]
    ambiguous_frames = public["ambiguous_frames"]
    SS = public["sifting_strings"]

    frames = [ tuple(frame) for frame in frames ]
    ambiguous_frames = [ tuple(frame) for frame in ambiguous_frames ]

    key = attack(frames, ambiguous_frames, SS)
    print(f"Recovered shared key: {key}")

    encrypted_command = encrypt(key, b"OPEN THE GATE").hex()

    data = {
        "command": encrypted_command
    }

    r.sendlineafter(b"> ", json.dumps(data).encode())

    flag = json.loads(r.recvline())['info']

    print(flag)
