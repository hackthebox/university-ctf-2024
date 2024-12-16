![](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='5'>Clutch</font>

02<sup>th</sup> December 2024 / Document No. D24.102.232

Prepared By: `D-Cryp7`

Challenge Author: `D-Cryp7`

Difficulty: <font color='red'>Hard</font>




# Synopsis

- Break a novel Frame-based Quantum Key Distribution (QKD) protocol using simple cryptanalysis techniques related to the quantum state pairs reused in the frames computation. This design flaw, combined with the discarded frames in the reconciliation phase, allows recovery of the entire shared key and encryption of the desired command that outputs the flag.

# Description

- The last objective is clear: steal the legendary artifact called "The Starry Spurr". Traveling to The Frontier Cluster, our space cowboys face a novel secure transmission system based on the nature of quantum physics. The team intercepts the public information exchanged between members of The Frontier Board. We are running out of time, the entrance is waiting for our command.

## Skills Required

- Python source code analysis and scripting.
- Basic understanding of Qiskit library.
- Understanding of Quantum Key Distribution (QKD) protocols.

## Skills Learned

- Understanding of Frame-based Quantum Key Distribution (QKD) protocols.
- Pairs reuse attack on LL20 protocol.

# Enumeration

The challenge contains the following files:
- `__init__.py`: This is the basic empty file for managing imports.
- `helpers.py`: Lookup tables (LUTs) for the usable and auxiliary frames identification, including key derivation and error correction rules.
- `alice.py` Python class for the transmitter.
- `bob.py` Python class for the receiver.
- `server.py`: The main script that is executed, performing the QKD protocol. The server ouputs the flag if the player manages to recover the shared key and encrypt the command `OPEN THE GATE`.

## Analyzing the source code

The server implements a novel Frame-based Quantum Key Distribution (QKD) protocol described [here](https://www.mdpi.com/2073-8994/12/6/1053). We will call it "LL20", and the steps are briefly described below:

1. Alice generates $n$ non-orthogonal pairs of quantum states $ P_i \in \{(|0_X\rangle, |0_Z\rangle), (|0_X\rangle, |1_Z\rangle), (|1_X\rangle, |0_Z\rangle), (|1_X\rangle, |1_Z\rangle)\}$.

2. Alice sends each pair through the quantum channel.

3. Bob randomly measures each pair $P_i$ with the same basis, choosing between $Z$ and $X$.

4. Bob sends the double matching detection events through the classical channel. A double matching detection event occurs when both states collapse to the same bit.

5. Alice computes all possible frames. A frame is a 2x2 matrix that groups two non-orthogonal pairs of quantum state states, represented by its indices. Alice computes $\binom{|m|}{2}$ combinations, storing only the usable and auxiliary frames. The usable frames derive secret bits, while the auxiliary frames are used for the reconciliation (or error correction) process.

6. Alice sends the computed frames through the classic channel.

7. Bob computes the Sifting String (SS) of each frame, defined below. Each sifting bit corresponds to the XOR of each column. The list of SS is sent through the classical channel.
$$
 SS = \text{1st sifting bit } || \text{ } \text{2nd sifting bit } , 
            \text{1st bit obtained } || \text{ } \text{2nd bit obtained } .
$$

8. Alice detects and corrects the quantum channel errors as follows:
    1. For an invalid SS, the frames are considered ambiguous and they must be discarded from the shared key.
    2. For a valid $SS \in \{00,11; 11,11\}$, the error is detected and corrected using Tables 10 and 11 from the original paper.  For example, if a frame of type $f_2$ shares the first pair with an auxiliary frame $f_{10}$ with $SS = 01,10$, then the error is detected and corrected. The rest of the frames with valid SS are discarded.
    3. For a valid $SS \in \{00,11; 11,11\}$, if there are no auxiliary frames that satisfy the conditions of Tables 10 and 11, then the error passes undetected. In that case, the shared keys are not equal and we repeat the key distribution.
9. Alice sends the discarded frames (ambiguous and auxiliary ones) through the classical channel.
10. Alice computes the measurement results of each usable frame using Tables 4 and 5 from the original paper. Then, the shared key is derived using Table 13.
11. Bob computes the measurement results of each frame that is not discarded, using Table 5 from the original paper. Then, the shared key is derived using Table 13.

Generally speaking, the shared key is derived using the public SS of each frame and its Measurement Result (MR). Then, our objective is to recover the MR.


## Finding the vulnerability

Understanding the LL20 protocol, we note that by design frames share non-orthogonal pairs of quantum states, represented by its indices. Then, we can think that there's a security flaw involving the pairs reuse. Indeed, there's a vulnerability, combined with the discarded frames in the reconciliation process.

### Pairs reuse attack

Let's consider two frames $f_i$ and $f_j$ with SS defined as $S_i = 11,11$ and $S_j = 10,10$ such that they share a pair. A simple diagram is presented below, including the two possible frames for each SS. As a clarification, each frame is presented from Bob's perspective, where each row describes if the double matching detection event occurs on the $X$ (left) or $Z$ (right) basis. The basis that was not used is annotated as a $-$ symbol, equivalent to a zero bit for the sifting bit calculation.

$$
    \underset{S_i = 11,11}{
        \begin{pmatrix}
            \textcolor{red}{1_X} & \textcolor{red}{-} \\
            - & 1_Z
        \end{pmatrix} , 
        \begin{pmatrix}
            - & 1_Z \\
            \textcolor{red}{1_X} & \textcolor{red}{-}
        \end{pmatrix}
    }
    \text{ }
    -
    \text{ }
    \underset{S_j = 10,10}{
        \begin{pmatrix}
            \textcolor{red}{1_X} & \textcolor{red}{-} \\
            0_X & -
        \end{pmatrix} , 
        \begin{pmatrix}
            \textcolor{red}{1_X} & \textcolor{red}{-} \\
            - & 0_Z
        \end{pmatrix} .
    }
$$

Then, let's define each row of $f_i$ and $f_j$ as $f_{i}^{1}, f_{i}^{2}$ and $f_{j}^{1}, f_{j}^{2}$ respectively. So, if $f_{i}^{1} = f_{j}^{1}$, we can conclude with 100\% certainty that $MR_i = 10$, using Table 4 from the original paper. Also, if $f_{i}^{2} = f_{j}^{1}$, we know that $MR_i = 11$. It is important to note that we can't recover the MR of frame $f_j$ since there's no distinguishability on the position of the pair reuse between the two possible frames. 

The same rule apply for the following pair of frames $f_i$ and $f_j$, bringing different MRs for frame $f_i$:

$$
    \underset{S_i = 11,11}{
        \begin{pmatrix}
            \textcolor{red}{1_X} & \textcolor{red}{-} \\
            - & 1_Z
        \end{pmatrix} , 
        \begin{pmatrix}
            - & 1_Z \\
            \textcolor{red}{1_X} & \textcolor{red}{-}
        \end{pmatrix}
    }
    \text{ }
    -
    \text{ }
    \underset{S_j = 10,01}{
        \begin{pmatrix}
            - & 0_Z \\
            \textcolor{red}{1_X} & \textcolor{red}{-}
        \end{pmatrix} , 
        \begin{pmatrix}
            0_X & - \\
            \textcolor{red}{1_X} & \textcolor{red}{-}
        \end{pmatrix}
    },
$$
$$
    \underset{S_i = 11,11}{
        \begin{pmatrix}
            1_X & - \\
            \textcolor{red}{-} & \textcolor{red}{1_Z}
        \end{pmatrix} , 
        \begin{pmatrix}
            \textcolor{red}{-} & \textcolor{red}{1_Z} \\
            1_X & -
        \end{pmatrix}
    }
    \text{ }
    -
    \text{ }
    \underset{S_j = 01,10}{
        \begin{pmatrix}
            \textcolor{red}{-} & \textcolor{red}{1_Z} \\
            - & 0_Z
        \end{pmatrix} , 
        \begin{pmatrix}
            \textcolor{red}{-} & \textcolor{red}{1_Z} \\
            0_X & -
        \end{pmatrix}
    },
$$
$$
    \underset{S_i = 11,11}{
        \begin{pmatrix}
            1_X & - \\
            \textcolor{red}{-} & \textcolor{red}{1_Z}
        \end{pmatrix} , 
        \begin{pmatrix}
            \textcolor{red}{-} & \textcolor{red}{1_Z} \\
            1_X & -
        \end{pmatrix}
    }
    \text{ }
    -
    \text{ }
    \underset{S_j = 01,01}{
        \begin{pmatrix}
            0_X & - \\
            \textcolor{red}{-} & \textcolor{red}{1_Z}
        \end{pmatrix} , 
        \begin{pmatrix}
            - & 0_Z \\
            \textcolor{red}{-} & \textcolor{red}{1_Z}
        \end{pmatrix}
    },
$$
$$
    \underset{S_i = 00,11}{
        \begin{pmatrix}
            \textcolor{red}{1_X} & \textcolor{red}{-} \\
            \textcolor{red}{1_X} & \textcolor{red}{-}
        \end{pmatrix} , 
        \begin{pmatrix}
            - & 1_Z \\
            - & 1_Z
        \end{pmatrix}
    }
    \text{ }
    -
    \text{ }
    \underset{S_j = 10,10}{
        \begin{pmatrix}
            \textcolor{red}{1_X} & \textcolor{red}{-} \\
            0_X & -
        \end{pmatrix} , 
        \begin{pmatrix}
            \textcolor{red}{1_X} & \textcolor{red}{-} \\
            - & 0_Z
        \end{pmatrix}
    },
$$
$$
    \underset{S_i = 00,11}{
        \begin{pmatrix}
            \textcolor{red}{1_X} & \textcolor{red}{-} \\
            \textcolor{red}{1_X} & \textcolor{red}{-}
        \end{pmatrix} , 
        \begin{pmatrix}
            - & 1_Z \\
            - & 1_Z
        \end{pmatrix}
    }
    \text{ }
    -
    \text{ }
    \underset{S_j = 10,01}{
        \begin{pmatrix}
            - & 0_Z \\
            \textcolor{red}{1_X} & \textcolor{red}{-}
        \end{pmatrix} , 
        \begin{pmatrix}
            0_X & - \\
            \textcolor{red}{1_X} & \textcolor{red}{-}
        \end{pmatrix}
    },
$$
$$
    \underset{S_i = 00,11}{
        \begin{pmatrix}
            1_X & - \\
            1_X & -
        \end{pmatrix} , 
        \begin{pmatrix}
            \textcolor{red}{-} & \textcolor{red}{1_Z} \\
            \textcolor{red}{-} & \textcolor{red}{1_Z}
        \end{pmatrix}
    }
    \text{ }
    -
    \text{ }
    \underset{S_j = 01,10}{
        \begin{pmatrix}
            \textcolor{red}{-} & \textcolor{red}{1_Z} \\
            - & 0_Z
        \end{pmatrix} , 
        \begin{pmatrix}
            \textcolor{red}{-} & \textcolor{red}{1_Z} \\
            0_X & -
        \end{pmatrix}
    },
$$
$$
    \underset{S_i = 00,11}{
        \begin{pmatrix}
            1_X & - \\
            1_X & -
        \end{pmatrix} , 
        \begin{pmatrix}
            \textcolor{red}{-} & \textcolor{red}{1_Z} \\
            \textcolor{red}{-} & \textcolor{red}{1_Z}
        \end{pmatrix}
    }
    \text{ }
    -
    \text{ }
    \underset{S_j = 01,01}{
        \begin{pmatrix}
            0_X & - \\
            \textcolor{red}{-} & \textcolor{red}{1_Z}
        \end{pmatrix} , 
        \begin{pmatrix}
            - & 0_Z \\
            \textcolor{red}{-} & \textcolor{red}{1_Z}
        \end{pmatrix}
    }.
$$

Finally, using a recovered frame $f_i$ with $S_i = 11,11$, we can recover the MR of a frame $f_j$ with $S_j = 00,11$, as described below.

$$
    \underset{S_i = 11,11}{
        \begin{pmatrix}
            \textcolor{red}{1_X} & \textcolor{red}{-} \\
            - & 1_Z
        \end{pmatrix}
    }
    \text{ }
    -
    \text{ }
    \underset{S_j = 00,11}{
        \begin{pmatrix}
            \textcolor{red}{1_X} & \textcolor{red}{-} \\
            \textcolor{red}{1_X} & \textcolor{red}{-}
        \end{pmatrix} , 
        \begin{pmatrix}
            - & 1_Z \\
            - & 1_Z
        \end{pmatrix} ,
    }
$$
$$
    \underset{S_i = 11,11}{ 
        \begin{pmatrix}
            \textcolor{red}{-} & \textcolor{red}{1_Z} \\
            1_X & -
        \end{pmatrix}
    }
    \text{ }
    -
    \text{ }
    \underset{S_j = 00,11}{
        \begin{pmatrix}
            1_X & - \\
            1_X & -
        \end{pmatrix} , 
        \begin{pmatrix}
            \textcolor{red}{-} & \textcolor{red}{1_Z} \\
            \textcolor{red}{-} & \textcolor{red}{1_Z}
        \end{pmatrix} .
    }
$$

With the pairs reuse attack, we can recover all frames $f_i$ with $S_i \in \{00,11; 11,11\}$. However, even though we can't recover the MR of each frame, the reconciliation process discards all frames $f_j$ with $S_j \notin \{00,11; 11,11\}$ from the shared key. Then, with the ambiguous frames known, we can recover the entire shared key.

# Solution

These are the steps involved in the challenge solution:

1. Initialize the server connection and retrieve the public information. We just have to worry about the list of frames, sifting strings, and ambiguous frames.
2. Execute the pairs reuse attack. With the diagrams above, we recover the MR of frames $f_i$ such that $S_i \in \{00,11; 11,11\}$. Then, we discard the ambiguous frames.
3. Encrypt the desired command with the recovered shared key. Then, the server returns the flag.

## Exploitation

The solution script is described below:
```python
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
        r = process(['python3', '../challenge/server.py'], level = 'error')

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

    flag = json.loads(r.recvline())

    print(flag)
```

### Getting the flag

Running the script, the server outputs the flag.

```console
└─$ python3 solver.py
[+] Opening connection to 0.0.0.0 on port 1337: Done
{'info': 'To all ships of The Frontier Board, use your secret key to get the coordinates of The Starry Spurr'}
{'info': 'Initializing QKD...'}
{'double_matchings': [1, 5, 6, 8, 9,...
Recovered shared key: 0101101101100...
{'info': " Welcome to The Frontier Board, the coordinates of The Starry Spurr are (51.08745653315925, 1.1786658883433339). Today's secret code: HTB{n0w_7h475_4_C1u7Ch!_d3f1n3731Y_Fr4m3_b453d_QKD_n33d5_70_M47ur3__C0ngr47u14710n5!}"}
[*] Closed connection to 0.0.0.0 port 1337
```

### Final words

First, i wanted to thank Hack The Box (HTB) for this amazing opportunity to be part of the challenge designers of University CTF 2024. I'm glad that the staff were interested in the incorporation of Quantum Key Distribution (QKD) challenges since Twisted Entanglement in the main platform. 

Whether we like it or not, Quantum Key Distribution (QKD) is a very important technology for academia and industry. However, QKD protocol proposals sometimes lack rigorous security proofs, as in LL20. Clutch was designed after finishing my thesis work, which consisted of performing cryptanalysis on Frame-based QKD protocols, LL20 was one of them.

Again, thanks to HTB for the enormous support, and i hope you guys liked this challenge!