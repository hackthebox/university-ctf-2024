import base64
import random
import re
import string

def generate_key(seed, length=16):
    random.seed(seed)
    key = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
    return key

def polyalphabetic_decrypt(ciphertext, key):
    key_length = len(key)
    decrypted_text = []
    ciphertext = base64.b64decode(ciphertext).decode()
    for i, char in enumerate(ciphertext):
        key_char = key[i % key_length]
        decrypted_char = chr((ord(char) - ord(key_char)) % 256)
        decrypted_text.append(decrypted_char)
    return ''.join(decrypted_text)

def xor_cipher(text, key):
    return bytes([c ^ key for c in text])

def pwnnn(ct, part):
    
    xor_key = 42
    # Try key_seed values from 1 to 101
    for key_seed in range(1, 1001):
        try:
            key = generate_key(key_seed)
            decrypted_with_xor_part1 = xor_cipher(ct, xor_key)
            
            decrypted_text_part1 = polyalphabetic_decrypt(decrypted_with_xor_part1, key)
            
            decrypted_text = decrypted_text_part1
            if(part == 1):
                if decrypted_text.startswith('HTB{'):
                    return decrypted_text
            if(part == 2):
                pattern = r'^[a-zA-Z0-9_]+}$'
                match = re.search(pattern, decrypted_text)
                if match:
                    return decrypted_text
        except Exception as e:
            continue

    # Try xor_key values from 1 to 255
    for xor_key in range(1, 256):
        key_seed = 42
        try:
            key = generate_key(key_seed)
            decrypted_with_xor_part1 = xor_cipher(ct, xor_key)
            
            decrypted_text_part1 = polyalphabetic_decrypt(decrypted_with_xor_part1, key)
            
            decrypted_text = decrypted_text_part1
            if(part == 1):
                if decrypted_text.startswith('HTB{'):
                    return decrypted_text
            if(part == 2):
                pattern = r'^[a-zA-Z0-9_]+}$'
                match = re.search(pattern, decrypted_text)
                if match:
                    return decrypted_text
        except Exception as e:
            continue
    return None

def main():
    # Load the hex-encoded encrypted flag parts from output.txt
    with open('output.txt', 'r') as f:
        encrypted_flag_part1_hex = f.readline().strip()
        encrypted_flag_part2_hex = f.readline().strip()
    
    # Convert hex-encoded encrypted flag parts back to bytes
    encrypted_flag_part1 = bytes.fromhex(encrypted_flag_part1_hex)
    encrypted_flag_part2 = bytes.fromhex(encrypted_flag_part2_hex)
  
    # Attempt to brute force the key
    decrypted_flag = pwnnn(encrypted_flag_part1, 1)
    decrypted_flag_p2 = pwnnn(encrypted_flag_part2, 2)

    if decrypted_flag:
        print(f"{decrypted_flag + decrypted_flag_p2}")
    else:
        print("Failed to retrieve the flag.")

if __name__ == "__main__":
    main()