![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='5'>MulTLock</font>

​	9<sup>th</sup> August 2024 / Document No. D24.102.228

​	Prepared By: `rasti`

​	Challenge Author(s): `sl1de`

​	Difficulty: <font color='lightgreen'>Very Easy</font>

​	Classification: Official







# Synopsis

- In this challenge, the user must decrypt a flag that has been split into two parts, encrypted separately using a polyalphabetic cipher combined with an XOR operation. The encryption process uses keys generated dynamically based on a timestamp. The user must analyze the provided output.txt file, which contains the encrypted flag parts, and then brute-force the correct keys to reconstruct the original flag. The goal is to find and decrypt both parts of the flag to retrieve the full flag.

# Description

- The Frontier Board encrypts their secrets using a system tied to the ever-shifting cosmic cycles, woven with patterns that seem random to the untrained eye. To outwit their defenses, you'll need to decipher the hidden rhythm of time and unlock the truth buried in their encoded transmissions. Can you crack the code and unveil their schemes?



## Skills Required

- Python scripting
- Understanding of polyalphabetic ciphers
- Experience with XOR operations
- Brute-forcing keys based on timestamp logic
- Familiarity with base64 and hex encoding/decoding
- Regex



## Skills Learned

- Implementing and decrypting polyalphabetic ciphers
- Applying XOR operations for encryption and decryption
- Handling base64 encoding and decoding
- Brute-forcing encryption keys with timestamp-based logic



# Enumeration

## Analyzing the Source Code

When you unzip the challenge file, you will find the `source.py` script. This script is responsible for encrypting the flag and saving it to `output.txt`. Here’s a detailed breakdown of how the script operates:

### Key Functions and Workflow

**1. Key Generation**

The `generate_key` function creates a random alphanumeric key based on a given seed. This seed influences the randomness of the key generation process:

```python
def generate_key(seed, length=16):
    random.seed(seed)
    key = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
    return key
```

- **Functionality**: Uses the seed to initialize the random number generator, ensuring reproducibility.
- **Key Creation**: Generates a key consisting of alphanumeric characters with a default length of 16 characters.

**2. Polyalphabetic Encryption**

The `polyalphabetic_encrypt` function performs polyalphabetic encryption, which is a form of substitution cipher where the key shifts the characters of the plaintext:

```python
def polyalphabetic_encrypt(plaintext, key):
    key_length = len(key)
    ciphertext = []
    for i, char in enumerate(plaintext):
        key_char = key[i % key_length]
        encrypted_char = chr((ord(char) + ord(key_char)) % 256)
        ciphertext.append(encrypted_char)
    return base64.b64encode(''.join(ciphertext).encode()).decode()
```

- **Functionality**: Encrypts the plaintext by shifting each character's ASCII value based on the corresponding key character.
- **Base64 Encoding**: The result is Base64 encoded to ensure it can be safely stored and transmitted.

**3. XOR Cipher**

The `xor_cipher` function applies XOR encryption to the text:

```python
def xor_cipher(text, key):
    return bytes([ord(c) ^ key for c in text])
```

- **Functionality**: XORs each character's ASCII value with a given key, converting the result into bytes.
- **Purpose**: Adds an additional layer of encryption on top of the polyalphabetic cipher.

**4. Timestamp-Based Key Generation**

The `get_timestamp_based_keys` function determines the key seed and XOR key based on the current timestamp:

```python
def get_timestamp_based_keys():
    timestamp = int(time.time())
    if timestamp % 2 == 0:
        key_seed = random.randint(1, 100)
        xor_key = 42
    else:
        key_seed = 42
        xor_key = random.randint(1, 255)
    return key_seed, xor_key
```

- **Functionality**: Chooses different keys based on whether the timestamp is even or odd.
- **Even Timestamp**: Randomly selects a key seed from 1 to 100 and sets a fixed XOR key (42).
- **Odd Timestamp**: Uses a fixed key seed (42) and randomly selects an XOR key from 1 to 255.

**5. Main Function**

The `main` function is the core of the script, which performs the following steps:

```python
def main():

    # Split the flag
    flag_half1 = FLAG[:len(FLAG)//2]
    flag_half2 = FLAG[len(FLAG)//2:]

    encrypted_flags = []
    timestamps = []

    for _ in range(2):
        key_seed, xor_key = get_timestamp_based_keys()
        key = generate_key(key_seed)
        encrypted_half = polyalphabetic_encrypt(flag_half1 if len(encrypted_flags) == 0 else flag_half2, key)
        encrypted_half = xor_cipher(encrypted_half, xor_key)
        encrypted_flags.append(encrypted_half.hex())
        timestamps.append(int(time.time()))  # Save timestamp for each encryption
        time.sleep(1)

    # Save encrypted flags to output.txt
    with open('output.txt', 'w') as f:
        f.write(f"{encrypted_flags[0]}\n{encrypted_flags[1]}\n")

    print(f"Flag Part 1: {encrypted_flags[0]}")
    print(f"Flag Part 2: {encrypted_flags[1]}")


if __name__ == "__main__":
    main()
```

- **Flag Splitting**: The flag is divided into two equal halves for separate encryption.
- **Encryption Loop**: Each flag half is encrypted separately. The encryption uses dynamically generated keys based on the timestamp.
- **Saving Results**: Encrypted flag parts are saved to `output.txt`. The use of `time.sleep(1)` ensures that each encryption occurs at a slightly different timestamp.
- **Output**: The script prints the encrypted flag parts in hexadecimal format along with their timestamps.

### Summary

1. **Key Generation**: The `generate_key` function uses a timestamp-based seed to create a random key.
2. **Encryption**: The flag is encrypted in two parts using polyalphabetic encryption followed by XOR encryption.
3. **Dynamic Keys**: Different keys are used for each part based on the timestamp, which adds complexity to the decryption process.
4. **Output File**: Encrypted flag parts are saved to `output.txt`, where the challenge solver will need to use this information to decrypt and recover the flag.

This script provides a challenging encryption scheme due to its use of dynamically generated keys and multiple encryption layers.

# Solution

### Finding the Vulnerability

The challenge involves decrypting a flag that has been encrypted and saved in two parts, each with its own timestamp. The encryption process uses a combination of polyalphabetic encryption and XOR cipher, and dynamically generated keys based on the timestamp. Here’s a detailed breakdown of the vulnerability and the steps to solve it:

#### Identifying the Vulnerability

1. **Predictable Key Generation**

   The key generation relies on the timestamp to create seeds and XOR keys. While this method introduces variability, the underlying issue is that the keys can be brute-forced since:

   - **Key Seed Range**: For even timestamps, the key seed is randomly chosen from a known small range (1 to 100).
   - **XOR Key Range**: The XOR key is either a fixed value (42) or randomly chosen from a known range (1 to 255).

2. **Repeated Use of Fixed XOR Key**

   For even timestamps, the XOR key is always 42. This predictable key usage simplifies the decryption process as it allows us to focus on brute-forcing only the key seed.

3. **Timestamp-Based Key Variability**

   The challenge's timestamps introduce variability, but the approach remains feasible since:

   - **Timestamp Prediction**: The timestamps are close to each other (due to a 1-second delay), making them predictable and consistent for brute-forcing.

4. **Split Flag Parts**

   The flag is split into two parts, each encrypted separately. Both parts are encrypted using dynamically generated keys, which means:

   - **Encryption Matching**: If we can decrypt one part successfully, the same key logic applies to the other part.
   - **Flag Format**: The flag format (e.g., `HTB{}`) can be used to validate successful decryption, providing clues to correct key values.

#### **Brute-Forcing the Keys**

1. **Brute-Force Key Seed for Even Timestamps**

   For even timestamps:

   - **Range**: Try key seeds from 1 to 100.
   - **Decryption**: Decrypt the encrypted flag part with each key seed and the fixed XOR key (42). Check if the decrypted text contains the expected flag format (`HTB{`).

2. **Brute-Force XOR Key for Odd Timestamps**

   For odd timestamps:

   - **Range**: Try XOR key values from 1 to 255.
   - **Decryption**: Decrypt the encrypted flag part with each XOR key and a fixed key seed (42). Validate if the decrypted text contains `}` to complete the flag.

3. **Combining Results**

   After successful decryption:

   - **Part 1**: Should reveal the first half of the flag.
   - **Part 2**: Should reveal the remaining part of the flag.

   Combine both parts to obtain the full flag.

#### **Implementing the Solution**

Here’s a Python script to automate the brute-forcing process and recover the flag:

```python
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

def pwn(ct, part):
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
    decrypted_flag = pwn(encrypted_flag_part1, 1)
    decrypted_flag_p2 = pwn(encrypted_flag_part2, 2)

    if decrypted_flag:
        print(f"\nFlag: {decrypted_flag + decrypted_flag_p2}\n")
    else:
        print("Failed to retrieve the flag.")

if __name__ == "__main__":
    main()
```

# Summary

- **Vulnerability**: Predictable key generation based on timestamp and fixed XOR key for even timestamps.
- **Approach**: Brute-force possible all possible key values and attempt decryption whilst searching for string starting with 'HTB{' for flag part 1 and string ending with `^[a-zA-Z0-9_]+}$` for flag part two.
- **Solution**: Decrypt both flag parts using the derived keys and combine them to reveal the full flag.

This approach takes advantage of the predictable nature of the encryption scheme, allowing for a systematic brute-forcing of possible key values to recover the original flag.
