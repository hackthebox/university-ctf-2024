from Crypto.Cipher import AES
import binascii



# Function to decrypt the Encryptedtext with the given key
def decrypt_aes_ecb(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_text = cipher.decrypt(ciphertext)
    return decrypted_text

# Read the encrypted file
with open('encrypted_message.aes', 'rb') as file:
    ciphertext = file.read()

wordlist = 'rockyou.txt'

# Brute-force to find the correct key
# with open(wordlist, 'r', encoding='latin-1') as f:
#     pass

f = ['avengedsevenfold\n']

for word in f:
    word = word.strip() 

    # Ensure the key is 16 bytes (AES key length for ECB)
    if len(word) == 16:
        key = word.encode('latin-1')
        
        try:
            # Decrypt the ciphertext with common words
            decrypted_text = decrypt_aes_ecb(ciphertext, key)
            common_words = [
                b"help",
                b"what",
                b"OMG",
                b"the",
                b"password",
                b"login",
                b"admin",
                b"then",
                b"that",
                b"what",
                b"this",
                b"there",
                b"when",
            ]
            # Check for a common word in the decrypted text
            if any(common_word in decrypted_text.lower() for common_word in common_words):
                print(f"Possible key found: {word}")
                print(f"Decrypted message: {decrypted_text}")
                break

        except Exception as e:
            # Ignore incorrect keys
            continue