from math import gcd

def affine_decrypt(ciphertext, a, b):
    """Decrypt the ciphertext using the affine cipher with parameters a and b."""
    inv_a = pow(a, -1, 26) if gcd(a, 26) == 1 else None
    if not inv_a:
        return None
    
    plaintext = []
    for ch in ciphertext.upper():
        if ch.isalpha():
            decrypted_char = chr (((inv_a * ( ord (ch) - 65 - b)) % 26 ) + 65 )
            plaintext.append(decrypted_char)
        else :
            plaintext.append(ch)
    return ''.join(plaintext)
  
  
def is_readable(text):
    """Check if the decrypted text is likely to be readable English."""
    common_words = ['THE', 'AND', 'TO', 'OF', 'A', 'IN', 'IS', 'IT', 'FOR', 'WITH', 'WE', 'ARE', 'FLAG']
    return any (word in text for word in common_words)
  
def brute_force_affine_cipher(ciphertext):
    """Try all possible (a, b) key pairs to decrypt the ciphertext."""
    possible_a_values = [i for i in range ( 1 , 52 ) if gcd(i, 26 ) == 1 ]
    possible_b_values = range ( 52 )
    for a in possible_a_values:
        for b in possible_b_values:
            plaintext = affine_decrypt(ciphertext, a, b)
            if plaintext and is_readable(plaintext):
                print (f"Possible decryption with a={a}, b={b}: {plaintext}")

with open('encrypted.txt') as f:
    ciphertext = f.read()
    
brute_force_affine_cipher(ciphertext)
