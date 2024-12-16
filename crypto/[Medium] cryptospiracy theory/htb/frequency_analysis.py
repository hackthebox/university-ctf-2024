import matplotlib.pyplot as plt
from collections import Counter
import binascii

# Read ciphertext from file
with open('encrypted_message.aes', 'rb') as file:
    ciphertext = file.read()

# Split ciphertext into 16-byte blocks
block_size = 16
blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]

# Count the frequency of each block
block_counts = Counter(blocks)

# Prepare data for plotting
block_labels = list(range(len(blocks)))
block_frequencies = [block_counts[block] for block in blocks]

# Plot the block frequency analysis
plt.bar(block_labels, block_frequencies)
plt.xlabel('Block Numbers')
plt.ylabel('Frequency')
plt.title('Block Frequency Analysis in Encrypted text')
plt.show()

print("Block (hex) -> Frequency")
for block, count in block_counts.most_common():
    print(f"{binascii.hexlify(block)} -> {count}")