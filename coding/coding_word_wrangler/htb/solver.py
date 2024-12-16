import re

input_text = input() 

normalized_text = re.sub(r'[^\w\s]', '', input_text.lower())

words = normalized_text.split()

word_counts = {}
for word in words:
    if word in word_counts:
        word_counts[word] += 1
    else:
        word_counts[word] = 1

most_common_word = max(word_counts, key=word_counts.get)

print(most_common_word)
