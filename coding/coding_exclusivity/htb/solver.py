n = input()

arr = n.split(' ')

seen = set()
unique = []
for i in arr:
    i = int(i)
    if i not in seen:
        unique.append(i)
        seen.add(i)

print(' '.join(map(str, unique)))
