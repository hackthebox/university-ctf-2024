#!/usr/bin/env python3

from z3 import *
from collections import defaultdict
from ctypes import CDLL
from copy import deepcopy

# Z3 takes time to solve the Sudoku like puzzle but it gets there.

lc = CDLL("/usr/lib/libc.so.6")
lc.srand(1337)

# Board identification.
identification_cols = [
    [1, 1, 1, 1, 1, 4, 4, 9, 9, 9, 9, 9, 10, 10, 10, 10],
    [1, 1, 1, 1, 4, 4, 4, 9, 9, 9, 9, 6, 10, 10, 10, 10],
    [1, 1, 1, 1, 4, 4, 4, 9, 9, 9, 9, 6, 10, 10, 10, 10],
    [1, 1, 1, 2, 4, 4, 4, 9, 9, 5, 5, 6, 10, 10, 10, 10],
    [2, 2, 2, 2, 4, 4, 4, 9, 5, 5, 5, 6, 11, 11, 11, 11],
    [2, 2, 2, 2, 5, 4, 4, 5, 5, 5, 5, 6, 11, 11, 11, 11],
    [2, 2, 2, 2, 5, 5, 5, 5, 5, 5, 6, 6, 11, 11, 11, 11],
    [2, 2, 2, 6, 6, 6, 6, 6, 6, 6, 6, 6, 11, 11, 11, 11],
    [3, 3, 3, 3, 7, 7, 7, 7, 7, 7, 7, 7, 12, 12, 12, 12],
    [3, 3, 3, 3, 7, 7, 7, 7, 7, 7, 7, 7, 12, 12, 12, 12],
    [3, 3, 3, 3, 8, 8, 8, 8, 8, 8, 8, 8, 12, 12, 12, 12],
    [3, 3, 3, 3, 8, 8, 8, 8, 8, 8, 8, 8, 12, 12, 12, 12],
    [13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15, 16, 16, 16, 16],
    [13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15, 16, 16, 16, 16],
    [13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15, 16, 16, 16, 16],
    [13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15, 16, 16, 16, 16],
]

# Make sure that there are only 16 of each numeration
verif = defaultdict(lambda: 0)
for l in identification_cols:
    for n in l:
        verif[n] = verif[n] + 1

# Assert board positioning
assert(all([x in verif for x in range(1, 10)]))
assert(all([verif[x] == 16 for x in range(1, 10)]))

# Generate board.
cols = []
for i in range(16):
    cols.append([Int(f'c_{i}_l_{j}') for j in range(16)])


curs = [
    (0, 0, 7), 
    (0, 1, 8), 
    (0, 3, 15), 
    (1, 1, 11), 
    (2, 2, 13), 
    (3, 2, 6), 
    (4, 0, 3), 
    (4, 3, 8), 
    (6, 1, 10), 
    (6, 3, 12), 
    (9, 3, 10), 
    (11, 0, 1), 
    (11, 3, 6),
    (1, 4, 2), 
    (3, 6, 11), 
    (5, 6, 13), 
    (3, 9, 7),
    (4, 10, 15), 
    (5, 4, 0), 
    (5, 9, 5), 
    (6, 4, 6), 
    (6, 5, 2), 
    (6, 7, 9), 
    (1, 11, 5), 
    (5, 11, 7), 
    (6, 11, 1), 
    (7, 4, 11), 
    (7, 6, 2), 
    (7, 7, 15), 
    (7, 8, 13), 
    (7, 11, 12), 
    (8, 5, 1), 
    (8, 7, 4), 
    (8, 9, 3), 
    (9, 4, 9), 
    (9, 5, 0), 
    (9, 6, 7), 
    (9, 11, 14), 
    (10, 4, 8), 
    (10, 5, 5), 
    (10, 8, 7), 
    (10, 9, 11), 
    (11, 10, 9), 
    (11, 11, 4), 
    (0, 8, 0), 
    (0, 10, 3), 
    (0, 11, 2), 
    (1, 8, 4), 
    (2, 8, 8), 
    (4, 7, 7), 
    (0, 12, 11), 
    (0, 14, 12), 
    (1, 15, 0), 
    (2, 14, 9), 
    (3, 13, 2), 
    (4, 13, 4), 
    (5, 14, 3), 
    (5, 15, 14), 
    (7, 12, 1), 
    (7, 13, 9), 
    (8, 12, 8), 
    (8, 13, 0), 
    (8, 14, 14), 
    (9, 15, 12), 
    (11, 14, 13), 
    (11, 15, 11), 
    (12, 0, 5), 
    (14, 0, 4), 
    (14, 1, 9), 
    (15, 0, 8), 
    (15, 3, 7), 
    (12, 7, 3),
    (14, 4, 10),
    (14, 5, 12), 
    (14, 6, 6), 
    (15, 7, 0), 
    (12, 8, 2), 
    (12, 11, 0), 
    (13, 9, 1), 
    (14, 8, 11), 
    (15, 9, 14), 
    (15, 10, 4), 
    (12, 15, 7), 
    (13, 12, 6), 
    (13, 15, 15), 
    (14, 13, 5), 
    (14, 14, 0), 
    (15, 15, 1)
]

s = Solver()

cols2 = deepcopy(cols)
# Add known board state.
for n in curs:
    s.add(cols[n[0]][n[1]] == n[2])
    cols2[n[0]][n[1]] = n[2]

# Make sure them all are between 0 and 15 and they are different.
for i in range(16):
    for j in range(16):
        s.add(And(cols[i][j] >= 0, cols[i][j] <= 15))
    # Distinct columns.
    s.add(Distinct(cols[i]))

# Distinct lines.
for i in range(16):
    s.add(Distinct([cols[j][i] for j in range(16)]))

# Group clusters.
cluster = defaultdict(lambda: [])
for i in range(16):
    for j in range(16):
        cluster[identification_cols[i][j]].append(cols[i][j])

# Distinct in cluster.
for k in cluster:
    s.add(Distinct(cluster[k]))


# Check if solution exists
solution = [
    [7, 8, 10, 15, 4, 6, 14, 13, 0, 9, 3, 2, 11, 1, 12, 5],
    [14, 11, 9, 3, 2, 7, 8, 12, 4, 15, 1, 5, 10, 13, 6, 0],
    [2, 1, 13, 5, 12, 4, 0, 14, 8, 6, 11, 10, 7, 15, 9, 3],
    [0, 12, 6, 1, 3, 15, 11, 5, 10, 7, 13, 9, 14, 2, 8, 4],
    [3, 14, 11, 8, 1, 9, 5, 7, 12, 10, 15, 6, 0, 4, 2, 13],
    [15, 4, 2, 9, 0, 10, 13, 11, 1, 5, 8, 7, 12, 6, 3, 14],
    [13, 10, 5, 12, 6, 2, 3, 9, 14, 4, 0, 1, 15, 11, 7, 8],
    [6, 7, 0, 4, 11, 3, 2, 15, 13, 8, 14, 12, 1, 9, 5, 10],
    [9, 15, 7, 2, 13, 1, 10, 4, 5, 3, 12, 11, 8, 0, 14, 6],
    [11, 13, 4, 10, 9, 0, 7, 8, 15, 2, 6, 14, 5, 3, 1, 12],
    [12, 3, 14, 0, 8, 5, 1, 6, 7, 11, 2, 13, 4, 10, 15, 9],
    [1, 5, 8, 6, 15, 14, 12, 10, 3, 0, 9, 4, 2, 7, 13, 11],
    [5, 6, 1, 11, 14, 13, 15, 3, 2, 12, 10, 0, 9, 8, 4, 7],
    [10, 0, 12, 13, 7, 8, 4, 2, 9, 1, 5, 3, 6, 14, 11, 15],
    [4, 9, 15, 14, 10, 12, 6, 1, 11, 13, 7, 8, 3, 5, 0, 2],
    [8, 2, 3, 7, 5, 11, 9, 0, 6, 14, 4, 15, 13, 12, 10, 1],
]

lc.srand(1337)

stuffs = []

print("Checking")
if s.check() == sat:
    print("Done")
    
    m = s.model()
    solution = [[m.evaluate(cols[i][j]).as_long() for j in range(16)] for i in range(16)]

    for s in solution:
        print(s)
    flag = "HTB{"
    while len(stuffs) != 16:
        cur = (lc.rand() % 16) + 1
        if cur not in stuffs:
            stuffs.append(cur)
            for j in range(len(solution)):
                for i in range(len(solution)):
                    if identification_cols[i][j] == cur and type(cols2[i][j]) != int:
                        flag += ("%1X" % (solution[i][j]))
    flag += "}"
    print(flag)
else:
    print("No solution found")

# HTB{A7E1DF6853496CDA5738F93D8EC4BA2C31674F9AE805DA85F2C6B0CF6B275D8A4380EA963BC1EA4D8DCE5A9F61BFE1C6A302D5423A71F69A6021CF3BDEE75D8BF4921E201CA93549BCFD3574E820FD6E47B25019}

