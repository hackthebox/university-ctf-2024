#!/usr/bin/env python3

import re
e = ""
ne = ""
with open("./enc", "rb") as f:
    e = f.read().decode()

with open("./notenc", "rb") as f:
    ne = f.read().decode()

for l in ne.split('\n'):
    addr = re.search('[0-9a-fA-F]+:\t+[0-9a-fA-F]+', l)
    if addr:
        addr = addr.group(0)
        num = addr.split()[0][:-1]
        addr2 = re.search(f'{num}:\t+[0-9a-fA-F]+', e)
        if not addr2:
            addr2 = re.search(f'{int(num, 16)-2:8x}:\t+[0-9a-fA-F]+ [0-9a-fA-F]+', e).group(0)
            b1 = e.index(addr2.split()[2], e.index(addr2))
            s1 = e[b1:b1+50].split(' ')[0]
            s1 = s1.split()[0]
            b1e = e.index(s1, base) + len(s1)
        else:
            addr2 = addr2.group(0)
            base = e.index(addr2)
            s1 = e[base:base+50].split('\t')[1]
            b1 = e.index(s1, base)
            b1e = e.index(s1, base) + len(s1)

        if (addr.split()[1] != addr2.split()[1]):
            base = ne.index(addr)
            s2 = ne[base:base+50].split('\t')[1]
            b2 = ne.index(s2, base)
            b2e = ne.index(s2, base) + len(s2)

            _from = e[b1:b1e]
            _to = ne[b2:b2e]
            ms = ""
            i = 0
            while i < len(_to):
                if _to[i] == ' ':

                    i += 1
                    ms += ' '
                    addr2 = re.search(f'\n.*\t+[0-9a-fA-F]+', e[b1e:]).group(0)[11:]
                    _from = "     " + addr2.split()[0]
                    # __import__('ipdb').set_trace()
                    continue
                if i > len(_from) or _to[i:i+2] != _from[i:i+2]:
                    ms = ms+("*%s*" % _to[i:i+2])
                else:
                    ms += _from[i:i+2]
                i += 2

            ne = ne[:b2] + ms + ne[b2e:]

    if "501000" in l:
        break

with open("./notenc", "w") as f:
    f.write(ne)


