from pwn import *
import json

io = None
usr_1 = 'TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak'
usr_2 = 'TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak'

def get_flag():
    io.sendlineafter(b' :: ', json.dumps({'option': 'register'}).encode())
    io.sendlineafter(b' :: ', json.dumps({'username': usr_1, 'password': 'password'}).encode())
    io.sendlineafter(b' :: ', json.dumps({'option': 'register'}).encode())
    io.sendlineafter(b' :: ', json.dumps({'username': usr_2, 'password': 'password'}).encode())
    io.sendlineafter(b' :: ', json.dumps({'option': 'login'}).encode())
    io.sendlineafter(b' :: ', json.dumps({'username': usr_2, 'password': 'password'}).encode())
    return io.recvline().decode().strip().split(' :: ')[-1]

def pwn():
    flag = get_flag()
    print(flag)

if __name__ == '__main__':
    if args.REMOTE:
        host_port = sys.argv[1].split(':')
        HOST = host_port[0]
        PORT = host_port[1]
        io = remote(HOST, PORT, level='error')
    else:
        import os
        os.chdir('../challenge')
        io = process(['python3', 'server.py'], level='error')

    pwn()