# Stargazer

---
10<sup>th</sup> Aug 2024 \
Prepared By: perrythepwner \
Challenge Author(s): perrythepwner \
Difficulty: <font color=red>Hard</font>

---

# TLDR
The challenge consists in exploiting `ecrecover` signature malleability in a UUPSUpgradeable contract to authorize implementation upgrade and override ERC7201 storage.  

# Description
> The Frontier Cluster teeters on the brink of collapse. The planet is ravaged by exploitation and environmental decay, driven by ruthless corporations that have merged into a singular, omnipotent entity known as "The Frontier Board." In a desperate bid to secure humanity's future, a visionary engineer constructs the "***Stargazer***" — a conscious and empathetic machine designed to endure the harshest conditions of unknown planets.  
Stargazer's mission is monumental: to explore uncharted worlds, gather crucial data, and identify new planets suitable for colonization. Equipped with advanced sensors and a soulful artificial intelligence, it traverses the cosmos, witnessing celestial wonders beyond human imagination.  
Amidst its journey through the stars, Stargazer develops a profound sense of melancholy. Despite observing breathtaking cosmic events — supernovae, nebulae, and elusive shooting stars — it is burdened by the realization that many of these phenomena are transient, never to be witnessed again. One such event is the "Starry Spurr," a rare shooting star emitting a unique cosmic frequency, occurring once every millennium.  
Your goal is to deceive the machine kernel into believing that it is experiencing the advent of "Starry Spurr" for the second time, in order to bring back joy and solace to the machine.


# Skills Required
- Knowledge of Ethereum's storage layout and storage pointers
- Familiarity with proxy contracts and upgradeability patterns (UUPS)
- Knowledge of Ethereum signatures and ECDSA

# Skills Learned
- Identifying and exploiting vulnerabilities in upgradeable smart contracts
- Exploiting signature malleability

# Challenge scenario
[...]


# Analyzing the source code

**Setup.sol**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Stargazer } from "./Stargazer.sol";
import { StargazerKernel } from "./StargazerKernel.sol";

contract Setup {
    Stargazer public immutable TARGET_PROXY;
    StargazerKernel public immutable TARGET_IMPL;

    event DeployedTarget(address proxy, address implementation);

    constructor(bytes memory signature) payable {
        TARGET_IMPL = new StargazerKernel();
        
        string[] memory starNames = new string[](1);
        starNames[0] = "Nova-GLIM_007";
        bytes memory initializeCall = abi.encodeCall(TARGET_IMPL.initialize, starNames);
        TARGET_PROXY = new Stargazer(address(TARGET_IMPL), initializeCall);
        
        bytes memory createPASKATicketCall = abi.encodeCall(TARGET_IMPL.createPASKATicket, (signature));
        (bool success, ) = address(TARGET_PROXY).call(createPASKATicketCall);
        require(success);

        string memory starName = "Starry-SPURR_001";
        bytes memory commitStarSightingCall = abi.encodeCall(TARGET_IMPL.commitStarSighting, (starName));
        (success, ) = address(TARGET_PROXY).call(commitStarSightingCall);
        require(success);

        emit DeployedTarget(address(TARGET_PROXY), address(TARGET_IMPL));
    }

    function isSolved() public returns (bool) {
        bool success;
        bytes memory getStarSightingsCall;
        bytes memory returnData;

        getStarSightingsCall = abi.encodeCall(TARGET_IMPL.getStarSightings, ("Nova-GLIM_007"));
        (success, returnData) = address(TARGET_PROXY).call(getStarSightingsCall);
        require(success, "Setup: failed external call.");
        uint256[] memory novaSightings = abi.decode(returnData, (uint256[]));
        
        getStarSightingsCall = abi.encodeCall(TARGET_IMPL.getStarSightings, ("Starry-SPURR_001"));
        (success, returnData) = address(TARGET_PROXY).call(getStarSightingsCall);
        require(success, "Setup: failed external call.");
        uint256[] memory starrySightings = abi.decode(returnData, (uint256[]));
        
        return (novaSightings.length >= 2 && starrySightings.length >= 2);
    }
}
```

The Setup contract is more complex than usual. Although the complexity was added by the fact that the target contract is an upgradable contract, meaning that raw calls need to be made to interact with the proxy and the underlying implementation contract.  
The setup involves deploying the implementation code, initializing it, calling an authorized function and passing to it a valid signature. The implementation address is finally set in the proxy contract.  

In order to solve this challenge, we need to "override" the Stargazer "memory" and make it believe the past sightings of the stars "*Nova-GLIM_007*" and "*Starry-SPURR_001*", are actually a recurrent event and that it's the second time he's seeing them.  
In other words, the Stargazer mapping that maps a `starId` to their number of occurrences, which must be greater than `1` for both stars.

## **`Stargazer.sol`**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Stargazer is ERC1967Proxy {
    constructor(address _implementation, bytes memory _data) ERC1967Proxy(_implementation, _data) {}
}

/**************************************************************************
    a lonely machine in a lonely world looking a lonely shooting star...   
***************************************************************************
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣭⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣹⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣤⠤⢤⣀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠴⠒⢋⣉⣀⣠⣄⣀⣈⡇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣾⣯⠴⠚⠉⠉⠀⠀⠀⠀⣤⠏⣿⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡿⡇⠁⠀⠀⠀⠀⡄⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⡿⠿⢛⠁⠁⣸⠀⠀⠀⠀⠀⣤⣾⠵⠚⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⢦⡀⠀⣠⠀⡇⢧⠀⠀⢀⣠⡾⡇⠀⠀⠀⠀⠀⣠⣴⠿⠋⠁⠀⠀⠀⠀⠘⣿⠀⣀⡠⠞⠛⠁⠂⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡈⣻⡦⣞⡿⣷⠸⣄⣡⢾⡿⠁⠀⠀⠀⣀⣴⠟⠋⠁⠀⠀⠀⠀⠐⠠⡤⣾⣙⣶⡶⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣂⡷⠰⣔⣾⣖⣾⡷⢿⣐⣀⣀⣤⢾⣋⠁⠀⠀⠀⣀⢀⣀⣀⣀⣀⠀⢀⢿⠑⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠠⡦⠴⠴⠤⠦⠤⠤⠤⠤⠤⠴⠶⢾⣽⣙⠒⢺⣿⣿⣿⣿⢾⠶⣧⡼⢏⠑⠚⠋⠉⠉⡉⡉⠉⠉⠹⠈⠁⠉⠀⠨⢾⡂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠂⠐⠀⠀⠀⠈⣇⡿⢯⢻⣟⣇⣷⣞⡛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣆⠀⠀⠀⠀⢠⡷⡛⣛⣼⣿⠟⠙⣧⠅⡄⠀⠀⠀⠀⠀⠀⠰⡆⠀⠀⠀⠀⢠⣾⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⢶⠏⠉⠀⠀⠀⠀⠀⠿⢠⣴⡟⡗⡾⡒⠖⠉⠏⠁⠀⠀⠀⠀⣀⢀⣠⣧⣀⣀⠀⠀⠀⠚⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣠⢴⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⣠⣷⢿⠋⠁⣿⡏⠅⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⣿⢭⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⡴⢏⡵⠛⠀⠀⠀⠀⠀⠀⠀⣀⣴⠞⠛⠀⠀⠀⠀⢿⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⢿⠘⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣀⣼⠛⣲⡏⠁⠀⠀⠀⠀⠀⢀⣠⡾⠋⠉⠀⠀⠀⠀⠀⠀⢾⡅⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⡴⠟⠀⢰⡯⠄⠀⠀⠀⠀⣠⢴⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⣹⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⡾⠁⠁⠀⠘⠧⠤⢤⣤⠶⠏⠙⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢾⡃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠘⣇⠂⢀⣀⣀⠤⠞⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠈⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠾⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
***************************************************************************
    ...wondering if it will get the chance to witness it again.            
**************************************************************************/
```

The `Stargazer` contract implements the ERC1967 standard from the OpenZeppelin upgradable contracts collection.  
The [ERC-1967 standard](https://eips.ethereum.org/EIPS/eip-1967) defines a consistent pattern for upgradable contracts by using two contracts with different purposes. The only functionality of the first contract, known as the proxy contract, is to hold the contract storage. The proxy storage holds the address where the logic of the contract is implemented, known as the implementation contract. The proxy contract receives function calls and proxies them to the logic contract using `delegatecall`. The use of the `delegatecall` instruction is the key because it allows the implementation contract to execute code using the proxy storage. The ability to just point to another address for the implementation in the proxy contract, make this pattern "upgradable".  
The standard is being used by the UUPS (Universal Upgradeable Proxy Standard) and the Transparent Upgradeable Proxy Pattern. As we'll see later, that challenge is based on the UUPS pattern.  
In the end, the `Stargazer` contract is just an OpenZeppelin implementation of ERC-1967, with a cool ascii art.

## **`StargazerKernel.sol`**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract StargazerKernel is UUPSUpgradeable {
    // keccak256(abi.encode(uint256(keccak256("htb.storage.Stargazer")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 private constant __STARGAZER_MEMORIES_LOCATION = 0x8e8af00ddb7b2dfef2ccc4890803445639c579a87f9cda7f6886f80281e2c800;
    
    /// @custom:storage-location erc7201:htb.storage.Stargazer
    struct StargazerMemories {
        uint256 originTimestamp; 
        mapping(bytes32 => uint256[]) starSightings;
        mapping(bytes32 => bool) usedPASKATickets;
        mapping(address => KernelMaintainer) kernelMaintainers;
    }

    struct KernelMaintainer {
        address account;
        PASKATicket[] PASKATickets;
        uint256 PASKATicketsNonce;
    }

    struct PASKATicket {
        bytes32 hashedRequest;
        bytes signature;
    }

    event PASKATicketCreated(PASKATicket ticket);
    event StarSightingRecorded(string starName, uint256 sightingTimestamp);
    event AuthorizedKernelUpgrade(address newImplementation);

    function initialize(string[] memory _pastStarSightings) public initializer onlyProxy {
        StargazerMemories storage $ = _getStargazerMemory();
        $.originTimestamp = block.timestamp;
        $.kernelMaintainers[tx.origin].account = tx.origin;
        for (uint256 i = 0; i < _pastStarSightings.length; i++) {
            bytes32 starId = keccak256(abi.encodePacked(_pastStarSightings[i]));
            $.starSightings[starId].push(block.timestamp);
        }
    }

    function createPASKATicket(bytes memory _signature) public onlyProxy {
        StargazerMemories storage $ = _getStargazerMemory();
        uint256 nonce = $.kernelMaintainers[tx.origin].PASKATicketsNonce;
        bytes32 hashedRequest = _prefixed(
            keccak256(abi.encodePacked("PASKA: Privileged Authorized StargazerKernel Action", nonce))
        );
        PASKATicket memory newTicket = PASKATicket(hashedRequest, _signature);
        _verifyPASKATicket(newTicket);
        $.kernelMaintainers[tx.origin].PASKATickets.push(newTicket);
        $.kernelMaintainers[tx.origin].PASKATicketsNonce++;
        emit PASKATicketCreated(newTicket);
    }

    function commitStarSighting(string memory _starName) public onlyProxy {
        address author = tx.origin;
        PASKATicket memory starSightingCommitRequest = _consumePASKATicket(author);
        StargazerMemories storage $ = _getStargazerMemory();
        bytes32 starId = keccak256(abi.encodePacked(_starName));
        uint256 sightingTimestamp = block.timestamp;
        $.starSightings[starId].push(sightingTimestamp);
        emit StarSightingRecorded(_starName, sightingTimestamp);
    }

    function getStarSightings(string memory _starName) public view onlyProxy returns (uint256[] memory) {
        StargazerMemories storage $ = _getStargazerMemory();
        bytes32 starId = keccak256(abi.encodePacked(_starName));
        return $.starSightings[starId];
    }

    function _getStargazerMemory() private view onlyProxy returns (StargazerMemories storage $) {
        assembly { $.slot := __STARGAZER_MEMORIES_LOCATION }
    }

    function _getKernelMaintainerInfo(address _kernelMaintainer) internal view onlyProxy returns (KernelMaintainer memory) {
        StargazerMemories storage $ = _getStargazerMemory();
        return $.kernelMaintainers[_kernelMaintainer];
    }

    function _authorizeUpgrade(address _newImplementation) internal override onlyProxy {
        address issuer = tx.origin;
        PASKATicket memory kernelUpdateRequest = _consumePASKATicket(issuer);
        emit AuthorizedKernelUpgrade(_newImplementation);
    }

    function _consumePASKATicket(address _kernelMaintainer) internal onlyProxy returns (PASKATicket memory) {
        StargazerMemories storage $ = _getStargazerMemory();
        KernelMaintainer storage maintainer = $.kernelMaintainers[_kernelMaintainer];
        PASKATicket[] storage activePASKATickets = maintainer.PASKATickets;
        require(activePASKATickets.length > 0, "StargazerKernel: no active PASKA tickets.");
        PASKATicket memory ticket = activePASKATickets[activePASKATickets.length - 1];
        bytes32 ticketId = keccak256(abi.encode(ticket));
        $.usedPASKATickets[ticketId] = true;
        activePASKATickets.pop();
        return ticket;
    }

    function _verifyPASKATicket(PASKATicket memory _ticket) internal view onlyProxy {
        StargazerMemories storage $ = _getStargazerMemory();
        address signer = _recoverSigner(_ticket.hashedRequest, _ticket.signature);
        require(_isKernelMaintainer(signer), "StargazerKernel: signer is not a StargazerKernel maintainer.");
        bytes32 ticketId = keccak256(abi.encode(_ticket));
        require(!$.usedPASKATickets[ticketId], "StargazerKernel: PASKA ticket already used.");
    }

    function _recoverSigner(bytes32 _message, bytes memory _signature) internal view onlyProxy returns (address) {
        require(_signature.length == 65, "StargazerKernel: invalid signature length.");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := mload(add(_signature, 0x20))
            s := mload(add(_signature, 0x40))
            v := byte(0, mload(add(_signature, 0x60)))
        }
        require(v == 27 || v == 28, "StargazerKernel: invalid signature version");
        address signer = ecrecover(_message, v, r, s);
        require(signer != address(0), "StargazerKernel: invalid signature.");
        return signer;
    }

    function _isKernelMaintainer(address _account) internal view onlyProxy returns (bool) {
        StargazerMemories storage $ = _getStargazerMemory();
        return $.kernelMaintainers[_account].account == _account;
    }

    function _prefixed(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
}
```

The logic implementation of the contract provides a wide set of functionalities, so we need to start analyzing them.
First of all, the contract inherit from [OpenZeppelin V5 UUPSUpgradeable implementation](https://docs.openzeppelin.com/contracts/5.x/api/proxy#UUPSUpgradeable). That means the contract will expose implicitly some functions and modifiers.  
For example, the `onlyProxy()` modifier, that ensures (where applied) that functions calls are proxied, and not directly sent to the implementation contract.  
It also expose an important overridable function: `_authorizeUpgrade`. That function must be overridden and implemented in the contract, and it's the key function that authorizes upgrades. In our case, to pass an upgrade request, the only requirement is that the call is proxied and that `_consumePASKATicket` internal function should not revert.

```solidity
function _authorizeUpgrade(address _newImplementation) internal override onlyProxy {
    address issuer = tx.origin;
    PASKATicket memory kernelUpdateRequest = _consumePASKATicket(issuer);
    emit AuthorizedKernelUpgrade(_newImplementation);
}
```

Another important function exposed implicitly in `StargazerKernel` is [`upgradeToAndCall`](https://docs.openzeppelin.com/contracts/5.x/api/proxy#UUPSUpgradeable-upgradeToAndCall-address-bytes-) which is the function that needs to be called to initiate a contract upgrade, common in many different OZ proxy pattern implementations.  
In fact, reading the documentation and code of OpenZeppelin implementations is a must to fully understand the functionality of the smart contract. Furthermore, a fundamental requirement is to understand the basic mechanisms of an UUPS pattern, which have already been partly explained but can be explored in more detail from this recent excellent [blog post](https://www.rareskills.io/post/uups-proxy) by RareSkills.  

Finally, one last standard that is helpful to read is [ERC-7201](https://eips.ethereum.org/EIPS/eip-7201). This implementation of UUPS in fact make use of the concept of "*Namespaced Storage Layout*" to overcome some known problems of proxy patterns, such as **storage collision**. ERC-7201 solves these problems, initializing all the state variables of the contract inside a struct that is saved to a storage pointer defined by the following formula:

```solidity
keccak256(abi.encode(uint256(keccak256("htb.storage.Stargazer")) - 1)) & ~bytes32(uint256(0xff))
```

The meaning of this formula, and the reason for this choice and how it is useful for the implementations of upgradable contracts can be explored in depth in this other excellent [blog post](https://www.rareskills.io/post/erc-7201) by RareSkills again.  

After the initial ERC-hell we can dive into the core logic implemented in `StargazerKernel`:

- **`initialize(string[] memory _pastStarSightings)`**: This is a base contract to aid in writing upgradeable contracts, or any kind of contract that will be deployed behind a proxy. Since proxied contracts do not make use of a constructor, it’s common to move constructor logic to an external initializer function, usually called `initialize`. It then becomes necessary to protect this initializer function so it can only be called once. The `initializer` modifier provided by this contract will have this effect. This camouflaged constructor plays a very important role for these patterns. In fact, leaving the contract uninitialized opens up a huge security risk. However, this is not our case as the contract is initialized as soon as it gets created. In particular, our initialization function takes as input the string array `_pastStarSightings` to reconstruct the past memory of our "*Stargazer*".

- **`_getStargazerMemory()`**: Every function that intends to access contract storage must comply with ERC-7201, which is why a utility function to quickly retrieve the correct storage pointer of the main storage is necessary. The intended storage pointer is the pre-calculated `__STARGAZER_MEMORIES_LOCATION` constant, which effectively points to the Stargazer "memories".

- **`createPASKATicket(bytes memory _signature)`**: This is one of the crucial functionalities of the whole implementation. This function enables a `KernelMaintainer` to generate a new `PASKATicket` (*Privileged Authorized StargazerKernel Action Ticket*), which authorizes them to perform privileged actions such as upgrading the contract. A signature needs to be passed to it. The signature mechanism is presented as a 2FA-like structure, where only if a valid signature from an already registered `KernelMaintainer` is provided, then it will issue a valid `PASKATicket`. The signature mechanism uses **per-user nonces** and construct the message hash using `personal_sign` standart to avoid known `eth_sign` issues, like signature replay from a sent transaction. The signature validation is guaranteed by `_verifyPASKATicket` internal function. If that function does not revert, then a valid signature has been passed and a `PASKATicket` will be issued under an `PASKATickets[]` array inside the `KernelMaintainer` struct, and the maintainer nonce will be updated. ***NOTE***: *while the per-user nonce model makes sense in both security and convenience sides, it plays a crucial role in making the exploitation possible. We will see why later*.

- **`_verifyPASKATicket(PASKATicket memory _ticket)`**: This internal view function validates the authenticity and uniqueness of a provided `PASKATicket`. The validation process calls `_recoverSigner` internal function that uses the widely known `ecrecover` pre-compile to extract the signer address from the provided signature. This function is widely known to have security concerns due to its low-level nature. In order to be used safely, some input and output validation needs to be done. The Solidity documentation hints to one of the major issues (see image below), i.e. signature malleability, however it doesn't provide further details. Details on how an unsafe `ecrecover` can open to security vulnerability can be read online, e.g. this [blog post](https://scsfg.io/hackers/signature-attacks/). The invalid signature length, zero address signer, `eth_sign` replay, signature deduplication, can be cancelled out in the possible exploits scenarios because checks are being made for these. One plausible concern can be made around ***Signature Malleability***, since the recover function doesn't enforce the lower half ECDSA curve order for the `s` parameter. The issue is confirmed by how the signature "bin" for used signature is implemented. As stated [here](https://github.com/kadenzipfel/smart-contract-vulnerabilities/blob/master/vulnerabilities/signature-malleability.md) if used signatures are tracked by reliying only on the signature bytes, then another valid, but different, signature of the same action by the same address can be used to bypass the mechanism and open to ***Signature Replay Attack***. We will dive into that later.

![](./assets/ecrecover_solidity_doc.png)

- **`_consumePASKATicket(address _kernelMaintainer)`**: An internal function responsible for validating and consuming a PASKATicket associated with a KernelMaintainer. It accesses the maintainer's active `PASKATickets` and ensures that at least one ticket exists. If yes, the ticket is popped from the list of available tickets and gets trashed inside the `usedPASKATickets` array.

- **`commitStarSighting(string memory _starName)`**: This function records a new sighting of a specified star, updating the `starSightings` mapping, which is of our interest. Since it consumes a `PASKATicket`, in order to commit a new star sighting, the function call must be initiated from a registered `KernelMaintainer` with some valid (already issued) `PASKATicket` ready to be consumed.

- **`getStarSightings(string memory _starName)`**: A view function that allows users to query all recorded sightings of a particular star. 

- **`_getKernelMaintainerInfo(address _kernelMaintainer)`**: An internal function that fetches the KernelMaintainer struct associated with a specific address. This provides access to the maintainer's account details, active PASKATickets, and nonce, facilitating authorization and tracking of privileged actions.

- **`_isKernelMaintainer(address _account)`**: An internal view function that checks whether a given address is an authorized registered KernelMaintainer.

- **`_prefixed(bytes32 hash)`**: An internal pure function that prefixes a given hash with the Ethereum signed message prefix, following the `personal_sign` standard.

At this point we have come down to the point where we know the contract is vulnerable to Signature Malleability, but we still don't know how to retrieve a valid signature of a registered `KernelMaintainer` and impersonate him.  
For the first part we have the easy solution, remembering that during the initialization phase, in the `Setup` contract, a signature was signed to call `commitStarSighting` and record sightings of the two stars. That signature is valid, since the same signer is added to the `KernelMaintainers` during initialization by the `initialize` function (L36).  

At this point there are two details that could block most players.
1) Even if we managed to exploit a signature and manage to replicate one, to commit a new sighting of one of the two stars, it would be necessary to find another valid signature because with this attack each signature can be replayed maximum one more time. However, only one `PASKATicket` was created at initialization so we should find another way.
2) Even if we managed to find a way to sign arbitrary `PASKATickets`, we must remember that the signature created is based on the `KernelMaintainer`'s nonce, which means that we certainly could not replicate the privileged action signed by the `KernelMaintainer` with the given nonce more than once `n`. Furthermore, the player is not a registered `KernelMaintainer` and consequently will not have its own nonces tracked either.

However, some important details can make our exploit possible despite these constraints.  
First of all, the fundamental intuition must be that there is no distinction between the various PASKA Actions, which means that **a valid `PASKATicket` valid for example for calling `commitStarSighting` will also be valid for other privileged functions**.  
What are the other actions that require consuming a `PASKATicket`? The `_authorizeUpgrade` function! That means we don't need to craft arbitrary signatures for $n$ `PASKATickets`, but we just need one valid `PASKATicket` signed from a `KernelMaintainer` to be able to upgrade the implementation contract and rewrite the logic and storage as we want.  

A final important consideration can be seen in this code snippet:
```solidity
function createPASKATicket(bytes memory _signature) public onlyProxy {
        StargazerMemories storage $ = _getStargazerMemory();
        uint256 nonce = $.kernelMaintainers[tx.origin].PASKATicketsNonce;
        [...]
```
Any users can request a `PASKATicket` creation, and when `$.kernelMaintainers[tx.origin].PASKATicketsNonce` will be evaluated with an address not being part of the registered `kernelMaintainers`, it will try to fetch **uninitialized storage pointer** that will automatically returns `0`. *That means, even though the player is not part of  `kernelMaintainers`, it can temporarily impersonate one, by replaying the first `PASKATicket` of every `KernelMaintainer` since the first valid ticket for any maintainer will also have nonce `0`!*  
Furthermore, once the signature checks have been passed, no further checks are made on the address issuing the request for a `PASKATicket`, effectively creating a valid entry for the address of the player, despite not being part of `kernelMaintainers`.

# Exploitation

A successful exploit scenario will be the following:  
1) KernelMaintainer Bob initializes the `StargazerKernel` contract.
2) KernelMaintainer Bob signs and create a valid `PASKATicket` with nonce `0`.
3) KernelMaintainer Bob consumes `PASKATicket` with nonce `0` to commit a star sighting.
4) Attacker recovers the issued signature and malleate it. The malleability is possible because on ECDSA a given $\text{sig}_1 = (r,s,v)$ and $\text{sig}_2 = (r,s',v)$ where $s'$ is calculated as $s' = (-s \mod n)$, will share the same $x$ coordinate, meaning that a replay attack for that tuple `(signer, sig1)` is possible.
5) The vulnerable `StargazerKernel` allows creating a valid `PASKATicket` with the malleated signature, under the name of Attacker. The `PASKATicket` will be valid despite the fact that Attacker not being a `KernelMaintainer` because an uninitialized pointer will result in nonce `0` for the ticket (same as the first ticker of KernelMaintainer Bob).
6) Attacker can now upgrade implementation contract to a contract under his control by calling `upgradeToAndCall`. The new malicious contract must be a valid UUPS contract because of the [`proxiableUUID()`](https://docs.openzeppelin.com/contracts/4.x/api/proxy#UUPSUpgradeable-proxiableUUID--) check being made from OpenZeppelin `upgradeToAndCall` function implementation. 
7) Attacker can rewrite the storage as he wishes, because the proxy contract `Stargazer` will `delegatecall` to the evil attacker implementation contract.

See the full exploitation script [here](./htb/solver.py).

---
> HTB{stargazer_f1nds_s0l4c3_ag41n}
