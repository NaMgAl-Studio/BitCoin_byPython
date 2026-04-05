"""
Bitcoin Merkle Tree Implementation
===================================

This module implements Merkle tree computation for Bitcoin:
- ComputeMerkleRoot: Compute merkle root from list of hashes
- BlockMerkleRoot: Compute merkle root of transactions in a block
- BlockWitnessMerkleRoot: Compute witness merkle root
- TransactionMerklePath: Compute merkle path for a transaction

IMPORTANT WARNING:
If you're reading this because you're learning about crypto and/or designing
a new system that will use merkle trees, keep in mind that the following
merkle tree algorithm has a serious flaw related to duplicate txids, resulting
in a vulnerability (CVE-2012-2459).

The reason is that if the number of hashes in the list at a given level is odd,
the last one is duplicated before computing the next level (which is unusual
in Merkle trees). This results in certain sequences of transactions leading to
the same merkle root.

Corresponds to Bitcoin Core's src/consensus/merkle.cpp

Copyright (c) 2015-present The Bitcoin Core developers
Distributed under the MIT software license.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from ..crypto.sha256 import double_sha256
from ..primitives.block import Block, uint256
from ..primitives.transaction import Transaction


def ComputeMerkleRoot(hashes: List[uint256], mutated: Optional[bool] = None) -> uint256:
    """
    Compute the merkle root from a list of hashes.
    
    This implements the Bitcoin merkle tree algorithm, which has a specific
    behavior when the number of leaves is odd (duplicate the last one).
    
    Args:
        hashes: List of leaf hashes
        mutated: Optional output parameter set to True if a duplicated
                 subtree was found (CVE-2012-2459 mitigation)
                 
    Returns:
        The merkle root hash
        
    Note:
        The `mutated` flag detects the case where two identical hashes would be
        combined, which could allow for merkle root collisions.
    """
    if len(hashes) == 0:
        return uint256.null()
    
    # Make a copy of the list
    hash_list = [h.data for h in hashes]
    mutation = False
    
    while len(hash_list) > 1:
        # Check for mutation (duplicate consecutive hashes)
        if mutated is not None:
            for i in range(0, len(hash_list) - 1, 2):
                if hash_list[i] == hash_list[i + 1]:
                    mutation = True
        
        # If odd number of hashes, duplicate the last one
        if len(hash_list) & 1:
            hash_list.append(hash_list[-1])
        
        # Compute next level
        new_level = []
        for i in range(0, len(hash_list), 2):
            # Concatenate and hash
            combined = hash_list[i] + hash_list[i + 1]
            new_hash = double_sha256(combined)
            new_level.append(new_hash)
        
        hash_list = new_level
    
    if mutated is not None:
        mutated = mutation
    
    return uint256(hash_list[0])


def BlockMerkleRoot(block: Block, mutated: Optional[bool] = None) -> uint256:
    """
    Compute the merkle root of the transactions in a block.
    
    Args:
        block: The block containing transactions
        mutated: Optional output parameter for mutation detection
        
    Returns:
        The merkle root of all transaction hashes
    """
    leaves = [tx.txid for tx in block.vtx]
    return ComputeMerkleRoot(leaves, mutated)


def BlockWitnessMerkleRoot(block: Block) -> uint256:
    """
    Compute the merkle root of the witness transactions in a block.
    
    The witness hash of the coinbase transaction is 0 (null).
    
    Args:
        block: The block containing transactions
        
    Returns:
        The witness merkle root
    """
    leaves: List[uint256] = []
    
    # Coinbase witness hash is null (zero)
    leaves.append(uint256.null())
    
    # Add witness hashes of non-coinbase transactions
    for tx in block.vtx[1:]:
        leaves.append(tx.wtxid)
    
    return ComputeMerkleRoot(leaves)


def TransactionMerklePath(block: Block, position: int) -> List[uint256]:
    """
    Compute merkle path to the specified transaction.
    
    This implements a constant-space merkle path calculator, limited to 2^32 leaves.
    
    Args:
        block: The block containing the transaction
        position: Transaction index (0 = coinbase)
        
    Returns:
        Merkle path ordered from deepest level to root (sibling hashes)
    """
    leaves = [tx.txid for tx in block.vtx]
    return ComputeMerklePath(leaves, position)


def ComputeMerklePath(leaves: List[uint256], position: int) -> List[uint256]:
    """
    Compute merkle path for a position in the tree.
    
    Args:
        leaves: List of leaf hashes
        position: Position of the target leaf (0-indexed)
        
    Returns:
        List of sibling hashes forming the merkle path
    """
    path: List[uint256] = []
    
    if len(leaves) == 0:
        return path
    
    if position >= len(leaves):
        raise ValueError(f"Position {position} out of range (max {len(leaves) - 1})")
    
    # Convert to bytes for computation
    hash_list = [h.data for h in leaves]
    
    # count is the number of leaves processed so far
    count = 0
    # inner is an array of eagerly computed subtree hashes, indexed by tree level
    inner: List[bytes] = [b''] * 32
    
    # Which position in inner is a hash that depends on the matching leaf
    match_level = -1
    
    # Process all leaves into 'inner' values
    while count < len(hash_list):
        h = hash_list[count]
        match_h = count == position
        count += 1
        
        # For each of the lower bits in count that are 0, do 1 step
        level = 0
        while not (count & (1 << level)):
            if match_h:
                path.append(uint256(inner[level]))
            elif match_level == level:
                path.append(uint256(h))
                match_h = True
            
            # Combine with inner hash
            h = double_sha256(inner[level] + h)
            level += 1
        
        # Store the resulting hash at inner position level
        inner[level] = h
        if match_h:
            match_level = level
    
    # Do a final 'sweep' over the rightmost branch
    level = 0
    while not (count & (1 << level)):
        level += 1
    
    h = inner[level]
    match_h = match_level == level
    
    while count != (1 << level):
        # Combine with itself (Bitcoin's special rule for odd levels)
        if match_h:
            path.append(uint256(h))
        h = double_sha256(h + h)
        
        # Increment count
        count += (1 << level)
        level += 1
        
        # Propagate upwards
        while not (count & (1 << level)):
            if match_h:
                path.append(uint256(inner[level]))
            elif match_level == level:
                path.append(uint256(h))
                match_h = True
            h = double_sha256(inner[level] + h)
            level += 1
    
    return path


def VerifyMerklePath(leaf: uint256, path: List[uint256], position: int, root: uint256) -> bool:
    """
    Verify a merkle path.
    
    Args:
        leaf: The leaf hash to verify
        path: The merkle path (sibling hashes)
        position: Position of the leaf (determines left/right)
        root: Expected merkle root
        
    Returns:
        True if the path is valid, False otherwise
    """
    current = leaf.data
    
    for i, sibling in enumerate(path):
        # Determine if we're left or right child based on position bit
        if (position >> i) & 1:
            # We're the right child, sibling is left
            current = double_sha256(sibling.data + current)
        else:
            # We're the left child, sibling is right
            current = double_sha256(current + sibling.data)
    
    return current == root.data


def MerkleRootFromPath(leaf: uint256, path: List[uint256], position: int) -> uint256:
    """
    Compute merkle root from a leaf and its path.
    
    Args:
        leaf: The leaf hash
        path: The merkle path (sibling hashes)
        position: Position of the leaf
        
    Returns:
        The computed merkle root
    """
    current = leaf.data
    
    for i, sibling in enumerate(path):
        if (position >> i) & 1:
            current = double_sha256(sibling.data + current)
        else:
            current = double_sha256(current + sibling.data)
    
    return uint256(current)
