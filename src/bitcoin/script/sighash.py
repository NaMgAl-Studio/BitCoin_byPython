# Copyright (c) 2009-2010 Satoshi Nakamoto
# Copyright (c) 2009-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Bitcoin Signature Hash Computation

This module implements signature hash computation for different signature versions:
- Legacy (BASE) signatures
- BIP143 (SegWit v0) signatures  
- BIP341 (Taproot) Schnorr signatures
"""

from typing import Optional, List, TYPE_CHECKING
from dataclasses import dataclass
import struct

from .script import Script, MAX_SCRIPT_ELEMENT_SIZE
from .sigversion import (
    SigVersion,
    SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY,
    SIGHASH_DEFAULT, SIGHASH_OUTPUT_MASK, SIGHASH_INPUT_MASK,
    TAPROOT_LEAF_MASK, TAPROOT_LEAF_TAPSCRIPT,
    TAPROOT_CONTROL_BASE_SIZE, TAPROOT_CONTROL_NODE_SIZE,
)
from .interpreter import ScriptExecutionData

if TYPE_CHECKING:
    from ..primitives.transaction import Transaction, TransactionInput, TransactionOutput


# ============================================================================
# Tagged Hashes (BIP340)
# ============================================================================

def tagged_hash(tag: str, data: bytes) -> bytes:
    """
    Compute a tagged hash as specified in BIP340.
    
    Tagged hashes are SHA256(SHA256(tag) || SHA256(tag) || data).
    This prevents collisions between different types of hashes.
    
    Args:
        tag: The tag string
        data: The data to hash
        
    Returns:
        32-byte hash
    """
    from ..crypto.sha256 import SHA256
    
    tag_hash = SHA256(tag.encode('utf-8'))
    return SHA256(tag_hash + tag_hash + data)


# Pre-computed tagged hash midstates for common tags
class TaggedHashers:
    """Pre-initialized tagged hash writers for common tags."""
    
    @staticmethod
    def TapSighash(data: bytes) -> bytes:
        """Tagged hash for Taproot sighash."""
        return tagged_hash("TapSighash", data)
    
    @staticmethod
    def TapLeaf(data: bytes) -> bytes:
        """Tagged hash for Taproot leaf hash."""
        return tagged_hash("TapLeaf", data)
    
    @staticmethod
    def TapBranch(data: bytes) -> bytes:
        """Tagged hash for Taproot branch hash."""
        return tagged_hash("TapBranch", data)
    
    @staticmethod
    def TapTweak(data: bytes) -> bytes:
        """Tagged hash for Taproot tweak."""
        return tagged_hash("TapTweak", data)


# ============================================================================
# Legacy Signature Hash
# ============================================================================

def SignatureHashLegacy(
    script_code: Script,
    tx: 'Transaction',
    n_in: int,
    n_hash_type: int
) -> bytes:
    """
    Compute legacy signature hash (pre-SegWit).
    
    Args:
        script_code: The subscript (from last OP_CODESEPARATOR)
        tx: The transaction
        n_in: Input index
        n_hash_type: Hash type byte
        
    Returns:
        32-byte signature hash
    """
    from ..crypto.sha256 import Hash256
    
    # Create a mutable copy of the transaction
    # This is done by serializing and modifying
    
    # 1. Clear all scriptSigs
    # 2. Set current input's scriptSig to script_code
    # 3. Handle SIGHASH_SINGLE/NONE
    
    # Simplified implementation - full version needs transaction modification
    preimage = b''
    
    # Version
    preimage += tx.version.to_bytes(4, 'little')
    
    # Input count (varint)
    preimage += encode_varint(len(tx.inputs))
    
    # Inputs
    for i, tx_in in enumerate(tx.inputs):
        preimage += tx_in.prevout.hash
        preimage += tx_in.prevout.n.to_bytes(4, 'little')
        
        if i == n_in:
            # Use script_code for current input
            preimage += encode_varint(len(script_code))
            preimage += bytes(script_code)
        else:
            # Empty scriptSig for other inputs
            preimage += b'\x00'
        
        preimage += tx_in.sequence.to_bytes(4, 'little')
    
    # Output count (varint)
    base_type = n_hash_type & 0x1f
    
    if base_type == SIGHASH_NONE:
        # No outputs
        preimage += b'\x00'
    elif base_type == SIGHASH_SINGLE:
        if n_in >= len(tx.outputs):
            # Return special hash for SIGHASH_SINGLE bug
            return bytes([1] + [0] * 31)
        # Outputs up to and including n_in + 1
        preimage += encode_varint(n_in + 1)
        for i in range(n_in):
            # Empty outputs before n_in
            preimage += b'\x00' * 8  # value
            preimage += b'\x00'  # scriptPubKey length
        preimage += tx.outputs[n_in].serialize()
    else:
        # SIGHASH_ALL
        preimage += encode_varint(len(tx.outputs))
        for tx_out in tx.outputs:
            preimage += tx_out.serialize()
    
    # Locktime
    preimage += tx.lock_time.to_bytes(4, 'little')
    
    # Hash type
    preimage += n_hash_type.to_bytes(4, 'little')
    
    return Hash256(preimage)


# ============================================================================
# BIP143 Witness v0 Signature Hash
# ============================================================================

def SignatureHashWitnessV0(
    script_code: Script,
    tx: 'Transaction',
    n_in: int,
    n_hash_type: int,
    amount: int,
    spent_outputs: Optional[List['TransactionOutput']] = None,
    cache: Optional[dict] = None
) -> bytes:
    """
    Compute BIP143 witness v0 signature hash.
    
    Args:
        script_code: The script code (witness script or pubkey script)
        tx: The transaction
        n_in: Input index
        n_hash_type: Hash type byte
        amount: Amount being spent (satoshis)
        spent_outputs: List of spent outputs (optional, for caching)
        cache: Precomputed hash cache
        
    Returns:
        32-byte signature hash
    """
    from ..crypto.sha256 import Hash256, SHA256
    
    preimage = b''
    
    # 1. nVersion (4 bytes)
    preimage += tx.version.to_bytes(4, 'little')
    
    # 2. hashPrevouts (32 bytes)
    if not (n_hash_type & SIGHASH_ANYONECANPAY):
        if cache and 'hashPrevouts' in cache:
            preimage += cache['hashPrevouts']
        else:
            prevout_data = b''
            for tx_in in tx.inputs:
                prevout_data += tx_in.prevout.hash
                prevout_data += tx_in.prevout.n.to_bytes(4, 'little')
            hash_prevouts = Hash256(prevout_data)
            preimage += hash_prevouts
    else:
        preimage += b'\x00' * 32
    
    # 3. hashSequence (32 bytes)
    base_type = n_hash_type & 0x1f
    if not (n_hash_type & SIGHASH_ANYONECANPAY) and base_type not in (SIGHASH_SINGLE, SIGHASH_NONE):
        if cache and 'hashSequence' in cache:
            preimage += cache['hashSequence']
        else:
            seq_data = b''
            for tx_in in tx.inputs:
                seq_data += tx_in.sequence.to_bytes(4, 'little')
            hash_sequence = Hash256(seq_data)
            preimage += hash_sequence
    else:
        preimage += b'\x00' * 32
    
    # 4. outpoint (36 bytes)
    tx_in = tx.inputs[n_in]
    preimage += tx_in.prevout.hash
    preimage += tx_in.prevout.n.to_bytes(4, 'little')
    
    # 5. scriptCode (var bytes)
    preimage += encode_varint(len(script_code))
    preimage += bytes(script_code)
    
    # 6. value (8 bytes)
    preimage += amount.to_bytes(8, 'little')
    
    # 7. nSequence (4 bytes)
    preimage += tx_in.sequence.to_bytes(4, 'little')
    
    # 8. hashOutputs (32 bytes)
    if base_type == SIGHASH_SINGLE and n_in < len(tx.outputs):
        preimage += Hash256(tx.outputs[n_in].serialize())
    elif base_type not in (SIGHASH_SINGLE, SIGHASH_NONE):
        if cache and 'hashOutputs' in cache:
            preimage += cache['hashOutputs']
        else:
            output_data = b''
            for tx_out in tx.outputs:
                output_data += tx_out.serialize()
            hash_outputs = Hash256(output_data)
            preimage += hash_outputs
    else:
        preimage += b'\x00' * 32
    
    # 9. nLockTime (4 bytes)
    preimage += tx.lock_time.to_bytes(4, 'little')
    
    # 10. sighash type (4 bytes)
    preimage += n_hash_type.to_bytes(4, 'little')
    
    return Hash256(preimage)


# ============================================================================
# BIP341 Taproot Signature Hash
# ============================================================================

# Extension bits for Taproot sighash
TAPROOT_SIGHASH_EPOCH = 0x00

# Sighash type extension positions
TAPROOT_SIGHASH_OUTPUT_COMMITMENT = 0x02
TAPROOT_SIGHASH_KEYPATH_SPEND = 0x00
TAPROOT_SIGHASH_SCRIPTPATH_SPEND = 0x01


def SignatureHashSchnorr(
    tx: 'Transaction',
    n_in: int,
    hash_type: int,
    sigversion: SigVersion,
    execdata: ScriptExecutionData,
    spent_outputs: List['TransactionOutput'],
    is_keypath: bool = True
) -> bytes:
    """
    Compute BIP341 Schnorr signature hash.
    
    Args:
        tx: The transaction
        n_in: Input index
        hash_type: Hash type (SIGHASH_DEFAULT, ALL, NONE, SINGLE + ANYONECANPAY)
        sigversion: Signature version (TAPROOT or TAPSCRIPT)
        execdata: Script execution data
        spent_outputs: List of spent outputs
        is_keypath: True for key path, False for script path
        
    Returns:
        32-byte signature hash
    """
    # Build the sighash preimage
    preimage = b''
    
    # Epoch (1 byte, always 0)
    preimage += bytes([TAPROOT_SIGHASH_EPOCH])
    
    # Type (1 byte)
    spend_type = TAPROOT_SIGHASH_KEYPATH_SPEND if is_keypath else TAPROOT_SIGHASH_SCRIPTPATH_SPEND
    if execdata.annex_present:
        spend_type |= 0x02  # Extension bit for annex
    preimage += bytes([spend_type])
    
    # nVersion (4 bytes)
    preimage += tx.version.to_bytes(4, 'little')
    
    # nLockTime (4 bytes)
    preimage += tx.lock_time.to_bytes(4, 'little')
    
    # Build the rest based on hash type
    base_type = hash_type & SIGHASH_OUTPUT_MASK
    anyone_can_pay = hash_type & SIGHASH_ANYONECANPAY
    
    # sha_prevouts (32 bytes) - hash of all input outpoints
    if not anyone_can_pay:
        prevout_data = b''
        for tx_in in tx.inputs:
            prevout_data += tx_in.prevout.hash
            prevout_data += tx_in.prevout.n.to_bytes(4, 'little')
        preimage += tagged_hash("TapSighash/prevouts", prevout_data)
    
    # sha_amounts (32 bytes) - hash of all input amounts
    if not anyone_can_pay:
        amounts_data = b''
        for spent_out in spent_outputs:
            amounts_data += spent_out.value.to_bytes(8, 'little')
        preimage += tagged_hash("TapSighash/amounts", amounts_data)
    
    # sha_scriptpubkeys (32 bytes) - hash of all scriptPubKeys
    if not anyone_can_pay:
        scripts_data = b''
        for spent_out in spent_outputs:
            scripts_data += encode_varint(len(spent_out.script_pubkey))
            scripts_data += bytes(spent_out.script_pubkey)
        preimage += tagged_hash("TapSighash/scriptPubKeys", scripts_data)
    
    # sha_sequences (32 bytes) - hash of all sequences
    if not anyone_can_pay and base_type != SIGHASH_SINGLE and base_type != SIGHASH_NONE:
        sequences_data = b''
        for tx_in in tx.inputs:
            sequences_data += tx_in.sequence.to_bytes(4, 'little')
        preimage += tagged_hash("TapSighash/sequences", sequences_data)
    
    # sha_outputs (32 bytes) - hash of all outputs
    if base_type != SIGHASH_NONE:
        if base_type == SIGHASH_SINGLE and n_in < len(tx.outputs):
            output_hash = tagged_hash("TapSighash/outputs", tx.outputs[n_in].serialize())
        else:
            outputs_data = b''
            for tx_out in tx.outputs:
                outputs_data += tx_out.serialize()
            output_hash = tagged_hash("TapSighash/outputs", outputs_data)
        preimage += output_hash
    
    # Current input data
    if anyone_can_pay:
        # Single input data
        tx_in = tx.inputs[n_in]
        preimage += tx_in.prevout.hash
        preimage += tx_in.prevout.n.to_bytes(4, 'little')
        preimage += spent_outputs[n_in].value.to_bytes(8, 'little')
        preimage += encode_varint(len(spent_outputs[n_in].script_pubkey))
        preimage += bytes(spent_outputs[n_in].script_pubkey)
        preimage += tx_in.sequence.to_bytes(4, 'little')
    else:
        # Input index (4 bytes)
        preimage += n_in.to_bytes(4, 'little')
    
    # Annex hash (if present)
    if execdata.annex_present:
        preimage += execdata.annex_hash
    
    # For script path: tapleaf hash and code separator position
    if not is_keypath:
        preimage += execdata.tapleaf_hash
        preimage += execdata.codeseparator_pos.to_bytes(4, 'little')
    
    return TaggedHashers.TapSighash(preimage)


# ============================================================================
# Taproot Helper Functions
# ============================================================================

def ComputeTapleafHash(leaf_version: int, script: bytes) -> bytes:
    """
    Compute the tapleaf hash for a script.
    
    Args:
        leaf_version: The leaf version byte
        script: The script bytes
        
    Returns:
        32-byte tapleaf hash
    """
    data = bytes([leaf_version]) + encode_varint(len(script)) + script
    return TaggedHashers.TapLeaf(data)


def ComputeTapbranchHash(a: bytes, b: bytes) -> bytes:
    """
    Compute the tapbranch hash from two child hashes.
    
    The hashes are sorted lexicographically before combining.
    
    Args:
        a: First child hash (32 bytes)
        b: Second child hash (32 bytes)
        
    Returns:
        32-byte tapbranch hash
    """
    if a < b:
        return TaggedHashers.TapBranch(a + b)
    else:
        return TaggedHashers.TapBranch(b + a)


def ComputeTaprootMerkleRoot(control: bytes, tapleaf_hash: bytes) -> bytes:
    """
    Compute the taproot merkle root from control block and tapleaf hash.
    
    Args:
        control: The control block (33 + k*32 bytes)
        tapleaf_hash: The tapleaf hash (32 bytes)
        
    Returns:
        32-byte merkle root (or internal key if no path)
    """
    # Control block structure:
    # 1 byte: leaf version + parity
    # 32 bytes: internal key
    # k*32 bytes: path (k nodes)
    
    path_len = (len(control) - TAPROOT_CONTROL_BASE_SIZE) // TAPROOT_CONTROL_NODE_SIZE
    
    if path_len == 0:
        return tapleaf_hash
    
    # Walk up the tree
    current_hash = tapleaf_hash
    for i in range(path_len):
        node = control[TAPROOT_CONTROL_BASE_SIZE + i * TAPROOT_CONTROL_NODE_SIZE:
                       TAPROOT_CONTROL_BASE_SIZE + (i + 1) * TAPROOT_CONTROL_NODE_SIZE]
        current_hash = ComputeTapbranchHash(current_hash, node)
    
    return current_hash


# ============================================================================
# Utility Functions
# ============================================================================

def encode_varint(n: int) -> bytes:
    """Encode an integer as a Bitcoin varint."""
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return bytes([0xfd]) + struct.pack('<H', n)
    elif n <= 0xffffffff:
        return bytes([0xfe]) + struct.pack('<I', n)
    else:
        return bytes([0xff]) + struct.pack('<Q', n)


def decode_varint(data: bytes, offset: int = 0) -> tuple:
    """Decode a Bitcoin varint from data. Returns (value, new_offset)."""
    first = data[offset]
    if first < 0xfd:
        return first, offset + 1
    elif first == 0xfd:
        return struct.unpack('<H', data[offset+1:offset+3])[0], offset + 3
    elif first == 0xfe:
        return struct.unpack('<I', data[offset+1:offset+5])[0], offset + 5
    else:
        return struct.unpack('<Q', data[offset+1:offset+9])[0], offset + 9
