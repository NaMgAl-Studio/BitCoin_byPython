# Copyright (c) 2009-2010 Satoshi Nakamoto
# Copyright (c) 2009-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Bitcoin Signature Version and Hash Types

This module defines signature versions and hash types used in Bitcoin
script verification, including:
- Legacy (BASE) signatures
- SegWit v0 (WITNESS_V0) signatures  
- Taproot (TAPROOT) signatures
- Tapscript (TAPSCRIPT) signatures
"""

from enum import IntEnum, IntFlag
from typing import Optional


class SigVersion(IntEnum):
    """
    Signature version enumeration.
    
    Different signature versions have different rules for signature hashing
    and verification.
    """
    
    # Base/legacy scripts (pre-SegWit) and BIP16 P2SH-wrapped redeemscripts
    BASE = 0
    
    # Witness v0 (P2WPKH and P2WSH) - BIP 141
    WITNESS_V0 = 1
    
    # Witness v1 with 32-byte program, not BIP16 P2SH-wrapped, key path spending - BIP 341
    TAPROOT = 2
    
    # Witness v1 with 32-byte program, not BIP16 P2SH-wrapped, script path spending - BIP 342
    TAPSCRIPT = 3


class SigHashType(IntFlag):
    """
    Signature hash type flags.
    
    The hash type affects which parts of the transaction are signed.
    The lower 4 bits (0-3) specify output hashing behavior.
    Bit 7 (0x80) specifies input hashing behavior (ANYONECANPAY).
    """
    
    # Sign all outputs
    SIGHASH_ALL = 0x01
    
    # Sign no outputs - anyone can choose where the funds go
    SIGHASH_NONE = 0x02
    
    # Sign the output at the same index as the input
    SIGHASH_SINGLE = 0x03
    
    # Sign only this input - other inputs can be modified
    SIGHASH_ANYONECANPAY = 0x80
    
    # Taproot only: implied when sighash byte is missing, equivalent to ALL
    SIGHASH_DEFAULT = 0x00
    
    # Masks for extracting hash type components
    SIGHASH_OUTPUT_MASK = 0x03   # Lower 2 bits for output type
    SIGHASH_INPUT_MASK = 0x80    # High bit for ANYONECANPAY


# Export hash type constants
SIGHASH_ALL = SigHashType.SIGHASH_ALL
SIGHASH_NONE = SigHashType.SIGHASH_NONE
SIGHASH_SINGLE = SigHashType.SIGHASH_SINGLE
SIGHASH_ANYONECANPAY = SigHashType.SIGHASH_ANYONECANPAY
SIGHASH_DEFAULT = SigHashType.SIGHASH_DEFAULT
SIGHASH_OUTPUT_MASK = SigHashType.SIGHASH_OUTPUT_MASK
SIGHASH_INPUT_MASK = SigHashType.SIGHASH_INPUT_MASK


def is_valid_sighash_type(hashtype: int, sigversion: SigVersion) -> bool:
    """
    Check if a hash type is valid for the given signature version.
    
    Args:
        hashtype: The hash type byte
        sigversion: The signature version
        
    Returns:
        True if the hash type is valid for this signature version
    """
    # Mask out ANYONECANPAY bit
    base_type = hashtype & ~SIGHASH_ANYONECANPAY
    
    if sigversion == SigVersion.BASE or sigversion == SigVersion.WITNESS_V0:
        # For legacy and witness v0, valid base types are ALL, NONE, SINGLE
        return base_type in (SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE)
    elif sigversion == SigVersion.TAPROOT or sigversion == SigVersion.TAPSCRIPT:
        # For taproot, valid base types are DEFAULT, ALL, NONE, SINGLE
        return base_type in (SIGHASH_DEFAULT, SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE)
    
    return False


# ============================================================================
# Witness and Taproot Constants
# ============================================================================

# Size constants for witness programs
WITNESS_V0_SCRIPTHASH_SIZE = 32  # P2WSH script hash is 32 bytes (SHA256)
WITNESS_V0_KEYHASH_SIZE = 20     # P2WPKH key hash is 20 bytes (HASH160)
WITNESS_V1_TAPROOT_SIZE = 32     # Taproot output key is 32 bytes

# Taproot constants
TAPROOT_LEAF_MASK = 0xfe         # Mask for leaf version (all bits except lowest)
TAPROOT_LEAF_TAPSCRIPT = 0xc0    # Tapscript leaf version

# Taproot control block constants
TAPROOT_CONTROL_BASE_SIZE = 33   # 1 byte leaf version + 32 byte internal key
TAPROOT_CONTROL_NODE_SIZE = 32   # Each additional node is 32 bytes
TAPROOT_CONTROL_MAX_NODE_COUNT = 128  # Maximum nodes in control block
TAPROOT_CONTROL_MAX_SIZE = TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT


def is_valid_taproot_leaf_version(version: int) -> bool:
    """
    Check if a leaf version is valid for taproot.
    
    Valid leaf versions have the lowest bit set (odd versions).
    The version byte also must not be 0x50 (ANNEX_TAG).
    
    Args:
        version: The leaf version byte
        
    Returns:
        True if the leaf version is valid
    """
    # Must be even version (lowest bit clear) and not 0x50
    return (version & 0x01) == 0 and version != 0x50


def get_taproot_leaf_version(control_byte: int) -> int:
    """
    Extract the leaf version from the first byte of a control block.
    
    Args:
        control_byte: The first byte of the control block
        
    Returns:
        The leaf version (masked with TAPROOT_LEAF_MASK)
    """
    return control_byte & TAPROOT_LEAF_MASK


def get_taproot_path_depth(control_size: int) -> int:
    """
    Calculate the depth of the taproot script path from control block size.
    
    Args:
        control_size: Size of the control block in bytes
        
    Returns:
        Number of nodes in the path, or -1 if size is invalid
    """
    if control_size < TAPROOT_CONTROL_BASE_SIZE:
        return -1
    
    extra_size = control_size - TAPROOT_CONTROL_BASE_SIZE
    if extra_size % TAPROOT_CONTROL_NODE_SIZE != 0:
        return -1
    
    depth = extra_size // TAPROOT_CONTROL_NODE_SIZE
    if depth > TAPROOT_CONTROL_MAX_NODE_COUNT:
        return -1
    
    return depth
