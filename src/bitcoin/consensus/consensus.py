"""
Bitcoin Consensus Constants
===========================

This module defines consensus-related constants from Bitcoin Core:
- Block size and weight limits
- Signature operation limits
- Coinbase maturity
- Witness scale factor
- Lock time flags

Corresponds to Bitcoin Core's src/consensus/consensus.h

Copyright (c) 2009-2010 Satoshi Nakamoto
Copyright (c) 2009-present The Bitcoin Core developers
Distributed under the MIT software license.
"""

from __future__ import annotations

# =============================================================================
# Block Size Limits
# =============================================================================

# The maximum allowed size for a serialized block, in bytes (only for buffer size limits)
MAX_BLOCK_SERIALIZED_SIZE: int = 4_000_000  # 4 MB

# The maximum allowed weight for a block, see BIP 141 (network rule)
MAX_BLOCK_WEIGHT: int = 4_000_000  # 4 million weight units

# The maximum allowed number of signature check operations in a block (network rule)
MAX_BLOCK_SIGOPS_COST: int = 80_000

# =============================================================================
# Coinbase Maturity
# =============================================================================

# Coinbase transaction outputs can only be spent after this number of new blocks (network rule)
COINBASE_MATURITY: int = 100

# =============================================================================
# Witness/SegWit Constants
# =============================================================================

# Witness scale factor (BIP 141)
WITNESS_SCALE_FACTOR: int = 4

# Minimum transaction weight (60 bytes is the lower bound for size of a valid serialized CTransaction)
MIN_TRANSACTION_WEIGHT: int = WITNESS_SCALE_FACTOR * 60  # 240 weight units

# Minimum serializable transaction weight (10 bytes is the lower bound for size of a serialized CTransaction)
MIN_SERIALIZABLE_TRANSACTION_WEIGHT: int = WITNESS_SCALE_FACTOR * 10  # 40 weight units

# =============================================================================
# Lock Time Flags
# =============================================================================

# Flags for nSequence and nLockTime locks
# Interpret sequence numbers as relative lock-time constraints (BIP 68)
LOCKTIME_VERIFY_SEQUENCE: int = 1 << 0

# =============================================================================
# Timewarp Mitigation (BIP 94)
# =============================================================================

# Maximum number of seconds that the timestamp of the first block of a difficulty
# adjustment period is allowed to be earlier than the last block of the previous period (BIP 94)
MAX_TIMEWARP: int = 600

# =============================================================================
# Helper Functions
# =============================================================================

def get_stripped_size(size_with_witness: int, witness_size: int) -> int:
    """
    Calculate stripped size from total size and witness size.
    
    Stripped size = total size - witness size
    """
    return size_with_witness - witness_size


def get_weight(stripped_size: int, total_size: int) -> int:
    """
    Calculate transaction/block weight.
    
    Weight = stripped_size * 3 + total_size
    or equivalently: weight = stripped_size * 4 + witness_size
    
    See BIP 141.
    """
    return stripped_size * 3 + total_size


def get_virtual_size(weight: int) -> int:
    """
    Calculate virtual size from weight.
    
    vsize = (weight + 3) / 4 (rounded up)
    
    See BIP 141.
    """
    return (weight + 3) // 4


def is_final_tx(n_sequence: int) -> bool:
    """
    Check if nSequence indicates a final transaction.
    
    A transaction is final if all inputs have nSequence == 0xFFFFFFFF.
    """
    return n_sequence == 0xFFFFFFFF


def sequence_lock_is_disabled(n_sequence: int) -> bool:
    """
    Check if relative lock-time is disabled for this input.
    
    If SEQUENCE_LOCKTIME_DISABLE_FLAG is set, the input is not
    subject to relative lock-time constraints.
    """
    return (n_sequence & 0x80000000) != 0  # Check bit 31


def get_sequence_lock_time(n_sequence: int) -> tuple[int, bool]:
    """
    Extract lock-time value and type from sequence number.
    
    Returns:
        Tuple of (lock_time, is_time_based)
        - lock_time: The lock-time value (in blocks or 512-second intervals)
        - is_time_based: True if time-based, False if block-based
    """
    if sequence_lock_is_disabled(n_sequence):
        return 0, False
    
    # Extract the lock-time value (lower 16 bits)
    lock_time = n_sequence & 0x0000FFFF
    
    # Check if it's time-based (bit 22)
    is_time_based = (n_sequence & 0x00400000) != 0
    
    return lock_time, is_time_based


def sequence_lock_to_seconds(n_sequence: int) -> int:
    """
    Convert sequence lock to seconds.
    
    If time-based, multiply by 512.
    If block-based, multiply by 600 (10 minutes target).
    """
    lock_time, is_time_based = get_sequence_lock_time(n_sequence)
    
    if is_time_based:
        return lock_time * 512  # Time-based: multiply by 512 seconds
    else:
        return lock_time * 600  # Block-based: assume 10 min per block
