# Copyright (c) 2009-2010 Satoshi Nakamoto
# Copyright (c) 2009-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Bitcoin Proof of Work

This module implements proof-of-work validation and difficulty adjustment.
Includes:
- Difficulty target calculation
- Next work required calculation
- PoW verification
"""

from typing import Optional, Tuple
from dataclasses import dataclass

from .params import ConsensusParams
from ..primitives.block import BlockHeader
from ..crypto.sha256 import Hash256


# ============================================================================
# Arith_uint256 - Arbitrary Precision Unsigned Integer
# ============================================================================

class ArithUint256:
    """
    256-bit unsigned integer for difficulty calculations.
    
    Bitcoin uses 256-bit arithmetic for difficulty targets.
    This class provides the necessary operations.
    """
    
    def __init__(self, value: int = 0):
        """Initialize from an integer value."""
        if value < 0:
            raise ValueError("ArithUint256 must be non-negative")
        if value >= (1 << 256):
            raise ValueError("ArithUint256 overflow")
        self._value = value
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'ArithUint256':
        """Create from 32-byte big-endian representation."""
        if len(data) != 32:
            raise ValueError("Must be exactly 32 bytes")
        # Bitcoin uses little-endian internally, but the target is big-endian
        return cls(int.from_bytes(data, 'little'))
    
    @classmethod
    def from_uint256(cls, data: bytes) -> 'ArithUint256':
        """Create from uint256 (little-endian bytes)."""
        return cls(int.from_bytes(data, 'little'))
    
    def to_bytes(self) -> bytes:
        """Convert to 32-byte little-endian representation."""
        return self._value.to_bytes(32, 'little')
    
    def to_uint256(self) -> bytes:
        """Convert to uint256 (little-endian bytes)."""
        return self.to_bytes()
    
    @property
    def value(self) -> int:
        return self._value
    
    def __int__(self) -> int:
        return self._value
    
    def __add__(self, other: 'ArithUint256') -> 'ArithUint256':
        result = self._value + other._value
        if result >= (1 << 256):
            raise OverflowError("ArithUint256 addition overflow")
        return ArithUint256(result)
    
    def __sub__(self, other: 'ArithUint256') -> 'ArithUint256':
        result = self._value - other._value
        if result < 0:
            raise ValueError("ArithUint256 subtraction underflow")
        return ArithUint256(result)
    
    def __mul__(self, other: 'ArithUint256') -> 'ArithUint256':
        result = self._value * other._value
        if result >= (1 << 256):
            raise OverflowError("ArithUint256 multiplication overflow")
        return ArithUint256(result)
    
    def __floordiv__(self, other: 'ArithUint256') -> 'ArithUint256':
        if other._value == 0:
            raise ZeroDivisionError("ArithUint256 division by zero")
        return ArithUint256(self._value // other._value)
    
    def __lt__(self, other: 'ArithUint256') -> bool:
        return self._value < other._value
    
    def __le__(self, other: 'ArithUint256') -> bool:
        return self._value <= other._value
    
    def __gt__(self, other: 'ArithUint256') -> bool:
        return self._value > other._value
    
    def __ge__(self, other: 'ArithUint256') -> bool:
        return self._value >= other._value
    
    def __eq__(self, other: object) -> bool:
        if isinstance(other, ArithUint256):
            return self._value == other._value
        return False
    
    def __lshift__(self, n: int) -> 'ArithUint256':
        result = self._value << n
        if result >= (1 << 256):
            raise OverflowError("ArithUint256 left shift overflow")
        return ArithUint256(result)
    
    def __rshift__(self, n: int) -> 'ArithUint256':
        return ArithUint256(self._value >> n)
    
    def __repr__(self) -> str:
        return f"ArithUint256({self._value})"
    
    def get_low64(self) -> int:
        """Get the lowest 64 bits."""
        return self._value & 0xFFFFFFFFFFFFFFFF
    
    def get_compact(self) -> int:
        """
        Convert to compact nBits representation.
        
        The compact format is a 4-byte value that encodes a 256-bit target.
        It uses a base-256 floating-point representation.
        """
        n_size = 0
        
        if self._value == 0:
            return 0
        
        # Count leading zero bytes (in base 256)
        temp = self._value
        while temp > 0:
            temp >>= 8
            n_size += 1
        
        # Compact representation
        if n_size <= 3:
            compact = (self._value << (8 * (3 - n_size))) & 0x00FFFFFF
        else:
            # Need to shift right, losing precision
            compact = (self._value >> (8 * (n_size - 3))) & 0x00FFFFFF
        
        # Add the size byte
        compact |= n_size << 24
        
        return compact
    
    @classmethod
    def set_compact(cls, n_compact: int) -> 'ArithUint256':
        """
        Create from compact nBits representation.
        
        Args:
            n_compact: Compact representation of difficulty target
            
        Returns:
            ArithUint256 representing the full target
        """
        n_size = n_compact >> 24
        n_word = n_compact & 0x007FFFFF
        
        if n_size <= 3:
            value = n_word >> (8 * (3 - n_size))
        else:
            value = n_word << (8 * (n_size - 3))
        
        return cls(value)


# ============================================================================
# Difficulty Target Functions
# ============================================================================

def DeriveTarget(n_bits: int, pow_limit: bytes) -> Optional[ArithUint256]:
    """
    Convert nBits value to target.
    
    Args:
        n_bits: Compact representation of the target
        pow_limit: Maximum allowed target (consensus parameter)
        
    Returns:
        The proof-of-work target, or None if invalid
    """
    target = ArithUint256.set_compact(n_bits)
    
    # Check for overflow (negative target)
    if n_bits & 0x00800000:
        return None
    
    # Check that target doesn't exceed pow_limit
    pow_limit_arith = ArithUint256.from_uint256(pow_limit)
    
    if target > pow_limit_arith:
        return None
    
    return target


def CheckProofOfWork(block_hash: bytes, n_bits: int, 
                     params: ConsensusParams) -> bool:
    """
    Check whether a block hash satisfies the proof-of-work requirement.
    
    The hash must be less than the target encoded in n_bits.
    
    Args:
        block_hash: 32-byte block hash
        n_bits: Compact target difficulty
        params: Consensus parameters
        
    Returns:
        True if the hash meets the proof-of-work target
    """
    target = DeriveTarget(n_bits, params.pow_limit)
    
    if target is None:
        return False
    
    hash_arith = ArithUint256.from_uint256(block_hash)
    
    # Hash must be less than target
    return hash_arith <= target


def CheckProofOfWorkImpl(block_hash: bytes, n_bits: int,
                         params: ConsensusParams) -> bool:
    """
    Implementation of proof-of-work check with detailed validation.
    """
    target = DeriveTarget(n_bits, params.pow_limit)
    
    if target is None:
        return False
    
    if target.value == 0:
        return False
    
    hash_arith = ArithUint256.from_uint256(block_hash)
    
    return hash_arith <= target


# ============================================================================
# Difficulty Adjustment
# ============================================================================

def GetNextWorkRequired(
    pindex_last: Optional['BlockIndex'],
    pblock: Optional[BlockHeader],
    params: ConsensusParams
) -> int:
    """
    Calculate the required difficulty for the next block.
    
    Args:
        pindex_last: Index of the last block in the chain
        pblock: The new block being mined (for testnet min-difficulty)
        params: Consensus parameters
        
    Returns:
        Compact difficulty target (nBits)
    """
    # Genesis block
    if pindex_last is None:
        return ArithUint256.from_uint256(params.pow_limit).get_compact()
    
    # Difficulty adjustment interval
    difficulty_interval = params.difficulty_adjustment_interval()
    
    # Only adjust at retarget intervals
    if (pindex_last.height + 1) % difficulty_interval != 0:
        # Special rules for testnet
        if params.pow_allow_min_difficulty_blocks:
            # Special difficulty rule for testnet:
            # If the new block's timestamp is more than 2 * target spacing
            # minutes then allow mining of a min-difficulty block
            if pblock and pblock.time > pindex_last.time + params.pow_target_spacing * 2:
                return ArithUint256.from_uint256(params.pow_limit).get_compact()
            else:
                # Return the last non-special-min-difficulty-rules-block
                pindex = pindex_last
                while pindex.prev and pindex.height % difficulty_interval != 0 and \
                      pindex.n_bits == ArithUint256.from_uint256(params.pow_limit).get_compact():
                    pindex = pindex.prev
                return pindex.n_bits
        
        # No retargeting needed
        return pindex_last.n_bits
    
    # Retarget
    # Go back the full adjustment interval
    pindex_first = pindex_last
    for _ in range(difficulty_interval - 1):
        if pindex_first.prev is None:
            return ArithUint256.from_uint256(params.pow_limit).get_compact()
        pindex_first = pindex_first.prev
    
    return CalculateNextWorkRequired(
        pindex_last, pindex_first.time, params
    )


def CalculateNextWorkRequired(
    pindex_last: 'BlockIndex',
    n_first_block_time: int,
    params: ConsensusParams
) -> int:
    """
    Calculate the next required difficulty.
    
    Args:
        pindex_last: Index of the last block
        n_first_block_time: Time of first block in retarget period
        params: Consensus parameters
        
    Returns:
        Compact difficulty target
    """
    # No retargeting in regtest mode
    if params.pow_no_retargeting:
        return pindex_last.n_bits
    
    # Limit adjustment step
    actual_timespan = pindex_last.time - n_first_block_time
    
    if actual_timespan < params.pow_target_timespan // 4:
        actual_timespan = params.pow_target_timespan // 4
    elif actual_timespan > params.pow_target_timespan * 4:
        actual_timespan = params.pow_target_timespan * 4
    
    # Retarget
    new_target = ArithUint256.set_compact(pindex_last.n_bits)
    
    # Multiply by actual timespan
    new_target = new_target * ArithUint256(actual_timespan)
    
    # Divide by target timespan
    new_target = new_target // ArithUint256(params.pow_target_timespan)
    
    # Limit to pow_limit
    pow_limit = ArithUint256.from_uint256(params.pow_limit)
    
    if new_target > pow_limit:
        new_target = pow_limit
    
    return new_target.get_compact()


def PermittedDifficultyTransition(
    params: ConsensusParams,
    height: int,
    old_nbits: int,
    new_nbits: int
) -> bool:
    """
    Check if a difficulty transition is valid.
    
    Returns False if the new difficulty at a given height is not
    possible given the prior difficulty.
    
    This checks that:
    - At retarget intervals, new difficulty is within 4x of old
    - At non-retarget blocks, difficulties are identical
    - Exception: min-difficulty blocks on testnet/regtest
    
    Args:
        params: Consensus parameters
        height: Block height
        old_nbits: Previous block's difficulty
        new_nbits: Current block's difficulty
        
    Returns:
        True if the transition is permitted
    """
    # Min-difficulty blocks are always allowed
    if params.pow_allow_min_difficulty_blocks:
        return True
    
    difficulty_interval = params.difficulty_adjustment_interval()
    
    # Non-retarget blocks must have same difficulty
    if height % difficulty_interval != 0:
        return old_nbits == new_nbits
    
    # At retarget, new difficulty must be within factor of 4
    old_target = ArithUint256.set_compact(old_nbits)
    new_target = ArithUint256.set_compact(new_nbits)
    
    # New can't be more than 4x larger (easier)
    if new_target > old_target * ArithUint256(4):
        return False
    
    # New can't be more than 4x smaller (harder)
    if new_target * ArithUint256(4) < old_target:
        return False
    
    return True


# ============================================================================
# BlockIndex Placeholder
# ============================================================================

@dataclass
class BlockIndex:
    """
    Placeholder for block index.
    
    The actual implementation is in chain.py.
    This is here for type hints in pow functions.
    """
    height: int
    time: int
    n_bits: int
    prev: Optional['BlockIndex'] = None
    
    @property
    def median_time_past(self) -> int:
        """Get median time past for this block."""
        # Simplified - actual implementation would look at last 11 blocks
        if self.prev:
            return self.prev.time
        return self.time
    
    def get_ancestor(self, height: int) -> Optional['BlockIndex']:
        """Get ancestor at given height."""
        if height > self.height:
            return None
        if height == self.height:
            return self
        
        # Walk back
        current = self
        while current and current.height > height:
            current = current.prev
        
        return current if current and current.height == height else None
