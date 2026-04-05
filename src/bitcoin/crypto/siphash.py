"""
SipHash Implementation for Bitcoin
===================================

SipHash-2-4 is a fast keyed hash function used for hash table
collision resistance. It's used in Bitcoin for:
- UTXO set hashing
- Transaction hash table lookup

Reference: https://131002.net/siphash/

Copyright (c) 2016-present The Bitcoin Core developers
Distributed under the MIT software license.
"""

from __future__ import annotations

from typing import Optional


# =============================================================================
# SipHash Constants
# =============================================================================

SIPHASH_C0: int = 0x736f6d6570736575
SIPHASH_C1: int = 0x646f72616e646f6d
SIPHASH_C2: int = 0x6c7967656e657261
SIPHASH_C3: int = 0x7465646279746573


# =============================================================================
# SipHash State
# =============================================================================

class SipHashState:
    """
    Shared SipHash internal state v[0..3], initialized from (k0, k1).
    """
    
    def __init__(self, k0: int, k1: int) -> None:
        """
        Initialize SipHash state with a 128-bit key.
        
        Args:
            k0: First 64 bits of key
            k1: Second 64 bits of key
        """
        self.v = [
            SIPHASH_C0 ^ k0,
            SIPHASH_C1 ^ k1,
            SIPHASH_C2 ^ k0,
            SIPHASH_C3 ^ k1,
        ]


def _rotl64(x: int, n: int) -> int:
    """Rotate left for 64-bit values."""
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _sipround(v: list[int]) -> None:
    """
    Perform one SipHash round.
    
    Modifies v in place.
    """
    v[0] = (v[0] + v[1]) & 0xFFFFFFFFFFFFFFFF
    v[1] = _rotl64(v[1], 13)
    v[1] ^= v[0]
    v[0] = _rotl64(v[0], 32)
    
    v[2] = (v[2] + v[3]) & 0xFFFFFFFFFFFFFFFF
    v[3] = _rotl64(v[3], 16)
    v[3] ^= v[2]
    
    v[0] = (v[0] + v[3]) & 0xFFFFFFFFFFFFFFFF
    v[3] = _rotl64(v[3], 21)
    v[3] ^= v[0]
    
    v[2] = (v[2] + v[1]) & 0xFFFFFFFFFFFFFFFF
    v[1] = _rotl64(v[1], 17)
    v[1] ^= v[2]
    v[2] = _rotl64(v[2], 32)


# =============================================================================
# SipHasher Class
# =============================================================================

class SipHasher:
    """
    General SipHash-2-4 implementation.
    
    Example:
        hasher = SipHasher(k0, k1)
        hasher.write(data)
        result = hasher.finalize()
    """
    
    def __init__(self, k0: int, k1: int) -> None:
        """
        Construct a SipHash calculator initialized with 128-bit key (k0, k1).
        
        Args:
            k0: First 64 bits of key
            k1: Second 64 bits of key
        """
        self._state = SipHashState(k0, k1)
        self._tmp: int = 0
        self._count: int = 0  # Only the low 8 bits of the input size matter
    
    def write_uint64(self, data: int) -> SipHasher:
        """
        Hash a 64-bit integer worth of data.
        
        It is treated as if this was the little-endian interpretation of 8 bytes.
        This function can only be used when a multiple of 8 bytes have been written so far.
        
        Args:
            data: 64-bit integer to hash
            
        Returns:
            self for method chaining
        """
        assert self._count % 8 == 0, "Count must be multiple of 8"
        
        v = self._state.v.copy()
        
        v[3] ^= data
        _sipround(v)
        _sipround(v)
        v[0] ^= data
        
        self._state.v = v
        self._count += 8
        
        return self
    
    def write(self, data: bytes) -> SipHasher:
        """
        Hash arbitrary bytes.
        
        Args:
            data: Bytes to hash
            
        Returns:
            self for method chaining
        """
        v = self._state.v.copy()
        t = self._tmp
        c = self._count
        
        for byte in data:
            t |= byte << (8 * (c % 8))
            c += 1
            
            if (c & 7) == 0:
                # We have a complete 64-bit word
                v[3] ^= t
                _sipround(v)
                _sipround(v)
                v[0] ^= t
                t = 0
        
        self._state.v = v
        self._count = c
        self._tmp = t
        
        return self
    
    def finalize(self) -> int:
        """
        Compute the 64-bit SipHash-2-4 of the data written so far.
        
        The object remains untouched and can continue to accept writes.
        
        Returns:
            64-bit SipHash digest
        """
        v = self._state.v.copy()
        
        # Final state
        t = self._tmp | (self._count << 56)
        
        v[3] ^= t
        _sipround(v)
        _sipround(v)
        v[0] ^= t
        
        # Finalize with 0xFF
        v[2] ^= 0xFF
        _sipround(v)
        _sipround(v)
        _sipround(v)
        _sipround(v)
        
        return v[0] ^ v[1] ^ v[2] ^ v[3]


# =============================================================================
# Presalted SipHasher
# =============================================================================

class PresaltedSipHasher:
    """
    Optimized SipHash-2-4 implementation for uint256.
    
    This class caches the initial SipHash v[0..3] state derived from (k0, k1)
    and implements a specialized hashing path for uint256 values.
    
    The internal state is immutable, so PresaltedSipHasher instances can be
    reused for multiple hashes with the same key.
    
    Example:
        hasher = PresaltedSipHasher(k0, k1)
        result = hasher(uint256_val)
    """
    
    def __init__(self, k0: int, k1: int) -> None:
        """
        Initialize with a 128-bit key.
        
        Args:
            k0: First 64 bits of key
            k1: Second 64 bits of key
        """
        self._state = SipHashState(k0, k1)
    
    def __call__(self, val: bytes, extra: Optional[int] = None) -> int:
        """
        Hash a 256-bit value, optionally with an extra 32-bit word.
        
        Args:
            val: 32-byte value to hash
            extra: Optional extra 32-bit word
            
        Returns:
            64-bit SipHash digest
        """
        if len(val) != 32:
            raise ValueError(f"Expected 32-byte value, got {len(val)}")
        
        v = self._state.v.copy()
        
        # Process the four 64-bit words of the uint256
        for i in range(4):
            d = int.from_bytes(val[i * 8:(i + 1) * 8], 'little')
            v[3] ^= d
            _sipround(v)
            _sipround(v)
            v[0] ^= d
        
        if extra is not None:
            # Include extra 32-bit word
            d = (36 << 56) | (extra & 0xFFFFFFFF)
            v[3] ^= d
            _sipround(v)
            _sipround(v)
            v[0] ^= d
        else:
            # Just the length (32 bytes = 4 words)
            d = 4 << 59
            v[3] ^= d
            _sipround(v)
            _sipround(v)
            v[0] ^= d
        
        # Finalize
        v[2] ^= 0xFF
        _sipround(v)
        _sipround(v)
        _sipround(v)
        _sipround(v)
        
        return v[0] ^ v[1] ^ v[2] ^ v[3]


# =============================================================================
# Convenience Functions
# =============================================================================

def SipHash24(k0: int, k1: int, data: bytes) -> int:
    """
    Compute SipHash-2-4 of data with key (k0, k1).
    
    Args:
        k0: First 64 bits of key
        k1: Second 64 bits of key
        data: Bytes to hash
        
    Returns:
        64-bit SipHash digest
    """
    hasher = SipHasher(k0, k1)
    hasher.write(data)
    return hasher.finalize()
