"""
RIPEMD-160 Implementation for Bitcoin
======================================

This module provides RIPEMD-160 hashing functionality for Bitcoin.
RIPEMD-160 is used for Bitcoin address generation (combined with SHA-256).

The implementation follows ISO/IEC 10118-3 and Bitcoin Core's
src/crypto/ripemd160.h and ripemd160.cpp

Copyright (c) 2014-present The Bitcoin Core developers
Distributed under the MIT software license.
"""

from __future__ import annotations

import hashlib
from typing import List


# =============================================================================
# RIPEMD-160 Constants
# =============================================================================

# Initial hash values
RIPEMD160_INITIAL_STATE: List[int] = [
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
]

# Constants for left line
RIPEMD160_K1: List[int] = [0x00000000] * 16 + [0x5A827999] * 16 + [0x6ED9EBA1] * 16 + [0x8F1BBCDC] * 16 + [0xA953FD4E] * 16

# Constants for right line  
RIPEMD160_K2: List[int] = [0x50A28BE6] * 16 + [0x5C4DD124] * 16 + [0x6D703EF3] * 16 + [0x7A6D76E9] * 16 + [0x00000000] * 16

# Rotation amounts for left line
RIPEMD160_R1: List[int] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
]

# Rotation amounts for right line
RIPEMD160_R2: List[int] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
]

# Selection permutations
RIPEMD160_S1: List[int] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
]

RIPEMD160_S2: List[int] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
]


# =============================================================================
# RIPEMD-160 Class
# =============================================================================

class RIPEMD160:
    """
    A hasher class for RIPEMD-160.
    
    This class provides an incremental hashing interface similar to
    Bitcoin Core's CRIPEMD160.
    
    Example:
        h = RIPEMD160()
        h.write(b"Hello, ")
        h.write(b"World!")
        digest = h.finalize()
    """
    
    OUTPUT_SIZE: int = 20  # 160 bits = 20 bytes
    
    def __init__(self) -> None:
        """Initialize the RIPEMD-160 hasher."""
        # Use hashlib if available (Python 3.8+)
        try:
            self._hasher = hashlib.new('ripemd160')
        except ValueError:
            # Fallback to pure Python implementation
            self._hasher = None
            self._state = RIPEMD160_INITIAL_STATE.copy()
            self._buffer = b''
            self._bytes = 0
    
    def write(self, data: bytes) -> RIPEMD160:
        """
        Add data to the hash.
        
        Args:
            data: Bytes to hash
            
        Returns:
            self for method chaining
        """
        if self._hasher:
            self._hasher.update(data)
        else:
            self._buffer += data
            self._bytes += len(data)
        return self
    
    def finalize(self) -> bytes:
        """
        Finalize the hash and return the digest.
        
        Returns:
            20-byte RIPEMD-160 digest
        """
        if self._hasher:
            return self._hasher.digest()
        else:
            return _ripemd160_finalize_pure_python(self._state, self._buffer, self._bytes)
    
    def reset(self) -> RIPEMD160:
        """
        Reset the hasher to initial state.
        
        Returns:
            self for method chaining
        """
        try:
            self._hasher = hashlib.new('ripemd160')
        except ValueError:
            self._hasher = None
            self._state = RIPEMD160_INITIAL_STATE.copy()
            self._buffer = b''
            self._bytes = 0
        return self


# =============================================================================
# Convenience Functions
# =============================================================================

def ripemd160(data: bytes) -> bytes:
    """
    Compute RIPEMD-160 hash of data.
    
    Args:
        data: Bytes to hash
        
    Returns:
        20-byte RIPEMD-160 digest
    """
    try:
        return hashlib.new('ripemd160', data).digest()
    except ValueError:
        # Fallback to pure Python
        return _ripemd160_pure_python(data)


def hash160(data: bytes) -> bytes:
    """
    Compute Bitcoin's hash160 (RIPEMD160(SHA256(data))).
    
    This is used for Bitcoin addresses.
    
    Args:
        data: Bytes to hash
        
    Returns:
        20-byte hash160 digest
    """
    from .sha256 import sha256
    return ripemd160(sha256(data))


# =============================================================================
# Internal Implementation (pure Python fallback)
# =============================================================================

def _rotl32(x: int, n: int) -> int:
    """Left rotate a 32-bit value."""
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _f(j: int, x: int, y: int, z: int) -> int:
    """RIPEMD-160 f functions."""
    if j < 16:
        return x ^ y ^ z
    elif j < 32:
        return (x & y) | (~x & z)
    elif j < 48:
        return (x | ~y) ^ z
    elif j < 64:
        return (x & z) | (y & ~z)
    else:
        return x ^ (y | ~z)


def _ripemd160_transform(state: List[int], block: bytes) -> List[int]:
    """
    Perform one RIPEMD-160 transformation on a 64-byte block.
    
    Args:
        state: Current state (5 x 32-bit words)
        block: 64-byte input block
        
    Returns:
        Updated state
    """
    assert len(block) == 64
    
    # Parse block into 16 32-bit little-endian words
    X = []
    for i in range(16):
        X.append(int.from_bytes(block[i * 4:(i + 1) * 4], 'little'))
    
    # Initialize working variables for left and right lines
    al, bl, cl, dl, el = state
    ar, br, cr, dr, er = state
    
    # 80 rounds
    for j in range(80):
        # Left line
        rnd = _f(j, bl, cl, dl)
        t = (al + rnd + X[RIPEMD160_S1[j]] + RIPEMD160_K1[j]) & 0xFFFFFFFF
        t = _rotl32(t, RIPEMD160_R1[j])
        t = (t + el) & 0xFFFFFFFF
        al = el
        el = dl
        dl = _rotl32(cl, 10)
        cl = bl
        bl = t
        
        # Right line
        rnd = _f(79 - j, br, cr, dr)
        t = (ar + rnd + X[RIPEMD160_S2[j]] + RIPEMD160_K2[j]) & 0xFFFFFFFF
        t = _rotl32(t, RIPEMD160_R2[j])
        t = (t + er) & 0xFFFFFFFF
        ar = er
        er = dr
        dr = _rotl32(cr, 10)
        cr = br
        br = t
    
    # Final addition
    t = state[1] + cl + dr
    state[1] = (state[2] + dl + er) & 0xFFFFFFFF
    state[2] = (state[3] + el + ar) & 0xFFFFFFFF
    state[3] = (state[4] + al + br) & 0xFFFFFFFF
    state[4] = (state[0] + bl + cr) & 0xFFFFFFFF
    state[0] = t & 0xFFFFFFFF
    
    return state


def _ripemd160_pure_python(data: bytes) -> bytes:
    """
    Pure Python RIPEMD-160 implementation.
    
    Args:
        data: Bytes to hash
        
    Returns:
        20-byte RIPEMD-160 digest
    """
    state = RIPEMD160_INITIAL_STATE.copy()
    
    # Pad message
    msg_len = len(data)
    data = data + b'\x80'
    data = data + b'\x00' * ((55 - msg_len) % 64)
    data = data + (msg_len * 8).to_bytes(8, 'little')
    
    # Process each 64-byte block
    for i in range(0, len(data), 64):
        state = _ripemd160_transform(state, data[i:i + 64])
    
    # Output
    return b''.join(word.to_bytes(4, 'little') for word in state)


def _ripemd160_finalize_pure_python(state: List[int], buffer: bytes, total_bytes: int) -> bytes:
    """
    Finalize RIPEMD-160 hash with padding.
    
    Args:
        state: Current state
        buffer: Unprocessed buffer
        total_bytes: Total bytes processed
        
    Returns:
        20-byte RIPEMD-160 digest
    """
    # Pad message
    msg_len = total_bytes
    buffer = buffer + b'\x80'
    buffer = buffer + b'\x00' * ((55 - msg_len % 64) % 64)
    buffer = buffer + (msg_len * 8).to_bytes(8, 'little')
    
    # Process remaining blocks
    for i in range(0, len(buffer), 64):
        state = _ripemd160_transform(state, buffer[i:i + 64])
    
    return b''.join(word.to_bytes(4, 'little') for word in state)
