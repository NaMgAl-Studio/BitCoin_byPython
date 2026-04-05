"""
SHA-256 Implementation for Bitcoin
===================================

This module provides SHA-256 hashing functionality for Bitcoin.
Bitcoin uses double SHA-256 (hash256) for most applications.

The implementation follows FIPS 180-4 and Bitcoin Core's
src/crypto/sha256.h and sha256.cpp

Copyright (c) 2014-present The Bitcoin Core developers
Distributed under the MIT software license.
"""

from __future__ import annotations

import hashlib
from typing import List, Union


# =============================================================================
# SHA-256 Constants
# =============================================================================

# Initial hash values (first 32 bits of the fractional parts of the
# square roots of the first 8 primes 2..19)
SHA256_INITIAL_STATE: List[int] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

# Round constants (first 32 bits of the fractional parts of the
# cube roots of the first 64 primes 2..311)
SHA256_K: List[int] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


# =============================================================================
# SHA-256 Class
# =============================================================================

class SHA256:
    """
    A hasher class for SHA-256.
    
    This class provides an incremental hashing interface similar to
    Bitcoin Core's CSHA256.
    
    Example:
        h = SHA256()
        h.write(b"Hello, ")
        h.write(b"World!")
        digest = h.finalize()
    """
    
    OUTPUT_SIZE: int = 32  # 256 bits = 32 bytes
    
    def __init__(self) -> None:
        """Initialize the SHA-256 hasher."""
        self._hasher = hashlib.sha256()
        self._bytes: int = 0
    
    def write(self, data: bytes) -> SHA256:
        """
        Add data to the hash.
        
        Args:
            data: Bytes to hash
            
        Returns:
            self for method chaining
        """
        self._hasher.update(data)
        self._bytes += len(data)
        return self
    
    def finalize(self) -> bytes:
        """
        Finalize the hash and return the digest.
        
        Returns:
            32-byte SHA-256 digest
        """
        return self._hasher.digest()
    
    def reset(self) -> SHA256:
        """
        Reset the hasher to initial state.
        
        Returns:
            self for method chaining
        """
        self._hasher = hashlib.sha256()
        self._bytes = 0
        return self
    
    @property
    def bytes(self) -> int:
        """Get the total number of bytes hashed."""
        return self._bytes


# =============================================================================
# Convenience Functions
# =============================================================================

def sha256(data: bytes) -> bytes:
    """
    Compute SHA-256 hash of data.
    
    Args:
        data: Bytes to hash
        
    Returns:
        32-byte SHA-256 digest
    """
    return hashlib.sha256(data).digest()


def double_sha256(data: bytes) -> bytes:
    """
    Compute double SHA-256 hash (Bitcoin's hash256).
    
    This is the primary hash function used in Bitcoin:
    hash256(data) = SHA256(SHA256(data))
    
    Args:
        data: Bytes to hash
        
    Returns:
        32-byte double SHA-256 digest
    """
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def SHA256D64(output: bytearray, input_data: bytes, blocks: int) -> None:
    """
    Compute multiple double-SHA256 hashes of 64-byte blobs.
    
    This is an optimized function for computing many hashes at once,
    used for Merkle tree computation.
    
    Args:
        output: Output buffer (must be at least blocks * 32 bytes)
        input_data: Input buffer (must be at least blocks * 64 bytes)
        blocks: Number of 64-byte blocks to hash
    """
    for i in range(blocks):
        block = input_data[i * 64:(i + 1) * 64]
        digest = double_sha256(block)
        output[i * 32:(i + 1) * 32] = digest


# =============================================================================
# Internal Implementation (for educational/testing purposes)
# =============================================================================

def _rotr(x: int, n: int) -> int:
    """Right rotate a 32-bit value."""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _shr(x: int, n: int) -> int:
    """Right shift a 32-bit value."""
    return x >> n


def _ch(x: int, y: int, z: int) -> int:
    """SHA-256 Ch function."""
    return (x & y) ^ (~x & z)


def _maj(x: int, y: int, z: int) -> int:
    """SHA-256 Maj function."""
    return (x & y) ^ (x & z) ^ (y & z)


def _sigma0(x: int) -> int:
    """SHA-256 Σ0 function."""
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)


def _sigma1(x: int) -> int:
    """SHA-256 Σ1 function."""
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)


def _gamma0(x: int) -> int:
    """SHA-256 σ0 function."""
    return _rotr(x, 7) ^ _rotr(x, 18) ^ _shr(x, 3)


def _gamma1(x: int) -> int:
    """SHA-256 σ1 function."""
    return _rotr(x, 17) ^ _rotr(x, 19) ^ _shr(x, 10)


def sha256_transform(state: List[int], block: bytes) -> List[int]:
    """
    Perform one SHA-256 transformation on a 64-byte block.
    
    This is the core transformation function, provided for
    educational purposes and low-level testing.
    
    Args:
        state: Current state (8 x 32-bit words)
        block: 64-byte input block
        
    Returns:
        Updated state
    """
    assert len(block) == 64
    assert len(state) == 8
    
    # Parse block into 16 32-bit big-endian words
    W = []
    for i in range(16):
        W.append(int.from_bytes(block[i * 4:(i + 1) * 4], 'big'))
    
    # Extend to 64 words
    for i in range(16, 64):
        W.append((_gamma1(W[i - 2]) + W[i - 7] + _gamma0(W[i - 15]) + W[i - 16]) & 0xFFFFFFFF)
    
    # Initialize working variables
    a, b, c, d, e, f, g, h = state
    
    # 64 rounds
    for i in range(64):
        T1 = (h + _sigma1(e) + _ch(e, f, g) + SHA256_K[i] + W[i]) & 0xFFFFFFFF
        T2 = (_sigma0(a) + _maj(a, b, c)) & 0xFFFFFFFF
        h = g
        g = f
        f = e
        e = (d + T1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (T1 + T2) & 0xFFFFFFFF
    
    # Add working variables to state
    state = [
        (state[0] + a) & 0xFFFFFFFF,
        (state[1] + b) & 0xFFFFFFFF,
        (state[2] + c) & 0xFFFFFFFF,
        (state[3] + d) & 0xFFFFFFFF,
        (state[4] + e) & 0xFFFFFFFF,
        (state[5] + f) & 0xFFFFFFFF,
        (state[6] + g) & 0xFFFFFFFF,
        (state[7] + h) & 0xFFFFFFFF,
    ]
    
    return state


def sha256_pure_python(data: bytes) -> bytes:
    """
    Pure Python SHA-256 implementation.
    
    This is provided for educational purposes and testing.
    In production, use hashlib.sha256 which uses optimized C code.
    
    Args:
        data: Bytes to hash
        
    Returns:
        32-byte SHA-256 digest
    """
    # Initialize state
    state = SHA256_INITIAL_STATE.copy()
    
    # Pad message
    msg_len = len(data)
    data = data + b'\x80'
    data = data + b'\x00' * ((55 - msg_len) % 64)
    data = data + (msg_len * 8).to_bytes(8, 'big')
    
    # Process each 64-byte block
    for i in range(0, len(data), 64):
        state = sha256_transform(state, data[i:i + 64])
    
    # Output
    return b''.join(word.to_bytes(4, 'big') for word in state)
