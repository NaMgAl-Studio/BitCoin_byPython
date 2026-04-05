"""
HMAC Implementation for Bitcoin
================================

HMAC-SHA256 and HMAC-SHA512 implementations.

Used in:
- BIP32 (HD Wallets) - HMAC-SHA512
- BIP340 (Schnorr signatures) - HMAC-SHA256

Copyright (c) 2014-present The Bitcoin Core developers
Distributed under the MIT software license.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac

from .sha256 import SHA256, sha256
from .sha512 import SHA512, sha512


class HMAC_SHA256:
    """
    A hasher class for HMAC-SHA256.
    
    Example:
        h = HMAC_SHA256(key, key_len)
        h.write(data)
        digest = h.finalize()
    """
    
    OUTPUT_SIZE: int = 32
    
    def __init__(self, key: bytes, key_len: int | None = None) -> None:
        """
        Initialize HMAC-SHA256 with a key.
        
        Args:
            key: The HMAC key
            key_len: Length of key (optional, derived from key if not provided)
        """
        if key_len is not None and key_len != len(key):
            key = key[:key_len] if key_len < len(key) else key + b'\x00' * (key_len - len(key))
        
        self._inner = SHA256()
        self._outer = SHA256()
        
        # If key is longer than block size, hash it
        if len(key) > 64:
            key = sha256(key)
        
        # Pad key to block size
        key = key + b'\x00' * (64 - len(key))
        
        # Create inner and outer padded keys
        inner_key = bytes((b ^ 0x36) for b in key)
        outer_key = bytes((b ^ 0x5c) for b in key)
        
        # Initialize inner hash
        self._inner.write(inner_key)
        
        # Store outer key for finalization
        self._outer_key = outer_key
    
    def write(self, data: bytes) -> HMAC_SHA256:
        """Add data to the HMAC."""
        self._inner.write(data)
        return self
    
    def finalize(self) -> bytes:
        """Finalize and return the HMAC digest."""
        # Compute inner hash
        inner_hash = self._inner.finalize()
        
        # Compute outer hash
        self._outer.write(self._outer_key)
        self._outer.write(inner_hash)
        
        return self._outer.finalize()


class HMAC_SHA512:
    """
    A hasher class for HMAC-SHA512.
    
    Used in BIP32 for HD wallet key derivation.
    
    Example:
        h = HMAC_SHA512(key, key_len)
        h.write(data)
        digest = h.finalize()
    """
    
    OUTPUT_SIZE: int = 64
    
    def __init__(self, key: bytes, key_len: int | None = None) -> None:
        """
        Initialize HMAC-SHA512 with a key.
        
        Args:
            key: The HMAC key
            key_len: Length of key (optional)
        """
        if key_len is not None and key_len != len(key):
            key = key[:key_len] if key_len < len(key) else key + b'\x00' * (key_len - len(key))
        
        self._inner = SHA512()
        self._outer = SHA512()
        
        # If key is longer than block size (128 for SHA-512), hash it
        if len(key) > 128:
            key = sha512(key)
        
        # Pad key to block size
        key = key + b'\x00' * (128 - len(key))
        
        # Create inner and outer padded keys
        inner_key = bytes((b ^ 0x36) for b in key)
        outer_key = bytes((b ^ 0x5c) for b in key)
        
        # Initialize inner hash
        self._inner.write(inner_key)
        
        # Store outer key for finalization
        self._outer_key = outer_key
    
    def write(self, data: bytes) -> HMAC_SHA512:
        """Add data to the HMAC."""
        self._inner.write(data)
        return self
    
    def finalize(self) -> bytes:
        """Finalize and return the HMAC digest."""
        # Compute inner hash
        inner_hash = self._inner.finalize()
        
        # Compute outer hash
        self._outer.write(self._outer_key)
        self._outer.write(inner_hash)
        
        return self._outer.finalize()


# =============================================================================
# Convenience Functions
# =============================================================================

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """
    Compute HMAC-SHA256.
    
    Args:
        key: The HMAC key
        data: The data to authenticate
        
    Returns:
        32-byte HMAC-SHA256 digest
    """
    return _hmac.new(key, data, hashlib.sha256).digest()


def hmac_sha512(key: bytes, data: bytes) -> bytes:
    """
    Compute HMAC-SHA512.
    
    Used in BIP32 for HD wallet key derivation.
    
    Args:
        key: The HMAC key (typically "Bitcoin seed" for master key)
        data: The data (typically seed entropy)
        
    Returns:
        64-byte HMAC-SHA512 digest
    """
    return _hmac.new(key, data, hashlib.sha512).digest()
