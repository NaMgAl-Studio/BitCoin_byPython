"""
HKDF Implementation for Bitcoin
================================

HKDF (HMAC-based Key Derivation Function) as specified in RFC 5869.

Used in:
- BIP324 (V2 P2P transport) - HKDF-SHA256

Copyright (c) 2018-present The Bitcoin Core developers
Distributed under the MIT software license.
"""

from __future__ import annotations

from typing import Optional

from .hmac import HMAC_SHA256, hmac_sha256


class HKDF_SHA256_L32:
    """
    RFC 5869 HKDF implementation with HMAC-SHA256.
    
    This class produces exactly 32 bytes of output (L=32).
    
    Example:
        hkdf = HKDF_SHA256_L32(ikm, len(ikm), salt)
        hkdf.expand32(info, output)
    """
    
    OUTPUT_SIZE: int = 32
    
    def __init__(self, ikm: bytes, ikm_len: int | None = None, salt: str = "") -> None:
        """
        Initialize HKDF with input keying material.
        
        Args:
            ikm: Input keying material
            ikm_len: Length of IKM (optional)
            salt: Optional salt string
        """
        if ikm_len is not None and ikm_len != len(ikm):
            ikm = ikm[:ikm_len]
        
        # Extract phase
        if not salt:
            salt = b'\x00' * 32
        else:
            salt = salt.encode() if isinstance(salt, str) else salt
        
        # PRK = HMAC-Hash(salt, IKM)
        self._prk = hmac_sha256(salt, ikm)
    
    def expand32(self, info: str = "", output: bytearray | None = None) -> bytes:
        """
        Expand the PRK into output keying material.
        
        Args:
            info: Optional context and application specific information
            output: Optional output buffer (must be at least 32 bytes)
            
        Returns:
            32-byte output keying material
        """
        info_bytes = info.encode() if isinstance(info, str) else info
        
        # For L=32, we only need one iteration (N = ceil(32/32) = 1)
        # T(1) = HMAC-Hash(PRK, info || 0x01)
        t = hmac_sha256(self._prk, info_bytes + b'\x01')
        
        if output is not None:
            output[:32] = t
            return bytes(output[:32])
        return t
    
    @property
    def prk(self) -> bytes:
        """Get the pseudo-random key."""
        return self._prk


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes = b"", length: int = 32) -> bytes:
    """
    Compute HKDF-SHA256.
    
    Args:
        ikm: Input keying material
        salt: Salt value
        info: Context and application specific information
        length: Desired output length (max 255 * 32 = 8160 bytes)
        
    Returns:
        Output keying material of specified length
    """
    if length > 255 * 32:
        raise ValueError(f"HKDF output length too large: {length}")
    
    # Extract
    if not salt:
        salt = b'\x00' * 32
    prk = hmac_sha256(salt, ikm)
    
    # Expand
    n = (length + 31) // 32  # Number of iterations
    okm = b""
    t = b""
    
    for i in range(1, n + 1):
        t = hmac_sha256(prk, t + info + bytes([i]))
        okm += t
    
    return okm[:length]
