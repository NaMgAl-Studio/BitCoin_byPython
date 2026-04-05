"""
SHA-1 Implementation for Bitcoin
=================================

SHA-1 is used in Bitcoin for certain legacy operations.
Note: SHA-1 is considered cryptographically weak and should not
be used for new applications.

Copyright (c) 2014-present The Bitcoin Core developers
Distributed under the MIT software license.
"""

from __future__ import annotations

import hashlib


class SHA1:
    """A hasher class for SHA-1."""
    
    OUTPUT_SIZE: int = 20  # 160 bits = 20 bytes
    
    def __init__(self) -> None:
        self._hasher = hashlib.sha1()
    
    def write(self, data: bytes) -> SHA1:
        self._hasher.update(data)
        return self
    
    def finalize(self) -> bytes:
        return self._hasher.digest()
    
    def reset(self) -> SHA1:
        self._hasher = hashlib.sha1()
        return self


def sha1(data: bytes) -> bytes:
    """Compute SHA-1 hash of data."""
    return hashlib.sha1(data).digest()
