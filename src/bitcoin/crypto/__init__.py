"""
Bitcoin Crypto Module
=====================

Cryptographic primitives used in Bitcoin:
- SHA256, SHA512, SHA1: Hash functions
- RIPEMD160: For address generation
- HMAC: HMAC-SHA256, HMAC-SHA512
- HKDF: Key derivation
- SipHash: Fast hash for hash tables
- ChaCha20, Poly1305: AEAD encryption
- AES: Block cipher
- MuHash: Multiplicative hash

This module provides both pure Python implementations and wrappers
around optimized C libraries where available.

Copyright (c) 2009-2010 Satoshi Nakamoto
Copyright (c) 2009-present The Bitcoin Core developers
Distributed under the MIT software license.
"""

from .sha256 import (
    SHA256,
    sha256,
    double_sha256,
    SHA256D64,
)

from .sha512 import (
    SHA512,
    sha512,
)

from .ripemd160 import (
    RIPEMD160,
    ripemd160,
)

from .sha1 import (
    SHA1,
    sha1,
)

from .hmac import (
    HMAC_SHA256,
    HMAC_SHA512,
)

from .hkdf import (
    HKDF_SHA256_L32,
)

from .siphash import (
    SipHasher,
    SipHash24,
    PresaltedSipHasher,
)

from .common import (
    ReadLE16,
    ReadLE32,
    ReadLE64,
    WriteLE16,
    WriteLE32,
    WriteLE64,
    ReadBE16,
    ReadBE32,
    ReadBE64,
    WriteBE16,
    WriteBE32,
    WriteBE64,
)

__all__ = [
    # SHA256
    "SHA256",
    "sha256",
    "double_sha256",
    "SHA256D64",
    # SHA512
    "SHA512",
    "sha512",
    # RIPEMD160
    "RIPEMD160",
    "ripemd160",
    # SHA1
    "SHA1",
    "sha1",
    # HMAC
    "HMAC_SHA256",
    "HMAC_SHA512",
    # HKDF
    "HKDF_SHA256_L32",
    # SipHash
    "SipHasher",
    "SipHash24",
    "PresaltedSipHasher",
    # Common
    "ReadLE16",
    "ReadLE32",
    "ReadLE64",
    "WriteLE16",
    "WriteLE32",
    "WriteLE64",
    "ReadBE16",
    "ReadBE32",
    "ReadBE64",
    "WriteBE16",
    "WriteBE32",
    "WriteBE64",
]
