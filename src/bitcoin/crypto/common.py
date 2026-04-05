"""
Common byte manipulation utilities.

These functions are used throughout the Bitcoin codebase for
reading and writing integers in little-endian and big-endian formats.

Reference: Bitcoin Core src/crypto/common.h
"""

import struct
from typing import Tuple


def ReadLE16(data: bytes, offset: int = 0) -> int:
    """Read a 16-bit little-endian integer from bytes."""
    return struct.unpack_from('<H', data, offset)[0]


def ReadLE32(data: bytes, offset: int = 0) -> int:
    """Read a 32-bit little-endian integer from bytes."""
    return struct.unpack_from('<I', data, offset)[0]


def ReadLE64(data: bytes, offset: int = 0) -> int:
    """Read a 64-bit little-endian integer from bytes."""
    return struct.unpack_from('<Q', data, offset)[0]


def WriteLE16(value: int) -> bytes:
    """Write a 16-bit integer as little-endian bytes."""
    return struct.pack('<H', value)


def WriteLE32(value: int) -> bytes:
    """Write a 32-bit integer as little-endian bytes."""
    return struct.pack('<I', value)


def WriteLE64(value: int) -> bytes:
    """Write a 64-bit integer as little-endian bytes."""
    return struct.pack('<Q', value)


def ReadBE16(data: bytes, offset: int = 0) -> int:
    """Read a 16-bit big-endian integer from bytes."""
    return struct.unpack_from('>H', data, offset)[0]


def ReadBE32(data: bytes, offset: int = 0) -> int:
    """Read a 32-bit big-endian integer from bytes."""
    return struct.unpack_from('>I', data, offset)[0]


def ReadBE64(data: bytes, offset: int = 0) -> int:
    """Read a 64-bit big-endian integer from bytes."""
    return struct.unpack_from('>Q', data, offset)[0]


def WriteBE16(value: int) -> bytes:
    """Write a 16-bit integer as big-endian bytes."""
    return struct.pack('>H', value)


def WriteBE32(value: int) -> bytes:
    """Write a 32-bit integer as big-endian bytes."""
    return struct.pack('>I', value)


def WriteBE64(value: int) -> bytes:
    """Write a 64-bit integer as big-endian bytes."""
    return struct.pack('>Q', value)
