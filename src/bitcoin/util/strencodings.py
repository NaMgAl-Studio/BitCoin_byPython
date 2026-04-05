"""
Bitcoin String Encoding Utilities
===================================

This module provides string encoding and decoding utilities:
- Hex encoding/decoding
- Base64 encoding/decoding
- Base32 encoding/decoding
- String sanitization
- Timing-resistant comparison

Corresponds to Bitcoin Core's src/util/strencodings.h

Copyright (c) 2009-2010 Satoshi Nakamoto
Copyright (c) 2009-present The Bitcoin Core developers
Distributed under the MIT software license.
"""

from __future__ import annotations

import base64
from typing import Callable, Generic, Iterable, Iterator, List, Optional, TypeVar, Union


# =============================================================================
# Type Definitions
# =============================================================================

T = TypeVar('T')
Byte = Union[bytes, bytearray]


def HexStr(data: bytes, *, reverse: bool = False) -> str:
    """
    Convert bytes to hex string.
    
    Args:
        data: Bytes to convert
        reverse: If True, reverse bytes before converting (Bitcoin convention)
        
    Returns:
        Lowercase hex string
    """
    if reverse:
        return data[::-1].hex()
    return data.hex()


def hex_to_bytes(hex_str: str, *, reverse: bool = False) -> bytes:
    """
    Convert hex string to bytes.
    
    Args:
        hex_str: Hex string to convert
        reverse: If True, reverse bytes after converting (Bitcoin convention)
        
    Returns:
        Bytes
    """
    data = bytes.fromhex(hex_str)
    if reverse:
        return data[::-1]
    return data


def ParseHex(hex_str: str) -> bytes:
    """
    Parse a hex string into bytes, ignoring whitespace.
    
    Args:
        hex_str: Hex string (may contain whitespace)
        
    Returns:
        Bytes, or empty bytes on error
    """
    result = TryParseHex(hex_str)
    return result if result is not None else b''


def TryParseHex(hex_str: str) -> Optional[bytes]:
    """
    Try to parse a hex string into bytes, ignoring whitespace.
    
    Args:
        hex_str: Hex string (may contain whitespace)
        
    Returns:
        Bytes on success, None on error
    """
    # Remove whitespace
    clean = ''.join(c for c in hex_str if not IsSpace(c))
    
    # Check for valid hex
    if len(clean) % 2 != 0:
        return None
    
    try:
        return bytes.fromhex(clean)
    except ValueError:
        return None


def IsHex(hex_str: str) -> bool:
    """
    Check if string is a valid hex string with even length.
    
    Args:
        hex_str: String to check
        
    Returns:
        True if valid hex string with even length
    """
    # Must have even length and all hex digits
    if len(hex_str) == 0:
        return False
    
    # Remove whitespace for check
    clean = ''.join(c for c in hex_str if not IsSpace(c))
    
    if len(clean) % 2 != 0:
        return False
    
    return all(c in '0123456789abcdefABCDEF' for c in clean)


# =============================================================================
# Base64 Encoding/Decoding
# =============================================================================

# Base64 alphabet
BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def EncodeBase64(data: bytes) -> str:
    """
    Encode bytes to Base64 string.
    
    Args:
        data: Bytes to encode
        
    Returns:
        Base64 encoded string
    """
    return base64.b64encode(data).decode('ascii')


def DecodeBase64(encoded: str) -> Optional[bytes]:
    """
    Decode Base64 string to bytes.
    
    Args:
        encoded: Base64 encoded string
        
    Returns:
        Decoded bytes, or None on error
    """
    try:
        return base64.b64decode(encoded)
    except Exception:
        return None


# =============================================================================
# Base32 Encoding/Decoding
# =============================================================================

# Base32 alphabet
BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"


def EncodeBase32(data: bytes, pad: bool = True) -> str:
    """
    Encode bytes to Base32 string.
    
    Args:
        data: Bytes to encode
        pad: If True, pad output with '=' to multiple of 8
        
    Returns:
        Base32 encoded string
    """
    result = base64.b32encode(data).decode('ascii').lower()
    if not pad:
        result = result.rstrip('=')
    return result


def DecodeBase32(encoded: str) -> Optional[bytes]:
    """
    Decode Base32 string to bytes.
    
    Args:
        encoded: Base32 encoded string
        
    Returns:
        Decoded bytes, or None on error
    """
    try:
        # Pad if necessary
        padding = (8 - len(encoded) % 8) % 8
        encoded = encoded.upper() + '=' * padding
        return base64.b32decode(encoded)
    except Exception:
        return None


# =============================================================================
# String Utilities
# =============================================================================

# Safe character sets for sanitization
SAFE_CHARS_DEFAULT = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,;-_/:?@()"
)
SAFE_CHARS_UA_COMMENT = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,;-_?@"
)
SAFE_CHARS_FILENAME = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"
)
SAFE_CHARS_URI = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!'()*;:@&=+$,/?#[]-_.~%"
)


def SanitizeString(s: str, rule: int = 0) -> str:
    """
    Remove unsafe characters from string.
    
    Args:
        s: String to sanitize
        rule: Which character set to use:
            0 = SAFE_CHARS_DEFAULT
            1 = SAFE_CHARS_UA_COMMENT
            2 = SAFE_CHARS_FILENAME
            3 = SAFE_CHARS_URI
            
    Returns:
        Sanitized string
    """
    safe_chars = [
        SAFE_CHARS_DEFAULT,
        SAFE_CHARS_UA_COMMENT,
        SAFE_CHARS_FILENAME,
        SAFE_CHARS_URI,
    ][rule]
    
    return ''.join(c for c in s if c in safe_chars)


def IsSpace(c: str) -> bool:
    """
    Check if character is whitespace.
    
    This function is locale independent.
    Whitespace: space, form-feed, newline, carriage return, tab, vertical tab.
    """
    return c in ' \f\n\r\t\v'


def IsDigit(c: str) -> bool:
    """Check if character is a decimal digit."""
    return '0' <= c <= '9'


def ToLower(c: str) -> str:
    """
    Convert character to lowercase (locale independent).
    
    Only converts uppercase ASCII letters.
    """
    if 'A' <= c <= 'Z':
        return chr(ord(c) - ord('A') + ord('a'))
    return c


def ToUpper(c: str) -> str:
    """
    Convert character to uppercase (locale independent).
    
    Only converts lowercase ASCII letters.
    """
    if 'a' <= c <= 'z':
        return chr(ord(c) - ord('a') + ord('A'))
    return c


def Capitalize(s: str) -> str:
    """Capitalize first character of string."""
    if not s:
        return s
    return ToUpper(s[0]) + s[1:]


def ToLowerString(s: str) -> str:
    """Convert entire string to lowercase."""
    return ''.join(ToLower(c) for c in s)


def ToUpperString(s: str) -> str:
    """Convert entire string to uppercase."""
    return ''.join(ToUpper(c) for c in s)


# =============================================================================
# Timing-Resistant Comparison
# =============================================================================

def TimingResistantEqual(a: bytes, b: bytes) -> bool:
    """
    Timing-attack-resistant comparison.
    
    Takes time proportional to length of first argument.
    This prevents timing attacks on cryptographic comparisons.
    
    Args:
        a: First byte sequence
        b: Second byte sequence
        
    Returns:
        True if equal, False otherwise
    """
    if len(b) == 0:
        return len(a) == 0
    
    accumulator = len(a) ^ len(b)
    for i, byte in enumerate(a):
        accumulator |= byte ^ b[i % len(b)]
    
    return accumulator == 0


# =============================================================================
# Bit Conversion
# =============================================================================

def ConvertBits(
    from_bits: int,
    to_bits: int,
    pad: bool,
    input_data: Iterable[int],
    input_fn: Callable[[int], int] = lambda x: x
) -> Optional[List[int]]:
    """
    Convert from one power-of-2 number base to another.
    
    Args:
        from_bits: Source bit width (e.g., 8 for bytes)
        to_bits: Target bit width (e.g., 5 for Base32)
        pad: Whether to pad incomplete groups
        input_data: Input values
        input_fn: Optional transform function for input
        
    Returns:
        List of output values, or None on error
    """
    acc = 0
    bits = 0
    maxv = (1 << to_bits) - 1
    max_acc = (1 << (from_bits + to_bits - 1)) - 1
    result: List[int] = []
    
    for value in input_data:
        v = input_fn(value)
        if v < 0:
            return None
        
        acc = ((acc << from_bits) | v) & max_acc
        bits += from_bits
        
        while bits >= to_bits:
            bits -= to_bits
            result.append((acc >> bits) & maxv)
    
    if pad:
        if bits:
            result.append((acc << (to_bits - bits)) & maxv)
    elif bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
        return None
    
    return result


# =============================================================================
# Hex Digit Lookup
# =============================================================================

def HexDigit(c: str) -> int:
    """
    Convert a hex character to its numeric value.
    
    Args:
        c: Single hex character
        
    Returns:
        Numeric value (0-15), or -1 if invalid
    """
    if '0' <= c <= '9':
        return ord(c) - ord('0')
    if 'a' <= c <= 'f':
        return ord(c) - ord('a') + 10
    if 'A' <= c <= 'F':
        return ord(c) - ord('A') + 10
    return -1


# =============================================================================
# Fixed Point Parsing
# =============================================================================

def ParseFixedPoint(value: str, decimals: int) -> Optional[int]:
    """
    Parse number as fixed point according to JSON number syntax.
    
    Args:
        value: String to parse
        decimals: Number of decimal places
        
    Returns:
        Fixed point integer value, or None on error
    """
    import re
    
    # JSON number pattern
    pattern = r'^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$'
    if not re.match(pattern, value):
        return None
    
    try:
        # Parse as float and convert to fixed point
        f = float(value)
        result = int(f * (10 ** decimals))
        
        # Check range
        upper_bound = 10 ** 18 - 1
        if result > upper_bound or result < -upper_bound:
            return None
        
        return result
    except (ValueError, OverflowError):
        return None
