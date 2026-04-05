"""
Bitcoin Utility Module
=======================

Utility functions and classes used throughout Bitcoin:
- String encoding/decoding (hex, base64, base32)
- Time utilities
- String manipulation
- Memory and system utilities

Copyright (c) 2009-2010 Satoshi Nakamoto
Copyright (c) 2009-present The Bitcoin Core developers
Distributed under the MIT software license.
"""

from .strencodings import (
    HexStr,
    hex_to_bytes,
    bytes_to_hex,
    ParseHex,
    TryParseHex,
    IsHex,
    EncodeBase64,
    DecodeBase64,
    EncodeBase32,
    DecodeBase32,
    SanitizeString,
    IsSpace,
    IsDigit,
    ToLower,
    ToUpper,
    Capitalize,
    TimingResistantEqual,
    ConvertBits,
)

from .time import (
    NodeSeconds,
    SteadyClock,
    SystemClock,
    TimeArgs,
    GetTime,
    GetTimeMillis,
    GetTimeMicros,
    GetLogTimeMicros,
    ParseISO8601DateTime,
    FormatISO8601DateTime,
)

from .string import (
    TrimString,
    TrimStringView,
    RemovePrefix,
    RemovePrefixView,
    SplitString,
    JoinStrings,
)

__all__ = [
    # String encodings
    "HexStr",
    "hex_to_bytes",
    "bytes_to_hex",
    "ParseHex",
    "TryParseHex",
    "IsHex",
    "EncodeBase64",
    "DecodeBase64",
    "EncodeBase32",
    "DecodeBase32",
    "SanitizeString",
    "IsSpace",
    "IsDigit",
    "ToLower",
    "ToUpper",
    "Capitalize",
    "TimingResistantEqual",
    "ConvertBits",
    # Time
    "NodeSeconds",
    "SteadyClock",
    "SystemClock",
    "TimeArgs",
    "GetTime",
    "GetTimeMillis",
    "GetTimeMicros",
    "GetLogTimeMicros",
    "ParseISO8601DateTime",
    "FormatISO8601DateTime",
    # String
    "TrimString",
    "TrimStringView",
    "RemovePrefix",
    "RemovePrefixView",
    "SplitString",
    "JoinStrings",
]
