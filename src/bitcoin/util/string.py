"""
Bitcoin String Utilities
========================

String manipulation utilities.

Corresponds to Bitcoin Core's src/util/string.h

Copyright (c) 2009-2010 Satoshi Nakamoto
Copyright (c) 2009-present The Bitcoin Core developers
Distributed under the MIT software license.
"""

from __future__ import annotations

from typing import List, Optional


def TrimString(s: str) -> str:
    """
    Trim whitespace from both ends of string.
    
    Args:
        s: String to trim
        
    Returns:
        Trimmed string
    """
    return s.strip()


def TrimStringView(s: str) -> str:
    """
    Trim whitespace from both ends of string (view version).
    
    Args:
        s: String to trim
        
    Returns:
        Trimmed string view
    """
    return s.strip()


def RemovePrefix(s: str, prefix: str) -> str:
    """
    Remove prefix from string if present.
    
    Args:
        s: String to process
        prefix: Prefix to remove
        
    Returns:
        String with prefix removed if it was present
    """
    if s.startswith(prefix):
        return s[len(prefix):]
    return s


def RemovePrefixView(s: str, prefix: str) -> str:
    """
    Remove prefix from string view if present.
    
    Args:
        s: String to process
        prefix: Prefix to remove
        
    Returns:
        String with prefix removed if it was present
    """
    if s.startswith(prefix):
        return s[len(prefix):]
    return s


def SplitString(s: str, delimiter: str = " ", maxsplit: int = -1) -> List[str]:
    """
    Split string by delimiter.
    
    Args:
        s: String to split
        delimiter: Delimiter character(s)
        maxsplit: Maximum number of splits (-1 for unlimited)
        
    Returns:
        List of substrings
    """
    return s.split(delimiter, maxsplit)


def JoinStrings(strings: List[str], delimiter: str = " ") -> str:
    """
    Join strings with delimiter.
    
    Args:
        strings: List of strings to join
        delimiter: Delimiter to use
        
    Returns:
        Joined string
    """
    return delimiter.join(strings)


def FormatParagraph(s: str, width: int = 79, indent: int = 0) -> str:
    """
    Format a paragraph of text to a fixed width.
    
    Args:
        s: Input string
        width: Maximum line width
        indent: Indentation for wrapped lines
        
    Returns:
        Formatted paragraph
    """
    if width < indent:
        raise ValueError("Width must be >= indent")
    
    lines = []
    for paragraph in s.split('\n'):
        if len(paragraph) <= width:
            lines.append(paragraph)
            continue
        
        remaining_width = width
        words = paragraph.split(' ')
        current_line = []
        
        for word in words:
            if current_line:
                # +1 for space
                if len(word) + sum(len(w) for w in current_line) + len(current_line) <= remaining_width:
                    current_line.append(word)
                else:
                    lines.append(' '.join(current_line))
                    current_line = [word]
                    remaining_width = width - indent
            else:
                if len(word) <= remaining_width:
                    current_line.append(word)
                else:
                    # Word is too long, break it
                    while len(word) > remaining_width:
                        lines.append(' ' * indent + word[:remaining_width])
                        word = word[remaining_width:]
                        remaining_width = width - indent
                    if word:
                        current_line = [word]
        
        if current_line:
            lines.append(' '.join(current_line))
    
    return '\n'.join(lines)


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
