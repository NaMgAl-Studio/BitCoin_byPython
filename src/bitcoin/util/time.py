"""
Bitcoin Time Utilities
======================

Time-related utilities for Bitcoin:
- Node time types
- Clock interfaces
- ISO 8601 date/time parsing

Corresponds to Bitcoin Core's src/util/time.h

Copyright (c) 2009-2010 Satoshi Nakamoto
Copyright (c) 2009-present The Bitcoin Core developers
Distributed under the MIT software license.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional, Protocol


# =============================================================================
# Time Types
# =============================================================================

@dataclass(frozen=True)
class NodeSeconds:
    """
    Type-safe wrapper for node time in seconds.
    
    This provides type safety for time values to prevent
    confusion with milliseconds or microseconds.
    """
    seconds: int
    
    def __int__(self) -> int:
        return self.seconds
    
    def __float__(self) -> float:
        return float(self.seconds)


@dataclass(frozen=True)
class SteadySeconds:
    """Steady clock time (monotonic, never goes backward)."""
    seconds: int


# =============================================================================
# Clock Interface
# =============================================================================

class ClockProtocol(Protocol):
    """Protocol for clock implementations."""
    
    def now(self) -> NodeSeconds:
        """Get current time."""
        ...


class SystemClock:
    """
    System clock implementation.
    
    Returns the actual system time.
    """
    
    @staticmethod
    def now() -> NodeSeconds:
        """Get current system time in seconds since epoch."""
        return NodeSeconds(int(time.time()))


class SteadyClock:
    """
    Steady (monotonic) clock implementation.
    
    This clock never goes backward and is not affected by
    system time changes.
    """
    
    @staticmethod
    def now() -> SteadySeconds:
        """Get current steady clock time."""
        return SteadySeconds(int(time.monotonic()))


# =============================================================================
# Time Argument (for mocking in tests)
# =============================================================================

TimeArgs = Callable[[], NodeSeconds]

def GetTime() -> int:
    """
    Get current time in seconds since epoch.
    
    Returns:
        Unix timestamp in seconds
    """
    return int(time.time())


def GetTimeMillis() -> int:
    """
    Get current time in milliseconds since epoch.
    
    Returns:
        Unix timestamp in milliseconds
    """
    return int(time.time() * 1000)


def GetTimeMicros() -> int:
    """
    Get current time in microseconds since epoch.
    
    Returns:
        Unix timestamp in microseconds
    """
    return int(time.time() * 1_000_000)


def GetLogTimeMicros() -> int:
    """
    Get log time in microseconds.
    
    This can be mocked for testing.
    
    Returns:
        Time in microseconds
    """
    return GetTimeMicros()


# =============================================================================
# ISO 8601 Date/Time Parsing
# =============================================================================

def ParseISO8601DateTime(date_str: str) -> Optional[int]:
    """
    Parse an ISO 8601 formatted date/time string to Unix timestamp.
    
    Args:
        date_str: ISO 8601 formatted string (e.g., "2024-01-15T12:30:45Z")
        
    Returns:
        Unix timestamp in seconds, or None on parse error
    """
    formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]
    
    for fmt in formats:
        try:
            dt = datetime.strptime(date_str, fmt)
            # If no timezone, assume UTC
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp())
        except ValueError:
            continue
    
    return None


def FormatISO8601DateTime(timestamp: int) -> str:
    """
    Format Unix timestamp as ISO 8601 string.
    
    Args:
        timestamp: Unix timestamp in seconds
        
    Returns:
        ISO 8601 formatted string (e.g., "2024-01-15T12:30:45Z")
    """
    dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def FormatISO8601DateTimeMsec(timestamp_msec: int) -> str:
    """
    Format Unix timestamp with milliseconds as ISO 8601 string.
    
    Args:
        timestamp_msec: Unix timestamp in milliseconds
        
    Returns:
        ISO 8601 formatted string with milliseconds
    """
    seconds = timestamp_msec // 1000
    msec = timestamp_msec % 1000
    dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    return dt.strftime(f"%Y-%m-%dT%H:%M:%S.{msec:03d}Z")


# =============================================================================
# Duration Helpers
# =============================================================================

def Hours(hours: int) -> int:
    """Convert hours to seconds."""
    return hours * 3600


def Minutes(minutes: int) -> int:
    """Convert minutes to seconds."""
    return minutes * 60


def Milliseconds(msec: int) -> int:
    """Convert milliseconds to microseconds."""
    return msec * 1000


def Microseconds(usec: int) -> int:
    """Return microseconds as-is."""
    return usec
