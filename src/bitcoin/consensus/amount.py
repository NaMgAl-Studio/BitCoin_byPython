"""
Bitcoin Amount Types and Constants
==================================

This module defines the amount type and constants used throughout Bitcoin:
- CAmount: Type alias for amounts in satoshis
- COIN: Number of satoshis in one BTC
- MAX_MONEY: Maximum valid amount
- MoneyRange: Function to validate amount range

Corresponds to Bitcoin Core's src/consensus/amount.h

Copyright (c) 2009-2010 Satoshi Nakamoto
Copyright (c) 2009-present The Bitcoin Core developers
Distributed under the MIT software license.
"""

from __future__ import annotations

from typing import TypeAlias

# Amount in satoshis (Can be negative)
CAmount: TypeAlias = int

# The amount of satoshis in one BTC
COIN: CAmount = 100_000_000  # 100 million satoshis = 1 BTC

# No amount larger than this (in satoshi) is valid.
#
# Note that this constant is *not* the total money supply, which in Bitcoin
# currently happens to be less than 21,000,000 BTC for various reasons, but
# rather a sanity check. As this sanity check is used by consensus-critical
# validation code, the exact value of the MAX_MONEY constant is consensus
# critical; in unusual circumstances like a(nother) overflow bug that allowed
# for the creation of coins out of thin air modification could lead to a fork.
MAX_MONEY: CAmount = 21_000_000 * COIN  # 21 million BTC in satoshis


def MoneyRange(n_value: CAmount) -> bool:
    """
    Check if an amount is within valid range.
    
    Args:
        n_value: The amount in satoshis
        
    Returns:
        True if 0 <= n_value <= MAX_MONEY
    """
    return 0 <= n_value <= MAX_MONEY


def satoshis_to_btc(satoshis: CAmount) -> float:
    """Convert satoshis to BTC."""
    return satoshis / COIN


def btc_to_satoshis(btc: float) -> CAmount:
    """Convert BTC to satoshis."""
    return int(btc * COIN)


def format_amount(amount: CAmount, decimals: int = 8) -> str:
    """
    Format an amount in BTC with specified decimal places.
    
    Args:
        amount: Amount in satoshis
        decimals: Number of decimal places (default 8 for BTC)
        
    Returns:
        Formatted string like "1.23456789"
    """
    btc_value = amount / COIN
    return f"{btc_value:.{decimals}f}"


def parse_amount(amount_str: str) -> CAmount:
    """
    Parse a BTC amount string to satoshis.
    
    Args:
        amount_str: String like "1.5" or "0.001"
        
    Returns:
        Amount in satoshis
        
    Raises:
        ValueError: If the string is not a valid amount
    """
    try:
        btc_value = float(amount_str)
        if btc_value < 0:
            raise ValueError("Amount cannot be negative")
        satoshis = int(btc_value * COIN)
        if satoshis > MAX_MONEY:
            raise ValueError(f"Amount exceeds MAX_MONEY ({MAX_MONEY} satoshis)")
        return satoshis
    except (ValueError, TypeError) as e:
        raise ValueError(f"Invalid amount string: {amount_str}") from e
