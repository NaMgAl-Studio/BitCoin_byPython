# Copyright (c) 2009-2010 Satoshi Nakamoto
# Copyright (c) 2009-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Bitcoin Coins (UTXO) Module

This module implements UTXO (Unspent Transaction Output) management:
- Coin: A single UTXO entry
- CoinsView: Abstract view of UTXO dataset
- CoinsViewCache: Cached view with modification tracking
"""

from .coins import (
    # Classes
    Coin,
    COIN_EMPTY,
    CoinsCacheEntry,
    CacheFlags,
    CoinsView,
    CoinsViewBacked,
    CoinsViewCache,
    
    # Functions
    AddCoins,
    AccessByTxid,
)

__all__ = [
    'Coin',
    'COIN_EMPTY',
    'CoinsCacheEntry',
    'CacheFlags',
    'CoinsView',
    'CoinsViewBacked',
    'CoinsViewCache',
    'AddCoins',
    'AccessByTxid',
]
