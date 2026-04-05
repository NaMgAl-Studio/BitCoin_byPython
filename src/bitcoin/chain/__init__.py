# Copyright (c) 2009-2010 Satoshi Nakamoto
# Copyright (c) 2009-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Bitcoin Chain Module

This module implements blockchain data structures and management:
- BlockIndex: Index for a block in the chain
- Chain: Active chain management
- ChainState: Chain state tracking
- BlockManager: Block storage and chain selection
"""

from .chain import (
    # Classes
    BlockStatus,
    CBlockIndex,
    CChain,
    ChainState,
    BlockManager,
)

__all__ = [
    'BlockStatus',
    'CBlockIndex',
    'CChain',
    'ChainState',
    'BlockManager',
]
