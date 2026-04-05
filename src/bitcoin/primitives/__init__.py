"""
Bitcoin Primitives Module
=========================

This module contains the basic data structures used throughout Bitcoin:
- OutPoint: Reference to a transaction output
- TxIn: Transaction input
- TxOut: Transaction output
- Transaction: Complete transaction
- BlockHeader: Block header
- Block: Complete block
- BlockLocator: For chain synchronization

Copyright (c) 2009-2010 Satoshi Nakamoto
Copyright (c) 2009-present The Bitcoin Core developers
Distributed under the MIT software license.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from .block import Block, BlockHeader, BlockLocator
from .transaction import (
    MutableTransaction,
    OutPoint,
    Transaction,
    TxIn,
    TxOut,
    TransactionWitness,
    Txid,
    Wtxid,
)

__all__ = [
    # Transaction types
    "OutPoint",
    "TxIn",
    "TxOut",
    "Transaction",
    "MutableTransaction",
    "TransactionWitness",
    "Txid",
    "Wtxid",
    # Block types
    "BlockHeader",
    "Block",
    "BlockLocator",
]
