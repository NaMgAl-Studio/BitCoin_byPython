"""
Wallet Transaction Module.

This module provides wallet transaction management, including
transaction state tracking and balance caching.

Reference: Bitcoin Core src/wallet/transaction.h, src/wallet/transaction.cpp
"""

import time
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Set, Any, Tuple
from enum import Enum, auto

from .types import (
    WalletTxState, TxStateConfirmed, TxStateInMempool,
    TxStateBlockConflicted, TxStateInactive, TxStateUnrecognized,
    tx_state_interpret_serialized
)


# Type alias for map values
MapValue = Dict[str, str]


class AmountType(Enum):
    """Amount type enumeration for caching."""
    DEBIT = 0
    CREDIT = 1


@dataclass
class CachableAmount:
    """
    Cachable amount subdivided into avoid reuse and all balances.
    """
    m_avoid_reuse_value: Optional[int] = None
    m_all_value: Optional[int] = None

    def reset(self):
        """Reset cached values."""
        self.m_avoid_reuse_value = None
        self.m_all_value = None

    def set(self, avoid_reuse: bool, value: int):
        """Set cached value."""
        if avoid_reuse:
            self.m_avoid_reuse_value = value
        else:
            self.m_all_value = value

    def get(self, avoid_reuse: bool) -> int:
        """Get cached value."""
        if avoid_reuse:
            assert self.m_avoid_reuse_value is not None
            return self.m_avoid_reuse_value
        assert self.m_all_value is not None
        return self.m_all_value

    def is_cached(self, avoid_reuse: bool) -> bool:
        """Check if value is cached."""
        if avoid_reuse:
            return self.m_avoid_reuse_value is not None
        return self.m_all_value is not None


@dataclass
class CWalletTx:
    """
    A transaction with additional wallet-specific information.

    Includes metadata about the transaction relevant to the wallet,
    such as time received, confirmation state, and balance changes.
    """
    # The actual transaction
    tx: Any  # CTransactionRef
    # Transaction state
    m_state: WalletTxState = field(default_factory=lambda: TxStateInactive())

    # Key/value map with transaction information
    map_value: MapValue = field(default_factory=dict)
    # Order form data (BIP 70/21)
    v_order_form: List[Tuple[str, str]] = field(default_factory=list)
    # Time received by node
    n_time_received: int = 0
    # Stable timestamp that never changes
    n_time_smart: int = 0
    # Position in ordered transaction list
    n_order_pos: int = -1
    # Cached "from me" status
    m_cached_from_me: Optional[bool] = None

    # Memory only - cached amounts
    m_amounts: List[CachableAmount] = field(default_factory=lambda: [
        CachableAmount(), CachableAmount()
    ])
    m_is_cache_empty: bool = True
    f_change_cached: bool = False
    n_change_cached: int = 0

    # Mempool conflicts
    mempool_conflicts: Set[bytes] = field(default_factory=set)

    # TRUC child tracking
    truc_child_in_mempool: Optional[bytes] = None

    def __post_init__(self):
        self.init()

    def init(self):
        """Initialize transaction fields."""
        self.map_value.clear()
        self.v_order_form.clear()
        self.n_time_received = 0
        self.n_time_smart = 0
        self.f_change_cached = False
        self.n_change_cached = 0
        self.n_order_pos = -1
        self.m_is_cache_empty = True
        self.m_cached_from_me = None
        for amount in self.m_amounts:
            amount.reset()

    def get_hash(self) -> bytes:
        """Get the transaction hash (txid)."""
        if hasattr(self.tx, 'get_hash'):
            return self.tx.get_hash()
        return bytes(32)

    def get_witness_hash(self) -> bytes:
        """Get the witness transaction hash (wtxid)."""
        if hasattr(self.tx, 'get_witness_hash'):
            return self.tx.get_witness_hash()
        return self.get_hash()

    def is_coinbase(self) -> bool:
        """Check if this is a coinbase transaction."""
        if hasattr(self.tx, 'is_coinbase'):
            return self.tx.is_coinbase()
        return False

    def mark_dirty(self):
        """Mark all cached data as needing recalculation."""
        for amount in self.m_amounts:
            amount.reset()
        self.f_change_cached = False
        self.m_is_cache_empty = True
        self.m_cached_from_me = None

    def is_equivalent_to(self, other: 'CWalletTx') -> bool:
        """
        Check if two wallet transactions are equivalent.

        They are equivalent if they have the same transaction data
        but possibly different scriptSigs.
        """
        # Compare core transaction properties
        if self.get_hash() != other.get_hash():
            return False
        return True

    def in_mempool(self) -> bool:
        """Check if transaction is in mempool."""
        return isinstance(self.m_state, TxStateInMempool)

    def get_tx_time(self) -> int:
        """Get the transaction time for display purposes."""
        # Use n_time_smart if available, otherwise n_time_received
        return self.n_time_smart if self.n_time_smart else self.n_time_received

    def is_abandoned(self) -> bool:
        """Check if transaction is abandoned."""
        return (isinstance(self.m_state, TxStateInactive) and
                self.m_state.abandoned)

    def is_mempool_conflicted(self) -> bool:
        """Check if there are mempool conflicts."""
        return len(self.mempool_conflicts) > 0

    def is_block_conflicted(self) -> bool:
        """Check if transaction conflicts with a confirmed block."""
        return isinstance(self.m_state, TxStateBlockConflicted)

    def is_inactive(self) -> bool:
        """Check if transaction is inactive."""
        return isinstance(self.m_state, TxStateInactive)

    def is_unconfirmed(self) -> bool:
        """Check if transaction is unconfirmed."""
        return (
            not self.is_abandoned() and
            not self.is_block_conflicted() and
            not self.is_mempool_conflicted() and
            not self.is_confirmed()
        )

    def is_confirmed(self) -> bool:
        """Check if transaction is confirmed."""
        return isinstance(self.m_state, TxStateConfirmed)

    def get_depth_in_main_chain(self) -> int:
        """
        Get depth in main chain.

        Returns:
            <0: conflicts with transaction this deep in chain
             0: in mempool
            >0: this many blocks deep in main chain
        """
        if isinstance(self.m_state, TxStateConfirmed):
            # Return positive depth for confirmed transactions
            # Actual depth would be calculated from current chain height
            return 1  # Placeholder

        if isinstance(self.m_state, TxStateInMempool):
            return 0

        if isinstance(self.m_state, TxStateBlockConflicted):
            return -self.m_state.conflicting_block_height

        if isinstance(self.m_state, TxStateInactive):
            if self.m_state.abandoned:
                return -1
            return 0

        return 0

    def get_blocks_to_maturity(self) -> int:
        """
        Get number of blocks to maturity for coinbase.

        Returns:
            0: not a coinbase or already mature
            >0: blocks until mature
        """
        if not self.is_coinbase():
            return 0

        depth = self.get_depth_in_main_chain()
        if depth < 0:
            return 0

        # Coinbase maturity is 100 blocks
        COINBASE_MATURITY = 100
        return max(0, COINBASE_MATURITY - depth)

    def is_immature_coinbase(self) -> bool:
        """Check if this is an immature coinbase transaction."""
        return self.get_blocks_to_maturity() > 0

    def copy_from(self, other: 'CWalletTx'):
        """Copy data from another wallet transaction."""
        self.tx = other.tx
        self.m_state = other.m_state
        self.map_value = dict(other.map_value)
        self.v_order_form = list(other.v_order_form)
        self.n_time_received = other.n_time_received
        self.n_time_smart = other.n_time_smart
        self.n_order_pos = other.n_order_pos
        self.mempool_conflicts = set(other.mempool_conflicts)
        self.truc_child_in_mempool = other.truc_child_in_mempool
        self.mark_dirty()

    def serialize(self) -> bytes:
        """Serialize for storage."""
        result = bytearray()

        # Serialize transaction (placeholder)
        if hasattr(self.tx, 'serialize'):
            tx_bytes = self.tx.serialize()
            result.extend(len(tx_bytes).to_bytes(4, 'little'))
            result.extend(tx_bytes)
        else:
            result.extend(bytes(4))  # No transaction

        # Serialize state
        if isinstance(self.m_state, TxStateConfirmed):
            result.append(1)
            result.extend(self.m_state.confirmed_block_hash)
            result.extend(self.m_state.confirmed_block_height.to_bytes(4, 'little'))
            result.extend(self.m_state.position_in_block.to_bytes(4, 'little'))
        elif isinstance(self.m_state, TxStateInMempool):
            result.append(2)
        elif isinstance(self.m_state, TxStateBlockConflicted):
            result.append(3)
            result.extend(self.m_state.conflicting_block_hash)
            result.extend(self.m_state.conflicting_block_height.to_bytes(4, 'little'))
        elif isinstance(self.m_state, TxStateInactive):
            result.append(4)
            result.append(1 if self.m_state.abandoned else 0)
        else:
            result.append(0)

        # Serialize map_value
        result.extend(len(self.map_value).to_bytes(4, 'little'))
        for key, value in self.map_value.items():
            key_bytes = key.encode('utf-8')
            value_bytes = value.encode('utf-8')
            result.extend(len(key_bytes).to_bytes(4, 'little'))
            result.extend(key_bytes)
            result.extend(len(value_bytes).to_bytes(4, 'little'))
            result.extend(value_bytes)

        # Serialize timestamps
        result.extend(self.n_time_received.to_bytes(8, 'little'))
        result.extend(self.n_time_smart.to_bytes(8, 'little'))
        result.extend(self.n_order_pos.to_bytes(8, 'little'))

        return bytes(result)

    @classmethod
    def deserialize(cls, data: bytes) -> 'CWalletTx':
        """Deserialize from storage."""
        offset = 0

        # Deserialize transaction
        tx_len = int.from_bytes(data[offset:offset+4], 'little')
        offset += 4
        tx_data = data[offset:offset+tx_len]
        offset += tx_len

        # Deserialize state
        state_type = data[offset]
        offset += 1

        if state_type == 1:
            block_hash = data[offset:offset+32]
            offset += 32
            block_height = int.from_bytes(data[offset:offset+4], 'little')
            offset += 4
            position = int.from_bytes(data[offset:offset+4], 'little')
            offset += 4
            state = TxStateConfirmed(block_hash, block_height, position)
        elif state_type == 2:
            state = TxStateInMempool()
        elif state_type == 3:
            block_hash = data[offset:offset+32]
            offset += 32
            block_height = int.from_bytes(data[offset:offset+4], 'little')
            offset += 4
            state = TxStateBlockConflicted(block_hash, block_height)
        elif state_type == 4:
            abandoned = data[offset] == 1
            offset += 1
            state = TxStateInactive(abandoned)
        else:
            state = TxStateInactive()

        # Create instance
        wtx = cls(tx=None, m_state=state)

        # Deserialize map_value
        map_len = int.from_bytes(data[offset:offset+4], 'little')
        offset += 4
        for _ in range(map_len):
            key_len = int.from_bytes(data[offset:offset+4], 'little')
            offset += 4
            key = data[offset:offset+key_len].decode('utf-8')
            offset += key_len
            value_len = int.from_bytes(data[offset:offset+4], 'little')
            offset += 4
            value = data[offset:offset+value_len].decode('utf-8')
            offset += value_len
            wtx.map_value[key] = value

        # Deserialize timestamps
        wtx.n_time_received = int.from_bytes(data[offset:offset+8], 'little')
        offset += 8
        wtx.n_time_smart = int.from_bytes(data[offset:offset+8], 'little')
        offset += 8
        wtx.n_order_pos = int.from_bytes(data[offset:offset+8], 'little')

        return wtx


@dataclass
class WalletTXO:
    """
    Wallet transaction output.

    Represents a specific output owned by the wallet.
    """
    wtx: CWalletTx
    output: Any  # CTxOut
    output_index: int

    def get_wallet_tx(self) -> CWalletTx:
        """Get the wallet transaction."""
        return self.wtx

    def get_tx_out(self) -> Any:
        """Get the transaction output."""
        return self.output


class WalletTxOrderComparator:
    """Comparator for ordering wallet transactions by position."""

    def __call__(self, a: CWalletTx, b: CWalletTx) -> bool:
        return a.n_order_pos < b.n_order_pos


@dataclass
class TxSpends:
    """
    Tracking of spent outpoints.

    Maps outpoints to the transactions that spend them.
    """
    # Map from outpoint to txid
    spends: Dict[bytes, bytes] = field(default_factory=dict)

    def add(self, outpoint: bytes, txid: bytes):
        """Add a spend mapping."""
        self.spends[outpoint] = txid

    def get(self, outpoint: bytes) -> Optional[bytes]:
        """Get the txid that spends an outpoint."""
        return self.spends.get(outpoint)

    def remove(self, outpoint: bytes):
        """Remove a spend mapping."""
        self.spends.pop(outpoint, None)

    def __contains__(self, outpoint: bytes) -> bool:
        return outpoint in self.spends

    def __iter__(self):
        return iter(self.spends.items())


# Helper functions for transaction state

def tx_state_string(state: WalletTxState) -> str:
    """Get string representation of transaction state."""
    if isinstance(state, TxStateConfirmed):
        return f"Confirmed (block={state.confirmed_block_hash.hex()[:16]}..., height={state.confirmed_block_height}, index={state.position_in_block})"
    elif isinstance(state, TxStateInMempool):
        return "InMempool"
    elif isinstance(state, TxStateBlockConflicted):
        return f"BlockConflicted (block={state.conflicting_block_hash.hex()[:16]}..., height={state.conflicting_block_height})"
    elif isinstance(state, TxStateInactive):
        return f"Inactive (abandoned={state.abandoned})"
    elif isinstance(state, TxStateUnrecognized):
        return f"Unrecognized (block={state.block_hash.hex()[:16]}..., index={state.index})"
    return "Unknown"


def compute_time_smart(wtx: CWalletTx, rescanning_old_block: bool = False) -> int:
    """
    Compute the nTimeSmart value for a transaction.

    This is a stable timestamp that reflects when the transaction
    was added to the wallet, adjusted for proper ordering.
    """
    # Start with time received
    time_smart = wtx.n_time_received

    # If confirmed, use block time if available
    if isinstance(wtx.m_state, TxStateConfirmed):
        # Block time would come from chain interface
        pass

    return time_smart
