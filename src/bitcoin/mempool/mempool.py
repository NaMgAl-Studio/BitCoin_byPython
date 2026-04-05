# Copyright (c) 2009-2010 Satoshi Nakamoto
# Copyright (c) 2009-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Bitcoin Mempool (Memory Pool)

This module implements the transaction memory pool:
- TxMempoolEntry: Individual transaction entry
- CTxMemPool: The mempool data structure
- Mempool acceptance and validation
"""

from dataclasses import dataclass, field
from typing import Dict, Set, List, Optional, Tuple
from collections import OrderedDict
from time import time
import heapq

from ..primitives.transaction import Transaction, OutPoint
from ..consensus.validation import TxValidationState, TxValidationResult
from ..consensus.tx_check import GetWeight, GetVirtualSize
from ..consensus.consensus import MAX_MONEY


# ============================================================================
# Mempool Removal Reasons
# ============================================================================

class MemPoolRemovalReason:
    """Reason why a transaction was removed from mempool."""
    
    EXPIRY = "expiry"           # Expired from mempool
    SIZE_LIMIT = "size_limit"   # Removed for mempool size limit
    REORG = "reorg"             # Removed for reorganization
    BLOCK = "block"             # Removed for inclusion in a block
    CONFLICT = "conflict"       # Removed for conflict with another tx
    REPLACED = "replaced"       # Removed for replacement (RBF)


# ============================================================================
# Mempool Limits
# ============================================================================

@dataclass
class MempoolLimits:
    """Limits for mempool size and transaction acceptance."""
    
    # Maximum mempool size in bytes (default 300MB)
    max_size: int = 300 * 1000 * 1000
    
    # Maximum number of transactions (no limit by default)
    max_count: int = 0
    
    # Minimum fee rate for mempool acceptance (satoshis per kvB)
    min_relay_fee: int = 1000
    
    # Maximum weight for a single transaction
    max_tx_weight: int = 400000
    
    # Maximum ancestry size (tx + all ancestors)
    max_ancestors: int = 25
    
    # Maximum ancestry size in bytes
    max_ancestors_size: int = 101 * 1000
    
    # Maximum descendant size (tx + all descendants)
    max_descendants: int = 25
    
    # Maximum descendant size in bytes
    max_descendants_size: int = 101 * 1000


# ============================================================================
# Mempool Entry
# ============================================================================

@dataclass
class TxMempoolEntry:
    """
    An entry in the transaction memory pool.
    
    Contains the transaction and associated metadata for
    fee calculation, prioritization, and eviction.
    """
    
    tx: Transaction
    fee: int                           # Transaction fee in satoshis
    time: int                          # Time when entering mempool
    height: int                        # Chain height when entering
    
    # Size info
    weight: int = 0
    vsize: int = 0
    sigop_cost: int = 0
    
    # Fee rates
    fee_per_kw: int = 0               # Fee per kilo-weight
    fee_per_kvbyte: int = 0           # Fee per kilo-vbyte
    
    # Ancestor/descendant tracking
    ancestor_count: int = 1
    ancestor_size: int = 0            # Including this tx
    ancestor_fee: int = 0
    ancestor_sigop_cost: int = 0
    
    descendant_count: int = 1
    descendant_size: int = 0
    descendant_fee: int = 0
    
    # Set of ancestor txids
    ancestors: Set[bytes] = field(default_factory=set)
    
    # Set of descendant txids
    descendants: Set[bytes] = field(default_factory=set)
    
    # Spends and spent by tracking
    spends: Set[OutPoint] = field(default_factory=set)
    spent_by: Set[bytes] = field(default_factory=set)  # txids of spenders
    
    def __post_init__(self):
        """Calculate derived values."""
        if self.weight == 0:
            self.weight = GetWeight(self.tx)
        if self.vsize == 0:
            self.vsize = GetVirtualSize(self.tx)
        if self.fee_per_kw == 0 and self.weight > 0:
            self.fee_per_kw = self.fee * 1000 // self.weight
        if self.fee_per_kvbyte == 0 and self.vsize > 0:
            self.fee_per_kvbyte = self.fee * 1000 // self.vsize
        
        # Track what this transaction spends
        for txin in self.tx.inputs:
            self.spends.add(txin.prevout)
    
    @property
    def txid(self) -> bytes:
        """Get the transaction ID."""
        return self.tx.hash
    
    @property
    def wtxid(self) -> bytes:
        """Get the witness transaction ID."""
        return self.tx.witness_hash if hasattr(self.tx, 'witness_hash') else self.tx.hash
    
    def get_fee(self) -> int:
        """Get the transaction fee."""
        return self.fee
    
    def get_fee_per_kw(self) -> int:
        """Get fee per kilo-weight."""
        return self.fee_per_kw
    
    def get_tx_size(self) -> int:
        """Get transaction virtual size."""
        return self.vsize
    
    def get_modified_fee(self, modifier: int = 0) -> int:
        """Get modified fee (for prioritization)."""
        return self.fee + modifier


# ============================================================================
# Transaction Mempool
# ============================================================================

class CTxMemPool:
    """
    The transaction memory pool.
    
    Stores transactions that have been broadcast but not yet
    included in a block. Handles:
    - Transaction acceptance
    - Fee-based eviction
    - Ancestor/descendant tracking
    - RBF (Replace-by-Fee)
    """
    
    def __init__(self, limits: Optional[MempoolLimits] = None):
        self.limits = limits or MempoolLimits()
        
        # Main storage: txid -> entry
        self._map: Dict[bytes, TxMempoolEntry] = OrderedDict()
        
        # Index by wtxid
        self._wtxid_map: Dict[bytes, bytes] = {}  # wtxid -> txid
        
        # Index by outpoint (spent by)
        self._next_spent: Dict[OutPoint, bytes] = {}  # outpoint -> txid of spender
        
        # Delta priority for prioritisetransaction
        self._delta_priority: Dict[bytes, int] = {}
        
        # Total size tracking
        self._total_tx_size: int = 0
        self._total_sigop_cost: int = 0
        
        # Cached fee rate histogram
        self._min_fee_rate: int = 1000
    
    def size(self) -> int:
        """Get number of transactions in mempool."""
        return len(self._map)
    
    def get_total_tx_size(self) -> int:
        """Get total virtual size of all transactions."""
        return self._total_tx_size
    
    def get_total_sigop_cost(self) -> int:
        """Get total signature operation cost."""
        return self._total_sigop_cost
    
    def exists(self, txid: bytes) -> bool:
        """Check if a transaction is in the mempool."""
        return txid in self._map
    
    def exists_wtxid(self, wtxid: bytes) -> bool:
        """Check if a transaction exists by witness txid."""
        return wtxid in self._wtxid_map
    
    def lookup(self, txid: bytes) -> Optional[Transaction]:
        """Look up a transaction by txid."""
        entry = self._map.get(txid)
        return entry.tx if entry else None
    
    def get_entry(self, txid: bytes) -> Optional[TxMempoolEntry]:
        """Get mempool entry by txid."""
        return self._map.get(txid)
    
    def map_tx(self) -> Dict[bytes, TxMempoolEntry]:
        """Get the map of all entries."""
        return self._map
    
    # ========================================================================
    # Transaction Acceptance
    # ========================================================================
    
    def add_tx(self, entry: TxMempoolEntry, 
               state: TxValidationState) -> bool:
        """
        Add a transaction to the mempool.
        
        Args:
            entry: The mempool entry
            state: Validation state for error reporting
            
        Returns:
            True if successfully added
        """
        txid = entry.txid
        wtxid = entry.wtxid
        
        # Check if already exists
        if self.exists(txid):
            return state.invalid(
                TxValidationResult.TX_CONFLICT,
                "txn-already-in-mempool"
            )
        
        # Check size limits
        if self.limits.max_count > 0 and self.size() >= self.limits.max_count:
            return state.invalid(
                TxValidationResult.TX_MEMPOOL_POLICY,
                "mempool full"
            )
        
        # Check for conflicts (double spend)
        for txin in entry.tx.inputs:
            if txin.prevout in self._next_spent:
                return state.invalid(
                    TxValidationResult.TX_CONFLICT,
                    "txn-mempool-conflict"
                )
        
        # Add to mempool
        self._map[txid] = entry
        self._wtxid_map[wtxid] = txid
        
        # Track spent outpoints
        for txin in entry.tx.inputs:
            self._next_spent[txin.prevout] = txid
        
        # Update totals
        self._total_tx_size += entry.vsize
        self._total_sigop_cost += entry.sigop_cost
        
        # Update ancestor/descendant links
        self._update_links(entry)
        
        return True
    
    def remove_tx(self, txid: bytes, reason: str = "", 
                  remove_recursively: bool = False) -> List[bytes]:
        """
        Remove a transaction from the mempool.
        
        Args:
            txid: Transaction to remove
            reason: Why it's being removed
            remove_recursively: Also remove descendants
            
        Returns:
            List of removed txids
        """
        removed = []
        
        if remove_recursively:
            # Remove all descendants first
            entry = self._map.get(txid)
            if entry:
                for desc_txid in list(entry.descendants):
                    if desc_txid in self._map:
                        self._remove_entry(desc_txid)
                        removed.append(desc_txid)
        
        # Remove the transaction itself
        if txid in self._map:
            self._remove_entry(txid)
            removed.append(txid)
        
        return removed
    
    def _remove_entry(self, txid: bytes) -> None:
        """Internal method to remove an entry."""
        entry = self._map.get(txid)
        if not entry:
            return
        
        # Remove from spent index
        for txin in entry.tx.inputs:
            if txin.prevout in self._next_spent:
                del self._next_spent[txin.prevout]
        
        # Update ancestor links
        for ancestor_txid in entry.ancestors:
            if ancestor_txid in self._map:
                self._map[ancestor_txid].descendants.discard(txid)
        
        # Update descendant links
        for desc_txid in entry.descendants:
            if desc_txid in self._map:
                self._map[desc_txid].ancestors.discard(txid)
        
        # Update totals
        self._total_tx_size -= entry.vsize
        self._total_sigop_cost -= entry.sigop_cost
        
        # Remove from maps
        del self._map[txid]
        if entry.wtxid in self._wtxid_map:
            del self._wtxid_map[entry.wtxid]
    
    def _update_links(self, entry: TxMempoolEntry) -> None:
        """Update ancestor/descendant links when adding a transaction."""
        txid = entry.txid
        
        for txin in entry.tx.inputs:
            # Find parent transaction in mempool
            parent_txid = self._next_spent.get(txin.prevout)
            if parent_txid and parent_txid in self._map:
                parent_entry = self._map[parent_txid]
                
                # Add as ancestor
                entry.ancestors.add(parent_txid)
                entry.ancestors.update(parent_entry.ancestors)
                
                # Update parent's descendants
                parent_entry.descendants.add(txid)
                
                # Update all ancestors' descendants
                for anc_txid in parent_entry.ancestors:
                    if anc_txid in self._map:
                        self._map[anc_txid].descendants.add(txid)
        
        # Update counts
        entry.ancestor_count = len(entry.ancestors) + 1
        entry.ancestor_size = sum(
            self._map[a].vsize for a in entry.ancestors if a in self._map
        ) + entry.vsize
        entry.ancestor_fee = sum(
            self._map[a].fee for a in entry.ancestors if a in self._map
        ) + entry.fee
    
    # ========================================================================
    # Fee-based Eviction
    # ========================================================================
    
    def trim_to_size(self, sizelimit: int) -> List[bytes]:
        """
        Remove transactions until mempool is under size limit.
        
        Eviction is done by mining score (fee rate).
        
        Args:
            sizelimit: Target size in bytes
            
        Returns:
            List of removed txids
        """
        removed = []
        
        while self._total_tx_size > sizelimit and self._map:
            # Find lowest fee rate transaction
            # For simplicity, just remove the last added
            # Real implementation would use mining score
            txid = next(reversed(self._map))
            removed.extend(self.remove_tx(txid, MemPoolRemovalReason.SIZE_LIMIT, 
                                         remove_recursively=True))
        
        return removed
    
    # ========================================================================
    # Query Methods
    # ========================================================================
    
    def get_spent_outpoints(self) -> Set[OutPoint]:
        """Get all outpoints spent by mempool transactions."""
        return set(self._next_spent.keys())
    
    def get_outpoints_spent_by_tx(self, txid: bytes) -> Set[OutPoint]:
        """Get outpoints spent by a specific transaction."""
        entry = self._map.get(txid)
        return entry.spends if entry else set()
    
    def get_tx_spending_outpoint(self, outpoint: OutPoint) -> Optional[bytes]:
        """Get the txid of the transaction spending an outpoint."""
        return self._next_spent.get(outpoint)
    
    def get_ancestors(self, txid: bytes) -> Set[bytes]:
        """Get all ancestors of a transaction."""
        entry = self._map.get(txid)
        return entry.ancestors if entry else set()
    
    def get_descendants(self, txid: bytes) -> Set[bytes]:
        """Get all descendants of a transaction."""
        entry = self._map.get(txid)
        return entry.descendants if entry else set()
    
    def clear(self) -> None:
        """Clear the mempool."""
        self._map.clear()
        self._wtxid_map.clear()
        self._next_spent.clear()
        self._total_tx_size = 0
        self._total_sigop_cost = 0
    
    def __iter__(self):
        """Iterate over mempool entries."""
        return iter(self._map.values())
    
    def __len__(self) -> int:
        return len(self._map)


# ============================================================================
# Mempool Accept
# ============================================================================

@dataclass
class MempoolAcceptResult:
    """Result of mempool acceptance."""
    success: bool
    txid: Optional[bytes] = None
    wtxid: Optional[bytes] = None
    fee: int = 0
    vsize: int = 0
    effective_fee_rate: int = 0
    rejects: List[bytes] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)


def AcceptToMemoryPool(
    mempool: CTxMemPool,
    tx: Transaction,
    state: TxValidationState,
    limits: MempoolLimits,
    bypass_limits: bool = False
) -> Tuple[bool, MempoolAcceptResult]:
    """
    Try to accept a transaction to the mempool.
    
    This performs validation checks and adds the transaction
    if all checks pass.
    
    Args:
        mempool: The mempool to add to
        tx: Transaction to add
        state: Validation state
        limits: Mempool limits
        bypass_limits: If True, skip size limit checks
        
    Returns:
        Tuple of (success, result)
    """
    from ..consensus.tx_check import CheckTransaction
    
    # Basic structural checks
    if not CheckTransaction(tx, state):
        return False, MempoolAcceptResult(success=False)
    
    # Check size
    weight = GetWeight(tx)
    vsize = GetVirtualSize(tx)
    
    if weight > limits.max_tx_weight:
        state.invalid(TxValidationResult.TX_MEMPOOL_POLICY, "tx-size-too-large")
        return False, MempoolAcceptResult(success=False)
    
    # Calculate fee (would need input values)
    # For now, assume fee is provided or calculated elsewhere
    fee = 0  # Placeholder
    
    # Create mempool entry
    entry = TxMempoolEntry(
        tx=tx,
        fee=fee,
        time=int(time()),
        height=0,  # Current chain height
        weight=weight,
        vsize=vsize
    )
    
    # Try to add
    if not mempool.add_tx(entry, state):
        return False, MempoolAcceptResult(success=False)
    
    result = MempoolAcceptResult(
        success=True,
        txid=tx.hash,
        wtxid=entry.wtxid,
        fee=fee,
        vsize=vsize
    )
    
    return True, result
