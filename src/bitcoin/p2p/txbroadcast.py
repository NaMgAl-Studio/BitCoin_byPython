"""
Bitcoin Transaction Broadcast.

This module implements transaction broadcast and relay mechanisms
for the Bitcoin P2P network.

Reference: Bitcoin Core src/net_processing.cpp, src/txmempool.cpp
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Final, Dict, List, Optional, Set, Callable, Any
from collections import defaultdict
from datetime import datetime, timezone

from .connman import CNode, CConnMan
from .protocol import NetMsgType, CInv, GetDataMsg, ServiceFlags, NodeId
from .messages import TxMessage, InvMessage, GetDataMessage, NotFoundMessage
from ..primitives.transaction import Transaction
from ..consensus.amount import Amount


# ==============================================================================
# Constants
# ==============================================================================

# Maximum inventory in flight per peer
MAX_INV_IN_FLIGHT_PER_PEER: Final[int] = 500

# Inventory broadcast interval
INVENTORY_BROADCAST_INTERVAL: Final[int] = 5  # seconds

# Maximum orphan transactions
MAX_ORPHAN_TRANSACTIONS: Final[int] = 100

# Transaction relay delay (for anti-DoS)
TX_RELAY_DELAY: Final[int] = 2  # seconds

# Maximum time to wait for parents of orphan
ORPHAN_EXPIRY_TIME: Final[int] = 20 * 60  # 20 minutes

# Announce transactions via inv or wtxid
INVENTORY_MAX_ANNOUNCE: Final[int] = 7


# ==============================================================================
# Transaction Request State
# ==============================================================================

class TxRequestState:
    """State of a transaction request."""
    
    UNREQUESTED = "unrequested"
    REQUESTED = "requested"
    DOWNLOADED = "downloaded"
    FAILED = "failed"


# ==============================================================================
# Transaction Request
# ==============================================================================

@dataclass
class TxRequest:
    """Tracks a transaction download request."""
    
    # Transaction hash (txid or wtxid)
    hash: bytes
    
    # Whether this is a wtxid
    is_wtxid: bool = False
    
    # Peers we're requesting from
    peer_ids: Set[NodeId] = field(default_factory=set)
    
    # Request time
    request_time: float = 0.0
    
    # State
    state: str = TxRequestState.UNREQUESTED
    
    # Retry count
    retry_count: int = 0
    
    def __post_init__(self):
        if self.request_time == 0.0:
            self.request_time = time.time()


# ==============================================================================
# Orphan Transaction Pool
# ==============================================================================

@dataclass
class OrphanTx:
    """Orphan transaction with metadata."""
    
    tx: Transaction
    from_peer_id: NodeId
    arrival_time: float = 0.0
    
    def __post_init__(self):
        if self.arrival_time == 0.0:
            self.arrival_time = time.time()


class OrphanTxPool:
    """
    Manages orphan transactions.
    
    Orphan transactions are those that reference unknown inputs (parents).
    They're stored until their parents arrive or they expire.
    """
    
    def __init__(self, max_size: int = MAX_ORPHAN_TRANSACTIONS):
        """
        Initialize orphan transaction pool.
        
        Args:
            max_size: Maximum number of orphan transactions
        """
        self._max_size = max_size
        self._orphans: Dict[bytes, OrphanTx] = {}  # wtxid -> OrphanTx
        self._outpoints: Dict[bytes, bytes] = {}  # outpoint -> wtxid
        self._orphan_by_prev: Dict[bytes, Set[bytes]] = defaultdict(set)  # prevout -> wtxids
        self._orphan_time: Dict[bytes, float] = {}  # wtxid -> arrival_time
    
    def add(self, tx: Transaction, from_peer_id: NodeId) -> bool:
        """
        Add a transaction to the orphan pool.
        
        Args:
            tx: Transaction to add
            from_peer_id: Peer that sent the transaction
            
        Returns:
            True if added
        """
        wtxid = tx.get_wtxid()
        
        if wtxid in self._orphans:
            return False
        
        # Check capacity
        while len(self._orphans) >= self._max_size:
            self._evict_oldest()
        
        # Create orphan
        orphan = OrphanTx(tx=tx, from_peer_id=from_peer_id)
        
        # Add to pool
        self._orphans[wtxid] = orphan
        self._orphan_time[wtxid] = time.time()
        
        # Index by inputs (for finding children when parents arrive)
        for tx_in in tx.vin:
            prevout = tx_in.prevout
            self._orphan_by_prev[prevout].add(wtxid)
        
        return True
    
    def get(self, wtxid: bytes) -> Optional[OrphanTx]:
        """Get an orphan transaction by wtxid."""
        return self._orphans.get(wtxid)
    
    def get_children(self, txid: bytes) -> List[OrphanTx]:
        """
        Get all orphan transactions that depend on a given transaction.
        
        Args:
            txid: Parent transaction id
            
        Returns:
            List of orphan transactions
        """
        children = []
        
        # Find all orphans that reference this txid as an input
        for outpoint, wtxid in list(self._outpoints.items()):
            if outpoint[:32] == txid:
                orphan = self._orphans.get(wtxid)
                if orphan:
                    children.append(orphan)
        
        return children
    
    def pop_children(self, txid: bytes) -> List[Transaction]:
        """
        Pop all orphan transactions that depend on a given transaction.
        
        Args:
            txid: Parent transaction id
            
        Returns:
            List of orphan transactions
        """
        children = []
        
        # Find wtxids that reference this txid
        wtxids_to_remove = []
        
        for outpoint, wtxid in list(self._outpoints.items()):
            if outpoint[:32] == txid:
                orphan = self._orphans.pop(wtxid, None)
                if orphan:
                    children.append(orphan.tx)
                    wtxids_to_remove.append(wtxid)
        
        # Clean up indexes
        for wtxid in wtxids_to_remove:
            self._orphan_time.pop(wtxid, None)
        
        return children
    
    def remove(self, wtxid: bytes) -> Optional[OrphanTx]:
        """Remove an orphan from the pool."""
        orphan = self._orphans.pop(wtxid, None)
        if orphan:
            self._orphan_time.pop(wtxid, None)
            # Clean up input index
            for tx_in in orphan.tx.vin:
                prevout = tx_in.prevout
                self._outpoints.pop(prevout, None)
        return orphan
    
    def contains(self, wtxid: bytes) -> bool:
        """Check if transaction is in orphan pool."""
        return wtxid in self._orphans
    
    def size(self) -> int:
        """Get number of orphan transactions."""
        return len(self._orphans)
    
    def _evict_oldest(self) -> None:
        """Evict the oldest orphan."""
        if not self._orphan_time:
            return
        
        oldest_wtxid = min(self._orphan_time.keys(), key=lambda h: self._orphan_time[h])
        self.remove(oldest_wtxid)
    
    def cleanup(self, max_age: float = ORPHAN_EXPIRY_TIME) -> None:
        """Clean up expired orphan transactions."""
        current_time = time.time()
        expired = [
            h for h, t in self._orphan_time.items()
            if current_time - t > max_age
        ]
        
        for wtxid in expired:
            self.remove(wtxid)


# ==============================================================================
# Transaction Broadcast Manager
# ==============================================================================

class TxBroadcastManager:
    """
    Transaction Broadcast Manager.
    
    Manages transaction broadcasting to peers and handling
    transaction inventory.
    """
    
    def __init__(
        self,
        connman: CConnMan,
        mempool_accept: Callable[[Transaction, bool], bool],
        mempool_exists: Callable[[bytes], bool],
        mempool_get: Callable[[bytes], Optional[Transaction]]
    ):
        """
        Initialize transaction broadcast manager.
        
        Args:
            connman: Connection manager
            mempool_accept: Function to accept transaction to mempool
            mempool_exists: Function to check if tx exists in mempool
            mempool_get: Function to get transaction from mempool
        """
        self._connman = connman
        self._mempool_accept = mempool_accept
        self._mempool_exists = mempool_exists
        self._mempool_get = mempool_get
        
        # Pending transaction requests
        self._tx_requests: Dict[bytes, TxRequest] = {}
        
        # Orphan pool
        self._orphan_pool = OrphanTxPool()
        
        # Transactions we've announced
        self._announced_txs: Dict[bytes, Set[NodeId]] = defaultdict(set)
        
        # Recently seen transactions (for anti-replay)
        self._recent_txs: Set[bytes] = set()
        
        # Transactions we're currently relaying
        self._relay_txs: Dict[bytes, float] = {}  # wtxid -> time
        
        # Callbacks
        self._on_tx_accepted: Optional[Callable] = None
        self._on_tx_rejected: Optional[Callable] = None
    
    # ==========================================================================
    # Transaction Processing
    # ==========================================================================
    
    def process_tx_message(
        self,
        peer: CNode,
        tx_msg: TxMessage
    ) -> bool:
        """
        Process a received transaction.
        
        Args:
            peer: Peer that sent transaction
            tx_msg: Transaction message
            
        Returns:
            True if processed successfully
        """
        if tx_msg.tx is None:
            return False
        
        tx = tx_msg.tx
        wtxid = tx.get_wtxid()
        txid = tx.get_txid()
        
        # Check if already in mempool
        if self._mempool_exists(txid) or self._mempool_exists(wtxid):
            return True
        
        # Check if already requested
        request = self._tx_requests.get(wtxid)
        if request and request.state == TxRequestState.REQUESTED:
            request.state = TxRequestState.DOWNLOADED
            self._tx_requests.pop(wtxid, None)
        
        # Try to accept to mempool
        if self._mempool_accept(tx, False):
            # Success - process any orphan children
            self._process_orphan_children(txid)
            
            # Announce to peers
            self._announce_transaction(tx)
            
            # Callback
            if self._on_tx_accepted:
                self._on_tx_accepted(tx, peer.id)
            
            return True
        
        # Check for orphan
        missing_parents = self._find_missing_parents(tx)
        if missing_parents:
            # Add to orphan pool
            self._orphan_pool.add(tx, peer.id)
            
            # Request missing parents
            for parent_txid in missing_parents:
                self._request_transaction(parent_txid, peer.id)
            
            return True
        
        # Transaction rejected
        if self._on_tx_rejected:
            self._on_tx_rejected(tx, peer.id, "rejected")
        
        return False
    
    def _process_orphan_children(self, txid: bytes) -> None:
        """
        Process orphan transactions that depend on a parent.
        
        Args:
            txid: Parent transaction id
        """
        children = self._orphan_pool.pop_children(txid)
        
        for child_tx in children:
            # Try to accept each child
            child_txid = child_tx.get_txid()
            
            if self._mempool_accept(child_tx, False):
                self._announce_transaction(child_tx)
                # Recursively process children
                self._process_orphan_children(child_txid)
    
    def _find_missing_parents(self, tx: Transaction) -> List[bytes]:
        """
        Find missing parent transactions.
        
        Args:
            tx: Transaction to check
            
        Returns:
            List of missing parent txids
        """
        missing = []
        
        for tx_in in tx.vin:
            prevout = tx_in.prevout
            parent_txid = prevout[:32]
            
            if not self._mempool_exists(parent_txid):
                missing.append(parent_txid)
        
        return missing
    
    # ==========================================================================
    # Transaction Requests
    # ==========================================================================
    
    def _request_transaction(self, txid: bytes, peer_id: NodeId) -> None:
        """
        Request a transaction from a peer.
        
        Args:
            txid: Transaction id to request
            peer_id: Peer to request from
        """
        if txid in self._tx_requests:
            self._tx_requests[txid].peer_ids.add(peer_id)
            return
        
        request = TxRequest(hash=txid, is_wtxid=False)
        request.peer_ids.add(peer_id)
        request.state = TxRequestState.REQUESTED
        
        self._tx_requests[txid] = request
    
    def handle_inv_message(
        self,
        peer: CNode,
        inv_msg: InvMessage
    ) -> None:
        """
        Handle an inv message containing transaction announcements.
        
        Args:
            peer: Sending peer
            inv_msg: Inv message
        """
        tx_invs = [inv for inv in inv_msg.invs if inv.is_gen_tx_msg()]
        
        if not tx_invs:
            return
        
        # Build request list
        to_request = []
        
        for inv in tx_invs:
            tx_hash = inv.hash
            
            # Check if we already have it
            if self._mempool_exists(tx_hash):
                continue
            
            # Track announcement
            self._announced_txs[tx_hash].add(peer.id)
            
            # Add to request list
            to_request.append(inv)
        
        # Send getdata for unknown transactions
        if to_request:
            get_data = GetDataMessage(invs=to_request)
            peer.send_message(get_data)
    
    def handle_getdata_message(
        self,
        peer: CNode,
        getdata_msg: GetDataMessage
    ) -> None:
        """
        Handle a getdata message requesting transactions.
        
        Args:
            peer: Requesting peer
            getdata_msg: GetData message
        """
        tx_invs = [inv for inv in getdata_msg.invs if inv.is_gen_tx_msg()]
        
        for inv in tx_invs:
            tx_hash = inv.hash
            
            # Try to find transaction
            tx = self._mempool_get(tx_hash)
            
            if tx is not None:
                # Send transaction
                tx_msg = TxMessage(tx=tx)
                peer.send_message(tx_msg)
            else:
                # Send notfound
                notfound = NotFoundMessage(invs=[inv])
                peer.send_message(notfound)
    
    # ==========================================================================
    # Transaction Announcement
    # ==========================================================================
    
    def _announce_transaction(self, tx: Transaction) -> None:
        """
        Announce a transaction to peers.
        
        Args:
            tx: Transaction to announce
        """
        wtxid = tx.get_wtxid()
        
        # Get peers to announce to
        # Simplified - would use proper peer selection
        
        # Track announcement
        self._relay_txs[wtxid] = time.time()
    
    def broadcast_transaction(
        self,
        tx: Transaction,
        preferred_peers: Optional[List[NodeId]] = None
    ) -> bool:
        """
        Broadcast a transaction to the network.
        
        Args:
            tx: Transaction to broadcast
            preferred_peers: Optional list of preferred peers
            
        Returns:
            True if broadcast initiated
        """
        wtxid = tx.get_wtxid()
        txid = tx.get_txid()
        
        # First, try to accept to mempool
        if not self._mempool_accept(tx, True):
            return False
        
        # Track for relay
        self._relay_txs[wtxid] = time.time()
        
        # Broadcast to peers
        # Simplified - would send inv to connected peers
        
        return True
    
    # ==========================================================================
    # Inventory Management
    # ==========================================================================
    
    def get_inventory_to_send(
        self,
        peer: CNode,
        max_count: int
    ) -> List[CInv]:
        """
        Get transaction inventory to send to a peer.
        
        Args:
            peer: Peer to send to
            max_count: Maximum number of items
            
        Returns:
            List of inventory items
        """
        invs = []
        current_time = time.time()
        
        # Get transactions we've recently seen
        for wtxid, relay_time in list(self._relay_txs.items()):
            # Check relay delay
            if current_time - relay_time < TX_RELAY_DELAY:
                continue
            
            # Check if already announced to this peer
            if peer.id in self._announced_txs.get(wtxid, set()):
                continue
            
            # Create inv
            inv = CInv(type=GetDataMsg.MSG_WTX, hash=wtxid)
            invs.append(inv)
            
            # Track announcement
            self._announced_txs[wtxid].add(peer.id)
            
            if len(invs) >= max_count:
                break
        
        return invs
    
    # ==========================================================================
    # Orphan Management
    # ==========================================================================
    
    def cleanup_orphans(self) -> None:
        """Clean up expired orphan transactions."""
        self._orphan_pool.cleanup()
    
    def get_orphan_count(self) -> int:
        """Get number of orphan transactions."""
        return self._orphan_pool.size()
    
    # ==========================================================================
    # Callbacks
    # ==========================================================================
    
    def set_on_tx_accepted(self, callback: Callable) -> None:
        """Set callback for transaction acceptance."""
        self._on_tx_accepted = callback
    
    def set_on_tx_rejected(self, callback: Callable) -> None:
        """Set callback for transaction rejection."""
        self._on_tx_rejected = callback
    
    # ==========================================================================
    # Statistics
    # ==========================================================================
    
    def get_stats(self) -> Dict[str, Any]:
        """Get broadcast statistics."""
        return {
            'pending_requests': len(self._tx_requests),
            'orphan_count': self._orphan_pool.size(),
            'announced_count': len(self._announced_txs),
            'relay_count': len(self._relay_txs),
        }


# ==============================================================================
# Transaction Submission Result
# ==============================================================================

@dataclass
class TxSubmitResult:
    """Result of transaction submission."""
    
    success: bool
    txid: Optional[bytes] = None
    error: Optional[str] = None
    accepted_to_mempool: bool = False
    broadcast_to_peers: int = 0
