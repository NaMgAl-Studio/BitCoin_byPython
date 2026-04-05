"""
Bitcoin Block Download.

This module implements the block download mechanism for the Bitcoin P2P network,
including headers-first download, block announcements, and orphan handling.

Reference: Bitcoin Core src/net_processing.cpp, src/txdownloadman.cpp
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Final, Dict, List, Optional, Set, Callable, Any
from collections import defaultdict
from datetime import datetime, timezone

from .netaddress import CNetAddr
from .connman import CNode, CConnMan
from .protocol import NetMsgType, CInv, GetDataMsg, ServiceFlags, NodeId
from .messages import (
    GetBlocksMessage, GetHeadersMessage, HeadersMessage,
    BlockMessage, InvMessage, GetDataMessage
)
from ..primitives.block import Block, BlockHeader
from ..primitives.transaction import Transaction
from ..chain.chain import CBlockIndex


# ==============================================================================
# Constants
# ==============================================================================

# Maximum number of headers in a headers message
MAX_HEADERS_MESSAGE_SIZE: Final[int] = 2000

# Maximum number of blocks to request at once
MAX_BLOCKS_IN_TRANSIT_PER_PEER: Final[int] = 16

# Block download timeout in seconds
BLOCK_DOWNLOAD_TIMEOUT: Final[int] = 20 * 60  # 20 minutes

# Headers download timeout
HEADERS_DOWNLOAD_TIMEOUT: Final[int] = 15 * 60  # 15 minutes

# Maximum orphan blocks
MAX_ORPHAN_BLOCKS: Final[int] = 100


# ==============================================================================
# Block Download State
# ==============================================================================

class BlockDownloadState:
    """Block download state machine."""
    
    # Initial state - no blocks being downloaded
    IDLE = "idle"
    
    # Downloading headers first
    DOWNLOADING_HEADERS = "downloading_headers"
    
    # Headers downloaded, downloading blocks
    DOWNLOADING_BLOCKS = "downloading_blocks"
    
    # Paused due to block full
    BLOCK_STALL = "block_stall"
    
    # Completed
    COMPLETED = "completed"


# ==============================================================================
# Block Request Tracker
# ==============================================================================

@dataclass
class BlockRequest:
    """Tracks a block download request."""
    
    # Block hash
    hash: bytes
    
    # Peer we're downloading from
    peer_id: NodeId
    
    # Request time
    request_time: float = 0.0
    
    # Number of retry attempts
    retry_count: int = 0
    
    # Priority (lower is higher priority)
    priority: int = 0
    
    def __post_init__(self):
        if self.request_time == 0.0:
            self.request_time = time.time()


# ==============================================================================
# Orphan Block Pool
# ==============================================================================

class OrphanBlockPool:
    """
    Manages orphan blocks that we received before their parent.
    
    When a block arrives that references an unknown parent, it's stored
    as an orphan until the parent is received.
    """
    
    def __init__(self, max_size: int = MAX_ORPHAN_BLOCKS):
        """
        Initialize orphan block pool.
        
        Args:
            max_size: Maximum number of orphan blocks
        """
        self._max_size = max_size
        self._orphans: Dict[bytes, Block] = {}  # hash -> block
        self._orphan_by_prev: Dict[bytes, List[bytes]] = defaultdict(list)  # prev_hash -> [orphan_hashes]
        self._orphan_time: Dict[bytes, float] = {}  # hash -> arrival_time
    
    def add(self, block: Block) -> bool:
        """
        Add a block to the orphan pool.
        
        Args:
            block: Block to add
            
        Returns:
            True if added
        """
        block_hash = block.get_hash()
        prev_hash = block.header.hash_prev_block
        
        if block_hash in self._orphans:
            return False
        
        # Check if we need to evict
        while len(self._orphans) >= self._max_size:
            self._evict_oldest()
        
        # Add orphan
        self._orphans[block_hash] = block
        self._orphan_by_prev[prev_hash].append(block_hash)
        self._orphan_time[block_hash] = time.time()
        
        return True
    
    def get(self, block_hash: bytes) -> Optional[Block]:
        """Get an orphan block by hash."""
        return self._orphans.get(block_hash)
    
    def pop_children(self, block_hash: bytes) -> List[Block]:
        """
        Pop all children of a block from the pool.
        
        Args:
            block_hash: Parent block hash
            
        Returns:
            List of child blocks
        """
        children = []
        orphan_hashes = self._orphan_by_prev.get(block_hash, [])
        
        for orphan_hash in orphan_hashes:
            block = self._orphans.pop(orphan_hash, None)
            if block:
                children.append(block)
                self._orphan_time.pop(orphan_hash, None)
        
        # Clear the list
        if block_hash in self._orphan_by_prev:
            del self._orphan_by_prev[block_hash]
        
        return children
    
    def contains(self, block_hash: bytes) -> bool:
        """Check if block is in orphan pool."""
        return block_hash in self._orphans
    
    def size(self) -> int:
        """Get number of orphan blocks."""
        return len(self._orphans)
    
    def _evict_oldest(self) -> None:
        """Evict the oldest orphan."""
        if not self._orphan_time:
            return
        
        # Find oldest
        oldest_hash = min(self._orphan_time.keys(), key=lambda h: self._orphan_time[h])
        
        # Remove
        block = self._orphans.pop(oldest_hash, None)
        if block:
            prev_hash = block.header.hash_prev_block
            if oldest_hash in self._orphan_by_prev.get(prev_hash, []):
                self._orphan_by_prev[prev_hash].remove(oldest_hash)
        
        self._orphan_time.pop(oldest_hash, None)
    
    def cleanup(self, max_age: float = 20 * 60) -> None:
        """
        Clean up expired orphan blocks.
        
        Args:
            max_age: Maximum age in seconds
        """
        current_time = time.time()
        expired = [
            h for h, t in self._orphan_time.items()
            if current_time - t > max_age
        ]
        
        for block_hash in expired:
            block = self._orphans.pop(block_hash, None)
            if block:
                prev_hash = block.header.hash_prev_block
                if block_hash in self._orphan_by_prev.get(prev_hash, []):
                    self._orphan_by_prev[prev_hash].remove(block_hash)
            self._orphan_time.pop(block_hash, None)


# ==============================================================================
# Headers Sync State
# ==============================================================================

@dataclass
class HeadersSyncState:
    """State for headers synchronization."""
    
    # Starting chain work
    chain_work: int = 0
    
    # Current headers tip
    tip_hash: bytes = field(default_factory=lambda: bytes(32))
    tip_height: int = 0
    
    # Download start time
    start_time: float = 0.0
    
    # Headers received count
    headers_received: int = 0
    
    # Peer we're syncing from
    sync_peer_id: Optional[NodeId] = None
    
    # Whether we're in IBD (initial block download)
    is_ibd: bool = True


# ==============================================================================
# Block Download Manager
# ==============================================================================

class BlockDownloadManager:
    """
    Block Download Manager.
    
    Manages the download of blocks from peers using a headers-first
    approach. Handles block announcements, orphan blocks, and retry logic.
    """
    
    def __init__(
        self,
        connman: CConnMan,
        get_block_index: Callable[[bytes], Optional[CBlockIndex]],
        process_block: Callable[[Block, bool], bool]
    ):
        """
        Initialize block download manager.
        
        Args:
            connman: Connection manager
            get_block_index: Function to get block index by hash
            process_block: Function to process a new block
        """
        self._connman = connman
        self._get_block_index = get_block_index
        self._process_block = process_block
        
        # Download state
        self._state = BlockDownloadState.IDLE
        self._headers_sync = HeadersSyncState()
        
        # Block requests
        self._block_requests: Dict[bytes, BlockRequest] = {}
        self._requested_blocks: Set[bytes] = set()
        
        # Orphan pool
        self._orphan_pool = OrphanBlockPool()
        
        # Pending blocks (headers downloaded but blocks not requested)
        self._pending_blocks: List[bytes] = []
        
        # Block announcement tracking
        self._recent_announcements: Dict[bytes, Set[NodeId]] = defaultdict(set)
        
        # Callbacks
        self._on_block_downloaded: Optional[Callable] = None
        self._on_headers_synced: Optional[Callable] = None
    
    # ==========================================================================
    # State Management
    # ==========================================================================
    
    @property
    def state(self) -> str:
        """Get current download state."""
        return self._state
    
    @property
    def is_syncing(self) -> bool:
        """Check if we're currently syncing."""
        return self._state in (
            BlockDownloadState.DOWNLOADING_HEADERS,
            BlockDownloadState.DOWNLOADING_BLOCKS
        )
    
    @property
    def is_ibd(self) -> bool:
        """Check if we're in initial block download."""
        return self._headers_sync.is_ibd
    
    # ==========================================================================
    # Headers Download
    # ==========================================================================
    
    def start_headers_sync(self, peer: CNode, locator_hashes: List[bytes]) -> None:
        """
        Start headers synchronization with a peer.
        
        Args:
            peer: Peer to sync from
            locator_hashes: Block locator hashes
        """
        self._headers_sync.sync_peer_id = peer.id
        self._headers_sync.start_time = time.time()
        self._headers_sync.headers_received = 0
        self._state = BlockDownloadState.DOWNLOADING_HEADERS
        
        # Send getheaders message
        get_headers = GetHeadersMessage(
            locator_hashes=locator_hashes,
            hash_stop=bytes(32)
        )
        peer.send_message(get_headers)
    
    def process_headers_message(
        self,
        peer: CNode,
        headers_msg: HeadersMessage
    ) -> bool:
        """
        Process a headers message.
        
        Args:
            peer: Peer that sent headers
            headers_msg: Headers message
            
        Returns:
            True if headers were processed successfully
        """
        if not headers_msg.headers:
            # Empty headers message means we're synced
            self._state = BlockDownloadState.DOWNLOADING_BLOCKS
            self._start_block_download()
            return True
        
        # Process each header
        for header in headers_msg.headers:
            block_hash = header.get_hash()
            
            # Validate header
            if not self._validate_header(header):
                return False
            
            # Update sync state
            self._headers_sync.tip_hash = block_hash
            self._headers_sync.tip_height += 1
            self._headers_sync.headers_received += 1
            
            # Add to pending blocks
            self._pending_blocks.append(block_hash)
        
        # Request more headers if needed
        if len(headers_msg.headers) == MAX_HEADERS_MESSAGE_SIZE:
            # More headers available
            locator = [self._headers_sync.tip_hash]
            get_headers = GetHeadersMessage(
                locator_hashes=locator,
                hash_stop=bytes(32)
            )
            peer.send_message(get_headers)
        else:
            # Headers sync complete
            self._state = BlockDownloadState.DOWNLOADING_BLOCKS
            self._start_block_download()
        
        return True
    
    def _validate_header(self, header: BlockHeader) -> bool:
        """
        Validate a block header.
        
        Args:
            header: Header to validate
            
        Returns:
            True if valid
        """
        # Check proof of work
        # Check timestamp
        # Check parent exists
        # Simplified for now
        return True
    
    # ==========================================================================
    # Block Download
    # ==========================================================================
    
    def _start_block_download(self) -> None:
        """Start downloading blocks from pending list."""
        if not self._pending_blocks:
            self._state = BlockDownloadState.COMPLETED
            return
        
        # Request blocks from available peers
        self._request_next_blocks()
    
    def _request_next_blocks(self) -> None:
        """Request the next batch of blocks."""
        # Get available peers
        # Simplified - would use proper peer selection
        
        while self._pending_blocks and len(self._block_requests) < MAX_BLOCKS_IN_TRANSIT_PER_PEER:
            block_hash = self._pending_blocks.pop(0)
            
            if block_hash in self._requested_blocks:
                continue
            
            # Find a peer to request from
            peer = self._select_block_download_peer(block_hash)
            if peer is None:
                # Put back and try later
                self._pending_blocks.insert(0, block_hash)
                break
            
            # Request block
            self._request_block(peer, block_hash)
    
    def _select_block_download_peer(self, block_hash: bytes) -> Optional[CNode]:
        """
        Select a peer to download a block from.
        
        Args:
            block_hash: Block to download
            
        Returns:
            Selected peer or None
        """
        # Check which peers announced this block
        announcing_peers = self._recent_announcements.get(block_hash, set())
        
        # Get available peers from connection manager
        # Simplified - would use proper peer selection logic
        
        return None
    
    def _request_block(self, peer: CNode, block_hash: bytes) -> None:
        """
        Request a block from a peer.
        
        Args:
            peer: Peer to request from
            block_hash: Block hash to request
        """
        # Create inv
        inv = CInv(type=GetDataMsg.MSG_BLOCK, hash=block_hash)
        
        # Create getdata message
        get_data = GetDataMessage(invs=[inv])
        
        # Track request
        request = BlockRequest(hash=block_hash, peer_id=peer.id)
        self._block_requests[block_hash] = request
        self._requested_blocks.add(block_hash)
        
        # Send request
        peer.send_message(get_data)
    
    def process_block_message(
        self,
        peer: CNode,
        block_msg: BlockMessage
    ) -> bool:
        """
        Process a received block.
        
        Args:
            peer: Peer that sent block
            block_msg: Block message
            
        Returns:
            True if block was processed successfully
        """
        if block_msg.block is None:
            return False
        
        block = block_msg.block
        block_hash = block.get_hash()
        
        # Check if we requested this block
        if block_hash not in self._requested_blocks:
            # Might be an orphan
            return self._handle_potential_orphan(block)
        
        # Remove from tracking
        self._block_requests.pop(block_hash, None)
        self._requested_blocks.discard(block_hash)
        
        # Process block
        success = self._process_block(block, True)
        
        if success:
            # Process any orphan children
            children = self._orphan_pool.pop_children(block_hash)
            for child in children:
                self._process_block(child, True)
            
            # Request next block
            self._request_next_blocks()
        
        return success
    
    def _handle_potential_orphan(self, block: Block) -> bool:
        """
        Handle a block that might be an orphan.
        
        Args:
            block: Block that might be orphan
            
        Returns:
            True if handled
        """
        prev_hash = block.header.hash_prev_block
        
        # Check if parent exists
        parent_index = self._get_block_index(prev_hash)
        
        if parent_index is not None:
            # Parent exists, process directly
            return self._process_block(block, True)
        else:
            # Add to orphan pool
            return self._orphan_pool.add(block)
    
    # ==========================================================================
    # Block Announcements
    # ==========================================================================
    
    def handle_block_announcement(
        self,
        peer: CNode,
        block_hash: bytes,
        is_compact_block: bool = False
    ) -> None:
        """
        Handle a block announcement from a peer.
        
        Args:
            peer: Announcing peer
            block_hash: Announced block hash
            is_compact_block: Whether announcement is via compact block
        """
        # Track announcement
        self._recent_announcements[block_hash].add(peer.id)
        
        # Check if we already have this block
        if self._get_block_index(block_hash) is not None:
            return
        
        # Check if already requested
        if block_hash in self._requested_blocks:
            return
        
        # If in headers sync, add to pending
        if self._state == BlockDownloadState.DOWNLOADING_BLOCKS:
            if block_hash not in self._pending_blocks:
                self._pending_blocks.append(block_hash)
                self._request_next_blocks()
    
    def handle_inv_message(
        self,
        peer: CNode,
        inv_msg: InvMessage
    ) -> None:
        """
        Handle an inv message.
        
        Args:
            peer: Sending peer
            inv_msg: Inv message
        """
        block_invs = [inv for inv in inv_msg.invs if inv.is_msg_block()]
        
        for inv in block_invs:
            self.handle_block_announcement(peer, inv.hash)
    
    # ==========================================================================
    # Callbacks
    # ==========================================================================
    
    def set_on_block_downloaded(self, callback: Callable) -> None:
        """Set callback for block download completion."""
        self._on_block_downloaded = callback
    
    def set_on_headers_synced(self, callback: Callable) -> None:
        """Set callback for headers sync completion."""
        self._on_headers_synced = callback
    
    # ==========================================================================
    # Statistics
    # ==========================================================================
    
    def get_download_stats(self) -> Dict[str, Any]:
        """Get download statistics."""
        return {
            'state': self._state,
            'headers_received': self._headers_sync.headers_received,
            'blocks_requested': len(self._requested_blocks),
            'blocks_pending': len(self._pending_blocks),
            'orphans': self._orphan_pool.size(),
        }
