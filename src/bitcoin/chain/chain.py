# Copyright (c) 2009-2010 Satoshi Nakamoto
# Copyright (c) 2009-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Bitcoin Chain Management

This module implements blockchain data structures:
- BlockIndex: Index for a block in the chain
- Chain: Active chain management
- ChainState: Chain state tracking
"""

from dataclasses import dataclass, field
from typing import Dict, Optional, List, Set
from collections import OrderedDict

from ..primitives.block import Block, BlockHeader
from ..crypto.sha256 import Hash256


# ============================================================================
# Block Status
# ============================================================================

class BlockStatus:
    """
    Status flags for a block index.
    
    These track validation state of the block.
    """
    
    # No state information
    VALID_UNKNOWN = 0
    
    # Header is valid (determined by pow)
    VALID_HEADER = 1
    
    # All parent headers found, but not all transactions validated
    VALID_TREE = 2
    
    # Only validity of transactions determined
    VALID_TRANSACTIONS = 3
    
    # Scripts ok, but spend height too low
    VALID_CHAIN = 4
    
    # Scripts and spend height ok, but not persisted
    VALID_SCRIPTS = 5
    
    # All validity flags
    VALID_MASK = VALID_HEADER | VALID_TREE | VALID_TRANSACTIONS | VALID_CHAIN | VALID_SCRIPTS
    
    # Block has failed validation
    FAILED = 100
    FAILED_VALID = FAILED | VALID_MASK


# ============================================================================
# Block Index
# ============================================================================

@dataclass
class CBlockIndex:
    """
    The block index is the internal data structure for a block
    in the chain.
    
    It stores:
    - Block header data
    - Chain state (height, chain work)
    - Validation status
    - Links to previous/next blocks
    """
    
    # Block hash (32 bytes)
    hash: bytes = field(default_factory=lambda: bytes(32))
    
    # Header fields
    version: int = 0
    hash_prev_block: bytes = field(default_factory=lambda: bytes(32))
    merkle_root: bytes = field(default_factory=lambda: bytes(32))
    time: int = 0
    n_bits: int = 0
    nonce: int = 0
    
    # Chain state
    height: int = 0
    chain_work: bytes = field(default_factory=lambda: bytes(32))
    
    # Transaction count
    tx_count: int = 0
    
    # Status
    status: int = BlockStatus.VALID_UNKNOWN
    
    # Navigation
    prev: Optional['CBlockIndex'] = None
    skip: Optional['CBlockIndex'] = None  # Skip pointer for efficient navigation
    
    # File location (for block storage)
    file_number: int = -1
    data_pos: int = 0
    undo_pos: int = 0
    
    # Median time past (cached)
    _median_time_past: int = 0
    
    @property
    def block_header(self) -> BlockHeader:
        """Get the block header."""
        return BlockHeader(
            version=self.version,
            hash_prev_block=self.hash_prev_block,
            merkle_root=self.merkle_root,
            time=self.time,
            n_bits=self.n_bits,
            nonce=self.nonce
        )
    
    @property
    def is_valid(self) -> bool:
        """Check if block has passed full validation."""
        return self.status >= BlockStatus.VALID_SCRIPTS
    
    @property
    def is_failed(self) -> bool:
        """Check if block has failed validation."""
        return bool(self.status & BlockStatus.FAILED)
    
    @property
    def has_header(self) -> bool:
        """Check if header has been validated."""
        return self.status >= BlockStatus.VALID_HEADER
    
    def get_block_hash(self) -> bytes:
        """Get the block hash."""
        return self.hash
    
    def get_block_time(self) -> int:
        """Get the block time."""
        return self.time
    
    def get_median_time_past(self) -> int:
        """
        Get the median time past.
        
        This is the median of the last 11 block times,
        used for lock-time verification.
        """
        if self._median_time_past > 0:
            return self._median_time_past
        
        times = []
        current = self
        
        for _ in range(11):
            if current is None:
                break
            times.append(current.time)
            current = current.prev
        
        if not times:
            return self.time
        
        times.sort()
        self._median_time_past = times[len(times) // 2]
        
        return self._median_time_past
    
    def get_ancestor(self, height: int) -> Optional['CBlockIndex']:
        """
        Get ancestor at specified height.
        
        Uses skip pointers for efficient traversal.
        """
        if height > self.height or height < 0:
            return None
        
        # Walk back using skip pointers
        current = self
        
        while current and current.height > height:
            # Use skip pointer if it gets us closer
            if current.skip and current.skip.height >= height:
                current = current.skip
            elif current.prev:
                current = current.prev
            else:
                return None
        
        return current if current and current.height == height else None
    
    def __repr__(self) -> str:
        return f"CBlockIndex(height={self.height}, hash={self.hash.hex()[:16]}...)"
    
    def __hash__(self) -> int:
        return hash(self.hash)
    
    def __eq__(self, other: object) -> bool:
        if isinstance(other, CBlockIndex):
            return self.hash == other.hash
        return False


# ============================================================================
# Chain (Active Chain)
# ============================================================================

class CChain:
    """
    Active chain management.
    
    This maintains the current active chain and provides
    efficient navigation through the chain.
    """
    
    def __init__(self):
        # Map of height -> block index
        self._chain: Dict[int, CBlockIndex] = OrderedDict()
        
        # Map of hash -> block index
        self._index: Dict[bytes, CBlockIndex] = {}
        
        # Genesis block
        self._genesis: Optional[CBlockIndex] = None
        
        # Tip of the chain
        self._tip: Optional[CBlockIndex] = None
    
    def set_tip(self, tip: CBlockIndex) -> None:
        """
        Set the tip of the chain.
        
        This rebuilds the chain map from the tip back to genesis.
        """
        self._chain.clear()
        
        current = tip
        while current:
            self._chain[current.height] = current
            current = current.prev
        
        self._tip = tip
        
        if tip.height == 0:
            self._genesis = tip
    
    def get_tip(self) -> Optional[CBlockIndex]:
        """Get the tip of the chain."""
        return self._tip
    
    def get_genesis(self) -> Optional[CBlockIndex]:
        """Get the genesis block."""
        return self._genesis
    
    def contains(self, block_index: CBlockIndex) -> bool:
        """Check if a block index is in the active chain."""
        if block_index.height not in self._chain:
            return False
        return self._chain[block_index.height].hash == block_index.hash
    
    def contains_hash(self, block_hash: bytes) -> bool:
        """Check if a block hash is in the active chain."""
        return block_hash in self._index
    
    def find_height(self, block_hash: bytes) -> int:
        """
        Find the height of a block in the chain.
        
        Returns -1 if not found.
        """
        if block_hash not in self._index:
            return -1
        return self._index[block_hash].height
    
    def operator_bracket(self, height: int) -> Optional[CBlockIndex]:
        """Get block index at height (like C++ operator[])."""
        return self._chain.get(height)
    
    def __getitem__(self, height: int) -> Optional[CBlockIndex]:
        """Get block index at height."""
        return self._chain.get(height)
    
    def height(self) -> int:
        """Get the current chain height."""
        return self._tip.height if self._tip else -1
    
    def get_ancestor(self, height: int) -> Optional[CBlockIndex]:
        """Get ancestor at height."""
        if self._tip is None:
            return None
        return self._tip.get_ancestor(height)
    
    def next(self, block_index: CBlockIndex) -> Optional[CBlockIndex]:
        """Get the next block in the chain after block_index."""
        return self._chain.get(block_index.height + 1)
    
    def find_fork(self, block_index: CBlockIndex) -> Optional[CBlockIndex]:
        """
        Find the last common ancestor between this chain and a block.
        
        This is used during reorganizations.
        """
        if block_index is None:
            return None
        
        # Find block in our chain with same height
        current = block_index
        
        while current:
            if self.contains(current):
                return current
            current = current.prev
        
        return None
    
    def add_block_index(self, index: CBlockIndex) -> None:
        """Add a block index to the hash map."""
        self._index[index.hash] = index
    
    def __len__(self) -> int:
        return len(self._chain)
    
    def __iter__(self):
        """Iterate over chain in height order."""
        for height in sorted(self._chain.keys()):
            yield self._chain[height]


# ============================================================================
# Chain State Manager
# ============================================================================

@dataclass
class ChainState:
    """
    Global chain state.
    
    Tracks the active chain and various state flags.
    """
    
    # The active chain
    chain: CChain = field(default_factory=CChain)
    
    # Best invalid block hash (for marking bad chains)
    best_invalid: bytes = field(default_factory=lambda: bytes(32))
    
    # Snapshot block hash (for assumeutxo)
    snapshot_block_hash: bytes = field(default_factory=lambda: bytes(32))
    
    # Flags
    disabled: bool = False
    
    # Initial block download status
    is_initial_block_download: bool = True
    
    def get_tip(self) -> Optional[CBlockIndex]:
        """Get the chain tip."""
        return self.chain.get_tip()
    
    def height(self) -> int:
        """Get the chain height."""
        return self.chain.height()
    
    def is_valid_tip(self, block_index: CBlockIndex) -> bool:
        """Check if a block index is the current tip."""
        tip = self.get_tip()
        return tip is not None and tip == block_index


# ============================================================================
# Block Manager
# ============================================================================

class BlockManager:
    """
    Manager for block data and indices.
    
    Handles:
    - Block index creation and lookup
    - Block storage
    - Chain selection
    """
    
    def __init__(self):
        # All known block indices (including orphans)
        self._block_index: Dict[bytes, CBlockIndex] = {}
        
        # Current chain state
        self._active_chainstate = ChainState()
        
        # Block data storage (simplified - real implementation uses files)
        self._blocks: Dict[bytes, Block] = {}
    
    def add_block(self, block: Block) -> CBlockIndex:
        """
        Add a new block and create its index.
        
        Args:
            block: The block to add
            
        Returns:
            The created block index
        """
        block_hash = block.hash
        
        # Check if already exists
        if block_hash in self._block_index:
            return self._block_index[block_hash]
        
        # Create block index
        index = CBlockIndex(
            hash=block_hash,
            version=block.header.version,
            hash_prev_block=block.header.hash_prev_block,
            merkle_root=block.header.merkle_root,
            time=block.header.time,
            n_bits=block.header.n_bits,
            nonce=block.header.nonce,
            tx_count=len(block.transactions)
        )
        
        # Set height and parent link
        if block.header.hash_prev_block == bytes(32):
            # Genesis block
            index.height = 0
        else:
            # Find parent
            parent = self._block_index.get(block.header.hash_prev_block)
            if parent:
                index.height = parent.height + 1
                index.prev = parent
        
        # Add to index map
        self._block_index[block_hash] = index
        
        # Store block data
        self._blocks[block_hash] = block
        
        return index
    
    def get_block_index(self, block_hash: bytes) -> Optional[CBlockIndex]:
        """Get block index by hash."""
        return self._block_index.get(block_hash)
    
    def get_block(self, block_hash: bytes) -> Optional[Block]:
        """Get block data by hash."""
        return self._blocks.get(block_hash)
    
    def have_block_index(self, block_hash: bytes) -> bool:
        """Check if block index exists."""
        return block_hash in self._block_index
    
    def have_block_data(self, block_hash: bytes) -> bool:
        """Check if block data exists."""
        return block_hash in self._blocks
    
    def activate_chain(self, tip: CBlockIndex) -> None:
        """Set the active chain tip."""
        self._active_chainstate.chain.set_tip(tip)
    
    def get_active_chain(self) -> CChain:
        """Get the active chain."""
        return self._active_chainstate.chain
    
    def lookup_block_index(self, block_hash: bytes) -> Optional[CBlockIndex]:
        """Lookup block index (alias for get_block_index)."""
        return self.get_block_index(block_hash)
