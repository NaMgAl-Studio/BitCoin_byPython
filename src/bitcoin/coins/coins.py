# Copyright (c) 2009-2010 Satoshi Nakamoto
# Copyright (c) 2009-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Bitcoin Coins (UTXO) Management

This module implements UTXO (Unspent Transaction Output) management:
- Coin: A single UTXO entry
- CoinsView: Abstract view of UTXO dataset
- CoinsViewCache: Cached view with modification tracking
"""

from dataclasses import dataclass, field
from typing import Dict, Optional, List, Set, Tuple, Iterator
from copy import deepcopy

from ..primitives.transaction import Transaction, TransactionOutput, OutPoint
from ..consensus.consensus import MAX_MONEY


# ============================================================================
# Coin Class
# ============================================================================

@dataclass
class Coin:
    """
    A UTXO entry.
    
    Represents an unspent transaction output with its metadata:
    - The output itself (value and scriptPubKey)
    - Whether it was a coinbase output
    - The height at which it was included
    
    Serialized format:
    - VARINT((coinbase ? 1 : 0) | (height << 1))
    - The non-spent CTxOut (compressed)
    """
    
    output: TransactionOutput
    is_coinbase: bool = False
    height: int = 0
    
    def is_spent(self) -> bool:
        """Check if this coin has been spent."""
        return self.output is None or self.output.is_null()
    
    def clear(self) -> None:
        """Clear this coin (mark as spent)."""
        self.output = TransactionOutput(value=-1, script_pubkey=b'')
        self.is_coinbase = False
        self.height = 0
    
    def dynamic_memory_usage(self) -> int:
        """Estimate memory usage of this coin."""
        if self.output is None:
            return 0
        return len(self.output.script_pubkey) + 32  # Rough estimate
    
    @classmethod
    def from_txout(cls, txout: TransactionOutput, height: int, is_coinbase: bool) -> 'Coin':
        """Create a coin from a transaction output."""
        return cls(output=txout, height=height, is_coinbase=is_coinbase)
    
    def serialize(self) -> bytes:
        """Serialize this coin."""
        # Encode height and coinbase flag
        code = (self.height << 1) | (1 if self.is_coinbase else 0)
        
        # Simple varint encoding
        result = bytearray()
        while code >= 0x80:
            result.append((code & 0x7f) | 0x80)
            code >>= 7
        result.append(code)
        
        # Serialize output (compressed)
        result.extend(self._serialize_txout(self.output))
        
        return bytes(result)
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'Coin':
        """Deserialize a coin from bytes."""
        # Decode varint
        code = 0
        shift = 0
        i = 0
        
        while i < len(data):
            byte = data[i]
            code |= (byte & 0x7f) << shift
            shift += 7
            i += 1
            
            if not (byte & 0x80):
                break
        
        height = code >> 1
        is_coinbase = bool(code & 1)
        
        # Deserialize output
        output_data = data[i:]
        output = cls._deserialize_txout(output_data)
        
        return cls(output=output, height=height, is_coinbase=is_coinbase)
    
    @staticmethod
    def _serialize_txout(txout: TransactionOutput) -> bytes:
        """Serialize a transaction output."""
        result = bytearray()
        
        # Value (8 bytes little-endian)
        result.extend(txout.value.to_bytes(8, 'little'))
        
        # Script length (varint) + script
        script_len = len(txout.script_pubkey)
        while script_len >= 0x80:
            result.append((script_len & 0x7f) | 0x80)
            script_len >>= 7
        result.append(script_len)
        
        result.extend(txout.script_pubkey)
        
        return bytes(result)
    
    @staticmethod
    def _deserialize_txout(data: bytes) -> TransactionOutput:
        """Deserialize a transaction output."""
        if len(data) < 8:
            return TransactionOutput(value=0, script_pubkey=b'')
        
        # Value
        value = int.from_bytes(data[:8], 'little')
        
        # Script length
        script_len = 0
        shift = 0
        i = 8
        
        while i < len(data):
            byte = data[i]
            script_len |= (byte & 0x7f) << shift
            shift += 7
            i += 1
            
            if not (byte & 0x80):
                break
        
        # Script
        script = data[i:i + script_len] if i + script_len <= len(data) else b''
        
        return TransactionOutput(value=value, script_pubkey=script)


# Empty coin constant
COIN_EMPTY = Coin(output=TransactionOutput(value=-1, script_pubkey=b''), height=0, is_coinbase=False)


# ============================================================================
# Coins Cache Entry
# ============================================================================

class CacheFlags:
    """Flags for coins cache entries."""
    DIRTY = 1 << 0  # Potentially different from parent
    FRESH = 1 << 1  # Parent doesn't have this coin, or it's spent


@dataclass
class CoinsCacheEntry:
    """
    A Coin in one level of the coins database caching hierarchy.
    
    A coin can be:
    - unspent or spent
    - DIRTY or not DIRTY
    - FRESH or not FRESH
    
    Valid state combinations:
    - unspent, FRESH, DIRTY (new coin created in cache)
    - unspent, not FRESH, DIRTY (coin changed during reorg)
    - unspent, not FRESH, not DIRTY (unspent coin from parent cache)
    - spent, not FRESH, DIRTY (spent coin needing flush to parent)
    """
    
    coin: Coin
    flags: int = 0
    
    def is_dirty(self) -> bool:
        return bool(self.flags & CacheFlags.DIRTY)
    
    def is_fresh(self) -> bool:
        return bool(self.flags & CacheFlags.FRESH)
    
    def set_dirty(self) -> None:
        self.flags |= CacheFlags.DIRTY
    
    def set_fresh(self) -> None:
        self.flags |= CacheFlags.FRESH
    
    def clear_flags(self) -> None:
        self.flags = 0


# ============================================================================
# Coins View (Abstract Base)
# ============================================================================

class CoinsView:
    """
    Abstract view on the open txout dataset.
    
    This is the base class for UTXO views. Subclasses implement
    actual storage and retrieval mechanisms.
    """
    
    def __init__(self):
        self._best_block: bytes = bytes(32)
    
    def get_coin(self, outpoint: OutPoint) -> Optional[Coin]:
        """
        Retrieve the Coin for a given outpoint.
        May populate the cache.
        
        Args:
            outpoint: The outpoint to look up
            
        Returns:
            The coin if unspent, None otherwise
        """
        raise NotImplementedError
    
    def peek_coin(self, outpoint: OutPoint) -> Optional[Coin]:
        """
        Retrieve the Coin without caching results.
        
        Args:
            outpoint: The outpoint to look up
            
        Returns:
            The coin if unspent, None otherwise
        """
        raise NotImplementedError
    
    def have_coin(self, outpoint: OutPoint) -> bool:
        """
        Check whether a given outpoint is unspent.
        
        Args:
            outpoint: The outpoint to check
            
        Returns:
            True if unspent
        """
        coin = self.get_coin(outpoint)
        return coin is not None and not coin.is_spent()
    
    def get_best_block(self) -> bytes:
        """
        Retrieve the block hash whose state this view represents.
        
        Returns:
            32-byte block hash
        """
        return self._best_block
    
    def set_best_block(self, block_hash: bytes) -> None:
        """Set the best block hash for this view."""
        self._best_block = block_hash
    
    def batch_write(self, coins: Dict[OutPoint, CoinsCacheEntry], 
                   block_hash: bytes) -> None:
        """
        Do a bulk modification (multiple Coin changes + BestBlock change).
        
        Args:
            coins: Map of outpoints to cache entries
            block_hash: New best block hash
        """
        raise NotImplementedError
    
    def estimate_size(self) -> int:
        """Estimate database size."""
        return 0


# ============================================================================
# Coins View Backed
# ============================================================================

class CoinsViewBacked(CoinsView):
    """
    A CoinsView that is backed by another CoinsView.
    
    This allows stacking views on top of each other.
    """
    
    def __init__(self, base: Optional[CoinsView] = None):
        super().__init__()
        self._base = base
    
    @property
    def base(self) -> Optional[CoinsView]:
        return self._base
    
    def set_backend(self, view: CoinsView) -> None:
        """Set the backend view."""
        self._base = view
    
    def get_coin(self, outpoint: OutPoint) -> Optional[Coin]:
        if self._base is None:
            return None
        return self._base.get_coin(outpoint)
    
    def peek_coin(self, outpoint: OutPoint) -> Optional[Coin]:
        if self._base is None:
            return None
        return self._base.peek_coin(outpoint)
    
    def have_coin(self, outpoint: OutPoint) -> bool:
        if self._base is None:
            return False
        return self._base.have_coin(outpoint)
    
    def get_best_block(self) -> bytes:
        if self._base is not None:
            return self._base.get_best_block()
        return self._best_block
    
    def batch_write(self, coins: Dict[OutPoint, CoinsCacheEntry],
                   block_hash: bytes) -> None:
        if self._base is not None:
            self._base.batch_write(coins, block_hash)
    
    def estimate_size(self) -> int:
        if self._base is not None:
            return self._base.estimate_size()
        return 0


# ============================================================================
# Coins View Cache
# ============================================================================

class CoinsViewCache(CoinsViewBacked):
    """
    A CoinsView that adds a memory cache for UTXOs.
    
    This provides caching on top of a base view, with modification
    tracking for efficient flushing.
    """
    
    def __init__(self, base: Optional[CoinsView] = None, deterministic: bool = False):
        super().__init__(base)
        self._deterministic = deterministic
        self._cache: Dict[OutPoint, CoinsCacheEntry] = {}
        self._cached_coins_usage: int = 0
        self._dirty_count: int = 0
    
    def get_coin(self, outpoint: OutPoint) -> Optional[Coin]:
        """Get a coin, populating cache if needed."""
        # Check cache first
        if outpoint in self._cache:
            entry = self._cache[outpoint]
            if entry.coin.is_spent():
                return None
            return entry.coin
        
        # Fetch from base
        if self._base is None:
            return None
        
        coin = self._base.get_coin(outpoint)
        if coin is None:
            return None
        
        # Add to cache
        entry = CoinsCacheEntry(coin=coin)
        self._cache[outpoint] = entry
        self._cached_coins_usage += coin.dynamic_memory_usage()
        
        return coin
    
    def peek_coin(self, outpoint: OutPoint) -> Optional[Coin]:
        """Get a coin without populating intermediate caches."""
        # Check cache first
        if outpoint in self._cache:
            entry = self._cache[outpoint]
            if entry.coin.is_spent():
                return None
            return entry.coin
        
        # Peek from base
        if self._base is None:
            return None
        
        return self._base.peek_coin(outpoint)
    
    def have_coin(self, outpoint: OutPoint) -> bool:
        """Check if a coin exists and is unspent."""
        # Check cache first
        if outpoint in self._cache:
            return not self._cache[outpoint].coin.is_spent()
        
        return super().have_coin(outpoint)
    
    def have_coin_in_cache(self, outpoint: OutPoint) -> bool:
        """Check if we have a coin in this cache (not checking parent)."""
        if outpoint in self._cache:
            return not self._cache[outpoint].coin.is_spent()
        return False
    
    def access_coin(self, outpoint: OutPoint) -> Coin:
        """
        Return a reference to Coin in the cache, or empty if not found.
        
        This is more efficient than get_coin as it returns a reference
        instead of a copy.
        """
        coin = self.get_coin(outpoint)
        return coin if coin is not None else COIN_EMPTY
    
    def add_coin(self, outpoint: OutPoint, coin: Coin, 
                 possible_overwrite: bool = False) -> None:
        """
        Add a coin to the cache.
        
        Args:
            outpoint: The outpoint
            coin: The coin to add
            possible_overwrite: If True, allow overwriting existing coin
        """
        if outpoint in self._cache:
            if not possible_overwrite:
                raise ValueError("Attempt to overwrite existing coin")
            # Update existing entry
            old_entry = self._cache[outpoint]
            self._cached_coins_usage -= old_entry.coin.dynamic_memory_usage()
            old_entry.coin = coin
            old_entry.set_dirty()
        else:
            # Create new entry
            entry = CoinsCacheEntry(coin=coin, flags=CacheFlags.DIRTY | CacheFlags.FRESH)
            self._cache[outpoint] = entry
            self._dirty_count += 1
        
        self._cached_coins_usage += coin.dynamic_memory_usage()
    
    def spend_coin(self, outpoint: OutPoint, 
                   moveto: Optional[Coin] = None) -> bool:
        """
        Spend a coin.
        
        Args:
            outpoint: The outpoint to spend
            moveto: Optional output parameter to receive the spent coin
            
        Returns:
            True if the coin was spent, False if it didn't exist
        """
        entry = self._cache.get(outpoint)
        
        if entry is None:
            # Need to fetch from base
            if self._base is not None:
                coin = self._base.get_coin(outpoint)
                if coin is None or coin.is_spent():
                    return False
                
                # Add spent entry to cache
                entry = CoinsCacheEntry(coin=COIN_EMPTY, flags=CacheFlags.DIRTY)
                self._cache[outpoint] = entry
                self._dirty_count += 1
                
                if moveto is not None:
                    # Copy the coin data
                    moveto = deepcopy(coin)
                
                return True
            return False
        
        if entry.coin.is_spent():
            return False
        
        if moveto is not None:
            moveto = deepcopy(entry.coin)
        
        # Mark as spent
        old_usage = entry.coin.dynamic_memory_usage()
        entry.coin = COIN_EMPTY
        self._cached_coins_usage -= old_usage
        entry.flags &= ~CacheFlags.FRESH
        
        return True
    
    def have_inputs(self, tx: Transaction) -> bool:
        """Check whether all prevouts of the transaction are present."""
        if tx.is_coinbase():
            return True
        
        for txin in tx.inputs:
            if not self.have_coin(txin.prevout):
                return False
        
        return True
    
    def get_cache_size(self) -> int:
        """Get size of cache in number of coins."""
        return len(self._cache)
    
    def get_dirty_count(self) -> int:
        """Get number of dirty cache entries."""
        return self._dirty_count
    
    def dynamic_memory_usage(self) -> int:
        """Calculate size of cache in bytes."""
        return self._cached_coins_usage + len(self._cache) * 64  # Rough overhead
    
    def flush(self, reallocate_cache: bool = True) -> None:
        """
        Push modifications to base view and wipe local state.
        
        Args:
            reallocate_cache: Whether to reallocate memory after flush
        """
        if self._base is None:
            return
        
        self._base.batch_write(self._cache, self._best_block)
        
        # Clear cache
        self._cache.clear()
        self._cached_coins_usage = 0
        self._dirty_count = 0
        
        if reallocate_cache:
            self._cache = {}
    
    def sync(self) -> None:
        """
        Push modifications to base while retaining cache contents.
        
        Spent coins are erased from the cache.
        """
        if self._base is None:
            return
        
        # Filter out spent coins and clear flags
        to_write = {}
        for outpoint, entry in list(self._cache.items()):
            if entry.is_dirty():
                to_write[outpoint] = entry
        
        self._base.batch_write(to_write, self._best_block)
        
        # Clear spent coins and flags
        for outpoint in list(self._cache.keys()):
            entry = self._cache[outpoint]
            if entry.coin.is_spent():
                del self._cache[outpoint]
            else:
                entry.clear_flags()
        
        self._dirty_count = 0
    
    def uncache(self, outpoint: OutPoint) -> None:
        """Remove a coin from cache if not modified."""
        if outpoint in self._cache:
            entry = self._cache[outpoint]
            if not entry.is_dirty():
                self._cached_coins_usage -= entry.coin.dynamic_memory_usage()
                del self._cache[outpoint]


# ============================================================================
# Coins View Database
# ============================================================================

class CoinsViewDB(CoinsView):
    """
    Coins view backed by an in-memory database (leveldb-style).
    
    This provides a persistent UTXO set storage. For production use,
    this should be backed by a proper database (LevelDB/RocksDB).
    """
    
    def __init__(self):
        super().__init__()
        self._coins_db: Dict[bytes, bytes] = {}  # outpoint_hash -> serialized coin
        self._best_block_hash: bytes = bytes(32)
    
    def _outpoint_to_key(self, outpoint: OutPoint) -> bytes:
        """Convert an outpoint to a database key."""
        return outpoint.hash + outpoint.n.to_bytes(4, 'little')
    
    def get_coin(self, outpoint: OutPoint) -> Optional[Coin]:
        """Retrieve a coin from the database."""
        key = self._outpoint_to_key(outpoint)
        data = self._coins_db.get(key)
        if data is None:
            return None
        try:
            return Coin.deserialize(data)
        except Exception:
            return None
    
    def peek_coin(self, outpoint: OutPoint) -> Optional[Coin]:
        """Retrieve a coin without caching."""
        return self.get_coin(outpoint)
    
    def have_coin(self, outpoint: OutPoint) -> bool:
        """Check if a coin exists and is unspent."""
        key = self._outpoint_to_key(outpoint)
        data = self._coins_db.get(key)
        if data is None:
            return False
        try:
            coin = Coin.deserialize(data)
            return not coin.is_spent()
        except Exception:
            return False
    
    def get_best_block(self) -> bytes:
        """Get the best block hash."""
        return self._best_block_hash
    
    def set_best_block(self, block_hash: bytes) -> None:
        """Set the best block hash."""
        self._best_block_hash = block_hash
    
    def batch_write(self, coins: Dict[OutPoint, CoinsCacheEntry], 
                   block_hash: bytes) -> None:
        """
        Write multiple coin changes to the database.
        
        Args:
            coins: Map of outpoints to cache entries
            block_hash: New best block hash
        """
        for outpoint, entry in coins.items():
            key = self._outpoint_to_key(outpoint)
            if entry.coin.is_spent() or entry.is_dirty():
                if entry.coin.is_spent():
                    # Remove spent coin from database
                    self._coins_db.pop(key, None)
                else:
                    # Write updated coin
                    self._coins_db[key] = entry.coin.serialize()
        
        if block_hash != bytes(32):
            self._best_block_hash = block_hash
    
    def estimate_size(self) -> int:
        """Estimate database size in bytes."""
        total = 0
        for data in self._coins_db.values():
            total += len(data)
        return total
    
    def get_coin_count(self) -> int:
        """Get the number of UTXOs in the database."""
        return len(self._coins_db)
    
    def clear(self) -> None:
        """Clear all coins from the database."""
        self._coins_db.clear()


# ============================================================================
# Utility Functions
# ============================================================================

def AddCoins(cache: CoinsViewCache, tx: Transaction, height: int,
             check: bool = False) -> None:
    """
    Add all outputs of a transaction to a coins view cache.
    
    Args:
        cache: The coins cache
        tx: The transaction whose outputs to add
        height: Height at which tx was included
        check: If True, check for potential overwrites
    """
    is_coinbase = tx.is_coinbase()
    
    for i, txout in enumerate(tx.outputs):
        outpoint = OutPoint(tx.hash, i)
        coin = Coin(output=txout, height=height, is_coinbase=is_coinbase)
        cache.add_coin(outpoint, coin, possible_overwrite=check)


def AccessByTxid(cache: CoinsViewCache, txid: bytes) -> Coin:
    """
    Find any unspent output with a given txid.
    
    This can be expensive as it may check up to
    MAX_OUTPUTS_PER_BLOCK outputs.
    
    Args:
        cache: The coins cache
        txid: Transaction ID to search for
        
    Returns:
        The first unspent coin found, or empty coin
    """
    # Maximum outputs per block
    MAX_OUTPUTS_PER_BLOCK = 100
    
    for i in range(MAX_OUTPUTS_PER_BLOCK):
        outpoint = OutPoint(txid, i)
        coin = cache.get_coin(outpoint)
        
        if coin is not None:
            return coin
        
        # Check if we've gone past the last output
        if not cache.have_coin(OutPoint(txid, i)) and i > 0:
            # Output doesn't exist and previous outputs were checked
            break
    
    return COIN_EMPTY
