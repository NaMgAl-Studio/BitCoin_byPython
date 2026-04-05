"""
Bitcoin Address Manager.

This module implements the address manager for storing and selecting
peer addresses for the Bitcoin P2P network.

Reference: Bitcoin Core src/addrman.h, src/addrman.cpp
"""

from __future__ import annotations

import os
import random
import time
from dataclasses import dataclass, field
from typing import Final, Dict, List, Optional, Set, Tuple
from datetime import datetime, timezone

from .netaddress import CNetAddr, CService, CSubNet, Network
from .protocol import ServiceFlags
from .netbase import is_bad_port


# ==============================================================================
# Constants
# ==============================================================================

ADDRMAN_NEW_BUCKETS: Final[int] = 1 << 10  # 1024 buckets for new addresses
ADDRMAN_TRIED_BUCKETS: Final[int] = 1 << 8  # 256 buckets for tried addresses
ADDRMAN_BUCKET_SIZE: Final[int] = 64  # Maximum entries per bucket
ADDRMAN_HORIZON: Final[int] = 24 * 60 * 60  # 24 hours in seconds
ADDRMAN_RETRIES: Final[int] = 3
ADDRMAN_MAX_FAILURES: Final[int] = 10
ADDRMAN_MIN_FAIL: Final[int] = 7 * 24 * 60 * 60  # 7 days
ADDRMAN_MAX_FAILURES_AGE: Final[int] = 1 << 28  # About 8.5 years

# Deterministic salt
ADDRMAN_DETERMINISTIC_SALT: Final[bytes] = b'\x00' * 32


# ==============================================================================
# Address Information
# ==============================================================================

@dataclass
class AddrInfo:
    """
    Extended address information for the address manager.
    
    Stores additional metadata about peer addresses beyond what
    CAddress provides.
    """
    
    # Inherited from CAddress
    address: CService
    source: CNetAddr
    n_services: ServiceFlags = ServiceFlags.NODE_NONE
    n_time: int = 0  # Last seen time (Unix timestamp)
    
    # Address manager specific fields
    n_last_try: int = 0  # Last connection attempt
    n_last_count_attempt: int = 0  # Last "counted" attempt
    n_last_success: int = 0  # Last successful connection
    n_attempts: int = 0  # Connection attempts
    
    # Position in bucket
    n_bucket_pos: int = 0
    
    def __post_init__(self):
        if self.n_time == 0:
            self.n_time = int(datetime.now(timezone.utc).timestamp())
    
    @property
    def is_valid(self) -> bool:
        """Check if address is valid."""
        return self.address.is_valid()
    
    @property
    def is_routable(self) -> bool:
        """Check if address is routable."""
        return self.address.is_routable()
    
    def get_last_seen(self) -> int:
        """Get last seen timestamp."""
        return self.n_time
    
    def get_last_try(self) -> int:
        """Get last try timestamp."""
        return self.n_last_try
    
    def get_network(self) -> Network:
        """Get the network type."""
        return self.address.get_network()
    
    def serialize(self) -> bytes:
        """Serialize the address info."""
        result = bytearray()
        
        # Time (4 bytes)
        result.extend(self.n_time.to_bytes(4, 'little'))
        
        # Services (8 bytes)
        result.extend(self.n_services.to_bytes(8, 'little'))
        
        # Address (network serialization)
        result.extend(self.address.serialize_v1())
        
        # Source
        result.extend(self.source.serialize_v1())
        
        # Last try (4 bytes)
        result.extend(self.n_last_try.to_bytes(4, 'little'))
        
        return bytes(result)
    
    @classmethod
    def deserialize(cls, data: bytes) -> Tuple[AddrInfo, int]:
        """Deserialize from bytes. Returns (AddrInfo, bytes_consumed)."""
        pos = 0
        
        # Time
        n_time = int.from_bytes(data[pos:pos + 4], 'little')
        pos += 4
        
        # Services
        n_services = ServiceFlags(int.from_bytes(data[pos:pos + 8], 'little'))
        pos += 8
        
        # Address
        address, consumed = CService.deserialize_v1(data[pos:])
        pos += consumed
        
        # Source
        source, consumed = CNetAddr.deserialize_v1(data[pos:])
        pos += consumed
        
        # Last try
        n_last_try = int.from_bytes(data[pos:pos + 4], 'little')
        pos += 4
        
        return cls(
            address=address,
            source=source,
            n_services=n_services,
            n_time=n_time,
            n_last_try=n_last_try
        ), pos


# ==============================================================================
# Address Manager
# ==============================================================================

class AddrMan:
    """
    Address Manager.
    
    Manages peer addresses for the Bitcoin P2P network, organizing them
    into "new" and "tried" buckets for efficient peer selection.
    """
    
    def __init__(self, asmap: bytes = b"", deterministic: bool = False):
        """
        Initialize the address manager.
        
        Args:
            asmap: ASMap for ASN-based bucketing
            deterministic: Use deterministic operation (for testing)
        """
        self._asmap = asmap
        self._deterministic = deterministic
        
        # Generate random salt for bucketing
        if deterministic:
            self._n_key = ADDRMAN_DETERMINISTIC_SALT
        else:
            self._n_key = os.urandom(32)
        
        # Storage
        self._map_addr: Dict[CService, int] = {}  # address -> id
        self._map_info: Dict[int, AddrInfo] = {}  # id -> info
        self._n_id_counter = 0
        
        # New addresses (untried)
        self._vv_new: List[List[int]] = [[] for _ in range(ADDRMAN_NEW_BUCKETS)]
        
        # Tried addresses
        self._vv_tried: List[List[int]] = [[] for _ in range(ADDRMAN_TRIED_BUCKETS)]
        
        # Random position tracking
        self._random_selection = False
        self._random_pos = 0
        
        # Statistics
        self._n_new = 0
        self._n_tried = 0
    
    # ==========================================================================
    # Bucketing Functions
    # ==========================================================================
    
    def _compute_bucket(
        self,
        addr: CNetAddr,
        source: CNetAddr,
        bucket_count: int,
        use_asmap: bool = False
    ) -> int:
        """
        Compute the bucket for an address.
        
        The bucket is determined by a hash of the address and source,
        ensuring that addresses from different sources are spread
        across different buckets.
        """
        # Simplified bucket computation
        addr_bytes = addr.get_addr_bytes()
        source_bytes = source.get_addr_bytes() if hasattr(source, 'get_addr_bytes') else b''
        
        # Use nKey as salt
        data = self._n_key + addr_bytes + source_bytes
        
        # Simple hash (in production would use SipHash)
        h = int.from_bytes(data[:8], 'little') if len(data) >= 8 else 0
        for i in range(8, len(data), 8):
            chunk = data[i:i + 8]
            if len(chunk) < 8:
                chunk = chunk + b'\x00' * (8 - len(chunk))
            h ^= int.from_bytes(chunk, 'little')
        
        return h % bucket_count
    
    def _compute_bucket_position(
        self,
        addr: CNetAddr,
        bucket: int,
        bucket_count: int
    ) -> int:
        """Compute the position within a bucket."""
        addr_bytes = addr.get_addr_bytes()
        data = self._n_key + bucket.to_bytes(4, 'little') + addr_bytes
        
        h = int.from_bytes(data[:8], 'little') if len(data) >= 8 else 0
        return h % ADDRMAN_BUCKET_SIZE
    
    # ==========================================================================
    # Address Management
    # ==========================================================================
    
    def add(
        self,
        addr: CService,
        source: CNetAddr,
        time_penalty: int = 0
    ) -> bool:
        """
        Add an address to the manager.
        
        Args:
            addr: Address to add
            source: Source of the address
            time_penalty: Time penalty to apply
            
        Returns:
            True if address was added or updated
        """
        if not addr.is_valid():
            return False
        
        if is_bad_port(addr.get_port()):
            return False
        
        # Check if already exists
        if addr in self._map_addr:
            # Update existing
            n_id = self._map_addr[addr]
            info = self._map_info[n_id]
            
            # Update time if newer
            current_time = int(datetime.now(timezone.utc).timestamp())
            if info.n_time < current_time - time_penalty:
                info.n_time = current_time - time_penalty
            
            return False
        
        # Create new address info
        current_time = int(datetime.now(timezone.utc).timestamp())
        info = AddrInfo(
            address=addr,
            source=source,
            n_time=max(0, current_time - time_penalty),
            n_last_try=0,
            n_last_success=0,
            n_attempts=0
        )
        
        # Add to new bucket
        n_id = self._n_id_counter
        self._n_id_counter += 1
        
        self._map_info[n_id] = info
        self._map_addr[addr] = n_id
        
        bucket = self._compute_bucket(addr, source, ADDRMAN_NEW_BUCKETS)
        bucket_pos = self._compute_bucket_position(addr, bucket, ADDRMAN_NEW_BUCKETS)
        
        info.n_bucket_pos = bucket_pos
        
        # Add to bucket (if space)
        if len(self._vv_new[bucket]) < ADDRMAN_BUCKET_SIZE:
            self._vv_new[bucket].append(n_id)
            self._n_new += 1
            return True
        
        return False
    
    def add_many(
        self,
        addrs: List[CService],
        source: CNetAddr,
        time_penalty: int = 0
    ) -> int:
        """
        Add multiple addresses.
        
        Args:
            addrs: List of addresses to add
            source: Source of the addresses
            time_penalty: Time penalty to apply
            
        Returns:
            Number of addresses added
        """
        count = 0
        for addr in addrs:
            if self.add(addr, source, time_penalty):
                count += 1
        return count
    
    def remove(self, addr: CService) -> bool:
        """
        Remove an address from the manager.
        
        Args:
            addr: Address to remove
            
        Returns:
            True if address was found and removed
        """
        if addr not in self._map_addr:
            return False
        
        n_id = self._map_addr[addr]
        info = self._map_info[n_id]
        
        # Remove from bucket
        # Would need to track which bucket it's in
        # Simplified implementation
        
        del self._map_addr[addr]
        del self._map_info[n_id]
        
        return True
    
    # ==========================================================================
    # Selection Functions
    # ==========================================================================
    
    def select(
        self,
        network: Optional[Network] = None,
        new_only: bool = False,
        reachable_only: bool = True
    ) -> Optional[AddrInfo]:
        """
        Select an address to connect to.
        
        Args:
            network: Filter by network type
            new_only: Only select from new addresses
            reachable_only: Only select reachable addresses
            
        Returns:
            Selected address or None
        """
        # Select with probability favoring tried addresses
        use_tried = random.random() < 0.8 and not new_only
        
        if use_tried and self._n_tried > 0:
            return self._select_from_tried(network, reachable_only)
        elif self._n_new > 0:
            return self._select_from_new(network, reachable_only)
        
        return None
    
    def _select_from_tried(
        self,
        network: Optional[Network],
        reachable_only: bool
    ) -> Optional[AddrInfo]:
        """Select an address from tried buckets."""
        candidates = []
        
        for bucket in self._vv_tried:
            for n_id in bucket:
                info = self._map_info.get(n_id)
                if info is None:
                    continue
                
                if network is not None and info.get_network() != network:
                    continue
                
                if reachable_only and not info.is_routable:
                    continue
                
                candidates.append(info)
        
        if not candidates:
            return None
        
        return random.choice(candidates)
    
    def _select_from_new(
        self,
        network: Optional[Network],
        reachable_only: bool
    ) -> Optional[AddrInfo]:
        """Select an address from new buckets."""
        candidates = []
        
        for bucket in self._vv_new:
            for n_id in bucket:
                info = self._map_info.get(n_id)
                if info is None:
                    continue
                
                if network is not None and info.get_network() != network:
                    continue
                
                if reachable_only and not info.is_routable:
                    continue
                
                candidates.append(info)
        
        if not candidates:
            return None
        
        return random.choice(candidates)
    
    def select_random(
        self,
        max_count: int,
        network: Optional[Network] = None
    ) -> List[AddrInfo]:
        """
        Select random addresses.
        
        Args:
            max_count: Maximum number to return
            network: Filter by network type
            
        Returns:
            List of selected addresses
        """
        candidates = []
        
        for n_id, info in self._map_info.items():
            if network is not None and info.get_network() != network:
                continue
            candidates.append(info)
        
        random.shuffle(candidates)
        return candidates[:max_count]
    
    # ==========================================================================
    # Address State Updates
    # ==========================================================================
    
    def good(self, addr: CService, n_time: Optional[int] = None) -> None:
        """
        Mark an address as good (successfully connected).
        
        Args:
            addr: Address to mark
            n_time: Time of success (defaults to now)
        """
        if addr not in self._map_addr:
            return
        
        current_time = n_time or int(datetime.now(timezone.utc).timestamp())
        n_id = self._map_addr[addr]
        info = self._map_info[n_id]
        
        info.n_last_success = current_time
        info.n_last_try = current_time
        info.n_attempts = 0
        
        # Move from new to tried
        # Simplified - would need proper bucket management
    
    def attempt(self, addr: CService, f_count: bool, n_time: Optional[int] = None) -> None:
        """
        Record a connection attempt.
        
        Args:
            addr: Address attempted
            f_count: Whether this attempt counts toward failure threshold
            n_time: Time of attempt
        """
        if addr not in self._map_addr:
            return
        
        current_time = n_time or int(datetime.now(timezone.utc).timestamp())
        n_id = self._map_addr[addr]
        info = self._map_info[n_id]
        
        info.n_last_try = current_time
        
        if f_count:
            info.n_last_count_attempt = current_time
            info.n_attempts += 1
    
    def connected(self, addr: CService, n_time: Optional[int] = None) -> None:
        """
        Mark an address as connected (but not necessarily successful).
        
        Args:
            addr: Address connected to
            n_time: Time of connection
        """
        if addr not in self._map_addr:
            return
        
        current_time = n_time or int(datetime.now(timezone.utc).timestamp())
        n_id = self._map_addr[addr]
        info = self._map_info[n_id]
        
        info.n_time = current_time
    
    def set_services(self, addr: CService, n_services: ServiceFlags) -> None:
        """
        Set services for an address.
        
        Args:
            addr: Address to update
            n_services: Service flags
        """
        if addr not in self._map_addr:
            return
        
        n_id = self._map_addr[addr]
        self._map_info[n_id].n_services = n_services
    
    # ==========================================================================
    # Address Lookup
    # ==========================================================================
    
    def find(self, addr: CService) -> Optional[AddrInfo]:
        """
        Find an address in the manager.
        
        Args:
            addr: Address to find
            
        Returns:
            AddrInfo if found, None otherwise
        """
        if addr not in self._map_addr:
            return None
        
        n_id = self._map_addr[addr]
        return self._map_info.get(n_id)
    
    def get_addr(self, max_addresses: int = 2500) -> List[AddrInfo]:
        """
        Get all addresses (up to max_addresses).
        
        Args:
            max_addresses: Maximum number to return
            
        Returns:
            List of addresses
        """
        all_addrs = list(self._map_info.values())
        random.shuffle(all_addrs)
        return all_addrs[:max_addresses]
    
    # ==========================================================================
    # Statistics
    # ==========================================================================
    
    def size(self) -> int:
        """Get total number of addresses."""
        return self._n_new + self._n_tried
    
    def size_new(self) -> int:
        """Get number of new addresses."""
        return self._n_new
    
    def size_tried(self) -> int:
        """Get number of tried addresses."""
        return self._n_tried
    
    # ==========================================================================
    # Serialization
    # ==========================================================================
    
    def serialize(self) -> bytes:
        """Serialize the address manager to bytes."""
        result = bytearray()
        
        # Version
        result.extend((1).to_bytes(4, 'little'))
        
        # nKey (salt)
        result.extend(self._n_key)
        
        # Number of new addresses
        result.extend(self._n_new.to_bytes(4, 'little'))
        
        # Number of tried addresses
        result.extend(self._n_tried.to_bytes(4, 'little'))
        
        # Serialize all addresses
        for n_id, info in self._map_info.items():
            result.extend(info.serialize())
        
        return bytes(result)
    
    @classmethod
    def deserialize(cls, data: bytes) -> AddrMan:
        """Deserialize an address manager from bytes."""
        pos = 0
        
        # Version
        _ = int.from_bytes(data[pos:pos + 4], 'little')
        pos += 4
        
        # nKey
        n_key = data[pos:pos + 32]
        pos += 32
        
        # Create instance
        addr_man = cls(deterministic=True)
        addr_man._n_key = n_key
        
        # New count
        n_new = int.from_bytes(data[pos:pos + 4], 'little')
        pos += 4
        
        # Tried count
        n_tried = int.from_bytes(data[pos:pos + 4], 'little')
        pos += 4
        
        # Read addresses
        for _ in range(n_new + n_tried):
            info, consumed = AddrInfo.deserialize(data[pos:])
            pos += consumed
            
            n_id = addr_man._n_id_counter
            addr_man._n_id_counter += 1
            
            addr_man._map_info[n_id] = info
            addr_man._map_addr[info.address] = n_id
        
        addr_man._n_new = n_new
        addr_man._n_tried = n_tried
        
        return addr_man
