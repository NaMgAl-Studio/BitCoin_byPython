"""
Bitcoin DNS Seed and Peer Discovery.

This module implements DNS seed queries and peer discovery mechanisms
for the Bitcoin P2P network.

Reference: Bitcoin Core src/net.cpp, src/chainparams.cpp
"""

from __future__ import annotations

import asyncio
import socket
import struct
import time
from dataclasses import dataclass
from typing import Final, List, Optional, Dict, Callable
from datetime import datetime, timezone

from .netaddress import CNetAddr, CService, Network
from .addrman import AddrMan, AddrInfo
from .protocol import ServiceFlags, seeds_service_flags
from .netbase import lookup_host_single


# ==============================================================================
# DNS Seed Configuration
# ==============================================================================

@dataclass
class DNSSeedData:
    """DNS seed configuration."""
    
    host: str
    port: int = 8333
    
    # Whether this seed supports service bit filtering
    supports_service_bits: bool = False
    
    # Custom port field (BIP155)
    default_port: int = 8333


# Mainnet DNS seeds
MAINNET_DNS_SEEDS: Final[List[DNSSeedData]] = [
    DNSSeedData("seed.bitcoin.sipa.be", supports_service_bits=True),
    DNSSeedData("dnsseed.bluematt.me"),
    DNSSeedData("dnsseed.bitcoin.dashjr.org"),
    DNSSeedData("seed.bitcoinstats.com", supports_service_bits=True),
    DNSSeedData("seed.bitcoin.jonasschnelli.ch", supports_service_bits=True),
    DNSSeedData("seed.btc.petertodd.org"),
    DNSSeedData("seed.bitcoin.sprovoost.nl"),
    DNSSeedData("dnsseed.emzy.de", supports_service_bits=True),
    DNSSeedData("seed.bitcoin.wiz.biz"),
]

# Testnet3 DNS seeds
TESTNET_DNS_SEEDS: Final[List[DNSSeedData]] = [
    DNSSeedData("testnet-seed.bitcoin.jonasschnelli.ch"),
    DNSSeedData("seed.tbtc.petertodd.org"),
    DNSSeedData("seed.testnet.bitcoin.sprovoost.nl"),
    DNSSeedData("testnet-seed.bluematt.me"),
]

# Testnet4 DNS seeds
TESTNET4_DNS_SEEDS: Final[List[DNSSeedData]] = [
    DNSSeedData("seed.testnet4.bitcoin.sprovoost.nl"),
]

# Signet DNS seeds
SIGNET_DNS_SEEDS: Final[List[DNSSeedData]] = [
    DNSSeedData("seed.signet.bitcoin.sprovoost.nl"),
]


# ==============================================================================
# DNS Seed Query Options
# ==============================================================================

@dataclass
class DNSSeedQueryOptions:
    """Options for DNS seed queries."""
    
    # Maximum number of seeds to query
    max_seeds: int = 3
    
    # Number of addresses to request per seed
    max_addresses_per_seed: int = 256
    
    # Whether to require service bits
    require_service_bits: bool = True
    
    # Service bits to request
    service_bits: ServiceFlags = ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_WITNESS
    
    # Query timeout in seconds
    timeout: float = 30.0
    
    # Use random delay between queries
    random_delay: bool = True


# ==============================================================================
# DNS Seed Result
# ==============================================================================

@dataclass
class DNSSeedResult:
    """Result of a DNS seed query."""
    
    seed_host: str
    addresses: List[CService]
    success: bool
    error: Optional[str] = None
    query_time: float = 0.0
    
    def __post_init__(self):
        if self.query_time == 0.0:
            self.query_time = time.time()


# ==============================================================================
# DNS Seed Querier
# ==============================================================================

class DNSSeedQuerier:
    """
    DNS Seed Querier.
    
    Handles querying DNS seeds for peer addresses.
    """
    
    def __init__(
        self,
        seeds: List[DNSSeedData],
        default_port: int = 8333
    ):
        """
        Initialize DNS seed querier.
        
        Args:
            seeds: List of DNS seed configurations
            default_port: Default port for addresses
        """
        self._seeds = seeds
        self._default_port = default_port
    
    async def query_seed(
        self,
        seed: DNSSeedData,
        options: DNSSeedQueryOptions
    ) -> DNSSeedResult:
        """
        Query a single DNS seed.
        
        Args:
            seed: DNS seed configuration
            options: Query options
            
        Returns:
            DNS seed query result
        """
        addresses = []
        error = None
        
        try:
            # Perform DNS lookup
            loop = asyncio.get_event_loop()
            
            # Use asyncio to query DNS
            try:
                addr_info_list = await asyncio.wait_for(
                    loop.getaddrinfo(seed.host, seed.port),
                    timeout=options.timeout
                )
                
                for family, _, _, _, sockaddr in addr_info_list:
                    if family == socket.AF_INET:
                        # IPv4
                        ip = sockaddr[0]
                        addr = CNetAddr()
                        addr.m_net = Network.NET_IPV4
                        addr.m_addr = socket.inet_pton(socket.AF_INET, ip)
                        
                        service = CService(
                            m_addr=addr.m_addr,
                            m_net=addr.m_net,
                            port=sockaddr[1]
                        )
                        addresses.append(service)
                        
                    elif family == socket.AF_INET6:
                        # IPv6
                        ip = sockaddr[0]
                        addr = CNetAddr()
                        addr.m_net = Network.NET_IPV6
                        addr.m_addr = socket.inet_pton(socket.AF_INET6, ip)
                        
                        service = CService(
                            m_addr=addr.m_addr,
                            m_net=addr.m_net,
                            port=sockaddr[1]
                        )
                        addresses.append(service)
                    
                    if len(addresses) >= options.max_addresses_per_seed:
                        break
                
            except asyncio.TimeoutError:
                error = "DNS query timed out"
            except socket.gaierror as e:
                error = f"DNS resolution failed: {e}"
            
        except Exception as e:
            error = f"Query failed: {e}"
        
        return DNSSeedResult(
            seed_host=seed.host,
            addresses=addresses,
            success=len(addresses) > 0,
            error=error
        )
    
    async def query_all(
        self,
        options: Optional[DNSSeedQueryOptions] = None
    ) -> List[DNSSeedResult]:
        """
        Query all DNS seeds.
        
        Args:
            options: Query options
            
        Returns:
            List of query results
        """
        options = options or DNSSeedQueryOptions()
        
        # Select seeds to query
        import random
        seeds_to_query = list(self._seeds)
        random.shuffle(seeds_to_query)
        seeds_to_query = seeds_to_query[:options.max_seeds]
        
        # Query seeds concurrently
        tasks = [
            self.query_seed(seed, options)
            for seed in seeds_to_query
        ]
        
        results = await asyncio.gather(*tasks)
        return list(results)
    
    def get_addresses(
        self,
        results: List[DNSSeedResult]
    ) -> List[CService]:
        """
        Extract all addresses from results.
        
        Args:
            results: List of DNS seed results
            
        Returns:
            Combined list of addresses
        """
        addresses = []
        for result in results:
            addresses.extend(result.addresses)
        return addresses


# ==============================================================================
# Peer Discovery Manager
# ==============================================================================

class PeerDiscovery:
    """
    Peer Discovery Manager.
    
    Manages various peer discovery mechanisms including DNS seeds,
    hardcoded seeds, and peer address exchange.
    """
    
    def __init__(
        self,
        addr_man: AddrMan,
        dns_seeds: List[DNSSeedData],
        default_port: int = 8333
    ):
        """
        Initialize peer discovery.
        
        Args:
            addr_man: Address manager instance
            dns_seeds: List of DNS seed configurations
            default_port: Default port for addresses
        """
        self._addr_man = addr_man
        self._dns_seeds = dns_seeds
        self._default_port = default_port
        self._dns_querier = DNSSeedQuerier(dns_seeds, default_port)
        
        # Discovery state
        self._last_dns_seed_query = 0.0
        self._dns_seed_query_interval = 24 * 60 * 60  # 24 hours
    
    async def discover_dns_seeds(
        self,
        options: Optional[DNSSeedQueryOptions] = None
    ) -> int:
        """
        Discover peers from DNS seeds.
        
        Args:
            options: Query options
            
        Returns:
            Number of addresses added
        """
        options = options or DNSSeedQueryOptions()
        
        # Query DNS seeds
        results = await self._dns_querier.query_all(options)
        
        # Add addresses to addrman
        count = 0
        current_time = int(datetime.now(timezone.utc).timestamp())
        
        for result in results:
            if not result.success:
                continue
            
            source = CNetAddr()
            source.set_internal(result.seed_host)
            
            for addr in result.addresses:
                # Calculate time penalty
                time_penalty = 2 * 60 * 60  # 2 hours
                addr_time = current_time - int(result.query_time) + time_penalty
                
                if self._addr_man.add(addr, source, time_penalty):
                    count += 1
        
        self._last_dns_seed_query = time.time()
        return count
    
    def should_query_dns_seeds(
        self,
        min_outbound_connections: int = 2
    ) -> bool:
        """
        Check if we should query DNS seeds.
        
        Args:
            min_outbound_connections: Minimum outbound connections threshold
            
        Returns:
            True if we should query DNS seeds
        """
        # Check if enough time has passed
        elapsed = time.time() - self._last_dns_seed_query
        if elapsed < self._dns_seed_query_interval:
            return False
        
        # Check if we have enough addresses
        if self._addr_man.size() < min_outbound_connections * 100:
            return True
        
        return False
    
    def get_doubled_dns_seeds(self) -> List[str]:
        """
        Get DNS seeds in wire format for sending to peers.
        
        Returns:
            List of DNS seed hostnames
        """
        return [seed.host for seed in self._dns_seeds]
    
    # ==========================================================================
    # Hardcoded Seed Support
    # ==========================================================================
    
    def load_hardcoded_seeds(self, seed_data: bytes) -> int:
        """
        Load hardcoded seed addresses.
        
        Args:
            seed_data: Serialized seed data
            
        Returns:
            Number of addresses added
        """
        # Parse seed data
        # Format would be from chainparamsseeds.h
        count = 0
        pos = 0
        
        while pos + 16 <= len(seed_data):
            # Read address (16 bytes for IPv6/IPv4-mapped)
            addr_bytes = seed_data[pos:pos + 16]
            pos += 16
            
            # Read port (2 bytes)
            port = struct.unpack('>H', seed_data[pos:pos + 2])[0]
            pos += 2
            
            # Create address
            if addr_bytes[:12] == bytes([0] * 10 + [0xFF, 0xFF]):
                # IPv4-mapped
                addr = CService(
                    m_addr=addr_bytes[12:16],
                    m_net=Network.NET_IPV4,
                    port=port
                )
            else:
                # IPv6
                addr = CService(
                    m_addr=addr_bytes,
                    m_net=Network.NET_IPV6,
                    port=port
                )
            
            # Create source as internal
            source = CNetAddr()
            source.set_internal("hardcoded")
            
            # Add with random time penalty
            import random
            time_penalty = random.randint(0, 7 * 24 * 60 * 60)  # 0-7 days
            
            if self._addr_man.add(addr, source, time_penalty):
                count += 1
        
        return count
    
    # ==========================================================================
    # Address Exchange
    # ==========================================================================
    
    def process_received_addresses(
        self,
        addresses: List[CService],
        source: CNetAddr
    ) -> int:
        """
        Process addresses received from a peer.
        
        Args:
            addresses: List of received addresses
            source: Source peer that sent addresses
            
        Returns:
            Number of addresses added
        """
        count = 0
        current_time = int(datetime.now(timezone.utc).timestamp())
        
        for addr in addresses:
            # Add with time penalty based on advertised time
            time_penalty = 0  # Would use actual time from addr message
            
            if self._addr_man.add(addr, source, time_penalty):
                count += 1
        
        return count
    
    def get_addresses_to_send(
        self,
        max_addresses: int = 1000,
        preferred_network: Optional[Network] = None
    ) -> List[CService]:
        """
        Get addresses to send to a peer.
        
        Args:
            max_addresses: Maximum number of addresses
            preferred_network: Preferred network type
            
        Returns:
            List of addresses to send
        """
        addr_infos = self._addr_man.select_random(max_addresses, preferred_network)
        return [info.address for info in addr_infos]


# ==============================================================================
# Factory Functions
# ==============================================================================

def create_dns_seed_querier(chain: str) -> DNSSeedQuerier:
    """
    Create a DNS seed querier for a specific chain.
    
    Args:
        chain: Chain name ('main', 'test', 'testnet4', 'signet')
        
    Returns:
        DNS seed querier instance
    """
    if chain == 'main':
        return DNSSeedQuerier(MAINNET_DNS_SEEDS, 8333)
    elif chain == 'test' or chain == 'testnet3':
        return DNSSeedQuerier(TESTNET_DNS_SEEDS, 18333)
    elif chain == 'testnet4':
        return DNSSeedQuerier(TESTNET4_DNS_SEEDS, 48333)
    elif chain == 'signet':
        return DNSSeedQuerier(SIGNET_DNS_SEEDS, 38333)
    else:
        # Return empty querier for regtest
        return DNSSeedQuerier([], 18444)


def create_peer_discovery(
    addr_man: AddrMan,
    chain: str
) -> PeerDiscovery:
    """
    Create a peer discovery manager for a specific chain.
    
    Args:
        addr_man: Address manager instance
        chain: Chain name
        
    Returns:
        Peer discovery instance
    """
    if chain == 'main':
        return PeerDiscovery(addr_man, MAINNET_DNS_SEEDS, 8333)
    elif chain == 'test' or chain == 'testnet3':
        return PeerDiscovery(addr_man, TESTNET_DNS_SEEDS, 18333)
    elif chain == 'testnet4':
        return PeerDiscovery(addr_man, TESTNET4_DNS_SEEDS, 48333)
    elif chain == 'signet':
        return PeerDiscovery(addr_man, SIGNET_DNS_SEEDS, 38333)
    else:
        # Regtest has no seeds
        return PeerDiscovery(addr_man, [], 18444)
