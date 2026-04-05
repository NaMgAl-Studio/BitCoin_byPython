"""
Bitcoin P2P Connection Manager.

This module implements the connection management for the Bitcoin P2P network,
including peer connections, message handling, and network state.

Reference: Bitcoin Core src/net.h, src/net.cpp (CNode, CConnman)
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Final, Optional, Callable, Dict, List, Set, Any
from datetime import datetime, timezone

from .netaddress import CNetAddr, CService, CSubNet, Network
from .netbase import (
    ConnectionDirection, Proxy, ProxyCredentials,
    connect_directly, connect_through_proxy, is_bad_port,
    g_reachable_nets, get_name_proxy, get_proxy
)
from .protocol import (
    NodeId, ConnectionType, TransportProtocolType,
    ServiceFlags, PROTOCOL_VERSION, INIT_PROTO_VERSION,
    DEFAULT_MAX_PEER_CONNECTIONS, DEFAULT_LISTEN,
    DEFAULT_PEER_CONNECT_TIMEOUT, TIMEOUT_INTERVAL_SECONDS
)
from .transport import Transport, V1Transport, V2Transport, CSerializedNetMsg, CNetMessage
from .messages import (
    P2PMessage, VersionMessage, VerackMessage, PingMessage, PongMessage,
    AddrMessage, AddrV2Message, GetAddrMessage, InvMessage, GetDataMessage,
    FeeFilterMessage, SendHeadersMessage, WTXIDRelayMessage, SendAddrV2Message,
    deserialize_message
)


# ==============================================================================
# Connection Rate Limiter
# ==============================================================================

class ConnectionRateLimiter:
    """
    Rate limiter for incoming connections.
    
    Prevents abuse by limiting the rate of new connections from the same
    IP address or overall connection rate.
    """
    
    def __init__(
        self,
        max_connections_per_second: float = 0.1,
        max_connections_per_ip: int = 3,
        window_seconds: int = 60
    ):
        self._max_per_second = max_connections_per_second
        self._max_per_ip = max_connections_per_ip
        self._window = window_seconds
        
        # Track connection timestamps
        self._connection_times: List[float] = []
        self._ip_connections: Dict[str, List[float]] = {}
        self._lock = None  # Would use asyncio.Lock
    
    def allow_connection(self, ip_address: str) -> bool:
        """
        Check if a connection from the given IP should be allowed.
        
        Args:
            ip_address: The IP address of the incoming connection
            
        Returns:
            True if the connection should be allowed
        """
        import time
        now = time.time()
        
        # Clean old entries
        self._cleanup(now)
        
        # Check overall rate limit
        recent_count = len(self._connection_times)
        max_allowed = int(self._max_per_second * self._window)
        if recent_count >= max_allowed:
            return False
        
        # Check per-IP rate limit
        ip_connections = self._ip_connections.get(ip_address, [])
        if len(ip_connections) >= self._max_per_ip:
            return False
        
        # Record this connection
        self._connection_times.append(now)
        if ip_address not in self._ip_connections:
            self._ip_connections[ip_address] = []
        self._ip_connections[ip_address].append(now)
        
        return True
    
    def _cleanup(self, now: float) -> None:
        """Remove entries older than the window."""
        cutoff = now - self._window
        
        self._connection_times = [
            t for t in self._connection_times if t > cutoff
        ]
        
        expired_ips = []
        for ip, times in self._ip_connections.items():
            cleaned = [t for t in times if t > cutoff]
            if cleaned:
                self._ip_connections[ip] = cleaned
            else:
                expired_ips.append(ip)
        
        for ip in expired_ips:
            del self._ip_connections[ip]
    
    def get_stats(self) -> dict:
        """Get rate limiter statistics."""
        import time
        self._cleanup(time.time())
        return {
            "recent_connections": len(self._connection_times),
            "tracked_ips": len(self._ip_connections),
            "max_per_ip": self._max_per_ip,
        }


# ==============================================================================
# Constants
# ==============================================================================

LOCAL_NONE: Final[int] = 0
LOCAL_IF: Final[int] = 1
LOCAL_BIND: Final[int] = 2
LOCAL_MAPPED: Final[int] = 3
LOCAL_MANUAL: Final[int] = 4
LOCAL_MAX: Final[int] = 5

SELECT_TIMEOUT_MILLISECONDS: Final[int] = 50

MAX_SUBVERSION_LENGTH: Final[int] = 256
MAX_ADDR_TO_SEND: Final[int] = 1000
MAX_ADDR_PROCESSING_INTERVAL: Final[int] = 100  # seconds

# Randomizer IDs
RANDOMIZER_ID_NETGROUP: Final[int] = 0x6c0edd8036ef4036
RANDOMIZER_ID_LOCALHOSTNONCE: Final[int] = 0xd93e69e2bbfa5735
RANDOMIZER_ID_NETWORKKEY: Final[int] = 0x0e8a2b136c592a7d


# ==============================================================================
# Global State
# ==============================================================================

# Local service info
@dataclass
class LocalServiceInfo:
    n_score: int = 0
    n_port: int = 0


# Global state
f_discover: bool = True
f_listen: bool = True
map_local_host: Dict[CService, LocalServiceInfo] = {}
str_sub_version: str = "/python-bitcoin:0.1.0/"


# ==============================================================================
# CNodeStats
# ==============================================================================

@dataclass
class CNodeStats:
    """Statistics for a peer connection."""
    
    nodeid: NodeId = 0
    addr: CService = field(default_factory=CService)
    addr_bind: CService = field(default_factory=CService)
    m_network: Network = Network.NET_IPV4
    
    m_last_send: int = 0
    m_last_recv: int = 0
    m_last_tx_time: int = 0
    m_last_block_time: int = 0
    m_connected: int = 0
    
    m_addr_name: str = ""
    n_version: int = 0
    clean_sub_ver: str = ""
    f_inbound: bool = False
    
    m_bip152_highbandwidth_to: bool = False
    m_bip152_highbandwidth_from: bool = False
    
    n_send_bytes: int = 0
    map_send_bytes_per_msg_type: Dict[str, int] = field(default_factory=dict)
    n_recv_bytes: int = 0
    map_recv_bytes_per_msg_type: Dict[str, int] = field(default_factory=dict)
    
    m_permission_flags: int = 0
    m_last_ping_time: int = 0
    m_min_ping_time: int = 0
    
    addr_local: str = ""
    m_conn_type: ConnectionType = ConnectionType.INBOUND
    m_transport_type: TransportProtocolType = TransportProtocolType.V1
    m_session_id: str = ""


# ==============================================================================
# Net Permission Flags
# ==============================================================================

class NetPermissionFlags(Enum):
    """Network permission flags."""
    
    NONE = 0
    BLOOMFILTER = 1
    RELAY = 2
    FORCE_RELAY = 4
    NOBAN = 8
    MEMPOOL = 16
    ADDR = 32
    DOWNLOAD = 64
    IMPLICIT = 128
    ALL = BLOOMFILTER | RELAY | FORCE_RELAY | NOBAN | MEMPOOL | ADDR | DOWNLOAD


# ==============================================================================
# CNode Options
# ==============================================================================

@dataclass
class CNodeOptions:
    """Options for creating a node connection."""
    
    permission_flags: NetPermissionFlags = NetPermissionFlags.NONE
    prefer_evict: bool = False
    recv_flood_size: int = 5 * 1000 * 1000
    use_v2transport: bool = True


# ==============================================================================
# CNode - Peer Connection
# ==============================================================================

class CNode:
    """
    Information about a peer.
    
    This class represents a single peer connection.
    """
    
    def __init__(
        self,
        node_id: NodeId,
        addr: CService,
        addr_bind: CService,
        addr_name: str,
        conn_type: ConnectionType,
        inbound_onion: bool,
        network_key: int,
        options: CNodeOptions = None
    ):
        """
        Initialize a peer connection.
        
        Args:
            node_id: Unique node identifier
            addr: Peer address
            addr_bind: Local bind address
            addr_name: Address name string
            conn_type: Type of connection
            inbound_onion: Whether inbound onion connection
            network_key: Network key for fingerprinting prevention
            options: Connection options
        """
        options = options or CNodeOptions()
        
        # Identity
        self._id = node_id
        self._addr = addr
        self._addr_bind = addr_bind
        self._addr_name = addr_name
        self._conn_type = conn_type
        self._inbound_onion = inbound_onion
        self._network_key = network_key
        
        # Permissions
        self._permission_flags = options.permission_flags
        
        # Transport
        self._transport: Optional[Transport] = None
        
        # Connection state
        self._connected = int(datetime.now(timezone.utc).timestamp())
        self._successfully_connected = False
        self._disconnect = False
        self._ref_count = 0
        
        # Version state
        self._version = 0
        self._greatest_common_version = INIT_PROTO_VERSION
        self._sub_ver = ""
        self._nonce = self._generate_nonce()
        
        # Keyed net group
        self._keyed_net_group = self._calculate_keyed_net_group()
        
        # Pause states
        self._pause_recv = False
        self._pause_send = False
        
        # Services
        self._services = ServiceFlags.NODE_NONE
        self._has_all_wanted_services = False
        self._relays_txs = False
        self._bloom_filter_loaded = False
        self._wtxid_relay = False
        
        # Time tracking
        self._last_send = 0
        self._last_recv = 0
        self._last_tx_time = 0
        self._last_block_time = 0
        self._last_ping_time = 0
        self._min_ping_time = 2 ** 63 - 1  # Max int
        
        # BIP152 compact blocks
        self._bip152_highbandwidth_to = False
        self._bip152_highbandwidth_from = False
        
        # Local address
        self._addr_local: Optional[CService] = None
        
        # Message queues
        self._send_queue: List[CSerializedNetMsg] = []
        self._recv_queue: List[CNetMessage] = []
        
        # Statistics
        self._send_bytes = 0
        self._recv_bytes = 0
        self._send_bytes_per_msg_type: Dict[str, int] = {}
        self._recv_bytes_per_msg_type: Dict[str, int] = {}
        
        # Flood protection
        self._recv_flood_size = options.recv_flood_size
        
        # V2 transport preference
        self._use_v2transport = options.use_v2transport
    
    def _generate_nonce(self) -> int:
        """Generate a random nonce for this connection."""
        # Combine node ID with random data
        random_bytes = os.urandom(8)
        return int.from_bytes(random_bytes, 'little') ^ self._id
    
    def _calculate_keyed_net_group(self) -> int:
        """Calculate the keyed net group for this peer."""
        # Simplified hash of address
        addr_bytes = self._addr.get_addr_bytes()
        return int.from_bytes(addr_bytes[:8], 'little')
    
    # ==========================================================================
    # Properties
    # ==========================================================================
    
    @property
    def id(self) -> NodeId:
        return self._id
    
    @property
    def addr(self) -> CService:
        return self._addr
    
    @property
    def addr_bind(self) -> CService:
        return self._addr_bind
    
    @property
    def addr_name(self) -> str:
        return self._addr_name
    
    @property
    def conn_type(self) -> ConnectionType:
        return self._conn_type
    
    @property
    def nonce(self) -> int:
        return self._nonce
    
    @property
    def version(self) -> int:
        return self._version
    
    @property
    def services(self) -> ServiceFlags:
        return self._services
    
    @property
    def successfully_connected(self) -> bool:
        return self._successfully_connected
    
    @property
    def disconnect(self) -> bool:
        return self._disconnect
    
    # ==========================================================================
    # Connection Type Helpers
    # ==========================================================================
    
    def is_outbound_or_block_relay_conn(self) -> bool:
        """Check if this is an outbound or block-relay connection."""
        return self._conn_type in (
            ConnectionType.OUTBOUND_FULL_RELAY,
            ConnectionType.BLOCK_RELAY
        )
    
    def is_full_outbound_conn(self) -> bool:
        """Check if this is a full outbound relay connection."""
        return self._conn_type == ConnectionType.OUTBOUND_FULL_RELAY
    
    def is_manual_conn(self) -> bool:
        """Check if this is a manual connection."""
        return self._conn_type == ConnectionType.MANUAL
    
    def is_block_only_conn(self) -> bool:
        """Check if this is a block-relay-only connection."""
        return self._conn_type == ConnectionType.BLOCK_RELAY
    
    def is_feeler_conn(self) -> bool:
        """Check if this is a feeler connection."""
        return self._conn_type == ConnectionType.FEELER
    
    def is_addr_fetch_conn(self) -> bool:
        """Check if this is an addr-fetch connection."""
        return self._conn_type == ConnectionType.ADDR_FETCH
    
    def is_inbound_conn(self) -> bool:
        """Check if this is an inbound connection."""
        return self._conn_type == ConnectionType.INBOUND
    
    def expect_services_from_conn(self) -> bool:
        """Check if we expect services from this connection."""
        return self._conn_type in (
            ConnectionType.OUTBOUND_FULL_RELAY,
            ConnectionType.BLOCK_RELAY,
            ConnectionType.ADDR_FETCH
        )
    
    def connected_through_network(self) -> Network:
        """Get the network this peer connected through."""
        if self._inbound_onion:
            return Network.NET_ONION
        return self._addr.get_net_class()
    
    def is_connected_through_privacy_net(self) -> bool:
        """Check if connected through a privacy network."""
        return self._inbound_onion or self._addr.is_privacy_net()
    
    # ==========================================================================
    # Permission Checks
    # ==========================================================================
    
    def has_permission(self, permission: NetPermissionFlags) -> bool:
        """Check if this peer has a specific permission."""
        return (self._permission_flags.value & permission.value) != 0
    
    # ==========================================================================
    # Address Management
    # ==========================================================================
    
    def get_addr_local(self) -> CService:
        """Get the local address as seen by this peer."""
        if self._addr_local is None:
            return CService()
        return self._addr_local
    
    def set_addr_local(self, addr: CService) -> None:
        """Set the local address as reported by this peer."""
        if self._addr_local is None:
            self._addr_local = addr
    
    # ==========================================================================
    # Reference Counting
    # ==========================================================================
    
    def add_ref(self) -> CNode:
        """Add a reference to this node."""
        self._ref_count += 1
        return self
    
    def release(self) -> None:
        """Release a reference to this node."""
        self._ref_count -= 1
    
    def get_ref_count(self) -> int:
        """Get the current reference count."""
        return self._ref_count
    
    # ==========================================================================
    # Version Management
    # ==========================================================================
    
    def set_common_version(self, version: int) -> None:
        """Set the greatest common version."""
        self._greatest_common_version = version
    
    def get_common_version(self) -> int:
        """Get the greatest common version."""
        return self._greatest_common_version
    
    # ==========================================================================
    # Statistics
    # ==========================================================================
    
    def copy_stats(self, stats: CNodeStats) -> None:
        """Copy connection statistics to a stats object."""
        stats.nodeid = self._id
        stats.addr = self._addr
        stats.addr_bind = self._addr_bind
        stats.m_network = self.connected_through_network()
        stats.m_last_send = self._last_send
        stats.m_last_recv = self._last_recv
        stats.m_last_tx_time = self._last_tx_time
        stats.m_last_block_time = self._last_block_time
        stats.m_connected = self._connected
        stats.m_addr_name = self._addr_name
        stats.n_version = self._version
        stats.clean_sub_ver = self._sub_ver
        stats.f_inbound = self.is_inbound_conn()
        stats.m_bip152_highbandwidth_to = self._bip152_highbandwidth_to
        stats.m_bip152_highbandwidth_from = self._bip152_highbandwidth_from
        stats.n_send_bytes = self._send_bytes
        stats.map_send_bytes_per_msg_type = dict(self._send_bytes_per_msg_type)
        stats.n_recv_bytes = self._recv_bytes
        stats.map_recv_bytes_per_msg_type = dict(self._recv_bytes_per_msg_type)
        stats.m_permission_flags = self._permission_flags.value
        stats.m_last_ping_time = self._last_ping_time
        stats.m_min_ping_time = self._min_ping_time
        stats.addr_local = str(self._addr_local) if self._addr_local else ""
        stats.m_conn_type = self._conn_type
    
    # ==========================================================================
    # Message Handling
    # ==========================================================================
    
    def receive_msg_bytes(self, msg_bytes: bytes) -> bool:
        """
        Receive and process message bytes.
        
        Args:
            msg_bytes: Raw bytes from the network
            
        Returns:
            True if successful, False if peer should be disconnected
        """
        current_time = int(datetime.now(timezone.utc).timestamp())
        self._last_recv = current_time
        self._recv_bytes += len(msg_bytes)
        
        if self._transport is None:
            return False
        
        # Feed bytes to transport
        success, _ = self._transport.received_bytes(msg_bytes)
        
        if not success:
            return False
        
        # Check for completed messages
        while self._transport.received_message_complete():
            msg, reject = self._transport.get_received_message(current_time)
            
            if reject:
                # Invalid message, but don't disconnect
                continue
            
            self._recv_queue.append(msg)
        
        return True
    
    def poll_message(self) -> Optional[CNetMessage]:
        """Poll the next message from the receive queue."""
        if not self._recv_queue:
            return None
        return self._recv_queue.pop(0)
    
    def send_message(self, msg: P2PMessage) -> bool:
        """
        Queue a message for sending.
        
        Args:
            msg: Message to send
            
        Returns:
            True if message was queued
        """
        serialized = CSerializedNetMsg(
            data=msg.serialize(),
            m_type=msg.command
        )
        self._send_queue.append(serialized)
        return True
    
    # ==========================================================================
    # Logging
    # ==========================================================================
    
    def log_peer(self) -> str:
        """Get log string for this peer."""
        return f"peer={self._id}"
    
    def disconnect_msg(self) -> str:
        """Get disconnect log message."""
        return f"disconnecting {self.log_peer()}"


# ==============================================================================
# CConnman - Connection Manager
# ==============================================================================

class CConnman:
    """
    Connection Manager.
    
    This class manages all peer connections, both inbound and outbound.
    """
    
    def __init__(
        self,
        network_magic: bytes,
        default_port: int,
        max_connections: int = DEFAULT_MAX_PEER_CONNECTIONS
    ):
        """
        Initialize connection manager.
        
        Args:
            network_magic: Network magic bytes
            default_port: Default P2P port
            max_connections: Maximum number of connections
        """
        self._network_magic = network_magic
        self._default_port = default_port
        self._max_connections = max_connections
        
        # Node management
        self._nodes: Dict[NodeId, CNode] = {}
        self._node_id_counter = 0
        self._nodes_mutex = asyncio.Lock()
        
        # Address management
        self._addr_fetches: List[str] = []
        self._addr_fetches_mutex = asyncio.Lock()
        
        # Local addresses
        self._local_services: Dict[CNetAddr, LocalServiceInfo] = {}
        self._local_services_mutex = asyncio.Lock()
        
        # Ban management
        self._ban_map: Dict[CSubNet, int] = {}  # subnet -> ban_time
        
        # Network state
        self._network_active = True
        self._interrupt = False
        
        # Event handlers
        self._on_version: Optional[Callable] = None
        self._on_verack: Optional[Callable] = None
        self._on_addr: Optional[Callable] = None
        self._on_inv: Optional[Callable] = None
        self._on_block: Optional[Callable] = None
        self._on_tx: Optional[Callable] = None
    
    # ==========================================================================
    # Node ID Management
    # ==========================================================================
    
    def get_new_node_id(self) -> NodeId:
        """Get a new unique node ID."""
        self._node_id_counter += 1
        return self._node_id_counter
    
    # ==========================================================================
    # Address Management
    # ==========================================================================
    
    def add_addr_fetch(self, dest: str) -> None:
        """Add an address to fetch from."""
        async def _add():
            async with self._addr_fetches_mutex:
                self._addr_fetches.append(dest)
        
        # If we're in an async context, this will work
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(_add())
            else:
                self._addr_fetches.append(dest)
        except RuntimeError:
            self._addr_fetches.append(dest)
    
    # ==========================================================================
    # Connection Management
    # ==========================================================================
    
    async def connect_node(
        self,
        addr_connect: CService,
        dest: Optional[str] = None,
        count_failure: bool = True,
        conn_type: ConnectionType = ConnectionType.OUTBOUND_FULL_RELAY,
        use_v2transport: bool = True,
        proxy_override: Optional[Proxy] = None
    ) -> Optional[CNode]:
        """
        Connect to a peer.
        
        Args:
            addr_connect: Address to connect to
            dest: Optional destination string
            count_failure: Whether to count as connection attempt
            conn_type: Type of connection
            use_v2transport: Whether to use V2 transport
            proxy_override: Optional proxy to use
            
        Returns:
            Connected CNode or None on failure
        """
        if dest is None:
            # Check if already connected
            if await self.already_connected_to_address_port(addr_connect):
                return None
        
        # Check if local address
        if is_local(addr_connect):
            return None
        
        # Determine proxy
        proxy = None
        if proxy_override:
            proxy = proxy_override
        else:
            proxy = get_proxy(addr_connect.get_network())
        
        # Connect
        reader = None
        proxy_connection_failed = False
        
        if addr_connect.is_i2p() and proxy:
            # I2P connection
            # Simplified - would need I2P SAM session
            pass
        elif proxy:
            # Proxy connection
            reader = await connect_through_proxy(
                proxy,
                addr_connect.to_string_addr(),
                addr_connect.get_port()
            )
        else:
            # Direct connection
            reader = await connect_directly(addr_connect)
        
        if reader is None:
            return None
        
        # Create node
        node_id = self.get_new_node_id()
        nonce = self._generate_nonce(node_id)
        network_key = self._generate_network_key(addr_connect)
        
        node = CNode(
            node_id=node_id,
            addr=addr_connect,
            addr_bind=CService(),  # Would need to get from socket
            addr_name=dest or "",
            conn_type=conn_type,
            inbound_onion=False,
            network_key=network_key,
            options=CNodeOptions(use_v2transport=use_v2transport)
        )
        
        # Initialize transport
        if use_v2transport:
            node._transport = V2Transport(
                self._network_magic,
                node_id,
                initiating=True
            )
        else:
            node._transport = V1Transport(
                self._network_magic,
                node_id
            )
        
        # Add to nodes
        async with self._nodes_mutex:
            self._nodes[node_id] = node
        
        return node
    
    async def already_connected_to_address_port(self, addr: CService) -> bool:
        """Check if already connected to an address."""
        async with self._nodes_mutex:
            for node in self._nodes.values():
                if node.addr == addr:
                    return True
        return False
    
    async def already_connected_to_host(self, host: str) -> bool:
        """Check if already connected to a host."""
        async with self._nodes_mutex:
            for node in self._nodes.values():
                if node.addr_name == host:
                    return True
        return False
    
    def _generate_nonce(self, node_id: NodeId) -> int:
        """Generate a deterministic nonce from node ID."""
        random_bytes = os.urandom(8)
        return int.from_bytes(random_bytes, 'little') ^ node_id
    
    def _generate_network_key(self, addr: CService) -> int:
        """Generate a network key for this connection."""
        # Simplified hash
        addr_bytes = addr.get_addr_bytes()
        return int.from_bytes(addr_bytes[:8], 'little')
    
    # ==========================================================================
    # Local Address Management
    # ==========================================================================
    
    def add_local(self, addr: CService, score: int = LOCAL_NONE) -> bool:
        """Add a local address."""
        if not addr.is_routable():
            return False
        
        if not f_discover and score < LOCAL_MANUAL:
            return False
        
        if not g_reachable_nets.contains_addr(addr):
            return False
        
        # Add to local services
        # Simplified - in production would need proper locking
        return True
    
    # ==========================================================================
    # Ban Management
    # ==========================================================================
    
    def is_banned(self, addr: CNetAddr) -> bool:
        """Check if an address is banned."""
        subnet = CSubNet(addr)
        return self.is_banned_subnet(subnet)
    
    def is_banned_subnet(self, subnet: CSubNet) -> bool:
        """Check if a subnet is banned."""
        if subnet in self._ban_map:
            ban_time = self._ban_map[subnet]
            return ban_time > time.time()
        return False
    
    def ban(self, addr: CNetAddr, ban_time: int) -> None:
        """Ban an address until a specific time."""
        subnet = CSubNet(addr)
        self._ban_map[subnet] = ban_time
    
    def unban(self, addr: CNetAddr) -> None:
        """Remove a ban on an address."""
        subnet = CSubNet(addr)
        if subnet in self._ban_map:
            del self._ban_map[subnet]
    
    # ==========================================================================
    # Connection Statistics
    # ==========================================================================
    
    def get_connection_count(self) -> int:
        """Get the number of connections."""
        return len(self._nodes)
    
    def get_outbound_connection_count(self) -> int:
        """Get the number of outbound connections."""
        count = 0
        for node in self._nodes.values():
            if node.is_outbound_or_block_relay_conn():
                count += 1
        return count
    
    def get_node_stats(self) -> List[CNodeStats]:
        """Get statistics for all nodes."""
        stats = []
        for node in self._nodes.values():
            node_stats = CNodeStats()
            node.copy_stats(node_stats)
            stats.append(node_stats)
        return stats
    
    # ==========================================================================
    # Event Handlers
    # ==========================================================================
    
    def set_on_version(self, handler: Callable) -> None:
        """Set version message handler."""
        self._on_version = handler
    
    def set_on_verack(self, handler: Callable) -> None:
        """Set verack message handler."""
        self._on_verack = handler
    
    def set_on_addr(self, handler: Callable) -> None:
        """Set addr message handler."""
        self._on_addr = handler
    
    def set_on_inv(self, handler: Callable) -> None:
        """Set inv message handler."""
        self._on_inv = handler
    
    def set_on_block(self, handler: Callable) -> None:
        """Set block message handler."""
        self._on_block = handler
    
    def set_on_tx(self, handler: Callable) -> None:
        """Set tx message handler."""
        self._on_tx = handler
    
    # ==========================================================================
    # Network Control
    # ==========================================================================
    
    def interrupt(self) -> None:
        """Interrupt all network operations."""
        self._interrupt = True
    
    def stop(self) -> None:
        """Stop all network operations."""
        self._network_active = False
        self._interrupt = True


# ==============================================================================
# Helper Functions
# ==============================================================================

def is_local(addr: CService) -> bool:
    """Check if an address is a local address."""
    # Simplified check
    if addr.is_local():
        return True
    
    # Check if in local services map
    return addr in map_local_host


def add_local(addr: CService, score: int = LOCAL_NONE) -> bool:
    """Add a local address."""
    if not addr.is_routable():
        return False
    
    if not f_discover and score < LOCAL_MANUAL:
        return False
    
    if not g_reachable_nets.contains_addr(addr):
        return False
    
    if addr in map_local_host:
        info = map_local_host[addr]
        if score >= info.n_score:
            info.n_score = score + 1
    else:
        map_local_host[addr] = LocalServiceInfo(n_score=score, n_port=addr.get_port())
    
    return True


def remove_local(addr: CService) -> None:
    """Remove a local address."""
    if addr in map_local_host:
        del map_local_host[addr]


def seen_local(addr: CService) -> bool:
    """Vote for a local address (increase score)."""
    if addr in map_local_host:
        map_local_host[addr].n_score += 1
        return True
    return False


def clear_local() -> None:
    """Clear all local addresses."""
    map_local_host.clear()


def get_local_address(peer: CNode) -> CService:
    """Get the best local address for a peer."""
    # Simplified - would need proper implementation
    return CService()


def get_listen_port() -> int:
    """Get the port to listen on."""
    return 8333  # Default mainnet port


def calculate_keyed_net_group(addr: CService) -> int:
    """Calculate the keyed net group for an address."""
    addr_bytes = addr.get_addr_bytes()
    return int.from_bytes(addr_bytes[:8], 'little')
