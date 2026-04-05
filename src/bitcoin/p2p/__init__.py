"""
Bitcoin P2P Network Implementation.

This module provides a complete implementation of the Bitcoin P2P protocol,
including network addressing, transport protocols, message handling,
peer connections, and transaction/block relay.

Key Components:
- netaddress: Network address types (IPv4, IPv6, Tor, I2P, CJDNS)
- netbase: Network utilities (DNS, proxy, socket operations)
- protocol: Protocol constants and message types
- transport: V1 and V2 (BIP324) transport layers
- messages: P2P message serialization
- connman: Connection manager
- addrman: Address manager
- dnsseed: DNS seed queries
- blockdownload: Block download mechanism
- txbroadcast: Transaction broadcast

Reference: Bitcoin Core src/net.h, src/net.cpp
"""

from .netaddress import (
    Network,
    CNetAddr,
    CService,
    CSubNet,
    BIP155Network,
    ADDR_IPV4_SIZE,
    ADDR_IPV6_SIZE,
    ADDR_TORV3_SIZE,
    ADDR_I2P_SIZE,
    ADDR_CJDNS_SIZE,
    maybe_flip_ipv6_to_cjdns,
)

from .netbase import (
    ConnectionDirection,
    Proxy,
    ProxyCredentials,
    ReachableNets,
    g_reachable_nets,
    lookup_host,
    lookup_host_single,
    lookup,
    lookup_single,
    lookup_numeric,
    lookup_sub_net,
    is_bad_port,
    set_proxy,
    get_proxy,
    set_name_proxy,
    get_name_proxy,
)

from .protocol import (
    # Protocol versions
    PROTOCOL_VERSION,
    INIT_PROTO_VERSION,
    MIN_PEER_PROTO_VERSION,
    WTXID_RELAY_VERSION,
    
    # Service flags
    ServiceFlags,
    service_flags_to_str,
    seeds_service_flags,
    
    # Message types
    NetMsgType,
    ALL_NET_MESSAGE_TYPES,
    
    # Inventory
    CInv,
    GetDataMsg,
    MSG_WITNESS_FLAG,
    MSG_TYPE_MASK,
    
    # Connection types
    ConnectionType,
    TransportProtocolType,
    
    # Message header
    MessageHeader,
    HEADER_SIZE,
    
    # Network constants
    MAX_PROTOCOL_MESSAGE_LENGTH,
    MAX_OUTBOUND_FULL_RELAY_CONNECTIONS,
    MAX_ADDNODE_CONNECTIONS,
    DEFAULT_MAX_PEER_CONNECTIONS,
    
    # Node ID type
    NodeId,
)

from .transport import (
    Transport,
    V1Transport,
    V2Transport,
    CSerializedNetMsg,
    CNetMessage,
    TransportProtocolType as TransportType,
    get_v2_short_id,
    get_v2_message_type,
)

from .messages import (
    # Base message
    P2PMessage,
    
    # Version handshake
    VersionMessage,
    VerackMessage,
    
    # Address messages
    AddrMessage,
    AddrV2Message,
    
    # Inventory messages
    InvMessage,
    GetDataMessage,
    NotFoundMessage,
    
    # Block messages
    GetBlocksMessage,
    GetHeadersMessage,
    HeadersMessage,
    BlockMessage,
    
    # Transaction messages
    TxMessage,
    
    # Keepalive
    PingMessage,
    PongMessage,
    
    # Fee and relay
    FeeFilterMessage,
    SendHeadersMessage,
    WTXIDRelayMessage,
    SendAddrV2Message,
    
    # Other
    MempoolMessage,
    GetAddrMessage,
    
    # Serialization helpers
    encode_compact_size,
    decode_compact_size,
    encode_varint,
    decode_varint,
    
    # Registry
    MESSAGE_REGISTRY,
    deserialize_message,
)

from .connman import (
    CNode,
    CConnMan,
    CNodeStats,
    CNodeOptions,
    NetPermissionFlags,
    LOCAL_NONE,
    LOCAL_IF,
    LOCAL_BIND,
    LOCAL_MANUAL,
    add_local,
    remove_local,
    is_local,
    calculate_keyed_net_group,
)

from .addrman import (
    AddrMan,
    AddrInfo,
)

from .dnsseed import (
    DNSSeedData,
    DNSSeedQuerier,
    DNSSeedQueryOptions,
    DNSSeedResult,
    PeerDiscovery,
    MAINNET_DNS_SEEDS,
    TESTNET_DNS_SEEDS,
    TESTNET4_DNS_SEEDS,
    SIGNET_DNS_SEEDS,
    create_dns_seed_querier,
    create_peer_discovery,
)

from .blockdownload import (
    BlockDownloadManager,
    BlockDownloadState,
    HeadersSyncState,
    OrphanBlockPool,
)

from .txbroadcast import (
    TxBroadcastManager,
    OrphanTxPool,
    TxSubmitResult,
)


__all__ = [
    # Network addressing
    'Network',
    'CNetAddr',
    'CService',
    'CSubNet',
    'BIP155Network',
    'ADDR_IPV4_SIZE',
    'ADDR_IPV6_SIZE',
    'ADDR_TORV3_SIZE',
    'ADDR_I2P_SIZE',
    'ADDR_CJDNS_SIZE',
    'maybe_flip_ipv6_to_cjdns',
    
    # Network base
    'ConnectionDirection',
    'Proxy',
    'ProxyCredentials',
    'ReachableNets',
    'g_reachable_nets',
    'lookup_host',
    'lookup_host_single',
    'lookup',
    'lookup_single',
    'lookup_numeric',
    'lookup_sub_net',
    'is_bad_port',
    'set_proxy',
    'get_proxy',
    'set_name_proxy',
    'get_name_proxy',
    
    # Protocol
    'PROTOCOL_VERSION',
    'INIT_PROTO_VERSION',
    'MIN_PEER_PROTO_VERSION',
    'WTXID_RELAY_VERSION',
    'ServiceFlags',
    'service_flags_to_str',
    'seeds_service_flags',
    'NetMsgType',
    'ALL_NET_MESSAGE_TYPES',
    'CInv',
    'GetDataMsg',
    'MSG_WITNESS_FLAG',
    'MSG_TYPE_MASK',
    'ConnectionType',
    'TransportProtocolType',
    'MessageHeader',
    'HEADER_SIZE',
    'MAX_PROTOCOL_MESSAGE_LENGTH',
    'MAX_OUTBOUND_FULL_RELAY_CONNECTIONS',
    'MAX_ADDNODE_CONNECTIONS',
    'DEFAULT_MAX_PEER_CONNECTIONS',
    'NodeId',
    
    # Transport
    'Transport',
    'V1Transport',
    'V2Transport',
    'CSerializedNetMsg',
    'CNetMessage',
    'TransportType',
    'get_v2_short_id',
    'get_v2_message_type',
    
    # Messages
    'P2PMessage',
    'VersionMessage',
    'VerackMessage',
    'AddrMessage',
    'AddrV2Message',
    'InvMessage',
    'GetDataMessage',
    'NotFoundMessage',
    'GetBlocksMessage',
    'GetHeadersMessage',
    'HeadersMessage',
    'BlockMessage',
    'TxMessage',
    'PingMessage',
    'PongMessage',
    'FeeFilterMessage',
    'SendHeadersMessage',
    'WTXIDRelayMessage',
    'SendAddrV2Message',
    'MempoolMessage',
    'GetAddrMessage',
    'encode_compact_size',
    'decode_compact_size',
    'encode_varint',
    'decode_varint',
    'MESSAGE_REGISTRY',
    'deserialize_message',
    
    # Connection manager
    'CNode',
    'CConnMan',
    'CNodeStats',
    'CNodeOptions',
    'NetPermissionFlags',
    'LOCAL_NONE',
    'LOCAL_IF',
    'LOCAL_BIND',
    'LOCAL_MANUAL',
    'add_local',
    'remove_local',
    'is_local',
    'calculate_keyed_net_group',
    
    # Address manager
    'AddrMan',
    'AddrInfo',
    
    # DNS seeds
    'DNSSeedData',
    'DNSSeedQuerier',
    'DNSSeedQueryOptions',
    'DNSSeedResult',
    'PeerDiscovery',
    'MAINNET_DNS_SEEDS',
    'TESTNET_DNS_SEEDS',
    'TESTNET4_DNS_SEEDS',
    'SIGNET_DNS_SEEDS',
    'create_dns_seed_querier',
    'create_peer_discovery',
    
    # Block download
    'BlockDownloadManager',
    'BlockDownloadState',
    'HeadersSyncState',
    'OrphanBlockPool',
    
    # Transaction broadcast
    'TxBroadcastManager',
    'OrphanTxPool',
    'TxSubmitResult',
]
