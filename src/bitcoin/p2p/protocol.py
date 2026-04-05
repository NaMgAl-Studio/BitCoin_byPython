"""
Bitcoin P2P Protocol Definitions.

This module implements the Bitcoin P2P protocol constants, message types,
service flags, and protocol version information.

Reference: Bitcoin Core src/protocol.h, src/node/protocol_version.h
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum, IntFlag
from typing import Final, ClassVar


# ==============================================================================
# Protocol Version Constants
# ==============================================================================

PROTOCOL_VERSION: Final[int] = 70016
"""Current network protocol version"""

INIT_PROTO_VERSION: Final[int] = 209
"""Initial protocol version, to be increased after version/verack negotiation"""

MIN_PEER_PROTO_VERSION: Final[int] = 31800
"""Disconnect from peers older than this protocol version"""

BIP0031_VERSION: Final[int] = 60000
"""BIP 0031, pong message, is enabled for all versions AFTER this one"""

SENDHEADERS_VERSION: Final[int] = 70012
""""sendheaders" message type and announcing blocks with headers starts with this version"""

FEEFILTER_VERSION: Final[int] = 70013
""""feefilter" tells peers to filter invs to you by fee starts with this version"""

SHORT_IDS_BLOCKS_VERSION: Final[int] = 70014
"""Short-id-based block download starts with this version"""

INVALID_CB_NO_BAN_VERSION: Final[int] = 70015
"""Not banning for invalid compact blocks starts with this version"""

WTXID_RELAY_VERSION: Final[int] = 70016
""""wtxidrelay" message type for wtxid-based relay starts with this version"""


# ==============================================================================
# Network Constants
# ==============================================================================

MAX_PROTOCOL_MESSAGE_LENGTH: Final[int] = 4 * 1000 * 1000
"""Maximum length of incoming protocol messages (no message over 4 MB is currently acceptable)"""

MAX_SUBVERSION_LENGTH: Final[int] = 256
"""Maximum length of the user agent string in `version` message"""

MAX_OUTBOUND_FULL_RELAY_CONNECTIONS: Final[int] = 8
"""Maximum number of automatic outgoing nodes over which we'll relay everything"""

MAX_ADDNODE_CONNECTIONS: Final[int] = 8
"""Maximum number of addnode outgoing nodes"""

MAX_BLOCK_RELAY_ONLY_CONNECTIONS: Final[int] = 2
"""Maximum number of block-relay-only outgoing connections"""

MAX_FEELER_CONNECTIONS: Final[int] = 1
"""Maximum number of feeler connections"""

MAX_PRIVATE_BROADCAST_CONNECTIONS: Final[int] = 64
"""Maximum number of private broadcast connections"""

DEFAULT_MAX_PEER_CONNECTIONS: Final[int] = 125
"""The maximum number of peer connections to maintain"""

DEFAULT_LISTEN: Final[bool] = True
"""-listen default"""

DEFAULT_BLOCKSONLY: Final[bool] = False
"""Default for blocks only"""

DEFAULT_PEER_CONNECT_TIMEOUT: Final[int] = 60
"""-peertimeout default"""

DEFAULT_MAXRECEIVEBUFFER: Final[int] = 5 * 1000
DEFAULT_MAXSENDBUFFER: Final[int] = 1 * 1000

DEFAULT_V2_TRANSPORT: Final[bool] = True
"""Default for V2 transport (BIP324)"""

DEFAULT_FORCEDNSSEED: Final[bool] = False
DEFAULT_DNSSEED: Final[bool] = True
DEFAULT_FIXEDSEEDS: Final[bool] = True

TIMEOUT_INTERVAL_SECONDS: Final[int] = 20 * 60
"""Time after which to disconnect, after waiting for a ping response (or inactivity)"""

FEELER_INTERVAL_SECONDS: Final[int] = 2 * 60
"""Run the feeler connection loop once every 2 minutes"""

EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL_SECONDS: Final[int] = 5 * 60
"""Run the extra block-relay-only connection loop once every 5 minutes"""


# ==============================================================================
# Service Flags
# ==============================================================================

class ServiceFlags(IntFlag):
    """
    nServices flags.
    
    These flags are advertised in version messages.
    """
    
    NODE_NONE = 0
    """Nothing"""
    
    NODE_NETWORK = 1 << 0
    """
    NODE_NETWORK means that the node is capable of serving the complete block chain.
    It is currently set by all Bitcoin Core non pruned nodes, and is unset by
    SPV clients or other light clients.
    """
    
    NODE_BLOOM = 1 << 2
    """
    NODE_BLOOM means the node is capable and willing to handle bloom-filtered connections.
    """
    
    NODE_WITNESS = 1 << 3
    """
    NODE_WITNESS indicates that a node can be asked for blocks and transactions
    including witness data.
    """
    
    NODE_COMPACT_FILTERS = 1 << 6
    """
    NODE_COMPACT_FILTERS means the node will service basic block filter requests.
    See BIP157 and BIP158 for details on how this is implemented.
    """
    
    NODE_NETWORK_LIMITED = 1 << 10
    """
    NODE_NETWORK_LIMITED means the same as NODE_NETWORK with the limitation of only
    serving the last 288 (2 day) blocks.
    See BIP159 for details on how this is implemented.
    """
    
    NODE_P2P_V2 = 1 << 11
    """
    NODE_P2P_V2 means the node supports BIP324 transport.
    """


def service_flags_to_str(flags: int) -> list[str]:
    """
    Convert service flags (a bitmask of NODE_*) to human readable strings.
    
    It supports unknown service flags which will be returned as "UNKNOWN[...]".
    
    Args:
        flags: multiple NODE_* bitwise-OR-ed together
        
    Returns:
        List of human-readable service flag strings
    """
    result = []
    
    if flags & ServiceFlags.NODE_NETWORK:
        result.append("NETWORK")
    if flags & ServiceFlags.NODE_BLOOM:
        result.append("BLOOM")
    if flags & ServiceFlags.NODE_WITNESS:
        result.append("WITNESS")
    if flags & ServiceFlags.NODE_COMPACT_FILTERS:
        result.append("COMPACT_FILTERS")
    if flags & ServiceFlags.NODE_NETWORK_LIMITED:
        result.append("NETWORK_LIMITED")
    if flags & ServiceFlags.NODE_P2P_V2:
        result.append("P2P_V2")
    
    # Check for unknown flags (bits 12-23 are unknown)
    known_mask = (
        ServiceFlags.NODE_NETWORK |
        ServiceFlags.NODE_BLOOM |
        ServiceFlags.NODE_WITNESS |
        ServiceFlags.NODE_COMPACT_FILTERS |
        ServiceFlags.NODE_NETWORK_LIMITED |
        ServiceFlags.NODE_P2P_V2
    )
    
    unknown_flags = flags & ~known_mask
    if unknown_flags:
        result.append(f"UNKNOWN[{unknown_flags:016x}]")
    
    return result


def seeds_service_flags() -> ServiceFlags:
    """
    State independent service flags.
    
    If the return value is changed, contrib/seeds/makeseeds.py
    should be updated appropriately to filter for nodes with
    desired service flags (compatible with our new flags).
    """
    return ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_WITNESS


def may_have_useful_address_db(services: ServiceFlags) -> bool:
    """
    Checks if a peer with the given service flags may be capable of having a
    robust address-storage DB.
    """
    return bool(services & ServiceFlags.NODE_NETWORK) or bool(services & ServiceFlags.NODE_NETWORK_LIMITED)


# ==============================================================================
# Message Types
# ==============================================================================

class NetMsgType:
    """
    Bitcoin protocol message types.
    
    When adding new message types, don't forget to update ALL_NET_MESSAGE_TYPES.
    """
    
    VERSION: Final[str] = "version"
    """
    The version message provides information about the transmitting node to the
    receiving node at the beginning of a connection.
    """
    
    VERACK: Final[str] = "verack"
    """
    The verack message acknowledges a previously-received version message,
    informing the connecting node that it can begin to send other messages.
    """
    
    ADDR: Final[str] = "addr"
    """
    The addr (IP address) message relays connection information for peers on the
    network.
    """
    
    ADDRV2: Final[str] = "addrv2"
    """
    The addrv2 message relays connection information for peers on the network just
    like the addr message, but is extended to allow gossiping of longer node
    addresses (see BIP155).
    """
    
    SENDADDRV2: Final[str] = "sendaddrv2"
    """
    The sendaddrv2 message signals support for receiving ADDRV2 messages (BIP155).
    It also implies that its sender can encode as ADDRV2 and would send ADDRV2
    instead of ADDR to a peer that has signaled ADDRV2 support by sending SENDADDRV2.
    """
    
    INV: Final[str] = "inv"
    """
    The inv message (inventory message) transmits one or more inventories of
    objects known to the transmitting peer.
    """
    
    GETDATA: Final[str] = "getdata"
    """
    The getdata message requests one or more data objects from another node.
    """
    
    MERKLEBLOCK: Final[str] = "merkleblock"
    """
    The merkleblock message is a reply to a getdata message which requested a
    block using the inventory type MSG_MERKLEBLOCK.
    @since protocol version 70001 as described by BIP37.
    """
    
    GETBLOCKS: Final[str] = "getblocks"
    """
    The getblocks message requests an inv message that provides block header
    hashes starting from a particular point in the block chain.
    """
    
    GETHEADERS: Final[str] = "getheaders"
    """
    The getheaders message requests a headers message that provides block
    headers starting from a particular point in the block chain.
    @since protocol version 31800.
    """
    
    TX: Final[str] = "tx"
    """
    The tx message transmits a single transaction.
    """
    
    HEADERS: Final[str] = "headers"
    """
    The headers message sends one or more block headers to a node which
    previously requested certain headers with a getheaders message.
    @since protocol version 31800.
    """
    
    BLOCK: Final[str] = "block"
    """
    The block message transmits a single serialized block.
    """
    
    GETADDR: Final[str] = "getaddr"
    """
    The getaddr message requests an addr message from the receiving node,
    preferably one with lots of IP addresses of other receiving nodes.
    """
    
    MEMPOOL: Final[str] = "mempool"
    """
    The mempool message requests the TXIDs of transactions that the receiving
    node has verified as valid but which have not yet appeared in a block.
    @since protocol version 60002 as described by BIP35.
    Only available with service bit NODE_BLOOM, see also BIP111.
    """
    
    PING: Final[str] = "ping"
    """
    The ping message is sent periodically to help confirm that the receiving
    peer is still connected.
    """
    
    PONG: Final[str] = "pong"
    """
    The pong message replies to a ping message, proving to the pinging node that
    the ponging node is still alive.
    @since protocol version 60001 as described by BIP31.
    """
    
    NOTFOUND: Final[str] = "notfound"
    """
    The notfound message is a reply to a getdata message which requested an
    object the receiving node does not have available for relay.
    @since protocol version 70001.
    """
    
    FILTERLOAD: Final[str] = "filterload"
    """
    The filterload message tells the receiving peer to filter all relayed
    transactions and requested merkle blocks through the provided filter.
    @since protocol version 70001 as described by BIP37.
    Only available with service bit NODE_BLOOM since protocol version
    70011 as described by BIP111.
    """
    
    FILTERADD: Final[str] = "filteradd"
    """
    The filteradd message tells the receiving peer to add a single element to a
    previously-set bloom filter, such as a new public key.
    @since protocol version 70001 as described by BIP37.
    Only available with service bit NODE_BLOOM since protocol version
    70011 as described by BIP111.
    """
    
    FILTERCLEAR: Final[str] = "filterclear"
    """
    The filterclear message tells the receiving peer to remove a previously-set
    bloom filter.
    @since protocol version 70001 as described by BIP37.
    Only available with service bit NODE_BLOOM since protocol version
    70011 as described by BIP111.
    """
    
    SENDHEADERS: Final[str] = "sendheaders"
    """
    Indicates that a node prefers to receive new block announcements via a
    "headers" message rather than an "inv".
    @since protocol version 70012 as described by BIP130.
    """
    
    FEEFILTER: Final[str] = "feefilter"
    """
    The feefilter message tells the receiving peer not to inv us any txs
    which do not meet the specified min fee rate.
    @since protocol version 70013 as described by BIP133
    """
    
    SENDCMPCT: Final[str] = "sendcmpct"
    """
    Contains a 1-byte bool and 8-byte LE version number.
    Indicates that a node is willing to provide blocks via "cmpctblock" messages.
    May indicate that a node prefers to receive new block announcements via a
    "cmpctblock" message rather than an "inv", depending on message contents.
    @since protocol version 70014 as described by BIP 152
    """
    
    CMPCTBLOCK: Final[str] = "cmpctblock"
    """
    Contains a CBlockHeaderAndShortTxIDs object - providing a header and
    list of "short txids".
    @since protocol version 70014 as described by BIP 152
    """
    
    GETBLOCKTXN: Final[str] = "getblocktxn"
    """
    Contains a BlockTransactionsRequest
    Peer should respond with "blocktxn" message.
    @since protocol version 70014 as described by BIP 152
    """
    
    BLOCKTXN: Final[str] = "blocktxn"
    """
    Contains a BlockTransactions.
    Sent in response to a "getblocktxn" message.
    @since protocol version 70014 as described by BIP 152
    """
    
    GETCFILTERS: Final[str] = "getcfilters"
    """
    getcfilters requests compact filters for a range of blocks.
    Only available with service bit NODE_COMPACT_FILTERS as described by
    BIP 157 & 158.
    """
    
    CFILTER: Final[str] = "cfilter"
    """
    cfilter is a response to a getcfilters request containing a single compact
    filter.
    """
    
    GETCFHEADERS: Final[str] = "getcfheaders"
    """
    getcfheaders requests a compact filter header and the filter hashes for a
    range of blocks, which can then be used to reconstruct the filter headers
    for those blocks.
    Only available with service bit NODE_COMPACT_FILTERS as described by
    BIP 157 & 158.
    """
    
    CFHEADERS: Final[str] = "cfheaders"
    """
    cfheaders is a response to a getcfheaders request containing a filter header
    and a vector of filter hashes for each subsequent block in the requested range.
    """
    
    GETCFCHECKPT: Final[str] = "getcfcheckpt"
    """
    getcfcheckpt requests evenly spaced compact filter headers, enabling
    parallelized download and validation of the headers between them.
    Only available with service bit NODE_COMPACT_FILTERS as described by
    BIP 157 & 158.
    """
    
    CFCHECKPT: Final[str] = "cfcheckpt"
    """
    cfcheckpt is a response to a getcfcheckpt request containing a vector of
    evenly spaced filter headers for blocks on the requested chain.
    """
    
    WTXIDRELAY: Final[str] = "wtxidrelay"
    """
    Indicates that a node prefers to relay transactions via wtxid, rather than
    txid.
    @since protocol version 70016 as described by BIP 339.
    """
    
    SENDTXRCNCL: Final[str] = "sendtxrcncl"
    """
    Contains a 4-byte version number and an 8-byte salt.
    The salt is used to compute short txids needed for efficient
    txreconciliation, as described by BIP 330.
    """


# All known message types (in the same order as above)
ALL_NET_MESSAGE_TYPES: Final[list[str]] = [
    NetMsgType.VERSION,
    NetMsgType.VERACK,
    NetMsgType.ADDR,
    NetMsgType.ADDRV2,
    NetMsgType.SENDADDRV2,
    NetMsgType.INV,
    NetMsgType.GETDATA,
    NetMsgType.MERKLEBLOCK,
    NetMsgType.GETBLOCKS,
    NetMsgType.GETHEADERS,
    NetMsgType.TX,
    NetMsgType.HEADERS,
    NetMsgType.BLOCK,
    NetMsgType.GETADDR,
    NetMsgType.MEMPOOL,
    NetMsgType.PING,
    NetMsgType.PONG,
    NetMsgType.NOTFOUND,
    NetMsgType.FILTERLOAD,
    NetMsgType.FILTERADD,
    NetMsgType.FILTERCLEAR,
    NetMsgType.SENDHEADERS,
    NetMsgType.FEEFILTER,
    NetMsgType.SENDCMPCT,
    NetMsgType.CMPCTBLOCK,
    NetMsgType.GETBLOCKTXN,
    NetMsgType.BLOCKTXN,
    NetMsgType.GETCFILTERS,
    NetMsgType.CFILTER,
    NetMsgType.GETCFHEADERS,
    NetMsgType.CFHEADERS,
    NetMsgType.GETCFCHECKPT,
    NetMsgType.CFCHECKPT,
    NetMsgType.WTXIDRELAY,
    NetMsgType.SENDTXRCNCL,
]

NET_MESSAGE_TYPE_OTHER: Final[str] = "other"


# ==============================================================================
# GetData Message Types
# ==============================================================================

MSG_WITNESS_FLAG: Final[int] = 1 << 30
MSG_TYPE_MASK: Final[int] = 0xFFFFFFFF >> 2


class GetDataMsg(IntEnum):
    """
    getdata / inv message types.
    These numbers are defined by the protocol. When adding a new value, be sure
    to mention it in the respective BIP.
    """
    
    UNDEFINED = 0
    MSG_TX = 1
    MSG_BLOCK = 2
    MSG_WTX = 5  # Defined in BIP 339
    
    # The following can only occur in getdata. Invs always use TX/WTX or BLOCK.
    MSG_FILTERED_BLOCK = 3  # Defined in BIP37
    MSG_CMPCT_BLOCK = 4  # Defined in BIP152
    
    MSG_WITNESS_BLOCK = MSG_BLOCK | MSG_WITNESS_FLAG  # Defined in BIP144
    MSG_WITNESS_TX = MSG_TX | MSG_WITNESS_FLAG  # Defined in BIP144
    
    # MSG_FILTERED_WITNESS_BLOCK is defined in BIP144 as reserved for future
    # use and remains unused.
    # MSG_FILTERED_WITNESS_BLOCK = MSG_FILTERED_BLOCK | MSG_WITNESS_FLAG,


# ==============================================================================
# Connection Types
# ==============================================================================

class ConnectionType(Enum):
    """
    Different types of connections to a peer.
    
    This enum encapsulates the information we have available at the time of
    opening or accepting the connection. Aside from INBOUND, all types are
    initiated by us.
    """
    
    INBOUND = "inbound"
    """
    Inbound connections are those initiated by a peer. This is the only
    property we know at the time of connection, until P2P messages are
    exchanged.
    """
    
    OUTBOUND_FULL_RELAY = "outbound-full-relay"
    """
    These are the default connections that we use to connect with the
    network. There is no restriction on what is relayed; by default we relay
    blocks, addresses & transactions. We automatically attempt to open
    MAX_OUTBOUND_FULL_RELAY_CONNECTIONS using addresses from our AddrMan.
    """
    
    MANUAL = "manual"
    """
    We open manual connections to addresses that users explicitly requested
    via the addnode RPC or the -addnode/-connect configuration options. Even if a
    manual connection is misbehaving, we do not automatically disconnect or
    add it to our discouragement filter.
    """
    
    FEELER = "feeler"
    """
    Feeler connections are short-lived connections made to check that a node
    is alive. They can be useful for:
    - test-before-evict: if one of the peers is considered for eviction from
      our AddrMan because another peer is mapped to the same slot in the tried table,
      evict only if this longer-known peer is offline.
    - move node addresses from New to Tried table, so that we have more
      connectable addresses in our AddrMan.
    """
    
    BLOCK_RELAY = "block-relay"
    """
    We use block-relay-only connections to help prevent against partition
    attacks. By not relaying transactions or addresses, these connections
    are harder to detect by a third party, thus helping obfuscate the
    network topology.
    """
    
    ADDR_FETCH = "addr-fetch"
    """
    AddrFetch connections are short lived connections used to solicit
    addresses from peers. These are initiated to addresses submitted via the
    -seednode command line argument, or under certain conditions when the
    AddrMan is empty.
    """
    
    PRIVATE_BROADCAST = "private-broadcast"
    """
    Private broadcast connections are short-lived and only opened to
    privacy networks (Tor, I2P) for relaying privacy-sensitive data (like
    our own transactions) and closed afterwards.
    """


def connection_type_to_string(conn_type: ConnectionType) -> str:
    """Convert ConnectionType enum to a string value."""
    return conn_type.value


class TransportProtocolType(Enum):
    """Transport layer version."""
    
    DETECTING = "detecting"
    """Peer could be v1 or v2"""
    
    V1 = "v1"
    """Unencrypted, plaintext protocol"""
    
    V2 = "v2"
    """BIP324 protocol"""


def transport_type_to_string(transport_type: TransportProtocolType) -> str:
    """Convert TransportProtocolType enum to a string value."""
    return transport_type.value


# ==============================================================================
# Message Header
# ==============================================================================

MESSAGE_TYPE_SIZE: Final[int] = 12
MESSAGE_SIZE_SIZE: Final[int] = 4
CHECKSUM_SIZE: Final[int] = 4
MESSAGE_SIZE_OFFSET: Final[int] = 4 + MESSAGE_TYPE_SIZE  # MessageStartChars + MESSAGE_TYPE_SIZE
CHECKSUM_OFFSET: Final[int] = MESSAGE_SIZE_OFFSET + MESSAGE_SIZE_SIZE
HEADER_SIZE: Final[int] = 4 + MESSAGE_TYPE_SIZE + MESSAGE_SIZE_SIZE + CHECKSUM_SIZE


@dataclass
class MessageHeader:
    """
    Message header.
    
    (4) message start.
    (12) message type.
    (4) size.
    (4) checksum.
    """
    
    message_start: bytes  # 4 bytes
    message_type: str  # 12 bytes (padded with null)
    message_size: int
    checksum: bytes  # 4 bytes
    
    def is_message_type_valid(self) -> bool:
        """Check if message type is valid."""
        return self.message_type.rstrip('\x00') in ALL_NET_MESSAGE_TYPES
    
    def get_message_type(self) -> str:
        """Get the message type string."""
        return self.message_type.rstrip('\x00')
    
    def to_bytes(self) -> bytes:
        """Serialize the header to bytes."""
        result = bytearray()
        result.extend(self.message_start)
        # Pad message type to 12 bytes
        msg_type_bytes = self.message_type.encode('ascii')
        msg_type_bytes = msg_type_bytes.ljust(MESSAGE_TYPE_SIZE, b'\x00')
        result.extend(msg_type_bytes[:MESSAGE_TYPE_SIZE])
        # Message size (4 bytes, little-endian)
        result.extend(self.message_size.to_bytes(4, 'little'))
        # Checksum (4 bytes)
        result.extend(self.checksum)
        return bytes(result)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> MessageHeader:
        """Deserialize a message header from bytes."""
        if len(data) < HEADER_SIZE:
            raise ValueError(f"Header data too short: {len(data)} < {HEADER_SIZE}")
        
        message_start = data[:4]
        message_type = data[4:4 + MESSAGE_TYPE_SIZE].decode('ascii').rstrip('\x00')
        message_size = int.from_bytes(data[MESSAGE_SIZE_OFFSET:MESSAGE_SIZE_OFFSET + 4], 'little')
        checksum = data[CHECKSUM_OFFSET:CHECKSUM_OFFSET + CHECKSUM_SIZE]
        
        return cls(
            message_start=message_start,
            message_type=message_type,
            message_size=message_size,
            checksum=checksum
        )


# ==============================================================================
# Inventory
# ==============================================================================

@dataclass
class CInv:
    """
    inv message data.
    """
    
    type: int
    hash: bytes  # 32 bytes
    
    def __post_init__(self):
        if len(self.hash) != 32:
            raise ValueError(f"Hash must be 32 bytes, got {len(self.hash)}")
    
    def __lt__(self, other: CInv) -> bool:
        return (self.type, self.hash) < (other.type, other.hash)
    
    def get_message_type(self) -> str:
        """Get the message type string."""
        if self.type == GetDataMsg.MSG_TX:
            return NetMsgType.TX
        elif self.type == GetDataMsg.MSG_BLOCK:
            return NetMsgType.BLOCK
        elif self.type == GetDataMsg.MSG_WTX:
            return NetMsgType.TX  # WTX is still a transaction
        elif self.type == GetDataMsg.MSG_FILTERED_BLOCK:
            return NetMsgType.MERKLEBLOCK
        elif self.type == GetDataMsg.MSG_CMPCT_BLOCK:
            return NetMsgType.CMPCTBLOCK
        elif self.type == GetDataMsg.MSG_WITNESS_BLOCK:
            return NetMsgType.BLOCK
        elif self.type == GetDataMsg.MSG_WITNESS_TX:
            return NetMsgType.TX
        else:
            return f"UNKNOWN[{self.type}]"
    
    def is_msg_tx(self) -> bool:
        return self.type == GetDataMsg.MSG_TX
    
    def is_msg_block(self) -> bool:
        return self.type == GetDataMsg.MSG_BLOCK
    
    def is_msg_wtx(self) -> bool:
        return self.type == GetDataMsg.MSG_WTX
    
    def is_msg_filtered_block(self) -> bool:
        return self.type == GetDataMsg.MSG_FILTERED_BLOCK
    
    def is_msg_cmpct_block(self) -> bool:
        return self.type == GetDataMsg.MSG_CMPCT_BLOCK
    
    def is_msg_witness_block(self) -> bool:
        return self.type == GetDataMsg.MSG_WITNESS_BLOCK
    
    def is_gen_tx_msg(self) -> bool:
        """Check if this is a transaction-related message."""
        return self.type in (
            GetDataMsg.MSG_TX,
            GetDataMsg.MSG_WTX,
            GetDataMsg.MSG_WITNESS_TX
        )
    
    def is_gen_block_msg(self) -> bool:
        """Check if this is a block-related message."""
        return self.type in (
            GetDataMsg.MSG_BLOCK,
            GetDataMsg.MSG_FILTERED_BLOCK,
            GetDataMsg.MSG_CMPCT_BLOCK,
            GetDataMsg.MSG_WITNESS_BLOCK
        )
    
    def __str__(self) -> str:
        return f"CInv({self.get_message_type()}, {self.hash.hex()[:16]}...)"
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes."""
        result = bytearray()
        result.extend(self.type.to_bytes(4, 'little'))
        result.extend(self.hash)
        return bytes(result)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> CInv:
        """Deserialize from bytes."""
        if len(data) < 36:
            raise ValueError(f"Inv data too short: {len(data)} < 36")
        
        inv_type = int.from_bytes(data[:4], 'little')
        hash_bytes = data[4:36]
        
        return cls(type=inv_type, hash=hash_bytes)


# ==============================================================================
# Node ID Type
# ==============================================================================

NodeId = int
"""Type alias for node identifiers"""


# ==============================================================================
# Message Start Characters (Network Magic)
# ==============================================================================

def get_message_start(chain: str) -> bytes:
    """
    Get the message start characters (magic bytes) for a chain.
    
    Args:
        chain: Chain name ('main', 'test', 'testnet4', 'signet', 'regtest')
        
    Returns:
        4-byte magic bytes
    """
    MESSAGE_STARTS = {
        'main': bytes.fromhex('f9beb4d9'),
        'test': bytes.fromhex('0b110907'),  # testnet3
        'testnet4': bytes.fromhex('1c163f28'),
        'signet': bytes.fromhex('0a03cf40'),
        'regtest': bytes.fromhex('fabfb5da'),
    }
    
    if chain not in MESSAGE_STARTS:
        raise ValueError(f"Unknown chain: {chain}")
    
    return MESSAGE_STARTS[chain]
