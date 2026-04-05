"""
Bitcoin P2P Messages.

This module implements the P2P message serialization and deserialization
for the Bitcoin protocol.

Reference: Bitcoin Core src/protocol.h, src/net_processing.cpp
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Final, List, Optional, ClassVar

from .netaddress import CNetAddr, CService
from .protocol import (
    ServiceFlags, NetMsgType, CInv, GetDataMsg,
    PROTOCOL_VERSION, WTXID_RELAY_VERSION
)
from ..primitives.transaction import Transaction, OutPoint
from ..primitives.block import Block, BlockHeader
from ..consensus.amount import Amount


# ==============================================================================
# Serialization Helpers
# ==============================================================================

def encode_compact_size(size: int) -> bytes:
    """Encode a variable-length integer (CompactSize)."""
    if size < 0xFD:
        return bytes([size])
    elif size <= 0xFFFF:
        return bytes([0xFD]) + struct.pack('<H', size)
    elif size <= 0xFFFFFFFF:
        return bytes([0xFE]) + struct.pack('<I', size)
    else:
        return bytes([0xFF]) + struct.pack('<Q', size)


def decode_compact_size(data: bytes, offset: int = 0) -> tuple[int, int]:
    """
    Decode a CompactSize integer.
    
    Returns:
        Tuple of (value, new_offset)
    """
    if offset >= len(data):
        raise ValueError("Data too short for CompactSize")
    
    first = data[offset]
    if first < 0xFD:
        return first, offset + 1
    elif first == 0xFD:
        if offset + 3 > len(data):
            raise ValueError("Data too short for CompactSize")
        return struct.unpack('<H', data[offset + 1:offset + 3])[0], offset + 3
    elif first == 0xFE:
        if offset + 5 > len(data):
            raise ValueError("Data too short for CompactSize")
        return struct.unpack('<I', data[offset + 1:offset + 5])[0], offset + 5
    else:
        if offset + 9 > len(data):
            raise ValueError("Data too short for CompactSize")
        return struct.unpack('<Q', data[offset + 1:offset + 9])[0], offset + 9


def encode_varint(value: int) -> bytes:
    """Encode a variable-length integer (used in transaction serialization)."""
    return encode_compact_size(value)


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode a variable-length integer."""
    return decode_compact_size(data, offset)


# ==============================================================================
# Message Base Class
# ==============================================================================

@dataclass
class P2PMessage:
    """Base class for all P2P messages."""
    
    command: ClassVar[str] = ""
    
    def serialize(self) -> bytes:
        """Serialize the message to bytes."""
        raise NotImplementedError
    
    @classmethod
    def deserialize(cls, data: bytes) -> P2PMessage:
        """Deserialize a message from bytes."""
        raise NotImplementedError


# ==============================================================================
# Version Message
# ==============================================================================

@dataclass
class VersionMessage(P2PMessage):
    """
    Version message.
    
    The version message provides information about the transmitting node
    to the receiving node at the beginning of a connection.
    """
    
    command: ClassVar[str] = NetMsgType.VERSION
    
    n_version: int = PROTOCOL_VERSION
    n_services: ServiceFlags = ServiceFlags.NODE_NONE
    n_time: int = 0  # Unix timestamp
    addr_recv: CService = field(default_factory=CService)
    addr_from: CService = field(default_factory=CService)
    n_nonce: int = 0
    str_sub_ver: str = ""  # User agent
    n_start_height: int = 0  # Last block height
    n_relay: bool = True  # Whether to relay transactions
    
    def __post_init__(self):
        if self.n_time == 0:
            self.n_time = int(datetime.now(timezone.utc).timestamp())
    
    def serialize(self) -> bytes:
        """Serialize version message."""
        result = bytearray()
        
        # Version (4 bytes)
        result.extend(struct.pack('<i', self.n_version))
        
        # Services (8 bytes)
        result.extend(struct.pack('<Q', self.n_services))
        
        # Time (8 bytes)
        result.extend(struct.pack('<q', self.n_time))
        
        # Receiver address (26 bytes in version message format)
        result.extend(self._serialize_addr_version(self.addr_recv))
        
        # Sender address (26 bytes)
        result.extend(self._serialize_addr_version(self.addr_from))
        
        # Nonce (8 bytes)
        result.extend(struct.pack('<Q', self.n_nonce))
        
        # User agent (variable)
        result.extend(encode_compact_size(len(self.str_sub_ver)))
        result.extend(self.str_sub_ver.encode('utf-8'))
        
        # Start height (4 bytes)
        result.extend(struct.pack('<i', self.n_start_height))
        
        # Relay flag (1 byte) - only if version >= 70001
        if self.n_version >= 70001:
            result.append(1 if self.n_relay else 0)
        
        return bytes(result)
    
    @staticmethod
    def _serialize_addr_version(addr: CService) -> bytes:
        """Serialize address in version message format (26 bytes)."""
        result = bytearray()
        
        # Services (8 bytes)
        result.extend(struct.pack('<Q', ServiceFlags.NODE_NONE))
        
        # IP address (16 bytes)
        if addr.is_ipv4():
            result.extend(bytes([0] * 10 + [0xFF, 0xFF]))
            result.extend(addr.m_addr)
        else:
            result.extend(addr.m_addr[:16] if len(addr.m_addr) >= 16 else
                         addr.m_addr + bytes(16 - len(addr.m_addr)))
        
        # Port (2 bytes, big-endian)
        result.extend(struct.pack('>H', addr.port))
        
        return bytes(result)
    
    @classmethod
    def deserialize(cls, data: bytes) -> VersionMessage:
        """Deserialize version message."""
        offset = 0
        
        # Version
        n_version = struct.unpack('<i', data[offset:offset + 4])[0]
        offset += 4
        
        # Services
        n_services = ServiceFlags(struct.unpack('<Q', data[offset:offset + 8])[0])
        offset += 8
        
        # Time
        n_time = struct.unpack('<q', data[offset:offset + 8])[0]
        offset += 8
        
        # Receiver address
        addr_recv, offset = cls._deserialize_addr_version(data, offset)
        
        # Sender address
        addr_from, offset = cls._deserialize_addr_version(data, offset)
        
        # Nonce
        n_nonce = struct.unpack('<Q', data[offset:offset + 8])[0]
        offset += 8
        
        # User agent
        user_agent_len, offset = decode_compact_size(data, offset)
        str_sub_ver = data[offset:offset + user_agent_len].decode('utf-8')
        offset += user_agent_len
        
        # Start height
        n_start_height = struct.unpack('<i', data[offset:offset + 4])[0]
        offset += 4
        
        # Relay flag (optional)
        n_relay = True
        if len(data) > offset and n_version >= 70001:
            n_relay = data[offset] != 0
        
        return cls(
            n_version=n_version,
            n_services=n_services,
            n_time=n_time,
            addr_recv=addr_recv,
            addr_from=addr_from,
            n_nonce=n_nonce,
            str_sub_ver=str_sub_ver,
            n_start_height=n_start_height,
            n_relay=n_relay
        )
    
    @staticmethod
    def _deserialize_addr_version(data: bytes, offset: int) -> tuple[CService, int]:
        """Deserialize address in version message format."""
        # Services
        services = struct.unpack('<Q', data[offset:offset + 8])[0]
        offset += 8
        
        # IP address (16 bytes)
        ip_bytes = data[offset:offset + 16]
        offset += 16
        
        # Port
        port = struct.unpack('>H', data[offset:offset + 2])[0]
        offset += 2
        
        # Parse IP address
        if ip_bytes[:12] == bytes([0] * 10 + [0xFF, 0xFF]):
            # IPv4-mapped IPv6
            addr = CNetAddr()
            addr.m_net = CNetAddr._net if hasattr(CNetAddr, '_net') else 1  # IPv4
            addr.m_addr = ip_bytes[12:16]
        else:
            addr = CNetAddr()
            addr.m_net = 2  # IPv6
            addr.m_addr = ip_bytes
        
        return CService(m_addr=addr.m_addr, m_net=addr.m_net, port=port), offset


# ==============================================================================
# Verack Message
# ==============================================================================

@dataclass
class VerackMessage(P2PMessage):
    """Verack message - acknowledges version message."""
    
    command: ClassVar[str] = NetMsgType.VERACK
    
    def serialize(self) -> bytes:
        return b""
    
    @classmethod
    def deserialize(cls, data: bytes) -> VerackMessage:
        return cls()


# ==============================================================================
# Addr Message
# ==============================================================================

@dataclass
class AddrMessage(P2PMessage):
    """Addr message - relays peer addresses."""
    
    command: ClassVar[str] = NetMsgType.ADDR
    
    addrs: List[tuple[int, CService]] = field(default_factory=list)  # (time, address)
    
    def serialize(self) -> bytes:
        result = bytearray()
        
        # Count
        result.extend(encode_compact_size(len(self.addrs)))
        
        for time, addr in self.addrs:
            # Time (4 bytes)
            result.extend(struct.pack('<I', time))
            
            # Services (8 bytes)
            # This should be from CAddress, but we use a default here
            result.extend(struct.pack('<Q', ServiceFlags.NODE_NETWORK))
            
            # IP address (16 bytes)
            if addr.is_ipv4():
                result.extend(bytes([0] * 10 + [0xFF, 0xFF]))
                result.extend(addr.m_addr)
            else:
                result.extend(addr.m_addr[:16] if len(addr.m_addr) >= 16 else
                             addr.m_addr + bytes(16 - len(addr.m_addr)))
            
            # Port (2 bytes, big-endian)
            result.extend(struct.pack('>H', addr.port))
        
        return bytes(result)
    
    @classmethod
    def deserialize(cls, data: bytes) -> AddrMessage:
        offset = 0
        
        # Count
        count, offset = decode_compact_size(data, offset)
        
        addrs = []
        for _ in range(count):
            # Time (4 bytes)
            time = struct.unpack('<I', data[offset:offset + 4])[0]
            offset += 4
            
            # Services (8 bytes)
            offset += 8
            
            # IP address (16 bytes)
            ip_bytes = data[offset:offset + 16]
            offset += 16
            
            # Port
            port = struct.unpack('>H', data[offset:offset + 2])[0]
            offset += 2
            
            # Create CService
            if ip_bytes[:12] == bytes([0] * 10 + [0xFF, 0xFF]):
                addr = CService(m_addr=ip_bytes[12:16], m_net=1, port=port)  # IPv4
            else:
                addr = CService(m_addr=ip_bytes, m_net=2, port=port)  # IPv6
            
            addrs.append((time, addr))
        
        return cls(addrs=addrs)


# ==============================================================================
# AddrV2 Message (BIP155)
# ==============================================================================

@dataclass
class AddrV2Message(P2PMessage):
    """AddrV2 message - BIP155 extended address relay."""
    
    command: ClassVar[str] = NetMsgType.ADDRV2
    
    addrs: List[tuple[int, CService]] = field(default_factory=list)
    
    def serialize(self) -> bytes:
        result = bytearray()
        
        # Count
        result.extend(encode_compact_size(len(self.addrs)))
        
        for time, addr in self.addrs:
            # Time (4 bytes)
            result.extend(struct.pack('<I', time))
            
            # Services (CompactSize)
            result.extend(encode_compact_size(ServiceFlags.NODE_NETWORK))
            
            # Address (BIP155 format)
            result.extend(addr.serialize_v2())
        
        return bytes(result)
    
    @classmethod
    def deserialize(cls, data: bytes) -> AddrV2Message:
        offset = 0
        
        # Count
        count, offset = decode_compact_size(data, offset)
        
        addrs = []
        for _ in range(count):
            # Time (4 bytes)
            time = struct.unpack('<I', data[offset:offset + 4])[0]
            offset += 4
            
            # Services (CompactSize)
            _, offset = decode_compact_size(data, offset)
            
            # Address (BIP155 format)
            addr, consumed = CService.deserialize_v2(data[offset:])
            offset += consumed
            
            addrs.append((time, addr))
        
        return cls(addrs=addrs)


# ==============================================================================
# Inv Message
# ==============================================================================

@dataclass
class InvMessage(P2PMessage):
    """Inv message - inventory broadcast."""
    
    command: ClassVar[str] = NetMsgType.INV
    
    invs: List[CInv] = field(default_factory=list)
    
    def serialize(self) -> bytes:
        result = bytearray()
        
        # Count
        result.extend(encode_compact_size(len(self.invs)))
        
        for inv in self.invs:
            result.extend(inv.to_bytes())
        
        return bytes(result)
    
    @classmethod
    def deserialize(cls, data: bytes) -> InvMessage:
        offset = 0
        
        # Count
        count, offset = decode_compact_size(data, offset)
        
        invs = []
        for _ in range(count):
            inv = CInv.from_bytes(data[offset:offset + 36])
            invs.append(inv)
            offset += 36
        
        return cls(invs=invs)


# ==============================================================================
# GetData Message
# ==============================================================================

@dataclass
class GetDataMessage(P2PMessage):
    """GetData message - request data objects."""
    
    command: ClassVar[str] = NetMsgType.GETDATA
    
    invs: List[CInv] = field(default_factory=list)
    
    def serialize(self) -> bytes:
        result = bytearray()
        result.extend(encode_compact_size(len(self.invs)))
        for inv in self.invs:
            result.extend(inv.to_bytes())
        return bytes(result)
    
    @classmethod
    def deserialize(cls, data: bytes) -> GetDataMessage:
        offset = 0
        count, offset = decode_compact_size(data, offset)
        
        invs = []
        for _ in range(count):
            inv = CInv.from_bytes(data[offset:offset + 36])
            invs.append(inv)
            offset += 36
        
        return cls(invs=invs)


# ==============================================================================
# NotFound Message
# ==============================================================================

@dataclass
class NotFoundMessage(P2PMessage):
    """NotFound message - response when data not available."""
    
    command: ClassVar[str] = NetMsgType.NOTFOUND
    
    invs: List[CInv] = field(default_factory=list)
    
    def serialize(self) -> bytes:
        result = bytearray()
        result.extend(encode_compact_size(len(self.invs)))
        for inv in self.invs:
            result.extend(inv.to_bytes())
        return bytes(result)
    
    @classmethod
    def deserialize(cls, data: bytes) -> NotFoundMessage:
        offset = 0
        count, offset = decode_compact_size(data, offset)
        
        invs = []
        for _ in range(count):
            inv = CInv.from_bytes(data[offset:offset + 36])
            invs.append(inv)
            offset += 36
        
        return cls(invs=invs)


# ==============================================================================
# Ping Message
# ==============================================================================

@dataclass
class PingMessage(P2PMessage):
    """Ping message - keepalive."""
    
    command: ClassVar[str] = NetMsgType.PING
    
    nonce: int = 0
    
    def serialize(self) -> bytes:
        return struct.pack('<Q', self.nonce)
    
    @classmethod
    def deserialize(cls, data: bytes) -> PingMessage:
        nonce = struct.unpack('<Q', data[:8])[0]
        return cls(nonce=nonce)


# ==============================================================================
# Pong Message
# ==============================================================================

@dataclass
class PongMessage(P2PMessage):
    """Pong message - response to ping."""
    
    command: ClassVar[str] = NetMsgType.PONG
    
    nonce: int = 0
    
    def serialize(self) -> bytes:
        return struct.pack('<Q', self.nonce)
    
    @classmethod
    def deserialize(cls, data: bytes) -> PongMessage:
        nonce = struct.unpack('<Q', data[:8])[0]
        return cls(nonce=nonce)


# ==============================================================================
# GetBlocks Message
# ==============================================================================

@dataclass
class GetBlocksMessage(P2PMessage):
    """GetBlocks message - request block inventory."""
    
    command: ClassVar[str] = NetMsgType.GETBLOCKS
    
    locator_hashes: List[bytes] = field(default_factory=list)
    hash_stop: bytes = field(default_factory=lambda: bytes(32))
    
    def serialize(self) -> bytes:
        result = bytearray()
        
        # Version
        result.extend(struct.pack('<I', PROTOCOL_VERSION))
        
        # Locator count
        result.extend(encode_compact_size(len(self.locator_hashes)))
        
        # Locator hashes
        for h in self.locator_hashes:
            result.extend(h)
        
        # Hash stop
        result.extend(self.hash_stop)
        
        return bytes(result)
    
    @classmethod
    def deserialize(cls, data: bytes) -> GetBlocksMessage:
        offset = 0
        
        # Version
        _ = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4
        
        # Locator count
        count, offset = decode_compact_size(data, offset)
        
        # Locator hashes
        locator_hashes = []
        for _ in range(count):
            locator_hashes.append(data[offset:offset + 32])
            offset += 32
        
        # Hash stop
        hash_stop = data[offset:offset + 32]
        
        return cls(locator_hashes=locator_hashes, hash_stop=hash_stop)


# ==============================================================================
# GetHeaders Message
# ==============================================================================

@dataclass
class GetHeadersMessage(P2PMessage):
    """GetHeaders message - request block headers."""
    
    command: ClassVar[str] = NetMsgType.GETHEADERS
    
    locator_hashes: List[bytes] = field(default_factory=list)
    hash_stop: bytes = field(default_factory=lambda: bytes(32))
    
    def serialize(self) -> bytes:
        result = bytearray()
        
        # Version
        result.extend(struct.pack('<I', PROTOCOL_VERSION))
        
        # Locator count
        result.extend(encode_compact_size(len(self.locator_hashes)))
        
        # Locator hashes
        for h in self.locator_hashes:
            result.extend(h)
        
        # Hash stop
        result.extend(self.hash_stop)
        
        return bytes(result)
    
    @classmethod
    def deserialize(cls, data: bytes) -> GetHeadersMessage:
        offset = 0
        
        # Version
        _ = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4
        
        # Locator count
        count, offset = decode_compact_size(data, offset)
        
        # Locator hashes
        locator_hashes = []
        for _ in range(count):
            locator_hashes.append(data[offset:offset + 32])
            offset += 32
        
        # Hash stop
        hash_stop = data[offset:offset + 32]
        
        return cls(locator_hashes=locator_hashes, hash_stop=hash_stop)


# ==============================================================================
# Headers Message
# ==============================================================================

@dataclass
class HeadersMessage(P2PMessage):
    """Headers message - return block headers."""
    
    command: ClassVar[str] = NetMsgType.HEADERS
    
    headers: List[BlockHeader] = field(default_factory=list)
    
    def serialize(self) -> bytes:
        result = bytearray()
        
        # Count
        result.extend(encode_compact_size(len(self.headers)))
        
        for header in self.headers:
            result.extend(header.serialize())
            # Each header is followed by a 0 for tx count
            result.append(0)
        
        return bytes(result)
    
    @classmethod
    def deserialize(cls, data: bytes) -> HeadersMessage:
        offset = 0
        
        # Count
        count, offset = decode_compact_size(data, offset)
        
        headers = []
        for _ in range(count):
            header, consumed = BlockHeader.deserialize(data[offset:])
            offset += consumed
            # Skip tx count (should be 0)
            offset += 1
            headers.append(header)
        
        return cls(headers=headers)


# ==============================================================================
# Block Message
# ==============================================================================

@dataclass
class BlockMessage(P2PMessage):
    """Block message - serialized block."""
    
    command: ClassVar[str] = NetMsgType.BLOCK
    
    block: Optional[Block] = None
    
    def serialize(self) -> bytes:
        if self.block is None:
            return b""
        return self.block.serialize()
    
    @classmethod
    def deserialize(cls, data: bytes) -> BlockMessage:
        block = Block.deserialize(data)
        return cls(block=block)


# ==============================================================================
# Tx Message
# ==============================================================================

@dataclass
class TxMessage(P2PMessage):
    """Tx message - serialized transaction."""
    
    command: ClassVar[str] = NetMsgType.TX
    
    tx: Optional[Transaction] = None
    
    def serialize(self) -> bytes:
        if self.tx is None:
            return b""
        return self.tx.serialize()
    
    @classmethod
    def deserialize(cls, data: bytes) -> TxMessage:
        tx = Transaction.deserialize(data)
        return cls(tx=tx)


# ==============================================================================
# FeeFilter Message (BIP133)
# ==============================================================================

@dataclass
class FeeFilterMessage(P2PMessage):
    """FeeFilter message - announce minimum fee rate."""
    
    command: ClassVar[str] = NetMsgType.FEEFILTER
    
    fee_rate: int = 0  # Satoshis per kilobyte
    
    def serialize(self) -> bytes:
        return struct.pack('<q', self.fee_rate)
    
    @classmethod
    def deserialize(cls, data: bytes) -> FeeFilterMessage:
        fee_rate = struct.unpack('<q', data[:8])[0]
        return cls(fee_rate=fee_rate)


# ==============================================================================
# SendHeaders Message (BIP130)
# ==============================================================================

@dataclass
class SendHeadersMessage(P2PMessage):
    """SendHeaders message - prefer headers announcements."""
    
    command: ClassVar[str] = NetMsgType.SENDHEADERS
    
    def serialize(self) -> bytes:
        return b""
    
    @classmethod
    def deserialize(cls, data: bytes) -> SendHeadersMessage:
        return cls()


# ==============================================================================
# WTXIDRelay Message (BIP339)
# ==============================================================================

@dataclass
class WTXIDRelayMessage(P2PMessage):
    """WTXIDRelay message - use wtxid for transaction relay."""
    
    command: ClassVar[str] = NetMsgType.WTXIDRELAY
    
    def serialize(self) -> bytes:
        return b""
    
    @classmethod
    def deserialize(cls, data: bytes) -> WTXIDRelayMessage:
        return cls()


# ==============================================================================
# SendAddrV2 Message (BIP155)
# ==============================================================================

@dataclass
class SendAddrV2Message(P2PMessage):
    """SendAddrV2 message - signal support for addrv2."""
    
    command: ClassVar[str] = NetMsgType.SENDADDRV2
    
    def serialize(self) -> bytes:
        return b""
    
    @classmethod
    def deserialize(cls, data: bytes) -> SendAddrV2Message:
        return cls()


# ==============================================================================
# Mempool Message (BIP35)
# ==============================================================================

@dataclass
class MempoolMessage(P2PMessage):
    """Mempool message - request mempool contents."""
    
    command: ClassVar[str] = NetMsgType.MEMPOOL
    
    def serialize(self) -> bytes:
        return b""
    
    @classmethod
    def deserialize(cls, data: bytes) -> MempoolMessage:
        return cls()


# ==============================================================================
# GetAddr Message
# ==============================================================================

@dataclass
class GetAddrMessage(P2PMessage):
    """GetAddr message - request peer addresses."""
    
    command: ClassVar[str] = NetMsgType.GETADDR
    
    def serialize(self) -> bytes:
        return b""
    
    @classmethod
    def deserialize(cls, data: bytes) -> GetAddrMessage:
        return cls()


# ==============================================================================
# Message Registry
# ==============================================================================

# Map message types to message classes
MESSAGE_REGISTRY: dict[str, type[P2PMessage]] = {
    NetMsgType.VERSION: VersionMessage,
    NetMsgType.VERACK: VerackMessage,
    NetMsgType.ADDR: AddrMessage,
    NetMsgType.ADDRV2: AddrV2Message,
    NetMsgType.INV: InvMessage,
    NetMsgType.GETDATA: GetDataMessage,
    NetMsgType.NOTFOUND: NotFoundMessage,
    NetMsgType.PING: PingMessage,
    NetMsgType.PONG: PongMessage,
    NetMsgType.GETBLOCKS: GetBlocksMessage,
    NetMsgType.GETHEADERS: GetHeadersMessage,
    NetMsgType.HEADERS: HeadersMessage,
    NetMsgType.BLOCK: BlockMessage,
    NetMsgType.TX: TxMessage,
    NetMsgType.FEEFILTER: FeeFilterMessage,
    NetMsgType.SENDHEADERS: SendHeadersMessage,
    NetMsgType.WTXIDRELAY: WTXIDRelayMessage,
    NetMsgType.SENDADDRV2: SendAddrV2Message,
    NetMsgType.MEMPOOL: MempoolMessage,
    NetMsgType.GETADDR: GetAddrMessage,
}


def deserialize_message(msg_type: str, data: bytes) -> Optional[P2PMessage]:
    """
    Deserialize a message based on its type.
    
    Args:
        msg_type: Message type string
        data: Message payload
        
    Returns:
        Deserialized message or None if unknown type
    """
    msg_class = MESSAGE_REGISTRY.get(msg_type)
    if msg_class is None:
        return None
    
    return msg_class.deserialize(data)
