"""
Bitcoin P2P Transport Layer.

This module implements the V1 and V2 (BIP324) transport protocols for
the Bitcoin P2P network.

Reference: Bitcoin Core src/net.h (V1Transport, V2Transport)
"""

from __future__ import annotations

import asyncio
import os
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Final, Optional, Tuple

from .netaddress import CNetAddr, Network
from .protocol import (
    HEADER_SIZE, MESSAGE_TYPE_SIZE, CHECKSUM_SIZE,
    MAX_PROTOCOL_MESSAGE_LENGTH, NetMsgType, ALL_NET_MESSAGE_TYPES
)
from ..crypto.sha256 import SHA256, double_sha256


# ==============================================================================
# Constants
# ==============================================================================

MAX_SIZE: Final[int] = 0x02000000
"""Maximum size of a message"""

V1_PREFIX_LEN: Final[int] = 16
"""Length of V1 prefix to match for V2 detection"""

MAX_GARBAGE_LEN: Final[int] = 4095
"""Maximum length of garbage in V2 handshake"""


# ==============================================================================
# Transport Protocol Type
# ==============================================================================

class TransportProtocolType:
    """Transport protocol type enumeration."""
    
    DETECTING = "detecting"
    V1 = "v1"
    V2 = "v2"


# ==============================================================================
# Message Types
# ==============================================================================

@dataclass
class CSerializedNetMsg:
    """Serialized network message."""
    
    data: bytes = b""
    m_type: str = ""
    
    def get_memory_usage(self) -> int:
        """Compute total memory usage of this object."""
        return len(self.data) + len(self.m_type) + 32  # Approximate overhead
    
    def copy(self) -> CSerializedNetMsg:
        """Create a copy of this message."""
        return CSerializedNetMsg(data=bytes(self.data), m_type=self.m_type)


@dataclass
class CNetMessage:
    """
    Transport protocol agnostic message container.
    
    Ideally it should only contain receive time, payload,
    type and size.
    """
    
    m_recv: bytes = b""
    m_time: int = 0  # Microseconds since epoch
    m_message_size: int = 0
    m_raw_message_size: int = 0
    m_type: str = ""
    
    def get_memory_usage(self) -> int:
        """Compute total memory usage of this object."""
        return len(self.m_recv) + len(self.m_type) + 32


# ==============================================================================
# Transport Base Class
# ==============================================================================

class Transport(ABC):
    """
    Abstract base class for transport protocols.
    
    The Transport converts one connection's sent messages to wire bytes,
    and received bytes back to CNetMessage objects.
    """
    
    @dataclass
    class Info:
        """Transport information."""
        transport_type: str
        session_id: Optional[bytes] = None
    
    @abstractmethod
    def get_info(self) -> Info:
        """Retrieve information about this transport."""
        pass
    
    # ==========================================================================
    # Receiver Side Functions
    # ==========================================================================
    
    @abstractmethod
    def received_message_complete(self) -> bool:
        """Returns true if the current message is complete."""
        pass
    
    @abstractmethod
    def received_bytes(self, msg_bytes: bytes) -> Tuple[bool, int]:
        """
        Feed wire bytes to the transport.
        
        Args:
            msg_bytes: Raw bytes from the wire
            
        Returns:
            Tuple of (success, bytes_consumed)
            - success: False if some bytes were invalid
            - bytes_consumed: Number of bytes consumed from msg_bytes
        """
        pass
    
    @abstractmethod
    def get_received_message(self, time: int) -> Tuple[CNetMessage, bool]:
        """
        Retrieve a completed message from transport.
        
        Args:
            time: Time of message receipt (microseconds)
            
        Returns:
            Tuple of (message, reject_message)
            - message: The received message
            - reject_message: True if the message is invalid
        """
        pass
    
    # ==========================================================================
    # Sending Side Functions
    # ==========================================================================
    
    @abstractmethod
    def set_message_to_send(self, msg: CSerializedNetMsg) -> bool:
        """
        Set the next message to send.
        
        Args:
            msg: Message to send
            
        Returns:
            True if message was set, False if transport is busy
        """
        pass
    
    @abstractmethod
    def get_bytes_to_send(self, have_next_message: bool) -> Tuple[bytes, bool, str]:
        """
        Get bytes to send on the wire.
        
        Args:
            have_next_message: Whether there's another message ready
            
        Returns:
            Tuple of (to_send, more, m_type)
            - to_send: Bytes to send
            - more: Whether there will be more bytes after these
            - m_type: Message type being sent
        """
        pass
    
    @abstractmethod
    def mark_bytes_sent(self, bytes_sent: int) -> None:
        """
        Report how many bytes have been sent.
        
        Args:
            bytes_sent: Number of bytes sent
        """
        pass
    
    @abstractmethod
    def get_send_memory_usage(self) -> int:
        """Return memory usage of buffered data to send."""
        pass
    
    # ==========================================================================
    # Miscellaneous Functions
    # ==========================================================================
    
    @abstractmethod
    def should_reconnect_v1(self) -> bool:
        """Whether upon disconnection, a reconnect with V1 is warranted."""
        pass


# ==============================================================================
# V1 Transport
# ==============================================================================

class V1Transport(Transport):
    """
    V1 Transport Protocol (unencrypted, plaintext).
    
    Message format:
    - 4 bytes: Message start (magic bytes)
    - 12 bytes: Message type (null-padded)
    - 4 bytes: Payload length (little-endian)
    - 4 bytes: Checksum (first 4 bytes of double SHA256)
    - N bytes: Payload
    """
    
    def __init__(self, magic_bytes: bytes, node_id: int = 0):
        """
        Initialize V1 transport.
        
        Args:
            magic_bytes: 4-byte network magic
            node_id: Node ID for logging
        """
        self._magic_bytes = magic_bytes
        self._node_id = node_id
        
        # Receive state
        self._in_data = False
        self._hdr_pos = 0
        self._data_pos = 0
        self._header = bytearray(HEADER_SIZE)
        self._recv_buffer = bytearray()
        self._message_size = 0
        self._message_type = ""
        self._checksum = bytes(CHECKSUM_SIZE)
        
        # Send state
        self._sending_header = False
        self._bytes_sent = 0
        self._header_to_send = bytearray()
        self._message_to_send: Optional[CSerializedNetMsg] = None
    
    def get_info(self) -> Transport.Info:
        """Get transport information."""
        return Transport.Info(
            transport_type=TransportProtocolType.V1,
            session_id=None
        )
    
    # ==========================================================================
    # Receiver Side
    # ==========================================================================
    
    def received_message_complete(self) -> bool:
        """Check if current message is complete."""
        if not self._in_data:
            return False
        return self._data_pos == self._message_size
    
    def received_bytes(self, msg_bytes: bytes) -> Tuple[bool, int]:
        """
        Process received bytes.
        
        Returns:
            Tuple of (success, bytes_consumed)
        """
        pos = 0
        
        while pos < len(msg_bytes):
            if not self._in_data:
                # Reading header
                remaining = HEADER_SIZE - self._hdr_pos
                to_copy = min(remaining, len(msg_bytes) - pos)
                
                self._header[self._hdr_pos:self._hdr_pos + to_copy] = \
                    msg_bytes[pos:pos + to_copy]
                self._hdr_pos += to_copy
                pos += to_copy
                
                if self._hdr_pos < HEADER_SIZE:
                    # Header not complete yet
                    break
                
                # Parse header
                if not self._parse_header():
                    self._reset()
                    return False, pos
            
            else:
                # Reading data
                remaining = self._message_size - self._data_pos
                to_copy = min(remaining, len(msg_bytes) - pos)
                
                self._recv_buffer.extend(msg_bytes[pos:pos + to_copy])
                self._data_pos += to_copy
                pos += to_copy
                
                if self._data_pos == self._message_size:
                    # Message complete
                    break
        
        return True, pos
    
    def _parse_header(self) -> bool:
        """Parse the message header."""
        # Check magic bytes
        if self._header[:4] != self._magic_bytes:
            return False
        
        # Extract message type
        msg_type_bytes = bytes(self._header[4:4 + MESSAGE_TYPE_SIZE])
        self._message_type = msg_type_bytes.rstrip(b'\x00').decode('ascii', errors='replace')
        
        # Extract message size
        self._message_size = struct.unpack('<I', self._header[20:24])[0]
        
        # Validate message size
        if self._message_size > MAX_SIZE or self._message_size > MAX_PROTOCOL_MESSAGE_LENGTH:
            return False
        
        # Extract checksum
        self._checksum = bytes(self._header[24:28])
        
        # Switch to data state
        self._in_data = True
        self._data_pos = 0
        self._recv_buffer = bytearray()
        
        return True
    
    def get_received_message(self, time: int) -> Tuple[CNetMessage, bool]:
        """
        Get the received message.
        
        Returns:
            Tuple of (message, reject_message)
        """
        # Compute checksum
        computed_hash = double_sha256(bytes(self._recv_buffer))
        computed_checksum = computed_hash[:CHECKSUM_SIZE]
        
        # Verify checksum
        reject = False
        if computed_checksum != self._checksum:
            reject = True
        
        # Verify message type
        if self._message_type.rstrip('\x00') not in ALL_NET_MESSAGE_TYPES:
            # Allow unknown types but flag them
            pass
        
        # Create message
        msg = CNetMessage(
            m_recv=bytes(self._recv_buffer),
            m_time=time,
            m_message_size=self._message_size,
            m_raw_message_size=self._message_size + HEADER_SIZE,
            m_type=self._message_type
        )
        
        # Reset for next message
        self._reset()
        
        return msg, reject
    
    def _reset(self) -> None:
        """Reset receive state."""
        self._in_data = False
        self._hdr_pos = 0
        self._data_pos = 0
        self._header = bytearray(HEADER_SIZE)
        self._recv_buffer = bytearray()
        self._message_size = 0
        self._message_type = ""
        self._checksum = bytes(CHECKSUM_SIZE)
    
    # ==========================================================================
    # Sending Side
    # ==========================================================================
    
    def set_message_to_send(self, msg: CSerializedNetMsg) -> bool:
        """Set message to send."""
        if self._message_to_send is not None:
            if self._bytes_sent < len(self._message_to_send.data):
                return False
        
        # Create header
        checksum = double_sha256(msg.data)[:CHECKSUM_SIZE]
        
        self._header_to_send = bytearray()
        self._header_to_send.extend(self._magic_bytes)
        
        # Pad message type
        msg_type_bytes = msg.m_type.encode('ascii')[:MESSAGE_TYPE_SIZE]
        msg_type_bytes = msg_type_bytes.ljust(MESSAGE_TYPE_SIZE, b'\x00')
        self._header_to_send.extend(msg_type_bytes)
        
        # Message size
        self._header_to_send.extend(struct.pack('<I', len(msg.data)))
        
        # Checksum
        self._header_to_send.extend(checksum)
        
        self._message_to_send = msg
        self._sending_header = True
        self._bytes_sent = 0
        
        return True
    
    def get_bytes_to_send(self, have_next_message: bool) -> Tuple[bytes, bool, str]:
        """Get bytes to send."""
        if self._message_to_send is None:
            return b"", False, ""
        
        msg_type = self._message_to_send.m_type
        
        if self._sending_header:
            remaining = bytes(self._header_to_send)[self._bytes_sent:]
            more = have_next_message or len(self._message_to_send.data) > 0
            return remaining, more, msg_type
        else:
            remaining = self._message_to_send.data[self._bytes_sent:]
            return remaining, have_next_message, msg_type
    
    def mark_bytes_sent(self, bytes_sent: int) -> None:
        """Mark bytes as sent."""
        self._bytes_sent += bytes_sent
        
        if self._sending_header:
            if self._bytes_sent >= len(self._header_to_send):
                self._sending_header = False
                self._bytes_sent = 0
        else:
            if self._message_to_send and self._bytes_sent >= len(self._message_to_send.data):
                self._message_to_send = None
                self._bytes_sent = 0
    
    def get_send_memory_usage(self) -> int:
        """Get send buffer memory usage."""
        if self._message_to_send is None:
            return 0
        return self._message_to_send.get_memory_usage()
    
    def should_reconnect_v1(self) -> bool:
        """V1 never reconnects as V1."""
        return False


# ==============================================================================
# V2 Transport (BIP324)
# ==============================================================================

class V2Transport(Transport):
    """
    V2 Transport Protocol (BIP324 encrypted).
    
    This implements the BIP324 protocol for encrypted P2P communication.
    """
    
    # V2 message IDs for short message types
    V2_MESSAGE_IDS = [
        "",  # 0: 12 bytes follow encoding the message type like in V1
        NetMsgType.ADD,
        NetMsgType.BLOCK,
        NetMsgType.BLOCKTXN,
        NetMsgType.CMPCTBLOCK,
        NetMsgType.FEEFILTER,
        NetMsgType.FILTERADD,
        NetMsgType.FILTERCLEAR,
        NetMsgType.FILTERLOAD,
        NetMsgType.GETBLOCKS,
        NetMsgType.GETBLOCKTXN,
        NetMsgType.GETDATA,
        NetMsgType.GETHEADERS,
        NetMsgType.HEADERS,
        NetMsgType.INV,
        NetMsgType.MEMPOOL,
        NetMsgType.MERKLEBLOCK,
        NetMsgType.NOTFOUND,
        NetMsgType.PING,
        NetMsgType.PONG,
        NetMsgType.SENDCMPCT,
        NetMsgType.TX,
        NetMsgType.GETCFILTERS,
        NetMsgType.CFILTER,
        NetMsgType.GETCFHEADERS,
        NetMsgType.CFHEADERS,
        NetMsgType.GETCFCHECKPT,
        NetMsgType.CFCHECKPT,
        NetMsgType.ADDRV2,
        "",  # 30: Reserved
        "",  # 31: Reserved
        "",  # 32: Reserved
        "",  # 33: Reserved
    ]
    
    # Receive states
    class RecvState:
        KEY_MAYBE_V1 = "key_maybe_v1"
        KEY = "key"
        GARB_GARBTERM = "garb_garbterm"
        VERSION = "version"
        APP = "app"
        APP_READY = "app_ready"
        V1 = "v1"
    
    # Send states
    class SendState:
        MAYBE_V1 = "maybe_v1"
        AWAITING_KEY = "awaiting_key"
        READY = "ready"
        V1 = "v1"
    
    def __init__(
        self,
        magic_bytes: bytes,
        node_id: int = 0,
        initiating: bool = True
    ):
        """
        Initialize V2 transport.
        
        Args:
            magic_bytes: Network magic bytes
            node_id: Node ID for logging
            initiating: Whether we are the initiator
        """
        self._magic_bytes = magic_bytes
        self._node_id = node_id
        self._initiating = initiating
        
        # Cipher (placeholder - would use BIP324 cipher in production)
        self._cipher = None
        self._session_id: Optional[bytes] = None
        
        # Receive state
        self._recv_state = self.RecvState.KEY_MAYBE_V1 if not initiating else self.RecvState.KEY
        self._recv_buffer = bytearray()
        self._recv_len = 0
        self._recv_aad = bytearray()
        self._recv_decode_buffer = bytearray()
        
        # Send state
        self._send_state = self.SendState.MAYBE_V1 if not initiating else self.SendState.AWAITING_KEY
        self._send_buffer = bytearray()
        self._send_pos = 0
        self._send_garbage = bytearray()
        self._send_type = ""
        self._sent_v1_header_worth = False
        
        # V1 fallback
        self._v1_fallback = V1Transport(magic_bytes, node_id)
        
        # Generate keys (placeholder)
        self._our_pubkey = os.urandom(64)  # EllSwift public key
        self._their_pubkey: Optional[bytes] = None
        
        # Initialize handshake if initiator
        if initiating:
            self._start_sending_handshake()
    
    def _start_sending_handshake(self) -> None:
        """Start the V2 handshake as initiator."""
        self._send_buffer = bytearray()
        self._send_buffer.extend(self._our_pubkey)
        # Add garbage (0 to MAX_GARBAGE_LEN bytes)
        garbage_len = os.urandom(1)[0] % (MAX_GARBAGE_LEN + 1)
        self._send_garbage = bytearray(os.urandom(garbage_len))
        self._send_buffer.extend(self._send_garbage)
        self._send_state = self.SendState.AWAITING_KEY
    
    def get_info(self) -> Transport.Info:
        """Get transport information."""
        return Transport.Info(
            transport_type=TransportProtocolType.V2,
            session_id=self._session_id
        )
    
    # ==========================================================================
    # Receiver Side
    # ==========================================================================
    
    def received_message_complete(self) -> bool:
        """Check if message is complete."""
        if self._recv_state == self.RecvState.V1:
            return self._v1_fallback.received_message_complete()
        
        return self._recv_state == self.RecvState.APP_READY
    
    def received_bytes(self, msg_bytes: bytes) -> Tuple[bool, int]:
        """Process received bytes."""
        # For now, fall back to V1 behavior
        # Full V2 implementation would require BIP324 cipher
        if self._recv_state == self.RecvState.V1:
            return self._v1_fallback.received_bytes(msg_bytes)
        
        # Check for V1 prefix detection
        if self._recv_state == self.RecvState.KEY_MAYBE_V1:
            if len(msg_bytes) >= V1_PREFIX_LEN:
                # Check if it looks like V1
                if msg_bytes[:4] == self._magic_bytes:
                    self._recv_state = self.RecvState.V1
                    return self._v1_fallback.received_bytes(msg_bytes)
                else:
                    self._recv_state = self.RecvState.KEY
        
        # Buffer the bytes
        self._recv_buffer.extend(msg_bytes)
        
        # Placeholder: mark all bytes as consumed
        return True, len(msg_bytes)
    
    def get_received_message(self, time: int) -> Tuple[CNetMessage, bool]:
        """Get received message."""
        if self._recv_state == self.RecvState.V1:
            return self._v1_fallback.get_received_message(time)
        
        # Placeholder: return empty message
        msg = CNetMessage(
            m_recv=bytes(self._recv_buffer),
            m_time=time,
            m_message_size=len(self._recv_buffer),
            m_raw_message_size=len(self._recv_buffer),
            m_type=""
        )
        self._recv_buffer = bytearray()
        self._recv_state = self.RecvState.APP
        
        return msg, False
    
    # ==========================================================================
    # Sending Side
    # ==========================================================================
    
    def set_message_to_send(self, msg: CSerializedNetMsg) -> bool:
        """Set message to send."""
        if self._send_state == self.SendState.V1:
            return self._v1_fallback.set_message_to_send(msg)
        
        # Placeholder
        return False
    
    def get_bytes_to_send(self, have_next_message: bool) -> Tuple[bytes, bool, str]:
        """Get bytes to send."""
        if self._send_state == self.SendState.V1:
            return self._v1_fallback.get_bytes_to_send(have_next_message)
        
        if self._send_state == self.SendState.AWAITING_KEY:
            remaining = bytes(self._send_buffer)[self._send_pos:]
            return remaining, True, ""
        
        return b"", False, ""
    
    def mark_bytes_sent(self, bytes_sent: int) -> None:
        """Mark bytes as sent."""
        if self._send_state == self.SendState.V1:
            self._v1_fallback.mark_bytes_sent(bytes_sent)
            return
        
        self._send_pos += bytes_sent
    
    def get_send_memory_usage(self) -> int:
        """Get send buffer memory usage."""
        if self._send_state == self.SendState.V1:
            return self._v1_fallback.get_send_memory_usage()
        
        return len(self._send_buffer) + len(self._send_garbage)
    
    def should_reconnect_v1(self) -> bool:
        """Check if should reconnect as V1."""
        # V2 may reconnect as V1 in certain error conditions
        return False


# ==============================================================================
# V2 Message Type Mapping
# ==============================================================================

# Build reverse mapping from message type to short ID
V2_MESSAGE_MAP: dict[str, int] = {}
for idx, msg_type in enumerate(V2Transport.V2_MESSAGE_IDS):
    if msg_type:
        V2_MESSAGE_MAP[msg_type] = idx


def get_v2_short_id(msg_type: str) -> Optional[int]:
    """Get the short ID for a message type in V2 protocol."""
    return V2_MESSAGE_MAP.get(msg_type)


def get_v2_message_type(short_id: int) -> Optional[str]:
    """Get the message type for a short ID in V2 protocol."""
    if 0 <= short_id < len(V2Transport.V2_MESSAGE_IDS):
        return V2Transport.V2_MESSAGE_IDS[short_id]
    return None
