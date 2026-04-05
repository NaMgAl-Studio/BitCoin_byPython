"""
Bitcoin Network Address Implementation.

This module implements network address types for the Bitcoin P2P protocol.
Supports IPv4, IPv6, Tor (ONION), I2P, CJDNS, and internal addresses.

Reference: Bitcoin Core src/netaddress.h, src/netaddress.cpp
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Final, Optional

from ..crypto.sha256 import SHA256
from ..crypto.sha3 import SHA3_256


# ==============================================================================
# Address Size Constants
# ==============================================================================

ADDR_IPV4_SIZE: Final[int] = 4
"""Size of IPv4 address (in bytes)"""

ADDR_IPV6_SIZE: Final[int] = 16
"""Size of IPv6 address (in bytes)"""

ADDR_TORV3_SIZE: Final[int] = 32
"""Size of TORv3 address (in bytes)"""

ADDR_I2P_SIZE: Final[int] = 32
"""Size of I2P address (in bytes)"""

ADDR_CJDNS_SIZE: Final[int] = 16
"""Size of CJDNS address (in bytes)"""

ADDR_INTERNAL_SIZE: Final[int] = 10
"""Size of "internal" (NET_INTERNAL) address (in bytes)"""

V1_SERIALIZATION_SIZE: Final[int] = ADDR_IPV6_SIZE
"""Size of CNetAddr when serialized as ADDRv1 (pre-BIP155)"""

MAX_ADDRV2_SIZE: Final[int] = 512
"""Maximum size of an address as defined in BIP155"""


# ==============================================================================
# IPv6 Prefix Constants
# ==============================================================================

# Prefix of an IPv6 address when it contains an embedded IPv4 address
IPV4_IN_IPV6_PREFIX: Final[bytes] = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                            0x00, 0x00, 0xFF, 0xFF])

# Prefix of an IPv6 address when it contains an embedded TORv2 address (deprecated)
TORV2_IN_IPV6_PREFIX: Final[bytes] = bytes([0xFD, 0x87, 0xD8, 0x7E, 0xEB, 0x43])

# Prefix of an IPv6 address when it contains an embedded "internal" address
# 0xFD + SHA256("bitcoin")[0:5]
INTERNAL_IN_IPV6_PREFIX: Final[bytes] = bytes([0xFD, 0x6B, 0x88, 0xC0, 0x87, 0x24])

# CJDNS addresses start with 0xFC
CJDNS_PREFIX: Final[int] = 0xFC

# I2P SAM 3.1 and earlier do not support specifying ports
I2P_SAM31_PORT: Final[int] = 0


# ==============================================================================
# Network Type Enum
# ==============================================================================

class Network(IntEnum):
    """
    A network type.
    
    Note: An address may belong to more than one network, for example 10.0.0.1
    belongs to both NET_UNROUTABLE and NET_IPV4.
    """
    
    NET_UNROUTABLE = 0
    """Addresses from these networks are not publicly routable on the global Internet."""
    
    NET_IPV4 = 1
    """IPv4"""
    
    NET_IPV6 = 2
    """IPv6"""
    
    NET_ONION = 3
    """TOR (v2 or v3)"""
    
    NET_I2P = 4
    """I2P"""
    
    NET_CJDNS = 5
    """CJDNS"""
    
    NET_INTERNAL = 6
    """
    A set of addresses that represent the hash of a string or FQDN.
    We use them in AddrMan to keep track of which DNS seeds were used.
    """
    
    NET_MAX = 7
    """Dummy value to indicate the number of NET_* constants."""


# ==============================================================================
# BIP155 Network IDs
# ==============================================================================

class BIP155Network(IntEnum):
    """BIP155 network ids recognized by this software."""
    
    IPV4 = 1
    IPV6 = 2
    TORV2 = 3  # Deprecated, no longer supported
    TORV3 = 4
    I2P = 5
    CJDNS = 6


# ==============================================================================
# CNetAddr Class
# ==============================================================================

@dataclass
class CNetAddr:
    """
    Network address.
    
    This class represents a network address that can be IPv4, IPv6, Tor, I2P,
    CJDNS, or an internal address.
    """
    
    # Raw representation of the network address (network byte order)
    m_addr: bytes = field(default_factory=lambda: bytes(ADDR_IPV6_SIZE))
    
    # Network to which this address belongs
    m_net: Network = Network.NET_IPV6
    
    # Scope id if scoped/link-local IPV6 address
    m_scope_id: int = 0
    
    def __post_init__(self):
        """Validate address size after initialization."""
        if len(self.m_addr) == 0:
            self.m_addr = bytes(ADDR_IPV6_SIZE)
    
    def set_ip(self, ip: CNetAddr) -> None:
        """Set IP address from another CNetAddr."""
        self.m_net = ip.m_net
        self.m_addr = ip.m_addr
        self.m_scope_id = ip.m_scope_id
    
    def set_legacy_ipv6(self, ipv6: bytes) -> None:
        """
        Set from a legacy IPv6 address.
        
        Legacy IPv6 address may be a normal IPv6 address, or another address
        (e.g. IPv4) disguised as IPv6. This encoding is used in the legacy
        `addr` encoding.
        """
        if len(ipv6) != ADDR_IPV6_SIZE:
            raise ValueError(f"Invalid IPv6 address size: {len(ipv6)}")
        
        if ipv6.startswith(IPV4_IN_IPV6_PREFIX):
            # IPv4-in-IPv6
            self.m_net = Network.NET_IPV4
            self.m_addr = ipv6[12:16]
        elif ipv6.startswith(TORV2_IN_IPV6_PREFIX):
            # TORv2-in-IPv6 (unsupported)
            self.m_net = Network.NET_IPV6
            self.m_addr = bytes(ADDR_IPV6_SIZE)
        elif ipv6.startswith(INTERNAL_IN_IPV6_PREFIX):
            # Internal-in-IPv6
            self.m_net = Network.NET_INTERNAL
            self.m_addr = ipv6[6:16]
        else:
            # IPv6
            self.m_net = Network.NET_IPV6
            self.m_addr = ipv6
    
    def set_internal(self, name: str) -> bool:
        """
        Create an "internal" address that represents a name or FQDN.
        
        AddrMan uses these fake addresses to keep track of which DNS seeds were used.
        
        Args:
            name: The name to create an internal address for
            
        Returns:
            True if successful
        """
        if not name:
            return False
        
        self.m_net = Network.NET_INTERNAL
        # Hash the name using SHA256 and take first 10 bytes
        hash_result = SHA256(name.encode()).digest()
        self.m_addr = hash_result[:ADDR_INTERNAL_SIZE]
        return True
    
    def set_special(self, addr: str) -> bool:
        """
        Parse a Tor or I2P address and set this object to it.
        
        Args:
            addr: Address to parse (e.g., xxx.onion or xxx.b32.i2p)
            
        Returns:
            Whether the operation was successful
        """
        if '\x00' in addr:
            return False
        
        if self._set_tor(addr):
            return True
        
        if self._set_i2p(addr):
            return True
        
        return False
    
    def _set_tor(self, addr: str) -> bool:
        """Parse and set a Tor address."""
        if not addr.endswith('.onion'):
            return False
        
        addr = addr[:-6]  # Remove .onion suffix
        
        # Decode base32
        try:
            import base64
            # Add padding if needed
            padding = (8 - len(addr) % 8) % 8
            addr_padded = addr + '=' * padding
            decoded = base64.b32decode(addr_padded.upper())
        except Exception:
            return False
        
        # TORv3: 32 bytes pubkey + 2 bytes checksum + 1 byte version = 35 bytes
        if len(decoded) == ADDR_TORV3_SIZE + 2 + 1:
            pubkey = decoded[:ADDR_TORV3_SIZE]
            checksum = decoded[ADDR_TORV3_SIZE:ADDR_TORV3_SIZE + 2]
            version = decoded[ADDR_TORV3_SIZE + 2]
            
            if version != 3:
                return False
            
            # Verify checksum
            # TORv3 CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[:2]
            checksum_data = b".onion checksum" + pubkey + bytes([version])
            calculated = SHA3_256(checksum_data).digest()[:2]
            
            if checksum != calculated:
                return False
            
            self.m_net = Network.NET_ONION
            self.m_addr = pubkey
            return True
        
        return False
    
    def _set_i2p(self, addr: str) -> bool:
        """Parse and set an I2P address."""
        # I2P addresses: 52 base32 characters + ".b32.i2p"
        if not addr.endswith('.b32.i2p'):
            return False
        
        addr = addr[:-8]  # Remove .b32.i2p suffix
        if len(addr) != 52:
            return False
        
        try:
            import base64
            # Add padding
            addr_padded = addr + '===='
            decoded = base64.b32decode(addr_padded.upper())
        except Exception:
            return False
        
        if len(decoded) != ADDR_I2P_SIZE:
            return False
        
        self.m_net = Network.NET_I2P
        self.m_addr = decoded
        return True
    
    # ==========================================================================
    # Network Type Checks
    # ==========================================================================
    
    def is_ipv4(self) -> bool:
        """Check if this is an IPv4 address."""
        return self.m_net == Network.NET_IPV4
    
    def is_ipv6(self) -> bool:
        """Check if this is an IPv6 address."""
        return self.m_net == Network.NET_IPV6
    
    def is_tor(self) -> bool:
        """Check if this is a Tor address."""
        return self.m_net == Network.NET_ONION
    
    def is_i2p(self) -> bool:
        """Check if this is an I2P address."""
        return self.m_net == Network.NET_I2P
    
    def is_cjdns(self) -> bool:
        """Check if this is a CJDNS address."""
        return self.m_net == Network.NET_CJDNS
    
    def has_cjdns_prefix(self) -> bool:
        """Check if the address has the CJDNS prefix."""
        return len(self.m_addr) > 0 and self.m_addr[0] == CJDNS_PREFIX
    
    def is_internal(self) -> bool:
        """Check if this is an internal address."""
        return self.m_net == Network.NET_INTERNAL
    
    def is_privacy_net(self) -> bool:
        """Check if this is a privacy network."""
        return self.is_tor() or self.is_i2p()
    
    # ==========================================================================
    # RFC Checks
    # ==========================================================================
    
    def is_rfc1918(self) -> bool:
        """IPv4 private networks (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12)"""
        return (self.is_ipv4() and
                (self.m_addr[0] == 10 or
                 (self.m_addr[0] == 192 and self.m_addr[1] == 168) or
                 (self.m_addr[0] == 172 and 16 <= self.m_addr[1] <= 31)))
    
    def is_rfc2544(self) -> bool:
        """IPv4 inter-network communications (198.18.0.0/15)"""
        return self.is_ipv4() and self.m_addr[0] == 198 and self.m_addr[1] in (18, 19)
    
    def is_rfc3927(self) -> bool:
        """IPv4 autoconfig (169.254.0.0/16)"""
        return self.is_ipv4() and self.m_addr[0] == 169 and self.m_addr[1] == 254
    
    def is_rfc6598(self) -> bool:
        """IPv4 ISP-level NAT (100.64.0.0/10)"""
        return (self.is_ipv4() and
                self.m_addr[0] == 100 and 64 <= self.m_addr[1] <= 127)
    
    def is_rfc5737(self) -> bool:
        """IPv4 documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)"""
        return (self.is_ipv4() and
                (self.m_addr[:3] == bytes([192, 0, 2]) or
                 self.m_addr[:3] == bytes([198, 51, 100]) or
                 self.m_addr[:3] == bytes([203, 0, 113])))
    
    def is_rfc3849(self) -> bool:
        """IPv6 documentation address (2001:0DB8::/32)"""
        return self.is_ipv6() and self.m_addr[:4] == bytes([0x20, 0x01, 0x0D, 0xB8])
    
    def is_rfc3964(self) -> bool:
        """IPv6 6to4 tunnelling (2002::/16)"""
        return self.is_ipv6() and self.m_addr[:2] == bytes([0x20, 0x02])
    
    def is_rfc4193(self) -> bool:
        """IPv6 unique local (FC00::/7)"""
        return self.is_ipv6() and (self.m_addr[0] & 0xFE) == 0xFC
    
    def is_rfc4380(self) -> bool:
        """IPv6 Teredo tunnelling (2001::/32)"""
        return self.is_ipv6() and self.m_addr[:4] == bytes([0x20, 0x01, 0x00, 0x00])
    
    def is_rfc4843(self) -> bool:
        """IPv6 ORCHID (deprecated) (2001:10::/28)"""
        return (self.is_ipv6() and
                self.m_addr[:3] == bytes([0x20, 0x01, 0x00]) and
                (self.m_addr[3] & 0xF0) == 0x10)
    
    def is_rfc7343(self) -> bool:
        """IPv6 ORCHIDv2 (2001:20::/28)"""
        return (self.is_ipv6() and
                self.m_addr[:3] == bytes([0x20, 0x01, 0x00]) and
                (self.m_addr[3] & 0xF0) == 0x20)
    
    def is_rfc4862(self) -> bool:
        """IPv6 autoconfig (FE80::/64)"""
        return self.is_ipv6() and self.m_addr[:8] == bytes([0xFE, 0x80] + [0] * 6)
    
    def is_rfc6052(self) -> bool:
        """IPv6 well-known prefix for IPv4-embedded address (64:FF9B::/96)"""
        return (self.is_ipv6() and
                self.m_addr[:12] == bytes([0x00, 0x64, 0xFF, 0x9B] + [0] * 8))
    
    def is_rfc6145(self) -> bool:
        """IPv6 IPv4-translated address (::FFFF:0:0:0/96)"""
        return (self.is_ipv6() and
                self.m_addr[:12] == bytes([0] * 10 + [0xFF, 0xFF]))
    
    def is_he_net(self) -> bool:
        """IPv6 Hurricane Electric - https://he.net (2001:0470::/36)"""
        return self.is_ipv6() and self.m_addr[:4] == bytes([0x20, 0x01, 0x04, 0x70])
    
    def is_local(self) -> bool:
        """Check if this is a local address."""
        # IPv4 loopback (127.0.0.0/8 or 0.0.0.0/8)
        if self.is_ipv4() and self.m_addr[0] in (127, 0):
            return True
        
        # IPv6 loopback (::1/128)
        if self.is_ipv6() and self.m_addr == bytes([0] * 15 + [1]):
            return True
        
        return False
    
    def is_routable(self) -> bool:
        """Check if this is a publicly routable address."""
        return (self.is_valid() and
                not (self.is_rfc1918() or self.is_rfc2544() or self.is_rfc3927() or
                     self.is_rfc4862() or self.is_rfc6598() or self.is_rfc5737() or
                     self.is_rfc4193() or self.is_rfc4843() or self.is_rfc7343() or
                     self.is_local() or self.is_internal()))
    
    def is_valid(self) -> bool:
        """
        Check if this is a valid address that could be used to refer to an actual host.
        
        Note: A valid address may or may not be publicly routable on the global internet.
        """
        # Unspecified IPv6 address (::/128)
        if self.is_ipv6() and self.m_addr == bytes(ADDR_IPV6_SIZE):
            return False
        
        if self.is_cjdns() and not self.has_cjdns_prefix():
            return False
        
        # Documentation IPv6 address
        if self.is_rfc3849():
            return False
        
        if self.is_internal():
            return False
        
        if self.is_ipv4():
            addr = struct.unpack('>I', self.m_addr)[0]
            if addr == 0 or addr == 0xFFFFFFFF:
                return False
        
        return True
    
    def is_bind_any(self) -> bool:
        """Check if this is INADDR_ANY equivalent."""
        if not self.is_ipv4() and not self.is_ipv6():
            return False
        return all(b == 0 for b in self.m_addr)
    
    def is_addr_v1_compatible(self) -> bool:
        """Check if the current object can be serialized in pre-ADDRv2/BIP155 format."""
        return self.m_net in (Network.NET_IPV4, Network.NET_IPV6, Network.NET_INTERNAL)
    
    def is_relayable(self) -> bool:
        """
        Whether this address should be relayed to other peers even if we can't
        reach it ourselves.
        """
        return (self.is_ipv4() or self.is_ipv6() or
                self.is_tor() or self.is_i2p() or self.is_cjdns())
    
    # ==========================================================================
    # Address Operations
    # ==========================================================================
    
    def get_network(self) -> Network:
        """Get the network type of this address."""
        if self.is_internal():
            return Network.NET_INTERNAL
        
        if not self.is_routable():
            return Network.NET_UNROUTABLE
        
        return self.m_net
    
    def get_net_class(self) -> Network:
        """Get the network class for grouping purposes."""
        if self.is_internal():
            return Network.NET_INTERNAL
        
        if not self.is_routable():
            return Network.NET_UNROUTABLE
        
        if self.has_linked_ipv4():
            return Network.NET_IPV4
        
        return self.m_net
    
    def get_addr_bytes(self) -> bytes:
        """Get the raw address bytes."""
        if self.is_addr_v1_compatible():
            return self._serialize_v1_array()
        return self.m_addr
    
    def _serialize_v1_array(self) -> bytes:
        """Serialize in pre-ADDRv2/BIP155 format to an array."""
        result = bytearray(ADDR_IPV6_SIZE)
        
        if self.m_net == Network.NET_IPV6:
            result[:] = self.m_addr
        elif self.m_net == Network.NET_IPV4:
            result[:12] = IPV4_IN_IPV6_PREFIX
            result[12:16] = self.m_addr
        elif self.m_net == Network.NET_INTERNAL:
            result[:6] = INTERNAL_IN_IPV6_PREFIX
            result[6:16] = self.m_addr
        else:
            # ONION, I2P, CJDNS serialize as all-zeros
            pass
        
        return bytes(result)
    
    def has_linked_ipv4(self) -> bool:
        """Check if this address has a linked IPv4 address."""
        return (self.is_routable() and
                (self.is_ipv4() or self.is_rfc6145() or
                 self.is_rfc6052() or self.is_rfc3964() or self.is_rfc4380()))
    
    def get_linked_ipv4(self) -> Optional[int]:
        """Get the linked IPv4 address if available."""
        if self.is_ipv4():
            return struct.unpack('>I', self.m_addr)[0]
        elif self.is_rfc6052() or self.is_rfc6145():
            # Last 4 bytes
            return struct.unpack('>I', self.m_addr[12:16])[0]
        elif self.is_rfc3964():
            # Bytes 2-6
            return struct.unpack('>I', self.m_addr[2:6])[0]
        elif self.is_rfc4380():
            # Last 4 bytes, bitflipped
            return ~struct.unpack('>I', self.m_addr[12:16])[0] & 0xFFFFFFFF
        return None
    
    def get_bip155_network(self) -> BIP155Network:
        """Get the BIP155 network id of this address."""
        if self.m_net == Network.NET_IPV4:
            return BIP155Network.IPV4
        elif self.m_net == Network.NET_IPV6:
            return BIP155Network.IPV6
        elif self.m_net == Network.NET_ONION:
            return BIP155Network.TORV3
        elif self.m_net == Network.NET_I2P:
            return BIP155Network.I2P
        elif self.m_net == Network.NET_CJDNS:
            return BIP155Network.CJDNS
        else:
            raise ValueError(f"Invalid network for BIP155: {self.m_net}")
    
    def set_net_from_bip155_network(self, bip155_net: int, address_size: int) -> bool:
        """
        Set m_net from the provided BIP155 network id and size after validation.
        
        Returns True if the network was recognized and valid.
        Raises ValueError for wrong address sizes for known networks.
        """
        if bip155_net == BIP155Network.IPV4:
            if address_size != ADDR_IPV4_SIZE:
                raise ValueError(f"BIP155 IPv4 address with length {address_size}")
            self.m_net = Network.NET_IPV4
            return True
        elif bip155_net == BIP155Network.IPV6:
            if address_size != ADDR_IPV6_SIZE:
                raise ValueError(f"BIP155 IPv6 address with length {address_size}")
            self.m_net = Network.NET_IPV6
            return True
        elif bip155_net == BIP155Network.TORV3:
            if address_size != ADDR_TORV3_SIZE:
                raise ValueError(f"BIP155 TORv3 address with length {address_size}")
            self.m_net = Network.NET_ONION
            return True
        elif bip155_net == BIP155Network.I2P:
            if address_size != ADDR_I2P_SIZE:
                raise ValueError(f"BIP155 I2P address with length {address_size}")
            self.m_net = Network.NET_I2P
            return True
        elif bip155_net == BIP155Network.CJDNS:
            if address_size != ADDR_CJDNS_SIZE:
                raise ValueError(f"BIP155 CJDNS address with length {address_size}")
            self.m_net = Network.NET_CJDNS
            return True
        
        # Unknown network - silently ignore
        return False
    
    # ==========================================================================
    # Serialization
    # ==========================================================================
    
    def serialize_v1(self) -> bytes:
        """Serialize in V1 (pre-BIP155) format."""
        return self._serialize_v1_array()
    
    def serialize_v2(self) -> bytes:
        """Serialize in V2 (BIP155) format."""
        result = bytearray()
        
        if self.is_internal():
            # Serialize NET_INTERNAL as embedded in IPv6
            result.append(BIP155Network.IPV6)
            result.extend(_encode_compact_size(ADDR_IPV6_SIZE))
            result.extend(self._serialize_v1_array())
            return bytes(result)
        
        result.append(self.get_bip155_network())
        result.extend(_encode_compact_size(len(self.m_addr)))
        result.extend(self.m_addr)
        
        return bytes(result)
    
    @classmethod
    def deserialize_v1(cls, data: bytes) -> tuple[CNetAddr, int]:
        """
        Deserialize from V1 format.
        
        Returns:
            Tuple of (CNetAddr, bytes_consumed)
        """
        if len(data) < ADDR_IPV6_SIZE:
            raise ValueError(f"Data too short for V1 address: {len(data)}")
        
        addr = cls()
        addr.set_legacy_ipv6(data[:ADDR_IPV6_SIZE])
        return addr, ADDR_IPV6_SIZE
    
    @classmethod
    def deserialize_v2(cls, data: bytes) -> tuple[CNetAddr, int]:
        """
        Deserialize from V2 (BIP155) format.
        
        Returns:
            Tuple of (CNetAddr, bytes_consumed)
        """
        if len(data) < 1:
            raise ValueError("Data too short for V2 address")
        
        pos = 0
        bip155_net = data[pos]
        pos += 1
        
        # Read compact size
        addr_size, consumed = _decode_compact_size(data[pos:])
        pos += consumed
        
        if addr_size > MAX_ADDRV2_SIZE:
            raise ValueError(f"Address too long: {addr_size} > {MAX_ADDRV2_SIZE}")
        
        if len(data) < pos + addr_size:
            raise ValueError(f"Data too short for address: {len(data)} < {pos + addr_size}")
        
        addr = cls()
        addr.m_scope_id = 0
        
        if addr.set_net_from_bip155_network(bip155_net, addr_size):
            addr.m_addr = data[pos:pos + addr_size]
            pos += addr_size
            
            # Handle internal addresses embedded in IPv6
            if addr.m_net == Network.NET_IPV6:
                if addr.m_addr.startswith(INTERNAL_IN_IPV6_PREFIX):
                    addr.m_net = Network.NET_INTERNAL
                    addr.m_addr = addr.m_addr[6:16]
                elif addr.m_addr.startswith(IPV4_IN_IPV6_PREFIX):
                    # Ignore embedded IPv4 in V2
                    addr.m_net = Network.NET_IPV6
                    addr.m_addr = bytes(ADDR_IPV6_SIZE)
        else:
            # Unknown network - skip bytes and return invalid address
            pos += addr_size
            addr.m_net = Network.NET_IPV6
            addr.m_addr = bytes(ADDR_IPV6_SIZE)
        
        return addr, pos
    
    # ==========================================================================
    # String Conversion
    # ==========================================================================
    
    def to_string_addr(self) -> str:
        """Convert address to string representation."""
        if self.m_net == Network.NET_IPV4:
            return f"{self.m_addr[0]}.{self.m_addr[1]}.{self.m_addr[2]}.{self.m_addr[3]}"
        
        elif self.m_net == Network.NET_IPV6:
            return self._ipv6_to_string(self.m_addr, self.m_scope_id)
        
        elif self.m_net == Network.NET_ONION:
            return self._onion_to_string(self.m_addr)
        
        elif self.m_net == Network.NET_I2P:
            import base64
            return base64.b32encode(self.m_addr).decode().rstrip('=').lower() + ".b32.i2p"
        
        elif self.m_net == Network.NET_CJDNS:
            return self._ipv6_to_string(self.m_addr, 0)
        
        elif self.m_net == Network.NET_INTERNAL:
            import base64
            return base64.b32encode(self.m_addr).decode().rstrip('=') + ".internal"
        
        return ""
    
    def _ipv6_to_string(self, addr: bytes, scope_id: int) -> str:
        """Convert IPv6 address to string with zero compression (RFC 5952)."""
        # Read 8 groups of 16 bits
        groups = []
        for i in range(0, 16, 2):
            groups.append((addr[i] << 8) | addr[i + 1])
        
        # Find longest sequence of zeros
        longest_start = 0
        longest_len = 0
        current_start = 0
        current_len = 0
        
        for i, g in enumerate(groups):
            if g == 0:
                if current_len == 0:
                    current_start = i
                current_len += 1
                if current_len > longest_len:
                    longest_start = current_start
                    longest_len = current_len
            else:
                current_len = 0
        
        # Build string
        parts = []
        i = 0
        while i < 8:
            if i == longest_start and longest_len >= 2:
                if i == 0:
                    parts.append("")
                i += longest_len
                if i == 8:
                    parts.append("")
            else:
                parts.append(f"{groups[i]:x}")
                i += 1
        
        result = ":".join(parts)
        
        if scope_id != 0:
            result += f"%{scope_id}"
        
        return result
    
    def _onion_to_string(self, addr: bytes) -> str:
        """Convert Tor address to string."""
        # TORv3 onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
        checksum_data = b".onion checksum" + addr + bytes([3])
        checksum = SHA3_256(checksum_data).digest()[:2]
        
        import base64
        address = addr + checksum + bytes([3])
        return base64.b32encode(address).decode().rstrip('=').lower() + ".onion"
    
    def __str__(self) -> str:
        return self.to_string_addr()
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CNetAddr):
            return False
        return self.m_net == other.m_net and self.m_addr == other.m_addr
    
    def __lt__(self, other: CNetAddr) -> bool:
        return (self.m_net, self.m_addr) < (other.m_net, other.m_addr)
    
    def __hash__(self) -> int:
        return hash((self.m_net, self.m_addr))


# ==============================================================================
# CService Class
# ==============================================================================

@dataclass
class CService(CNetAddr):
    """
    A combination of a network address (CNetAddr) and a (TCP) port.
    """
    
    port: int = 0
    
    def __post_init__(self):
        super().__post_init__()
        if not (0 <= self.port <= 65535):
            raise ValueError(f"Invalid port: {self.port}")
    
    def get_port(self) -> int:
        """Get the port number."""
        return self.port
    
    def get_key(self) -> bytes:
        """Get an identifier unique to this service's address and port number."""
        key = bytearray(self.get_addr_bytes())
        key.append(self.port >> 8)
        key.append(self.port & 0xFF)
        return bytes(key)
    
    def get_sock_addr(self) -> tuple[str, int]:
        """Get (host, port) tuple for socket operations."""
        return (self.to_string_addr(), self.port)
    
    def get_sa_family(self) -> int:
        """Get the address family (AF_INET, AF_INET6, or AF_UNSPEC)."""
        if self.is_ipv4():
            return socket.AF_INET
        elif self.is_ipv6() or self.is_cjdns():
            return socket.AF_INET6
        else:
            return socket.AF_UNSPEC
    
    def to_string_addr_port(self) -> str:
        """Convert to string with port."""
        addr_str = self.to_string_addr()
        if self.is_ipv4() or self.is_tor() or self.is_i2p() or self.is_internal():
            return f"{addr_str}:{self.port}"
        else:
            return f"[{addr_str}]:{self.port}"
    
    def __str__(self) -> str:
        return self.to_string_addr_port()
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CService):
            return False
        return super().__eq__(other) and self.port == other.port
    
    def __lt__(self, other: CService) -> bool:
        return (super().__lt__(other) or
                (super().__eq__(other) and self.port < other.port))
    
    def __hash__(self) -> int:
        return hash((super().__hash__(), self.port))
    
    # ==========================================================================
    # Serialization
    # ==========================================================================
    
    def serialize_v1(self) -> bytes:
        """Serialize in V1 format (address + port)."""
        result = bytearray()
        result.extend(super().serialize_v1())
        result.extend(struct.pack('>H', self.port))
        return bytes(result)
    
    def serialize_v2(self) -> bytes:
        """Serialize in V2 format (address + port)."""
        result = bytearray()
        result.extend(super().serialize_v2())
        result.extend(struct.pack('>H', self.port))
        return bytes(result)
    
    @classmethod
    def deserialize_v1(cls, data: bytes) -> tuple[CService, int]:
        """Deserialize from V1 format."""
        addr, consumed = CNetAddr.deserialize_v1(data)
        
        if len(data) < consumed + 2:
            raise ValueError("Data too short for port")
        
        port = struct.unpack('>H', data[consumed:consumed + 2])[0]
        
        service = cls(m_addr=addr.m_addr, m_net=addr.m_net,
                      m_scope_id=addr.m_scope_id, port=port)
        return service, consumed + 2
    
    @classmethod
    def deserialize_v2(cls, data: bytes) -> tuple[CService, int]:
        """Deserialize from V2 format."""
        addr, consumed = CNetAddr.deserialize_v2(data)
        
        if len(data) < consumed + 2:
            raise ValueError("Data too short for port")
        
        port = struct.unpack('>H', data[consumed:consumed + 2])[0]
        
        service = cls(m_addr=addr.m_addr, m_net=addr.m_net,
                      m_scope_id=addr.m_scope_id, port=port)
        return service, consumed + 2


# ==============================================================================
# CSubNet Class
# ==============================================================================

@dataclass
class CSubNet:
    """
    Represents a network subnet for IP filtering.
    """
    
    network: CNetAddr = field(default_factory=CNetAddr)
    netmask: bytes = field(default_factory=lambda: bytes(16))
    valid: bool = False
    
    def __init__(self, addr: Optional[CNetAddr] = None, mask: Optional[int] = None):
        """
        Construct a subnet.
        
        Args:
            addr: Network start address
            mask: CIDR mask (number of bits)
        """
        self.netmask = bytes(16)
        self.valid = False
        
        if addr is None:
            self.network = CNetAddr()
            return
        
        self.network = addr
        
        if mask is None:
            # Single-host subnet
            if addr.is_ipv4() or addr.is_ipv6():
                self.valid = True
                self.netmask = bytes([0xFF] * len(addr.m_addr))
            elif addr.is_tor() or addr.is_i2p() or addr.is_cjdns():
                self.valid = True
            else:
                self.valid = False
            return
        
        # CIDR mask provided
        if addr.is_ipv4() and mask <= 32:
            self.valid = True
        elif addr.is_ipv6() and mask <= 128:
            self.valid = True
        else:
            self.valid = False
            return
        
        # Build netmask
        self.netmask = bytearray(16)
        bits = mask
        for i in range(len(self.network.m_addr)):
            if bits >= 8:
                self.netmask[i] = 0xFF
                bits -= 8
            elif bits > 0:
                self.netmask[i] = 0xFF << (8 - bits)
                bits = 0
        
        self.netmask = bytes(self.netmask)
        
        # Normalize network
        normalized = bytearray(self.network.m_addr)
        for i in range(len(normalized)):
            normalized[i] &= self.netmask[i] if i < len(self.netmask) else 0
        self.network.m_addr = bytes(normalized)
    
    def match(self, addr: CNetAddr) -> bool:
        """Check if an address matches this subnet."""
        if not self.valid or not addr.is_valid():
            return False
        
        if self.network.m_net != addr.m_net:
            return False
        
        if self.network.m_net in (Network.NET_ONION, Network.NET_I2P,
                                  Network.NET_CJDNS, Network.NET_INTERNAL):
            return addr == self.network
        
        # Compare with netmask
        for i in range(len(addr.m_addr)):
            if (addr.m_addr[i] & self.netmask[i]) != self.network.m_addr[i]:
                return False
        
        return True
    
    def is_valid(self) -> bool:
        """Check if this subnet is valid."""
        return self.valid
    
    def to_string(self) -> str:
        """Convert to string representation."""
        result = self.network.to_string_addr()
        
        if self.network.is_ipv4() or self.network.is_ipv6():
            # Count bits in netmask
            bits = 0
            for b in self.netmask[:len(self.network.m_addr)]:
                bits += bin(b).count('1')
            result += f"/{bits}"
        
        return result
    
    def __str__(self) -> str:
        return self.to_string()
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CSubNet):
            return False
        return (self.valid == other.valid and
                self.network == other.network and
                self.netmask == other.netmask)
    
    def __hash__(self) -> int:
        return hash((self.valid, self.network, self.netmask))


# ==============================================================================
# Helper Functions
# ==============================================================================

def _encode_compact_size(size: int) -> bytes:
    """Encode a size as CompactSize."""
    if size < 0xFD:
        return bytes([size])
    elif size <= 0xFFFF:
        return bytes([0xFD]) + struct.pack('<H', size)
    elif size <= 0xFFFFFFFF:
        return bytes([0xFE]) + struct.pack('<I', size)
    else:
        return bytes([0xFF]) + struct.pack('<Q', size)


def _decode_compact_size(data: bytes) -> tuple[int, int]:
    """
    Decode a CompactSize from bytes.
    
    Returns:
        Tuple of (size, bytes_consumed)
    """
    if len(data) < 1:
        raise ValueError("Data too short for CompactSize")
    
    first = data[0]
    if first < 0xFD:
        return first, 1
    elif first == 0xFD:
        if len(data) < 3:
            raise ValueError("Data too short for CompactSize")
        return struct.unpack('<H', data[1:3])[0], 3
    elif first == 0xFE:
        if len(data) < 5:
            raise ValueError("Data too short for CompactSize")
        return struct.unpack('<I', data[1:5])[0], 5
    else:
        if len(data) < 9:
            raise ValueError("Data too short for CompactSize")
        return struct.unpack('<Q', data[1:9])[0], 9


def onion_to_string(addr: bytes) -> str:
    """Convert Tor address bytes to string."""
    checksum_data = b".onion checksum" + addr + bytes([3])
    checksum = SHA3_256(checksum_data).digest()[:2]
    
    import base64
    address = addr + checksum + bytes([3])
    return base64.b32encode(address).decode().rstrip('=').lower() + ".onion"


@classmethod
def from_ip_port(cls, ip: str, port: int, ipv6: bool = False) -> 'CService':
    """
    Create a CService from an IP address string and port.
    
    Args:
        ip: IP address string (IPv4 or IPv6)
        port: Port number
        ipv6: Whether to treat as IPv6 (auto-detected if False)
        
    Returns:
        CService instance
    """
    import socket
    
    if ipv6 or ':' in ip:
        # IPv6
        addr_bytes = socket.inet_pton(socket.AF_INET6, ip)
        return cls(m_addr=addr_bytes, m_net=Network.NET_IPV6, port=port)
    else:
        # IPv4
        addr_bytes = socket.inet_pton(socket.AF_INET, ip)
        return cls(m_addr=addr_bytes, m_net=Network.NET_IPV4, port=port)


# Add the classmethod to CService
CService.from_ip_port = from_ip_port


def maybe_flip_ipv6_to_cjdns(service: CService) -> CService:
    """
    If an IPv6 address belongs to the address range used by the CJDNS network,
    change the type from NET_IPV6 to NET_CJDNS.
    """
    if service.is_ipv6() and service.has_cjdns_prefix():
        return CService(
            m_addr=service.m_addr,
            m_net=Network.NET_CJDNS,
            m_scope_id=service.m_scope_id,
            port=service.port
        )
    return service
