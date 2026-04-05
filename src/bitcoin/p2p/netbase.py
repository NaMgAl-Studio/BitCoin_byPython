"""
Bitcoin Network Base Functions.

This module implements network utility functions for the Bitcoin P2P protocol,
including DNS resolution, proxy support, and socket operations.

Reference: Bitcoin Core src/netbase.h, src/netbase.cpp
"""

from __future__ import annotations

import asyncio
import socket
import struct
import sys
from dataclasses import dataclass
from enum import Flag, auto
from typing import Final, Callable, Optional, List

from .netaddress import (
    CNetAddr, CService, CSubNet, Network,
    ADDR_IPV4_SIZE, ADDR_IPV6_SIZE, I2P_SAM31_PORT
)


# ==============================================================================
# Constants
# ==============================================================================

DEFAULT_CONNECT_TIMEOUT: Final[int] = 5000
"""-timeout default (milliseconds)"""

DEFAULT_NAME_LOOKUP: Final[bool] = True
"""-dns default"""

ADDR_PREFIX_UNIX: Final[str] = "unix:"
"""Prefix for unix domain socket addresses"""


# ==============================================================================
# Global Variables
# ==============================================================================

n_connect_timeout: int = DEFAULT_CONNECT_TIMEOUT
f_name_lookup: bool = DEFAULT_NAME_LOOKUP


# ==============================================================================
# Connection Direction Enum
# ==============================================================================

class ConnectionDirection(Flag):
    """Connection direction flags."""
    
    NONE = 0
    IN = auto()
    OUT = auto()
    BOTH = IN | OUT


# ==============================================================================
# Proxy Class
# ==============================================================================

@dataclass
class Proxy:
    """
    Proxy configuration.
    
    Supports TCP proxies and Unix domain socket proxies.
    """
    
    proxy: CService = None
    m_unix_socket_path: str = ""
    m_is_unix_socket: bool = False
    m_tor_stream_isolation: bool = False
    
    def __init__(
        self,
        proxy: Optional[CService] = None,
        unix_socket_path: str = "",
        tor_stream_isolation: bool = False
    ):
        if proxy is not None:
            self.proxy = proxy
            self.m_is_unix_socket = False
        elif unix_socket_path:
            self.m_unix_socket_path = unix_socket_path
            self.m_is_unix_socket = True
        else:
            self.proxy = CService()
            self.m_is_unix_socket = False
        
        self.m_tor_stream_isolation = tor_stream_isolation
    
    def is_valid(self) -> bool:
        """Check if proxy configuration is valid."""
        if self.m_is_unix_socket:
            return is_unix_socket_path(self.m_unix_socket_path)
        return self.proxy is not None and self.proxy.is_valid()
    
    def get_family(self) -> int:
        """Get the address family."""
        if self.m_is_unix_socket:
            return socket.AF_UNIX
        return self.proxy.get_sa_family()
    
    def to_string(self) -> str:
        """Convert to string representation."""
        if self.m_is_unix_socket:
            return self.m_unix_socket_path
        if self.proxy:
            return self.proxy.to_string_addr_port()
        return ""
    
    async def connect(self) -> Optional[asyncio.StreamReader]:
        """Connect to the proxy."""
        if self.m_is_unix_socket:
            try:
                reader, writer = await asyncio.open_unix_connection(
                    self.m_unix_socket_path
                )
                return reader
            except Exception:
                return None
        else:
            return await connect_directly(self.proxy)


# ==============================================================================
# Proxy Credentials
# ==============================================================================

@dataclass
class ProxyCredentials:
    """Credentials for proxy authentication."""
    
    username: str
    password: str


# ==============================================================================
# Reachable Networks
# ==============================================================================

class ReachableNets:
    """
    List of reachable networks.
    
    Everything is reachable by default.
    """
    
    def __init__(self):
        self._reachable = self._default_nets()
    
    @staticmethod
    def _default_nets() -> set[Network]:
        return {
            Network.NET_UNROUTABLE,
            Network.NET_IPV4,
            Network.NET_IPV6,
            Network.NET_ONION,
            Network.NET_I2P,
            Network.NET_CJDNS,
            Network.NET_INTERNAL,
        }
    
    def add(self, net: Network) -> None:
        """Add a network to the reachable set."""
        self._reachable.add(net)
    
    def remove(self, net: Network) -> None:
        """Remove a network from the reachable set."""
        self._reachable.discard(net)
    
    def remove_all(self) -> None:
        """Remove all networks from the reachable set."""
        self._reachable.clear()
    
    def reset(self) -> None:
        """Reset to default networks."""
        self._reachable = self._default_nets()
    
    def contains(self, net: Network) -> bool:
        """Check if a network is reachable."""
        return net in self._reachable
    
    def contains_addr(self, addr: CNetAddr) -> bool:
        """Check if an address's network is reachable."""
        return self.contains(addr.get_network())
    
    def all(self) -> set[Network]:
        """Get all reachable networks."""
        return self._reachable.copy()


# Global reachable networks instance
g_reachable_nets = ReachableNets()


# ==============================================================================
# DNS Lookup Type
# ==============================================================================

DNSLookupFn = Callable[[str, bool], List[CNetAddr]]


def default_dns_lookup(name: str, allow_lookup: bool) -> List[CNetAddr]:
    """Default DNS lookup function."""
    return wrapped_get_addr_info(name, allow_lookup)


g_dns_lookup: DNSLookupFn = default_dns_lookup


# ==============================================================================
# Network Parsing
# ==============================================================================

def parse_network(net: str) -> Network:
    """Parse a network string to Network enum."""
    net = net.lower().strip()
    
    if net in ('ipv4', 'ipv4', 'v4'):
        return Network.NET_IPV4
    elif net in ('ipv6', 'v6'):
        return Network.NET_IPV6
    elif net in ('onion', 'tor', 'torv3'):
        return Network.NET_ONION
    elif net == 'i2p':
        return Network.NET_I2P
    elif net == 'cjdns':
        return Network.NET_CJDNS
    elif net in ('internal', ''):
        return Network.NET_INTERNAL
    else:
        return Network.NET_UNROUTABLE


def get_network_name(net: Network) -> str:
    """Get the name of a network."""
    names = {
        Network.NET_UNROUTABLE: "unroutable",
        Network.NET_IPV4: "ipv4",
        Network.NET_IPV6: "ipv6",
        Network.NET_ONION: "onion",
        Network.NET_I2P: "i2p",
        Network.NET_CJDNS: "cjdns",
        Network.NET_INTERNAL: "internal",
    }
    return names.get(net, "unknown")


def get_network_names(append_unroutable: bool = False) -> List[str]:
    """Get list of publicly routable network names."""
    names = ["ipv4", "ipv6", "onion", "i2p", "cjdns"]
    if append_unroutable:
        names.append("unroutable")
    return names


# ==============================================================================
# Socket Creation
# ==============================================================================

def create_sock_os(domain: int, sock_type: int, protocol: int) -> Optional[socket.socket]:
    """
    Create a real socket from the operating system.
    
    Args:
        domain: Communications domain (AF_INET, AF_INET6, etc.)
        sock_type: Type of the socket (SOCK_STREAM, etc.)
        protocol: Protocol to use
        
    Returns:
        Socket object or None on failure
    """
    try:
        return socket.socket(domain, sock_type, protocol)
    except OSError:
        return None


# Socket factory (can be overridden for testing)
create_sock = create_sock_os


# ==============================================================================
# DNS Resolution
# ==============================================================================

def wrapped_get_addr_info(name: str, allow_lookup: bool) -> List[CNetAddr]:
    """
    Wrapper for getaddrinfo.
    
    Args:
        name: Hostname to resolve
        allow_lookup: Whether DNS lookups are allowed
        
    Returns:
        List of resolved addresses
    """
    addresses = []
    
    try:
        # Determine if we should do DNS lookup
        if not allow_lookup:
            # Try to parse as numeric address only
            try:
                # Try IPv4
                addr = socket.inet_pton(socket.AF_INET, name)
                net_addr = CNetAddr()
                net_addr.m_net = Network.NET_IPV4
                net_addr.m_addr = addr
                addresses.append(net_addr)
                return addresses
            except OSError:
                pass
            
            try:
                # Try IPv6
                addr = socket.inet_pton(socket.AF_INET6, name)
                net_addr = CNetAddr()
                net_addr.m_net = Network.NET_IPV6
                net_addr.m_addr = addr
                addresses.append(net_addr)
                return addresses
            except OSError:
                pass
            
            return addresses
        
        # Do DNS lookup
        addr_info = socket.getaddrinfo(name, None)
        
        for family, _, _, _, sockaddr in addr_info:
            if family == socket.AF_INET:
                net_addr = CNetAddr()
                net_addr.m_net = Network.NET_IPV4
                net_addr.m_addr = sockaddr[0].packed if hasattr(sockaddr[0], 'packed') else \
                    socket.inet_pton(socket.AF_INET, sockaddr[0])
                addresses.append(net_addr)
            elif family == socket.AF_INET6:
                net_addr = CNetAddr()
                net_addr.m_net = Network.NET_IPV6
                # Handle scope_id
                if len(sockaddr) >= 4:
                    scope_id = sockaddr[3]
                else:
                    scope_id = 0
                net_addr.m_scope_id = scope_id
                net_addr.m_addr = sockaddr[0].packed if hasattr(sockaddr[0], 'packed') else \
                    socket.inet_pton(socket.AF_INET6, sockaddr[0])
                addresses.append(net_addr)
    
    except (OSError, socket.gaierror):
        pass
    
    return addresses


def lookup_host(
    name: str,
    max_solutions: int,
    allow_lookup: bool,
    dns_lookup_fn: DNSLookupFn = g_dns_lookup
) -> List[CNetAddr]:
    """
    Resolve a host string to network addresses.
    
    Args:
        name: Hostname or IP address string
        max_solutions: Maximum number of results (0 = all)
        allow_lookup: Whether DNS lookups are allowed
        dns_lookup_fn: DNS lookup function to use
        
    Returns:
        List of resolved addresses
    """
    addresses = dns_lookup_fn(name, allow_lookup)
    
    if max_solutions > 0 and len(addresses) > max_solutions:
        addresses = addresses[:max_solutions]
    
    return addresses


def lookup_host_single(
    name: str,
    allow_lookup: bool,
    dns_lookup_fn: DNSLookupFn = g_dns_lookup
) -> Optional[CNetAddr]:
    """
    Resolve a host string to its first corresponding network address.
    
    Returns:
        The first resolved address or None
    """
    addresses = lookup_host(name, 1, allow_lookup, dns_lookup_fn)
    return addresses[0] if addresses else None


def lookup(
    name: str,
    port_default: int,
    allow_lookup: bool,
    max_solutions: int,
    dns_lookup_fn: DNSLookupFn = g_dns_lookup
) -> List[CService]:
    """
    Resolve a service string to services.
    
    Args:
        name: Service string (host or host:port)
        port_default: Default port if not specified
        allow_lookup: Whether DNS lookups are allowed
        max_solutions: Maximum number of results (0 = all)
        dns_lookup_fn: DNS lookup function to use
        
    Returns:
        List of resolved services
    """
    # Parse host and port
    host, port = split_host_port(name, port_default)
    
    # Resolve host
    addresses = lookup_host(host, max_solutions if max_solutions > 0 else 0,
                            allow_lookup, dns_lookup_fn)
    
    # Build services
    services = []
    for addr in addresses:
        service = CService(m_addr=addr.m_addr, m_net=addr.m_net,
                          m_scope_id=addr.m_scope_id, port=port)
        services.append(service)
    
    return services


def lookup_single(
    name: str,
    port_default: int,
    allow_lookup: bool,
    dns_lookup_fn: DNSLookupFn = g_dns_lookup
) -> Optional[CService]:
    """
    Resolve a service string to its first corresponding service.
    
    Returns:
        The first resolved service or None
    """
    services = lookup(name, port_default, allow_lookup, 1, dns_lookup_fn)
    return services[0] if services else None


def lookup_numeric(
    name: str,
    port_default: int = 0,
    dns_lookup_fn: DNSLookupFn = g_dns_lookup
) -> CService:
    """
    Resolve a service string with a numeric IP.
    
    Returns:
        The resolved service or [::]:0 on failure
    """
    result = lookup_single(name, port_default, False, dns_lookup_fn)
    if result:
        return result
    
    # Return unspecified address
    return CService(m_addr=bytes(ADDR_IPV6_SIZE), m_net=Network.NET_IPV6, port=0)


def lookup_sub_net(subnet_str: str) -> CSubNet:
    """
    Parse and resolve a subnet string.
    
    Args:
        subnet_str: Subnet string (e.g., "192.168.0.0/24")
        
    Returns:
        CSubNet object (may be invalid)
    """
    # Parse CIDR notation
    if '/' in subnet_str:
        parts = subnet_str.rsplit('/', 1)
        addr_str = parts[0]
        
        try:
            mask = int(parts[1])
        except ValueError:
            # Try parsing as netmask
            mask_addr = lookup_single(parts[1], 0, False)
            if mask_addr and (mask_addr.is_ipv4() or mask_addr.is_ipv6()):
                # Convert netmask to CIDR
                mask = 0
                for b in mask_addr.m_addr:
                    mask += bin(b).count('1')
            else:
                return CSubNet()
        
        addr = lookup_single(addr_str, 0, True)
        if addr:
            return CSubNet(addr, mask)
    
    else:
        # Single address
        addr = lookup_single(subnet_str, 0, True)
        if addr:
            return CSubNet(addr)
    
    return CSubNet()


# ==============================================================================
# Host/Port Parsing
# ==============================================================================

def split_host_port(name: str, port_default: int) -> tuple[str, int]:
    """
    Split a host:port string.
    
    Args:
        name: String to split
        port_default: Default port if not specified
        
    Returns:
        Tuple of (host, port)
    """
    port = port_default
    
    # Handle IPv6 bracket notation
    if name.startswith('['):
        bracket_end = name.find(']')
        if bracket_end != -1:
            host = name[1:bracket_end]
            if bracket_end + 1 < len(name) and name[bracket_end + 1] == ':':
                try:
                    port = int(name[bracket_end + 2:])
                except ValueError:
                    pass
            return host, port
    
    # Regular host:port
    if ':' in name:
        # Could be IPv6 address or host:port
        colons = name.count(':')
        if colons == 1:
            # host:port
            parts = name.rsplit(':', 1)
            try:
                port = int(parts[1])
                return parts[0], port
            except ValueError:
                pass
        elif colons >= 2 and '::' not in name:
            # Might be IPv6:port at the end
            last_colon = name.rfind(':')
            try:
                port = int(name[last_colon + 1:])
                return name[:last_colon], port
            except ValueError:
                pass
    
    return name, port


# ==============================================================================
# Connection Functions
# ==============================================================================

async def connect_directly(
    dest: CService,
    timeout_ms: int = DEFAULT_CONNECT_TIMEOUT
) -> Optional[asyncio.StreamReader]:
    """
    Create a socket and connect to the specified service.
    
    Args:
        dest: Service to connect to
        timeout_ms: Connection timeout in milliseconds
        
    Returns:
        StreamReader if successful, None otherwise
    """
    if not dest.is_valid():
        return None
    
    try:
        family = dest.get_sa_family()
        if family == socket.AF_UNSPEC:
            return None
        
        host = dest.to_string_addr()
        port = dest.get_port()
        
        # Use asyncio for async connection
        if family == socket.AF_INET:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, family=socket.AF_INET),
                timeout=timeout_ms / 1000.0
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, family=socket.AF_INET6),
                timeout=timeout_ms / 1000.0
            )
        
        return reader
    
    except (asyncio.TimeoutError, OSError, ConnectionError):
        return None


async def connect_through_proxy(
    proxy: Proxy,
    dest: str,
    port: int,
    timeout_ms: int = DEFAULT_CONNECT_TIMEOUT
) -> Optional[asyncio.StreamReader]:
    """
    Connect to a destination through a SOCKS5 proxy.
    
    Args:
        proxy: Proxy configuration
        dest: Destination hostname
        port: Destination port
        timeout_ms: Connection timeout
        
    Returns:
        StreamReader if successful, None otherwise
    """
    if not proxy.is_valid():
        return None
    
    # Connect to proxy
    reader = await proxy.connect()
    if reader is None:
        return None
    
    # Perform SOCKS5 handshake
    try:
        # Get the writer from the connection
        # Note: In asyncio, we get both reader and writer
        if proxy.m_is_unix_socket:
            reader, writer = await asyncio.open_unix_connection(proxy.m_unix_socket_path)
        else:
            reader, writer = await asyncio.open_connection(
                proxy.proxy.to_string_addr(),
                proxy.proxy.get_port()
            )
        
        # SOCKS5 greeting
        # Version 5, 1 method, no auth
        writer.write(bytes([0x05, 0x01, 0x00]))
        await writer.drain()
        
        # Read response
        response = await asyncio.wait_for(
            reader.read(2),
            timeout=timeout_ms / 1000.0
        )
        
        if len(response) != 2 or response[0] != 5:
            writer.close()
            await writer.wait_closed()
            return None
        
        # SOCKS5 connect request
        # Version 5, CONNECT, reserved, domain name
        dest_bytes = dest.encode('utf-8')
        request = bytes([
            0x05,  # SOCKS version
            0x01,  # CONNECT command
            0x00,  # Reserved
            0x03,  # Domain name
            len(dest_bytes)
        ]) + dest_bytes + struct.pack('>H', port)
        
        writer.write(request)
        await writer.drain()
        
        # Read response (at least 10 bytes)
        response = await asyncio.wait_for(
            reader.read(10),
            timeout=timeout_ms / 1000.0
        )
        
        if len(response) < 10 or response[1] != 0:
            writer.close()
            await writer.wait_closed()
            return None
        
        return reader
    
    except (asyncio.TimeoutError, OSError, ConnectionError):
        return None


# ==============================================================================
# SOCKS5 Protocol
# ==============================================================================

async def socks5_connect(
    dest: str,
    port: int,
    auth: Optional[ProxyCredentials],
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    timeout_ms: int = DEFAULT_CONNECT_TIMEOUT
) -> bool:
    """
    Connect to a destination through an already connected SOCKS5 proxy.
    
    Args:
        dest: Destination hostname
        port: Destination port
        auth: Optional proxy credentials
        reader: Connected reader
        writer: Connected writer
        timeout_ms: Timeout
        
    Returns:
        True if successful
    """
    try:
        # SOCKS5 greeting
        if auth:
            # Version 5, 2 methods, no auth + username/password
            writer.write(bytes([0x05, 0x02, 0x00, 0x02]))
        else:
            # Version 5, 1 method, no auth
            writer.write(bytes([0x05, 0x01, 0x00]))
        
        await writer.drain()
        
        # Read response
        response = await asyncio.wait_for(
            reader.read(2),
            timeout=timeout_ms / 1000.0
        )
        
        if len(response) != 2 or response[0] != 5:
            return False
        
        method = response[1]
        
        # Handle authentication if required
        if method == 0x02 and auth:
            # Username/password auth
            username = auth.username.encode('utf-8')
            password = auth.password.encode('utf-8')
            
            auth_request = bytes([0x01, len(username)]) + username + \
                          bytes([len(password)]) + password
            writer.write(auth_request)
            await writer.drain()
            
            auth_response = await asyncio.wait_for(
                reader.read(2),
                timeout=timeout_ms / 1000.0
            )
            
            if len(auth_response) != 2 or auth_response[1] != 0:
                return False
        
        elif method != 0x00:
            return False
        
        # SOCKS5 connect request
        dest_bytes = dest.encode('utf-8')
        request = bytes([
            0x05,  # SOCKS version
            0x01,  # CONNECT command
            0x00,  # Reserved
            0x03,  # Domain name
            len(dest_bytes)
        ]) + dest_bytes + struct.pack('>H', port)
        
        writer.write(request)
        await writer.drain()
        
        # Read response header
        response = await asyncio.wait_for(
            reader.read(4),
            timeout=timeout_ms / 1000.0
        )
        
        if len(response) != 4 or response[0] != 5 or response[1] != 0:
            return False
        
        # Read bind address based on address type
        addr_type = response[3]
        if addr_type == 0x01:
            # IPv4
            await asyncio.wait_for(
                reader.read(4 + 2),  # 4 bytes IP + 2 bytes port
                timeout=timeout_ms / 1000.0
            )
        elif addr_type == 0x03:
            # Domain name
            len_byte = await asyncio.wait_for(
                reader.read(1),
                timeout=timeout_ms / 1000.0
            )
            if len(len_byte) != 1:
                return False
            await asyncio.wait_for(
                reader.read(len_byte[0] + 2),
                timeout=timeout_ms / 1000.0
            )
        elif addr_type == 0x04:
            # IPv6
            await asyncio.wait_for(
                reader.read(16 + 2),  # 16 bytes IP + 2 bytes port
                timeout=timeout_ms / 1000.0
            )
        
        return True
    
    except (asyncio.TimeoutError, OSError, ConnectionError):
        return False


# ==============================================================================
# Utility Functions
# ==============================================================================

def is_unix_socket_path(name: str) -> bool:
    """
    Check if a string is a valid UNIX domain socket path.
    
    Args:
        name: The string representing a local path
        
    Returns:
        Whether the string is a valid UNIX socket path
    """
    if not name:
        return False
    
    # Check for unix: prefix
    if name.startswith(ADDR_PREFIX_UNIX):
        return True
    
    # Check length (max path length varies by OS)
    if len(name) > 107:  # Typical max for sun_path
        return False
    
    return True


def is_bad_port(port: int) -> bool:
    """
    Check if a port is "bad" from the perspective of connecting.
    
    Some ports are commonly used for other services and should be avoided.
    
    Args:
        port: Port to check
        
    Returns:
        Whether the port is considered bad
    """
    bad_ports = {
        1,      # tcpmux
        7,      # echo
        9,      # discard
        11,     # systat
        13,     # daytime
        15,     # netstat
        17,     # qotd
        19,     # chargen
        20,     # ftp data
        21,     # ftp access
        22,     # ssh
        23,     # telnet
        25,     # smtp
        37,     # time
        42,     # name
        43,     # nicname
        53,     # domain
        69,     # tftp
        77,     # priv-rjs
        79,     # finger
        87,     # ttylink
        95,     # supdup
        101,    # hostriame
        102,    # iso-tsap
        103,    # gppitnp
        104,    # acr-nema
        109,    # pop2
        110,    # pop3
        111,    # sunrpc
        113,    # auth
        115,    # sftp
        117,    # uucp-path
        119,    # nntp
        123,    # NTP
        135,    # loc-srv /epmap
        137,    # netbios
        139,    # netbios
        143,    # imap2
        161,    # snmp
        179,    # BGP
        389,    # ldap
        427,    # SLP (Also used by Apple Filing Protocol)
        465,    # smtp+ssl
        512,    # print / exec
        513,    # login
        514,    # shell
        515,    # printer
        526,    # tempo
        530,    # courier
        531,    # chat
        532,    # netnews
        540,    # uucp
        548,    # AFP (Apple Filing Protocol)
        554,    # rtsp
        556,    # remotefs
        563,    # nntp+ssl
        587,    # smtp (rfc6409)
        601,    # syslog-conn (rfc6587)
        636,    # ldap+ssl
        989,    # ftps-data
        990,    # ftps
        993,    # ldap+ssl
        995,    # pop3+ssl
        1719,   # h323gatestat
        1720,   # h323hostcall
        1723,   # pptp
        2049,   # nfs
        3659,   # apple-sasl / PasswordServer
        4045,   # lockd
        5060,   # sip
        5061,   # sips
        6000,   # X11
        6566,   # sane-port
        6665,   # Alternate IRC
        6666,   # Alternate IRC
        6667,   # Standard IRC
        6668,   # Alternate IRC
        6669,   # Alternate IRC
        6697,   # IRC + TLS
        10080,  # Amanda
    }
    
    return port in bad_ports


def get_bind_address(sock: socket.socket) -> CService:
    """Get the bind address for a socket as CService."""
    try:
        sockname = sock.getsockname()
        if isinstance(sockname, tuple):
            if len(sockname) >= 2:
                if ':' in sockname[0]:  # IPv6
                    addr = CNetAddr()
                    addr.m_net = Network.NET_IPV6
                    addr.m_addr = socket.inet_pton(socket.AF_INET6, sockname[0])
                    return CService(m_addr=addr.m_addr, m_net=addr.m_net, port=sockname[1])
                else:  # IPv4
                    addr = CNetAddr()
                    addr.m_net = Network.NET_IPV4
                    addr.m_addr = socket.inet_pton(socket.AF_INET, sockname[0])
                    return CService(m_addr=addr.m_addr, m_net=addr.m_net, port=sockname[1])
    except OSError:
        pass
    
    return CService()


# ==============================================================================
# Global Proxy Settings
# ==============================================================================

_proxies: dict[Network, Proxy] = {}
_name_proxy: Optional[Proxy] = None


def set_proxy(net: Network, proxy: Proxy) -> bool:
    """Set the proxy for a network."""
    if proxy.is_valid():
        _proxies[net] = proxy
        return True
    return False


def get_proxy(net: Network) -> Optional[Proxy]:
    """Get the proxy for a network."""
    return _proxies.get(net)


def is_proxy(addr: CNetAddr) -> bool:
    """Check if an address is a configured proxy."""
    for proxy in _proxies.values():
        if proxy.proxy and proxy.proxy == CService(
            m_addr=addr.m_addr, m_net=addr.m_net, port=proxy.proxy.port
        ):
            return True
    return False


def set_name_proxy(proxy: Proxy) -> bool:
    """Set the name proxy for all hostname connections."""
    global _name_proxy
    if proxy.is_valid():
        _name_proxy = proxy
        return True
    return False


def have_name_proxy() -> bool:
    """Check if a name proxy is configured."""
    return _name_proxy is not None


def get_name_proxy() -> Optional[Proxy]:
    """Get the configured name proxy."""
    return _name_proxy
