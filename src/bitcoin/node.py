#!/usr/bin/env python3
"""
Bitcoin Node - Main entry point for bitcoind-py.

This module provides the main entry point for running a Bitcoin node
in Python, including P2P networking and RPC server.

The node connects to the real Bitcoin network and syncs block headers.

Usage:
    bitcoind-py [options]
    
Options:
    --rpcport PORT     RPC server port (default: 8332)
    --rpcuser USER     RPC username
    --rpcpassword PASS RPC password
    --daemon           Run as daemon
    --regtest          Use regtest network
    --testnet          Use testnet network
    --connect HOST     Connect to specific node (bypass DNS seeds)
    --addnode HOST     Add a node to connect to
    --dnsseed          Use DNS seeds (default: True)
    --printtoconsole   Print to console instead of debug log

Reference: Bitcoin Core src/bitcoind.cpp
"""

import argparse
import asyncio
import hashlib
import logging
import os
import random
import secrets
import signal
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Callable

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bitcoin.rpc.httpserver import HTTPRPCServer, HTTPServerConfig
from bitcoin.rpc.server import (
    tableRPC, CRPCCommand, start_rpc, stop_rpc, set_rpc_warmup_finished
)
from bitcoin.rpc.auth import RPCAuthenticator
from bitcoin.rpc.client import RPCClient, RPCClientConfig

# P2P imports
from bitcoin.p2p.netaddress import CNetAddr, CService, Network
from bitcoin.p2p.netbase import connect_directly, lookup_host_single
from bitcoin.p2p.protocol import (
    ServiceFlags, PROTOCOL_VERSION, get_message_start,
    ConnectionType, HEADER_SIZE
)
from bitcoin.p2p.messages import (
    P2PMessage, VersionMessage, VerackMessage, PingMessage, PongMessage,
    AddrMessage, AddrV2Message, GetAddrMessage, InvMessage, GetDataMessage,
    HeadersMessage, GetHeadersMessage, BlockMessage, TxMessage,
    SendHeadersMessage, WTXIDRelayMessage, SendAddrV2Message,
    deserialize_message, encode_compact_size
)
from bitcoin.p2p.dnsseed import (
    MAINNET_DNS_SEEDS, TESTNET_DNS_SEEDS, TESTNET4_DNS_SEEDS, SIGNET_DNS_SEEDS,
    DNSSeedData
)
from bitcoin.primitives.block import BlockHeader
from bitcoin.chain.chain import ChainState


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ==============================================================================
# Network Configuration
# ==============================================================================

@dataclass
class ChainParams:
    """Chain parameters for different networks."""
    
    name: str
    magic: bytes
    default_port: int
    rpc_port: int
    dns_seeds: List[DNSSeedData]
    genesis_hash: str
    

CHAIN_PARAMS = {
    'main': ChainParams(
        name='main',
        magic=bytes.fromhex('f9beb4d9'),
        default_port=8333,
        rpc_port=8332,
        dns_seeds=MAINNET_DNS_SEEDS,
        genesis_hash='000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'
    ),
    'test': ChainParams(
        name='testnet3',
        magic=bytes.fromhex('0b110907'),
        default_port=18333,
        rpc_port=18332,
        dns_seeds=TESTNET_DNS_SEEDS,
        genesis_hash='000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943'
    ),
    'testnet4': ChainParams(
        name='testnet4',
        magic=bytes.fromhex('1c163f28'),
        default_port=48333,
        rpc_port=48332,
        dns_seeds=TESTNET4_DNS_SEEDS,
        genesis_hash='00000000da84f2bafbbc53dee25a72f507e5a2715b4e5a0a7d1e9c0d0e0f0a0b0'
    ),
    'signet': ChainParams(
        name='signet',
        magic=bytes.fromhex('0a03cf40'),
        default_port=38333,
        rpc_port=38332,
        dns_seeds=SIGNET_DNS_SEEDS,
        genesis_hash='00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6'
    ),
    'regtest': ChainParams(
        name='regtest',
        magic=bytes.fromhex('fabfb5da'),
        default_port=18444,
        rpc_port=18443,
        dns_seeds=[],
        genesis_hash='0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206'
    ),
}


# ==============================================================================
# Peer Connection
# ==============================================================================

@dataclass
class PeerConnection:
    """Represents a connection to a Bitcoin peer."""
    
    id: int
    address: CService
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    
    # Protocol state
    connected: bool = False
    handshake_complete: bool = False
    version: int = 0
    services: ServiceFlags = ServiceFlags.NODE_NONE
    user_agent: str = ""
    start_height: int = 0
    nonce: int = 0
    
    # Async state
    recv_task: Optional[asyncio.Task] = None
    
    # Statistics
    bytes_recv: int = 0
    bytes_sent: int = 0
    last_recv: float = 0.0
    last_send: float = 0.0
    
    # Message buffer
    _recv_buffer: bytes = field(default=b'', repr=False)
    
    def close(self):
        """Close the connection."""
        self.connected = False
        if self.recv_task:
            self.recv_task.cancel()
        try:
            self.writer.close()
        except:
            pass


# ==============================================================================
# Bitcoin Node
# ==============================================================================

class BitcoinNode:
    """
    Bitcoin Node implementation.
    
    Connects to the Bitcoin P2P network and syncs block headers.
    """
    
    def __init__(
        self,
        chain: str = 'main',
        rpc_port: int = 8332,
        rpc_user: str = '',
        rpc_password: str = ''
    ):
        """Initialize the Bitcoin node."""
        
        # Get chain parameters
        if chain not in CHAIN_PARAMS:
            raise ValueError(f"Unknown chain: {chain}")
        
        self.chain_params = CHAIN_PARAMS[chain]
        self.chain_name = chain
        
        # RPC configuration
        self.rpc_port = rpc_port or self.chain_params.rpc_port
        self.rpc_user = rpc_user
        self.rpc_password = rpc_password
        
        # Node state
        self.running = False
        self.peers: Dict[int, PeerConnection] = {}
        self.peer_id_counter = 0
        
        # Address manager
        self.known_addresses: Set[str] = set()
        self.tried_addresses: Set[str] = set()
        
        # Chain state
        self.chain_state = ChainState()
        self.headers: List[BlockHeader] = []
        self.best_height = 0
        self.best_hash = bytes(32)
        
        # Sync state
        self.syncing = False
        self.headers_synced = False
        self.sync_peer: Optional[PeerConnection] = None
        
        # Configuration
        self.max_peers = 8
        self.connect_timeout = 10.0
        
        # Our node identity
        self.local_nonce = secrets.randbits(64)
        self.local_services = ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_WITNESS
        self.user_agent = "/bitcoin-python:0.1.0/"
        
        # Callbacks
        self._on_header_received: Optional[Callable] = None
        
        # Lock for peer operations
        self._peer_lock = asyncio.Lock()
        
        # Event loop reference
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        
    async def start(self):
        """Start the Bitcoin node."""
        
        logger.info(f"Starting Bitcoin node on {self.chain_params.name}")
        
        self.running = True
        self._loop = asyncio.get_event_loop()
        
        # Discover peers
        await self._discover_peers()
        
        # Connect to peers
        await self._connect_to_peers()
        
        # Start sync
        asyncio.create_task(self._sync_task())
        
        # Start ping task
        asyncio.create_task(self._ping_task())
        
    async def stop(self):
        """Stop the Bitcoin node."""
        
        logger.info("Stopping Bitcoin node")
        self.running = False
        
        # Disconnect all peers
        async with self._peer_lock:
            for peer in list(self.peers.values()):
                self._disconnect_peer(peer, "Node shutting down")
        
        stop_rpc()
        
    # ==========================================================================
    # Peer Discovery
    # ==========================================================================
    
    async def _discover_peers(self):
        """Discover peers from DNS seeds."""
        
        if not self.chain_params.dns_seeds:
            logger.info("No DNS seeds for this network")
            return
        
        logger.info("Querying DNS seeds for peers...")
        
        for seed in self.chain_params.dns_seeds:
            try:
                addresses = await self._query_dns_seed(seed)
                for addr in addresses:
                    addr_str = addr.to_string_addr_port()
                    if addr_str not in self.known_addresses and addr_str not in self.tried_addresses:
                        self.known_addresses.add(addr_str)
                        logger.debug(f"Discovered peer: {addr_str}")
                
                logger.info(f"Discovered {len(addresses)} addresses from {seed.host}")
                
                if len(self.known_addresses) >= 100:
                    break
                    
            except Exception as e:
                logger.warning(f"Failed to query DNS seed {seed.host}: {e}")
        
        logger.info(f"Total known addresses: {len(self.known_addresses)}")
        
    async def _query_dns_seed(self, seed: DNSSeedData) -> List[CService]:
        """Query a DNS seed for peer addresses."""
        
        addresses = []
        
        try:
            loop = asyncio.get_event_loop()
            
            # Query DNS
            addr_info_list = await asyncio.wait_for(
                loop.getaddrinfo(seed.host, self.chain_params.default_port),
                timeout=5.0
            )
            
            for family, _, _, _, sockaddr in addr_info_list:
                if family == socket.AF_INET:
                    ip = sockaddr[0]
                    port = sockaddr[1]
                    addresses.append(CService.from_ip_port(ip, port))
                elif family == socket.AF_INET6:
                    ip = sockaddr[0]
                    port = sockaddr[1]
                    addresses.append(CService.from_ip_port(ip, port, ipv6=True))
                    
        except asyncio.TimeoutError:
            logger.debug(f"DNS query timeout for {seed.host}")
        except socket.gaierror as e:
            logger.debug(f"DNS resolution failed for {seed.host}: {e}")
        except Exception as e:
            logger.debug(f"Error querying DNS seed {seed.host}: {e}")
        
        return addresses
    
    def add_node(self, host: str, port: int = None):
        """Add a node to connect to."""
        port = port or self.chain_params.default_port
        addr_str = f"{host}:{port}"
        self.known_addresses.add(addr_str)
        logger.info(f"Added node: {addr_str}")
        
    # ==========================================================================
    # Peer Connection
    # ==========================================================================
    
    async def _connect_to_peers(self):
        """Connect to peers."""
        
        needed = self.max_peers - len(self.peers)
        
        if needed <= 0:
            return
        
        # Get addresses to try
        addresses = list(self.known_addresses)
        random.shuffle(addresses)
        
        connected = 0
        for addr_str in addresses[:needed * 3]:  # Try 3x needed
            if len(self.peers) >= self.max_peers:
                break
                
            try:
                # Parse address
                if ':' in addr_str:
                    host, port_str = addr_str.rsplit(':', 1)
                    port = int(port_str)
                else:
                    host = addr_str
                    port = self.chain_params.default_port
                
                # Connect
                peer = await self._connect_to_peer(host, port)
                if peer:
                    connected += 1
                    await asyncio.sleep(0.5)  # Small delay between connections
                    
            except Exception as e:
                logger.debug(f"Failed to connect to {addr_str}: {e}")
                continue
        
        logger.info(f"Connected to {connected} peers")
        
    async def _connect_to_peer(self, host: str, port: int) -> Optional[PeerConnection]:
        """Connect to a single peer."""
        
        try:
            logger.debug(f"Connecting to {host}:{port}...")
            
            # Open connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.connect_timeout
            )
            
            # Create peer
            async with self._peer_lock:
                self.peer_id_counter += 1
                peer_id = self.peer_id_counter
            
            # Create CService
            try:
                # Try to parse as IP
                if ':' in host:  # IPv6
                    addr_bytes = socket.inet_pton(socket.AF_INET6, host)
                    service = CService(m_addr=addr_bytes, m_net=Network.NET_IPV6, port=port)
                else:  # IPv4
                    addr_bytes = socket.inet_pton(socket.AF_INET, host)
                    service = CService(m_addr=addr_bytes, m_net=Network.NET_IPV4, port=port)
            except:
                # Use hostname
                service = CService()
                service.host = host
                service.port = port
            
            peer = PeerConnection(
                id=peer_id,
                address=service,
                reader=reader,
                writer=writer,
                connected=True
            )
            
            # Store peer
            async with self._peer_lock:
                self.peers[peer_id] = peer
            
            # Mark address as tried
            addr_str = f"{host}:{port}"
            self.known_addresses.discard(addr_str)
            self.tried_addresses.add(addr_str)
            
            logger.info(f"Connected to peer {peer_id} ({host}:{port})")
            
            # Start handshake
            await self._send_version(peer)
            
            # Start receive task
            peer.recv_task = asyncio.create_task(self._receive_loop(peer))
            
            return peer
            
        except asyncio.TimeoutError:
            logger.debug(f"Connection timeout to {host}:{port}")
            return None
        except OSError as e:
            logger.debug(f"Connection error to {host}:{port}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Unexpected error connecting to {host}:{port}: {e}")
            return None
    
    def _disconnect_peer(self, peer: PeerConnection, reason: str = ""):
        """Disconnect from a peer."""
        
        logger.info(f"Disconnecting peer {peer.id}: {reason}")
        
        peer.connected = False
        peer.close()
        
        # Remove from peers dict
        if peer.id in self.peers:
            del self.peers[peer.id]
            
        # Update sync peer if needed
        if self.sync_peer and self.sync_peer.id == peer.id:
            self.sync_peer = None
    
    # ==========================================================================
    # Protocol Messages
    # ==========================================================================
    
    async def _send_message(self, peer: PeerConnection, message: P2PMessage):
        """Send a message to a peer."""
        
        if not peer.connected:
            return
        
        try:
            # Serialize message
            payload = message.serialize()
            
            # Build message packet
            packet = self._build_message_packet(message.command, payload)
            
            # Send
            peer.writer.write(packet)
            await peer.writer.drain()
            
            peer.bytes_sent += len(packet)
            peer.last_send = time.time()
            
            logger.debug(f"Sent {message.command} to peer {peer.id} ({len(packet)} bytes)")
            
        except Exception as e:
            logger.warning(f"Error sending {message.command} to peer {peer.id}: {e}")
            self._disconnect_peer(peer, f"Send error: {e}")
    
    def _build_message_packet(self, command: str, payload: bytes) -> bytes:
        """Build a complete message packet."""
        
        # Message start (magic)
        packet = bytearray(self.chain_params.magic)
        
        # Command (12 bytes, null-padded)
        cmd_bytes = command.encode('ascii')[:12].ljust(12, b'\x00')
        packet.extend(cmd_bytes)
        
        # Length (4 bytes, little-endian)
        packet.extend(struct.pack('<I', len(payload)))
        
        # Checksum (double SHA256, first 4 bytes)
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        packet.extend(checksum)
        
        # Payload
        packet.extend(payload)
        
        return bytes(packet)
    
    async def _send_version(self, peer: PeerConnection):
        """Send version message to peer."""
        
        now = int(time.time())
        
        # Create version message
        version = VersionMessage(
            n_version=PROTOCOL_VERSION,
            n_services=self.local_services,
            n_time=now,
            addr_recv=peer.address,
            addr_from=CService(m_addr=bytes(16), m_net=Network.NET_IPV6, port=0),
            n_nonce=self.local_nonce,
            str_sub_ver=self.user_agent,
            n_start_height=self.best_height,
            n_relay=True
        )
        
        await self._send_message(peer, version)
        
    async def _send_verack(self, peer: PeerConnection):
        """Send verack message to peer."""
        await self._send_message(peer, VerackMessage())
        
    async def _send_ping(self, peer: PeerConnection):
        """Send ping message to peer."""
        nonce = secrets.randbits(64)
        peer.nonce = nonce
        await self._send_message(peer, PingMessage(nonce=nonce))
        
    async def _send_pong(self, peer: PeerConnection, nonce: int):
        """Send pong message to peer."""
        await self._send_message(peer, PongMessage(nonce=nonce))
        
    async def _send_getaddr(self, peer: PeerConnection):
        """Send getaddr message to peer."""
        await self._send_message(peer, GetAddrMessage())
        
    async def _send_getheaders(self, peer: PeerConnection, locator_hashes: List[bytes] = None):
        """Send getheaders message to peer."""
        
        if locator_hashes is None:
            # Use genesis hash as locator
            genesis_hash = bytes.fromhex(self.chain_params.genesis_hash)[::-1]
            locator_hashes = [genesis_hash]
        
        getheaders = GetHeadersMessage(
            locator_hashes=locator_hashes,
            hash_stop=bytes(32)  # No stop hash
        )
        
        await self._send_message(peer, getheaders)
        
    # ==========================================================================
    # Message Receiving
    # ==========================================================================
    
    async def _receive_loop(self, peer: PeerConnection):
        """Receive messages from a peer."""
        
        logger.debug(f"Starting receive loop for peer {peer.id}")
        
        try:
            while peer.connected and self.running:
                # Read message header
                header_data = await peer.reader.read(HEADER_SIZE)
                
                if not header_data:
                    logger.debug(f"Peer {peer.id} disconnected")
                    break
                
                if len(header_data) < HEADER_SIZE:
                    # Incomplete header, wait for more data
                    peer._recv_buffer += header_data
                    continue
                
                peer.bytes_recv += len(header_data)
                peer.last_recv = time.time()
                
                # Parse header
                try:
                    magic = header_data[:4]
                    if magic != self.chain_params.magic:
                        logger.warning(f"Invalid magic from peer {peer.id}")
                        break
                    
                    command = header_data[4:16].decode('ascii').rstrip('\x00')
                    length = struct.unpack('<I', header_data[16:20])[0]
                    checksum = header_data[20:24]
                    
                    # Check message size
                    if length > 4 * 1024 * 1024:  # 4 MB max
                        logger.warning(f"Message too large from peer {peer.id}: {length}")
                        break
                    
                except Exception as e:
                    logger.warning(f"Error parsing header from peer {peer.id}: {e}")
                    continue
                
                # Read payload
                payload = b''
                while len(payload) < length:
                    remaining = length - len(payload)
                    chunk = await peer.reader.read(min(remaining, 65536))
                    if not chunk:
                        logger.warning(f"Incomplete message from peer {peer.id}")
                        break
                    payload += chunk
                
                if len(payload) != length:
                    break
                
                peer.bytes_recv += len(payload)
                
                # Verify checksum
                computed_checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
                if computed_checksum != checksum:
                    logger.warning(f"Invalid checksum from peer {peer.id}")
                    continue
                
                # Process message
                await self._process_message(peer, command, payload)
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.warning(f"Error in receive loop for peer {peer.id}: {e}")
        finally:
            if peer.connected:
                self._disconnect_peer(peer, "Receive loop ended")
                
    async def _process_message(self, peer: PeerConnection, command: str, payload: bytes):
        """Process a received message."""
        
        logger.debug(f"Received {command} from peer {peer.id} ({len(payload)} bytes)")
        
        try:
            if command == "version":
                await self._handle_version(peer, payload)
            elif command == "verack":
                await self._handle_verack(peer, payload)
            elif command == "ping":
                await self._handle_ping(peer, payload)
            elif command == "pong":
                await self._handle_pong(peer, payload)
            elif command == "addr":
                await self._handle_addr(peer, payload)
            elif command == "headers":
                await self._handle_headers(peer, payload)
            elif command == "inv":
                await self._handle_inv(peer, payload)
            elif command == "block":
                await self._handle_block(peer, payload)
            elif command == "tx":
                await self._handle_tx(peer, payload)
            else:
                logger.debug(f"Unhandled message type: {command}")
                
        except Exception as e:
            logger.warning(f"Error processing {command} from peer {peer.id}: {e}")
    
    # ==========================================================================
    # Message Handlers
    # ==========================================================================
    
    async def _handle_version(self, peer: PeerConnection, payload: bytes):
        """Handle version message."""
        
        version = VersionMessage.deserialize(payload)
        
        peer.version = version.n_version
        peer.services = version.n_services
        peer.user_agent = version.str_sub_ver
        peer.start_height = version.n_start_height
        
        logger.info(f"Peer {peer.id} version: {version.n_version}, "
                   f"services: {version.n_services}, "
                   f"agent: {version.str_sub_ver}, "
                   f"height: {version.n_start_height}")
        
        # Send verack
        await self._send_verack(peer)
        
    async def _handle_verack(self, peer: PeerConnection, payload: bytes):
        """Handle verack message."""
        
        peer.handshake_complete = True
        logger.info(f"Handshake complete with peer {peer.id}")
        
        # Request addresses
        await self._send_getaddr(peer)
        
        # Send additional feature messages
        await self._send_message(peer, SendHeadersMessage())
        await self._send_message(peer, WTXIDRelayMessage())
        await self._send_message(peer, SendAddrV2Message())
        
        # Start header sync if this is the first peer
        if not self.sync_peer:
            self.sync_peer = peer
            await self._request_headers(peer)
            
    async def _handle_ping(self, peer: PeerConnection, payload: bytes):
        """Handle ping message."""
        ping = PingMessage.deserialize(payload)
        await self._send_pong(peer, ping.nonce)
        
    async def _handle_pong(self, peer: PeerConnection, payload: bytes):
        """Handle pong message."""
        pong = PongMessage.deserialize(payload)
        if pong.nonce == peer.nonce:
            logger.debug(f"Pong received from peer {peer.id}")
        
    async def _handle_addr(self, peer: PeerConnection, payload: bytes):
        """Handle addr message."""
        
        try:
            addr_msg = AddrMessage.deserialize(payload)
            
            for timestamp, addr in addr_msg.addrs:
                addr_str = addr.to_string_addr_port()
                if addr_str not in self.known_addresses and addr_str not in self.tried_addresses:
                    self.known_addresses.add(addr_str)
            
            logger.debug(f"Received {len(addr_msg.addrs)} addresses from peer {peer.id}")
            
        except Exception as e:
            logger.warning(f"Error parsing addr from peer {peer.id}: {e}")
        
    async def _handle_headers(self, peer: PeerConnection, payload: bytes):
        """Handle headers message."""
        
        try:
            headers_msg = HeadersMessage.deserialize(payload)
            
            if not headers_msg.headers:
                logger.info(f"No more headers from peer {peer.id}")
                self.headers_synced = True
                return
            
            # Process headers
            for header in headers_msg.headers:
                self.headers.append(header)
                self.best_height += 1
                self.best_hash = header.get_hash().data  # Store raw bytes
            
            logger.info(f"Received {len(headers_msg.headers)} headers, "
                       f"best height: {self.best_height}")
            
            # Request more headers
            if len(headers_msg.headers) == 2000:  # Maximum per message
                await self._request_headers(peer, [self.best_hash])
            else:
                self.headers_synced = True
                logger.info(f"Headers sync complete, height: {self.best_height}")
                
        except Exception as e:
            logger.warning(f"Error parsing headers from peer {peer.id}: {e}")
    
    async def _handle_inv(self, peer: PeerConnection, payload: bytes):
        """Handle inv message."""
        inv_msg = InvMessage.deserialize(payload)
        logger.debug(f"Received {len(inv_msg.invs)} inventory items from peer {peer.id}")
        
    async def _handle_block(self, peer: PeerConnection, payload: bytes):
        """Handle block message."""
        logger.debug(f"Received block from peer {peer.id}")
        
    async def _handle_tx(self, peer: PeerConnection, payload: bytes):
        """Handle tx message."""
        logger.debug(f"Received transaction from peer {peer.id}")
        
    # ==========================================================================
    # Sync Tasks
    # ==========================================================================
    
    async def _request_headers(self, peer: PeerConnection, locator_hashes: List[bytes] = None):
        """Request block headers from peer."""
        
        if locator_hashes is None:
            # Build locator from our headers
            if self.headers:
                locator_hashes = [self.best_hash]
                # Add more hashes going back (exponentially)
                step = 1
                for i in range(len(self.headers) - 1, -1, -step):
                    locator_hashes.append(self.headers[i].get_hash().data)
                    if len(locator_hashes) >= 10:
                        step *= 2
            else:
                # Use genesis
                genesis_hash = bytes.fromhex(self.chain_params.genesis_hash)[::-1]
                locator_hashes = [genesis_hash]
        
        await self._send_getheaders(peer, locator_hashes)
        
    async def _sync_task(self):
        """Background sync task."""
        
        while self.running:
            await asyncio.sleep(30)
            
            # Check if we need more peers
            if len(self.peers) < self.max_peers // 2:
                await self._connect_to_peers()
            
            # Continue header sync if needed
            if not self.headers_synced and self.sync_peer and self.sync_peer.connected:
                await self._request_headers(self.sync_peer)
                
    async def _ping_task(self):
        """Background ping task."""
        
        while self.running:
            await asyncio.sleep(60)
            
            for peer in list(self.peers.values()):
                if peer.connected and peer.handshake_complete:
                    await self._send_ping(peer)
    
    # ==========================================================================
    # RPC Interface
    # ==========================================================================
    
    def getblockchaininfo(self, request=None) -> Dict[str, Any]:
        """Get blockchain info."""
        return {
            "chain": self.chain_params.name,
            "blocks": self.best_height,
            "headers": self.best_height,
            "bestblockhash": self.best_hash[::-1].hex() if self.best_hash else "",
            "difficulty": 1.0,  # Would calculate from headers
            "mediantime": int(time.time()),
            "verificationprogress": 1.0 if self.headers_synced else self.best_height / 850000,
            "initialblockdownload": not self.headers_synced,
            "chainwork": "0" * 64,
            "size_on_disk": 0,
            "pruned": False,
        }
    
    def getnetworkinfo(self, request=None) -> Dict[str, Any]:
        """Get network info."""
        return {
            "version": 270000,
            "subversion": self.user_agent,
            "protocolversion": PROTOCOL_VERSION,
            "connections": len(self.peers),
            "connections_in": 0,
            "connections_out": len(self.peers),
            "networkactive": True,
            "relayfee": 0.00001,
        }
    
    def getpeerinfo(self, request=None) -> List[Dict[str, Any]]:
        """Get peer info."""
        result = []
        for peer in self.peers.values():
            result.append({
                "id": peer.id,
                "addr": peer.address.to_string_addr_port(),
                "services": hex(peer.services),
                "version": peer.version,
                "subver": peer.user_agent,
                "startingheight": peer.start_height,
                "bytesrecv": peer.bytes_recv,
                "bytessent": peer.bytes_sent,
                "connetime": int(peer.last_recv),
            })
        return result
    
    def getblockheader(self, request) -> Dict[str, Any]:
        """Get block header."""
        if not request or not request.params:
            raise ValueError("Missing block hash parameter")
        
        block_hash = request.params[0]
        
        # Search for header
        for idx, header in enumerate(self.headers):
            header_hash = header.get_hash().data[::-1].hex()
            if header_hash == block_hash:
                return {
                    "hash": block_hash,
                    "confirmations": self.best_height - idx,
                    "height": idx,
                    "version": header.n_version,
                    "merkleroot": header.hash_merkle_root.data[::-1].hex(),
                    "time": header.n_time,
                    "nonce": header.n_nonce,
                    "bits": hex(header.n_bits),
                }
        
        raise ValueError("Block not found")
    
    def getblockcount(self, request=None) -> int:
        """Get block count."""
        return self.best_height
    
    def getblockhash(self, request) -> str:
        """Get block hash at height."""
        if not request or not request.params:
            raise ValueError("Missing height parameter")
        
        height = request.params[0]
        
        if height < 0 or height >= len(self.headers):
            raise ValueError("Block height out of range")
        
        return self.headers[height].get_hash().data[::-1].hex()


# ==============================================================================
# Global Node Instance
# ==============================================================================

_node_instance: Optional[BitcoinNode] = None


def get_node() -> Optional[BitcoinNode]:
    """Get the global node instance."""
    return _node_instance


def set_node(node: BitcoinNode):
    """Set the global node instance."""
    global _node_instance
    _node_instance = node


# ==============================================================================
# Main Entry Point
# ==============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="bitcoind-py",
        description="Bitcoin Core Python - A Python implementation of Bitcoin Core",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Network selection
    parser.add_argument(
        "--regtest",
        action="store_true",
        help="Use regtest network"
    )
    parser.add_argument(
        "--testnet",
        action="store_true",
        help="Use testnet3 network"
    )
    parser.add_argument(
        "--testnet4",
        action="store_true",
        help="Use testnet4 network"
    )
    parser.add_argument(
        "--signet",
        action="store_true",
        help="Use signet network"
    )
    
    # RPC options
    parser.add_argument(
        "--rpcport",
        type=int,
        default=None,
        help="RPC server port"
    )
    parser.add_argument(
        "--rpcuser",
        default=None,
        help="RPC username (default: auto-generated)"
    )
    parser.add_argument(
        "--rpcpassword",
        default=None,
        help="RPC password (default: auto-generated)"
    )
    parser.add_argument(
        "--rpcallowip",
        action="append",
        default=[],
        help="Allow RPC connections from IP"
    )
    
    # Connection options
    parser.add_argument(
        "--connect",
        action="append",
        default=[],
        help="Connect only to specified node(s)"
    )
    parser.add_argument(
        "--addnode",
        action="append",
        default=[],
        help="Add a node to connect to"
    )
    parser.add_argument(
        "--dnsseed",
        action="store_true",
        default=True,
        help="Use DNS seeds (default: True)"
    )
    
    # General options
    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Run as daemon"
    )
    parser.add_argument(
        "--datadir",
        help="Data directory for blockchain storage"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    parser.add_argument(
        "--printtoconsole",
        action="store_true",
        help="Print to console"
    )
    parser.add_argument(
        "--version", "-v",
        action="store_true",
        help="Show version"
    )
    
    return parser


def register_rpc_commands(node: BitcoinNode):
    """Register RPC commands."""
    
    commands = [
        ("getblockchaininfo", node.getblockchaininfo),
        ("getnetworkinfo", node.getnetworkinfo),
        ("getpeerinfo", node.getpeerinfo),
        ("getblockheader", node.getblockheader),
        ("getblockcount", node.getblockcount),
        ("getblockhash", node.getblockhash),
    ]
    
    for name, handler in commands:
        command = CRPCCommand(
            category=name[:4],
            name=name,
            actor=handler
        )
        tableRPC.append_command(name, command)
    
    logger.info(f"Registered {len(commands)} RPC commands")


async def run_node_async(args):
    """Run the node asynchronously."""
    
    # Determine chain
    chain = 'main'
    if args.regtest:
        chain = 'regtest'
    elif args.testnet:
        chain = 'test'
    elif args.testnet4:
        chain = 'testnet4'
    elif args.signet:
        chain = 'signet'
    
    # Generate random RPC credentials if not provided
    rpc_user = args.rpcuser if args.rpcuser else secrets.token_hex(8)
    rpc_password = args.rpcpassword if args.rpcpassword else secrets.token_hex(16)
    
    # Write cookie file for RPC authentication
    cookie_dir = Path(args.datadir) if args.datadir else Path(".")
    cookie_dir.mkdir(parents=True, exist_ok=True)
    cookie_path = cookie_dir / ".cookie"
    cookie_path.write_text(f"{rpc_user}:{rpc_password}\n")
    
    logger.info(f"RPC credentials: user={rpc_user}")
    logger.info(f"Cookie file written to: {cookie_path}")
    
    # Create node
    node = BitcoinNode(
        chain=chain,
        rpc_port=args.rpcport,
        rpc_user=rpc_user,
        rpc_password=rpc_password
    )
    
    set_node(node)
    
    # Add manual nodes
    for addr in args.addnode:
        node.add_node(addr)
    
    # If connect is specified, only connect to those nodes
    for addr in args.connect:
        node.add_node(addr)
        node.max_peers = len(args.connect)
    
    # Register RPC commands
    register_rpc_commands(node)
    
    # Start RPC server
    start_rpc()
    set_rpc_warmup_finished()
    
    # Create authenticator
    authenticator = RPCAuthenticator()
    authenticator.set_cookie(args.rpcuser, args.rpcpassword)
    
    # Create HTTP server config
    config = HTTPServerConfig(
        host="0.0.0.0" if args.rpcallowip else "127.0.0.1",
        port=node.rpc_port,
    )
    
    # Run node and RPC server concurrently
    node_task = asyncio.create_task(node.start())
    
    # Start RPC server
    from bitcoin.rpc.httpserver import run_server_async
    
    try:
        await asyncio.gather(
            node_task,
            run_server_async(config, authenticator)
        )
    except asyncio.CancelledError:
        pass
    finally:
        await node.stop()


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Show version
    if args.version:
        print("Bitcoin Core Python v0.1.0")
        return 0
    
    # Set debug logging
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Determine chain
    chain = 'main'
    if args.regtest:
        chain = 'regtest'
    elif args.testnet:
        chain = 'test'
    elif args.testnet4:
        chain = 'testnet4'
    elif args.signet:
        chain = 'signet'
    
    # Get chain params for default RPC port
    chain_params = CHAIN_PARAMS.get(chain, CHAIN_PARAMS['main'])
    if args.rpcport is None:
        args.rpcport = chain_params.rpc_port
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║           Bitcoin Core Python v0.1.0                         ║
╠══════════════════════════════════════════════════════════════╣
║  Network: {chain:<52} ║
║  RPC Port: {args.rpcport:<51} ║
║  RPC User: {args.rpcuser:<51} ║
║  DNS Seeds: {'Enabled' if args.dnsseed else 'Disabled':<49} ║
╠══════════════════════════════════════════════════════════════╣
║  Press Ctrl+C to stop                                        ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Handle signals
    def signal_handler(sig, frame):
        print("\nShutting down...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run the async event loop
    try:
        asyncio.run(run_node_async(args))
    except KeyboardInterrupt:
        pass
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
