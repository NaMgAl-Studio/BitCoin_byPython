"""
Bitcoin Block Primitives
========================

This module implements the block-related data structures from Bitcoin Core:
- BlockHeader: Contains version, prev_block, merkle_root, time, bits, nonce
- Block: Contains header + list of transactions
- BlockLocator: Used for chain synchronization

The implementation follows Bitcoin Core's src/primitives/block.h

Copyright (c) 2009-2010 Satoshi Nakamoto
Copyright (c) 2009-present The Bitcoin Core developers
Distributed under the MIT software license.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from typing import ClassVar, List, Optional, Tuple

from ..crypto.sha256 import double_sha256
from ..primitives.transaction import Transaction, Txid, encode_compact_size, decode_compact_size
from ..util.strencodings import HexStr


# =============================================================================
# uint256 - 256-bit unsigned integer (blob)
# =============================================================================

@dataclass(frozen=True, order=True)
class uint256:
    """
    256-bit opaque blob.
    
    Note: This type is called uint256 for historical reasons only.
    It is an opaque blob of 256 bits and has no integer operations.
    Use arith_uint256 if integer operations are required.
    
    Corresponds to Bitcoin Core's `uint256` class.
    """
    data: bytes  # 32 bytes
    
    def __post_init__(self):
        if len(self.data) != 32:
            raise ValueError(f"uint256 must be 32 bytes, got {len(self.data)}")
    
    @classmethod
    def from_hex(cls, hex_str: str) -> uint256:
        """Create from hex string (reverse byte order for display)."""
        # Remove 0x prefix if present
        hex_str = hex_str.removeprefix('0x')
        data = bytes.fromhex(hex_str)
        # Reverse for internal representation (Bitcoin displays in reverse)
        return cls(data[::-1])
    
    def to_hex(self) -> str:
        """Convert to hex string (reverse byte order for display)."""
        return self.data[::-1].hex()
    
    def __str__(self) -> str:
        return self.to_hex()
    
    def __repr__(self) -> str:
        return f"uint256({self.to_hex()})"
    
    def is_null(self) -> bool:
        """Check if this is the null/zero value."""
        return self.data == b'\x00' * 32
    
    @classmethod
    def null(cls) -> uint256:
        """Create the null/zero value."""
        return cls(b'\x00' * 32)
    
    @classmethod
    def one(cls) -> uint256:
        """Create uint256 with value 1."""
        return cls(b'\x01' + b'\x00' * 31)
    
    @classmethod
    def from_uint64_le(cls, values: Tuple[int, int, int, int]) -> uint256:
        """Create from four 64-bit values in little-endian order."""
        data = b''.join(struct.pack('<Q', v) for v in values)
        return cls(data)
    
    def get_uint64(self, pos: int) -> int:
        """Get a 64-bit value at the given position (0-3)."""
        return struct.unpack('<Q', self.data[pos * 8:(pos + 1) * 8])[0]


# Constants for uint256
uint256_ZERO = uint256.null()
uint256_ONE = uint256.one()


# =============================================================================
# BlockHeader - 80-byte header
# =============================================================================

@dataclass
class BlockHeader:
    """
    Block header - 80 bytes.
    
    Nodes collect new transactions into a block, hash them into a hash tree,
    and scan through nonce values to make the block's hash satisfy proof-of-work
    requirements.
    
    Corresponds to Bitcoin Core's CBlockHeader.
    
    Attributes:
        n_version: Block version
        hash_prev_block: Hash of previous block in chain
        hash_merkle_root: Merkle root of transactions
        n_time: Unix timestamp
        n_bits: Difficulty target (compact form)
        n_nonce: Nonce for proof-of-work
    """
    n_version: int = 0  # int32_t
    hash_prev_block: uint256 = field(default_factory=uint256.null)
    hash_merkle_root: uint256 = field(default_factory=uint256.null)
    n_time: int = 0  # uint32_t
    n_bits: int = 0  # uint32_t
    n_nonce: int = 0  # uint32_t
    
    def __post_init__(self):
        # Convert hex strings if needed
        if isinstance(self.hash_prev_block, str):
            self.hash_prev_block = uint256.from_hex(self.hash_prev_block)
        if isinstance(self.hash_merkle_root, str):
            self.hash_merkle_root = uint256.from_hex(self.hash_merkle_root)
    
    def is_null(self) -> bool:
        """Check if header is null (n_bits == 0)."""
        return self.n_bits == 0
    
    def set_null(self) -> None:
        """Set header to null."""
        self.n_version = 0
        self.hash_prev_block = uint256.null()
        self.hash_merkle_root = uint256.null()
        self.n_time = 0
        self.n_bits = 0
        self.n_nonce = 0
    
    def get_hash(self) -> uint256:
        """Compute the block hash (double SHA256 of header)."""
        return uint256(double_sha256(self.serialize()))
    
    def get_block_time(self) -> int:
        """Get the block time as a Unix timestamp."""
        return self.n_time
    
    def get_node_seconds(self) -> float:
        """Get block time as seconds since epoch."""
        return float(self.n_time)
    
    def serialize(self) -> bytes:
        """Serialize the 80-byte block header."""
        result = struct.pack('<i', self.n_version)  # int32_t
        result += self.hash_prev_block.data
        result += self.hash_merkle_root.data
        result += struct.pack('<III', self.n_time, self.n_bits, self.n_nonce)
        return result
    
    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> Tuple[BlockHeader, int]:
        """Deserialize a block header from bytes."""
        start = offset
        
        n_version = struct.unpack('<i', data[offset:offset + 4])[0]
        offset += 4
        
        hash_prev_block = uint256(data[offset:offset + 32])
        offset += 32
        
        hash_merkle_root = uint256(data[offset:offset + 32])
        offset += 32
        
        n_time, n_bits, n_nonce = struct.unpack('<III', data[offset:offset + 12])
        offset += 12
        
        return cls(
            n_version=n_version,
            hash_prev_block=hash_prev_block,
            hash_merkle_root=hash_merkle_root,
            n_time=n_time,
            n_bits=n_bits,
            n_nonce=n_nonce
        ), offset - start
    
    def __str__(self) -> str:
        block_hash = self.get_hash()
        return (f"BlockHeader(hash={block_hash.to_hex()[:16]}..., "
                f"ver=0x{self.n_version:08x}, "
                f"prev={self.hash_prev_block.to_hex()[:16]}..., "
                f"merkle={self.hash_merkle_root.to_hex()[:16]}..., "
                f"time={self.n_time}, bits=0x{self.n_bits:08x}, nonce={self.n_nonce})")


# =============================================================================
# Block - Header + Transactions
# =============================================================================

@dataclass
class Block(BlockHeader):
    """
    Complete block with transactions.
    
    Inherits from BlockHeader and adds the list of transactions.
    
    Corresponds to Bitcoin Core's CBlock.
    
    Attributes:
        vtx: List of transactions in the block
        f_checked: Memory-only flag for block validation cache
        m_checked_witness_commitment: Memory-only flag
        m_checked_merkle_root: Memory-only flag
    """
    vtx: List[Transaction] = field(default_factory=list)
    
    # Memory-only flags for caching expensive checks
    f_checked: bool = False
    m_checked_witness_commitment: bool = False
    m_checked_merkle_root: bool = False
    
    @classmethod
    def from_header(cls, header: BlockHeader) -> Block:
        """Create a block from a header."""
        return cls(
            n_version=header.n_version,
            hash_prev_block=header.hash_prev_block,
            hash_merkle_root=header.hash_merkle_root,
            n_time=header.n_time,
            n_bits=header.n_bits,
            n_nonce=header.n_nonce
        )
    
    def set_null(self) -> None:
        """Set block to null."""
        super().set_null()
        self.vtx.clear()
        self.f_checked = False
        self.m_checked_witness_commitment = False
        self.m_checked_merkle_root = False
    
    def serialize(self, with_witness: bool = True) -> bytes:
        """
        Serialize the block.
        
        Args:
            with_witness: Whether to include witness data
        """
        result = super().serialize()  # Header
        result += encode_compact_size(len(self.vtx))
        for tx in self.vtx:
            result += tx.serialize(with_witness=with_witness)
        return result
    
    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> Tuple[Block, int]:
        """Deserialize a block from bytes."""
        header, consumed = BlockHeader.deserialize(data, offset)
        offset += consumed
        
        tx_count, varint_size = decode_compact_size(data, offset)
        offset += varint_size
        
        vtx: List[Transaction] = []
        for _ in range(tx_count):
            tx, consumed = Transaction.deserialize(data, offset)
            offset += consumed
            vtx.append(tx)
        
        block = cls(
            n_version=header.n_version,
            hash_prev_block=header.hash_prev_block,
            hash_merkle_root=header.hash_merkle_root,
            n_time=header.n_time,
            n_bits=header.n_bits,
            n_nonce=header.n_nonce,
            vtx=vtx
        )
        
        return block, offset - (offset - consumed - varint_size - sum(len(tx.serialize()) for tx in vtx))
    
    def compute_merkle_root(self, mutated: bool = False) -> uint256:
        """
        Compute the merkle root of the transactions.
        
        This is imported from consensus.merkle module.
        """
        from ..consensus.merkle import BlockMerkleRoot
        return BlockMerkleRoot(self)
    
    def __str__(self) -> str:
        block_hash = self.get_hash()
        return (f"Block(hash={block_hash.to_hex()}, "
                f"ver=0x{self.n_version:08x}, "
                f"prev={self.hash_prev_block.to_hex()[:16]}..., "
                f"merkle={self.hash_merkle_root.to_hex()[:16]}..., "
                f"time={self.n_time}, bits=0x{self.n_bits:08x}, "
                f"nonce={self.n_nonce}, txs={len(self.vtx)})")


# =============================================================================
# BlockLocator - For chain synchronization
# =============================================================================

@dataclass
class BlockLocator:
    """
    Describes a place in the block chain to another node.
    
    Used for getheaders and getblocks messages to help find a common ancestor.
    The further back it is, the further before the fork it may be.
    
    Corresponds to Bitcoin Core's CBlockLocator.
    
    Attributes:
        v_have: List of block hashes, from most recent backwards
    """
    v_have: List[uint256] = field(default_factory=list)
    
    # Dummy version for serialization compatibility
    DUMMY_VERSION: ClassVar[int] = 70016
    
    def is_null(self) -> bool:
        """Check if locator is empty."""
        return len(self.v_have) == 0
    
    def set_null(self) -> None:
        """Clear the locator."""
        self.v_have.clear()
    
    def serialize(self) -> bytes:
        """Serialize the locator."""
        result = struct.pack('<I', self.DUMMY_VERSION)
        result += encode_compact_size(len(self.v_have))
        for block_hash in self.v_have:
            result += block_hash.data
        return result
    
    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> Tuple[BlockLocator, int]:
        """Deserialize from bytes."""
        start = offset
        
        # Read and discard version
        _version = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4
        
        hash_count, varint_size = decode_compact_size(data, offset)
        offset += varint_size
        
        v_have: List[uint256] = []
        for _ in range(hash_count):
            block_hash = uint256(data[offset:offset + 32])
            offset += 32
            v_have.append(block_hash)
        
        return cls(v_have=v_have), offset - start
    
    def __str__(self) -> str:
        return f"BlockLocator(hashes={len(self.v_have)})"
