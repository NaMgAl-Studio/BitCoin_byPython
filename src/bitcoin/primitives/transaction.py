"""
Bitcoin Transaction Primitives
==============================

This module implements the transaction-related data structures from Bitcoin Core:
- OutPoint: A reference to a specific output of a transaction
- TxIn: Transaction input (references previous output + scriptSig + sequence)
- TxOut: Transaction output (value + scriptPubKey)
- Transaction: Immutable transaction with cached hash
- MutableTransaction: Mutable version for construction

The implementation follows Bitcoin Core's src/primitives/transaction.h

Copyright (c) 2009-2010 Satoshi Nakamoto
Copyright (c) 2009-present The Bitcoin Core developers
Distributed under the MIT software license.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar, List, Optional, Tuple

if TYPE_CHECKING:
    from .block import Block

from ..consensus.amount import MAX_MONEY, COIN, CAmount, MoneyRange
from ..crypto.sha256 import sha256, double_sha256
from ..util.strencodings import HexStr, hex_to_bytes

# =============================================================================
# Transaction Identifier Types
# =============================================================================

@dataclass(frozen=True, order=True)
class Txid:
    """
    Transaction identifier (txid) - 256-bit hash of the transaction (without witness).
    
    The txid is the double SHA256 hash of the serialization of the transaction
    without witness data. It is displayed in reverse byte order (little-endian
    as a number).
    
    This corresponds to Bitcoin Core's `Txid` type.
    """
    data: bytes  # 32 bytes
    
    def __post_init__(self):
        if len(self.data) != 32:
            raise ValueError(f"Txid must be 32 bytes, got {len(self.data)}")
    
    @classmethod
    def from_hex(cls, hex_str: str) -> Txid:
        """Create Txid from hex string (reverse byte order for display)."""
        data = bytes.fromhex(hex_str)
        # Reverse for internal representation (Bitcoin displays in reverse)
        return cls(data[::-1])
    
    def to_hex(self) -> str:
        """Convert to hex string (reverse byte order for display)."""
        return self.data[::-1].hex()
    
    def __str__(self) -> str:
        return self.to_hex()
    
    def __repr__(self) -> str:
        return f"Txid({self.to_hex()})"
    
    def is_null(self) -> bool:
        """Check if this is the null/zero txid."""
        return self.data == b'\x00' * 32
    
    @classmethod
    def null(cls) -> Txid:
        """Create the null/zero txid."""
        return cls(b'\x00' * 32)
    
    def to_uint256(self) -> bytes:
        """Get the raw 256-bit value."""
        return self.data


@dataclass(frozen=True, order=True)
class Wtxid:
    """
    Witness transaction identifier (wtxid) - 256-bit hash including witness data.
    
    The wtxid is the double SHA256 hash of the full serialization including
    witness data. For transactions without witness, wtxid == txid.
    
    This corresponds to Bitcoin Core's `Wtxid` type.
    """
    data: bytes  # 32 bytes
    
    def __post_init__(self):
        if len(self.data) != 32:
            raise ValueError(f"Wtxid must be 32 bytes, got {len(self.data)}")
    
    @classmethod
    def from_hex(cls, hex_str: str) -> Wtxid:
        """Create Wtxid from hex string (reverse byte order for display)."""
        data = bytes.fromhex(hex_str)
        return cls(data[::-1])
    
    def to_hex(self) -> str:
        """Convert to hex string (reverse byte order for display)."""
        return self.data[::-1].hex()
    
    def __str__(self) -> str:
        return self.to_hex()
    
    def __repr__(self) -> str:
        return f"Wtxid({self.to_hex()})"
    
    def is_null(self) -> bool:
        """Check if this is the null/zero wtxid."""
        return self.data == b'\x00' * 32
    
    @classmethod
    def null(cls) -> Wtxid:
        """Create the null/zero wtxid."""
        return cls(b'\x00' * 32)


# =============================================================================
# OutPoint - Reference to a transaction output
# =============================================================================

# NULL_INDEX constant - maximum uint32 value
NULL_INDEX: int = 0xFFFFFFFF


@dataclass
class OutPoint:
    """
    An outpoint - a combination of a transaction hash and an index n into its vout.
    
    This uniquely identifies a specific output of a specific transaction.
    
    Corresponds to Bitcoin Core's COutPoint class.
    
    Attributes:
        hash: The txid of the transaction containing the output
        n: The index of the output in the transaction's vout list
    """
    hash: Txid
    n: int  # uint32_t in C++
    
    def __post_init__(self):
        if self.n < 0 or self.n > 0xFFFFFFFF:
            raise ValueError(f"OutPoint index must be uint32, got {self.n}")
    
    def is_null(self) -> bool:
        """Check if this is a null outpoint (used for coinbase inputs)."""
        return self.hash.is_null() and self.n == NULL_INDEX
    
    @classmethod
    def null(cls) -> OutPoint:
        """Create a null outpoint."""
        return cls(hash=Txid.null(), n=NULL_INDEX)
    
    def serialize(self) -> bytes:
        """Serialize the outpoint."""
        return self.hash.data + struct.pack('<I', self.n)
    
    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> Tuple[OutPoint, int]:
        """Deserialize an outpoint from bytes. Returns (outpoint, bytes_consumed)."""
        txid = Txid(data[offset:offset + 32])
        n = struct.unpack('<I', data[offset + 32:offset + 36])[0]
        return cls(hash=txid, n=n), 36
    
    def __str__(self) -> str:
        return f"OutPoint({self.hash.to_hex()[:10]}..., {self.n})"
    
    def __hash__(self) -> int:
        return hash((self.hash.data, self.n))
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, OutPoint):
            return NotImplemented
        return self.hash == other.hash and self.n == other.n
    
    def __lt__(self, other: OutPoint) -> bool:
        return (self.hash.data, self.n) < (other.hash.data, other.n)


# =============================================================================
# Sequence Constants (BIP 68, 112)
# =============================================================================

# Setting nSequence to this value for every input in a transaction
# disables nLockTime/IsFinalTx()
SEQUENCE_FINAL: int = 0xFFFFFFFF

# This is the maximum sequence number that enables both nLockTime and
# OP_CHECKLOCKTIMEVERIFY (BIP 65)
MAX_SEQUENCE_NONFINAL: int = SEQUENCE_FINAL - 1

# If this flag is set, CTxIn::nSequence is NOT interpreted as a
# relative lock-time (BIP 68)
SEQUENCE_LOCKTIME_DISABLE_FLAG: int = (1 << 31)

# If CTxIn::nSequence encodes a relative lock-time and this flag
# is set, the relative lock-time has units of 512 seconds,
# otherwise it specifies blocks with a granularity of 1
SEQUENCE_LOCKTIME_TYPE_FLAG: int = (1 << 22)

# If CTxIn::nSequence encodes a relative lock-time, this mask is
# applied to extract that lock-time from the sequence field
SEQUENCE_LOCKTIME_MASK: int = 0x0000FFFF

# Converting from CTxIn::nSequence to seconds is performed by
# multiplying by 512 = 2^9
SEQUENCE_LOCKTIME_GRANULARITY: int = 9


# =============================================================================
# ScriptWitness - Witness data for a single input
# =============================================================================

@dataclass
class TransactionWitness:
    """
    Witness data for a single transaction input.
    
    This is a stack of byte arrays (scripts/signatures) that constitute
    the witness for a SegWit input.
    
    Corresponds to Bitcoin Core's CScriptWitness.
    """
    stack: List[bytes] = field(default_factory=list)
    
    def is_null(self) -> bool:
        """Check if witness is empty/null."""
        return len(self.stack) == 0 or all(len(item) == 0 for item in self.stack)
    
    def serialize(self) -> bytes:
        """Serialize the witness stack."""
        result = encode_compact_size(len(self.stack))
        for item in self.stack:
            result += encode_compact_size(len(item))
            result += item
        return result
    
    def __str__(self) -> str:
        if self.is_null():
            return "Witness:{}"
        items = [HexStr(item) for item in self.stack]
        return f"Witness:{items}"


# =============================================================================
# TxIn - Transaction Input
# =============================================================================

@dataclass
class TxIn:
    """
    An input of a transaction.
    
    It contains the location of the previous transaction's output that it claims
    and a signature that matches the output's public key.
    
    Corresponds to Bitcoin Core's CTxIn class.
    
    Attributes:
        prevout: The previous output being spent
        script_sig: The script signature (unlocking script)
        n_sequence: Sequence number (for RBF, relative locktime)
        script_witness: Witness data (for SegWit)
    """
    prevout: OutPoint
    script_sig: bytes = field(default_factory=bytes)
    n_sequence: int = SEQUENCE_FINAL
    script_witness: TransactionWitness = field(default_factory=TransactionWitness)
    
    def __post_init__(self):
        if isinstance(self.script_sig, str):
            self.script_sig = bytes.fromhex(self.script_sig)
        if self.n_sequence < 0 or self.n_sequence > 0xFFFFFFFF:
            raise ValueError(f"Sequence must be uint32, got {self.n_sequence}")
    
    def serialize(self, include_witness: bool = False) -> bytes:
        """Serialize the transaction input."""
        result = self.prevout.serialize()
        result += encode_compact_size(len(self.script_sig))
        result += self.script_sig
        result += struct.pack('<I', self.n_sequence)
        return result
    
    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> Tuple[TxIn, int]:
        """Deserialize a transaction input from bytes."""
        prevout, consumed = OutPoint.deserialize(data, offset)
        offset += consumed
        
        script_len, varint_size = decode_compact_size(data, offset)
        offset += varint_size
        script_sig = data[offset:offset + script_len]
        offset += script_len
        
        n_sequence = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4
        
        return cls(prevout=prevout, script_sig=script_sig, n_sequence=n_sequence), offset - (offset - consumed - varint_size - script_len - 4)
    
    def __str__(self) -> str:
        if self.prevout.is_null():
            return f"TxIn(coinbase: {HexStr(self.script_sig)})"
        script_str = HexStr(self.script_sig)[:24]
        result = f"TxIn({self.prevout}, scriptSig={script_str}"
        if self.n_sequence != SEQUENCE_FINAL:
            result += f", nSequence={self.n_sequence}"
        result += ")"
        return result
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TxIn):
            return NotImplemented
        return (self.prevout == other.prevout and 
                self.script_sig == other.script_sig and 
                self.n_sequence == other.n_sequence)


# =============================================================================
# TxOut - Transaction Output
# =============================================================================

@dataclass
class TxOut:
    """
    An output of a transaction.
    
    It contains the public key that the next input must be able to sign with to claim it.
    
    Corresponds to Bitcoin Core's CTxOut class.
    
    Attributes:
        n_value: The amount in satoshis
        script_pub_key: The script public key (locking script)
    """
    n_value: CAmount  # in satoshis, can be negative (-1) for null
    script_pub_key: bytes = field(default_factory=bytes)
    
    def __post_init__(self):
        if isinstance(self.script_pub_key, str):
            self.script_pub_key = bytes.fromhex(self.script_pub_key)
    
    def is_null(self) -> bool:
        """Check if this is a null output (value = -1)."""
        return self.n_value == -1
    
    def set_null(self) -> None:
        """Set this output to null."""
        self.n_value = -1
        self.script_pub_key = b''
    
    def serialize(self) -> bytes:
        """Serialize the transaction output."""
        result = struct.pack('<q', self.n_value)  # int64_t
        result += encode_compact_size(len(self.script_pub_key))
        result += self.script_pub_key
        return result
    
    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> Tuple[TxOut, int]:
        """Deserialize a transaction output from bytes."""
        n_value = struct.unpack('<q', data[offset:offset + 8])[0]
        offset += 8
        
        script_len, varint_size = decode_compact_size(data, offset)
        offset += varint_size
        script_pub_key = data[offset:offset + script_len]
        offset += script_len
        
        return cls(n_value=n_value, script_pub_key=script_pub_key), 8 + varint_size + script_len
    
    def __str__(self) -> str:
        btc_value = self.n_value / COIN
        script_str = HexStr(self.script_pub_key)[:30]
        return f"TxOut(nValue={btc_value:.8f} BTC, scriptPubKey={script_str})"
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TxOut):
            return NotImplemented
        return self.n_value == other.n_value and self.script_pub_key == other.script_pub_key


# =============================================================================
# Transaction - Immutable Transaction
# =============================================================================

# Default transaction version
CURRENT_VERSION: int = 2


@dataclass
class Transaction:
    """
    The basic transaction that is broadcasted on the network and contained in blocks.
    
    A transaction can contain multiple inputs and outputs. This class is immutable
    with cached hash values.
    
    Corresponds to Bitcoin Core's CTransaction class.
    
    Attributes:
        version: Transaction version (currently 2)
        vin: List of transaction inputs
        vout: List of transaction outputs
        n_lock_time: Lock time (block height or unix timestamp)
    """
    version: int = CURRENT_VERSION
    vin: List[TxIn] = field(default_factory=list)
    vout: List[TxOut] = field(default_factory=list)
    n_lock_time: int = 0
    
    # Cached values
    _has_witness: Optional[bool] = field(default=None, repr=False, compare=False)
    _txid: Optional[Txid] = field(default=None, repr=False, compare=False)
    _wtxid: Optional[Wtxid] = field(default=None, repr=False, compare=False)
    _total_size: Optional[int] = field(default=None, repr=False, compare=False)
    
    def __post_init__(self):
        # Validate version
        if self.version < 1 or self.version > 0xFFFFFFFF:
            raise ValueError(f"Invalid transaction version: {self.version}")
        if self.n_lock_time < 0 or self.n_lock_time > 0xFFFFFFFF:
            raise ValueError(f"Invalid lock time: {self.n_lock_time}")
    
    @property
    def has_witness(self) -> bool:
        """Check if transaction has witness data."""
        if self._has_witness is None:
            self._has_witness = any(
                not txin.script_witness.is_null() for txin in self.vin
            )
        return self._has_witness
    
    def compute_hash(self) -> Txid:
        """Compute the txid (hash without witness)."""
        if self._txid is None:
            serialized = self.serialize(with_witness=False)
            self._txid = Txid(double_sha256(serialized))
        return self._txid
    
    def compute_witness_hash(self) -> Wtxid:
        """Compute the wtxid (hash with witness)."""
        if self._wtxid is None:
            if not self.has_witness:
                self._wtxid = Wtxid(self.compute_hash().data)
            else:
                serialized = self.serialize(with_witness=True)
                self._wtxid = Wtxid(double_sha256(serialized))
        return self._wtxid
    
    @property
    def txid(self) -> Txid:
        """Get the transaction ID (cached)."""
        return self.compute_hash()
    
    @property
    def wtxid(self) -> Wtxid:
        """Get the witness transaction ID (cached)."""
        return self.compute_witness_hash()
    
    def is_null(self) -> bool:
        """Check if transaction is empty."""
        return len(self.vin) == 0 and len(self.vout) == 0
    
    def is_coinbase(self) -> bool:
        """Check if this is a coinbase transaction."""
        return len(self.vin) == 1 and self.vin[0].prevout.is_null()
    
    def get_value_out(self) -> CAmount:
        """Get the total output value in satoshis."""
        total: CAmount = 0
        for txout in self.vout:
            if not MoneyRange(txout.n_value):
                raise ValueError("Transaction output value out of range")
            if not MoneyRange(total + txout.n_value):
                raise ValueError("Transaction total output value out of range")
            total += txout.n_value
        return total
    
    def compute_total_size(self) -> int:
        """Compute the total serialized size including witness."""
        return len(self.serialize(with_witness=True))
    
    def compute_weight(self) -> int:
        """
        Compute the transaction weight.
        
        Weight = (stripped_size * 4) + witness_size
               = (stripped_size * 3) + total_size
        
        See BIP 141.
        """
        stripped_size = len(self.serialize(with_witness=False))
        total_size = self.compute_total_size()
        return stripped_size * 3 + total_size
    
    def compute_vsize(self) -> int:
        """Compute the virtual size (weight / 4, rounded up)."""
        return (self.compute_weight() + 3) // 4
    
    def serialize(self, with_witness: bool = True) -> bytes:
        """
        Serialize the transaction.
        
        Args:
            with_witness: If True, include witness data (for wtxid).
                         If False, serialize without witness (for txid).
        """
        result = struct.pack('<I', self.version)
        
        if with_witness and self.has_witness:
            # Extended format with witness
            # Write marker and flag
            result += b'\x00'  # marker (empty vin dummy)
            result += b'\x01'  # flag (witness present)
            
            # Write inputs
            result += encode_compact_size(len(self.vin))
            for txin in self.vin:
                result += txin.serialize()
            
            # Write outputs
            result += encode_compact_size(len(self.vout))
            for txout in self.vout:
                result += txout.serialize()
            
            # Write witness data
            for txin in self.vin:
                result += txin.script_witness.serialize()
        else:
            # Standard format without witness
            result += encode_compact_size(len(self.vin))
            for txin in self.vin:
                result += txin.serialize()
            
            result += encode_compact_size(len(self.vout))
            for txout in self.vout:
                result += txout.serialize()
        
        result += struct.pack('<I', self.n_lock_time)
        return result
    
    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> Tuple[Transaction, int]:
        """
        Deserialize a transaction from bytes.
        
        Returns:
            Tuple of (Transaction, bytes_consumed)
        """
        start_offset = offset
        
        # Read version
        version = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4
        
        # Check for witness marker
        has_witness = False
        vin_count, varint_size = decode_compact_size(data, offset)
        offset += varint_size
        
        if vin_count == 0 and offset < len(data):
            # Might be witness marker
            flags = data[offset]
            offset += 1
            if flags != 0:
                has_witness = True
                # Re-read actual vin count
                vin_count, varint_size = decode_compact_size(data, offset)
                offset += varint_size
        
        # Read inputs
        vin: List[TxIn] = []
        for _ in range(vin_count):
            txin, consumed = TxIn.deserialize(data, offset)
            offset += consumed
            vin.append(txin)
        
        # Read outputs
        vout_count, varint_size = decode_compact_size(data, offset)
        offset += varint_size
        
        vout: List[TxOut] = []
        for _ in range(vout_count):
            txout, consumed = TxOut.deserialize(data, offset)
            offset += consumed
            vout.append(txout)
        
        # Read witness data if present
        if has_witness:
            for txin in vin:
                # Read witness stack
                stack_items, varint_size = decode_compact_size(data, offset)
                offset += varint_size
                
                stack: List[bytes] = []
                for _ in range(stack_items):
                    item_len, varint_size = decode_compact_size(data, offset)
                    offset += varint_size
                    stack.append(data[offset:offset + item_len])
                    offset += item_len
                
                txin.script_witness = TransactionWitness(stack=stack)
        
        # Read lock time
        n_lock_time = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4
        
        tx = cls(version=version, vin=vin, vout=vout, n_lock_time=n_lock_time)
        tx._has_witness = has_witness
        
        return tx, offset - start_offset
    
    def __str__(self) -> str:
        txid_str = self.txid.to_hex()[:10]
        return (f"Transaction(hash={txid_str}..., ver={self.version}, "
                f"vin.size={len(self.vin)}, vout.size={len(self.vout)}, "
                f"nLockTime={self.n_lock_time})")
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Transaction):
            return NotImplemented
        return self.wtxid == other.wtxid
    
    def __hash__(self) -> int:
        return hash(self.wtxid.data)


# =============================================================================
# MutableTransaction - Mutable version for construction
# =============================================================================

@dataclass
class MutableTransaction:
    """
    A mutable version of Transaction for construction purposes.
    
    Use this to build transactions, then convert to immutable Transaction
    for hashing and validation.
    
    Corresponds to Bitcoin Core's CMutableTransaction.
    """
    version: int = CURRENT_VERSION
    vin: List[TxIn] = field(default_factory=list)
    vout: List[TxOut] = field(default_factory=list)
    n_lock_time: int = 0
    
    def has_witness(self) -> bool:
        """Check if transaction has witness data."""
        return any(not txin.script_witness.is_null() for txin in self.vin)
    
    def get_hash(self) -> Txid:
        """Compute the txid (not cached for mutable transactions)."""
        tx = self.to_transaction()
        return tx.compute_hash()
    
    def to_transaction(self) -> Transaction:
        """Convert to immutable Transaction."""
        return Transaction(
            version=self.version,
            vin=list(self.vin),  # Copy the list
            vout=list(self.vout),  # Copy the list
            n_lock_time=self.n_lock_time
        )
    
    @classmethod
    def from_transaction(cls, tx: Transaction) -> MutableTransaction:
        """Create a mutable copy of a transaction."""
        return cls(
            version=tx.version,
            vin=list(tx.vin),
            vout=list(tx.vout),
            n_lock_time=tx.n_lock_time
        )
    
    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> Tuple[MutableTransaction, int]:
        """Deserialize from bytes."""
        tx, consumed = Transaction.deserialize(data, offset)
        return cls.from_transaction(tx), consumed


# =============================================================================
# Helper Functions for Compact Size Encoding
# =============================================================================

def encode_compact_size(n: int) -> bytes:
    """
    Encode a variable-length integer (compact size).
    
    Bitcoin uses a variable-length encoding for sizes:
    - 0-252: 1 byte (the value itself)
    - 253-65535: 3 bytes (0xFD + 2 bytes little-endian)
    - 65536-4294967295: 5 bytes (0xFE + 4 bytes little-endian)
    - larger: 9 bytes (0xFF + 8 bytes little-endian)
    """
    if n < 0:
        raise ValueError(f"Cannot encode negative size: {n}")
    elif n <= 252:
        return bytes([n])
    elif n <= 0xFFFF:
        return b'\xFD' + struct.pack('<H', n)
    elif n <= 0xFFFFFFFF:
        return b'\xFE' + struct.pack('<I', n)
    else:
        return b'\xFF' + struct.pack('<Q', n)


def decode_compact_size(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """
    Decode a variable-length integer (compact size).
    
    Returns:
        Tuple of (value, bytes_consumed)
    """
    first_byte = data[offset]
    
    if first_byte <= 252:
        return first_byte, 1
    elif first_byte == 0xFD:
        return struct.unpack('<H', data[offset + 1:offset + 3])[0], 3
    elif first_byte == 0xFE:
        return struct.unpack('<I', data[offset + 1:offset + 5])[0], 5
    else:  # 0xFF
        return struct.unpack('<Q', data[offset + 1:offset + 9])[0], 9
