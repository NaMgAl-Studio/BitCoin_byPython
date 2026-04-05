"""
Tests for Bitcoin Primitives Module
===================================

Tests for transaction, block, and other primitive data structures.
"""

import pytest

from bitcoin.primitives.transaction import (
    OutPoint,
    TxIn,
    TxOut,
    Transaction,
    MutableTransaction,
    Txid,
    Wtxid,
    NULL_INDEX,
    SEQUENCE_FINAL,
    encode_compact_size,
    decode_compact_size,
)
from bitcoin.primitives.block import (
    BlockHeader,
    Block,
    BlockLocator,
    uint256,
)


class TestOutPoint:
    """Tests for OutPoint class."""
    
    def test_null_outpoint(self):
        """Test null outpoint creation."""
        op = OutPoint.null()
        assert op.is_null()
        assert op.hash.is_null()
        assert op.n == NULL_INDEX
    
    def test_outpoint_creation(self):
        """Test regular outpoint creation."""
        txid = Txid.from_hex("0" * 64)
        op = OutPoint(hash=txid, n=0)
        assert not op.is_null()
        assert op.n == 0
    
    def test_outpoint_comparison(self):
        """Test outpoint ordering."""
        txid1 = Txid.null()
        txid2 = Txid.from_hex("0" * 63 + "1")
        
        op1 = OutPoint(hash=txid1, n=0)
        op2 = OutPoint(hash=txid1, n=1)
        op3 = OutPoint(hash=txid2, n=0)
        
        assert op1 < op2
        assert op1 < op3
        assert op2 < op3


class TestTxIn:
    """Tests for TxIn class."""
    
    def test_coinbase_input(self):
        """Test coinbase input creation."""
        prevout = OutPoint.null()
        script_sig = b"coinbase data"
        txin = TxIn(prevout=prevout, script_sig=script_sig)
        
        assert txin.prevout.is_null()
        assert txin.n_sequence == SEQUENCE_FINAL
    
    def test_regular_input(self):
        """Test regular input creation."""
        txid = Txid.null()
        prevout = OutPoint(hash=txid, n=0)
        script_sig = b"\x47\x30\x44..."  # Dummy script
        
        txin = TxIn(prevout=prevout, script_sig=script_sig, n_sequence=0xFFFFFFFE)
        
        assert not txin.prevout.is_null()
        assert txin.n_sequence == 0xFFFFFFFE


class TestTxOut:
    """Tests for TxOut class."""
    
    def test_null_output(self):
        """Test null output."""
        txout = TxOut(n_value=-1, script_pub_key=b"")
        assert txout.is_null()
    
    def test_regular_output(self):
        """Test regular output."""
        txout = TxOut(n_value=100_000_000, script_pub_key=b"\x76\xa9\x14...")
        assert not txout.is_null()
        assert txout.n_value == 100_000_000  # 1 BTC in satoshis


class TestTransaction:
    """Tests for Transaction class."""
    
    def test_empty_transaction(self):
        """Test empty transaction creation."""
        tx = Transaction()
        assert tx.is_null()
        assert len(tx.vin) == 0
        assert len(tx.vout) == 0
    
    def test_coinbase_transaction(self):
        """Test coinbase transaction detection."""
        coinbase_input = TxIn(prevout=OutPoint.null())
        coinbase_output = TxOut(n_value=50 * 100_000_000)
        
        tx = Transaction(vin=[coinbase_input], vout=[coinbase_output])
        
        assert tx.is_coinbase()
        assert tx.get_value_out() == 50 * 100_000_000
    
    def test_transaction_hash(self):
        """Test transaction hash computation."""
        tx = Transaction(
            version=2,
            vin=[TxIn(prevout=OutPoint.null())],
            vout=[TxOut(n_value=1_000_000)],
            n_lock_time=0,
        )
        
        # Hash should be computed
        txid = tx.txid
        assert isinstance(txid, Txid)
        assert len(txid.data) == 32
    
    def test_transaction_serialization(self):
        """Test transaction serialization roundtrip."""
        # Create a simple transaction
        txin = TxIn(
            prevout=OutPoint(hash=Txid.null(), n=0),
            script_sig=b"\x48\x30\x45...",  # Dummy signature
        )
        txout = TxOut(n_value=1_000_000, script_pub_key=b"\x76\xa9\x14...")
        
        tx = Transaction(
            version=2,
            vin=[txin],
            vout=[txout],
            n_lock_time=0,
        )
        
        # Serialize
        serialized = tx.serialize(with_witness=False)
        
        # Deserialize
        tx2, consumed = Transaction.deserialize(serialized)
        
        assert tx2.version == tx.version
        assert len(tx2.vin) == len(tx.vin)
        assert len(tx2.vout) == len(tx.vout)
        assert tx2.n_lock_time == tx.n_lock_time


class TestCompactSize:
    """Tests for compact size encoding."""
    
    @pytest.mark.parametrize("value", [0, 1, 127, 252, 253, 65535, 65536, 0xFFFFFFFF])
    def test_compact_size_roundtrip(self, value: int):
        """Test compact size encoding/decoding roundtrip."""
        encoded = encode_compact_size(value)
        decoded, consumed = decode_compact_size(encoded)
        
        assert decoded == value
    
    def test_compact_size_sizes(self):
        """Test compact size encoding sizes."""
        # 0-252: 1 byte
        assert len(encode_compact_size(0)) == 1
        assert len(encode_compact_size(252)) == 1
        
        # 253-65535: 3 bytes
        assert len(encode_compact_size(253)) == 3
        assert len(encode_compact_size(65535)) == 3
        
        # 65536-0xFFFFFFFF: 5 bytes
        assert len(encode_compact_size(65536)) == 5
        assert len(encode_compact_size(0xFFFFFFFF)) == 5


class TestBlockHeader:
    """Tests for BlockHeader class."""
    
    def test_null_header(self):
        """Test null header creation."""
        header = BlockHeader()
        assert header.is_null()
        assert header.n_bits == 0
    
    def test_header_hash(self):
        """Test block header hash computation."""
        header = BlockHeader(
            n_version=1,
            hash_prev_block=uint256.null(),
            hash_merkle_root=uint256.null(),
            n_time=1234567890,
            n_bits=0x1d00ffff,
            n_nonce=0,
        )
        
        block_hash = header.get_hash()
        assert isinstance(block_hash, uint256)
        assert len(block_hash.data) == 32


class Testuint256:
    """Tests for uint256 class."""
    
    def test_null(self):
        """Test null/zero uint256."""
        n = uint256.null()
        assert n.is_null()
        assert n.data == b'\x00' * 32
    
    def test_one(self):
        """Test uint256 with value 1."""
        n = uint256.one()
        assert not n.is_null()
        assert n.data == b'\x01' + b'\x00' * 31
    
    def test_hex_roundtrip(self):
        """Test hex conversion roundtrip."""
        hex_str = "0" * 63 + "1"
        n = uint256.from_hex(hex_str)
        
        result = n.to_hex()
        assert result == hex_str
    
    def test_comparison(self):
        """Test uint256 comparison."""
        n1 = uint256.null()
        n2 = uint256.one()
        
        assert n1 < n2
        assert n1 == uint256.null()
        assert n2 == uint256.one()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
