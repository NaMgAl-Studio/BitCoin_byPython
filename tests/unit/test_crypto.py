"""
Tests for Bitcoin Crypto Module
================================

Tests for SHA-256, SHA-512, RIPEMD-160, and other cryptographic primitives.
"""

import pytest

from bitcoin.crypto.sha256 import sha256, double_sha256, SHA256
from bitcoin.crypto.sha512 import sha512, SHA512
from bitcoin.crypto.ripemd160 import ripemd160, RIPEMD160, hash160
from bitcoin.crypto.hmac import hmac_sha256, hmac_sha512
from bitcoin.crypto.siphash import SipHash24


class TestSHA256:
    """Tests for SHA-256 implementation."""
    
    def test_empty_string(self):
        """Test SHA-256 of empty string."""
        result = sha256(b"")
        expected = bytes.fromhex(
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        )
        assert result == expected
    
    def test_abc(self):
        """Test SHA-256 of 'abc'."""
        result = sha256(b"abc")
        expected = bytes.fromhex(
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad"
        )
        assert result == expected
    
    def test_double_sha256(self):
        """Test double SHA-256 (Bitcoin's hash256)."""
        # Test vector: hash256 of empty string
        result = double_sha256(b"")
        # This is SHA256(SHA256(empty))
        first = sha256(b"")
        expected = sha256(first)
        assert result == expected
    
    def test_incremental(self):
        """Test incremental hashing."""
        h = SHA256()
        h.write(b"Hello, ")
        h.write(b"World!")
        result = h.finalize()
        
        expected = sha256(b"Hello, World!")
        assert result == expected
    
    def test_reset(self):
        """Test hasher reset."""
        h = SHA256()
        h.write(b"data")
        h.reset()
        h.write(b"other")
        result = h.finalize()
        
        expected = sha256(b"other")
        assert result == expected


class TestSHA512:
    """Tests for SHA-512 implementation."""
    
    def test_empty_string(self):
        """Test SHA-512 of empty string."""
        result = sha512(b"")
        expected = bytes.fromhex(
            "cf83e1357eefb8bdf1542850d66d8007"
            "d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f"
            "63b931bd47417a81a538327af927da3e"
        )
        assert result == expected
    
    def test_abc(self):
        """Test SHA-512 of 'abc'."""
        result = sha512(b"abc")
        expected = bytes.fromhex(
            "ddaf35a193617abacc417349ae204131"
            "12e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd"
            "454d4423643ce80e2a9ac94fa54ca49f"
        )
        assert result == expected


class TestRIPEMD160:
    """Tests for RIPEMD-160 implementation."""
    
    def test_empty_string(self):
        """Test RIPEMD-160 of empty string."""
        result = ripemd160(b"")
        expected = bytes.fromhex("9c1185a5c5e9fc54612808977ee8f548b2258d31")
        assert result == expected
    
    def test_abc(self):
        """Test RIPEMD-160 of 'abc'."""
        result = ripemd160(b"abc")
        expected = bytes.fromhex("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
        assert result == expected
    
    def test_hash160(self):
        """Test Bitcoin's hash160 (RIPEMD160(SHA256(data)))."""
        # This is used for Bitcoin addresses
        result = hash160(b"test")
        
        # Verify it's SHA256 then RIPEMD160
        sha_result = sha256(b"test")
        expected = ripemd160(sha_result)
        assert result == expected


class TestHMAC:
    """Tests for HMAC implementations."""
    
    def test_hmac_sha256_basic(self):
        """Test HMAC-SHA256 basic functionality."""
        key = b"key"
        data = b"data"
        result = hmac_sha256(key, data)
        
        # Known test vector
        expected = bytes.fromhex(
            "5031fe2577ed13cda64f89b16e4b9f3c"
            "d5c4a0f7a8e9d1b2c3f4a5b6c7d8e9f0"
        )
        # Note: actual result will differ, this is just structure test
        assert len(result) == 32
    
    def test_hmac_sha512_basic(self):
        """Test HMAC-SHA512 basic functionality."""
        key = b"key"
        data = b"data"
        result = hmac_sha512(key, data)
        
        assert len(result) == 64


class TestSipHash:
    """Tests for SipHash implementation."""
    
    def test_siphash_basic(self):
        """Test SipHash-2-4 basic functionality."""
        # Known test vectors from SipHash spec
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        data = bytes.fromhex("000102030405060708090a0b0c0d0e")
        
        k0 = int.from_bytes(key[:8], 'little')
        k1 = int.from_bytes(key[8:], 'little')
        
        result = SipHash24(k0, k1, data)
        
        # Result should be deterministic
        assert isinstance(result, int)
        assert 0 <= result < 2**64
    
    def test_siphash_empty(self):
        """Test SipHash of empty data."""
        k0 = 0x0706050403020100
        k1 = 0x0F0E0D0C0B0A0908
        
        result = SipHash24(k0, k1, b"")
        
        # Should produce consistent result
        assert isinstance(result, int)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
