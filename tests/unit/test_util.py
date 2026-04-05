"""
Tests for Bitcoin Utility Module
=================================

Tests for string encodings, time utilities, and other helpers.
"""

import pytest

from bitcoin.util.strencodings import (
    HexStr,
    hex_to_bytes,
    IsHex,
    ParseHex,
    EncodeBase64,
    DecodeBase64,
    EncodeBase32,
    DecodeBase32,
    SanitizeString,
    IsSpace,
    IsDigit,
    ToLower,
    ToUpper,
    TimingResistantEqual,
)
from bitcoin.util.time import (
    GetTime,
    GetTimeMillis,
    ParseISO8601DateTime,
    FormatISO8601DateTime,
)
from bitcoin.util.string import (
    TrimString,
    RemovePrefix,
    SplitString,
    JoinStrings,
)


class TestHexEncodings:
    """Tests for hex encoding/decoding."""
    
    def test_hex_str(self):
        """Test HexStr function."""
        result = HexStr(b'\x01\x02\x03')
        assert result == "010203"
    
    def test_hex_str_reverse(self):
        """Test HexStr with reverse option."""
        result = HexStr(b'\x01\x02\x03', reverse=True)
        assert result == "030201"
    
    def test_hex_to_bytes(self):
        """Test hex_to_bytes function."""
        result = hex_to_bytes("010203")
        assert result == b'\x01\x02\x03'
    
    def test_hex_to_bytes_reverse(self):
        """Test hex_to_bytes with reverse option."""
        result = hex_to_bytes("010203", reverse=True)
        assert result == b'\x03\x02\x01'
    
    def test_is_hex(self):
        """Test IsHex validation."""
        assert IsHex("0123456789abcdef")
        assert IsHex("0123456789ABCDEF")
        assert not IsHex("xyz")
        assert not IsHex("1")  # Odd length
        assert not IsHex("")
    
    def test_parse_hex(self):
        """Test ParseHex function."""
        result = ParseHex("01 02 03")  # With whitespace
        assert result == b'\x01\x02\x03'


class TestBase64:
    """Tests for Base64 encoding/decoding."""
    
    def test_encode_decode(self):
        """Test Base64 encode/decode roundtrip."""
        data = b"Hello, World!"
        encoded = EncodeBase64(data)
        decoded = DecodeBase64(encoded)
        
        assert decoded == data
    
    def test_known_vectors(self):
        """Test known Base64 vectors."""
        assert EncodeBase64(b"") == ""
        assert EncodeBase64(b"f") == "Zg=="
        assert EncodeBase64(b"fo") == "Zm8="
        assert EncodeBase64(b"foo") == "Zm9v"


class TestBase32:
    """Tests for Base32 encoding/decoding."""
    
    def test_encode_decode(self):
        """Test Base32 encode/decode roundtrip."""
        data = b"Hello, World!"
        encoded = EncodeBase32(data)
        decoded = DecodeBase32(encoded)
        
        assert decoded == data


class TestStringUtilities:
    """Tests for string utilities."""
    
    def test_sanitize_string(self):
        """Test string sanitization."""
        # Should remove unsafe characters
        result = SanitizeString("hello<>world")
        assert result == "helloworld"
    
    def test_is_space(self):
        """Test space detection."""
        assert IsSpace(' ')
        assert IsSpace('\t')
        assert IsSpace('\n')
        assert not IsSpace('a')
    
    def test_is_digit(self):
        """Test digit detection."""
        assert IsDigit('0')
        assert IsDigit('9')
        assert not IsDigit('a')
    
    def test_to_lower(self):
        """Test lowercase conversion."""
        assert ToLower('A') == 'a'
        assert ToLower('Z') == 'z'
        assert ToLower('a') == 'a'
    
    def test_to_upper(self):
        """Test uppercase conversion."""
        assert ToUpper('a') == 'A'
        assert ToUpper('z') == 'Z'
        assert ToUpper('A') == 'A'


class TestTimingResistantEqual:
    """Tests for timing-resistant comparison."""
    
    def test_equal_strings(self):
        """Test equal byte sequences."""
        a = b"password123"
        b = b"password123"
        assert TimingResistantEqual(a, b)
    
    def test_different_strings(self):
        """Test different byte sequences."""
        a = b"password123"
        b = b"password456"
        assert not TimingResistantEqual(a, b)
    
    def test_empty_strings(self):
        """Test empty byte sequences."""
        assert TimingResistantEqual(b"", b"")
        assert not TimingResistantEqual(b"", b"a")


class TestStringManipulation:
    """Tests for string manipulation functions."""
    
    def test_trim_string(self):
        """Test string trimming."""
        assert TrimString("  hello  ") == "hello"
        assert TrimString("\t\nhello\n\t") == "hello"
    
    def test_remove_prefix(self):
        """Test prefix removal."""
        assert RemovePrefix("hello_world", "hello_") == "world"
        assert RemovePrefix("hello_world", "xyz") == "hello_world"
    
    def test_split_string(self):
        """Test string splitting."""
        result = SplitString("a,b,c", ",")
        assert result == ["a", "b", "c"]
    
    def test_join_strings(self):
        """Test string joining."""
        result = JoinStrings(["a", "b", "c"], ",")
        assert result == "a,b,c"


class TestTimeUtilities:
    """Tests for time utilities."""
    
    def test_get_time(self):
        """Test GetTime returns valid timestamp."""
        t = GetTime()
        assert isinstance(t, int)
        assert t > 0
    
    def test_get_time_millis(self):
        """Test GetTimeMillis returns valid timestamp."""
        t = GetTimeMillis()
        assert isinstance(t, int)
        assert t > 0
    
    def test_iso8601_roundtrip(self):
        """Test ISO 8601 date/time roundtrip."""
        timestamp = 1704067200  # 2024-01-01 00:00:00 UTC
        
        formatted = FormatISO8601DateTime(timestamp)
        parsed = ParseISO8601DateTime(formatted)
        
        assert parsed == timestamp
    
    def test_parse_iso8601_invalid(self):
        """Test parsing invalid ISO 8601 string."""
        result = ParseISO8601DateTime("not-a-date")
        assert result is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
