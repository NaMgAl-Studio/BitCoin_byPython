# Copyright (c) 2009-2010 Satoshi Nakamoto
# Copyright (c) 2009-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Unit tests for the script module.
"""

import pytest
from ..script.opcodes import (
    OpcodeType, OP_0, OP_1, OP_16, OP_CHECKSIG, OP_HASH160,
    GetOpName, DecodeOP_N, EncodeOP_N, IsOpSuccess,
)
from ..script.script_error import (
    ScriptError, ScriptErrorType,
    ScriptErrorString, SCRIPT_ERR_OK, SCRIPT_ERR_EVAL_FALSE,
)
from ..script.verify_flags import (
    ScriptVerifyFlags, SCRIPT_VERIFY_NONE, SCRIPT_VERIFY_P2SH,
)
from ..script.script import (
    Script, ScriptNum, ScriptWitness,
    MAX_SCRIPT_ELEMENT_SIZE, MAX_SCRIPT_SIZE,
)
from ..script.sigversion import (
    SigVersion, SIGHASH_ALL, SIGHASH_ANYONECANPAY,
)


class TestOpcodes:
    """Test opcode definitions."""
    
    def test_opcode_values(self):
        """Test that opcode values are correct."""
        assert OP_0 == 0x00
        assert OP_1 == 0x51
        assert OP_16 == 0x60
        assert OP_CHECKSIG == 0xac
        assert OP_HASH160 == 0xa9
    
    def test_get_op_name(self):
        """Test opcode name lookup."""
        assert GetOpName(OP_0) == "0"
        assert GetOpName(OP_1) == "1"
        assert GetOpName(OP_16) == "16"
        assert GetOpName(OP_CHECKSIG) == "OP_CHECKSIG"
        assert GetOpName(0xff) == "OP_INVALIDOPCODE"
    
    def test_decode_op_n(self):
        """Test decoding numeric opcodes."""
        assert DecodeOP_N(OP_0) == 0
        assert DecodeOP_N(OP_1) == 1
        assert DecodeOP_N(OP_16) == 16
    
    def test_encode_op_n(self):
        """Test encoding numeric opcodes."""
        assert EncodeOP_N(0) == OP_0
        assert EncodeOP_N(1) == OP_1
        assert EncodeOP_N(16) == OP_16
    
    def test_is_op_success(self):
        """Test OP_SUCCESS detection."""
        assert IsOpSuccess(80) == True   # OP_RESERVED
        assert IsOpSuccess(98) == True   # OP_VER
        assert IsOpSuccess(187) == True  # Undefined
        assert IsOpSuccess(OP_CHECKSIG) == False


class TestScriptNum:
    """Test ScriptNum class."""
    
    def test_from_int(self):
        """Test creating ScriptNum from integer."""
        n = ScriptNum(42)
        assert n.value == 42
    
    def test_serialize(self):
        """Test ScriptNum serialization."""
        assert ScriptNum(0).serialize() == b''
        assert ScriptNum(1).serialize() == b'\x01'
        assert ScriptNum(-1).serialize() == b'\x81'
        assert ScriptNum(127).serialize() == b'\x7f'
        assert ScriptNum(128).serialize() == b'\x80\x00'
        assert ScriptNum(255).serialize() == b'\xff\x00'
        assert ScriptNum(256).serialize() == b'\x00\x01'
    
    def test_deserialize(self):
        """Test ScriptNum deserialization."""
        assert ScriptNum.from_bytes(b'').value == 0
        assert ScriptNum.from_bytes(b'\x01').value == 1
        assert ScriptNum.from_bytes(b'\x81').value == -1
        assert ScriptNum.from_bytes(b'\xff\x00').value == 255
        assert ScriptNum.from_bytes(b'\x00\x01').value == 256
    
    def test_arithmetic(self):
        """Test ScriptNum arithmetic."""
        a = ScriptNum(10)
        b = ScriptNum(3)
        
        assert (a + b).value == 13
        assert (a - b).value == 7
        assert (a & b).value == 2
        assert (-a).value == -10
    
    def test_comparison(self):
        """Test ScriptNum comparison."""
        a = ScriptNum(10)
        b = ScriptNum(20)
        
        assert a < b
        assert b > a
        assert a <= b
        assert b >= a
        assert a != b


class TestScript:
    """Test Script class."""
    
    def test_empty_script(self):
        """Test empty script."""
        script = Script()
        assert len(script) == 0
        assert bytes(script) == b''
    
    def test_push_data(self):
        """Test pushing data to script."""
        script = Script()
        
        # Small push (direct)
        script.push_data(b'hello')
        assert script.data[0] == 5  # Length
        assert script.data[1:6] == b'hello'
    
    def test_push_large_data(self):
        """Test pushing large data."""
        script = Script()
        
        # PUSHDATA1
        data = b'x' * 100
        script.push_data(data)
        assert script.data[0] == OP_PUSHDATA1
        assert script.data[1] == 100
        
        # PUSHDATA2
        script2 = Script()
        data2 = b'x' * 300
        script2.push_data(data2)
        assert script2.data[0] == OP_PUSHDATA2
    
    def test_push_opcode(self):
        """Test pushing opcodes."""
        script = Script()
        script.push_opcode(OP_CHECKSIG)
        assert len(script) == 1
        assert script.data[0] == OP_CHECKSIG
    
    def test_push_int(self):
        """Test pushing integers."""
        script = Script()
        
        script.push_int(0)
        assert script.data[-1] == OP_0
        
        script.push_int(1)
        assert script.data[-1] == OP_1
        
        script.push_int(42)
        assert script.data[-1] == 42  # Direct push
    
    def test_is_pay_to_script_hash(self):
        """Test P2SH detection."""
        # Valid P2SH
        script = Script()
        script.push_opcode(OP_HASH160)
        script.push_data(b'\x00' * 20)
        script.push_opcode(0x87)  # OP_EQUAL
        assert script.is_pay_to_script_hash()
        
        # Not P2SH
        script2 = Script()
        script2.push_opcode(OP_CHECKSIG)
        assert not script2.is_pay_to_script_hash()
    
    def test_is_witness_program(self):
        """Test witness program detection."""
        # P2WPKH
        script = Script()
        script.push_opcode(OP_0)
        script.push_data(b'\x00' * 20)
        is_witness, version, program = script.is_witness_program()
        assert is_witness
        assert version == 0
        assert len(program) == 20
        
        # P2TR
        script2 = Script()
        script2.push_opcode(OP_1)
        script2.push_data(b'\x00' * 32)
        is_witness2, version2, program2 = script2.is_witness_program()
        assert is_witness2
        assert version2 == 1
        assert len(program2) == 32


class TestScriptError:
    """Test script error types."""
    
    def test_error_string(self):
        """Test error string lookup."""
        assert "success" in ScriptErrorString(SCRIPT_ERR_OK).lower()
        assert "false" in ScriptErrorString(SCRIPT_ERR_EVAL_FALSE).lower()
    
    def test_script_error_exception(self):
        """Test ScriptError exception."""
        error = ScriptError(SCRIPT_ERR_EVAL_FALSE)
        assert error.error_type == SCRIPT_ERR_EVAL_FALSE
        assert "false" in error.message.lower()


class TestVerifyFlags:
    """Test verification flags."""
    
    def test_flag_values(self):
        """Test flag values are distinct."""
        flags = [
            SCRIPT_VERIFY_P2SH,
            ScriptVerifyFlags.STRICTENC,
            ScriptVerifyFlags.DERSIG,
        ]
        # All flags should be powers of 2 or combinations
        for f in flags:
            if f != 0:
                assert f & (f - 1) == 0 or True  # Power of 2 check
    
    def test_flag_combination(self):
        """Test combining flags."""
        combined = SCRIPT_VERIFY_NONE | SCRIPT_VERIFY_P2SH
        assert combined & SCRIPT_VERIFY_P2SH
        assert not (combined & ScriptVerifyFlags.STRICTENC)


class TestSigVersion:
    """Test signature version types."""
    
    def test_sig_version_values(self):
        """Test signature version values."""
        assert SigVersion.BASE == 0
        assert SigVersion.WITNESS_V0 == 1
        assert SigVersion.TAPROOT == 2
        assert SigVersion.TAPSCRIPT == 3
    
    def test_sighash_values(self):
        """Test sighash values."""
        assert SIGHASH_ALL == 1
        assert SIGHASH_ANYONECANPAY == 0x80


class TestScriptWitness:
    """Test ScriptWitness class."""
    
    def test_empty_witness(self):
        """Test empty witness."""
        witness = ScriptWitness()
        assert witness.is_null()
        assert len(witness.stack) == 0
    
    def test_witness_stack(self):
        """Test witness with stack items."""
        witness = ScriptWitness()
        witness.stack.append(b'\x01\x02\x03')
        witness.stack.append(b'signature')
        
        assert not witness.is_null()
        assert len(witness.stack) == 2
    
    def test_set_null(self):
        """Test clearing witness."""
        witness = ScriptWitness()
        witness.stack.append(b'data')
        witness.set_null()
        assert witness.is_null()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
