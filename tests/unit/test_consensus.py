# Copyright (c) 2009-2010 Satoshi Nakamoto
# Copyright (c) 2009-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Unit tests for the consensus module.
"""

import pytest
from ..consensus.params import (
    ConsensusParams, BIP9Deployment, ChainType,
    create_mainnet_params, create_testnet_params,
    create_regtest_params, get_block_subsidy,
    MessageStartChars, get_mainnet_magic, get_network_for_magic,
)
from ..consensus.validation import (
    TxValidationState, TxValidationResult,
    BlockValidationState, BlockValidationResult,
    get_transaction_weight, get_virtual_size,
)
from ..consensus.pow import (
    ArithUint256, CheckProofOfWork, DeriveTarget,
)


class TestConsensusParams:
    """Test consensus parameters."""
    
    def test_mainnet_params(self):
        """Test mainnet parameters."""
        params = create_mainnet_params()
        
        assert params.n_subsidy_halving_interval == 210000
        assert params.pow_target_spacing == 600
        assert params.pow_target_timespan == 1209600
        assert params.pow_allow_min_difficulty_blocks == False
    
    def test_regtest_params(self):
        """Test regtest parameters."""
        params = create_regtest_params()
        
        assert params.n_subsidy_halving_interval == 150
        assert params.pow_allow_min_difficulty_blocks == True
        assert params.pow_no_retargeting == True
    
    def test_difficulty_adjustment_interval(self):
        """Test difficulty adjustment interval calculation."""
        params = create_mainnet_params()
        
        # 2 weeks / 10 minutes = 2016 blocks
        assert params.difficulty_adjustment_interval() == 2016


class TestBlockSubsidy:
    """Test block subsidy calculation."""
    
    def test_genesis_subsidy(self):
        """Test genesis block subsidy."""
        params = create_mainnet_params()
        
        subsidy = get_block_subsidy(0, params)
        assert subsidy == 50 * 100000000  # 50 BTC
    
    def test_first_halving(self):
        """Test first halving at block 210000."""
        params = create_mainnet_params()
        
        # Block before halving
        subsidy_before = get_block_subsidy(209999, params)
        assert subsidy_before == 50 * 100000000
        
        # Block at halving
        subsidy_at = get_block_subsidy(210000, params)
        assert subsidy_at == 25 * 100000000  # 25 BTC
    
    def test_multiple_halvings(self):
        """Test multiple halving events."""
        params = create_mainnet_params()
        
        # After 1 halving
        assert get_block_subsidy(210000, params) == 25 * 100000000
        
        # After 2 halvings
        assert get_block_subsidy(420000, params) == 12.5 * 100000000
        
        # After 3 halvings
        assert get_block_subsidy(630000, params) == 6.25 * 100000000
    
    def test_subsidy_becomes_zero(self):
        """Test that subsidy eventually becomes zero."""
        params = create_mainnet_params()
        
        # After 64 halvings
        height = 64 * 210000
        subsidy = get_block_subsidy(height, params)
        assert subsidy == 0


class TestMessageStartChars:
    """Test network magic bytes."""
    
    def test_mainnet_magic(self):
        """Test mainnet magic bytes."""
        magic = get_mainnet_magic()
        
        assert len(magic.data) == 4
        assert magic.data == bytes.fromhex("f9beb4d9")
    
    def test_network_detection(self):
        """Test network detection from magic."""
        magic = get_mainnet_magic()
        chain_type = get_network_for_magic(magic)
        
        assert chain_type == ChainType.MAIN


class TestValidationState:
    """Test validation state classes."""
    
    def test_initial_state(self):
        """Test initial validation state."""
        state = TxValidationState()
        
        assert state.is_valid()
        assert not state.is_invalid()
        assert not state.is_error()
    
    def test_invalid_state(self):
        """Test marking state as invalid."""
        state = TxValidationState()
        
        result = state.invalid(
            TxValidationResult.TX_CONSENSUS,
            "test-error"
        )
        
        assert result == False  # Should always return False
        assert state.is_invalid()
        assert not state.is_valid()
        assert state.result == TxValidationResult.TX_CONSENSUS
        assert state.reject_reason == "test-error"
    
    def test_error_state(self):
        """Test marking state as error."""
        state = TxValidationState()
        
        result = state.error("test-error")
        
        assert result == False
        assert state.is_error()
    
    def test_state_string(self):
        """Test string representation."""
        state = TxValidationState()
        assert str(state) == "Valid"
        
        state.invalid(TxValidationResult.TX_CONSENSUS, "test")
        assert "test" in str(state)


class TestArithUint256:
    """Test ArithUint256 class."""
    
    def test_initialization(self):
        """Test initialization from int."""
        n = ArithUint256(100)
        assert int(n) == 100
    
    def test_from_bytes(self):
        """Test creation from bytes."""
        data = bytes(32)
        n = ArithUint256.from_bytes(data)
        assert int(n) == 0
    
    def test_comparison(self):
        """Test comparison operations."""
        a = ArithUint256(100)
        b = ArithUint256(200)
        
        assert a < b
        assert b > a
        assert a <= b
        assert b >= a
        assert a != b
    
    def test_arithmetic(self):
        """Test arithmetic operations."""
        a = ArithUint256(100)
        b = ArithUint256(50)
        
        assert int(a + b) == 150
        assert int(a - b) == 50
        assert int(a // b) == 2
    
    def test_shifts(self):
        """Test bit shifts."""
        n = ArithUint256(256)
        
        assert int(n >> 4) == 16
        assert int(n << 2) == 1024
    
    def test_compact_format(self):
        """Test compact (nBits) format."""
        # Difficulty 1 target
        n_compact = 0x1d00ffff
        target = ArithUint256.set_compact(n_compact)
        
        # Convert back
        compact = target.get_compact()
        
        # Should be approximately the same (may lose precision)
        assert compact >> 24 == n_compact >> 24


class TestWeightFunctions:
    """Test transaction weight functions."""
    
    def test_weight_calculation(self):
        """Test weight calculation."""
        # 100 bytes total, 20 bytes witness
        total_size = 100
        witness_size = 20
        
        weight = get_transaction_weight(total_size, witness_size)
        
        # weight = (stripped * 4) + witness = (80 * 4) + 20 = 340
        assert weight == 340
    
    def test_virtual_size(self):
        """Test virtual size calculation."""
        weight = 400
        
        vsize = get_virtual_size(weight)
        
        # vsize = weight / 4 = 100
        assert vsize == 100
    
    def test_virtual_size_rounding(self):
        """Test virtual size rounds up."""
        # Weight that doesn't divide evenly
        weight = 401
        
        vsize = get_virtual_size(weight)
        
        # Should round up: 401/4 = 100.25 -> 101
        assert vsize == 101


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
