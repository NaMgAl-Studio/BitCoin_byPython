# Copyright (c) 2009-2010 Satoshi Nakamoto
# Copyright (c) 2009-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Bitcoin Validation Types

This module defines validation result types and state objects for
transaction and block validation.
"""

from dataclasses import dataclass, field
from typing import Optional, Generic, TypeVar
from enum import Enum, auto


# ============================================================================
# Constants
# ============================================================================

# Index marker for when no witness commitment is present in a coinbase transaction
NO_WITNESS_COMMITMENT = -1

# Minimum size of a witness commitment structure (BIP 141)
MINIMUM_WITNESS_COMMITMENT = 38


# ============================================================================
# Transaction Validation Result
# ============================================================================

class TxValidationResult(Enum):
    """
    A "reason" why a transaction was invalid.
    
    Used for determining whether the provider of the transaction
    should be banned/ignored/disconnected/etc.
    """
    
    TX_RESULT_UNSET = auto()      # Initial value, tx has not yet been rejected
    TX_CONSENSUS = auto()         # Invalid by consensus rules
    TX_INPUTS_NOT_STANDARD = auto()  # Inputs failed policy rules
    TX_NOT_STANDARD = auto()      # Didn't meet local policy rules
    TX_MISSING_INPUTS = auto()    # Transaction was missing some of its inputs
    TX_PREMATURE_SPEND = auto()   # Spends coinbase too early or violates locktime
    TX_WITNESS_MUTATED = auto()   # Witness might be invalid or malleated
    TX_WITNESS_STRIPPED = auto()  # Transaction is missing a witness
    TX_CONFLICT = auto()          # Conflicts with existing tx in mempool or chain
    TX_MEMPOOL_POLICY = auto()    # Violated mempool's fee/size/RBF limits
    TX_NO_MEMPOOL = auto()        # Node does not have a mempool
    TX_RECONSIDERABLE = auto()    # Might be acceptable if submitted differently
    TX_UNKNOWN = auto()           # Transaction was not validated (package failed)


# ============================================================================
# Block Validation Result
# ============================================================================

class BlockValidationResult(Enum):
    """
    A "reason" why a block was invalid.
    
    Used for determining whether the provider of the block should be
    banned/ignored/disconnected/etc.
    """
    
    BLOCK_RESULT_UNSET = auto()   # Initial value, block has not yet been rejected
    BLOCK_CONSENSUS = auto()      # Invalid by consensus rules
    BLOCK_CACHED_INVALID = auto() # Block was cached as invalid
    BLOCK_INVALID_HEADER = auto() # Invalid proof of work or time too old
    BLOCK_MUTATED = auto()        # Block data didn't match PoW commitment
    BLOCK_MISSING_PREV = auto()   # Don't have the previous block
    BLOCK_INVALID_PREV = auto()   # Previous block is invalid
    BLOCK_TIME_FUTURE = auto()    # Block timestamp > 2 hours in future
    BLOCK_HEADER_LOW_WORK = auto()  # Block header may be on low-work chain


# ============================================================================
# Validation State
# ============================================================================

T = TypeVar('T')


class ModeState(Enum):
    """Internal state for validation state."""
    M_VALID = auto()
    M_INVALID = auto()
    M_ERROR = auto()


@dataclass
class ValidationState(Generic[T]):
    """
    Template for capturing information about block/transaction validation.
    
    This is instantiated by TxValidationState and BlockValidationState.
    """
    
    _mode: ModeState = field(default=ModeState.M_VALID, init=False)
    _result: Optional[T] = field(default=None, init=False)
    _reject_reason: str = field(default="", init=False)
    _debug_message: str = field(default="", init=False)
    
    def invalid(self, result: T, reject_reason: str = "",
                debug_message: str = "") -> bool:
        """
        Mark validation as invalid with reason.
        
        Args:
            result: The validation result type
            reject_reason: Human-readable rejection reason
            debug_message: Additional debug information
            
        Returns:
            Always returns False for convenience in validation functions
        """
        self._result = result
        self._reject_reason = reject_reason
        self._debug_message = debug_message
        
        if self._mode != ModeState.M_ERROR:
            self._mode = ModeState.M_INVALID
        
        return False
    
    def error(self, reject_reason: str) -> bool:
        """
        Mark validation as having an error.
        
        Args:
            reject_reason: Human-readable error reason
            
        Returns:
            Always returns False for convenience
        """
        if self._mode == ModeState.M_VALID:
            self._reject_reason = reject_reason
        self._mode = ModeState.M_ERROR
        return False
    
    def is_valid(self) -> bool:
        """Check if validation passed."""
        return self._mode == ModeState.M_VALID
    
    def is_invalid(self) -> bool:
        """Check if validation failed."""
        return self._mode == ModeState.M_INVALID
    
    def is_error(self) -> bool:
        """Check if validation encountered an error."""
        return self._mode == ModeState.M_ERROR
    
    @property
    def result(self) -> Optional[T]:
        """Get the validation result."""
        return self._result
    
    @property
    def reject_reason(self) -> str:
        """Get the rejection reason."""
        return self._reject_reason
    
    @property
    def debug_message(self) -> str:
        """Get the debug message."""
        return self._debug_message
    
    def __str__(self) -> str:
        if self.is_valid():
            return "Valid"
        
        if self._debug_message:
            return f"{self._reject_reason}, {self._debug_message}"
        
        return self._reject_reason
    
    def __repr__(self) -> str:
        return f"ValidationState(mode={self._mode.name}, result={self._result})"


# ============================================================================
# Specific Validation States
# ============================================================================

class TxValidationState(ValidationState[TxValidationResult]):
    """
    Validation state for transactions.
    
    Use this to track the validation status and reasons for failure
    when validating a transaction.
    """
    pass


class BlockValidationState(ValidationState[BlockValidationResult]):
    """
    Validation state for blocks.
    
    Use this to track the validation status and reasons for failure
    when validating a block.
    """
    pass


# ============================================================================
# Transaction Weight Functions
# ============================================================================

def get_transaction_weight(tx_serialized_size: int, witness_size: int) -> int:
    """
    Calculate transaction weight.
    
    weight = (stripped_size * 4) + witness_size
    = (stripped_size * 3) + total_size
    
    Args:
        tx_serialized_size: Total serialized size including witness
        witness_size: Size of witness data
        
    Returns:
        Transaction weight in weight units
    """
    stripped_size = tx_serialized_size - witness_size
    return stripped_size * 4 + witness_size


def get_block_weight(block_serialized_size: int, witness_size: int) -> int:
    """
    Calculate block weight.
    
    Args:
        block_serialized_size: Total serialized size including witness
        witness_size: Size of witness data
        
    Returns:
        Block weight in weight units
    """
    stripped_size = block_serialized_size - witness_size
    return stripped_size * 4 + witness_size


def get_virtual_size(weight: int) -> int:
    """
    Convert weight to virtual size.
    
    vsize = weight / 4 (rounded up)
    
    Args:
        weight: Weight in weight units
        
    Returns:
        Virtual size in bytes
    """
    return (weight + 3) // 4


# ============================================================================
# Witness Commitment
# ============================================================================

def get_witness_commitment_index(coinbase_outputs: list) -> int:
    """
    Find the position of the witness commitment in coinbase outputs.
    
    The witness commitment is identified by:
    - OP_RETURN prefix
    - 0x24 (36) byte length
    - Magic bytes 0xaa21a9ed
    
    Args:
        coinbase_outputs: List of transaction outputs from coinbase
        
    Returns:
        Index of witness commitment output, or NO_WITNESS_COMMITMENT if not found
    """
    for i, output in enumerate(coinbase_outputs):
        script = output.script_pubkey if hasattr(output, 'script_pubkey') else output
        
        if len(script) >= MINIMUM_WITNESS_COMMITMENT:
            if (script[0] == 0x6a and    # OP_RETURN
                script[1] == 0x24 and    # Push 36 bytes
                script[2] == 0xaa and    # Magic byte 1
                script[3] == 0x21 and    # Magic byte 2
                script[4] == 0xa9 and    # Magic byte 3
                script[5] == 0xed):      # Magic byte 4
                return i
    
    return NO_WITNESS_COMMITMENT


# ============================================================================
# Script Verify Flag Exceptions
# ============================================================================

def script_flag_exceptions_for_block(block_hash: bytes, params) -> int:
    """
    Get script verify flag exceptions for a specific block.
    
    Some blocks are known to be valid but fail with default script
    verify flags. This returns the exception flags for such blocks.
    
    Args:
        block_hash: The block hash
        params: Consensus parameters
        
    Returns:
        Script verify flags to exclude for this block
    """
    if hasattr(params, 'script_flag_exceptions'):
        return params.script_flag_exceptions.get(block_hash, 0)
    return 0
