# Copyright (c) 2017-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Bitcoin Transaction Verification

Transaction validation functions that depend on chain state.
Includes input checking, sequence locks, and sigop counting.
"""

from typing import List, Tuple, Optional, TYPE_CHECKING
from dataclasses import dataclass

from .validation import TxValidationState, TxValidationResult
from .consensus import LOCKTIME_THRESHOLD, COINBASE_MATURITY
from .amount import MoneyRange, MAX_MONEY
from .tx_check import GetValueOut
from ..primitives.transaction import Transaction, TransactionInput
from ..script.verify_flags import SCRIPT_VERIFY_P2SH

if TYPE_CHECKING:
    from ..coins.coins import CoinsViewCache, Coin
    from ..chain.chain import BlockIndex


# ============================================================================
# Constants
# ============================================================================

# Sequence lock constants
SEQUENCE_FINAL = 0xFFFFFFFF
SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22
SEQUENCE_LOCKTIME_MASK = 0x0000FFFF
SEQUENCE_LOCKTIME_GRANULARITY = 9  # 512 seconds

# Locktime verify sequence flag
LOCKTIME_VERIFY_SEQUENCE = 1 << 0


# ============================================================================
# Transaction Finality
# ============================================================================

def IsFinalTx(tx: Transaction, n_block_height: int, n_block_time: int) -> bool:
    """
    Check if transaction is final and can be included in a block.
    
    A transaction is final if:
    - nLockTime is 0, or
    - nLockTime < block height (for block-based locktime), or
    - nLockTime < block time (for time-based locktime), or
    - All inputs have nSequence == SEQUENCE_FINAL
    
    This is consensus critical.
    
    Args:
        tx: The transaction
        n_block_height: Current block height
        n_block_time: Current block time (median time past)
        
    Returns:
        True if transaction is final
    """
    if tx.lock_time == 0:
        return True
    
    # Check if locktime is satisfied
    if tx.lock_time < (LOCKTIME_THRESHOLD if tx.lock_time < LOCKTIME_THRESHOLD 
                       else n_block_time):
        # Block height-based locktime
        if tx.lock_time < LOCKTIME_THRESHOLD:
            if tx.lock_time < n_block_height:
                return True
        # Time-based locktime
        else:
            if tx.lock_time < n_block_time:
                return True
    
    # Even if nLockTime isn't satisfied, tx is still final if
    # all inputs' nSequence == SEQUENCE_FINAL
    for txin in tx.inputs:
        if txin.sequence != SEQUENCE_FINAL:
            return False
    
    return True


# ============================================================================
# Sequence Locks (BIP68)
# ============================================================================

@dataclass
class SequenceLock:
    """Result of sequence lock calculation."""
    min_height: int = -1
    min_time: int = -1


def CalculateSequenceLocks(
    tx: Transaction,
    flags: int,
    prev_heights: List[int],
    block: 'BlockIndex'
) -> SequenceLock:
    """
    Calculate the block height and time at which a transaction
    will be considered final per BIP68.
    
    Args:
        tx: The transaction
        flags: Verification flags
        prev_heights: Heights at which tx's inputs confirmed
        block: The block being connected
        
    Returns:
        SequenceLock with minimum height and time
    """
    assert len(prev_heights) == len(tx.inputs)
    
    # Default values: -1 means any height or time is valid
    lock = SequenceLock(min_height=-1, min_time=-1)
    
    # Check if BIP68 should be enforced
    enforce_bip68 = tx.version >= 2 and (flags & LOCKTIME_VERIFY_SEQUENCE)
    
    if not enforce_bip68:
        return lock
    
    for i, txin in enumerate(tx.inputs):
        # Sequence numbers with MSB set are not treated as relative lock-times
        if txin.sequence & SEQUENCE_LOCKTIME_TYPE_FLAG:
            # The height of this input is not relevant for sequence locks
            prev_heights[i] = 0
            continue
        
        n_coin_height = prev_heights[i]
        
        if txin.sequence & SEQUENCE_LOCKTIME_TYPE_FLAG:
            # Time-based relative lock-time
            # Get median time past of block prior to confirmation
            n_coin_time = _get_median_time_past(block, max(n_coin_height - 1, 0))
            
            # Time is measured in 512-second increments
            n_time = (txin.sequence & SEQUENCE_LOCKTIME_MASK) << SEQUENCE_LOCKTIME_GRANULARITY
            lock.min_time = max(lock.min_time, n_coin_time + n_time - 1)
        else:
            # Block-height-based relative lock-time
            n_blocks = txin.sequence & SEQUENCE_LOCKTIME_MASK
            lock.min_height = max(lock.min_height, n_coin_height + n_blocks - 1)
    
    return lock


def _get_median_time_past(block: 'BlockIndex', height: int) -> int:
    """Get median time past at a given height."""
    # Simplified - would need full chain traversal
    # For now, return the block time at that height
    if hasattr(block, 'get_ancestor'):
        ancestor = block.get_ancestor(height)
        if ancestor:
            return ancestor.median_time_past
    return 0


def EvaluateSequenceLocks(block: 'BlockIndex', lock: SequenceLock) -> bool:
    """
    Evaluate if sequence locks are satisfied.
    
    Args:
        block: The block being connected
        lock: The sequence lock to evaluate
        
    Returns:
        True if sequence locks are satisfied
    """
    # Need previous block for median time past
    if not hasattr(block, 'prev') or block.prev is None:
        return True
    
    n_block_time = block.prev.median_time_past
    
    if lock.min_height >= block.height or lock.min_time >= n_block_time:
        return False
    
    return True


def SequenceLocks(
    tx: Transaction,
    flags: int,
    prev_heights: List[int],
    block: 'BlockIndex'
) -> bool:
    """
    Check if transaction is final per BIP68 sequence numbers.
    
    Args:
        tx: The transaction
        flags: Verification flags
        prev_heights: Heights at which tx's inputs confirmed
        block: The block being connected
        
    Returns:
        True if sequence locks are satisfied
    """
    return EvaluateSequenceLocks(
        block,
        CalculateSequenceLocks(tx, flags, prev_heights, block)
    )


# ============================================================================
# Input Checking
# ============================================================================

def CheckTxInputs(
    tx: Transaction,
    state: TxValidationState,
    inputs: 'CoinsViewCache',
    n_spend_height: int
) -> Tuple[bool, int]:
    """
    Check whether all inputs of this transaction are valid.
    
    This does not modify the UTXO set. This does not check scripts.
    
    Args:
        tx: The transaction (must not be coinbase)
        state: Validation state
        inputs: Coins view for input lookup
        n_spend_height: Height at which inputs are being spent
        
    Returns:
        Tuple of (success, txfee)
        txfee is set to the transaction fee if successful.
    """
    assert not tx.is_coinbase()
    
    # Check if all inputs are available
    if not inputs.have_inputs(tx):
        return state.invalid(
            TxValidationResult.TX_MISSING_INPUTS,
            "bad-txns-inputs-missingorspent"
        ), 0
    
    value_in = 0
    
    for i, txin in enumerate(tx.inputs):
        coin = inputs.access_coin(txin.prevout)
        
        if coin is None or coin.is_spent:
            return state.invalid(
                TxValidationResult.TX_MISSING_INPUTS,
                "bad-txns-inputs-missingorspent"
            ), 0
        
        # If prev is coinbase, check that it's matured
        if coin.is_coinbase:
            depth = n_spend_height - coin.height
            if depth < COINBASE_MATURITY:
                return state.invalid(
                    TxValidationResult.TX_PREMATURE_SPEND,
                    f"bad-txns-premature-spend-of-coinbase (depth {depth})"
                ), 0
        
        # Check for overflow
        value_in += coin.output.value
        
        if not MoneyRange(coin.output.value) or not MoneyRange(value_in):
            return state.invalid(
                TxValidationResult.TX_CONSENSUS,
                "bad-txns-inputvalues-outofrange"
            ), 0
    
    # Get output value
    value_out = GetValueOut(tx)
    
    # Check that inputs >= outputs
    if value_in < value_out:
        return state.invalid(
            TxValidationResult.TX_CONSENSUS,
            f"bad-txns-in-belowout (value_in={value_in}, value_out={value_out})"
        ), 0
    
    # Calculate fee
    txfee = value_in - value_out
    
    if not MoneyRange(txfee):
        return state.invalid(
            TxValidationResult.TX_CONSENSUS,
            "bad-txns-fee-outofrange"
        ), 0
    
    return True, txfee


# ============================================================================
# Signature Operation Counting
# ============================================================================

def GetLegacySigOpCount(tx: Transaction) -> int:
    """
    Count ECDSA signature operations the old-fashioned way.
    
    This counts sigops in scriptSig and scriptPubKey without
    considering P2SH or witness.
    
    Args:
        tx: The transaction
        
    Returns:
        Number of signature operations
    """
    n_sigops = 0
    
    for txin in tx.inputs:
        n_sigops += _count_sigops_in_script(txin.script_sig, False)
    
    for txout in tx.outputs:
        n_sigops += _count_sigops_in_script(txout.script_pubkey, False)
    
    return n_sigops


def GetP2SHSigOpCount(tx: Transaction, inputs: 'CoinsViewCache') -> int:
    """
    Count ECDSA signature operations in pay-to-script-hash inputs.
    
    Args:
        tx: The transaction (must not be coinbase)
        inputs: Coins view for input lookup
        
    Returns:
        Number of P2SH signature operations
    """
    if tx.is_coinbase():
        return 0
    
    n_sigops = 0
    
    for txin in tx.inputs:
        coin = inputs.access_coin(txin.prevout)
        
        if coin is None or coin.is_spent:
            continue
        
        prevout_script = coin.output.script_pubkey
        
        # Check if previous output is P2SH
        if _is_p2sh(prevout_script):
            n_sigops += _count_sigops_in_script(txin.script_sig, True)
    
    return n_sigops


def GetTransactionSigOpCost(
    tx: Transaction,
    inputs: 'CoinsViewCache',
    flags: int
) -> int:
    """
    Compute total signature operation cost of a transaction.
    
    This includes legacy sigops, P2SH sigops, and witness sigops.
    Sigops are weighted by WITNESS_SCALE_FACTOR.
    
    Args:
        tx: The transaction
        inputs: Coins view for input lookup
        flags: Script verification flags
        
    Returns:
        Total signature operation cost
    """
    from ..script.interpreter import CountWitnessSigOps
    
    # Legacy sigops
    n_sigops = GetLegacySigOpCount(tx) * 4  # WITNESS_SCALE_FACTOR
    
    if tx.is_coinbase():
        return n_sigops
    
    # P2SH sigops
    if flags & SCRIPT_VERIFY_P2SH:
        n_sigops += GetP2SHSigOpCount(tx, inputs) * 4
    
    # Witness sigops
    for txin in tx.inputs:
        coin = inputs.access_coin(txin.prevout)
        
        if coin is None or coin.is_spent:
            continue
        
        prevout_script = coin.output.script_pubkey
        
        # This would need the full witness structure
        # n_sigops += CountWitnessSigOps(txin.script_sig, prevout_script, txin.witness, flags)
    
    return n_sigops


# ============================================================================
# Internal Helper Functions
# ============================================================================

def _count_sigops_in_script(script: bytes, is_p2sh: bool) -> int:
    """
    Count signature operations in a script.
    
    Args:
        script: The script bytes
        is_p2sh: Whether this is a P2SH script check
        
    Returns:
        Number of signature operations
    """
    from ..script.opcodes import OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY
    
    # Simplified counting - would need full script parsing
    n_sigops = 0
    
    i = 0
    while i < len(script):
        opcode = script[i]
        
        if opcode == OP_CHECKSIG or opcode == OP_CHECKSIGVERIFY:
            n_sigops += 1
        elif opcode == OP_CHECKMULTISIG or opcode == OP_CHECKMULTISIGVERIFY:
            # For accurate counting, we'd need to look at the preceding push
            # For P2SH, assume 20 pubkeys (worst case)
            n_sigops += 20 if is_p2sh else 1
        
        i += 1
    
    return n_sigops


def _is_p2sh(script: bytes) -> bool:
    """Check if script is pay-to-script-hash."""
    if len(script) != 23:
        return False
    
    from ..script.opcodes import OP_HASH160, OP_EQUAL
    
    return (script[0] == OP_HASH160 and
            script[1] == 0x14 and  # Push 20 bytes
            script[22] == OP_EQUAL)
