# Copyright (c) 2017-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Bitcoin Transaction Check

Context-independent transaction checking code that can be called outside
the bitcoin server and doesn't depend on chain or mempool state.
"""

from typing import Set

from .validation import TxValidationState, TxValidationResult
from .consensus import MAX_MONEY, MAX_BLOCK_WEIGHT, WITNESS_SCALE_FACTOR
from ..primitives.transaction import Transaction, TransactionOutput, OutPoint
from ..consensus.amount import MoneyRange


def CheckTransaction(tx: Transaction, state: TxValidationState) -> bool:
    """
    Check transaction for basic structural validity.
    
    This performs context-independent checks that don't depend on chain
    state, mempool state, or any external data.
    
    Checks performed:
    - Non-empty inputs and outputs
    - Size limits
    - Output value range and overflow
    - No duplicate inputs
    - Coinbase scriptSig size limits
    - Non-null prevouts for non-coinbase transactions
    
    Args:
        tx: The transaction to check
        state: Validation state (modified on error)
        
    Returns:
        True if transaction passes all checks
    """
    # Check for empty inputs
    if not tx.inputs:
        return state.invalid(
            TxValidationResult.TX_CONSENSUS,
            "bad-txns-vin-empty"
        )
    
    # Check for empty outputs
    if not tx.outputs:
        return state.invalid(
            TxValidationResult.TX_CONSENSUS,
            "bad-txns-vout-empty"
        )
    
    # Size limits (this doesn't take the witness into account,
    # as that hasn't been checked for malleability)
    stripped_size = tx.serialized_size(include_witness=False)
    weight = stripped_size * WITNESS_SCALE_FACTOR
    
    if weight > MAX_BLOCK_WEIGHT:
        return state.invalid(
            TxValidationResult.TX_CONSENSUS,
            "bad-txns-oversize"
        )
    
    # Check for negative or overflow output values (CVE-2010-5139)
    value_out = 0
    for txout in tx.outputs:
        if txout.value < 0:
            return state.invalid(
                TxValidationResult.TX_CONSENSUS,
                "bad-txns-vout-negative"
            )
        
        if txout.value > MAX_MONEY:
            return state.invalid(
                TxValidationResult.TX_CONSENSUS,
                "bad-txns-vout-toolarge"
            )
        
        value_out += txout.value
        
        if not MoneyRange(value_out):
            return state.invalid(
                TxValidationResult.TX_CONSENSUS,
                "bad-txns-txouttotal-toolarge"
            )
    
    # Check for duplicate inputs (CVE-2018-17144)
    # While CheckTxInputs does check if all inputs are available,
    # it does not check if the tx has duplicate inputs.
    # Failure to run this check will result in either a crash or
    # an inflation bug, depending on the implementation.
    seen_outpoints: Set[OutPoint] = set()
    
    for txin in tx.inputs:
        if txin.prevout in seen_outpoints:
            return state.invalid(
                TxValidationResult.TX_CONSENSUS,
                "bad-txns-inputs-duplicate"
            )
        seen_outpoints.add(txin.prevout)
    
    # Coinbase-specific checks
    if tx.is_coinbase():
        script_sig = tx.inputs[0].script_sig
        if len(script_sig) < 2 or len(script_sig) > 100:
            return state.invalid(
                TxValidationResult.TX_CONSENSUS,
                "bad-cb-length"
            )
    else:
        # Non-coinbase transactions must not have null prevouts
        for txin in tx.inputs:
            if txin.prevout.is_null():
                return state.invalid(
                    TxValidationResult.TX_CONSENSUS,
                    "bad-txns-prevout-null"
                )
    
    return True


def CheckTransactionSanity(tx: Transaction) -> bool:
    """
    Quick sanity check for a transaction.
    
    This is a convenience function that returns a boolean
    instead of requiring a state object.
    
    Args:
        tx: The transaction to check
        
    Returns:
        True if transaction passes sanity checks
    """
    state = TxValidationState()
    return CheckTransaction(tx, state)


# ============================================================================
# Transaction Basic Properties
# ============================================================================

def GetValueOut(tx: Transaction) -> int:
    """
    Calculate total output value of a transaction.
    
    Args:
        tx: The transaction
        
    Returns:
        Total value of all outputs in satoshis
        
    Raises:
        ValueError: If values are out of range
    """
    value_out = 0
    
    for txout in tx.outputs:
        if txout.value < 0:
            raise ValueError("Transaction output value is negative")
        if txout.value > MAX_MONEY:
            raise ValueError("Transaction output value is too large")
        
        value_out += txout.value
        
        if not MoneyRange(value_out):
            raise ValueError("Transaction total output value is too large")
    
    return value_out


def GetTotalSize(tx: Transaction) -> int:
    """
    Get total serialized size of transaction.
    
    Args:
        tx: The transaction
        
    Returns:
        Total serialized size in bytes (including witness)
    """
    return tx.serialized_size(include_witness=True)


def GetWeight(tx: Transaction) -> int:
    """
    Calculate transaction weight.
    
    weight = (stripped_size * 3) + total_size
    
    Args:
        tx: The transaction
        
    Returns:
        Transaction weight in weight units
    """
    total_size = GetTotalSize(tx)
    stripped_size = tx.serialized_size(include_witness=False)
    
    return (stripped_size * 3) + total_size


def GetVirtualSize(tx: Transaction) -> int:
    """
    Calculate transaction virtual size.
    
    vsize = weight / 4 = ((stripped_size * 3) + total_size) / 4
    
    This is used for fee calculation.
    
    Args:
        tx: The transaction
        
    Returns:
        Virtual size in bytes
    """
    weight = GetWeight(tx)
    return (weight + 3) // 4  # Round up


# ============================================================================
# Witness Checking
# ============================================================================

def HasWitness(tx: Transaction) -> bool:
    """
    Check if transaction has witness data.
    
    Args:
        tx: The transaction
        
    Returns:
        True if transaction has any witness data
    """
    for txin in tx.inputs:
        if txin.witness and len(txin.witness) > 0:
            # Check for non-empty witness stack
            for item in txin.witness:
                if len(item) > 0:
                    return True
    return False


def IsSegwit(tx: Transaction) -> bool:
    """
    Check if transaction uses segwit.
    
    Args:
        tx: The transaction
        
    Returns:
        True if transaction is a segwit transaction
    """
    # A transaction uses segwit if it has witness data
    return HasWitness(tx)
