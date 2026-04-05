# Copyright (c) 2009-2010 Satoshi Nakamoto
# Copyright (c) 2009-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Bitcoin Signature Checker

This module provides signature verification functionality for the script interpreter.
It includes:
- BaseSignatureChecker: Abstract base class
- TransactionSignatureChecker: Checks signatures for transactions
- PrecomputedTransactionData: Cached data for signature hashing
- ScriptExecutionData: Data tracked during script execution
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, List, TYPE_CHECKING
from enum import Enum

from .script import Script, ScriptNum
from .sigversion import (
    SigVersion, SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE,
    SIGHASH_ANYONECANPAY, SIGHASH_DEFAULT
)
from .script_error import (
    ScriptError, SCRIPT_ERR_SCHNORR_SIG_SIZE,
    SCRIPT_ERR_SCHNORR_SIG_HASHTYPE, SCRIPT_ERR_SCHNORR_SIG,
    SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY,
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
    SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT,
)
from .verify_flags import (
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
    SCRIPT_VERIFY_TAPROOT,
)
from .interpreter import ScriptExecutionData, set_error

# Import crypto primitives
# Note: In full implementation, use coincurve for secp256k1 operations
try:
    from coincurve import PublicKey, PrivateKey
    from coincurve._libsecp256k1 import ffi, lib
    HAS_COINCURVE = True
except ImportError:
    HAS_COINCURVE = False

if TYPE_CHECKING:
    from ..primitives.transaction import Transaction, TransactionInput, TransactionOutput


# ============================================================================
# Missing Data Behavior
# ============================================================================

class MissingDataBehavior(Enum):
    """
    Behavior when missing transaction data during signature checking.
    """
    ASSERT_FAIL = 0  # Abort execution (for consensus code)
    FAIL = 1         # Treat as invalid signature


# ============================================================================
# Precomputed Transaction Data
# ============================================================================

@dataclass
class PrecomputedTransactionData:
    """
    Precomputed data for signature hashing.
    
    This caches the hashes of various transaction components to avoid
    recomputing them for each signature in a transaction.
    """
    
    # BIP341 (Taproot) precomputed data - single SHA256
    prevouts_single_hash: Optional[bytes] = None
    sequences_single_hash: Optional[bytes] = None
    outputs_single_hash: Optional[bytes] = None
    spent_amounts_single_hash: Optional[bytes] = None
    spent_scripts_single_hash: Optional[bytes] = None
    bip341_taproot_ready: bool = False
    
    # BIP143 (SegWit) precomputed data - double SHA256
    hash_prevouts: Optional[bytes] = None
    hash_sequence: Optional[bytes] = None
    hash_outputs: Optional[bytes] = None
    bip143_segwit_ready: bool = False
    
    # Spent outputs for Taproot
    spent_outputs: List['TransactionOutput'] = field(default_factory=list)
    spent_outputs_ready: bool = False
    
    def __init__(self):
        self.prevouts_single_hash = None
        self.sequences_single_hash = None
        self.outputs_single_hash = None
        self.spent_amounts_single_hash = None
        self.spent_scripts_single_hash = None
        self.bip341_taproot_ready = False
        
        self.hash_prevouts = None
        self.hash_sequence = None
        self.hash_outputs = None
        self.bip143_segwit_ready = False
        
        self.spent_outputs = []
        self.spent_outputs_ready = False
    
    def init(self, tx: 'Transaction', spent_outputs: List['TransactionOutput'],
             force: bool = False) -> None:
        """
        Initialize precomputed data for a transaction.
        
        Args:
            tx: The transaction
            spent_outputs: The outputs being spent
            force: Precompute all data regardless of inputs
        """
        from ..crypto.sha256 import SHA256, Hash256
        
        # BIP143 precomputation
        if not self.bip143_segwit_ready:
            # Hash prevouts
            prevout_data = b''
            for tx_in in tx.inputs:
                prevout_data += tx_in.prevout.hash
                prevout_data += tx_in.prevout.n.to_bytes(4, 'little')
            self.hash_prevouts = Hash256(prevout_data)
            
            # Hash sequences
            sequence_data = b''
            for tx_in in tx.inputs:
                sequence_data += tx_in.sequence.to_bytes(4, 'little')
            self.hash_sequence = Hash256(sequence_data)
            
            # Hash outputs
            output_data = b''
            for tx_out in tx.outputs:
                output_data += tx_out.serialize()
            self.hash_outputs = Hash256(output_data)
            
            self.bip143_segwit_ready = True
        
        # Store spent outputs
        if spent_outputs:
            self.spent_outputs = spent_outputs
            self.spent_outputs_ready = True


# ============================================================================
# Base Signature Checker
# ============================================================================

class BaseSignatureChecker(ABC):
    """
    Abstract base class for signature checking.
    
    Derived classes provide actual signature verification logic.
    This allows different implementations for testing, signing, and consensus.
    """
    
    @abstractmethod
    def check_ecdsa_signature(
        self,
        sig: bytes,
        pubkey: bytes,
        script_code: Script,
        sigversion: SigVersion
    ) -> bool:
        """
        Check an ECDSA signature.
        
        Args:
            sig: The signature (DER encoded + sighash byte)
            pubkey: The public key
            script_code: The script code
            sigversion: Signature version
            
        Returns:
            True if signature is valid
        """
        pass
    
    @abstractmethod
    def check_schnorr_signature(
        self,
        sig: bytes,
        pubkey: bytes,
        sigversion: SigVersion,
        execdata: ScriptExecutionData,
        error: Optional[ScriptError] = None
    ) -> bool:
        """
        Check a Schnorr signature (BIP340).
        
        Args:
            sig: The signature (64 or 65 bytes)
            pubkey: The 32-byte x-only public key
            sigversion: Signature version
            execdata: Script execution data
            error: Optional error output
            
        Returns:
            True if signature is valid
        """
        pass
    
    @abstractmethod
    def check_lock_time(self, n_locktime: ScriptNum) -> bool:
        """
        Check if transaction locktime satisfies the requirement.
        
        Args:
            n_locktime: Required locktime
            
        Returns:
            True if locktime requirement is satisfied
        """
        pass
    
    @abstractmethod
    def check_sequence(self, n_sequence: ScriptNum) -> bool:
        """
        Check if input sequence satisfies the requirement.
        
        Args:
            n_sequence: Required sequence
            
        Returns:
            True if sequence requirement is satisfied
        """
        pass


# ============================================================================
# Transaction Signature Checker
# ============================================================================

class TransactionSignatureChecker(BaseSignatureChecker):
    """
    Signature checker for transaction validation.
    
    This implementation verifies signatures against actual transaction data.
    """
    
    def __init__(
        self,
        tx: 'Transaction',
        n_in: int,
        amount: int,
        txdata: Optional[PrecomputedTransactionData] = None,
        missing_data_behavior: MissingDataBehavior = MissingDataBehavior.ASSERT_FAIL
    ):
        """
        Initialize the signature checker.
        
        Args:
            tx: The transaction being verified
            n_in: The input index being verified
            amount: The amount being spent (satoshis)
            txdata: Precomputed transaction data
            missing_data_behavior: How to handle missing data
        """
        self._tx = tx
        self._n_in = n_in
        self._amount = amount
        self._txdata = txdata
        self._missing_data_behavior = missing_data_behavior
    
    @property
    def tx(self) -> 'Transaction':
        return self._tx
    
    @property
    def n_in(self) -> int:
        return self._n_in
    
    @property
    def amount(self) -> int:
        return self._amount
    
    def check_ecdsa_signature(
        self,
        sig: bytes,
        pubkey: bytes,
        script_code: Script,
        sigversion: SigVersion
    ) -> bool:
        """
        Verify an ECDSA signature.
        
        Args:
            sig: DER-encoded signature + sighash type
            pubkey: Public key bytes
            script_code: Script code for sighash
            sigversion: Signature version
            
        Returns:
            True if signature is valid
        """
        from ..crypto.sha256 import Hash256
        
        if len(sig) == 0:
            return False
        
        # Extract hash type
        n_hash_type = sig[-1]
        sig = sig[:-1]
        
        # Compute signature hash
        sighash = self._signature_hash(
            script_code, n_hash_type, sigversion
        )
        
        if sighash is None:
            return False
        
        # Verify signature using coincurve
        if not HAS_COINCURVE:
            # Fallback - cannot verify without secp256k1
            return False
        
        try:
            pubkey_obj = PublicKey(pubkey)
            return pubkey_obj.verify(sig, sighash)
        except Exception:
            return False
    
    def check_schnorr_signature(
        self,
        sig: bytes,
        pubkey: bytes,
        sigversion: SigVersion,
        execdata: ScriptExecutionData,
        error: Optional[ScriptError] = None
    ) -> bool:
        """
        Verify a Schnorr signature (BIP340).
        
        Args:
            sig: 64 or 65 bytes (64 + optional hash type)
            pubkey: 32-byte x-only public key
            sigversion: Signature version
            execdata: Script execution data
            error: Optional error output
            
        Returns:
            True if signature is valid
        """
        # Validate signature size
        if len(sig) == 64:
            hash_type = SIGHASH_DEFAULT
        elif len(sig) == 65:
            hash_type = sig[64]
            sig = sig[:64]
        else:
            return set_error(error, SCRIPT_ERR_SCHNORR_SIG_SIZE)
        
        # Validate hash type
        base_type = hash_type & ~SIGHASH_ANYONECANPAY
        if base_type not in (SIGHASH_DEFAULT, SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE):
            return set_error(error, SCRIPT_ERR_SCHNORR_SIG_HASHTYPE)
        
        # Check public key
        if len(pubkey) == 0:
            return set_error(error, SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY)
        
        if len(pubkey) != 32:
            if sigversion == SigVersion.TAPSCRIPT:
                if self._flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE:
                    return set_error(error, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE)
            return False
        
        # Compute Schnorr sighash
        sighash = self._signature_hash_schnorr(hash_type, sigversion, execdata)
        if sighash is None:
            return False
        
        # Verify using coincurve's Schnorr verification
        if not HAS_COINCURVE:
            return False
        
        try:
            # Use libsecp256k1 for Schnorr verification
            # This is a simplified version - full implementation needs proper bindings
            pubkey_obj = PublicKey.from_signature_and_message(
                sig, sighash, hasher=None
            )
            return pubkey_obj.format(compressed=True)[1:] == pubkey
        except Exception:
            return set_error(error, SCRIPT_ERR_SCHNORR_SIG)
    
    def check_lock_time(self, n_locktime: ScriptNum) -> bool:
        """
        Check if transaction locktime satisfies the requirement.
        
        The transaction is considered valid if:
        - Locktime >= nLockTime
        - All inputs have sequence != SEQUENCE_FINAL
        """
        from ..primitives.transaction import SEQUENCE_FINAL
        
        # Locktime must be positive
        if n_locktime < 0:
            return False
        
        # Compare locktimes
        tx_locktime = self._tx.lock_time
        
        # Check if all inputs have final sequence
        all_final = True
        for tx_in in self._tx.inputs:
            if tx_in.sequence != SEQUENCE_FINAL:
                all_final = False
                break
        
        if all_final:
            return False
        
        # Compare locktime values
        # Height vs time threshold
        LOCKTIME_THRESHOLD = 500000000
        
        if n_locktime.value < LOCKTIME_THRESHOLD:
            # Block height comparison
            if tx_locktime >= LOCKTIME_THRESHOLD:
                return False
        else:
            # UNIX time comparison
            if tx_locktime < LOCKTIME_THRESHOLD:
                return False
        
        return tx_locktime <= n_locktime.value
    
    def check_sequence(self, n_sequence: ScriptNum) -> bool:
        """
        Check if input sequence satisfies the requirement.
        
        Implements BIP68 relative lock-time.
        """
        from ..primitives.transaction import SEQUENCE_FINAL, SEQUENCE_LOCKTIME_TYPE_FLAG
        
        # Sequence must be positive
        if n_sequence < 0:
            return False
        
        n_sequence_val = n_sequence.value
        tx_in = self._tx.inputs[self._n_in]
        
        # If disable flag is set, sequence is not checked
        if n_sequence_val & SEQUENCE_LOCKTIME_TYPE_FLAG:
            return False
        
        # Compare sequence values
        tx_sequence = tx_in.sequence
        
        # If transaction sequence has disable flag, fail
        if tx_sequence & SEQUENCE_LOCKTIME_TYPE_FLAG:
            return False
        
        # Check type (time vs blocks)
        tx_is_time = tx_sequence & SEQUENCE_LOCKTIME_TYPE_FLAG
        req_is_time = n_sequence_val & SEQUENCE_LOCKTIME_TYPE_FLAG
        
        if tx_is_time != req_is_time:
            return False
        
        # Compare values
        return (tx_sequence & 0xFFFF) >= (n_sequence_val & 0xFFFF)
    
    def _signature_hash(
        self,
        script_code: Script,
        n_hash_type: int,
        sigversion: SigVersion
    ) -> Optional[bytes]:
        """
        Compute the signature hash for the transaction input.
        
        Args:
            script_code: The script code
            n_hash_type: Hash type byte
            sigversion: Signature version
            
        Returns:
            32-byte hash, or None on error
        """
        from ..crypto.sha256 import Hash256
        
        if sigversion == SigVersion.BASE:
            # Legacy signature hash
            return self._legacy_signature_hash(script_code, n_hash_type)
        elif sigversion == SigVersion.WITNESS_V0:
            # BIP143 signature hash
            return self._witness_v0_signature_hash(script_code, n_hash_type)
        else:
            # Taproot uses Schnorr
            return None
    
    def _legacy_signature_hash(
        self,
        script_code: Script,
        n_hash_type: int
    ) -> Optional[bytes]:
        """
        Compute legacy (pre-SegWit) signature hash.
        
        Serializes the transaction with the appropriate scriptCode
        substituted for the current input's scriptSig.
        """
        from ..crypto.sha256 import Hash256
        from ..primitives.transaction import Transaction
        
        tx = self._tx
        n_in = self._n_in
        base_type = n_hash_type & 0x1f
        
        # Build preimage
        preimage = bytearray()
        
        # 1. nVersion
        preimage.extend(tx.version.to_bytes(4, 'little'))
        
        # 2. Number of inputs (varint)
        preimage.extend(self._encode_varint(len(tx.inputs)))
        
        # 3. Inputs
        for i, tx_in in enumerate(tx.inputs):
            # Previous output
            preimage.extend(tx_in.prevout.hash)
            preimage.extend(tx_in.prevout.n.to_bytes(4, 'little'))
            
            if i == n_in:
                # Current input: use script_code
                script_bytes = bytes(script_code)
                preimage.extend(self._encode_varint(len(script_bytes)))
                preimage.extend(script_bytes)
            else:
                # Other inputs: empty scriptSig
                preimage.extend(b'\x00')
            
            preimage.extend(tx_in.sequence.to_bytes(4, 'little'))
        
        # 4. Outputs
        if base_type == SIGHASH_NONE:
            # No outputs
            preimage.extend(b'\x00')
        elif base_type == SIGHASH_SINGLE:
            if n_in >= len(tx.outputs):
                # SIGHASH_SINGLE bug: return hash of 1 + 31 zeros
                return bytes([1] + [0] * 31)
            # Outputs up to and including n_in
            preimage.extend(self._encode_varint(n_in + 1))
            for i in range(n_in):
                # Empty output placeholder
                preimage.extend(b'\x00' * 8)  # value = 0
                preimage.extend(b'\x00')       # empty scriptPubKey
            # The actual output at n_in
            preimage.extend(tx.outputs[n_in].serialize())
        else:
            # SIGHASH_ALL: include all outputs
            preimage.extend(self._encode_varint(len(tx.outputs)))
            for tx_out in tx.outputs:
                preimage.extend(tx_out.serialize())
        
        # 5. nLockTime
        preimage.extend(tx.lock_time.to_bytes(4, 'little'))
        
        # 6. nHashType
        preimage.extend(n_hash_type.to_bytes(4, 'little'))
        
        return Hash256(bytes(preimage))
    
    @staticmethod
    def _encode_varint(n: int) -> bytes:
        """Encode an integer as a Bitcoin varint."""
        if n < 0xfd:
            return bytes([n])
        elif n <= 0xffff:
            return bytes([0xfd]) + n.to_bytes(2, 'little')
        elif n <= 0xffffffff:
            return bytes([0xfe]) + n.to_bytes(4, 'little')
        else:
            return bytes([0xff]) + n.to_bytes(8, 'little')
    
    def _witness_v0_signature_hash(
        self,
        script_code: Script,
        n_hash_type: int
    ) -> Optional[bytes]:
        """
        Compute BIP143 witness v0 signature hash.
        """
        from ..crypto.sha256 import Hash256
        
        # Initialize precomputed data if needed
        if self._txdata is None:
            self._txdata = PrecomputedTransactionData()
            self._txdata.init(self._tx, [])
        
        tx = self._tx
        
        # Build preimage according to BIP143
        preimage = b''
        
        # 1. nVersion
        preimage += tx.version.to_bytes(4, 'little')
        
        # 2. hashPrevouts
        if not (n_hash_type & SIGHASH_ANYONECANPAY):
            preimage += self._txdata.hash_prevouts
        else:
            preimage += b'\x00' * 32
        
        # 3. hashSequence
        if not (n_hash_type & SIGHASH_ANYONECANPAY) and \
           (n_hash_type & 0x1f) not in (SIGHASH_SINGLE, SIGHASH_NONE):
            preimage += self._txdata.hash_sequence
        else:
            preimage += b'\x00' * 32
        
        # 4. outpoint
        tx_in = tx.inputs[self._n_in]
        preimage += tx_in.prevout.hash
        preimage += tx_in.prevout.n.to_bytes(4, 'little')
        
        # 5. scriptCode
        preimage += bytes([len(script_code)])
        preimage += bytes(script_code)
        
        # 6. value
        preimage += self._amount.to_bytes(8, 'little')
        
        # 7. nSequence
        preimage += tx_in.sequence.to_bytes(4, 'little')
        
        # 8. hashOutputs
        if (n_hash_type & 0x1f) == SIGHASH_SINGLE:
            if self._n_in >= len(tx.outputs):
                return None
            preimage += Hash256(tx.outputs[self._n_in].serialize())
        elif (n_hash_type & 0x1f) != SIGHASH_NONE:
            preimage += self._txdata.hash_outputs
        else:
            preimage += b'\x00' * 32
        
        # 9. nLockTime
        preimage += tx.lock_time.to_bytes(4, 'little')
        
        # 10. sighash type
        preimage += n_hash_type.to_bytes(4, 'little')
        
        return Hash256(preimage)
    
    def _signature_hash_schnorr(
        self,
        hash_type: int,
        sigversion: SigVersion,
        execdata: ScriptExecutionData
    ) -> Optional[bytes]:
        """
        Compute Schnorr signature hash for Taproot (BIP341).
        """
        # Full implementation requires extensive transaction data handling
        # This is a placeholder
        return None


# ============================================================================
# Mutable Transaction Signature Checker
# ============================================================================

class MutableTransactionSignatureChecker(TransactionSignatureChecker):
    """
    Signature checker for mutable transactions (during signing).
    """
    
    def __init__(
        self,
        tx: 'Transaction',
        n_in: int,
        amount: int,
        txdata: Optional[PrecomputedTransactionData] = None
    ):
        super().__init__(tx, n_in, amount, txdata, MissingDataBehavior.FAIL)


# ============================================================================
# Deferring Signature Checker
# ============================================================================

class DeferringSignatureChecker(BaseSignatureChecker):
    """
    Signature checker that defers to another checker.
    
    Used for P2SH where we need to reuse the parent checker.
    """
    
    def __init__(self, checker: BaseSignatureChecker):
        self._checker = checker
    
    def check_ecdsa_signature(
        self,
        sig: bytes,
        pubkey: bytes,
        script_code: Script,
        sigversion: SigVersion
    ) -> bool:
        return self._checker.check_ecdsa_signature(sig, pubkey, script_code, sigversion)
    
    def check_schnorr_signature(
        self,
        sig: bytes,
        pubkey: bytes,
        sigversion: SigVersion,
        execdata: ScriptExecutionData,
        error: Optional[ScriptError] = None
    ) -> bool:
        return self._checker.check_schnorr_signature(sig, pubkey, sigversion, execdata, error)
    
    def check_lock_time(self, n_locktime: ScriptNum) -> bool:
        return self._checker.check_lock_time(n_locktime)
    
    def check_sequence(self, n_sequence: ScriptNum) -> bool:
        return self._checker.check_sequence(n_sequence)
