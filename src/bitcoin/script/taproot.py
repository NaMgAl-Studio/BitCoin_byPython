# Copyright (c) 2009-2010 Satoshi Nakamoto
# Copyright (c) 2009-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Bitcoin Taproot Implementation (BIP340, BIP341, BIP342)

This module implements Taproot functionality:
- Schnorr signatures (BIP340)
- Taproot output key computation (BIP341)
- Taproot script path verification (BIP341, BIP342)
- Tapscript execution rules (BIP342)
"""

from typing import Optional, List, Tuple
from dataclasses import dataclass
import struct

from .script import Script
from .sigversion import (
    SigVersion, TAPROOT_LEAF_MASK, TAPROOT_LEAF_TAPSCRIPT,
    TAPROOT_CONTROL_BASE_SIZE, TAPROOT_CONTROL_NODE_SIZE,
    TAPROOT_CONTROL_MAX_NODE_COUNT, TAPROOT_CONTROL_MAX_SIZE,
)
from .script_error import (
    ScriptError,
    SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE,
    SCRIPT_ERR_SCHNORR_SIG_SIZE,
    SCRIPT_ERR_SCHNORR_SIG_HASHTYPE,
    SCRIPT_ERR_SCHNORR_SIG,
    SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT,
    SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG,
    SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY,
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
)
from .verify_flags import (
    SCRIPT_VERIFY_TAPROOT,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
    SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
)
from .sighash import (
    tagged_hash, TaggedHashers,
    ComputeTapleafHash, ComputeTapbranchHash, ComputeTaprootMerkleRoot,
)
from .interpreter import ScriptExecutionData

# Try to import secp256k1 library
try:
    from coincurve import PublicKey, PrivateKey
    from coincurve._libsecp256k1 import ffi, lib
    HAS_COINCURVE = True
except ImportError:
    HAS_COINCURVE = False


# ============================================================================
# Constants
# ============================================================================

# secp256k1 field size
SECP256K1_FIELD_SIZE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# secp256k1 curve order
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# secp256k1 generator point
SECP256K1_GENERATOR = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
)


# ============================================================================
# X-Only Public Keys
# ============================================================================

@dataclass(frozen=True)
class XOnlyPubKey:
    """
    An x-only public key (32 bytes).
    
    In BIP340, public keys are represented as just the x-coordinate,
    with the parity implicitly determined during verification.
    """
    
    data: bytes  # 32 bytes
    
    def __post_init__(self):
        if len(self.data) != 32:
            raise ValueError("XOnlyPubKey must be 32 bytes")
    
    @classmethod
    def from_compressed(cls, compressed: bytes) -> 'XOnlyPubKey':
        """
        Create from a compressed public key (33 bytes).
        
        Args:
            compressed: 33-byte compressed public key (02/03 prefix + x)
            
        Returns:
            XOnlyPubKey (drops the parity byte)
        """
        if len(compressed) != 33:
            raise ValueError("Compressed pubkey must be 33 bytes")
        return cls(compressed[1:])
    
    def to_compressed(self, parity: bool) -> bytes:
        """
        Convert to compressed format with explicit parity.
        
        Args:
            parity: True for odd y-coordinate (03 prefix)
            
        Returns:
            33-byte compressed public key
        """
        prefix = bytes([0x03 if parity else 0x02])
        return prefix + self.data
    
    def verify_schnorr(self, sig: bytes, msg: bytes) -> bool:
        """
        Verify a Schnorr signature against this public key.
        
        Args:
            sig: 64-byte signature
            msg: 32-byte message
            
        Returns:
            True if signature is valid
        """
        if not HAS_COINCURVE:
            raise RuntimeError("coincurve required for Schnorr verification")
        
        if len(sig) != 64:
            return False
        
        if len(msg) != 32:
            return False
        
        try:
            # Use coincurve's Schnorr verification
            # This requires the full public key with parity
            # Try both parities
            for parity in [False, True]:
                try:
                    pubkey = PublicKey(self.to_compressed(parity))
                    if pubkey.verify_schnorr(sig, msg):
                        return True
                except Exception:
                    continue
            return False
        except Exception:
            return False
    
    def tweak_add(self, tweak: bytes) -> 'XOnlyPubKey':
        """
        Add a tweak to the public key.
        
        Args:
            tweak: 32-byte tweak value
            
        Returns:
            New XOnlyPubKey with tweak applied
        """
        if not HAS_COINCURVE:
            raise RuntimeError("coincurve required for tweaking")
        
        if len(tweak) != 32:
            raise ValueError("Tweak must be 32 bytes")
        
        # Try both parities
        for parity in [False, True]:
            try:
                pubkey = PublicKey(self.to_compressed(parity))
                tweaked = pubkey.add(tweak)
                return XOnlyPubKey(tweaked.format(compressed=True)[1:])
            except Exception:
                continue
        
        raise ValueError("Invalid public key for tweaking")


# ============================================================================
# Taproot Key Path Spending
# ============================================================================

def ComputeTaprootOutputKey(internal_key: XOnlyPubKey, merkle_root: bytes) -> XOnlyPubKey:
    """
    Compute the Taproot output key from internal key and merkle root.
    
    The output key is computed as:
    P = internal_key + int(Hash("TapTweak" || internal_key || merkle_root)) * G
    
    Args:
        internal_key: The internal public key
        merkle_root: 32-byte merkle root (or all zeros if no script path)
        
    Returns:
        The tweaked output key
    """
    # Compute tweak
    tweak_data = internal_key.data + merkle_root
    tweak = tagged_hash("TapTweak", tweak_data)
    
    # Apply tweak
    return internal_key.tweak_add(tweak)


def ComputeTaprootOutputKeyNoTweak(internal_key: XOnlyPubKey) -> XOnlyPubKey:
    """
    Compute Taproot output key without script path (no tweak).
    
    This is equivalent to ComputeTaprootOutputKey with merkle_root = 0.
    
    Args:
        internal_key: The internal public key
        
    Returns:
        The output key (tweaked with empty merkle tree)
    """
    return ComputeTaprootOutputKey(internal_key, bytes(32))


# ============================================================================
# Taproot Script Path
# ============================================================================

def VerifyTaprootScriptPath(
    output_key: bytes,
    script: Script,
    control_block: bytes,
    witness_stack: List[bytes],
    flags: int,
    checker,
    execdata: ScriptExecutionData,
    error: Optional[ScriptError] = None
) -> bool:
    """
    Verify a Taproot script path spend.
    
    Args:
        output_key: 32-byte output key from scriptPubKey
        script: The tapscript being spent
        control_block: The control block from witness
        witness_stack: Rest of witness stack (excluding script and control)
        flags: Verification flags
        checker: Signature checker
        execdata: Script execution data
        error: Optional error output
        
    Returns:
        True if script path is valid
    """
    # Validate control block size
    control_size = len(control_block)
    if control_size < TAPROOT_CONTROL_BASE_SIZE:
        return set_error(error, SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE)
    
    extra_size = control_size - TAPROOT_CONTROL_BASE_SIZE
    if extra_size % TAPROOT_CONTROL_NODE_SIZE != 0:
        return set_error(error, SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE)
    
    path_len = extra_size // TAPROOT_CONTROL_NODE_SIZE
    if path_len > 128:
        return set_error(error, SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE)
    
    # Extract leaf version and parity
    leaf_version = control_block[0] & TAPROOT_LEAF_MASK
    parity = control_block[0] & 0x01
    
    # Check leaf version
    if leaf_version != TAPROOT_LEAF_TAPSCRIPT:
        if flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION:
            return set_error(error, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION)
        # Unknown leaf version succeeds immediately
        return True
    
    # Get internal key from control block
    internal_key = XOnlyPubKey(control_block[1:33])
    
    # Compute tapleaf hash
    tapleaf_hash = ComputeTapleafHash(leaf_version, bytes(script))
    execdata.tapleaf_hash = tapleaf_hash
    execdata.tapleaf_hash_init = True
    
    # Compute merkle root
    merkle_root = ComputeTaprootMerkleRoot(control_block, tapleaf_hash)
    
    # Compute expected output key
    expected_output_key = ComputeTaprootOutputKey(internal_key, merkle_root)
    
    # Verify output key matches
    if expected_output_key.data != output_key:
        return False
    
    # Initialize execution data
    execdata.codeseparator_pos = 0xFFFFFFFF
    execdata.codeseparator_pos_init = True
    
    # Check for annex (last witness element if starts with 0x50)
    annex_present = False
    annex = None
    if len(witness_stack) > 0 and len(witness_stack[-1]) > 0:
        if witness_stack[-1][0] == 0x50:
            annex_present = True
            annex = witness_stack[-1]
    
    execdata.annex_present = annex_present
    execdata.annex_init = True
    if annex_present:
        execdata.annex_hash = tagged_hash("TapAnnex", annex)
    
    # Initialize validation weight
    # Weight budget = witness size * 50 + 50
    witness_size = sum(len(item) for item in witness_stack)
    execdata.validation_weight_left = witness_size * 50 + 50
    execdata.validation_weight_left_init = True
    
    # Execute the script with witness stack
    from .interpreter import EvalScript
    
    stack = list(witness_stack)
    if annex_present:
        stack.pop()  # Remove annex
    
    if not EvalScript(stack, script, flags, checker, SigVersion.TAPSCRIPT, execdata, error):
        return False
    
    # Check stack result
    if len(stack) == 0:
        return set_error(error, SCRIPT_ERR_EVAL_FALSE)
    
    from .interpreter import CastToBool
    if not CastToBool(stack[-1]):
        return set_error(error, SCRIPT_ERR_EVAL_FALSE)
    
    return True


# ============================================================================
# Tapscript-specific Rules
# ============================================================================

def CheckTapscriptSignature(
    sig: bytes,
    pubkey: bytes,
    flags: int,
    execdata: ScriptExecutionData,
    error: Optional[ScriptError] = None
) -> bool:
    """
    Check signature encoding for Tapscript.
    
    Args:
        sig: The signature (64 or 65 bytes)
        pubkey: The public key
        flags: Verification flags
        execdata: Script execution data
        error: Optional error output
        
    Returns:
        True if signature is valid format
    """
    from .interpreter import set_error
    
    # Check signature size
    if len(sig) not in (64, 65):
        return set_error(error, SCRIPT_ERR_SCHNORR_SIG_SIZE)
    
    # Check hash type if 65 bytes
    if len(sig) == 65:
        hash_type = sig[64]
        base_type = hash_type & 0x9f  # Mask out ANYONECANPAY and unused bits
        if base_type > 3:  # Only DEFAULT(0), ALL(1), NONE(2), SINGLE(3) valid
            return set_error(error, SCRIPT_ERR_SCHNORR_SIG_HASHTYPE)
    
    # Check pubkey
    if len(pubkey) == 0:
        return set_error(error, SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY)
    
    if len(pubkey) != 32:
        if flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE:
            return set_error(error, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE)
    
    return True


def CheckTapscriptValidationWeight(
    execdata: ScriptExecutionData,
    error: Optional[ScriptError] = None
) -> bool:
    """
    Check validation weight budget.
    
    Args:
        execdata: Script execution data
        error: Optional error output
        
    Returns:
        True if within budget
    """
    if execdata.validation_weight_left < 0:
        return set_error(error, SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT)
    return True


def IsCheckMultisigDisabledInTapscript(opcode: int) -> bool:
    """
    Check if opcode is disabled in Tapscript.
    
    OP_CHECKMULTISIG and OP_CHECKMULTISIGVERIFY are disabled in Tapscript
    because they have issues with batch signature verification.
    
    Args:
        opcode: The opcode to check
        
    Returns:
        True if opcode is disabled in Tapscript
    """
    from .opcodes import OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY
    return opcode in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY)


# ============================================================================
# Helper Functions
# ============================================================================

def set_error(error: Optional[ScriptError], error_type) -> bool:
    """Set error type and return False."""
    if error is not None:
        error.error_type = error_type
    return False


# ============================================================================
# Taproot Builder
# ============================================================================

class TaprootBuilder:
    """
    Builder for Taproot outputs and witnesses.
    
    This class helps construct Taproot script trees and compute
    output keys and control blocks.
    """
    
    def __init__(self):
        self._branches: List[Tuple[bytes, int]] = []  # (script, leaf_version)
        self._tree: Optional[TapTree] = None
    
    def add_leaf(self, script: Script, leaf_version: int = TAPROOT_LEAF_TAPSCRIPT) -> 'TaprootBuilder':
        """
        Add a leaf script to the tree.
        
        Args:
            script: The script
            leaf_version: Leaf version byte
            
        Returns:
            self for chaining
        """
        self._branches.append((bytes(script), leaf_version))
        return self
    
    def build(self, internal_key: XOnlyPubKey) -> Tuple[XOnlyPubKey, Optional[TapTree]]:
        """
        Build the Taproot output.
        
        Args:
            internal_key: The internal key
            
        Returns:
            Tuple of (output_key, tree)
        """
        if not self._branches:
            # Key path only
            return ComputeTaprootOutputKeyNoTweak(internal_key), None
        
        # Build tree from leaves
        tree = TapTree.from_leaves(self._branches)
        merkle_root = tree.root
        
        output_key = ComputeTaprootOutputKey(internal_key, merkle_root)
        return output_key, tree


class TapTree:
    """
    Taproot script tree.
    
    Represents a binary tree of tapleaves.
    """
    
    def __init__(self, root: bytes):
        self.root = root
    
    @classmethod
    def from_leaves(cls, leaves: List[Tuple[bytes, int]]) -> 'TapTree':
        """
        Build a tree from a list of leaves.
        
        Args:
            leaves: List of (script, leaf_version) tuples
            
        Returns:
            TapTree with computed root
        """
        if not leaves:
            return cls(bytes(32))
        
        # Compute tapleaf hashes
        leaf_hashes = []
        for script, version in leaves:
            leaf_hashes.append(ComputeTapleafHash(version, script))
        
        # Build merkle tree
        while len(leaf_hashes) > 1:
            new_level = []
            for i in range(0, len(leaf_hashes), 2):
                if i + 1 < len(leaf_hashes):
                    new_level.append(ComputeTapbranchHash(leaf_hashes[i], leaf_hashes[i+1]))
                else:
                    new_level.append(leaf_hashes[i])
            leaf_hashes = new_level
        
        return cls(leaf_hashes[0])
    
    def get_control_block(self, internal_key: XOnlyPubKey, leaf_index: int,
                          leaves: List[Tuple[bytes, int]]) -> bytes:
        """
        Get the control block for spending a specific leaf.
        
        Args:
            internal_key: The internal key
            leaf_index: Index of the leaf to spend
            leaves: List of (script, leaf_version) used to build tree
            
        Returns:
            Control block bytes
        """
        if leaf_index >= len(leaves):
            raise ValueError("Leaf index out of range")
        
        script, version = leaves[leaf_index]
        leaf_hash = ComputeTapleafHash(version, script)
        
        # Compute path from leaf to root
        leaf_hashes = [ComputeTapleafHash(v, s) for s, v in leaves]
        path = self._get_path(leaf_hashes, leaf_index)
        
        # Build control block
        control = bytearray()
        control.append(version)  # Leaf version (parity will be 0)
        control.extend(internal_key.data)
        control.extend(path)
        
        return bytes(control)
    
    def _get_path(self, hashes: List[bytes], index: int) -> bytes:
        """Get the path from a leaf to the root."""
        path = bytearray()
        current_level = hashes
        current_index = index
        
        while len(current_level) > 1:
            # Get sibling
            if current_index % 2 == 0:
                # We're on the left, sibling is on the right
                sibling_idx = current_index + 1
            else:
                # We're on the right, sibling is on the left
                sibling_idx = current_index - 1
            
            if sibling_idx < len(current_level):
                path.extend(current_level[sibling_idx])
            
            # Move up
            current_level = [
                ComputeTapbranchHash(current_level[i], current_level[i+1])
                for i in range(0, len(current_level) - 1, 2)
            ]
            if len(current_level) > 0 and current_index % 2 == 1:
                current_level = current_level[1:]
            current_index //= 2
        
        return bytes(path)
