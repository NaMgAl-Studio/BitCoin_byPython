# Copyright (c) 2009-2010 Satoshi Nakamoto
# Copyright (c) 2009-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Bitcoin Script Solver

This module provides functionality for analyzing and solving Bitcoin scripts.
It can extract standard script templates and generate solutions.
"""

from typing import Optional, List, Tuple, NamedTuple
from dataclasses import dataclass
from enum import Enum, auto

from .script import Script
from .opcodes import (
    OP_0, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4,
    OP_1NEGATE, OP_1, OP_16,
    OP_HASH160, OP_EQUAL, OP_CHECKSIG, OP_CHECKMULTISIG,
    OP_CHECKSIGVERIFY, OP_CHECKMULTISIGVERIFY,
    OP_CODESEPARATOR, OP_RETURN,
    DecodeOP_N,
)


# ============================================================================
# Script Types
# ============================================================================

class ScriptType(Enum):
    """Enumeration of standard script types."""
    
    # Non-standard
    NON_STANDARD = auto()
    
    # Pay to Public Key (P2PK)
    PUB_KEY = auto()            # <pubkey> OP_CHECKSIG
    
    # Pay to Public Key Hash (P2PKH)
    PUB_KEY_HASH = auto()       # OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
    
    # Pay to Script Hash (P2SH)
    SCRIPT_HASH = auto()        # OP_HASH160 <hash> OP_EQUAL
    
    # Multisig
    MULTISIG = auto()           # <m> <pubkey>* <n> OP_CHECKMULTISIG
    
    # Null Data (OP_RETURN)
    NULL_DATA = auto()          # OP_RETURN <data>*
    
    # Witness v0
    WITNESS_V0_KEYHASH = auto() # OP_0 <20 bytes>
    WITNESS_V0_SCRIPTHASH = auto()  # OP_0 <32 bytes>
    
    # Witness v1 (Taproot)
    WITNESS_V1_TAPROOT = auto() # OP_1 <32 bytes>
    
    # Anchor
    ANCHOR = auto()             # OP_1 <0x4e73>


@dataclass
class ScriptSolution:
    """
    Solution to a scriptPubKey.
    
    Contains the extracted parameters from a standard script.
    """
    
    script_type: ScriptType
    
    # P2PK
    pubkey: Optional[bytes] = None
    
    # P2PKH, P2SH, P2WPKH
    hash160: Optional[bytes] = None
    
    # P2WSH
    hash256: Optional[bytes] = None
    
    # P2TR
    output_key: Optional[bytes] = None
    
    # Multisig
    required_sigs: int = 0
    pubkeys: Optional[List[bytes]] = None
    
    # OP_RETURN
    data: Optional[List[bytes]] = None


# ============================================================================
# Script Solver
# ============================================================================

def Solver(script: Script) -> ScriptSolution:
    """
    Analyze a scriptPubKey and extract its solution.
    
    Args:
        script: The script to analyze
        
    Returns:
        ScriptSolution containing the extracted parameters
    """
    ops = list(script.iterate_ops())
    
    if not ops:
        return ScriptSolution(ScriptType.NON_STANDARD)
    
    # Check OP_RETURN
    if ops[0][0] == OP_RETURN:
        data = [op[1] for op in ops[1:]]
        return ScriptSolution(ScriptType.NULL_DATA, data=data)
    
    # Check P2PK: <pubkey> OP_CHECKSIG
    if len(ops) == 2:
        opcode, data = ops[0], ops[0][1]
        # Get the actual opcode and data
        success, _, first_opcode, first_data = script.get_op(0)
        if success and len(first_data) in (33, 65):  # Compressed or uncompressed
            success2, _, second_opcode, _ = script.get_op(1 + len(first_data) + 
                                                          (1 if len(first_data) < 76 else 2))
            if second_opcode == OP_CHECKSIG:
                return ScriptSolution(ScriptType.PUB_KEY, pubkey=first_data)
    
    # Check P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if _match_p2pkh(script):
        hash160 = bytes(script.data[3:23])
        return ScriptSolution(ScriptType.PUB_KEY_HASH, hash160=hash160)
    
    # Check P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    if _match_p2sh(script):
        hash160 = bytes(script.data[2:22])
        return ScriptSolution(ScriptType.SCRIPT_HASH, hash160=hash160)
    
    # Check P2WPKH: OP_0 <20 bytes>
    if _match_p2wpkh(script):
        hash160 = bytes(script.data[2:22])
        return ScriptSolution(ScriptType.WITNESS_V0_KEYHASH, hash160=hash160)
    
    # Check P2WSH: OP_0 <32 bytes>
    if _match_p2wsh(script):
        hash256 = bytes(script.data[2:34])
        return ScriptSolution(ScriptType.WITNESS_V0_SCRIPTHASH, hash256=hash256)
    
    # Check P2TR: OP_1 <32 bytes>
    if _match_p2tr(script):
        output_key = bytes(script.data[2:34])
        return ScriptSolution(ScriptType.WITNESS_V1_TAPROOT, output_key=output_key)
    
    # Check anchor
    if _match_anchor(script):
        return ScriptSolution(ScriptType.ANCHOR)
    
    # Check Multisig: <m> <pubkey>* <n> OP_CHECKMULTISIG
    multisig = _match_multisig(script)
    if multisig:
        m, pubkeys, n = multisig
        return ScriptSolution(
            ScriptType.MULTISIG,
            required_sigs=m,
            pubkeys=pubkeys
        )
    
    return ScriptSolution(ScriptType.NON_STANDARD)


# ============================================================================
# Pattern Matching Functions
# ============================================================================

def _match_p2pkh(script: Script) -> bool:
    """Check if script matches P2PKH pattern."""
    # OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if len(script) != 25:
        return False
    data = script.data
    return (data[0] == 0x76 and   # OP_DUP
            data[1] == 0xa9 and   # OP_HASH160
            data[2] == 0x14 and   # Push 20 bytes
            data[23] == 0x88 and  # OP_EQUALVERIFY
            data[24] == 0xac)     # OP_CHECKSIG


def _match_p2sh(script: Script) -> bool:
    """Check if script matches P2SH pattern."""
    # OP_HASH160 <20 bytes> OP_EQUAL
    if len(script) != 23:
        return False
    data = script.data
    return (data[0] == 0xa9 and   # OP_HASH160
            data[1] == 0x14 and   # Push 20 bytes
            data[22] == 0x87)     # OP_EQUAL


def _match_p2wpkh(script: Script) -> bool:
    """Check if script matches P2WPKH pattern."""
    # OP_0 <20 bytes>
    if len(script) != 22:
        return False
    data = script.data
    return (data[0] == 0x00 and   # OP_0
            data[1] == 0x14)      # Push 20 bytes


def _match_p2wsh(script: Script) -> bool:
    """Check if script matches P2WSH pattern."""
    # OP_0 <32 bytes>
    if len(script) != 34:
        return False
    data = script.data
    return (data[0] == 0x00 and   # OP_0
            data[1] == 0x20)      # Push 32 bytes


def _match_p2tr(script: Script) -> bool:
    """Check if script matches P2TR pattern."""
    # OP_1 <32 bytes>
    if len(script) != 34:
        return False
    data = script.data
    return (data[0] == 0x51 and   # OP_1
            data[1] == 0x20)      # Push 32 bytes


def _match_anchor(script: Script) -> bool:
    """Check if script matches anchor pattern."""
    # OP_1 <0x4e73>
    if len(script) != 4:
        return False
    data = script.data
    return (data[0] == 0x51 and   # OP_1
            data[1] == 0x02 and   # Push 2 bytes
            data[2] == 0x4e and   # First byte
            data[3] == 0x73)      # Second byte


def _match_multisig(script: Script) -> Optional[Tuple[int, List[bytes], int]]:
    """
    Check if script matches multisig pattern.
    
    Returns:
        Tuple of (m, pubkeys, n) or None if not multisig
    """
    # <m> <pubkey>* <n> OP_CHECKMULTISIG
    ops = list(script.iterate_ops())
    
    if len(ops) < 3:
        return None
    
    # First opcode must be OP_1..OP_16 (m)
    first_opcode = ops[0][0]
    if not (OP_1 <= first_opcode <= OP_16):
        return None
    
    m = DecodeOP_N(first_opcode)
    
    # Last opcode must be OP_CHECKMULTISIG
    if ops[-1][0] != OP_CHECKMULTISIG:
        return None
    
    # Second-to-last must be OP_1..OP_16 (n)
    second_last_opcode = ops[-2][0]
    if not (OP_1 <= second_last_opcode <= OP_16):
        return None
    
    n = DecodeOP_N(second_last_opcode)
    
    # Must have n pubkeys between m and n
    if len(ops) != n + 3:  # m + n pubkeys + n + OP_CHECKMULTISIG
        return None
    
    # Extract pubkeys
    pubkeys = []
    for i in range(1, n + 1):
        data = ops[i][1]
        if len(data) not in (33, 65):  # Must be valid pubkey size
            return None
        pubkeys.append(data)
    
    # m must be <= n
    if m > n:
        return None
    
    return m, pubkeys, n


# ============================================================================
# Script Classification
# ============================================================================

def IsStandard(script: Script) -> bool:
    """
    Check if a script is standard (relayable).
    
    Non-standard scripts may be valid but won't be relayed by default.
    
    Args:
        script: The script to check
        
    Returns:
        True if the script is standard
    """
    solution = Solver(script)
    return solution.script_type != ScriptType.NON_STANDARD


def IsPushOnly(script: Script) -> bool:
    """
    Check if a script contains only push operations.
    
    Args:
        script: The script to check
        
    Returns:
        True if the script only contains push operations
    """
    return script.is_push_only()


def IsPayToPubkey(script: Script) -> bool:
    """Check if script is P2PK."""
    return Solver(script).script_type == ScriptType.PUB_KEY


def IsPayToPubkeyHash(script: Script) -> bool:
    """Check if script is P2PKH."""
    return Solver(script).script_type == ScriptType.PUB_KEY_HASH


def IsPayToScriptHash(script: Script) -> bool:
    """Check if script is P2SH."""
    return Solver(script).script_type == ScriptType.SCRIPT_HASH


def IsPayToWitnessKeyHash(script: Script) -> bool:
    """Check if script is P2WPKH."""
    return Solver(script).script_type == ScriptType.WITNESS_V0_KEYHASH


def IsPayToWitnessScriptHash(script: Script) -> bool:
    """Check if script is P2WSH."""
    return Solver(script).script_type == ScriptType.WITNESS_V0_SCRIPTHASH


def IsPayToTaproot(script: Script) -> bool:
    """Check if script is P2TR."""
    return Solver(script).script_type == ScriptType.WITNESS_V1_TAPROOT


def IsMultisig(script: Script) -> bool:
    """Check if script is multisig."""
    return Solver(script).script_type == ScriptType.MULTISIG


def IsNullData(script: Script) -> bool:
    """Check if script is OP_RETURN data."""
    return Solver(script).script_type == ScriptType.NULL_DATA


# ============================================================================
# Script Extraction
# ============================================================================

def ExtractPubkey(script: Script) -> Optional[bytes]:
    """Extract public key from P2PK script."""
    solution = Solver(script)
    if solution.script_type == ScriptType.PUB_KEY:
        return solution.pubkey
    return None


def ExtractHash160(script: Script) -> Optional[bytes]:
    """Extract HASH160 from P2PKH or P2SH script."""
    solution = Solver(script)
    if solution.script_type in (ScriptType.PUB_KEY_HASH, ScriptType.SCRIPT_HASH):
        return solution.hash160
    if solution.script_type == ScriptType.WITNESS_V0_KEYHASH:
        return solution.hash160
    return None


def ExtractWitnessProgram(script: Script) -> Optional[Tuple[int, bytes]]:
    """
    Extract witness program from witness script.
    
    Returns:
        Tuple of (version, program) or None
    """
    is_witness, version, program = script.is_witness_program()
    if is_witness:
        return version, program
    return None


def ExtractMultisig(script: Script) -> Optional[Tuple[int, List[bytes]]]:
    """
    Extract multisig parameters from script.
    
    Returns:
        Tuple of (required_sigs, pubkeys) or None
    """
    solution = Solver(script)
    if solution.script_type == ScriptType.MULTISIG:
        return solution.required_sigs, solution.pubkeys
    return None
