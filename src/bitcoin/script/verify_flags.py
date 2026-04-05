# Copyright (c) 2009-2010 Satoshi Nakamoto
# Copyright (c) 2009-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Bitcoin Script Verification Flags

This module defines script verification flags that control which consensus
rules are applied during script validation. These flags are used to enable
soft-fork upgrades and additional validation rules.

All flags are intended to be soft forks: the set of acceptable scripts under
flags (A | B) is a subset of the acceptable scripts under flag (A).
"""

from enum import IntFlag, auto
from typing import List, Dict, Optional


class ScriptVerifyFlag(IntFlag):
    """
    Individual script verification flags.
    
    Each flag enables a specific validation rule. Flags can be combined
    using bitwise OR (|) to enable multiple rules.
    """
    
    # No validation rules enabled
    NONE = 0
    
    # Evaluate P2SH subscripts (BIP16)
    # Enables pay-to-script-hash validation
    P2SH = auto()
    
    # Passing a non-strict-DER signature or one with undefined hashtype
    # to a checksig operation causes script failure.
    # Evaluating a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes)
    # by checksig causes script failure.
    STRICTENC = auto()
    
    # Passing a non-strict-DER signature to a checksig operation causes
    # script failure (BIP62 rule 1)
    DERSIG = auto()
    
    # Passing a non-strict-DER signature or one with S > order/2 to a
    # checksig operation causes script failure (BIP62 rule 5)
    LOW_S = auto()
    
    # Verify dummy stack item consumed by CHECKMULTISIG is of zero-length
    # (BIP62 rule 7)
    NULLDUMMY = auto()
    
    # Using a non-push operator in the scriptSig causes script failure
    # (BIP62 rule 2)
    SIGPUSHONLY = auto()
    
    # Require minimal encodings for all push operations (BIP62 rule 3)
    # Also require minimal length when interpreting stack elements as numbers
    # (BIP62 rule 4)
    MINIMALDATA = auto()
    
    # Discourage use of NOPs reserved for upgrades (NOP1-10)
    # NOPs that have associated forks (CLTV, CSV) are not subject to this rule
    DISCOURAGE_UPGRADABLE_NOPS = auto()
    
    # Require that only a single stack element remains after evaluation
    # Changes success criterion from "at least one true element" to
    # "exactly one true element" (BIP62 rule 6)
    # Note: CLEANSTACK should never be used without P2SH or WITNESS
    CLEANSTACK = auto()
    
    # Verify CHECKLOCKTIMEVERIFY (BIP65)
    CHECKLOCKTIMEVERIFY = auto()
    
    # Support CHECKSEQUENCEVERIFY opcode (BIP112)
    CHECKSEQUENCEVERIFY = auto()
    
    # Support segregated witness (BIP141)
    WITNESS = auto()
    
    # Making v1-v16 witness program non-standard
    DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = auto()
    
    # Segwit script only: Require the argument of OP_IF/NOTIF to be exactly
    # 0x01 or empty vector
    MINIMALIF = auto()
    
    # Signature(s) must be empty vector if a CHECK(MULTI)SIG operation failed
    NULLFAIL = auto()
    
    # Public keys in segregated witness scripts must be compressed
    WITNESS_PUBKEYTYPE = auto()
    
    # Making OP_CODESEPARATOR and FindAndDelete fail any non-segwit scripts
    CONST_SCRIPTCODE = auto()
    
    # Taproot/Tapscript validation (BIPs 341 & 342)
    TAPROOT = auto()
    
    # Making unknown Taproot leaf versions non-standard
    DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = auto()
    
    # Making unknown OP_SUCCESS non-standard
    DISCOURAGE_OP_SUCCESS = auto()
    
    # Making unknown public key versions (in BIP 342 scripts) non-standard
    DISCOURAGE_UPGRADABLE_PUBKEYTYPE = auto()


class ScriptVerifyFlags:
    """
    Script verification flags container.
    
    This class provides methods for working with combined verification flags
    and converting between flag names and values.
    """
    
    # Flag values
    NONE = ScriptVerifyFlag.NONE
    P2SH = ScriptVerifyFlag.P2SH
    STRICTENC = ScriptVerifyFlag.STRICTENC
    DERSIG = ScriptVerifyFlag.DERSIG
    LOW_S = ScriptVerifyFlag.LOW_S
    NULLDUMMY = ScriptVerifyFlag.NULLDUMMY
    SIGPUSHONLY = ScriptVerifyFlag.SIGPUSHONLY
    MINIMALDATA = ScriptVerifyFlag.MINIMALDATA
    DISCOURAGE_UPGRADABLE_NOPS = ScriptVerifyFlag.DISCOURAGE_UPGRADABLE_NOPS
    CLEANSTACK = ScriptVerifyFlag.CLEANSTACK
    CHECKLOCKTIMEVERIFY = ScriptVerifyFlag.CHECKLOCKTIMEVERIFY
    CHECKSEQUENCEVERIFY = ScriptVerifyFlag.CHECKSEQUENCEVERIFY
    WITNESS = ScriptVerifyFlag.WITNESS
    DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = ScriptVerifyFlag.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
    MINIMALIF = ScriptVerifyFlag.MINIMALIF
    NULLFAIL = ScriptVerifyFlag.NULLFAIL
    WITNESS_PUBKEYTYPE = ScriptVerifyFlag.WITNESS_PUBKEYTYPE
    CONST_SCRIPTCODE = ScriptVerifyFlag.CONST_SCRIPTCODE
    TAPROOT = ScriptVerifyFlag.TAPROOT
    DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = ScriptVerifyFlag.DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
    DISCOURAGE_OP_SUCCESS = ScriptVerifyFlag.DISCOURAGE_OP_SUCCESS
    DISCOURAGE_UPGRADABLE_PUBKEYTYPE = ScriptVerifyFlag.DISCOURAGE_UPGRADABLE_PUBKEYTYPE
    
    # Maximum number of flag bits
    MAX_SCRIPT_VERIFY_FLAGS_BITS = 22
    
    # Maximum flags value
    MAX_SCRIPT_VERIFY_FLAGS = (1 << MAX_SCRIPT_VERIFY_FLAGS_BITS) - 1
    
    # Flag name to enum mapping
    _FLAG_NAMES: Dict[str, ScriptVerifyFlag] = {
        "P2SH": ScriptVerifyFlag.P2SH,
        "STRICTENC": ScriptVerifyFlag.STRICTENC,
        "DERSIG": ScriptVerifyFlag.DERSIG,
        "LOW_S": ScriptVerifyFlag.LOW_S,
        "NULLDUMMY": ScriptVerifyFlag.NULLDUMMY,
        "SIGPUSHONLY": ScriptVerifyFlag.SIGPUSHONLY,
        "MINIMALDATA": ScriptVerifyFlag.MINIMALDATA,
        "DISCOURAGE_UPGRADABLE_NOPS": ScriptVerifyFlag.DISCOURAGE_UPGRADABLE_NOPS,
        "CLEANSTACK": ScriptVerifyFlag.CLEANSTACK,
        "CHECKLOCKTIMEVERIFY": ScriptVerifyFlag.CHECKLOCKTIMEVERIFY,
        "CHECKSEQUENCEVERIFY": ScriptVerifyFlag.CHECKSEQUENCEVERIFY,
        "WITNESS": ScriptVerifyFlag.WITNESS,
        "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM": ScriptVerifyFlag.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
        "MINIMALIF": ScriptVerifyFlag.MINIMALIF,
        "NULLFAIL": ScriptVerifyFlag.NULLFAIL,
        "WITNESS_PUBKEYTYPE": ScriptVerifyFlag.WITNESS_PUBKEYTYPE,
        "CONST_SCRIPTCODE": ScriptVerifyFlag.CONST_SCRIPTCODE,
        "TAPROOT": ScriptVerifyFlag.TAPROOT,
        "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION": ScriptVerifyFlag.DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
        "DISCOURAGE_OP_SUCCESS": ScriptVerifyFlag.DISCOURAGE_OP_SUCCESS,
        "DISCOURAGE_UPGRADABLE_PUBKEYTYPE": ScriptVerifyFlag.DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
    }
    
    @classmethod
    def from_names(cls, names: List[str]) -> int:
        """
        Create flags value from a list of flag names.
        
        Args:
            names: List of flag names to enable
            
        Returns:
            Combined flags value
            
        Raises:
            ValueError: If an unknown flag name is provided
        """
        flags = 0
        for name in names:
            if name not in cls._FLAG_NAMES:
                raise ValueError(f"Unknown script verify flag: {name}")
            flags |= cls._FLAG_NAMES[name]
        return flags
    
    @classmethod
    def get_names(cls, flags: int) -> List[str]:
        """
        Get list of flag names from a flags value.
        
        Args:
            flags: The combined flags value
            
        Returns:
            List of enabled flag names
        """
        names = []
        for name, flag in cls._FLAG_NAMES.items():
            if flags & flag:
                names.append(name)
        return names
    
    @classmethod
    def has_flag(cls, flags: int, flag: ScriptVerifyFlag) -> bool:
        """
        Check if a specific flag is set.
        
        Args:
            flags: The combined flags value
            flag: The specific flag to check
            
        Returns:
            True if the flag is set
        """
        return bool(flags & flag)


# Standard flag combinations

# Mandatory script verification flags for consensus
MANDATORY_SCRIPT_VERIFY_FLAGS = (
    ScriptVerifyFlags.P2SH |
    ScriptVerifyFlags.DERSIG |
    ScriptVerifyFlags.NULLDUMMY |
    ScriptVerifyFlags.CHECKLOCKTIMEVERIFY |
    ScriptVerifyFlags.CHECKSEQUENCEVERIFY |
    ScriptVerifyFlags.WITNESS |
    ScriptVerifyFlags.TAPROOT
)

# Standard script verification flags for policy
STANDARD_SCRIPT_VERIFY_FLAGS = (
    MANDATORY_SCRIPT_VERIFY_FLAGS |
    ScriptVerifyFlags.STRICTENC |
    ScriptVerifyFlags.LOW_S |
    ScriptVerifyFlags.SIGPUSHONLY |
    ScriptVerifyFlags.MINIMALDATA |
    ScriptVerifyFlags.NULLFAIL |
    ScriptVerifyFlags.CLEANSTACK |
    ScriptVerifyFlags.MINIMALIF |
    ScriptVerifyFlags.WITNESS_PUBKEYTYPE |
    ScriptVerifyFlags.DISCOURAGE_UPGRADABLE_NOPS |
    ScriptVerifyFlags.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM |
    ScriptVerifyFlags.DISCOURAGE_UPGRADABLE_TAPROOT_VERSION |
    ScriptVerifyFlags.DISCOURAGE_OP_SUCCESS |
    ScriptVerifyFlags.DISCOURAGE_UPGRADABLE_PUBKEYTYPE
)

# Export individual flag constants
SCRIPT_VERIFY_NONE = ScriptVerifyFlags.NONE
SCRIPT_VERIFY_P2SH = ScriptVerifyFlags.P2SH
SCRIPT_VERIFY_STRICTENC = ScriptVerifyFlags.STRICTENC
SCRIPT_VERIFY_DERSIG = ScriptVerifyFlags.DERSIG
SCRIPT_VERIFY_LOW_S = ScriptVerifyFlags.LOW_S
SCRIPT_VERIFY_NULLDUMMY = ScriptVerifyFlags.NULLDUMMY
SCRIPT_VERIFY_SIGPUSHONLY = ScriptVerifyFlags.SIGPUSHONLY
SCRIPT_VERIFY_MINIMALDATA = ScriptVerifyFlags.MINIMALDATA
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = ScriptVerifyFlags.DISCOURAGE_UPGRADABLE_NOPS
SCRIPT_VERIFY_CLEANSTACK = ScriptVerifyFlags.CLEANSTACK
SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = ScriptVerifyFlags.CHECKLOCKTIMEVERIFY
SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = ScriptVerifyFlags.CHECKSEQUENCEVERIFY
SCRIPT_VERIFY_WITNESS = ScriptVerifyFlags.WITNESS
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = ScriptVerifyFlags.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
SCRIPT_VERIFY_MINIMALIF = ScriptVerifyFlags.MINIMALIF
SCRIPT_VERIFY_NULLFAIL = ScriptVerifyFlags.NULLFAIL
SCRIPT_VERIFY_WITNESS_PUBKEYTYPE = ScriptVerifyFlags.WITNESS_PUBKEYTYPE
SCRIPT_VERIFY_CONST_SCRIPTCODE = ScriptVerifyFlags.CONST_SCRIPTCODE
SCRIPT_VERIFY_TAPROOT = ScriptVerifyFlags.TAPROOT
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = ScriptVerifyFlags.DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS = ScriptVerifyFlags.DISCOURAGE_OP_SUCCESS
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE = ScriptVerifyFlags.DISCOURAGE_UPGRADABLE_PUBKEYTYPE
