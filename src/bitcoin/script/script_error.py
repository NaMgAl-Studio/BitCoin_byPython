# Copyright (c) 2009-2010 Satoshi Nakamoto
# Copyright (c) 2009-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Bitcoin Script Error Types

This module defines all script execution error types as specified in Bitcoin Core.
These errors are used by the script interpreter to indicate why a script failed.
"""

from enum import IntEnum
from typing import Optional


class ScriptErrorType(IntEnum):
    """
    Script execution error types enumeration.
    
    These error codes indicate why a script failed during execution.
    They are used for debugging, logging, and policy decisions.
    """
    
    # Script executed successfully
    SCRIPT_ERR_OK = 0
    
    # Unknown error occurred
    SCRIPT_ERR_UNKNOWN_ERROR = 1
    
    # Script evaluated to false (not a true value on stack)
    SCRIPT_ERR_EVAL_FALSE = 2
    
    # Script encountered OP_RETURN
    SCRIPT_ERR_OP_RETURN = 3
    
    # Script number encoding error
    SCRIPT_ERR_SCRIPTNUM = 4
    
    # Maximum sizes exceeded
    SCRIPT_ERR_SCRIPT_SIZE = 5      # Script too large (>10000 bytes)
    SCRIPT_ERR_PUSH_SIZE = 6        # Push data too large (>520 bytes)
    SCRIPT_ERR_OP_COUNT = 7         # Too many operations (>201)
    SCRIPT_ERR_STACK_SIZE = 8       # Stack too large (>1000 items)
    SCRIPT_ERR_SIG_COUNT = 9        # Too many signatures
    SCRIPT_ERR_PUBKEY_COUNT = 10    # Too many public keys
    
    # Failed verify operations
    SCRIPT_ERR_VERIFY = 11          # OP_VERIFY failed
    SCRIPT_ERR_EQUALVERIFY = 12     # OP_EQUALVERIFY failed
    SCRIPT_ERR_CHECKMULTISIGVERIFY = 13  # OP_CHECKMULTISIGVERIFY failed
    SCRIPT_ERR_CHECKSIGVERIFY = 14  # OP_CHECKSIGVERIFY failed
    SCRIPT_ERR_NUMEQUALVERIFY = 15  # OP_NUMEQUALVERIFY failed
    
    # Logical/Format/Canonical errors
    SCRIPT_ERR_BAD_OPCODE = 16          # Invalid opcode encountered
    SCRIPT_ERR_DISABLED_OPCODE = 17     # Disabled opcode encountered
    SCRIPT_ERR_INVALID_STACK_OPERATION = 18   # Stack underflow
    SCRIPT_ERR_INVALID_ALTSTACK_OPERATION = 19  # Alt stack underflow
    SCRIPT_ERR_UNBALANCED_CONDITIONAL = 20     # IF/ELSE/ENDIF mismatch
    
    # CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY errors
    SCRIPT_ERR_NEGATIVE_LOCKTIME = 21   # Negative locktime value
    SCRIPT_ERR_UNSATISFIED_LOCKTIME = 22  # Locktime requirement not met
    
    # Malleability errors (BIP62)
    SCRIPT_ERR_SIG_HASHTYPE = 23        # Invalid signature hash type
    SCRIPT_ERR_SIG_DER = 24             # Invalid DER signature encoding
    SCRIPT_ERR_MINIMALDATA = 25         # Non-minimal data encoding
    SCRIPT_ERR_SIG_PUSHONLY = 26        # Non-push operation in scriptSig
    SCRIPT_ERR_SIG_HIGH_S = 27          # S value > n/2 in signature (BIP62)
    SCRIPT_ERR_SIG_NULLDUMMY = 28       # Non-null dummy value in CHECKMULTISIG
    SCRIPT_ERR_PUBKEYTYPE = 29          # Invalid public key type
    SCRIPT_ERR_CLEANSTACK = 30          # Extra items left on stack
    SCRIPT_ERR_MINIMALIF = 31           # Non-minimal IF argument
    SCRIPT_ERR_SIG_NULLFAIL = 32        # Empty signature but non-null failure
    
    # Softfork safeness errors
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS = 33           # Reserved NOP used
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = 34  # Unknown witness version
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = 35  # Unknown taproot version
    SCRIPT_ERR_DISCOURAGE_OP_SUCCESS = 36                # OP_SUCCESS used
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE = 37     # Unknown pubkey type
    
    # Segregated witness errors
    SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH = 38   # Invalid witness program length
    SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY = 39  # Empty witness for witness program
    SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH = 40       # Witness doesn't match program
    SCRIPT_ERR_WITNESS_MALLEATED = 41              # Non-witness input with witness
    SCRIPT_ERR_WITNESS_MALLEATED_P2SH = 42         # P2SH with non-witness script
    SCRIPT_ERR_WITNESS_UNEXPECTED = 43             # Unexpected witness data
    SCRIPT_ERR_WITNESS_PUBKEYTYPE = 44             # Invalid witness pubkey type
    
    # Taproot errors (BIP341, BIP342)
    SCRIPT_ERR_SCHNORR_SIG_SIZE = 45           # Invalid Schnorr signature size
    SCRIPT_ERR_SCHNORR_SIG_HASHTYPE = 46       # Invalid Schnorr hash type
    SCRIPT_ERR_SCHNORR_SIG = 47                # Invalid Schnorr signature
    SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE = 48  # Invalid control block size
    SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT = 49  # Validation weight exceeded
    SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG = 50    # CHECKMULTISIG in tapscript
    SCRIPT_ERR_TAPSCRIPT_MINIMALIF = 51        # Non-minimal IF in tapscript
    SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY = 52     # Empty pubkey in tapscript
    
    # Constant scriptCode errors
    SCRIPT_ERR_OP_CODESEPARATOR = 53           # OP_CODESEPARATOR in non-segwit
    SCRIPT_ERR_SIG_FINDANDDELETE = 54          # Signature in scriptCode with CONST_SCRIPTCODE
    
    # Total number of error types
    SCRIPT_ERR_ERROR_COUNT = 55


# Create a custom exception class for script errors
class ScriptError(Exception):
    """
    Exception raised when script execution fails.
    
    Attributes:
        error_type: The type of script error that occurred
        message: Optional additional message
    """
    
    def __init__(self, error_type: ScriptErrorType, message: Optional[str] = None):
        """
        Initialize a ScriptError.
        
        Args:
            error_type: The type of script error
            message: Optional additional error message
        """
        self.error_type = error_type
        self.message = message or ScriptErrorString(error_type)
        super().__init__(self.message)
    
    def __repr__(self) -> str:
        return f"ScriptError({self.error_type.name}, '{self.message}')"


def ScriptErrorString(error: ScriptErrorType) -> str:
    """
    Get a human-readable description of a script error.
    
    Args:
        error: The script error type
        
    Returns:
        A string describing the error
    """
    error_messages = {
        ScriptErrorType.SCRIPT_ERR_OK: "Script evaluated successfully",
        ScriptErrorType.SCRIPT_ERR_UNKNOWN_ERROR: "Unknown error",
        ScriptErrorType.SCRIPT_ERR_EVAL_FALSE: "Script evaluated to false",
        ScriptErrorType.SCRIPT_ERR_OP_RETURN: "Script contains OP_RETURN",
        ScriptErrorType.SCRIPT_ERR_SCRIPTNUM: "Script number encoding error",
        ScriptErrorType.SCRIPT_ERR_SCRIPT_SIZE: "Script size exceeds maximum",
        ScriptErrorType.SCRIPT_ERR_PUSH_SIZE: "Push data size exceeds maximum",
        ScriptErrorType.SCRIPT_ERR_OP_COUNT: "Operation count exceeds maximum",
        ScriptErrorType.SCRIPT_ERR_STACK_SIZE: "Stack size exceeds maximum",
        ScriptErrorType.SCRIPT_ERR_SIG_COUNT: "Signature count exceeds maximum",
        ScriptErrorType.SCRIPT_ERR_PUBKEY_COUNT: "Public key count exceeds maximum",
        ScriptErrorType.SCRIPT_ERR_VERIFY: "OP_VERIFY failed",
        ScriptErrorType.SCRIPT_ERR_EQUALVERIFY: "OP_EQUALVERIFY failed",
        ScriptErrorType.SCRIPT_ERR_CHECKMULTISIGVERIFY: "OP_CHECKMULTISIGVERIFY failed",
        ScriptErrorType.SCRIPT_ERR_CHECKSIGVERIFY: "OP_CHECKSIGVERIFY failed",
        ScriptErrorType.SCRIPT_ERR_NUMEQUALVERIFY: "OP_NUMEQUALVERIFY failed",
        ScriptErrorType.SCRIPT_ERR_BAD_OPCODE: "Invalid opcode",
        ScriptErrorType.SCRIPT_ERR_DISABLED_OPCODE: "Disabled opcode",
        ScriptErrorType.SCRIPT_ERR_INVALID_STACK_OPERATION: "Invalid stack operation",
        ScriptErrorType.SCRIPT_ERR_INVALID_ALTSTACK_OPERATION: "Invalid altstack operation",
        ScriptErrorType.SCRIPT_ERR_UNBALANCED_CONDITIONAL: "Unbalanced conditional",
        ScriptErrorType.SCRIPT_ERR_NEGATIVE_LOCKTIME: "Negative locktime",
        ScriptErrorType.SCRIPT_ERR_UNSATISFIED_LOCKTIME: "Locktime requirement not satisfied",
        ScriptErrorType.SCRIPT_ERR_SIG_HASHTYPE: "Invalid signature hash type",
        ScriptErrorType.SCRIPT_ERR_SIG_DER: "Invalid DER signature encoding",
        ScriptErrorType.SCRIPT_ERR_MINIMALDATA: "Non-minimal data encoding",
        ScriptErrorType.SCRIPT_ERR_SIG_PUSHONLY: "ScriptSig contains non-push operations",
        ScriptErrorType.SCRIPT_ERR_SIG_HIGH_S: "Signature S value is high",
        ScriptErrorType.SCRIPT_ERR_SIG_NULLDUMMY: "Non-null dummy element in CHECKMULTISIG",
        ScriptErrorType.SCRIPT_ERR_PUBKEYTYPE: "Invalid public key type",
        ScriptErrorType.SCRIPT_ERR_CLEANSTACK: "Extra items on stack after execution",
        ScriptErrorType.SCRIPT_ERR_MINIMALIF: "Non-minimal IF argument",
        ScriptErrorType.SCRIPT_ERR_SIG_NULLFAIL: "Signature failed with non-empty signature",
        ScriptErrorType.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS: "Upgradable NOP used",
        ScriptErrorType.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: "Upgradable witness program",
        ScriptErrorType.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION: "Upgradable taproot version",
        ScriptErrorType.SCRIPT_ERR_DISCOURAGE_OP_SUCCESS: "OP_SUCCESS used",
        ScriptErrorType.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE: "Upgradable public key type",
        ScriptErrorType.SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH: "Witness program has wrong length",
        ScriptErrorType.SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY: "Witness program has empty witness",
        ScriptErrorType.SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH: "Witness program mismatch",
        ScriptErrorType.SCRIPT_ERR_WITNESS_MALLEATED: "Witness malleated",
        ScriptErrorType.SCRIPT_ERR_WITNESS_MALLEATED_P2SH: "P2SH witness malleated",
        ScriptErrorType.SCRIPT_ERR_WITNESS_UNEXPECTED: "Unexpected witness",
        ScriptErrorType.SCRIPT_ERR_WITNESS_PUBKEYTYPE: "Witness public key type invalid",
        ScriptErrorType.SCRIPT_ERR_SCHNORR_SIG_SIZE: "Invalid Schnorr signature size",
        ScriptErrorType.SCRIPT_ERR_SCHNORR_SIG_HASHTYPE: "Invalid Schnorr signature hash type",
        ScriptErrorType.SCRIPT_ERR_SCHNORR_SIG: "Invalid Schnorr signature",
        ScriptErrorType.SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE: "Wrong taproot control block size",
        ScriptErrorType.SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT: "Tapscript validation weight exceeded",
        ScriptErrorType.SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG: "CHECKMULTISIG disabled in tapscript",
        ScriptErrorType.SCRIPT_ERR_TAPSCRIPT_MINIMALIF: "Non-minimal IF in tapscript",
        ScriptErrorType.SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY: "Empty public key in tapscript",
        ScriptErrorType.SCRIPT_ERR_OP_CODESEPARATOR: "OP_CODESEPARATOR in non-segwit script",
        ScriptErrorType.SCRIPT_ERR_SIG_FINDANDDELETE: "Signature found in scriptCode with CONST_SCRIPTCODE",
    }
    return error_messages.get(error, f"Unknown error code: {error}")


# Export error constants
SCRIPT_ERR_OK = ScriptErrorType.SCRIPT_ERR_OK
SCRIPT_ERR_UNKNOWN_ERROR = ScriptErrorType.SCRIPT_ERR_UNKNOWN_ERROR
SCRIPT_ERR_EVAL_FALSE = ScriptErrorType.SCRIPT_ERR_EVAL_FALSE
SCRIPT_ERR_OP_RETURN = ScriptErrorType.SCRIPT_ERR_OP_RETURN
SCRIPT_ERR_SCRIPTNUM = ScriptErrorType.SCRIPT_ERR_SCRIPTNUM
SCRIPT_ERR_SCRIPT_SIZE = ScriptErrorType.SCRIPT_ERR_SCRIPT_SIZE
SCRIPT_ERR_PUSH_SIZE = ScriptErrorType.SCRIPT_ERR_PUSH_SIZE
SCRIPT_ERR_OP_COUNT = ScriptErrorType.SCRIPT_ERR_OP_COUNT
SCRIPT_ERR_STACK_SIZE = ScriptErrorType.SCRIPT_ERR_STACK_SIZE
SCRIPT_ERR_SIG_COUNT = ScriptErrorType.SCRIPT_ERR_SIG_COUNT
SCRIPT_ERR_PUBKEY_COUNT = ScriptErrorType.SCRIPT_ERR_PUBKEY_COUNT
SCRIPT_ERR_VERIFY = ScriptErrorType.SCRIPT_ERR_VERIFY
SCRIPT_ERR_EQUALVERIFY = ScriptErrorType.SCRIPT_ERR_EQUALVERIFY
SCRIPT_ERR_CHECKMULTISIGVERIFY = ScriptErrorType.SCRIPT_ERR_CHECKMULTISIGVERIFY
SCRIPT_ERR_CHECKSIGVERIFY = ScriptErrorType.SCRIPT_ERR_CHECKSIGVERIFY
SCRIPT_ERR_NUMEQUALVERIFY = ScriptErrorType.SCRIPT_ERR_NUMEQUALVERIFY
SCRIPT_ERR_BAD_OPCODE = ScriptErrorType.SCRIPT_ERR_BAD_OPCODE
SCRIPT_ERR_DISABLED_OPCODE = ScriptErrorType.SCRIPT_ERR_DISABLED_OPCODE
SCRIPT_ERR_INVALID_STACK_OPERATION = ScriptErrorType.SCRIPT_ERR_INVALID_STACK_OPERATION
SCRIPT_ERR_INVALID_ALTSTACK_OPERATION = ScriptErrorType.SCRIPT_ERR_INVALID_ALTSTACK_OPERATION
SCRIPT_ERR_UNBALANCED_CONDITIONAL = ScriptErrorType.SCRIPT_ERR_UNBALANCED_CONDITIONAL
SCRIPT_ERR_NEGATIVE_LOCKTIME = ScriptErrorType.SCRIPT_ERR_NEGATIVE_LOCKTIME
SCRIPT_ERR_UNSATISFIED_LOCKTIME = ScriptErrorType.SCRIPT_ERR_UNSATISFIED_LOCKTIME
SCRIPT_ERR_SIG_HASHTYPE = ScriptErrorType.SCRIPT_ERR_SIG_HASHTYPE
SCRIPT_ERR_SIG_DER = ScriptErrorType.SCRIPT_ERR_SIG_DER
SCRIPT_ERR_MINIMALDATA = ScriptErrorType.SCRIPT_ERR_MINIMALDATA
SCRIPT_ERR_SIG_PUSHONLY = ScriptErrorType.SCRIPT_ERR_SIG_PUSHONLY
SCRIPT_ERR_SIG_HIGH_S = ScriptErrorType.SCRIPT_ERR_SIG_HIGH_S
SCRIPT_ERR_SIG_NULLDUMMY = ScriptErrorType.SCRIPT_ERR_SIG_NULLDUMMY
SCRIPT_ERR_PUBKEYTYPE = ScriptErrorType.SCRIPT_ERR_PUBKEYTYPE
SCRIPT_ERR_CLEANSTACK = ScriptErrorType.SCRIPT_ERR_CLEANSTACK
SCRIPT_ERR_MINIMALIF = ScriptErrorType.SCRIPT_ERR_MINIMALIF
SCRIPT_ERR_SIG_NULLFAIL = ScriptErrorType.SCRIPT_ERR_SIG_NULLFAIL
SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS = ScriptErrorType.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS
SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = ScriptErrorType.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = ScriptErrorType.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
SCRIPT_ERR_DISCOURAGE_OP_SUCCESS = ScriptErrorType.SCRIPT_ERR_DISCOURAGE_OP_SUCCESS
SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE = ScriptErrorType.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE
SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH = ScriptErrorType.SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH
SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY = ScriptErrorType.SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY
SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH = ScriptErrorType.SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH
SCRIPT_ERR_WITNESS_MALLEATED = ScriptErrorType.SCRIPT_ERR_WITNESS_MALLEATED
SCRIPT_ERR_WITNESS_MALLEATED_P2SH = ScriptErrorType.SCRIPT_ERR_WITNESS_MALLEATED_P2SH
SCRIPT_ERR_WITNESS_UNEXPECTED = ScriptErrorType.SCRIPT_ERR_WITNESS_UNEXPECTED
SCRIPT_ERR_WITNESS_PUBKEYTYPE = ScriptErrorType.SCRIPT_ERR_WITNESS_PUBKEYTYPE
SCRIPT_ERR_SCHNORR_SIG_SIZE = ScriptErrorType.SCRIPT_ERR_SCHNORR_SIG_SIZE
SCRIPT_ERR_SCHNORR_SIG_HASHTYPE = ScriptErrorType.SCRIPT_ERR_SCHNORR_SIG_HASHTYPE
SCRIPT_ERR_SCHNORR_SIG = ScriptErrorType.SCRIPT_ERR_SCHNORR_SIG
SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE = ScriptErrorType.SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE
SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT = ScriptErrorType.SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT
SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG = ScriptErrorType.SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG
SCRIPT_ERR_TAPSCRIPT_MINIMALIF = ScriptErrorType.SCRIPT_ERR_TAPSCRIPT_MINIMALIF
SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY = ScriptErrorType.SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY
SCRIPT_ERR_OP_CODESEPARATOR = ScriptErrorType.SCRIPT_ERR_OP_CODESEPARATOR
SCRIPT_ERR_SIG_FINDANDDELETE = ScriptErrorType.SCRIPT_ERR_SIG_FINDANDDELETE
