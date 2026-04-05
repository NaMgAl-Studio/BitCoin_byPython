# Copyright (c) 2009-2010 Satoshi Nakamoto
# Copyright (c) 2009-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Bitcoin Script Opcodes

This module defines all Bitcoin script opcodes as specified in the Bitcoin protocol.
Each opcode is a single byte value that performs a specific operation in the script interpreter.

Reference: https://en.bitcoin.it/wiki/Script
"""

from enum import IntEnum
from typing import Optional


class OpcodeType(IntEnum):
    """
    Script opcodes enumeration.
    
    Each opcode is a single byte (0x00-0xFF) that instructs the script interpreter
    to perform a specific operation.
    
    Opcodes are categorized as follows:
    - Push value: Push data onto the stack
    - Control: Flow control operations (IF, ELSE, ENDIF, etc.)
    - Stack: Stack manipulation operations
    - Splice: String operations (disabled)
    - Bitwise logic: Bitwise operations (disabled)
    - Numeric: Arithmetic operations
    - Crypto: Cryptographic operations
    - Expansion: Reserved for future use (NOPs)
    """
    
    # ============================================================================
    # Push value opcodes
    # ============================================================================
    
    # Push empty byte array onto the stack
    OP_0 = 0x00
    OP_FALSE = OP_0  # Alias for OP_0
    
    # Push the next byte as a value (0x01-0x4b)
    # These are direct push opcodes - the opcode value itself indicates
    # how many bytes to push onto the stack (1-75 bytes)
    # Note: Values 0x01-0x4b are not named opcodes but direct push operations
    
    # Data push opcodes for larger data
    OP_PUSHDATA1 = 0x4c  # Next byte contains number of bytes to push (max 255)
    OP_PUSHDATA2 = 0x4d  # Next 2 bytes (little-endian) contain number of bytes to push
    OP_PUSHDATA4 = 0x4e  # Next 4 bytes (little-endian) contain number of bytes to push
    
    # Push the number -1 onto the stack
    OP_1NEGATE = 0x4f
    
    # Reserved opcode - fails script if executed
    OP_RESERVED = 0x50
    
    # Push numbers 1-16 onto the stack
    OP_1 = 0x51
    OP_TRUE = OP_1  # Alias for OP_1 (pushes "true" value)
    OP_2 = 0x52
    OP_3 = 0x53
    OP_4 = 0x54
    OP_5 = 0x55
    OP_6 = 0x56
    OP_7 = 0x57
    OP_8 = 0x58
    OP_9 = 0x59
    OP_10 = 0x5a
    OP_11 = 0x5b
    OP_12 = 0x5c
    OP_13 = 0x5d
    OP_14 = 0x5e
    OP_15 = 0x5f
    OP_16 = 0x60
    
    # ============================================================================
    # Control opcodes
    # ============================================================================
    
    # Do nothing
    OP_NOP = 0x61
    
    # Reserved - fails script if executed
    OP_VER = 0x62
    
    # Execute statements if top of stack is true
    OP_IF = 0x63
    
    # Execute statements if top of stack is false
    OP_NOTIF = 0x64
    
    # Reserved - fails script if executed
    OP_VERIF = 0x65
    
    # Reserved - fails script if executed
    OP_VERNOTIF = 0x66
    
    # Execute statements if previous IF/NOTIF was false
    OP_ELSE = 0x67
    
    # End IF/ELSE block
    OP_ENDIF = 0x68
    
    # Fail script if top of stack is false
    OP_VERIFY = 0x69
    
    # Always fail script
    OP_RETURN = 0x6a
    
    # ============================================================================
    # Stack opcodes
    # ============================================================================
    
    # Move top item to alt stack
    OP_TOALTSTACK = 0x6b
    
    # Move top item from alt stack to main stack
    OP_FROMALTSTACK = 0x6c
    
    # Remove top two items from stack
    OP_2DROP = 0x6d
    
    # Duplicate top two items
    OP_2DUP = 0x6e
    
    # Duplicate top three items
    OP_3DUP = 0x6f
    
    # Copy the pair of items two positions down to the top
    OP_2OVER = 0x70
    
    # Rotate the top three pairs of items
    OP_2ROT = 0x71
    
    # Swap the top two pairs of items
    OP_2SWAP = 0x72
    
    # Duplicate top item if it's non-zero
    OP_IFDUP = 0x73
    
    # Push the number of items on the stack
    OP_DEPTH = 0x74
    
    # Remove top item from stack
    OP_DROP = 0x75
    
    # Duplicate top item
    OP_DUP = 0x76
    
    # Remove second-to-top item
    OP_NIP = 0x77
    
    # Copy second-to-top item to top
    OP_OVER = 0x78
    
    # Move nth item to top
    OP_PICK = 0x79
    
    # Move nth item to top and remove original
    OP_ROLL = 0x7a
    
    # Rotate top three items (move 3rd to top)
    OP_ROT = 0x7b
    
    # Swap top two items
    OP_SWAP = 0x7c
    
    # Copy top item and insert before second-to-top
    OP_TUCK = 0x7d
    
    # ============================================================================
    # Splice opcodes (DISABLED - CVE-2010-5137)
    # ============================================================================
    
    # Concatenate top two items (DISABLED)
    OP_CAT = 0x7e
    
    # Return substring (DISABLED)
    OP_SUBSTR = 0x7f
    
    # Keep leftmost characters (DISABLED)
    OP_LEFT = 0x80
    
    # Keep rightmost characters (DISABLED)
    OP_RIGHT = 0x81
    
    # Push length of top item
    OP_SIZE = 0x82
    
    # ============================================================================
    # Bitwise logic opcodes (DISABLED)
    # ============================================================================
    
    # Flip all bits (DISABLED)
    OP_INVERT = 0x83
    
    # Boolean AND (DISABLED)
    OP_AND = 0x84
    
    # Boolean OR (DISABLED)
    OP_OR = 0x85
    
    # Boolean XOR (DISABLED)
    OP_XOR = 0x86
    
    # Check equality of top two items
    OP_EQUAL = 0x87
    
    # Check equality and verify (fails if not equal)
    OP_EQUALVERIFY = 0x88
    
    # Reserved (DISABLED)
    OP_RESERVED1 = 0x89
    
    # Reserved (DISABLED)
    OP_RESERVED2 = 0x8a
    
    # ============================================================================
    # Numeric opcodes
    # ============================================================================
    
    # Add 1 to top item
    OP_1ADD = 0x8b
    
    # Subtract 1 from top item
    OP_1SUB = 0x8c
    
    # Multiply by 2 (DISABLED)
    OP_2MUL = 0x8d
    
    # Divide by 2 (DISABLED)
    OP_2DIV = 0x8e
    
    # Negate top item
    OP_NEGATE = 0x8f
    
    # Absolute value
    OP_ABS = 0x90
    
    # Logical NOT
    OP_NOT = 0x91
    
    # Check if not zero
    OP_0NOTEQUAL = 0x92
    
    # Add top two items
    OP_ADD = 0x93
    
    # Subtract top two items
    OP_SUB = 0x94
    
    # Multiply top two items (DISABLED)
    OP_MUL = 0x95
    
    # Divide top two items (DISABLED)
    OP_DIV = 0x96
    
    # Modulo (DISABLED)
    OP_MOD = 0x97
    
    # Left shift (DISABLED)
    OP_LSHIFT = 0x98
    
    # Right shift (DISABLED)
    OP_RSHIFT = 0x99
    
    # Boolean AND of top two items
    OP_BOOLAND = 0x9a
    
    # Boolean OR of top two items
    OP_BOOLOR = 0x9b
    
    # Check if equal (returns 1 or 0)
    OP_NUMEQUAL = 0x9c
    
    # Check if equal and verify
    OP_NUMEQUALVERIFY = 0x9d
    
    # Check if not equal
    OP_NUMNOTEQUAL = 0x9e
    
    # Check if less than
    OP_LESSTHAN = 0x9f
    
    # Check if greater than
    OP_GREATERTHAN = 0xa0
    
    # Check if less than or equal
    OP_LESSTHANOREQUAL = 0xa1
    
    # Check if greater than or equal
    OP_GREATERTHANOREQUAL = 0xa2
    
    # Return smaller of top two items
    OP_MIN = 0xa3
    
    # Return larger of top two items
    OP_MAX = 0xa4
    
    # Check if within range
    OP_WITHIN = 0xa5
    
    # ============================================================================
    # Crypto opcodes
    # ============================================================================
    
    # RIPEMD-160 hash
    OP_RIPEMD160 = 0xa6
    
    # SHA-1 hash
    OP_SHA1 = 0xa7
    
    # SHA-256 hash
    OP_SHA256 = 0xa8
    
    # HASH160 (RIPEMD160(SHA256(data)))
    OP_HASH160 = 0xa9
    
    # HASH256 (SHA256(SHA256(data)))
    OP_HASH256 = 0xaa
    
    # Mark the location for signature verification
    OP_CODESEPARATOR = 0xab
    
    # Verify ECDSA signature
    OP_CHECKSIG = 0xac
    
    # Verify ECDSA signature and fail if invalid
    OP_CHECKSIGVERIFY = 0xad
    
    # Verify multiple ECDSA signatures
    OP_CHECKMULTISIG = 0xae
    
    # Verify multiple ECDSA signatures and fail if any invalid
    OP_CHECKMULTISIGVERIFY = 0xaf
    
    # ============================================================================
    # Expansion / Locktime opcodes
    # ============================================================================
    
    # NOP - reserved for future use
    OP_NOP1 = 0xb0
    
    # Check lock time (BIP65)
    OP_CHECKLOCKTIMEVERIFY = 0xb1
    OP_NOP2 = OP_CHECKLOCKTIMEVERIFY  # Historical alias
    
    # Check sequence (BIP112)
    OP_CHECKSEQUENCEVERIFY = 0xb2
    OP_NOP3 = OP_CHECKSEQUENCEVERIFY  # Historical alias
    
    # NOP - reserved for future use
    OP_NOP4 = 0xb3
    OP_NOP5 = 0xb4
    OP_NOP6 = 0xb5
    OP_NOP7 = 0xb6
    OP_NOP8 = 0xb7
    OP_NOP9 = 0xb8
    OP_NOP10 = 0xb9
    
    # ============================================================================
    # Tapscript opcodes (BIP342)
    # ============================================================================
    
    # Count signatures and add to accumulator
    OP_CHECKSIGADD = 0xba
    
    # Invalid opcode marker
    OP_INVALIDOPCODE = 0xff


# Maximum valid opcode value (not including OP_INVALIDOPCODE)
MAX_OPCODE = OpcodeType.OP_NOP10


def GetOpName(opcode: int) -> str:
    """
    Get the human-readable name for an opcode.
    
    Args:
        opcode: The opcode byte value
        
    Returns:
        The name of the opcode, or "OP_UNKNOWN" for unknown opcodes.
        For direct push operations (0x01-0x4b), returns the number of bytes pushed.
    """
    # Handle direct push operations (0x01-0x4b)
    if 0x01 <= opcode <= 0x4b:
        # Direct push - opcode value is the number of bytes to push
        return f"[{opcode}]"  # Indicate a push of N bytes
    
    # Handle named opcodes
    try:
        op = OpcodeType(opcode)
        if op == OpcodeType.OP_0:
            return "0"
        elif op == OpcodeType.OP_1NEGATE:
            return "-1"
        elif op in (OpcodeType.OP_1, OpcodeType.OP_2, OpcodeType.OP_3,
                   OpcodeType.OP_4, OpcodeType.OP_5, OpcodeType.OP_6,
                   OpcodeType.OP_7, OpcodeType.OP_8, OpcodeType.OP_9,
                   OpcodeType.OP_10, OpcodeType.OP_11, OpcodeType.OP_12,
                   OpcodeType.OP_13, OpcodeType.OP_14, OpcodeType.OP_15,
                   OpcodeType.OP_16):
            # Return just the number for OP_1 through OP_16
            return str(DecodeOP_N(op))
        else:
            return op.name
    except ValueError:
        return "OP_UNKNOWN"


def DecodeOP_N(opcode: int) -> int:
    """
    Decode a numeric opcode (OP_0, OP_1..OP_16) to its numeric value.
    
    OP_0 decodes to 0.
    OP_1 through OP_16 decode to 1 through 16.
    
    Args:
        opcode: The opcode to decode
        
    Returns:
        The numeric value represented by the opcode
        
    Raises:
        AssertionError: If opcode is not OP_0 or OP_1..OP_16
    """
    if opcode == OpcodeType.OP_0:
        return 0
    assert OpcodeType.OP_1 <= opcode <= OpcodeType.OP_16, \
        f"DecodeOP_N: Invalid opcode {opcode}, expected OP_0 or OP_1..OP_16"
    return opcode - OpcodeType.OP_1 + 1


def EncodeOP_N(n: int) -> int:
    """
    Encode a small integer (0-16) as an opcode.
    
    0 encodes to OP_0.
    1 through 16 encode to OP_1 through OP_16.
    
    Args:
        n: The numeric value to encode (0-16)
        
    Returns:
        The opcode representing that value
        
    Raises:
        AssertionError: If n is not in range 0-16
    """
    assert 0 <= n <= 16, f"EncodeOP_N: Invalid value {n}, expected 0-16"
    if n == 0:
        return OpcodeType.OP_0
    return OpcodeType.OP_1 + n - 1


def IsOpSuccess(opcode: int) -> bool:
    """
    Check if opcode is an OP_SUCCESSx as defined by BIP342 (Tapscript).
    
    OP_SUCCESSx opcodes cause script validation to immediately succeed,
    enabling future soft forks to give them new meaning.
    
    The OP_SUCCESSx opcodes are:
    - 80 (0x50, OP_RESERVED)
    - 98 (0x62, OP_VER)
    - 126-129 (0x7e-0x81, OP_CAT through OP_LEFT - disabled but success in tapscript)
    - 131-134 (0x83-0x86, OP_INVERT through OP_XOR - disabled but success in tapscript)
    - 137-138 (0x89-0x8a, OP_RESERVED1, OP_RESERVED2)
    - 141-142 (0x8d-0x8e, OP_2MUL, OP_2DIV - disabled but success in tapscript)
    - 149-153 (0x95-0x99, OP_MUL through OP_RSHIFT - disabled but success in tapscript)
    - 187-254 (0xbb-0xfe, undefined opcodes)
    
    Args:
        opcode: The opcode byte value
        
    Returns:
        True if this is an OP_SUCCESSx opcode
    """
    return (opcode == 80 or
            opcode == 98 or
            (opcode >= 126 and opcode <= 129) or
            (opcode >= 131 and opcode <= 134) or
            (opcode >= 137 and opcode <= 138) or
            (opcode >= 141 and opcode <= 142) or
            (opcode >= 149 and opcode <= 153) or
            (opcode >= 187 and opcode <= 254))


# Export commonly used opcode constants
OP_0 = OpcodeType.OP_0
OP_FALSE = OpcodeType.OP_FALSE
OP_PUSHDATA1 = OpcodeType.OP_PUSHDATA1
OP_PUSHDATA2 = OpcodeType.OP_PUSHDATA2
OP_PUSHDATA4 = OpcodeType.OP_PUSHDATA4
OP_1NEGATE = OpcodeType.OP_1NEGATE
OP_RESERVED = OpcodeType.OP_RESERVED
OP_1 = OpcodeType.OP_1
OP_TRUE = OpcodeType.OP_TRUE
OP_2 = OpcodeType.OP_2
OP_3 = OpcodeType.OP_3
OP_4 = OpcodeType.OP_4
OP_5 = OpcodeType.OP_5
OP_6 = OpcodeType.OP_6
OP_7 = OpcodeType.OP_7
OP_8 = OpcodeType.OP_8
OP_9 = OpcodeType.OP_9
OP_10 = OpcodeType.OP_10
OP_11 = OpcodeType.OP_11
OP_12 = OpcodeType.OP_12
OP_13 = OpcodeType.OP_13
OP_14 = OpcodeType.OP_14
OP_15 = OpcodeType.OP_15
OP_16 = OpcodeType.OP_16
OP_NOP = OpcodeType.OP_NOP
OP_VER = OpcodeType.OP_VER
OP_IF = OpcodeType.OP_IF
OP_NOTIF = OpcodeType.OP_NOTIF
OP_VERIF = OpcodeType.OP_VERIF
OP_VERNOTIF = OpcodeType.OP_VERNOTIF
OP_ELSE = OpcodeType.OP_ELSE
OP_ENDIF = OpcodeType.OP_ENDIF
OP_VERIFY = OpcodeType.OP_VERIFY
OP_RETURN = OpcodeType.OP_RETURN
OP_TOALTSTACK = OpcodeType.OP_TOALTSTACK
OP_FROMALTSTACK = OpcodeType.OP_FROMALTSTACK
OP_2DROP = OpcodeType.OP_2DROP
OP_2DUP = OpcodeType.OP_2DUP
OP_3DUP = OpcodeType.OP_3DUP
OP_2OVER = OpcodeType.OP_2OVER
OP_2ROT = OpcodeType.OP_2ROT
OP_2SWAP = OpcodeType.OP_2SWAP
OP_IFDUP = OpcodeType.OP_IFDUP
OP_DEPTH = OpcodeType.OP_DEPTH
OP_DROP = OpcodeType.OP_DROP
OP_DUP = OpcodeType.OP_DUP
OP_NIP = OpcodeType.OP_NIP
OP_OVER = OpcodeType.OP_OVER
OP_PICK = OpcodeType.OP_PICK
OP_ROLL = OpcodeType.OP_ROLL
OP_ROT = OpcodeType.OP_ROT
OP_SWAP = OpcodeType.OP_SWAP
OP_TUCK = OpcodeType.OP_TUCK
OP_CAT = OpcodeType.OP_CAT
OP_SUBSTR = OpcodeType.OP_SUBSTR
OP_LEFT = OpcodeType.OP_LEFT
OP_RIGHT = OpcodeType.OP_RIGHT
OP_SIZE = OpcodeType.OP_SIZE
OP_INVERT = OpcodeType.OP_INVERT
OP_AND = OpcodeType.OP_AND
OP_OR = OpcodeType.OP_OR
OP_XOR = OpcodeType.OP_XOR
OP_EQUAL = OpcodeType.OP_EQUAL
OP_EQUALVERIFY = OpcodeType.OP_EQUALVERIFY
OP_RESERVED1 = OpcodeType.OP_RESERVED1
OP_RESERVED2 = OpcodeType.OP_RESERVED2
OP_1ADD = OpcodeType.OP_1ADD
OP_1SUB = OpcodeType.OP_1SUB
OP_2MUL = OpcodeType.OP_2MUL
OP_2DIV = OpcodeType.OP_2DIV
OP_NEGATE = OpcodeType.OP_NEGATE
OP_ABS = OpcodeType.OP_ABS
OP_NOT = OpcodeType.OP_NOT
OP_0NOTEQUAL = OpcodeType.OP_0NOTEQUAL
OP_ADD = OpcodeType.OP_ADD
OP_SUB = OpcodeType.OP_SUB
OP_MUL = OpcodeType.OP_MUL
OP_DIV = OpcodeType.OP_DIV
OP_MOD = OpcodeType.OP_MOD
OP_LSHIFT = OpcodeType.OP_LSHIFT
OP_RSHIFT = OpcodeType.OP_RSHIFT
OP_BOOLAND = OpcodeType.OP_BOOLAND
OP_BOOLOR = OpcodeType.OP_BOOLOR
OP_NUMEQUAL = OpcodeType.OP_NUMEQUAL
OP_NUMEQUALVERIFY = OpcodeType.OP_NUMEQUALVERIFY
OP_NUMNOTEQUAL = OpcodeType.OP_NUMNOTEQUAL
OP_LESSTHAN = OpcodeType.OP_LESSTHAN
OP_GREATERTHAN = OpcodeType.OP_GREATERTHAN
OP_LESSTHANOREQUAL = OpcodeType.OP_LESSTHANOREQUAL
OP_GREATERTHANOREQUAL = OpcodeType.OP_GREATERTHANOREQUAL
OP_MIN = OpcodeType.OP_MIN
OP_MAX = OpcodeType.OP_MAX
OP_WITHIN = OpcodeType.OP_WITHIN
OP_RIPEMD160 = OpcodeType.OP_RIPEMD160
OP_SHA1 = OpcodeType.OP_SHA1
OP_SHA256 = OpcodeType.OP_SHA256
OP_HASH160 = OpcodeType.OP_HASH160
OP_HASH256 = OpcodeType.OP_HASH256
OP_CODESEPARATOR = OpcodeType.OP_CODESEPARATOR
OP_CHECKSIG = OpcodeType.OP_CHECKSIG
OP_CHECKSIGVERIFY = OpcodeType.OP_CHECKSIGVERIFY
OP_CHECKMULTISIG = OpcodeType.OP_CHECKMULTISIG
OP_CHECKMULTISIGVERIFY = OpcodeType.OP_CHECKMULTISIGVERIFY
OP_NOP1 = OpcodeType.OP_NOP1
OP_CHECKLOCKTIMEVERIFY = OpcodeType.OP_CHECKLOCKTIMEVERIFY
OP_NOP2 = OpcodeType.OP_NOP2
OP_CHECKSEQUENCEVERIFY = OpcodeType.OP_CHECKSEQUENCEVERIFY
OP_NOP3 = OpcodeType.OP_NOP3
OP_NOP4 = OpcodeType.OP_NOP4
OP_NOP5 = OpcodeType.OP_NOP5
OP_NOP6 = OpcodeType.OP_NOP6
OP_NOP7 = OpcodeType.OP_NOP7
OP_NOP8 = OpcodeType.OP_NOP8
OP_NOP9 = OpcodeType.OP_NOP9
OP_NOP10 = OpcodeType.OP_NOP10
OP_CHECKSIGADD = OpcodeType.OP_CHECKSIGADD
OP_INVALIDOPCODE = OpcodeType.OP_INVALIDOPCODE
