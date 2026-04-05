# Copyright (c) 2009-2010 Satoshi Nakamoto
# Copyright (c) 2009-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Bitcoin Script Implementation

This module implements the core Bitcoin script types:
- ScriptNum: Numeric type used in script operations
- Script: Serialized script used in transaction inputs and outputs
- ScriptWitness: Witness data for segwit transactions
- ScriptID: Hash160 reference to a script
"""

from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Iterator, Union
import struct

from .opcodes import (
    OpcodeType, OP_0, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4,
    OP_1NEGATE, OP_1, OP_16, OP_CODESEPARATOR, OP_CHECKSIG,
    OP_CHECKSIGVERIFY, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY,
    OP_HASH160, OP_EQUAL, OP_RETURN, MAX_OPCODE,
    DecodeOP_N, EncodeOP_N, GetOpName
)


# ============================================================================
# Script Constants
# ============================================================================

# Maximum number of bytes pushable to the stack
MAX_SCRIPT_ELEMENT_SIZE = 520

# Maximum number of non-push operations per script
MAX_OPS_PER_SCRIPT = 201

# Maximum number of public keys per multisig
MAX_PUBKEYS_PER_MULTISIG = 20

# Maximum keys in OP_CHECKSIGADD-based scripts (BIP342 stack limit)
MAX_PUBKEYS_PER_MULTI_A = 999

# Maximum script length in bytes
MAX_SCRIPT_SIZE = 10000

# Maximum number of values on script interpreter stack
MAX_STACK_SIZE = 1000

# Threshold for nLockTime: below this value it is interpreted as block number,
# otherwise as UNIX timestamp (Tue Nov  5 00:53:20 1985 UTC)
LOCKTIME_THRESHOLD = 500000000

# Maximum nLockTime value
LOCKTIME_MAX = 0xFFFFFFFF

# Tag for input annex (BIP341)
ANNEX_TAG = 0x50

# Validation weight per passing signature (Tapscript only, BIP342)
VALIDATION_WEIGHT_PER_SIGOP_PASSED = 50

# How much weight budget is added to the witness size (Tapscript only, BIP342)
VALIDATION_WEIGHT_OFFSET = 50


# ============================================================================
# ScriptNum - Numeric type for script operations
# ============================================================================

class ScriptNumError(Exception):
    """Exception raised when script number encoding is invalid."""
    pass


class ScriptNum:
    """
    Numeric type used in Bitcoin script operations.
    
    Numeric opcodes (OP_1ADD, etc.) are restricted to operating on 4-byte integers.
    The semantics are subtle:
    - Operands must be in the range [-2^31 +1 ... 2^31 -1]
    - Results may overflow (valid as long as not used in subsequent numeric operation)
    - Results are stored as int64 internally
    - Out-of-range values can be returned as bytes but throw on arithmetic
    
    This enforces those semantics by storing results as int64 and allowing
    out-of-range values to be returned as bytes but throwing an exception
    if arithmetic is done or the result is interpreted as an integer.
    """
    
    # Default maximum number size in bytes
    DEFAULT_MAX_NUM_SIZE = 4
    
    def __init__(self, value: int, max_num_size: int = DEFAULT_MAX_NUM_SIZE):
        """
        Initialize a ScriptNum from an integer value.
        
        Args:
            value: The integer value
            max_num_size: Maximum number of bytes for serialization
        """
        self._value = value
        self._max_num_size = max_num_size
    
    @classmethod
    def from_bytes(cls, data: bytes, require_minimal: bool = False,
                   max_num_size: int = DEFAULT_MAX_NUM_SIZE) -> 'ScriptNum':
        """
        Create a ScriptNum from serialized bytes.
        
        Args:
            data: The serialized bytes
            require_minimal: Whether to require minimal encoding
            max_num_size: Maximum number of bytes allowed
            
        Returns:
            A new ScriptNum instance
            
        Raises:
            ScriptNumError: If encoding is invalid
        """
        if len(data) > max_num_size:
            raise ScriptNumError("script number overflow")
        
        if require_minimal and len(data) > 0:
            # Check that the number is encoded with the minimum possible bytes
            # If the most-significant-byte - excluding the sign bit - is zero
            # then we're not minimal
            if (data[-1] & 0x7f) == 0:
                # One exception: if there's more than one byte and the most
                # significant bit of the second-most-significant-byte is set
                # it would conflict with the sign bit
                if len(data) <= 1 or (data[-2] & 0x80) == 0:
                    raise ScriptNumError("non-minimally encoded script number")
        
        value = cls._deserialize(data)
        return cls(value, max_num_size)
    
    @staticmethod
    def _deserialize(data: bytes) -> int:
        """
        Deserialize bytes to an integer (internal).
        
        Args:
            data: The bytes to deserialize
            
        Returns:
            The integer value
        """
        if not data:
            return 0
        
        result = 0
        for i, byte in enumerate(data):
            result |= byte << (8 * i)
        
        # If the most significant byte has bit 7 set, it's negative
        if data[-1] & 0x80:
            # Clear the sign bit and negate
            result = -((result & ~(0x80 << (8 * (len(data) - 1)))))
        
        return result
    
    def serialize(self) -> bytes:
        """
        Serialize the ScriptNum to bytes.
        
        Returns:
            The serialized bytes
        """
        return self._serialize(self._value)
    
    @staticmethod
    def _serialize(value: int) -> bytes:
        """
        Serialize an integer to bytes (internal).
        
        Args:
            value: The integer to serialize
            
        Returns:
            The serialized bytes
        """
        if value == 0:
            return b''
        
        negative = value < 0
        absvalue = -value if negative else value
        
        result = bytearray()
        while absvalue:
            result.append(absvalue & 0xff)
            absvalue >>= 8
        
        # Handle sign bit
        if result[-1] & 0x80:
            # Need to add an extra byte for sign
            result.append(0x80 if negative else 0)
        elif negative:
            # Set sign bit on last byte
            result[-1] |= 0x80
        
        return bytes(result)
    
    def getint(self) -> int:
        """
        Get the value as a 32-bit signed integer.
        
        Returns:
            The value clamped to int32 range
        """
        if self._value > 2**31 - 1:
            return 2**31 - 1
        elif self._value < -(2**31):
            return -(2**31)
        return self._value
    
    @property
    def value(self) -> int:
        """Get the raw integer value."""
        return self._value
    
    # Comparison operators
    def __eq__(self, other: Union[int, 'ScriptNum']) -> bool:
        if isinstance(other, ScriptNum):
            return self._value == other._value
        return self._value == other
    
    def __lt__(self, other: Union[int, 'ScriptNum']) -> bool:
        if isinstance(other, ScriptNum):
            return self._value < other._value
        return self._value < other
    
    def __le__(self, other: Union[int, 'ScriptNum']) -> bool:
        if isinstance(other, ScriptNum):
            return self._value <= other._value
        return self._value <= other
    
    def __gt__(self, other: Union[int, 'ScriptNum']) -> bool:
        if isinstance(other, ScriptNum):
            return self._value > other._value
        return self._value > other
    
    def __ge__(self, other: Union[int, 'ScriptNum']) -> bool:
        if isinstance(other, ScriptNum):
            return self._value >= other._value
        return self._value >= other
    
    # Arithmetic operators
    def __add__(self, other: Union[int, 'ScriptNum']) -> 'ScriptNum':
        if isinstance(other, ScriptNum):
            return ScriptNum(self._value + other._value, self._max_num_size)
        return ScriptNum(self._value + other, self._max_num_size)
    
    def __sub__(self, other: Union[int, 'ScriptNum']) -> 'ScriptNum':
        if isinstance(other, ScriptNum):
            return ScriptNum(self._value - other._value, self._max_num_size)
        return ScriptNum(self._value - other, self._max_num_size)
    
    def __and__(self, other: Union[int, 'ScriptNum']) -> 'ScriptNum':
        if isinstance(other, ScriptNum):
            return ScriptNum(self._value & other._value, self._max_num_size)
        return ScriptNum(self._value & other, self._max_num_size)
    
    def __neg__(self) -> 'ScriptNum':
        assert self._value != -(2**63), "Cannot negate minimum int64"
        return ScriptNum(-self._value, self._max_num_size)
    
    # In-place operators
    def __iadd__(self, other: Union[int, 'ScriptNum']) -> 'ScriptNum':
        if isinstance(other, ScriptNum):
            self._value += other._value
        else:
            self._value += other
        return self
    
    def __isub__(self, other: Union[int, 'ScriptNum']) -> 'ScriptNum':
        if isinstance(other, ScriptNum):
            self._value -= other._value
        else:
            self._value -= other
        return self
    
    def __iand__(self, other: Union[int, 'ScriptNum']) -> 'ScriptNum':
        if isinstance(other, ScriptNum):
            self._value &= other._value
        else:
            self._value &= other
        return self
    
    def __int__(self) -> int:
        return self._value
    
    def __repr__(self) -> str:
        return f"ScriptNum({self._value})"


# ============================================================================
# Script - Serialized script for transactions
# ============================================================================

class Script:
    """
    Serialized script, used inside transaction inputs and outputs.
    
    Scripts are a stack-based language that defines conditions under which
    a transaction output can be spent.
    
    This class provides methods for:
    - Building scripts from opcodes and data
    - Parsing scripts into operations
    - Serializing/deserializing scripts
    - Checking script properties (P2SH, P2WPKH, P2WSH, P2TR, etc.)
    """
    
    def __init__(self, data: Optional[bytes] = None):
        """
        Initialize a Script.
        
        Args:
            data: Optional raw script bytes
        """
        self._data = bytearray(data) if data else bytearray()
    
    @property
    def data(self) -> bytes:
        """Get the raw script bytes."""
        return bytes(self._data)
    
    def __len__(self) -> int:
        return len(self._data)
    
    def __bytes__(self) -> bytes:
        return bytes(self._data)
    
    def __eq__(self, other: object) -> bool:
        if isinstance(other, Script):
            return self._data == other._data
        if isinstance(other, bytes):
            return self._data == other
        return False
    
    def __repr__(self) -> str:
        return f"Script({self._data.hex()})"
    
    def __iter__(self) -> Iterator[int]:
        return iter(self._data)
    
    # ========================================================================
    # Script Building Methods
    # ========================================================================
    
    def push_data(self, data: bytes) -> 'Script':
        """
        Push data onto the script.
        
        Args:
            data: The data to push
            
        Returns:
            self for chaining
        """
        size = len(data)
        
        if size < OP_PUSHDATA1:
            # Direct push (opcode 0x01-0x4b indicates number of bytes to push)
            self._data.append(size)
        elif size <= 0xff:
            # Use OP_PUSHDATA1
            self._data.append(OP_PUSHDATA1)
            self._data.append(size)
        elif size <= 0xffff:
            # Use OP_PUSHDATA2
            self._data.append(OP_PUSHDATA2)
            self._data.extend(struct.pack('<H', size))
        else:
            # Use OP_PUSHDATA4
            self._data.append(OP_PUSHDATA4)
            self._data.extend(struct.pack('<I', size))
        
        self._data.extend(data)
        return self
    
    def push_int(self, n: int) -> 'Script':
        """
        Push an integer onto the script.
        
        Args:
            n: The integer to push
            
        Returns:
            self for chaining
        """
        if n == -1 or (1 <= n <= 16):
            # Use OP_1NEGATE or OP_1 through OP_16
            self._data.append(EncodeOP_N(n))
        elif n == 0:
            # Use OP_0
            self._data.append(OP_0)
        else:
            # Serialize as ScriptNum and push
            self.push_data(ScriptNum._serialize(n))
        return self
    
    def push_opcode(self, opcode: int) -> 'Script':
        """
        Push an opcode onto the script.
        
        Args:
            opcode: The opcode to push
            
        Returns:
            self for chaining
        """
        if opcode < 0 or opcode > 0xff:
            raise ValueError(f"Invalid opcode: {opcode}")
        self._data.append(opcode)
        return self
    
    def add_op(self, opcode: int) -> 'Script':
        """Alias for push_opcode."""
        return self.push_opcode(opcode)
    
    def __lshift__(self, other) -> 'Script':
        """
        Left shift operator for building scripts.
        
        Args:
            other: int (for opcode), bytes (for data), or ScriptNum
            
        Returns:
            self for chaining
        """
        if isinstance(other, int):
            if other in (OpcodeType.OP_0, OpcodeType.OP_1NEGATE) or \
               OpcodeType.OP_1 <= other <= OpcodeType.OP_16:
                self.push_int(DecodeOP_N(other))
            else:
                self.push_opcode(other)
        elif isinstance(other, bytes):
            self.push_data(other)
        elif isinstance(other, ScriptNum):
            self.push_data(other.serialize())
        elif isinstance(other, Script):
            self._data.extend(other._data)
        else:
            raise TypeError(f"Cannot add {type(other)} to Script")
        return self
    
    # ========================================================================
    # Script Parsing Methods
    # ========================================================================
    
    def get_op(self, pc: int) -> Tuple[bool, int, Optional[int], bytes]:
        """
        Get the next opcode and data from a position in the script.
        
        Args:
            pc: Current position in the script
            
        Returns:
            Tuple of (success, new_position, opcode, data)
            success: True if an operation was successfully read
            new_position: The new position after reading
            opcode: The opcode read (or None if data push)
            data: The data pushed (empty if opcode)
        """
        if pc >= len(self._data):
            return False, pc, None, b''
        
        opcode = self._data[pc]
        pc += 1
        
        # Handle push operations
        if opcode <= OP_PUSHDATA4:
            size = 0
            
            if opcode < OP_PUSHDATA1:
                # Direct push
                size = opcode
            elif opcode == OP_PUSHDATA1:
                if pc >= len(self._data):
                    return False, pc, None, b''
                size = self._data[pc]
                pc += 1
            elif opcode == OP_PUSHDATA2:
                if pc + 2 > len(self._data):
                    return False, pc, None, b''
                size = struct.unpack('<H', self._data[pc:pc+2])[0]
                pc += 2
            elif opcode == OP_PUSHDATA4:
                if pc + 4 > len(self._data):
                    return False, pc, None, b''
                size = struct.unpack('<I', self._data[pc:pc+4])[0]
                pc += 4
            
            # Read the data
            if pc + size > len(self._data):
                return False, pc, None, b''
            
            data = bytes(self._data[pc:pc+size])
            pc += size
            
            return True, pc, opcode, data
        
        # Regular opcode
        return True, pc, opcode, b''
    
    def iterate_ops(self) -> Iterator[Tuple[int, bytes]]:
        """
        Iterate over all operations in the script.
        
        Yields:
            Tuples of (opcode, data) for each operation
        """
        pc = 0
        while pc < len(self._data):
            success, pc, opcode, data = self.get_op(pc)
            if not success:
                break
            yield opcode, data
    
    # ========================================================================
    # Script Type Detection Methods
    # ========================================================================
    
    def is_pay_to_script_hash(self) -> bool:
        """
        Check if this is a P2SH scriptPubKey.
        
        P2SH scripts have the form: OP_HASH160 <20 bytes> OP_EQUAL
        
        Returns:
            True if this is a P2SH output
        """
        return (len(self._data) == 23 and
                self._data[0] == OP_HASH160 and
                self._data[1] == 0x14 and
                self._data[22] == OP_EQUAL)
    
    def is_pay_to_witness_script_hash(self) -> bool:
        """
        Check if this is a P2WSH scriptPubKey.
        
        P2WSH scripts have the form: OP_0 <32 bytes>
        
        Returns:
            True if this is a P2WSH output
        """
        return (len(self._data) == 34 and
                self._data[0] == OP_0 and
                self._data[1] == 0x20)
    
    def is_pay_to_witness_public_key_hash(self) -> bool:
        """
        Check if this is a P2WPKH scriptPubKey.
        
        P2WPKH scripts have the form: OP_0 <20 bytes>
        
        Returns:
            True if this is a P2WPKH output
        """
        return (len(self._data) == 22 and
                self._data[0] == OP_0 and
                self._data[1] == 0x14)
    
    def is_pay_to_taproot(self) -> bool:
        """
        Check if this is a P2TR (Taproot) scriptPubKey.
        
        P2TR scripts have the form: OP_1 <32 bytes>
        
        Returns:
            True if this is a P2TR output
        """
        return (len(self._data) == 34 and
                self._data[0] == OP_1 and
                self._data[1] == 0x20)
    
    def is_pay_to_anchor(self) -> bool:
        """
        Check if this is a P2A (anchor) scriptPubKey.
        
        P2A scripts have the form: OP_1 <0x4e73>
        
        Returns:
            True if this is a P2A output
        """
        return (len(self._data) == 4 and
                self._data[0] == OP_1 and
                self._data[1] == 0x02 and
                self._data[2] == 0x4e and
                self._data[3] == 0x73)
    
    def is_witness_program(self) -> Tuple[bool, int, bytes]:
        """
        Check if this is a witness program.
        
        A witness program is a script that consists of:
        - A version byte (OP_0 or OP_1 through OP_16)
        - A data push between 2 and 40 bytes
        
        Returns:
            Tuple of (is_witness, version, program)
        """
        if len(self._data) < 4 or len(self._data) > 42:
            return False, 0, b''
        
        # Check version byte
        if self._data[0] != OP_0 and not (OP_1 <= self._data[0] <= OP_16):
            return False, 0, b''
        
        # Check program length matches
        if len(self._data) != self._data[1] + 2:
            return False, 0, b''
        
        version = DecodeOP_N(self._data[0])
        program = bytes(self._data[2:])
        
        return True, version, program
    
    def is_push_only(self, start_pc: int = 0) -> bool:
        """
        Check if the script contains only push operations.
        
        Args:
            start_pc: Starting position to check from
            
        Returns:
            True if only push operations are present
        """
        pc = start_pc
        while pc < len(self._data):
            success, pc, opcode, _ = self.get_op(pc)
            if not success:
                return False
            # OP_RESERVED is considered a push for this check
            if opcode > OP_16:
                return False
        return True
    
    def is_unspendable(self) -> bool:
        """
        Check if this script is guaranteed to fail at execution.
        
        A script is unspendable if:
        - It starts with OP_RETURN
        - It's larger than MAX_SCRIPT_SIZE
        
        Returns:
            True if the script is unspendable
        """
        return (len(self._data) > 0 and self._data[0] == OP_RETURN) or \
               len(self._data) > MAX_SCRIPT_SIZE
    
    def has_valid_ops(self) -> bool:
        """
        Check if the script contains only valid opcodes.
        
        Returns:
            True if all opcodes are valid
        """
        for opcode, data in self.iterate_ops():
            if opcode > MAX_OPCODE:
                return False
            if len(data) > MAX_SCRIPT_ELEMENT_SIZE:
                return False
        return True
    
    # ========================================================================
    # Signature Operation Counting
    # ========================================================================
    
    def get_sigop_count(self, accurate: bool = False) -> int:
        """
        Count the number of signature operations in the script.
        
        Args:
            accurate: If True, count exact sigops in CHECKMULTISIG
            
        Returns:
            Number of signature operations
        """
        count = 0
        last_opcode = OP_0
        
        for opcode, _ in self.iterate_ops():
            if opcode == OP_CHECKSIG or opcode == OP_CHECKSIGVERIFY:
                count += 1
            elif opcode == OP_CHECKMULTISIG or opcode == OP_CHECKMULTISIGVERIFY:
                if accurate and OP_1 <= last_opcode <= OP_16:
                    # Use the preceding OP_N to determine key count
                    count += DecodeOP_N(last_opcode)
                else:
                    # Assume maximum keys
                    count += MAX_PUBKEYS_PER_MULTISIG
            last_opcode = opcode
        
        return count
    
    def get_sigop_count_with_scriptsig(self, scriptsig: 'Script') -> int:
        """
        Count sigops including those in P2SH redeem scripts.
        
        Args:
            scriptsig: The scriptSig being evaluated
            
        Returns:
            Total number of signature operations
        """
        if not self.is_pay_to_script_hash():
            return self.get_sigop_count(True)
        
        # Get the last item pushed by scriptSig
        data = None
        for opcode, push_data in scriptsig.iterate_ops():
            if opcode > OP_16:
                return 0
            data = push_data
        
        if data is None:
            return 0
        
        # Count sigops in the subscript
        subscript = Script(data)
        return subscript.get_sigop_count(True)
    
    # ========================================================================
    # Utility Methods
    # ========================================================================
    
    def clear(self) -> None:
        """Clear the script data."""
        self._data.clear()
    
    def copy(self) -> 'Script':
        """Create a copy of this script."""
        return Script(bytes(self._data))
    
    def to_string(self, verbose: bool = False) -> str:
        """
        Convert the script to a human-readable string.
        
        Args:
            verbose: If True, include hex data for pushes
            
        Returns:
            String representation of the script
        """
        parts = []
        for opcode, data in self.iterate_ops():
            if data:
                if verbose:
                    parts.append(f"0x{data.hex()}")
                else:
                    parts.append(f"[{len(data)} bytes]")
            else:
                parts.append(GetOpName(opcode))
        return " ".join(parts)
    
    @classmethod
    def build_p2pkh(cls, pubkey_hash: bytes) -> 'Script':
        """
        Build a P2PKH scriptPubKey.
        
        Args:
            pubkey_hash: 20-byte HASH160 of the public key
            
        Returns:
            P2PKH script
        """
        script = cls()
        script.push_opcode(OP_HASH160)
        script.push_data(pubkey_hash)
        script.push_opcode(OP_EQUAL)
        return script
    
    @classmethod
    def build_p2sh(cls, script_hash: bytes) -> 'Script':
        """
        Build a P2SH scriptPubKey.
        
        Args:
            script_hash: 20-byte HASH160 of the redeem script
            
        Returns:
            P2SH script
        """
        script = cls()
        script.push_opcode(OP_HASH160)
        script.push_data(script_hash)
        script.push_opcode(OP_EQUAL)
        return script
    
    @classmethod
    def build_p2wpkh(cls, pubkey_hash: bytes) -> 'Script':
        """
        Build a P2WPKH scriptPubKey.
        
        Args:
            pubkey_hash: 20-byte HASH160 of the public key
            
        Returns:
            P2WPKH script
        """
        script = cls()
        script.push_opcode(OP_0)
        script.push_data(pubkey_hash)
        return script
    
    @classmethod
    def build_p2wsh(cls, script_hash: bytes) -> 'Script':
        """
        Build a P2WSH scriptPubKey.
        
        Args:
            script_hash: 32-byte SHA256 of the witness script
            
        Returns:
            P2WSH script
        """
        script = cls()
        script.push_opcode(OP_0)
        script.push_data(script_hash)
        return script
    
    @classmethod
    def build_p2tr(cls, output_key: bytes) -> 'Script':
        """
        Build a P2TR (Taproot) scriptPubKey.
        
        Args:
            output_key: 32-byte Taproot output key
            
        Returns:
            P2TR script
        """
        script = cls()
        script.push_opcode(OP_1)
        script.push_data(output_key)
        return script


# ============================================================================
# ScriptWitness - Witness data for segwit transactions
# ============================================================================

@dataclass
class ScriptWitness:
    """
    Witness data for a transaction input.
    
    The witness is a stack of byte arrays (not a serialized script).
    Each element is pushed separately onto the stack during validation.
    """
    stack: List[bytes] = field(default_factory=list)
    
    def is_null(self) -> bool:
        """Check if the witness is empty."""
        return len(self.stack) == 0
    
    def set_null(self) -> None:
        """Clear the witness."""
        self.stack.clear()
    
    def to_string(self) -> str:
        """Convert to human-readable string."""
        parts = [f"0x{item.hex()}" for item in self.stack]
        return f"ScriptWitness({', '.join(parts)})"
    
    def __repr__(self) -> str:
        return self.to_string()


# ============================================================================
# ScriptID - Hash160 reference to a script
# ============================================================================

@dataclass(frozen=True)
class ScriptID:
    """
    A reference to a script: the HASH160 of its serialization.
    
    Used for P2SH addresses.
    """
    hash: bytes  # 20-byte HASH160
    
    def __post_init__(self):
        if len(self.hash) != 20:
            raise ValueError("ScriptID hash must be 20 bytes")
    
    def __bytes__(self) -> bytes:
        return self.hash
    
    def __hex__(self) -> str:
        return self.hash.hex()
    
    def __repr__(self) -> str:
        return f"ScriptID({self.hash.hex()})"


# ============================================================================
# Helper Functions
# ============================================================================

def GetScriptOp(data: bytes, pc: int) -> Tuple[bool, int, int, bytes]:
    """
    Parse a single operation from script data.
    
    Args:
        data: The script bytes
        pc: Current position
        
    Returns:
        Tuple of (success, new_pc, opcode, push_data)
    """
    if pc >= len(data):
        return False, pc, OpcodeType.OP_INVALIDOPCODE, b''
    
    opcode = data[pc]
    pc += 1
    
    # Handle push operations
    if opcode <= OP_PUSHDATA4:
        size = 0
        
        if opcode < OP_PUSHDATA1:
            size = opcode
        elif opcode == OP_PUSHDATA1:
            if pc >= len(data):
                return False, pc, OpcodeType.OP_INVALIDOPCODE, b''
            size = data[pc]
            pc += 1
        elif opcode == OP_PUSHDATA2:
            if pc + 2 > len(data):
                return False, pc, OpcodeType.OP_INVALIDOPCODE, b''
            size = struct.unpack('<H', data[pc:pc+2])[0]
            pc += 2
        elif opcode == OP_PUSHDATA4:
            if pc + 4 > len(data):
                return False, pc, OpcodeType.OP_INVALIDOPCODE, b''
            size = struct.unpack('<I', data[pc:pc+4])[0]
            pc += 4
        
        if pc + size > len(data):
            return False, pc, OpcodeType.OP_INVALIDOPCODE, b''
        
        return True, pc, opcode, data[pc:pc+size]
    
    return True, pc, opcode, b''


def CheckMinimalPush(data: bytes, opcode: int) -> bool:
    """
    Check if the data is pushed using the minimal encoding.
    
    Args:
        data: The data being pushed
        opcode: The opcode used to push it
        
    Returns:
        True if the push is minimal
    """
    # OP_1NEGATE, OP_1..OP_16 are always minimal
    assert 0 <= opcode <= OP_PUSHDATA4
    
    if len(data) == 0:
        # Should have used OP_0
        return opcode == OP_0
    
    if len(data) == 1 and 1 <= data[0] <= 16:
        # Should have used OP_1..OP_16
        return False
    
    if len(data) == 1 and data[0] == 0x81:
        # Should have used OP_1NEGATE
        return False
    
    if len(data) <= 75:
        # Must use direct push (opcode = length)
        return opcode == len(data)
    
    if len(data) <= 255:
        # Must use OP_PUSHDATA1
        return opcode == OP_PUSHDATA1
    
    if len(data) <= 65535:
        # Must use OP_PUSHDATA2
        return opcode == OP_PUSHDATA2
    
    return True


def ToByteVector(data: bytes) -> bytes:
    """Convert data to byte vector (identity function for bytes)."""
    return data
