"""
RPC Utilities.

This module provides utility functions and classes for RPC method
documentation, parameter validation, and type checking.

Reference: Bitcoin Core src/rpc/util.h, src/rpc/util.cpp
"""

import json
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Union, Tuple
from enum import Enum

from .protocol import RPCErrorCode
from .request import JSONRPCRequest, JSONRPCError, UniValue


# Unix epoch time description
UNIX_EPOCH_TIME = "UNIX epoch time"

# Example addresses for documentation
EXAMPLE_ADDRESS = [
    "bc1qxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",  # Mainnet example
    "tb1qxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",  # Testnet example
]


class RPCArgType(Enum):
    """Types for RPC arguments."""
    OBJ = "object"
    ARR = "array"
    STR = "string"
    NUM = "numeric"
    BOOL = "boolean"
    OBJ_NAMED_PARAMS = "object (named parameters)"
    OBJ_USER_KEYS = "object (user-defined keys)"
    AMOUNT = "amount"
    STR_HEX = "hex string"
    RANGE = "range"


class RPCResultType(Enum):
    """Types for RPC results."""
    OBJ = "object"
    ARR = "array"
    STR = "string"
    NUM = "numeric"
    BOOL = "boolean"
    NONE = "null"
    ANY = "any"
    STR_AMOUNT = "amount"
    STR_HEX = "hex string"
    OBJ_DYN = "object (dynamic keys)"
    ARR_FIXED = "array (fixed)"
    NUM_TIME = "unix time"
    ELISION = "..."


@dataclass
class RPCArgOptions:
    """Options for RPC arguments."""
    skip_type_check: bool = False
    oneline_description: str = ""
    type_str: List[str] = field(default_factory=list)
    hidden: bool = False
    also_positional: bool = False


@dataclass
class RPCArg:
    """RPC argument definition."""
    names: str
    type: RPCArgType
    fallback: Any = None  # Optional, DefaultHint, or default value
    description: str = ""
    inner: List['RPCArg'] = field(default_factory=list)
    opts: RPCArgOptions = field(default_factory=RPCArgOptions)
    
    def is_optional(self) -> bool:
        """Check if argument is optional."""
        return self.fallback is not None
    
    def get_first_name(self) -> str:
        """Get the first name from potentially multiple aliases."""
        if '|' in self.names:
            return self.names.split('|')[0]
        return self.names
    
    def get_name(self) -> str:
        """Get the name (throws if there are aliases)."""
        if '|' in self.names:
            raise ValueError("This argument has aliases")
        return self.names
    
    def to_string(self, oneline: bool = False) -> str:
        """Convert to string representation."""
        type_str = self.type.value
        if self.opts.type_str:
            if len(self.opts.type_str) >= 2:
                type_str = self.opts.type_str[1]
            elif self.opts.type_str:
                type_str = self.opts.type_str[0]
        
        if self.opts.oneline_description and oneline:
            return f"{self.names}={self.opts.oneline_description}"
        
        return f"{self.names} ({type_str})"
    
    def to_description_string(self, is_named_arg: bool = True) -> str:
        """Get the description string including type."""
        lines = []
        
        type_str = self.type.value
        if self.opts.type_str:
            if len(self.opts.type_str) >= 2:
                type_str = f"{self.opts.type_str[0]} or {self.opts.type_str[1]}"
            elif self.opts.type_str:
                type_str = self.opts.type_str[0]
        
        required_str = "required" if not self.is_optional() else "optional"
        
        lines.append(f"{self.names} ({type_str}, {required_str})")
        if self.description:
            lines.append(self.description)
        
        if self.fallback is not None and not isinstance(self.fallback, str):
            lines.append(f"Default: {self.fallback}")
        
        return "\n".join(lines)


@dataclass
class RPCResultOptions:
    """Options for RPC results."""
    skip_type_check: bool = False
    print_elision: Optional[str] = None


@dataclass
class RPCResult:
    """RPC result definition."""
    type: RPCResultType
    key_name: str = ""
    inner: List['RPCResult'] = field(default_factory=list)
    optional: bool = False
    opts: RPCResultOptions = field(default_factory=RPCResultOptions)
    description: str = ""
    cond: str = ""  # Condition string
    
    def to_string_obj(self) -> str:
        """Get string representation when in an object."""
        type_str = self.type.value
        optional_str = " (optional)" if self.optional else ""
        return f'"{self.key_name}": {type_str}{optional_str}'
    
    def to_description_string(self) -> str:
        """Get the description string."""
        lines = []
        
        if self.cond:
            lines.append(f"[{self.cond}]")
        
        type_str = self.type.value
        if self.opts.print_elision:
            lines.append(f"... {self.opts.print_elision}")
        else:
            if self.key_name:
                lines.append(f'{self.key_name}: {type_str}')
            else:
                lines.append(type_str)
            
            if self.description:
                lines.append(self.description)
        
        return "\n".join(lines)


@dataclass
class RPCResults:
    """Container for RPC result definitions."""
    results: List[RPCResult]
    
    def to_description_string(self) -> str:
        """Get description string for all results."""
        if not self.results:
            return ""
        
        if len(self.results) == 1:
            return self.results[0].to_description_string()
        
        lines = []
        for i, result in enumerate(self.results):
            if result.cond:
                lines.append(f"[{result.cond}]")
            lines.append(result.to_description_string())
        
        return "\n".join(lines)


@dataclass
class RPCExamples:
    """Container for RPC examples."""
    examples: str
    
    def to_description_string(self) -> str:
        """Get description string for examples."""
        return self.examples


def help_example_cli(method: str, args: str) -> str:
    """Generate CLI help example."""
    return f"> bitcoin-cli {method} {args}"


def help_example_cli_named(method: str, args: List[Tuple[str, Any]]) -> str:
    """Generate CLI help example with named arguments."""
    args_str = " ".join(f"{k}={v}" for k, v in args)
    return f"> bitcoin-cli {method} {args_str}"


def help_example_rpc(method: str, args: str) -> str:
    """Generate RPC help example."""
    return f'> curl --user myusername --data-binary \'{{"jsonrpc": "2.0", "id": "curltest", "method": "{method}", "params": [{args}]}}\' -H \'content-type: application/json\' http://127.0.0.1:8332/'


def help_example_rpc_named(method: str, args: List[Tuple[str, Any]]) -> str:
    """Generate RPC help example with named arguments."""
    params = ", ".join(f'"{k}": {json.dumps(v)}' for k, v in args)
    return f'> curl --user myusername --data-binary \'{{"jsonrpc": "2.0", "id": "curltest", "method": "{method}", "params": {{{params}}}}}\' -H \'content-type: application/json\' http://127.0.0.1:8332/'


def amount_from_value(value: Any, decimals: int = 8) -> int:
    """
    Convert a value to satoshi amount.
    
    Args:
        value: Numeric or string value
        decimals: Number of decimal places (default 8 for BTC)
    
    Returns:
        Amount in satoshis
    """
    if isinstance(value, (int, float)):
        return int(value * (10 ** decimals))
    
    if isinstance(value, str):
        # Try to parse as float
        try:
            return int(float(value) * (10 ** decimals))
        except ValueError:
            raise JSONRPCError(
                RPCErrorCode.RPC_TYPE_ERROR,
                f"Invalid amount: {value}"
            )
    
    raise JSONRPCError(
        RPCErrorCode.RPC_TYPE_ERROR,
        f"Expected numeric amount, got {type(value)}"
    )


def parse_hash_v(value: Any, name: str) -> bytes:
    """
    Parse a hex hash value.
    
    Args:
        value: Hex string
        name: Parameter name for error message
    
    Returns:
        32-byte hash
    """
    if not isinstance(value, str):
        raise JSONRPCError(
            RPCErrorCode.RPC_INVALID_PARAMETER,
            f"{name} must be a hex string"
        )
    
    try:
        data = bytes.fromhex(value)
        if len(data) != 32:
            raise JSONRPCError(
                RPCErrorCode.RPC_INVALID_PARAMETER,
                f"{name} must be 64 hex characters (32 bytes)"
            )
        return data
    except ValueError:
        raise JSONRPCError(
            RPCErrorCode.RPC_INVALID_PARAMETER,
            f"{name} must be a hex string"
        )


def parse_hash_o(obj: Dict, key: str) -> bytes:
    """Parse a hex hash from an object."""
    if key not in obj:
        raise JSONRPCError(
            RPCErrorCode.RPC_INVALID_PARAMETER,
            f"Missing {key}"
        )
    return parse_hash_v(obj[key], key)


def parse_hex_v(value: Any, name: str) -> bytes:
    """Parse a hex string to bytes."""
    if not isinstance(value, str):
        raise JSONRPCError(
            RPCErrorCode.RPC_INVALID_PARAMETER,
            f"{name} must be a hex string"
        )
    
    try:
        return bytes.fromhex(value)
    except ValueError:
        raise JSONRPCError(
            RPCErrorCode.RPC_INVALID_PARAMETER,
            f"{name} must be a hex string"
        )


def parse_hex_o(obj: Dict, key: str) -> bytes:
    """Parse hex from an object."""
    if key not in obj:
        raise JSONRPCError(
            RPCErrorCode.RPC_INVALID_PARAMETER,
            f"Missing {key}"
        )
    return parse_hex_v(obj[key], key)


def parse_verbosity(value: Any, default: int = 1, allow_bool: bool = True) -> int:
    """
    Parse verbosity parameter.
    
    Args:
        value: Verbosity value (int or bool)
        default: Default verbosity
        allow_bool: Allow boolean values
    
    Returns:
        Integer verbosity level
    """
    if value is None:
        return default
    
    if isinstance(value, bool):
        if allow_bool:
            return 1 if value else 0
        raise JSONRPCError(
            RPCErrorCode.RPC_INVALID_PARAMETER,
            "Verbosity must be an integer"
        )
    
    if isinstance(value, int):
        return value
    
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            pass
    
    raise JSONRPCError(
        RPCErrorCode.RPC_INVALID_PARAMETER,
        "Invalid verbosity value"
    )


def rpc_type_check_obj(
    obj: Dict,
    types_expected: Dict[str, Any],
    allow_null: bool = False,
    strict: bool = False
):
    """
    Check types of object values.
    
    Args:
        obj: Object to check
        types_expected: Expected types by key
        allow_null: Allow null values
        strict: Reject unexpected keys
    """
    for key, expected_type in types_expected.items():
        if key not in obj:
            raise JSONRPCError(
                RPCErrorCode.RPC_INVALID_PARAMETER,
                f"Missing required key: {key}"
            )
        
        value = obj[key]
        if value is None and allow_null:
            continue
        
        # Type checking would go here
    
    if strict:
        for key in obj:
            if key not in types_expected:
                raise JSONRPCError(
                    RPCErrorCode.RPC_INVALID_PARAMETER,
                    f"Unexpected key: {key}"
                )


def value_from_amount(amount: int) -> float:
    """
    Convert satoshi amount to BTC value.
    
    Args:
        amount: Amount in satoshis
    
    Returns:
        Amount in BTC
    """
    return amount / 100000000.0


def get_all_output_types() -> str:
    """Get all output types as comma-separated string."""
    return "legacy, p2sh-segwit, bech32, bech32m"
