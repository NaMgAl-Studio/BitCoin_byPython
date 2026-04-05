"""
RPC Request and Response Handling.

This module provides JSON-RPC 2.0 request parsing, response generation,
and authentication cookie management.

Reference: Bitcoin Core src/rpc/request.h, src/rpc/request.cpp
"""

import json
import os
import secrets
import hashlib
import base64
from dataclasses import dataclass, field
from typing import Optional, Any, Dict, List, Union
from pathlib import Path

from .protocol import RPCErrorCode, JSONRPCVersion


@dataclass
class JSONRPCRequest:
    """
    JSON-RPC Request representation.
    
    Supports both JSON-RPC 1.0/1.1 (legacy) and 2.0 versions.
    """
    # Request ID (used to match responses)
    id: Optional[Any] = None
    # Method name
    method: str = ""
    # Parameters (array or object)
    params: Union[List, Dict, None] = None
    # Execution mode
    mode: str = "EXECUTE"  # EXECUTE, GET_HELP, GET_ARGS
    # URI path
    uri: str = ""
    # Authenticated username
    auth_user: str = ""
    # Peer address
    peer_addr: str = ""
    # Context object (application-specific)
    context: Any = None
    # JSON-RPC version
    json_version: JSONRPCVersion = JSONRPCVersion.V1_LEGACY

    def parse(self, val_request: Dict) -> None:
        """
        Parse a JSON request object.
        
        Args:
            val_request: Dictionary containing JSON-RPC request
        """
        # Check JSON-RPC version
        jsonrpc = val_request.get("jsonrpc")
        if jsonrpc == "2.0":
            self.json_version = JSONRPCVersion.V2
        else:
            self.json_version = JSONRPCVersion.V1_LEGACY

        # Get method
        method_val = val_request.get("method")
        if method_val is None:
            raise JSONRPCError(RPCErrorCode.RPC_INVALID_REQUEST, "Missing method")
        
        if not isinstance(method_val, str):
            raise JSONRPCError(RPCErrorCode.RPC_INVALID_REQUEST, "Method must be a string")
        
        self.method = method_val

        # Get ID
        if "id" in val_request:
            self.id = val_request["id"]
        else:
            # JSON-RPC 2.0 notification (no id)
            self.id = None

        # Get params
        params_val = val_request.get("params")
        if params_val is not None:
            if not isinstance(params_val, (list, dict)):
                raise JSONRPCError(
                    RPCErrorCode.RPC_INVALID_PARAMS,
                    "Params must be an array or object"
                )
            self.params = params_val
        else:
            self.params = []

    def is_notification(self) -> bool:
        """Check if this is a JSON-RPC 2.0 notification."""
        return self.id is None and self.json_version == JSONRPCVersion.V2

    def to_dict(self) -> Dict:
        """Convert request to dictionary."""
        result = {"method": self.method}
        
        if self.json_version == JSONRPCVersion.V2:
            result["jsonrpc"] = "2.0"
        
        if self.id is not None:
            result["id"] = self.id
        
        if self.params:
            result["params"] = self.params
        
        return result


class JSONRPCError(Exception):
    """
    JSON-RPC Error exception.
    
    Represents an error that can be serialized to JSON-RPC error response.
    """

    def __init__(self, code: RPCErrorCode, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(message)

    def to_dict(self) -> Dict:
        """Convert error to JSON-RPC error object."""
        error = {
            "code": int(self.code),
            "message": self.message
        }
        if self.data is not None:
            error["data"] = self.data
        return error


def jsonrpc_request_obj(
    method: str,
    params: Union[List, Dict, None],
    request_id: Any
) -> Dict:
    """
    Create a JSON-RPC request object.
    
    Args:
        method: Method name
        params: Method parameters
        request_id: Request ID
    
    Returns:
        JSON-RPC request dictionary
    """
    obj = {
        "method": method,
        "params": params if params else [],
        "id": request_id
    }
    return obj


def jsonrpc_reply_obj(
    result: Any,
    error: Optional[JSONRPCError],
    request_id: Optional[Any],
    jsonrpc_version: JSONRPCVersion = JSONRPCVersion.V1_LEGACY
) -> Dict:
    """
    Create a JSON-RPC reply object.
    
    Args:
        result: Method result (if successful)
        error: Error object (if failed)
        request_id: Request ID to match
        jsonrpc_version: JSON-RPC protocol version
    
    Returns:
        JSON-RPC response dictionary
    """
    if jsonrpc_version == JSONRPCVersion.V2:
        obj = {"jsonrpc": "2.0"}
    else:
        obj = {}
    
    # For notifications (no id), we shouldn't respond
    if request_id is not None:
        obj["id"] = request_id
    
    if error is not None:
        obj["error"] = error.to_dict()
    else:
        obj["result"] = result
    
    return obj


def jsonrpc_error(code: RPCErrorCode, message: str, data: Any = None) -> Dict:
    """
    Create a JSON-RPC error response.
    
    Args:
        code: Error code
        message: Error message
        data: Optional additional error data
    
    Returns:
        JSON-RPC error dictionary
    """
    return JSONRPCError(code, message, data).to_dict()


def jsonrpc_process_batch_reply(response: Dict) -> List[Dict]:
    """
    Process a JSON-RPC batch response.
    
    Args:
        response: Batch response dictionary
    
    Returns:
        List of individual responses
    """
    if isinstance(response, list):
        return response
    return [response]


# Authentication Cookie Management

class GenerateAuthCookieResult:
    """Result of generate_auth_cookie operation."""
    DISABLED = "disabled"  # Cookie file generation disabled
    ERR = "error"          # Error occurred
    OK = "ok"              # Successfully generated


def generate_auth_cookie(
    cookie_dir: Optional[str] = None,
    cookie_perms: Optional[int] = None
) -> tuple:
    """
    Generate a new RPC authentication cookie and write it to disk.
    
    Args:
        cookie_dir: Directory to store cookie file (default: data directory)
        cookie_perms: File permissions (not used in Python implementation)
    
    Returns:
        Tuple of (status, username, password)
    """
    try:
        # Generate random username and password
        user = "__cookie__"
        pass_bytes = secrets.token_bytes(32)
        password = base64.b64encode(pass_bytes).decode('ascii')
        
        # Determine cookie file path
        if cookie_dir:
            cookie_path = Path(cookie_dir) / ".cookie"
        else:
            # Default to current directory
            cookie_path = Path(".cookie")
        
        # Create directory if needed
        cookie_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write cookie file
        cookie_content = f"{user}:{password}"
        cookie_path.write_text(cookie_content)
        
        # Set permissions (owner read/write only)
        if cookie_perms is None:
            os.chmod(cookie_path, 0o600)
        
        return (GenerateAuthCookieResult.OK, user, password)
    
    except Exception as e:
        return (GenerateAuthCookieResult.ERR, "", "")


def get_auth_cookie(cookie_path: Optional[str] = None) -> Optional[str]:
    """
    Read the RPC authentication cookie from disk.
    
    Args:
        cookie_path: Path to cookie file
    
    Returns:
        Cookie string (username:password) or None if not found
    """
    try:
        if cookie_path:
            path = Path(cookie_path)
        else:
            path = Path(".cookie")
        
        if not path.exists():
            return None
        
        return path.read_text().strip()
    
    except Exception:
        return None


def delete_auth_cookie(cookie_path: Optional[str] = None) -> bool:
    """
    Delete the RPC authentication cookie from disk.
    
    Args:
        cookie_path: Path to cookie file
    
    Returns:
        True if deleted successfully
    """
    try:
        if cookie_path:
            path = Path(cookie_path)
        else:
            path = Path(".cookie")
        
        if path.exists():
            path.unlink()
        return True
    
    except Exception:
        return False


# JSON-RPC ID Generation

_id_counter = 0

def generate_request_id() -> int:
    """Generate a unique request ID."""
    global _id_counter
    _id_counter += 1
    return _id_counter


# UniValue-like JSON handling

class UniValue:
    """
    JSON value wrapper providing type-safe access.
    
    Mimics Bitcoin Core's UniValue class for compatibility.
    """
    
    VNULL = 0
    VBOOL = 1
    VNUM = 2
    VSTR = 3
    VARR = 4
    VOBJ = 5
    
    def __init__(self, value=None, vtype=None):
        self._value = value
        self._type = vtype
        
        if vtype is not None:
            self._type = vtype
        elif value is None:
            self._type = self.VNULL
            self._value = None
        elif isinstance(value, bool):
            self._type = self.VBOOL
        elif isinstance(value, (int, float)):
            self._type = self.VNUM
        elif isinstance(value, str):
            self._type = self.VSTR
        elif isinstance(value, list):
            self._type = self.VARR
        elif isinstance(value, dict):
            self._type = self.VOBJ
        else:
            self._type = self.VSTR
            self._value = str(value)
    
    def is_null(self) -> bool:
        return self._type == self.VNULL
    
    def is_bool(self) -> bool:
        return self._type == self.VBOOL
    
    def is_num(self) -> bool:
        return self._type == self.VNUM
    
    def is_str(self) -> bool:
        return self._type == self.VSTR
    
    def is_array(self) -> bool:
        return self._type == self.VARR
    
    def is_object(self) -> bool:
        return self._type == self.VOBJ
    
    def get_int(self) -> int:
        if self._type == self.VNUM:
            return int(self._value)
        raise TypeError("Value is not a number")
    
    def get_int64(self) -> int:
        return self.get_int()
    
    def get_str(self) -> str:
        if self._type == self.VSTR:
            return self._value
        return str(self._value)
    
    def get_bool(self) -> bool:
        if self._type == self.VBOOL:
            return self._value
        raise TypeError("Value is not a boolean")
    
    def get_real(self) -> float:
        if self._type == self.VNUM:
            return float(self._value)
        raise TypeError("Value is not a number")
    
    def get_array(self) -> List:
        if self._type == self.VARR:
            return self._value
        raise TypeError("Value is not an array")
    
    def get_obj(self) -> Dict:
        if self._type == self.VOBJ:
            return self._value
        raise TypeError("Value is not an object")
    
    def __getitem__(self, key):
        if self._type == self.VARR:
            return UniValue(self._value[key])
        elif self._type == self.VOBJ:
            return UniValue(self._value[key])
        raise TypeError("Value is not indexable")
    
    def __len__(self):
        if self._type in (self.VARR, self.VOBJ):
            return len(self._value)
        return 0
    
    def __iter__(self):
        if self._type == self.VARR:
            return iter(self._value)
        elif self._type == self.VOBJ:
            return iter(self._value.items())
        return iter([])
    
    def keys(self):
        if self._type == self.VOBJ:
            return self._value.keys()
        return []
    
    def find_value(self, key: str):
        """Find a value by key in an object."""
        if self._type == self.VOBJ:
            if key in self._value:
                return UniValue(self._value[key])
        return UniValue(None, self.VNULL)
    
    def push_back(self, value):
        """Add a value to an array."""
        if self._type == self.VARR:
            self._value.append(value)
        else:
            raise TypeError("Value is not an array")
    
    def push_kv(self, key: str, value):
        """Add a key-value pair to an object."""
        if self._type == self.VOBJ:
            self._value[key] = value
        else:
            raise TypeError("Value is not an object")
    
    def write(self, pretty: bool = False) -> str:
        """Serialize to JSON string."""
        if pretty:
            return json.dumps(self._value, indent=2)
        return json.dumps(self._value, separators=(',', ':'))
    
    def read(self, s: str) -> bool:
        """Parse from JSON string."""
        try:
            self._value = json.loads(s)
            # Update type
            if self._value is None:
                self._type = self.VNULL
            elif isinstance(self._value, bool):
                self._type = self.VBOOL
            elif isinstance(self._value, (int, float)):
                self._type = self.VNUM
            elif isinstance(self._value, str):
                self._type = self.VSTR
            elif isinstance(self._value, list):
                self._type = self.VARR
            elif isinstance(self._value, dict):
                self._type = self.VOBJ
            return True
        except json.JSONDecodeError:
            return False
    
    @staticmethod
    def from_json(s: str):
        """Create UniValue from JSON string."""
        uv = UniValue()
        uv.read(s)
        return uv


# NullUniValue singleton
NullUniValue = UniValue(None, UniValue.VNULL)
