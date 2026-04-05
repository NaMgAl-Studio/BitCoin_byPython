"""
RPC Client Implementation.

This module provides a client for connecting to Bitcoin JSON-RPC servers.

Reference: Bitcoin Core src/rpc/client.cpp
"""

import json
import base64
import socket
import http.client
from typing import Optional, Dict, Any, List, Union
from dataclasses import dataclass
from contextlib import contextmanager

from .protocol import RPCErrorCode
from .request import JSONRPCRequest, JSONRPCError, generate_request_id


@dataclass
class RPCClientConfig:
    """RPC client configuration."""
    host: str = "127.0.0.1"
    port: int = 8332
    user: Optional[str] = None
    password: Optional[str] = None
    cookie_path: Optional[str] = None
    timeout: int = 30
    use_ssl: bool = False


class RPCClientError(Exception):
    """Exception raised for RPC client errors."""
    
    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"RPC Error {code}: {message}")


class RPCClient:
    """
    JSON-RPC Client for Bitcoin.
    
    Provides methods for calling RPC methods on a Bitcoin node.
    """
    
    def __init__(self, config: RPCClientConfig):
        self.config = config
        self._id_counter = 0
        self._cookie: Optional[str] = None
        
        # Load cookie if path provided
        if config.cookie_path:
            self._load_cookie(config.cookie_path)
    
    def _load_cookie(self, path: str):
        """Load authentication cookie from file."""
        try:
            with open(path, 'r') as f:
                self._cookie = f.read().strip()
        except Exception:
            self._cookie = None
    
    def _get_auth_header(self) -> str:
        """Get Authorization header value."""
        if self._cookie:
            # Use cookie authentication
            encoded = base64.b64encode(self._cookie.encode()).decode()
            return f"Basic {encoded}"
        
        if self.config.user and self.config.password:
            # Use user/password authentication
            credentials = f"{self.config.user}:{self.config.password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            return f"Basic {encoded}"
        
        return ""
    
    def _next_id(self) -> int:
        """Get next request ID."""
        self._id_counter += 1
        return self._id_counter
    
    def _make_request(self, method: str, params: List = None, request_id: Any = None) -> Dict:
        """Create a JSON-RPC request object."""
        if params is None:
            params = []
        
        if request_id is None:
            request_id = self._next_id()
        
        return {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": request_id
        }
    
    def _send_request(self, request: Dict) -> Dict:
        """Send JSON-RPC request and get response."""
        headers = {
            "Content-Type": "application/json",
        }
        
        auth_header = self._get_auth_header()
        if auth_header:
            headers["Authorization"] = auth_header
        
        body = json.dumps(request)
        
        # Create HTTP connection
        if self.config.use_ssl:
            conn = http.client.HTTPSConnection(
                self.config.host,
                self.config.port,
                timeout=self.config.timeout
            )
        else:
            conn = http.client.HTTPConnection(
                self.config.host,
                self.config.port,
                timeout=self.config.timeout
            )
        
        try:
            conn.request("POST", "/", body, headers)
            response = conn.getresponse()
            
            if response.status == 401:
                raise RPCClientError(
                    RPCErrorCode.RPC_INVALID_REQUEST,
                    "Authentication failed"
                )
            
            response_body = response.read().decode()
            
            try:
                return json.loads(response_body)
            except json.JSONDecodeError:
                raise RPCClientError(
                    RPCErrorCode.RPC_PARSE_ERROR,
                    f"Failed to parse response: {response_body[:100]}"
                )
        
        except socket.timeout:
            raise RPCClientError(
                RPCErrorCode.RPC_MISC_ERROR,
                "Request timed out"
            )
        except socket.error as e:
            raise RPCClientError(
                RPCErrorCode.RPC_CLIENT_NOT_CONNECTED,
                f"Connection error: {e}"
            )
        finally:
            conn.close()
    
    def call(self, method: str, *args) -> Any:
        """
        Call an RPC method.
        
        Args:
            method: RPC method name
            *args: Positional arguments
        
        Returns:
            Result from RPC call
        
        Raises:
            RPCClientError on RPC or connection errors
        """
        request = self._make_request(method, list(args))
        response = self._send_request(request)
        
        if "error" in response and response["error"] is not None:
            error = response["error"]
            raise RPCClientError(
                error.get("code", RPCErrorCode.RPC_MISC_ERROR),
                error.get("message", "Unknown error"),
                error.get("data")
            )
        
        return response.get("result")
    
    def call_named(self, method: str, **kwargs) -> Any:
        """
        Call an RPC method with named parameters.
        
        Args:
            method: RPC method name
            **kwargs: Named arguments
        
        Returns:
            Result from RPC call
        """
        request = self._make_request(method, kwargs)
        response = self._send_request(request)
        
        if "error" in response and response["error"] is not None:
            error = response["error"]
            raise RPCClientError(
                error.get("code", RPCErrorCode.RPC_MISC_ERROR),
                error.get("message", "Unknown error"),
                error.get("data")
            )
        
        return response.get("result")
    
    def batch(self, calls: List[Dict]) -> List[Dict]:
        """
        Execute a batch of RPC calls.
        
        Args:
            calls: List of {"method": ..., "params": ...} dicts
        
        Returns:
            List of responses
        """
        requests = []
        for call in calls:
            request = self._make_request(
                call["method"],
                call.get("params", [])
            )
            requests.append(request)
        
        # Send batch request
        headers = {
            "Content-Type": "application/json",
        }
        
        auth_header = self._get_auth_header()
        if auth_header:
            headers["Authorization"] = auth_header
        
        body = json.dumps(requests)
        
        if self.config.use_ssl:
            conn = http.client.HTTPSConnection(
                self.config.host,
                self.config.port,
                timeout=self.config.timeout
            )
        else:
            conn = http.client.HTTPConnection(
                self.config.host,
                self.config.port,
                timeout=self.config.timeout
            )
        
        try:
            conn.request("POST", "/", body, headers)
            response = conn.getresponse()
            response_body = response.read().decode()
            return json.loads(response_body)
        finally:
            conn.close()
    
    # Common RPC method shortcuts
    
    def getblockchaininfo(self) -> Dict:
        """Get blockchain information."""
        return self.call("getblockchaininfo")
    
    def getblockhash(self, height: int) -> str:
        """Get block hash by height."""
        return self.call("getblockhash", height)
    
    def getblock(self, block_hash: str, verbosity: int = 1) -> Dict:
        """Get block by hash."""
        return self.call("getblock", block_hash, verbosity)
    
    def getrawtransaction(self, txid: str, verbose: bool = False) -> Union[str, Dict]:
        """Get raw transaction."""
        return self.call("getrawtransaction", txid, verbose)
    
    def sendrawtransaction(self, hex_tx: str, maxfeerate: float = None) -> str:
        """Send raw transaction."""
        if maxfeerate is not None:
            return self.call("sendrawtransaction", hex_tx, maxfeerate)
        return self.call("sendrawtransaction", hex_tx)
    
    def createrawtransaction(
        self,
        inputs: List[Dict],
        outputs: Dict,
        locktime: int = None,
        replaceable: bool = None
    ) -> str:
        """Create raw transaction."""
        params = [inputs, outputs]
        if locktime is not None:
            params.append(locktime)
        if replaceable is not None:
            params.append(replaceable)
        return self.call("createrawtransaction", *params)
    
    def signrawtransactionwithwallet(self, hex_tx: str) -> Dict:
        """Sign raw transaction with wallet."""
        return self.call("signrawtransactionwithwallet", hex_tx)
    
    def getbalance(self, dummy: str = "*", minconf: int = 0, include_watchonly: bool = True) -> float:
        """Get wallet balance."""
        return self.call("getbalance", dummy, minconf, include_watchonly)
    
    def getnewaddress(self, label: str = "", address_type: str = None) -> str:
        """Get new address."""
        if address_type:
            return self.call("getnewaddress", label, address_type)
        return self.call("getnewaddress", label)
    
    def listunspent(
        self,
        minconf: int = 1,
        maxconf: int = 9999999,
        addresses: List[str] = None,
        include_unsafe: bool = True,
        query_options: Dict = None
    ) -> List[Dict]:
        """List unspent outputs."""
        params = [minconf, maxconf]
        if addresses:
            params.append(addresses)
        params.append(include_unsafe)
        if query_options:
            params.append(query_options)
        return self.call("listunspent", *params)


@contextmanager
def rpc_connection(config: RPCClientConfig):
    """
    Context manager for RPC connections.
    
    Usage:
        with rpc_connection(config) as rpc:
            info = rpc.getblockchaininfo()
    """
    client = RPCClient(config)
    yield client


def create_client(
    host: str = "127.0.0.1",
    port: int = 8332,
    user: str = None,
    password: str = None,
    cookie_path: str = None
) -> RPCClient:
    """
    Create an RPC client with simplified parameters.
    
    Args:
        host: RPC server host
        port: RPC server port
        user: Username (optional)
        password: Password (optional)
        cookie_path: Path to cookie file (optional)
    
    Returns:
        RPCClient instance
    """
    config = RPCClientConfig(
        host=host,
        port=port,
        user=user,
        password=password,
        cookie_path=cookie_path
    )
    return RPCClient(config)
