"""
Unit tests for RPC module.

Tests core RPC functionality including:
- Protocol definitions
- Request/response handling
- Server command registration
- Authentication
- Client operations
"""

import os
import sys
import json
import tempfile
import unittest

# Add the source directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from bitcoin.rpc.protocol import (
    HTTPStatusCode, RPCErrorCode, JSONRPCVersion,
    get_error_description, get_http_status_for_error
)
from bitcoin.rpc.request import (
    JSONRPCRequest, JSONRPCError, UniValue,
    jsonrpc_request_obj, jsonrpc_reply_obj, jsonrpc_error
)
from bitcoin.rpc.server import (
    CRPCCommand, CRPCTable, RPCHelpMan,
    tableRPC, rpc_method, jsonrpc_exec
)
from bitcoin.rpc.auth import (
    generate_salt, password_to_hmac, generate_rpcauth,
    parse_rpcauth, RPCAuthenticator, parse_basic_auth, create_basic_auth
)
from bitcoin.rpc.client import RPCClient, RPCClientConfig, RPCClientError
from bitcoin.rpc.util import (
    RPCArgType, RPCArg, RPCResult, RPCResults,
    help_example_cli, help_example_rpc, amount_from_value
)


class TestRPCProtocol(unittest.TestCase):
    """Test RPC protocol definitions."""

    def test_http_status_codes(self):
        """Test HTTP status codes."""
        self.assertEqual(HTTPStatusCode.HTTP_OK, 200)
        self.assertEqual(HTTPStatusCode.HTTP_BAD_REQUEST, 400)
        self.assertEqual(HTTPStatusCode.HTTP_UNAUTHORIZED, 401)
        self.assertEqual(HTTPStatusCode.HTTP_NOT_FOUND, 404)

    def test_rpc_error_codes(self):
        """Test RPC error codes."""
        self.assertEqual(RPCErrorCode.RPC_INVALID_REQUEST, -32600)
        self.assertEqual(RPCErrorCode.RPC_METHOD_NOT_FOUND, -32601)
        self.assertEqual(RPCErrorCode.RPC_INVALID_PARAMS, -32602)
        self.assertEqual(RPCErrorCode.RPC_PARSE_ERROR, -32700)
        self.assertEqual(RPCErrorCode.RPC_WALLET_ERROR, -4)

    def test_get_error_description(self):
        """Test error description lookup."""
        desc = get_error_description(RPCErrorCode.RPC_INVALID_REQUEST)
        self.assertIn("Invalid Request", desc)
        
        desc = get_error_description(RPCErrorCode.RPC_WALLET_ERROR)
        self.assertIn("Wallet", desc)

    def test_http_status_for_error(self):
        """Test HTTP status mapping."""
        status = get_http_status_for_error(RPCErrorCode.RPC_INVALID_REQUEST)
        self.assertEqual(status, HTTPStatusCode.HTTP_BAD_REQUEST)


class TestRPCRequest(unittest.TestCase):
    """Test JSON-RPC request handling."""

    def test_request_parsing(self):
        """Test parsing JSON-RPC request."""
        request_data = {
            "jsonrpc": "2.0",
            "method": "getbalance",
            "params": [],
            "id": 1
        }
        
        request = JSONRPCRequest()
        request.parse(request_data)
        
        self.assertEqual(request.method, "getbalance")
        self.assertEqual(request.id, 1)
        self.assertEqual(request.params, [])
        self.assertEqual(request.json_version, JSONRPCVersion.V2)

    def test_request_parsing_v1(self):
        """Test parsing legacy JSON-RPC request."""
        request_data = {
            "method": "getblockcount",
            "params": [],
            "id": 2
        }
        
        request = JSONRPCRequest()
        request.parse(request_data)
        
        self.assertEqual(request.method, "getblockcount")
        self.assertEqual(request.json_version, JSONRPCVersion.V1_LEGACY)

    def test_notification_detection(self):
        """Test JSON-RPC 2.0 notification detection."""
        request = JSONRPCRequest()
        request.id = None
        request.json_version = JSONRPCVersion.V2
        self.assertTrue(request.is_notification())
        
        request.id = 1
        self.assertFalse(request.is_notification())

    def test_request_obj_creation(self):
        """Test creating request object."""
        obj = jsonrpc_request_obj("getinfo", [], 1)
        
        self.assertEqual(obj["method"], "getinfo")
        self.assertEqual(obj["params"], [])
        self.assertEqual(obj["id"], 1)

    def test_reply_obj_creation(self):
        """Test creating reply object."""
        reply = jsonrpc_reply_obj(
            result={"balance": 1.5},
            error=None,
            request_id=1,
            jsonrpc_version=JSONRPCVersion.V2
        )
        
        self.assertEqual(reply["jsonrpc"], "2.0")
        self.assertEqual(reply["result"]["balance"], 1.5)
        self.assertNotIn("error", reply)

    def test_error_reply(self):
        """Test creating error reply."""
        error = JSONRPCError(
            RPCErrorCode.RPC_INVALID_PARAMETER,
            "Invalid parameter"
        )
        
        reply = jsonrpc_reply_obj(
            result=None,
            error=error,
            request_id=1
        )
        
        self.assertIn("error", reply)
        self.assertEqual(reply["error"]["code"], RPCErrorCode.RPC_INVALID_PARAMETER)

    def test_univalue(self):
        """Test UniValue JSON wrapper."""
        # Null value
        uv = UniValue(None)
        self.assertTrue(uv.is_null())
        
        # String value
        uv = UniValue("hello")
        self.assertTrue(uv.is_str())
        self.assertEqual(uv.get_str(), "hello")
        
        # Number value
        uv = UniValue(42)
        self.assertTrue(uv.is_num())
        self.assertEqual(uv.get_int(), 42)
        
        # Boolean value
        uv = UniValue(True)
        self.assertTrue(uv.is_bool())
        self.assertTrue(uv.get_bool())
        
        # Array value
        uv = UniValue([1, 2, 3])
        self.assertTrue(uv.is_array())
        self.assertEqual(len(uv), 3)
        
        # Object value
        uv = UniValue({"key": "value"})
        self.assertTrue(uv.is_object())
        self.assertEqual(uv.get_obj()["key"], "value")


class TestRPCServer(unittest.TestCase):
    """Test RPC server functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.table = CRPCTable()

    def test_command_registration(self):
        """Test registering RPC commands."""
        def test_handler(request):
            return {"result": "success"}
        
        cmd = CRPCCommand(
            category="test",
            name="testmethod",
            actor=test_handler,
            arg_names=[]
        )
        
        self.table.append_command("testmethod", cmd)
        
        # Execute the command
        request = JSONRPCRequest()
        request.method = "testmethod"
        request.params = []
        
        result = self.table.execute(request)
        self.assertEqual(result["result"], "success")

    def test_method_not_found(self):
        """Test error for unknown method."""
        request = JSONRPCRequest()
        request.method = "unknownmethod"
        request.params = []
        
        with self.assertRaises(JSONRPCError) as context:
            self.table.execute(request)
        
        self.assertEqual(context.exception.code, RPCErrorCode.RPC_METHOD_NOT_FOUND)

    def test_decorator_registration(self):
        """Test @rpc_method decorator."""
        @rpc_method("test", "decorated_method")
        def decorated_handler(request):
            return "decorated result"
        
        request = JSONRPCRequest()
        request.method = "decorated_method"
        request.params = []
        
        result = tableRPC.execute(request)
        self.assertEqual(result, "decorated result")

    def test_list_commands(self):
        """Test listing registered commands."""
        def handler1(request):
            return 1
        
        def handler2(request):
            return 2
        
        self.table.append_command("method1", CRPCCommand("test", "method1", handler1))
        self.table.append_command("method2", CRPCCommand("test", "method2", handler2))
        
        commands = self.table.list_commands()
        self.assertIn("method1", commands)
        self.assertIn("method2", commands)


class TestRPCAuth(unittest.TestCase):
    """Test RPC authentication."""

    def test_salt_generation(self):
        """Test salt generation."""
        salt = generate_salt(16)
        self.assertEqual(len(salt), 32)  # 16 bytes = 32 hex chars
        
        salt2 = generate_salt(16)
        self.assertNotEqual(salt, salt2)  # Should be random

    def test_password_to_hmac(self):
        """Test HMAC generation."""
        salt = "0123456789abcdef"
        password = "testpassword"
        
        hmac1 = password_to_hmac(salt, password)
        hmac2 = password_to_hmac(salt, password)
        
        self.assertEqual(hmac1, hmac2)  # Same input = same output
        self.assertEqual(len(hmac1), 64)  # SHA256 = 64 hex chars

    def test_rpcauth_generation(self):
        """Test rpcauth line generation."""
        username = "testuser"
        password = "testpassword"
        
        line, gen_pass = generate_rpcauth(username, password)
        
        self.assertIn(username, line)
        self.assertIn(":", line)
        self.assertIn("$", line)
        self.assertEqual(gen_pass, password)

    def test_rpcauth_parsing(self):
        """Test parsing rpcauth line."""
        line = "user:salt$hash"
        entry = parse_rpcauth(line)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.username, "user")
        self.assertEqual(entry.salt, "salt")
        self.assertEqual(entry.password_hmac, "hash")

    def test_authenticator(self):
        """Test RPC authenticator."""
        auth = RPCAuthenticator()
        auth.set_cookie("__cookie__", "testpassword")
        
        # Test cookie auth
        auth_header = create_basic_auth("__cookie__", "testpassword")
        username = auth.check_authorization(auth_header)
        self.assertEqual(username, "__cookie__")
        
        # Test invalid auth
        auth_header = create_basic_auth("invalid", "invalid")
        username = auth.check_authorization(auth_header)
        self.assertIsNone(username)

    def test_basic_auth_parsing(self):
        """Test parsing Basic auth header."""
        header = create_basic_auth("user", "pass")
        self.assertTrue(header.startswith("Basic "))
        
        username, password = parse_basic_auth(header)
        self.assertEqual(username, "user")
        self.assertEqual(password, "pass")


class TestRPCClient(unittest.TestCase):
    """Test RPC client."""

    def test_client_creation(self):
        """Test creating RPC client."""
        config = RPCClientConfig(
            host="127.0.0.1",
            port=8332,
            user="testuser",
            password="testpass"
        )
        
        client = RPCClient(config)
        self.assertEqual(client.config.host, "127.0.0.1")
        self.assertEqual(client.config.port, 8332)

    def test_request_creation(self):
        """Test creating RPC request."""
        config = RPCClientConfig()
        client = RPCClient(config)
        
        request = client._make_request("getbalance", [1, 2], 123)
        
        self.assertEqual(request["jsonrpc"], "2.0")
        self.assertEqual(request["method"], "getbalance")
        self.assertEqual(request["params"], [1, 2])
        self.assertEqual(request["id"], 123)


class TestRPCUtil(unittest.TestCase):
    """Test RPC utilities."""

    def test_rpc_arg(self):
        """Test RPC argument definition."""
        arg = RPCArg(
            names="height",
            type=RPCArgType.NUM,
            description="Block height",
            fallback=None
        )
        
        self.assertEqual(arg.get_first_name(), "height")
        self.assertFalse(arg.is_optional())

    def test_help_examples(self):
        """Test help example generation."""
        cli = help_example_cli("getblock", "blockhash")
        self.assertIn("bitcoin-cli", cli)
        self.assertIn("getblock", cli)
        
        rpc = help_example_rpc("getblock", '"blockhash"')
        self.assertIn("curl", rpc)
        self.assertIn("getblock", rpc)

    def test_amount_conversion(self):
        """Test amount conversion."""
        # Convert BTC to satoshis
        satoshis = amount_from_value(1.5)
        self.assertEqual(satoshis, 150000000)
        
        # Small amount
        satoshis = amount_from_value(0.001)
        self.assertEqual(satoshis, 100000)


class TestIntegration(unittest.TestCase):
    """Integration tests for RPC module."""

    def test_full_request_flow(self):
        """Test full request/response flow."""
        # Register a method
        @rpc_method("test", "flow_test")
        def flow_handler(request):
            return {"input": request.params[0] if request.params else None}
        
        # Create and parse request
        request_data = {
            "jsonrpc": "2.0",
            "method": "flow_test",
            "params": ["test_input"],
            "id": 1
        }
        
        jreq = JSONRPCRequest()
        jreq.parse(request_data)
        jreq.auth_user = "testuser"
        
        # Execute
        response = jsonrpc_exec(jreq, catch_errors=True)
        
        self.assertEqual(response["result"]["input"], "test_input")
        self.assertEqual(response["id"], 1)


if __name__ == '__main__':
    unittest.main()
