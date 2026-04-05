"""
Bitcoin RPC/API Module.

This module provides comprehensive JSON-RPC 2.0 and REST API functionality:

- JSON-RPC server with command registration and dispatch
- HTTP RPC server with authentication
- REST API endpoints for blockchain data
- RPC client for connecting to Bitcoin nodes
- Authentication (cookie and rpcauth)
- Help generation and parameter validation

Key Components:
- protocol: HTTP and RPC error codes
- request: JSON-RPC request/response handling
- server: RPC server with command table
- auth: Authentication mechanisms
- httpserver: HTTP server implementation
- rest: REST API endpoints
- client: RPC client for connecting to nodes
- util: Utilities and help generation
- methods_blockchain: Blockchain RPC methods
- methods_wallet: Wallet RPC methods

Reference: Bitcoin Core src/rpc/
"""

# Protocol definitions
from .protocol import (
    HTTPStatusCode,
    RPCErrorCode,
    JSONRPCVersion,
    get_error_description,
    get_http_status_for_error,
)

# Request handling
from .request import (
    JSONRPCRequest,
    JSONRPCError,
    UniValue,
    NullUniValue,
    jsonrpc_request_obj,
    jsonrpc_reply_obj,
    jsonrpc_error,
    jsonrpc_process_batch_reply,
    generate_auth_cookie,
    get_auth_cookie,
    delete_auth_cookie,
    generate_request_id,
)

# Server
from .server import (
    CRPCCommand,
    CRPCTable,
    RPCHelpMan,
    tableRPC,
    is_rpc_running,
    rpc_interruption_point,
    set_rpc_warmup_status,
    set_rpc_warmup_starting,
    set_rpc_warmup_finished,
    rpc_is_in_warmup,
    start_rpc,
    interrupt_rpc,
    stop_rpc,
    jsonrpc_exec,
    register_rpc_category,
    rpc_method,
)

# Authentication
from .auth import (
    RPCAuthenticator,
    RPCAuthEntry,
    generate_salt,
    password_to_hmac,
    generate_rpcauth,
    parse_rpcauth,
    create_auth_cookie,
    read_auth_cookie,
    delete_auth_cookie,
    parse_basic_auth,
    create_basic_auth,
    WWW_AUTHENTICATE_HEADER,
)

# HTTP Server
from .httpserver import (
    HTTPServerConfig,
    HTTPRequest,
    HTTPResponse,
    HTTPRPCServer,
    run_server,
)

# REST API
from .rest import (
    RESTResponseFormat,
    parse_data_format,
    available_data_formats,
    rest_error,
    RESTHandler,
    MAX_GETUTXOS_OUTPOINTS,
    MAX_REST_HEADERS_RESULTS,
)

# Client
from .client import (
    RPCClientConfig,
    RPCClientError,
    RPCClient,
    rpc_connection,
    create_client,
)

# Utilities
from .util import (
    RPCArgType,
    RPCResultType,
    RPCArg,
    RPCArgOptions,
    RPCResult,
    RPCResultOptions,
    RPCResults,
    RPCExamples,
    UNIX_EPOCH_TIME,
    EXAMPLE_ADDRESS,
    help_example_cli,
    help_example_cli_named,
    help_example_rpc,
    help_example_rpc_named,
    amount_from_value,
    parse_hash_v,
    parse_hash_o,
    parse_hex_v,
    parse_hex_o,
    parse_verbosity,
    rpc_type_check_obj,
    value_from_amount,
    get_all_output_types,
)


__all__ = [
    # Protocol
    'HTTPStatusCode',
    'RPCErrorCode',
    'JSONRPCVersion',
    'get_error_description',
    'get_http_status_for_error',
    
    # Request
    'JSONRPCRequest',
    'JSONRPCError',
    'UniValue',
    'NullUniValue',
    'jsonrpc_request_obj',
    'jsonrpc_reply_obj',
    'jsonrpc_error',
    'jsonrpc_process_batch_reply',
    'generate_auth_cookie',
    'get_auth_cookie',
    'delete_auth_cookie',
    'generate_request_id',
    
    # Server
    'CRPCCommand',
    'CRPCTable',
    'RPCHelpMan',
    'tableRPC',
    'is_rpc_running',
    'rpc_interruption_point',
    'set_rpc_warmup_status',
    'set_rpc_warmup_starting',
    'set_rpc_warmup_finished',
    'rpc_is_in_warmup',
    'start_rpc',
    'interrupt_rpc',
    'stop_rpc',
    'jsonrpc_exec',
    'register_rpc_category',
    'rpc_method',
    
    # Auth
    'RPCAuthenticator',
    'RPCAuthEntry',
    'generate_salt',
    'password_to_hmac',
    'generate_rpcauth',
    'parse_rpcauth',
    'create_auth_cookie',
    'read_auth_cookie',
    'delete_auth_cookie',
    'parse_basic_auth',
    'create_basic_auth',
    'WWW_AUTHENTICATE_HEADER',
    
    # HTTP Server
    'HTTPServerConfig',
    'HTTPRequest',
    'HTTPResponse',
    'HTTPRPCServer',
    'run_server',
    
    # REST
    'RESTResponseFormat',
    'parse_data_format',
    'available_data_formats',
    'rest_error',
    'RESTHandler',
    'MAX_GETUTXOS_OUTPOINTS',
    'MAX_REST_HEADERS_RESULTS',
    
    # Client
    'RPCClientConfig',
    'RPCClientError',
    'RPCClient',
    'rpc_connection',
    'create_client',
    
    # Utilities
    'RPCArgType',
    'RPCResultType',
    'RPCArg',
    'RPCArgOptions',
    'RPCResult',
    'RPCResultOptions',
    'RPCResults',
    'RPCExamples',
    'UNIX_EPOCH_TIME',
    'EXAMPLE_ADDRESS',
    'help_example_cli',
    'help_example_cli_named',
    'help_example_rpc',
    'help_example_rpc_named',
    'amount_from_value',
    'parse_hash_v',
    'parse_hash_o',
    'parse_hex_v',
    'parse_hex_o',
    'parse_verbosity',
    'rpc_type_check_obj',
    'value_from_amount',
    'get_all_output_types',
]
