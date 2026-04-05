"""
HTTP RPC Server.

This module provides an HTTP server implementation for the JSON-RPC API
with WebSocket support for real-time notifications.

Reference: Bitcoin Core src/httpserver.cpp
"""

import asyncio
import json
import logging
import time
import threading
from dataclasses import dataclass
from typing import Optional, Dict, Any, Callable, List
from concurrent.futures import ThreadPoolExecutor

from aiohttp import web, WSMsgType

from .protocol import HTTPStatusCode, RPCErrorCode
from .request import (
    JSONRPCRequest, JSONRPCError, UniValue,
    jsonrpc_reply_obj, jsonrpc_error
)
from .server import jsonrpc_exec, is_rpc_running, rpc_is_in_warmup
from .auth import (
    RPCAuthenticator, parse_basic_auth, WWW_AUTHENTICATE_HEADER
)

logger = logging.getLogger(__name__)


@dataclass
class HTTPServerConfig:
    """HTTP server configuration."""
    host: str = "127.0.0.1"
    port: int = 8332
    max_request_size: int = 10 * 1024 * 1024  # 10 MB
    timeout: int = 30
    cors_origins: List[str] = None
    
    def __post_init__(self):
        if self.cors_origins is None:
            self.cors_origins = []


class HTTPRequest:
    """
    HTTP Request wrapper.
    
    Provides access to request data and headers.
    """
    
    def __init__(self, aiohttp_request: web.Request):
        self._request = aiohttp_request
        self._body: Optional[bytes] = None
    
    @property
    def method(self) -> str:
        """Get HTTP method."""
        return self._request.method
    
    @property
    def path(self) -> str:
        """Get request path."""
        return self._request.path
    
    @property
    def query(self) -> Dict[str, str]:
        """Get query parameters."""
        return dict(self._request.query)
    
    def get_header(self, name: str) -> Optional[str]:
        """Get a header value."""
        return self._request.headers.get(name.lower())
    
    def get_headers(self) -> Dict[str, str]:
        """Get all headers."""
        return dict(self._request.headers)
    
    async def read_body(self) -> bytes:
        """Read request body."""
        if self._body is None:
            self._body = await self._request.read()
        return self._body
    
    async def read_body_text(self) -> str:
        """Read request body as text."""
        return await self._request.text()
    
    async def read_body_json(self) -> Any:
        """Read request body as JSON."""
        return await self._request.json()


class HTTPResponse:
    """
    HTTP Response builder.
    
    Provides methods to build responses.
    """
    
    def __init__(self):
        self._status = HTTPStatusCode.HTTP_OK
        self._headers: Dict[str, str] = {}
        self._body: bytes = b''
    
    def set_status(self, status: HTTPStatusCode) -> 'HTTPResponse':
        """Set response status."""
        self._status = status
        return self
    
    def set_header(self, name: str, value: str) -> 'HTTPResponse':
        """Set a response header."""
        self._headers[name] = value
        return self
    
    def set_body(self, body: bytes) -> 'HTTPResponse':
        """Set response body."""
        self._body = body
        return self
    
    def set_body_text(self, text: str) -> 'HTTPResponse':
        """Set text response body."""
        self._body = text.encode('utf-8')
        return self
    
    def set_body_json(self, data: Any) -> 'HTTPResponse':
        """Set JSON response body."""
        self._body = json.dumps(data).encode('utf-8')
        self._headers.setdefault('Content-Type', 'application/json')
        return self
    
    def build(self) -> web.Response:
        """Build aiohttp response."""
        return web.Response(
            status=self._status,
            body=self._body,
            headers=self._headers
        )


class HTTPRPCServer:
    """
    HTTP RPC Server.
    
    Provides JSON-RPC over HTTP with authentication.
    """
    
    def __init__(self, config: HTTPServerConfig, authenticator: RPCAuthenticator, context: Any = None):
        self.config = config
        self.authenticator = authenticator
        self.context = context
        self._app: Optional[web.Application] = None
        self._runner: Optional[web.AppRunner] = None
        self._site: Optional[web.TCPSite] = None
        self._running = False
        self._handlers: List[Callable] = []
    
    def register_handler(self, path: str, handler: Callable):
        """Register a custom HTTP handler."""
        self._handlers.append((path, handler))
    
    async def handle_rpc(self, request: web.Request) -> web.Response:
        """Handle JSON-RPC request."""
        # Check method
        if request.method != 'POST':
            return web.Response(
                status=HTTPStatusCode.HTTP_BAD_METHOD,
                text="JSONRPC server handles only POST requests"
            )
        
        # Check authorization
        auth_header = request.headers.get('Authorization', '')
        if not auth_header:
            return web.Response(
                status=HTTPStatusCode.HTTP_UNAUTHORIZED,
                headers={'WWW-Authenticate': WWW_AUTHENTICATE_HEADER}
            )
        
        username = self.authenticator.check_authorization(auth_header)
        if not username:
            # Delay to deter brute forcing
            await asyncio.sleep(0.25)
            return web.Response(
                status=HTTPStatusCode.HTTP_UNAUTHORIZED,
                headers={'WWW-Authenticate': WWW_AUTHENTICATE_HEADER}
            )
        
        # Check if in warmup
        if rpc_is_in_warmup():
            status = ["Service warming up"]
            rpc_is_in_warmup(status)
            error = jsonrpc_error(RPCErrorCode.RPC_IN_WARMUP, status[0])
            response = jsonrpc_reply_obj(None, JSONRPCError(RPCErrorCode.RPC_IN_WARMUP, status[0]), None)
            return web.Response(
                status=HTTPStatusCode.HTTP_SERVICE_UNAVAILABLE,
                content_type='application/json',
                body=json.dumps(response).encode()
            )
        
        try:
            # Read request body
            body = await request.read()
            body_text = body.decode('utf-8')
            
            # Parse JSON
            try:
                val_request = json.loads(body_text)
            except json.JSONDecodeError:
                error = jsonrpc_error(RPCErrorCode.RPC_PARSE_ERROR, "Parse error")
                return web.Response(
                    status=HTTPStatusCode.HTTP_BAD_REQUEST,
                    content_type='application/json',
                    body=json.dumps(error).encode()
                )
            
            # Process request(s)
            if isinstance(val_request, list):
                # Batch request
                responses = []
                for req_data in val_request:
                    try:
                        jreq = JSONRPCRequest()
                        jreq.parse(req_data)
                        jreq.auth_user = username
                        jreq.uri = request.path
                        jreq.context = self.context
                        
                        # Check whitelist
                        if not self.authenticator.is_method_allowed(username, jreq.method):
                            responses.append(jsonrpc_error(
                                RPCErrorCode.RPC_MISC_ERROR,
                                "Method not allowed"
                            ))
                            continue
                        
                        result = jsonrpc_exec(jreq, catch_errors=True)
                        if not jreq.is_notification():
                            responses.append(result)
                    except JSONRPCError as e:
                        responses.append(jsonrpc_reply_obj(None, e, None))
                
                return web.Response(
                    status=HTTPStatusCode.HTTP_OK,
                    content_type='application/json',
                    body=json.dumps(responses).encode()
                )
            
            elif isinstance(val_request, dict):
                # Single request
                jreq = JSONRPCRequest()
                jreq.parse(val_request)
                jreq.auth_user = username
                jreq.uri = request.path
                jreq.context = self.context
                
                # Check whitelist
                if not self.authenticator.is_method_allowed(username, jreq.method):
                    return web.Response(status=HTTPStatusCode.HTTP_FORBIDDEN)
                
                result = jsonrpc_exec(jreq, catch_errors=True)
                
                if jreq.is_notification():
                    return web.Response(status=HTTPStatusCode.HTTP_NO_CONTENT)
                
                return web.Response(
                    status=HTTPStatusCode.HTTP_OK,
                    content_type='application/json',
                    body=json.dumps(result).encode()
                )
            
            else:
                error = jsonrpc_error(RPCErrorCode.RPC_PARSE_ERROR, "Top-level object parse error")
                return web.Response(
                    status=HTTPStatusCode.HTTP_BAD_REQUEST,
                    content_type='application/json',
                    body=json.dumps(error).encode()
                )
        
        except JSONRPCError as e:
            response = jsonrpc_reply_obj(None, e, None)
            return web.Response(
                status=HTTPStatusCode.HTTP_INTERNAL_SERVER_ERROR,
                content_type='application/json',
                body=json.dumps(response).encode()
            )
        
        except Exception as e:
            logger.exception("RPC error")
            error = jsonrpc_error(RPCErrorCode.RPC_MISC_ERROR, str(e))
            return web.Response(
                status=HTTPStatusCode.HTTP_INTERNAL_SERVER_ERROR,
                content_type='application/json',
                body=json.dumps(error).encode()
            )
    
    async def handle_websocket(self, request: web.Request) -> web.WebSocketResponse:
        """Handle WebSocket connection for notifications."""
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                    # Handle WebSocket JSON-RPC
                    # This could be extended for subscriptions
                except json.JSONDecodeError:
                    pass
            elif msg.type == WSMsgType.ERROR:
                logger.error(f"WebSocket error: {ws.exception()}")
        
        return ws
    
    def create_app(self) -> web.Application:
        """Create aiohttp application."""
        app = web.Application()
        
        # Add CORS middleware if configured
        if self.config.cors_origins:
            @web.middleware
            async def cors_middleware(request, handler):
                if request.method == 'OPTIONS':
                    return web.Response(
                        headers={
                            'Access-Control-Allow-Origin': ', '.join(self.config.cors_origins),
                            'Access-Control-Allow-Methods': 'POST, OPTIONS',
                            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                        }
                    )
                response = await handler(request)
                response.headers['Access-Control-Allow-Origin'] = ', '.join(self.config.cors_origins)
                return response
            
            app.middlewares.append(cors_middleware)
        
        # Register routes
        app.router.add_route('POST', '/', self.handle_rpc)
        app.router.add_route('POST', '/wallet/{wallet_name}', self.handle_rpc)
        app.router.add_route('GET', '/ws', self.handle_websocket)
        
        # Register custom handlers
        for path, handler in self._handlers:
            app.router.add_route('*', path, handler)
        
        return app
    
    async def start(self):
        """Start the HTTP server."""
        self._app = self.create_app()
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        
        self._site = web.TCPSite(
            self._runner,
            self.config.host,
            self.config.port
        )
        await self._site.start()
        
        self._running = True
        logger.info(f"HTTP RPC server started on {self.config.host}:{self.config.port}")
    
    async def stop(self):
        """Stop the HTTP server."""
        self._running = False
        
        if self._site:
            await self._site.stop()
            self._site = None
        
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
        
        if self._app:
            await self._app.shutdown()
            await self._app.cleanup()
            self._app = None
        
        logger.info("HTTP RPC server stopped")
    
    def is_running(self) -> bool:
        """Check if server is running."""
        return self._running


def run_server(config: HTTPServerConfig, authenticator: RPCAuthenticator, context: Any = None):
    """
    Run the HTTP RPC server.
    
    Args:
        config: Server configuration
        authenticator: Authentication handler
        context: Application context
    """
    server = HTTPRPCServer(config, authenticator, context)
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        loop.run_until_complete(server.start())
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        loop.run_until_complete(server.stop())
        loop.close()


async def run_server_async(config: HTTPServerConfig, authenticator: RPCAuthenticator, context: Any = None):
    """
    Run the HTTP RPC server asynchronously.
    
    This function runs the server in the current event loop,
    allowing it to be combined with other async tasks.
    
    Args:
        config: Server configuration
        authenticator: Authentication handler
        context: Application context
    """
    server = HTTPRPCServer(config, authenticator, context)
    
    try:
        await server.start()
        # Keep running until cancelled
        while server.is_running():
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass
    finally:
        await server.stop()
