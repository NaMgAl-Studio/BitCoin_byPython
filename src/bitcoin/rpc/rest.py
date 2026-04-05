"""
REST API Implementation.

This module provides REST endpoints for blockchain data access.

Reference: Bitcoin Core src/rest.cpp
"""

import json
from enum import Enum
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass

from aiohttp import web


class RESTResponseFormat(Enum):
    """Supported REST response formats."""
    UNDEF = 0
    BINARY = 1
    HEX = 2
    JSON = 3


# Response format suffixes
FORMAT_SUFFIXES = {
    RESTResponseFormat.UNDEF: "",
    RESTResponseFormat.BINARY: "bin",
    RESTResponseFormat.HEX: "hex",
    RESTResponseFormat.JSON: "json",
}

# Maximum UTXOs to query at once
MAX_GETUTXOS_OUTPOINTS = 15

# Maximum headers to return
MAX_REST_HEADERS_RESULTS = 2000


def parse_data_format(uri: str) -> Tuple[str, RESTResponseFormat]:
    """
    Parse the response format from the URI.
    
    Args:
        uri: Request URI
    
    Returns:
        Tuple of (param_without_format, format)
    """
    # Remove query string
    query_pos = uri.find('?')
    if query_pos >= 0:
        param = uri[:query_pos]
    else:
        param = uri
    
    # Find format suffix
    dot_pos = param.rfind('.')
    if dot_pos < 0:
        return param, RESTResponseFormat.UNDEF
    
    suffix = param[dot_pos + 1:]
    
    for fmt, fmt_suffix in FORMAT_SUFFIXES.items():
        if fmt_suffix == suffix:
            return param[:dot_pos], fmt
    
    return param, RESTResponseFormat.UNDEF


def available_data_formats() -> str:
    """Get a string of available format suffixes."""
    formats = []
    for fmt, suffix in FORMAT_SUFFIXES.items():
        if suffix:
            formats.append(f".{suffix}")
    return ", ".join(formats)


def rest_error(request: web.Request, status: int, message: str) -> web.Response:
    """
    Create a REST error response.
    
    Args:
        request: HTTP request
        status: HTTP status code
        message: Error message
    
    Returns:
        HTTP response
    """
    return web.Response(
        status=status,
        content_type='text/plain',
        text=message + "\r\n"
    )


class RESTHandler:
    """
    REST API Handler.
    
    Provides endpoints for accessing blockchain data via REST.
    """
    
    def __init__(self, context: Any = None):
        self.context = context
    
    async def handle_headers(self, request: web.Request) -> web.Response:
        """
        Handle /rest/headers/<hash>.<ext>
        
        Get block headers starting from a given hash.
        """
        param, fmt = parse_data_format(request.path)
        
        # Parse path
        parts = param.split('/')
        if len(parts) < 4:
            return rest_error(request, 400, "Invalid URI format")
        
        # Get count and hash
        if len(parts) == 5:
            # Deprecated: /rest/headers/<count>/<hash>
            count_str = parts[3]
            hash_str = parts[4]
        else:
            # New: /rest/headers/<hash>?count=<count>
            hash_str = parts[3]
            count_str = request.query.get('count', '5')
        
        try:
            count = int(count_str)
            if count < 1 or count > MAX_REST_HEADERS_RESULTS:
                return rest_error(
                    request, 400,
                    f"Header count is invalid or out of range (1-{MAX_REST_HEADERS_RESULTS})"
                )
        except ValueError:
            return rest_error(request, 400, "Invalid count")
        
        # Validate hash
        try:
            block_hash = bytes.fromhex(hash_str)
            if len(block_hash) != 32:
                raise ValueError()
        except ValueError:
            return rest_error(request, 400, f"Invalid hash: {hash_str}")
        
        # Get headers from chain
        headers = []
        # This would normally fetch from the chain
        # For now, return empty response
        
        if fmt == RESTResponseFormat.JSON:
            return web.Response(
                status=200,
                content_type='application/json',
                text=json.dumps(headers) + "\n"
            )
        elif fmt == RESTResponseFormat.HEX:
            return web.Response(
                status=200,
                content_type='text/plain',
                text=""  # Would contain hex-encoded headers
            )
        elif fmt == RESTResponseFormat.BINARY:
            return web.Response(
                status=200,
                content_type='application/octet-stream',
                body=b''  # Would contain binary headers
            )
        else:
            return rest_error(
                request, 404,
                f"Output format not found (available: {available_data_formats()})"
            )
    
    async def handle_block(self, request: web.Request) -> web.Response:
        """
        Handle /rest/block/<hash>.<ext>
        
        Get a complete block.
        """
        param, fmt = parse_data_format(request.path)
        
        parts = param.split('/')
        if len(parts) < 4:
            return rest_error(request, 400, "Invalid URI format")
        
        hash_str = parts[3]
        
        try:
            block_hash = bytes.fromhex(hash_str)
            if len(block_hash) != 32:
                raise ValueError()
        except ValueError:
            return rest_error(request, 400, f"Invalid hash: {hash_str}")
        
        # Get block from storage
        # For now, return placeholder
        
        if fmt == RESTResponseFormat.JSON:
            block_data = {
                "hash": hash_str,
                "confirmations": 0,
                "tx": []
            }
            return web.Response(
                status=200,
                content_type='application/json',
                text=json.dumps(block_data) + "\n"
            )
        elif fmt == RESTResponseFormat.HEX:
            return web.Response(
                status=200,
                content_type='text/plain',
                text=""  # Would contain hex-encoded block
            )
        elif fmt == RESTResponseFormat.BINARY:
            return web.Response(
                status=200,
                content_type='application/octet-stream',
                body=b''  # Would contain binary block
            )
        else:
            return rest_error(
                request, 404,
                f"Output format not found (available: {available_data_formats()})"
            )
    
    async def handle_tx(self, request: web.Request) -> web.Response:
        """
        Handle /rest/tx/<txid>.<ext>
        
        Get a transaction.
        """
        param, fmt = parse_data_format(request.path)
        
        parts = param.split('/')
        if len(parts) < 4:
            return rest_error(request, 400, "Invalid URI format")
        
        txid_str = parts[3]
        
        try:
            txid = bytes.fromhex(txid_str)
            if len(txid) != 32:
                raise ValueError()
        except ValueError:
            return rest_error(request, 400, f"Invalid txid: {txid_str}")
        
        # Get transaction from mempool or disk
        # For now, return placeholder
        
        if fmt == RESTResponseFormat.JSON:
            tx_data = {
                "txid": txid_str,
                "version": 2,
                "vin": [],
                "vout": []
            }
            return web.Response(
                status=200,
                content_type='application/json',
                text=json.dumps(tx_data) + "\n"
            )
        elif fmt == RESTResponseFormat.HEX:
            return web.Response(
                status=200,
                content_type='text/plain',
                text=""
            )
        elif fmt == RESTResponseFormat.BINARY:
            return web.Response(
                status=200,
                content_type='application/octet-stream',
                body=b''
            )
        else:
            return rest_error(
                request, 404,
                f"Output format not found (available: {available_data_formats()})"
            )
    
    async def handle_chaininfo(self, request: web.Request) -> web.Response:
        """
        Handle /rest/chaininfo.json

        Get blockchain information.
        """
        param, fmt = parse_data_format(request.path)

        if fmt != RESTResponseFormat.JSON:
            return rest_error(request, 404, "Output format not found (available: json)")

        # Try to get data from node instance
        chain = "main"
        blocks = 0
        headers = 0
        bestblockhash = "0" * 64
        difficulty = 0.0
        mediantime = 0
        verificationprogress = 0.0
        chainwork = "0" * 64
        pruned = False

        try:
            from ...node import get_node
            node = get_node()
            if node is not None:
                info = node.getblockchaininfo()
                chain = info.get("chain", "main")
                blocks = info.get("blocks", 0)
                headers = info.get("headers", 0)
                bestblockhash = info.get("bestblockhash", "0" * 64)
                difficulty = info.get("difficulty", 0.0)
                mediantime = info.get("mediantime", 0)
                verificationprogress = info.get("verificationprogress", 0.0)
                chainwork = info.get("chainwork", "0" * 64)
                pruned = info.get("pruned", False)
        except Exception:
            pass

        chain_info = {
            "chain": chain,
            "blocks": blocks,
            "headers": headers,
            "bestblockhash": bestblockhash,
            "difficulty": difficulty,
            "mediantime": mediantime,
            "verificationprogress": verificationprogress,
            "chainwork": chainwork,
            "pruned": pruned
        }

        return web.Response(
            status=200,
            content_type='application/json',
            text=json.dumps(chain_info) + "\n"
        )
    
    async def handle_mempool(self, request: web.Request) -> web.Response:
        """
        Handle /rest/mempool/<info|contents>.json
        
        Get mempool information or contents.
        """
        param, fmt = parse_data_format(request.path)
        
        if fmt != RESTResponseFormat.JSON:
            return rest_error(request, 404, "Output format not found (available: json)")
        
        parts = param.split('/')
        if len(parts) < 4:
            return rest_error(request, 400, "Invalid URI format")
        
        subcommand = parts[3]
        
        if subcommand == "info":
            mempool_info = {
                "loaded": False,
                "size": 0,
                "bytes": 0,
                "usage": 0,
                "maxmempool": 300000000,
                "mempoolminfee": 0.00001000,
                "minrelaytxfee": 0.00001000
            }
            return web.Response(
                status=200,
                content_type='application/json',
                text=json.dumps(mempool_info) + "\n"
            )
        elif subcommand == "contents":
            verbose = request.query.get('verbose', 'true') == 'true'
            mempool = {} if not verbose else []
            return web.Response(
                status=200,
                content_type='application/json',
                text=json.dumps(mempool) + "\n"
            )
        else:
            return rest_error(request, 400, "Invalid URI format. Expected info or contents")
    
    async def handle_utxos(self, request: web.Request) -> web.Response:
        """
        Handle /rest/getutxos/<outpoints>.<ext>

        Get UTXO information.
        """
        param, fmt = parse_data_format(request.path)

        # Parse outpoints from URI or body
        parts = param.split('/')
        
        # Extract outpoints: /rest/getutxos/txid-n/txid-n.json
        outpoints = []
        if len(parts) >= 4:
            for part in parts[3:]:
                if '-' in part:
                    txid_str, n_str = part.rsplit('-', 1)
                    try:
                        n = int(n_str)
                        outpoints.append({
                            "txid": txid_str,
                            "vout": n,
                            "value": 0,
                            "scriptPubKey": "",
                            "confirmations": 0
                        })
                    except (ValueError, IndexError):
                        continue

        # Try to look up from coins database
        bitmap = ""
        try:
            from ...node import get_node
            node = get_node()
            if node is not None and hasattr(node, 'chain_state'):
                # Would query the coins view here
                pass
        except Exception:
            pass

        utxo_response = {
            "chainHeight": 0,
            "chaintipHash": "0" * 64,
            "bitmap": bitmap if bitmap else "",
            "utxos": outpoints
        }

        if fmt == RESTResponseFormat.JSON:
            return web.Response(
                status=200,
                content_type='application/json',
                text=json.dumps(utxo_response) + "\n"
            )
        elif fmt == RESTResponseFormat.HEX:
            return web.Response(
                status=200,
                content_type='text/plain',
                text=""
            )
        elif fmt == RESTResponseFormat.BINARY:
            return web.Response(
                status=200,
                content_type='application/octet-stream',
                body=b''
            )
        else:
            return rest_error(
                request, 404,
                f"Output format not found (available: {available_data_formats()})"
            )
    
    def register_handlers(self, app: web.Application):
        """Register REST handlers with an aiohttp application."""
        # Chain info
        app.router.add_route('GET', '/rest/chaininfo.json', self.handle_chaininfo)
        
        # Headers
        app.router.add_route('GET', '/rest/headers/{tail:.*}', self.handle_headers)
        
        # Block
        app.router.add_route('GET', '/rest/block/{tail:.*}', self.handle_block)
        app.router.add_route('GET', '/rest/block/notxdetails/{tail:.*}', self.handle_block)
        
        # Transaction
        app.router.add_route('GET', '/rest/tx/{tail:.*}', self.handle_tx)
        
        # Mempool
        app.router.add_route('GET', '/rest/mempool/{tail:.*}', self.handle_mempool)
        
        # UTXOs
        app.router.add_route('GET', '/rest/getutxos/{tail:.*}', self.handle_utxos)
        app.router.add_route('POST', '/rest/getutxos/{tail:.*}', self.handle_utxos)
