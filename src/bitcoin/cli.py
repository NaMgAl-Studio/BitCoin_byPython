#!/usr/bin/env python3
"""
Bitcoin CLI - Command Line Interface for Bitcoin RPC.

This module provides a command-line interface for interacting with
a Bitcoin JSON-RPC server, similar to bitcoin-cli.

Usage:
    bitcoin-cli-py [options] <command> [params]
    
Examples:
    bitcoin-cli-py getblockchaininfo
    bitcoin-cli-py getbalance
    bitcoin-cli-py getnewaddress
    bitcoin-cli-py sendtoaddress <address> <amount>

Reference: Bitcoin Core src/bitcoin-cli.cpp
"""

import argparse
import json
import sys
import os
from typing import List, Any, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bitcoin.rpc.client import RPCClient, RPCClientConfig, RPCClientError


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="bitcoin-cli-py",
        description="Bitcoin Core Python CLI - Command line interface for Bitcoin RPC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s getblockchaininfo          Get blockchain info
  %(prog)s getbalance                 Get wallet balance
  %(prog)s getnewaddress              Generate a new address
  %(prog)s sendtoaddress <addr> <amt> Send bitcoins
  %(prog)s listunspent                List UTXOs
  %(prog)s help                       List available commands

For more information, see: https://github.com/bitcoin/bitcoin
        """
    )
    
    # Connection options
    parser.add_argument(
        "-rpcconnect", "-rpcport", "-rpcuser", "-rpcpassword",
        dest="legacy", action="store_true", help=argparse.SUPPRESS
    )
    
    parser.add_argument(
        "--host", "-H",
        default=os.environ.get("BITCOIN_RPC_HOST", "127.0.0.1"),
        help="RPC server host (default: 127.0.0.1)"
    )
    
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=int(os.environ.get("BITCOIN_RPC_PORT", "8332")),
        help="RPC server port (default: 8332)"
    )
    
    parser.add_argument(
        "--user", "-u",
        default=os.environ.get("BITCOIN_RPC_USER", "bitcoin"),
        help="RPC username"
    )
    
    parser.add_argument(
        "--password", "-P",
        default=os.environ.get("BITCOIN_RPC_PASSWORD", "password"),
        help="RPC password"
    )
    
    parser.add_argument(
        "--cookie",
        help="Path to cookie file for authentication"
    )
    
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)"
    )
    
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output in JSON format"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    
    # Command and arguments
    parser.add_argument(
        "command",
        nargs="?",
        default="help",
        help="RPC command to execute"
    )
    
    parser.add_argument(
        "params",
        nargs="*",
        help="Parameters for the RPC command"
    )
    
    return parser


def parse_value(value: str) -> Any:
    """Parse a string value to appropriate type."""
    # Try JSON parse first
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        pass
    
    # Try boolean
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    
    # Try integer
    try:
        return int(value)
    except ValueError:
        pass
    
    # Try float
    try:
        return float(value)
    except ValueError:
        pass
    
    # Return as string
    return value


def format_output(result: Any, json_output: bool = False) -> str:
    """Format the output for display."""
    if result is None:
        return ""
    
    if json_output:
        return json.dumps(result, indent=2)
    
    if isinstance(result, bool):
        return "true" if result else "false"
    
    if isinstance(result, (dict, list)):
        return json.dumps(result, indent=2)
    
    return str(result)


def print_help():
    """Print help information."""
    help_text = """
Bitcoin Core Python CLI v0.1.0

Common Commands:
  getblockchaininfo       Get blockchain status information
  getnetworkinfo          Get network status information
  getwalletinfo           Get wallet status information
  getbalance              Get wallet balance
  getnewaddress           Generate a new receiving address
  listunspent             List unspent transaction outputs
  listtransactions        List recent transactions
  sendtoaddress           Send bitcoins to an address
  getblock                Get block information
  getrawtransaction       Get raw transaction data

Connection:
  --host, -H              RPC server host (default: 127.0.0.1)
  --port, -p              RPC server port (default: 8332)
  --user, -u              RPC username
  --password, -P          RPC password

Examples:
  bitcoin-cli-py getblockchaininfo
  bitcoin-cli-py getbalance
  bitcoin-cli-py --json getwalletinfo
  bitcoin-cli-py sendtoaddress bc1q... 0.1
"""
    print(help_text)


def main():
    """Main entry point for bitcoin-cli-py."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Handle help command
    if args.command == "help":
        print_help()
        return 0
    
    # Create client configuration
    config = RPCClientConfig(
        host=args.host,
        port=args.port,
        user=args.user if not args.cookie else None,
        password=args.password if not args.cookie else None,
        cookie_path=args.cookie,
        timeout=args.timeout
    )
    
    if args.verbose:
        print(f"Connecting to {config.host}:{config.port}...", file=sys.stderr)
    
    # Create client
    client = RPCClient(config)
    
    # Parse parameters
    params = [parse_value(p) for p in args.params]
    
    try:
        # Execute RPC call
        result = client.call(args.command, *params)
        
        # Format and print output
        output = format_output(result, args.json)
        if output:
            print(output)
        
        return 0
    
    except RPCClientError as e:
        print(f"error: {e.message}", file=sys.stderr)
        return 1
    
    except ConnectionRefusedError:
        print(f"error: Could not connect to {config.host}:{config.port}", file=sys.stderr)
        return 1
    
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
