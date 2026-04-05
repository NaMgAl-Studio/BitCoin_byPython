"""
RPC Server Implementation.

This module provides the core RPC server functionality including
command registration, dispatch, and execution.

Reference: Bitcoin Core src/rpc/server.h, src/rpc/server.cpp
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Callable, Any, Tuple, Set
from concurrent.futures import ThreadPoolExecutor

from .protocol import RPCErrorCode, JSONRPCVersion
from .request import (
    JSONRPCRequest, JSONRPCError, UniValue, NullUniValue,
    jsonrpc_reply_obj, jsonrpc_error
)


# Warmup state
_warmup_active = True
_warmup_status = "Initializing..."
_rpc_running = False
_rpc_interrupt = False

# Lock for warmup state
_warmup_lock = threading.Lock()

# Executor for async operations
_executor: Optional[ThreadPoolExecutor] = None


def is_rpc_running() -> bool:
    """Check if RPC server is running."""
    return _rpc_running


def rpc_interruption_point():
    """Throw an exception if RPC is interrupted."""
    if _rpc_interrupt:
        raise JSONRPCError(RPCErrorCode.RPC_MISC_ERROR, "RPC interrupted")


def set_rpc_warmup_status(status: str):
    """Set the current warmup status message."""
    global _warmup_status
    with _warmup_lock:
        _warmup_status = status


def set_rpc_warmup_starting():
    """Mark RPC as starting (in warmup)."""
    global _warmup_active
    with _warmup_lock:
        _warmup_active = True


def set_rpc_warmup_finished():
    """Mark RPC warmup as finished."""
    global _warmup_active
    with _warmup_lock:
        _warmup_active = False


def rpc_is_in_warmup(out_status: Optional[List] = None) -> bool:
    """Check if RPC is in warmup state."""
    with _warmup_lock:
        if out_status is not None and len(out_status) > 0:
            out_status[0] = _warmup_status
        return _warmup_active


def start_rpc():
    """Start the RPC server."""
    global _rpc_running, _rpc_interrupt, _executor
    
    _rpc_running = True
    _rpc_interrupt = False
    _executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="rpc")


def interrupt_rpc():
    """Interrupt the RPC server."""
    global _rpc_interrupt
    _rpc_interrupt = True


def stop_rpc():
    """Stop the RPC server."""
    global _rpc_running, _executor
    
    _rpc_running = False
    if _executor:
        _executor.shutdown(wait=False)
        _executor = None


@dataclass
class CRPCCommand:
    """
    RPC Command definition.
    
    Represents a single RPC method with its handler function.
    """
    # Category for grouping related commands
    category: str
    # Method name
    name: str
    # Handler function: (request) -> result
    actor: Callable
    # Parameter names and whether they are named-only
    arg_names: List[Tuple[str, bool]] = field(default_factory=list)
    # Unique identifier for the command
    unique_id: int = 0


class RPCHelpMan:
    """
    RPC Help and Documentation Manager.
    
    Provides automatic help generation and parameter validation
    for RPC methods.
    """
    
    def __init__(
        self,
        name: str,
        description: str = "",
        args: Optional[List] = None,
        results: Optional[List] = None,
        examples: str = ""
    ):
        self.name = name
        self.description = description
        self.args = args or []
        self.results = results or []
        self.examples = examples
    
    def handle_request(self, request: JSONRPCRequest) -> Any:
        """
        Handle an RPC request.
        
        Override this method in subclasses to implement
        actual RPC functionality.
        """
        raise NotImplementedError("Subclasses must implement handle_request")
    
    def get_arg_names(self) -> List[Tuple[str, bool]]:
        """Get list of argument names and named-only flags."""
        return [(arg.get("name", ""), arg.get("named_only", False)) for arg in self.args]
    
    def is_valid_num_args(self, num_args: int) -> bool:
        """Check if the number of arguments is valid."""
        min_args = sum(1 for arg in self.args if not arg.get("optional", False))
        max_args = len(self.args)
        return min_args <= num_args <= max_args
    
    def __str__(self) -> str:
        """Return help string for this RPC method."""
        lines = [f"{self.name}", self.description]
        
        if self.args:
            lines.append("\nArguments:")
            for i, arg in enumerate(self.args):
                name = arg.get("name", f"arg{i}")
                desc = arg.get("description", "")
                optional = arg.get("optional", False)
                lines.append(f"  {i+1}. {name}{'(optional)' if optional else ''}: {desc}")
        
        if self.results:
            lines.append("\nResult:")
            for result in self.results:
                lines.append(f"  {result}")
        
        if self.examples:
            lines.append(f"\nExamples:\n{self.examples}")
        
        return "\n".join(lines)


class CRPCTable:
    """
    RPC Command Dispatch Table.
    
    Manages registration and dispatch of RPC commands.
    """
    
    def __init__(self):
        # Map from method name to list of command handlers
        self._commands: Dict[str, List[CRPCCommand]] = {}
        self._lock = threading.RLock()
    
    def append_command(self, name: str, command: CRPCCommand):
        """
        Register an RPC command.
        
        Args:
            name: Method name
            command: Command definition
        """
        with self._lock:
            if name not in self._commands:
                self._commands[name] = []
            self._commands[name].append(command)
    
    def remove_command(self, name: str, command: CRPCCommand) -> bool:
        """
        Unregister an RPC command.
        
        Args:
            name: Method name
            command: Command to remove
        
        Returns:
            True if command was found and removed
        """
        with self._lock:
            if name in self._commands:
                try:
                    self._commands[name].remove(command)
                    return True
                except ValueError:
                    pass
            return False
    
    def execute(self, request: JSONRPCRequest) -> Any:
        """
        Execute an RPC method.
        
        Args:
            request: The JSON-RPC request
        
        Returns:
            Result of the method call
        
        Raises:
            JSONRPCError on failure
        """
        # Check if in warmup
        if rpc_is_in_warmup():
            status = [_warmup_status]
            rpc_is_in_warmup(status)
            raise JSONRPCError(
                RPCErrorCode.RPC_IN_WARMUP,
                f"Service temporarily unavailable: {status[0]}"
            )
        
        # Check if running
        if not is_rpc_running():
            raise JSONRPCError(
                RPCErrorCode.RPC_MISC_ERROR,
                "RPC server is not running"
            )
        
        method = request.method
        
        with self._lock:
            commands = self._commands.get(method, [])
        
        if not commands:
            raise JSONRPCError(
                RPCErrorCode.RPC_METHOD_NOT_FOUND,
                f"Method not found: {method}"
            )
        
        # Try each handler in order
        last_handler = len(commands) - 1
        for i, command in enumerate(commands):
            try:
                result = command.actor(request)
                return result
            except JSONRPCError:
                # Re-raise JSON-RPC errors
                raise
            except Exception as e:
                if i == last_handler:
                    raise JSONRPCError(
                        RPCErrorCode.RPC_MISC_ERROR,
                        str(e)
                    )
                # Try next handler
                continue
        
        raise JSONRPCError(
            RPCErrorCode.RPC_MISC_ERROR,
            "No handler succeeded"
        )
    
    def help(self, method: Optional[str] = None, help_request: Optional[JSONRPCRequest] = None) -> str:
        """
        Get help text for RPC methods.
        
        Args:
            method: Specific method name (optional)
            help_request: Request context for help generation
        
        Returns:
            Help text string
        """
        if method:
            with self._lock:
                commands = self._commands.get(method, [])
            if commands:
                # Return help for the first registered command
                return str(commands[0])
            return f"Unknown method: {method}"
        else:
            # Return list of all methods
            lines = ["Available RPC methods:"]
            with self._lock:
                for name in sorted(self._commands.keys()):
                    commands = self._commands[name]
                    if commands:
                        category = commands[0].category
                        lines.append(f"  [{category}] {name}")
            return "\n".join(lines)
    
    def list_commands(self) -> List[str]:
        """Get a list of all registered command names."""
        with self._lock:
            return sorted(self._commands.keys())
    
    def dump_arg_map(self, request: JSONRPCRequest) -> Dict:
        """Get argument type map for a method."""
        method = request.method
        with self._lock:
            commands = self._commands.get(method, [])
        
        if not commands:
            return {}
        
        result = {}
        for name, named_only in commands[0].arg_names:
            # Mark which args need type conversion from string
            result[name] = {"needs_conversion": False, "named_only": named_only}
        
        return result


# Global RPC table
tableRPC = CRPCTable()


def jsonrpc_exec(jreq: JSONRPCRequest, catch_errors: bool = False) -> Dict:
    """
    Execute a JSON-RPC request and format the response.
    
    Args:
        jreq: The JSON-RPC request
        catch_errors: If True, catch exceptions and return as error response
    
    Returns:
        JSON-RPC response dictionary
    """
    try:
        result = tableRPC.execute(jreq)
        
        # Handle help request
        if jreq.mode == "GET_HELP":
            return jsonrpc_reply_obj(result, None, jreq.id, jreq.json_version)
        
        return jsonrpc_reply_obj(result, None, jreq.id, jreq.json_version)
    
    except JSONRPCError as e:
        if catch_errors:
            return jsonrpc_reply_obj(None, e, jreq.id, jreq.json_version)
        raise
    
    except Exception as e:
        if catch_errors:
            error = JSONRPCError(RPCErrorCode.RPC_MISC_ERROR, str(e))
            return jsonrpc_reply_obj(None, error, jreq.id, jreq.json_version)
        raise


def register_rpc_category(category: str, methods: List[Tuple[str, Callable]]):
    """
    Register multiple RPC methods in a category.
    
    Args:
        category: Category name
        methods: List of (method_name, handler) tuples
    """
    for name, handler in methods:
        command = CRPCCommand(
            category=category,
            name=name,
            actor=handler
        )
        tableRPC.append_command(name, command)


# Decorator for RPC method registration
def rpc_method(category: str, name: Optional[str] = None):
    """
    Decorator to register a function as an RPC method.
    
    Usage:
        @rpc_method("blockchain", "getblockchaininfo")
        def getblockchaininfo(request):
            return {"chain": "main"}
    """
    def decorator(func: Callable):
        method_name = name or func.__name__
        command = CRPCCommand(
            category=category,
            name=method_name,
            actor=func
        )
        tableRPC.append_command(method_name, command)
        return func
    return decorator
