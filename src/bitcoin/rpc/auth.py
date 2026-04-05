"""
RPC Authentication.

This module provides authentication mechanisms for the RPC server
including cookie-based auth and rpcauth configuration.

Reference: Bitcoin Core share/rpcauth/rpcauth.py
"""

import hashlib
import secrets
import hmac
import base64
import os
from dataclasses import dataclass
from typing import Optional, Tuple, List, Dict
from pathlib import Path


def generate_salt(size: int = 16) -> str:
    """Generate a random hex salt."""
    return secrets.token_hex(size)


def password_to_hmac(salt: str, password: str) -> str:
    """
    Convert password to HMAC-SHA256 hash.
    
    Args:
        salt: Hex salt string
        password: Password string
    
    Returns:
        Hex-encoded HMAC hash
    """
    salt_bytes = bytes.fromhex(salt)
    password_bytes = password.encode('utf-8')
    
    h = hmac.new(salt_bytes, password_bytes, hashlib.sha256)
    return h.hexdigest()


def generate_rpcauth(username: str, password: Optional[str] = None) -> Tuple[str, str]:
    """
    Generate an rpcauth configuration line.
    
    Args:
        username: RPC username
        password: Optional password (auto-generated if not provided)
    
    Returns:
        Tuple of (rpcauth_line, generated_password)
    """
    if password is None:
        # Generate a random password
        password = secrets.token_urlsafe(32)
    
    salt = generate_salt(16)
    password_hmac = password_to_hmac(salt, password)
    
    # Format: username:salt$hex_hmac
    rpcauth_line = f"{username}:{salt}${password_hmac}"
    
    return rpcauth_line, password


@dataclass
class RPCAuthEntry:
    """Parsed rpcauth configuration entry."""
    username: str
    salt: str
    password_hmac: str


def parse_rpcauth(line: str) -> Optional[RPCAuthEntry]:
    """
    Parse an rpcauth configuration line.
    
    Args:
        line: rpcauth configuration line
    
    Returns:
        RPCAuthEntry or None if invalid
    """
    try:
        # Format: username:salt$hex_hmac
        if ':' not in line:
            return None
        
        username, rest = line.split(':', 1)
        
        if '$' not in rest:
            return None
        
        salt, password_hmac = rest.split('$', 1)
        
        return RPCAuthEntry(
            username=username,
            salt=salt,
            password_hmac=password_hmac
        )
    except Exception:
        return None


class RPCAuthenticator:
    """
    RPC Authentication Manager.
    
    Handles both cookie-based and rpcauth-based authentication.
    """
    
    def __init__(self):
        self._rpcauth_entries: List[RPCAuthEntry] = []
        self._cookie_user: Optional[str] = None
        self._cookie_password: Optional[str] = None
        self._whitelist: Dict[str, Set[str]] = {}  # user -> set of allowed methods
        self._whitelist_default: bool = True
    
    def load_rpcauth(self, rpcauth_lines: List[str]) -> bool:
        """
        Load rpcauth configuration lines.
        
        Args:
            rpcauth_lines: List of rpcauth configuration strings
        
        Returns:
            True if all entries loaded successfully
        """
        success = True
        
        for line in rpcauth_lines:
            entry = parse_rpcauth(line)
            if entry:
                self._rpcauth_entries.append(entry)
            else:
                success = False
        
        return success
    
    def set_cookie(self, username: str, password: str):
        """Set cookie credentials."""
        self._cookie_user = username
        self._cookie_password = password
    
    def load_whitelist(self, whitelist_lines: List[str]):
        """
        Load RPC whitelist configuration.
        
        Args:
            whitelist_lines: List of whitelist configuration strings
        """
        for line in whitelist_lines:
            if ':' not in line:
                # No methods specified - allow all
                user = line
                self._whitelist[user] = set()  # Empty set = allow all
            else:
                user, methods = line.split(':', 1)
                method_list = set(m.strip() for m in methods.split(','))
                if user in self._whitelist:
                    # Intersect with existing whitelist
                    self._whitelist[user] &= method_list
                else:
                    self._whitelist[user] = method_list
    
    def check_authorization(self, auth_header: str) -> Optional[str]:
        """
        Check HTTP Basic Authorization header.
        
        Args:
            auth_header: Authorization header value
        
        Returns:
            Authenticated username or None if invalid
        """
        if not auth_header:
            return None
        
        # Check for Basic auth
        if not auth_header.startswith('Basic '):
            return None
        
        # Decode Base64
        try:
            encoded = auth_header[6:].strip()
            decoded = base64.b64decode(encoded).decode('utf-8')
        except Exception:
            return None
        
        # Parse username:password
        if ':' not in decoded:
            return None
        
        username, password = decoded.split(':', 1)
        
        # Check cookie credentials
        if self._cookie_user and self._cookie_password:
            if username == self._cookie_user and password == self._cookie_password:
                return username
        
        # Check rpcauth entries
        for entry in self._rpcauth_entries:
            if entry.username == username:
                # Compute HMAC and compare
                expected_hmac = password_to_hmac(entry.salt, password)
                if hmac.compare_digest(expected_hmac, entry.password_hmac):
                    return username
        
        return None
    
    def is_method_allowed(self, username: str, method: str) -> bool:
        """
        Check if a user is allowed to call a method.
        
        Args:
            username: Authenticated username
            method: RPC method name
        
        Returns:
            True if method is allowed
        """
        # If no whitelist, allow all
        if not self._whitelist:
            return True
        
        # If user not in whitelist, use default policy
        if username not in self._whitelist:
            return self._whitelist_default
        
        # If whitelist is empty, allow all
        allowed = self._whitelist[username]
        if not allowed:
            return True
        
        # Check if method is in whitelist
        return method in allowed
    
    @staticmethod
    def timing_safe_compare(a: str, b: str) -> bool:
        """
        Timing-safe string comparison.
        
        Args:
            a: First string
            b: Second string
        
        Returns:
            True if strings are equal
        """
        return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))


def create_auth_cookie(cookie_path: Path) -> Tuple[str, str]:
    """
    Create an authentication cookie file.
    
    Args:
        cookie_path: Path to the cookie file
    
    Returns:
        Tuple of (username, password)
    """
    username = "__cookie__"
    password = secrets.token_urlsafe(32)
    
    cookie_content = f"{username}:{password}"
    
    # Ensure parent directory exists
    cookie_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write cookie
    cookie_path.write_text(cookie_content)
    
    # Set restrictive permissions
    os.chmod(cookie_path, 0o600)
    
    return username, password


def read_auth_cookie(cookie_path: Path) -> Optional[Tuple[str, str]]:
    """
    Read authentication cookie file.
    
    Args:
        cookie_path: Path to the cookie file
    
    Returns:
        Tuple of (username, password) or None if not found
    """
    try:
        content = cookie_path.read_text().strip()
        if ':' in content:
            username, password = content.split(':', 1)
            return username, password
    except Exception:
        pass
    
    return None


def delete_auth_cookie(cookie_path: Path) -> bool:
    """
    Delete authentication cookie file.
    
    Args:
        cookie_path: Path to the cookie file
    
    Returns:
        True if deleted successfully
    """
    try:
        if cookie_path.exists():
            cookie_path.unlink()
        return True
    except Exception:
        return False


# HTTP Authentication Utilities

def parse_basic_auth(auth_header: str) -> Optional[Tuple[str, str]]:
    """
    Parse HTTP Basic Authorization header.
    
    Args:
        auth_header: Authorization header value
    
    Returns:
        Tuple of (username, password) or None if invalid
    """
    if not auth_header or not auth_header.startswith('Basic '):
        return None
    
    try:
        encoded = auth_header[6:].strip()
        decoded = base64.b64decode(encoded).decode('utf-8')
        
        if ':' not in decoded:
            return None
        
        username, password = decoded.split(':', 1)
        return username, password
    except Exception:
        return None


def create_basic_auth(username: str, password: str) -> str:
    """
    Create HTTP Basic Authorization header value.
    
    Args:
        username: Username
        password: Password
    
    Returns:
        Authorization header value
    """
    credentials = f"{username}:{password}"
    encoded = base64.b64encode(credentials.encode('utf-8')).decode('ascii')
    return f"Basic {encoded}"


# WWW-Authenticate header
WWW_AUTHENTICATE_HEADER = 'Basic realm="jsonrpc"'
