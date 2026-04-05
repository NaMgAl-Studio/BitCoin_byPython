"""
Wallet Database Module.

This module provides the database abstraction layer for wallet storage,
using SQLite as the backend.

Reference: Bitcoin Core src/wallet/db.h, src/wallet/db.cpp, src/wallet/sqlite.cpp
"""

import sqlite3
import threading
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Tuple, Any, Dict, Iterator
from contextlib import contextmanager

from .types import DatabaseFormat, DatabaseStatus, DatabaseOptions


class DatabaseCursor(ABC):
    """
    Abstract base class for database cursors.
    """

    class Status:
        FAIL = 0
        MORE = 1
        DONE = 2

    @abstractmethod
    def next(self) -> Tuple[int, Optional[bytes], Optional[bytes]]:
        """
        Get next key-value pair from cursor.

        Returns:
            Tuple of (status, key, value)
        """
        pass


class SQLiteCursor(DatabaseCursor):
    """
    SQLite implementation of database cursor.
    """

    def __init__(self, cursor: sqlite3.Cursor, prefix: Optional[bytes] = None):
        self._cursor = cursor
        self._prefix = prefix
        self._done = False
        self._rows: List[Tuple[bytes, bytes]] = []
        self._index = 0
        self._fetch_rows()

    def _fetch_rows(self):
        """Fetch all matching rows."""
        if self._prefix is not None:
            self._cursor.execute(
                "SELECT key, value FROM wallet WHERE key >= ? ORDER BY key",
                (self._prefix,)
            )
        else:
            self._cursor.execute("SELECT key, value FROM wallet ORDER BY key")

        self._rows = [(row[0], row[1]) for row in self._cursor.fetchall()]
        self._done = len(self._rows) == 0

    def next(self) -> Tuple[int, Optional[bytes], Optional[bytes]]:
        """Get next key-value pair."""
        if self._done or self._index >= len(self._rows):
            self._done = True
            return (self.Status.DONE, None, None)

        # Check prefix match if filtering
        if self._prefix is not None:
            key, value = self._rows[self._index]
            if not key.startswith(self._prefix):
                self._done = True
                return (self.Status.DONE, None, None)

        key, value = self._rows[self._index]
        self._index += 1
        return (self.Status.MORE, key, value)


class DatabaseBatch(ABC):
    """
    Abstract base class for database batch operations.
    """

    @abstractmethod
    def read(self, key: bytes) -> Optional[bytes]:
        """Read a value by key."""
        pass

    @abstractmethod
    def write(self, key: bytes, value: bytes, overwrite: bool = True) -> bool:
        """Write a key-value pair."""
        pass

    @abstractmethod
    def erase(self, key: bytes) -> bool:
        """Erase a key-value pair."""
        pass

    @abstractmethod
    def exists(self, key: bytes) -> bool:
        """Check if a key exists."""
        pass

    @abstractmethod
    def close(self):
        """Close the batch."""
        pass

    @abstractmethod
    def get_cursor(self, prefix: Optional[bytes] = None) -> DatabaseCursor:
        """Get a cursor for iterating over keys."""
        pass

    @abstractmethod
    def txn_begin(self) -> bool:
        """Begin a transaction."""
        pass

    @abstractmethod
    def txn_commit(self) -> bool:
        """Commit the current transaction."""
        pass

    @abstractmethod
    def txn_abort(self) -> bool:
        """Abort the current transaction."""
        pass

    @abstractmethod
    def has_active_txn(self) -> bool:
        """Check if there's an active transaction."""
        pass

    @abstractmethod
    def erase_prefix(self, prefix: bytes) -> bool:
        """Erase all keys with the given prefix."""
        pass


class SQLiteBatch(DatabaseBatch):
    """
    SQLite implementation of database batch operations.
    """

    def __init__(self, db_path: str, connection: Optional[sqlite3.Connection] = None):
        self._db_path = db_path
        self._owns_connection = connection is None
        self._conn = connection or sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._in_txn = False
        self._ensure_table()

    def _ensure_table(self):
        """Ensure the wallet table exists."""
        cursor = self._conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS wallet (
                key BLOB PRIMARY KEY,
                value BLOB NOT NULL
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_key ON wallet(key)')
        self._conn.commit()

    def read(self, key: bytes) -> Optional[bytes]:
        """Read a value by key."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT value FROM wallet WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row[0] if row else None

    def write(self, key: bytes, value: bytes, overwrite: bool = True) -> bool:
        """Write a key-value pair."""
        try:
            cursor = self._conn.cursor()
            if overwrite:
                cursor.execute(
                    "INSERT OR REPLACE INTO wallet (key, value) VALUES (?, ?)",
                    (key, value)
                )
            else:
                cursor.execute(
                    "INSERT INTO wallet (key, value) VALUES (?, ?)",
                    (key, value)
                )
            if not self._in_txn:
                self._conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        except Exception:
            return False

    def erase(self, key: bytes) -> bool:
        """Erase a key-value pair."""
        try:
            cursor = self._conn.cursor()
            cursor.execute("DELETE FROM wallet WHERE key = ?", (key,))
            if not self._in_txn:
                self._conn.commit()
            return True
        except Exception:
            return False

    def exists(self, key: bytes) -> bool:
        """Check if a key exists."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT 1 FROM wallet WHERE key = ?", (key,))
        return cursor.fetchone() is not None

    def close(self):
        """Close the connection."""
        if self._owns_connection and self._conn:
            self._conn.close()
            self._conn = None

    def get_cursor(self, prefix: Optional[bytes] = None) -> DatabaseCursor:
        """Get a cursor for iterating over keys."""
        cursor = self._conn.cursor()
        return SQLiteCursor(cursor, prefix)

    def txn_begin(self) -> bool:
        """Begin a transaction."""
        if self._in_txn:
            return False
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            self._in_txn = True
            return True
        except Exception:
            return False

    def txn_commit(self) -> bool:
        """Commit the current transaction."""
        if not self._in_txn:
            return False
        try:
            self._conn.commit()
            self._in_txn = False
            return True
        except Exception:
            return False

    def txn_abort(self) -> bool:
        """Abort the current transaction."""
        if not self._in_txn:
            return False
        try:
            self._conn.rollback()
            self._in_txn = False
            return True
        except Exception:
            return False

    def has_active_txn(self) -> bool:
        """Check if there's an active transaction."""
        return self._in_txn

    def erase_prefix(self, prefix: bytes) -> bool:
        """Erase all keys with the given prefix."""
        try:
            cursor = self._conn.cursor()
            # Use LIKE with hex representation for prefix matching
            cursor.execute(
                "DELETE FROM wallet WHERE key >= ? AND key < ?",
                (prefix, prefix + b'\xff')
            )
            if not self._in_txn:
                self._conn.commit()
            return True
        except Exception:
            return False


class WalletDatabase(ABC):
    """
    Abstract base class for wallet database.
    """

    @abstractmethod
    def open(self):
        """Open the database."""
        pass

    @abstractmethod
    def close(self):
        """Close the database."""
        pass

    @abstractmethod
    def rewrite(self) -> bool:
        """Rewrite the entire database."""
        pass

    @abstractmethod
    def backup(self, dest_path: str) -> bool:
        """Backup the database to a file."""
        pass

    @abstractmethod
    def filename(self) -> str:
        """Return the database filename."""
        pass

    @abstractmethod
    def files(self) -> List[str]:
        """Return all database files."""
        pass

    @abstractmethod
    def format(self) -> DatabaseFormat:
        """Return the database format."""
        pass

    @abstractmethod
    def make_batch(self) -> DatabaseBatch:
        """Create a new batch for database operations."""
        pass


class SQLiteDatabase(WalletDatabase):
    """
    SQLite implementation of wallet database.
    """

    def __init__(self, db_path: str, options: Optional[DatabaseOptions] = None):
        self._db_path = db_path
        self._options = options or DatabaseOptions()
        self._conn: Optional[sqlite3.Connection] = None
        self._refcount = 0
        self._lock = threading.Lock()

    def open(self):
        """Open the database."""
        with self._lock:
            if self._conn is None:
                # Ensure directory exists
                os.makedirs(os.path.dirname(self._db_path) or '.', exist_ok=True)

                self._conn = sqlite3.connect(
                    self._db_path,
                    check_same_thread=False
                )
                self._conn.row_factory = sqlite3.Row

                # Enable WAL mode for better concurrency
                self._conn.execute("PRAGMA journal_mode=WAL")

                # Create table if needed
                self._ensure_table()

            self._refcount += 1

    def close(self):
        """Close the database."""
        with self._lock:
            self._refcount -= 1
            if self._refcount <= 0:
                self._refcount = 0
                if self._conn:
                    self._conn.close()
                    self._conn = None

    def _ensure_table(self):
        """Ensure the wallet table exists."""
        if self._conn:
            cursor = self._conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS wallet (
                    key BLOB PRIMARY KEY,
                    value BLOB NOT NULL
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_key ON wallet(key)')
            self._conn.commit()

    def rewrite(self) -> bool:
        """Rewrite the entire database."""
        try:
            # Create a temporary file
            temp_path = self._db_path + '.tmp'

            # Copy to temp and recreate
            if os.path.exists(self._db_path):
                import shutil
                shutil.copy2(self._db_path, temp_path)

                # Vacuum the database
                if self._conn:
                    self._conn.execute("VACUUM")
                    self._conn.commit()

                os.remove(temp_path)
                return True
            return False
        except Exception:
            return False

    def backup(self, dest_path: str) -> bool:
        """Backup the database to a file."""
        try:
            import shutil
            shutil.copy2(self._db_path, dest_path)
            return True
        except Exception:
            return False

    def filename(self) -> str:
        """Return the database filename."""
        return self._db_path

    def files(self) -> List[str]:
        """Return all database files."""
        files = [self._db_path]
        # SQLite WAL files
        wal_path = self._db_path + '-wal'
        shm_path = self._db_path + '-shm'
        if os.path.exists(wal_path):
            files.append(wal_path)
        if os.path.exists(shm_path):
            files.append(shm_path)
        return files

    def format(self) -> DatabaseFormat:
        """Return the database format."""
        return DatabaseFormat.SQLITE

    def make_batch(self) -> DatabaseBatch:
        """Create a new batch for database operations."""
        if self._conn is None:
            self.open()
        return SQLiteBatch(self._db_path, self._conn)


def is_sqlite_file(path: str) -> bool:
    """Check if a file is a SQLite database."""
    if not os.path.exists(path):
        return False

    try:
        with open(path, 'rb') as f:
            header = f.read(16)
            # SQLite file header starts with "SQLite format 3"
            return header.startswith(b'SQLite format 3')
    except Exception:
        return False


def make_database(
    path: str,
    options: DatabaseOptions,
    status: list
) -> Optional[WalletDatabase]:
    """
    Create or open a wallet database.

    Args:
        path: Path to the database file
        options: Database options
        status: Output list to receive status code

    Returns:
        WalletDatabase instance or None on failure
    """
    # Check path validity
    if not path:
        status.append(DatabaseStatus.FAILED_BAD_PATH)
        return None

    # Check if file exists
    exists = os.path.exists(path)

    if options.require_existing and not exists:
        status.append(DatabaseStatus.FAILED_NOT_FOUND)
        return None

    if options.require_create and exists:
        status.append(DatabaseStatus.FAILED_ALREADY_EXISTS)
        return None

    # Create directory if needed
    dir_path = os.path.dirname(path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)

    try:
        db = SQLiteDatabase(path, options)
        db.open()
        status.append(DatabaseStatus.SUCCESS)
        return db
    except Exception as e:
        status.append(DatabaseStatus.FAILED_CREATE)
        return None


def list_databases(path: str) -> List[Tuple[str, str]]:
    """
    List all wallet databases in a directory.

    Returns:
        List of (path, format) tuples
    """
    databases = []

    if not os.path.isdir(path):
        return databases

    for filename in os.listdir(path):
        filepath = os.path.join(path, filename)

        # Check for SQLite wallet files
        if is_sqlite_file(filepath):
            databases.append((filepath, 'sqlite'))

        # Check for wallet.dat files (legacy BDB, read-only)
        elif filename == 'wallet.dat':
            databases.append((filepath, 'bdb_ro'))

    return databases


@dataclass
class DbTxnListener:
    """Listener for database transaction events."""
    on_commit: Optional[callable] = None
    on_abort: Optional[callable] = None


def run_within_txn(
    database: WalletDatabase,
    process_desc: str,
    func: callable
) -> bool:
    """
    Execute a function within a database transaction.

    Args:
        database: The database to operate on
        process_desc: Description for logging
        func: Function to execute, takes DatabaseBatch as argument

    Returns:
        True if transaction succeeded
    """
    batch = database.make_batch()

    if not batch.txn_begin():
        return False

    try:
        result = func(batch)

        if result:
            batch.txn_commit()
            return True
        else:
            batch.txn_abort()
            return False
    except Exception:
        batch.txn_abort()
        return False
