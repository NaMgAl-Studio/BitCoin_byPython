"""
Wallet Database Operations.

This module provides high-level database operations for wallet storage,
including keys, transactions, and other wallet data.

Reference: Bitcoin Core src/wallet/walletdb.h, src/wallet/walletdb.cpp
"""

import struct
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Any, Callable, Tuple

from .db import DatabaseBatch, WalletDatabase, run_within_txn
from .types import (
    DBErrors, CKeyMetadata, CHDChain, AddressPurpose,
    WalletFlags, STRING_TO_WALLET_FLAG, WALLET_FLAG_TO_STRING
)


class DBKeys:
    """Database key prefixes for wallet data."""
    ACENTRY = b'acentry'           # Account entry
    ACTIVEEXTERNALSPK = b'activeexternalspk'
    ACTIVEINTERNALSPK = b'activeinternalspk'
    BESTBLOCK = b'bestblock'
    BESTBLOCK_NOMERKLE = b'bestblock_nomerkle'
    CRYPTED_KEY = b'ckey'
    CSCRIPT = b'cscript'
    DEFAULTKEY = b'defaultkey'
    DESTDATA = b'destdata'
    FLAGS = b'flags'
    HDCHAIN = b'hdchain'
    KEY = b'key'
    KEYMETA = b'keymeta'
    LOCKED_UTXO = b'lockedutxo'
    MASTER_KEY = b'mkey'
    MINVERSION = b'minversion'
    NAME = b'name'
    OLD_KEY = b'old_key'
    ORDERPOSNEXT = b'orderposnext'
    POOL = b'pool'
    PURPOSE = b'purpose'
    SETTINGS = b'settings'
    TX = b'tx'
    VERSION = b'version'
    WALLETDESCRIPTOR = b'walletdescriptor'
    WALLETDESCRIPTORCKEY = b'walletdescriptorckey'
    WALLETDESCRIPTORKEY = b'walletdescriptorkey'
    WATCHMETA = b'watchmeta'
    WATCHS = b'watchs'

    # Keys specific to legacy wallets (removed during migration)
    LEGACY_TYPES = {
        CRYPTED_KEY, KEY, KEYMETA, OLD_KEY, POOL,
        WATCHMETA, WATCHS, DEFAULTKEY, HDCHAIN
    }


@dataclass
class WalletDescriptor:
    """
    Descriptor for a wallet scriptPubKey manager.
    Contains the descriptor and range information.
    """
    descriptor: Any  # Descriptor object
    creation_time: int = 0
    range_start: int = 0
    range_end: int = 0
    next_index: int = 0

    def serialize(self) -> bytes:
        """Serialize the wallet descriptor."""
        # Format: creation_time (8) + range_start (4) + range_end (4) + next_index (4) + descriptor_str
        desc_str = str(self.descriptor) if self.descriptor else ""
        data = struct.pack('<QIII',
                          self.creation_time,
                          self.range_start,
                          self.range_end,
                          self.next_index)
        data += desc_str.encode('utf-8')
        return data

    @classmethod
    def deserialize(cls, data: bytes) -> 'WalletDescriptor':
        """Deserialize a wallet descriptor."""
        creation_time, range_start, range_end, next_index = struct.unpack('<QIII', data[:20])
        desc_str = data[20:].decode('utf-8')
        return cls(
            descriptor=desc_str,  # Will be parsed later
            creation_time=creation_time,
            range_start=range_start,
            range_end=range_end,
            next_index=next_index
        )


class WalletBatch:
    """
    Batch operations for wallet database.

    This class provides high-level operations for reading and writing
    wallet data to the database.
    """

    def __init__(self, database: WalletDatabase):
        self._batch = database.make_batch()
        self._txn_listeners: List[Callable] = []

    def _write_ic(self, key: bytes, value: bytes, overwrite: bool = True) -> bool:
        """Internal write with optional overwrite."""
        return self._batch.write(key, value, overwrite)

    def _erase_ic(self, key: bytes) -> bool:
        """Internal erase."""
        return self._batch.erase(key)

    def write_name(self, address: str, name: str) -> bool:
        """Write an address name/label."""
        key = DBKeys.NAME + address.encode('utf-8')
        return self._write_ic(key, name.encode('utf-8'))

    def erase_name(self, address: str) -> bool:
        """Erase an address name/label."""
        key = DBKeys.NAME + address.encode('utf-8')
        return self._erase_ic(key)

    def write_purpose(self, address: str, purpose: str) -> bool:
        """Write an address purpose."""
        key = DBKeys.PURPOSE + address.encode('utf-8')
        return self._write_ic(key, purpose.encode('utf-8'))

    def erase_purpose(self, address: str) -> bool:
        """Erase an address purpose."""
        key = DBKeys.PURPOSE + address.encode('utf-8')
        return self._erase_ic(key)

    def write_tx(self, tx_data: bytes, tx_hash: bytes) -> bool:
        """Write a transaction."""
        key = DBKeys.TX + tx_hash
        return self._write_ic(key, tx_data)

    def erase_tx(self, tx_hash: bytes) -> bool:
        """Erase a transaction."""
        key = DBKeys.TX + tx_hash
        return self._erase_ic(key)

    def write_key_metadata(self, meta: CKeyMetadata, pubkey: bytes) -> bool:
        """Write key metadata."""
        key = DBKeys.KEYMETA + pubkey
        return self._write_ic(key, self._serialize_key_metadata(meta))

    def _serialize_key_metadata(self, meta: CKeyMetadata) -> bytes:
        """Serialize key metadata."""
        data = bytearray()
        data.extend(struct.pack('<i', meta.n_version))
        data.extend(struct.pack('<q', meta.n_create_time))

        if meta.n_version >= CKeyMetadata.VERSION_WITH_HDDATA:
            data.extend(meta.hd_keypath.encode('utf-8') + b'\x00')
            data.extend(meta.hd_seed_id)

        if meta.n_version >= CKeyMetadata.VERSION_WITH_KEY_ORIGIN:
            data.extend(meta.key_origin or b'')
            data.append(1 if meta.has_key_origin else 0)

        return bytes(data)

    def write_key(self, pubkey: bytes, privkey: bytes, meta: CKeyMetadata) -> bool:
        """Write a key pair with metadata."""
        # Write metadata first
        if not self.write_key_metadata(meta, pubkey):
            return False

        # Write key
        key = DBKeys.KEY + pubkey
        return self._write_ic(key, privkey)

    def write_crypted_key(
        self,
        pubkey: bytes,
        crypted_secret: bytes,
        meta: CKeyMetadata
    ) -> bool:
        """Write an encrypted key."""
        # Write metadata first
        if not self.write_key_metadata(meta, pubkey):
            return False

        # Write encrypted key
        key = DBKeys.CRYPTED_KEY + pubkey
        return self._write_ic(key, crypted_secret)

    def write_master_key(self, n_id: int, master_key_data: bytes) -> bool:
        """Write a master encryption key."""
        key = DBKeys.MASTER_KEY + struct.pack('<I', n_id)
        return self._write_ic(key, master_key_data)

    def erase_master_key(self, n_id: int) -> bool:
        """Erase a master encryption key."""
        key = DBKeys.MASTER_KEY + struct.pack('<I', n_id)
        return self._erase_ic(key)

    def write_watch_only(self, script: bytes, meta: CKeyMetadata) -> bool:
        """Write a watch-only script."""
        key = DBKeys.WATCHS + script
        # Write metadata
        meta_key = DBKeys.WATCHMETA + script
        if not self._write_ic(meta_key, self._serialize_key_metadata(meta)):
            return False
        return self._write_ic(key, b'\x01')  # Just a marker

    def erase_watch_only(self, script: bytes) -> bool:
        """Erase a watch-only script."""
        key = DBKeys.WATCHS + script
        meta_key = DBKeys.WATCHMETA + script
        self._erase_ic(meta_key)
        return self._erase_ic(key)

    def write_best_block(self, locator: bytes) -> bool:
        """Write the best block locator."""
        return self._write_ic(DBKeys.BESTBLOCK, locator)

    def read_best_block(self) -> Optional[bytes]:
        """Read the best block locator."""
        return self._batch.read(DBKeys.BESTBLOCK)

    def is_encrypted(self) -> bool:
        """Check if wallet stores encryption keys."""
        cursor = self._batch.get_cursor(DBKeys.MASTER_KEY)
        status, key, value = cursor.next()
        return status == cursor.Status.MORE

    def write_order_pos_next(self, n_order_pos_next: int) -> bool:
        """Write the next order position."""
        return self._write_ic(
            DBKeys.ORDERPOSNEXT,
            struct.pack('<q', n_order_pos_next)
        )

    def write_descriptor_key(
        self,
        desc_id: bytes,
        pubkey: bytes,
        privkey: bytes
    ) -> bool:
        """Write a descriptor key."""
        key = DBKeys.WALLETDESCRIPTORKEY + desc_id + pubkey
        return self._write_ic(key, privkey)

    def write_crypted_descriptor_key(
        self,
        desc_id: bytes,
        pubkey: bytes,
        crypted_secret: bytes
    ) -> bool:
        """Write an encrypted descriptor key."""
        key = DBKeys.WALLETDESCRIPTORCKEY + desc_id + pubkey
        return self._write_ic(key, crypted_secret)

    def write_descriptor(self, desc_id: bytes, descriptor: WalletDescriptor) -> bool:
        """Write a wallet descriptor."""
        key = DBKeys.WALLETDESCRIPTOR + desc_id
        return self._write_ic(key, descriptor.serialize())

    def write_descriptor_derived_cache(
        self,
        xpub: bytes,
        desc_id: bytes,
        key_exp_index: int,
        der_index: int
    ) -> bool:
        """Write descriptor derived cache."""
        # Format: desc_id + key_exp_index + der_index -> xpub
        key = b'dcache' + desc_id + struct.pack('<II', key_exp_index, der_index)
        return self._write_ic(key, xpub)

    def write_descriptor_parent_cache(
        self,
        xpub: bytes,
        desc_id: bytes,
        key_exp_index: int
    ) -> bool:
        """Write descriptor parent cache."""
        key = b'dcachep' + desc_id + struct.pack('<I', key_exp_index)
        return self._write_ic(key, xpub)

    def write_descriptor_last_hardened_cache(
        self,
        xpub: bytes,
        desc_id: bytes,
        key_exp_index: int
    ) -> bool:
        """Write descriptor last hardened cache."""
        key = b'dcachelh' + desc_id + struct.pack('<I', key_exp_index)
        return self._write_ic(key, xpub)

    def write_locked_utxo(self, outpoint: bytes) -> bool:
        """Write a locked UTXO."""
        key = DBKeys.LOCKED_UTXO + outpoint
        return self._write_ic(key, b'\x01')

    def erase_locked_utxo(self, outpoint: bytes) -> bool:
        """Erase a locked UTXO."""
        key = DBKeys.LOCKED_UTXO + outpoint
        return self._erase_ic(key)

    def write_address_previously_spent(self, dest: bytes, spent: bool) -> bool:
        """Write address spent status."""
        key = DBKeys.DESTDATA + dest + b'used'
        return self._write_ic(key, b'\x01' if spent else b'\x00')

    def write_address_receive_request(
        self,
        dest: bytes,
        request_id: str,
        request_data: str
    ) -> bool:
        """Write address receive request."""
        key = DBKeys.DESTDATA + dest + b'rr' + request_id.encode('utf-8')
        return self._write_ic(key, request_data.encode('utf-8'))

    def erase_address_receive_request(self, dest: bytes, request_id: str) -> bool:
        """Erase address receive request."""
        key = DBKeys.DESTDATA + dest + b'rr' + request_id.encode('utf-8')
        return self._erase_ic(key)

    def erase_address_data(self, dest: bytes) -> bool:
        """Erase all address data."""
        prefix = DBKeys.DESTDATA + dest
        return self._batch.erase_prefix(prefix)

    def write_active_script_pub_key_man(
        self,
        output_type: int,
        spk_id: bytes,
        internal: bool
    ) -> bool:
        """Write active scriptPubKey manager."""
        prefix = DBKeys.ACTIVEINTERNALSPK if internal else DBKeys.ACTIVEEXTERNALSPK
        key = prefix + bytes([output_type])
        return self._write_ic(key, spk_id)

    def erase_active_script_pub_key_man(
        self,
        output_type: int,
        internal: bool
    ) -> bool:
        """Erase active scriptPubKey manager."""
        prefix = DBKeys.ACTIVEINTERNALSPK if internal else DBKeys.ACTIVEEXTERNALSPK
        key = prefix + bytes([output_type])
        return self._erase_ic(key)

    def write_wallet_flags(self, flags: int) -> bool:
        """Write wallet flags."""
        return self._write_ic(DBKeys.FLAGS, struct.pack('<Q', flags))

    def write_version(self, version: int) -> bool:
        """Write wallet version."""
        return self._write_ic(DBKeys.VERSION, struct.pack('<i', version))

    def erase_records(self, types: Set[bytes]) -> bool:
        """Erase all records of specified types."""
        for record_type in types:
            if not self._batch.erase_prefix(record_type):
                return False
        return True

    def txn_begin(self) -> bool:
        """Begin a transaction."""
        return self._batch.txn_begin()

    def txn_commit(self) -> bool:
        """Commit current transaction."""
        return self._batch.txn_commit()

    def txn_abort(self) -> bool:
        """Abort current transaction."""
        return self._batch.txn_abort()

    def has_active_txn(self) -> bool:
        """Check if there's an active transaction."""
        return self._batch.has_active_txn()

    def register_txn_listener(self, listener: Callable):
        """Register a transaction listener."""
        self._txn_listeners.append(listener)


def has_legacy_records(batch: DatabaseBatch) -> bool:
    """Check if there are any legacy wallet records."""
    for record_type in DBKeys.LEGACY_TYPES:
        cursor = batch.get_cursor(record_type)
        status, key, value = cursor.next()
        if status == cursor.Status.MORE:
            return True
    return False


# Serialization helpers for wallet data

def serialize_outpoint(tx_hash: bytes, n: int) -> bytes:
    """Serialize a COutPoint."""
    return tx_hash + struct.pack('<I', n)


def deserialize_outpoint(data: bytes) -> Tuple[bytes, int]:
    """Deserialize a COutPoint."""
    tx_hash = data[:32]
    n = struct.unpack('<I', data[32:36])[0]
    return tx_hash, n


def serialize_hd_chain(chain: CHDChain) -> bytes:
    """Serialize an HD chain."""
    data = bytearray()
    data.extend(struct.pack('<i', chain.n_version))
    data.extend(struct.pack('<I', chain.n_external_chain_counter))
    data.extend(chain.seed_id)
    if chain.n_version >= CHDChain.VERSION_HD_CHAIN_SPLIT:
        data.extend(struct.pack('<I', chain.n_internal_chain_counter))
    return bytes(data)


def deserialize_hd_chain(data: bytes) -> CHDChain:
    """Deserialize an HD chain."""
    offset = 0
    n_version = struct.unpack('<i', data[offset:offset+4])[0]
    offset += 4
    n_external_chain_counter = struct.unpack('<I', data[offset:offset+4])[0]
    offset += 4
    seed_id = data[offset:offset+20]
    offset += 20

    n_internal_chain_counter = 0
    if n_version >= CHDChain.VERSION_HD_CHAIN_SPLIT and offset + 4 <= len(data):
        n_internal_chain_counter = struct.unpack('<I', data[offset:offset+4])[0]

    return CHDChain(
        n_version=n_version,
        n_external_chain_counter=n_external_chain_counter,
        n_internal_chain_counter=n_internal_chain_counter,
        seed_id=seed_id
    )
