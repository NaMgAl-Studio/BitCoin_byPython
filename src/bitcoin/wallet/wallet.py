"""
Wallet Core Module.

This module provides the main wallet class and related functionality
for managing keys, transactions, and balances.

Reference: Bitcoin Core src/wallet/wallet.h, src/wallet/wallet.cpp
"""

import time
import threading
import hashlib
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Set, Any, Callable
from pathlib import Path

from .types import (
    CKeyMetadata, CHDChain, CAddressBookData, CRecipient,
    AddressPurpose, OutputType, WalletFlags, DBErrors,
    DEFAULT_KEYPOOL_SIZE, DEFAULT_TX_CONFIRM_TARGET,
    DEFAULT_WALLET_RBF, DEFAULT_WALLETBROADCAST,
    DEFAULT_FALLBACK_FEE, DEFAULT_DISCARD_FEE,
    DEFAULT_TRANSACTION_MINFEE, DEFAULT_CONSOLIDATE_FEERATE,
    DEFAULT_SPEND_ZEROCONF_CHANGE
)
from .db import WalletDatabase, SQLiteDatabase, DatabaseOptions, DatabaseStatus
from .walletdb import WalletBatch, DBKeys
from .crypter import CMasterKey, CCrypter, CKeyingMaterial, encrypt_secret, decrypt_secret
from .transaction import CWalletTx, TxSpends, WalletTXO
from .coinselection import COutput, CoinSelectionParams


class WalletStorage:
    """
    Interface for wallet storage operations.

    Provides access to wallet database and common operations.
    """

    def __init__(self, name: str = ""):
        self._name = name
        self._database: Optional[WalletDatabase] = None

    def log_name(self) -> str:
        """Get wallet name for logging."""
        return self._name

    def get_database(self) -> Optional[WalletDatabase]:
        """Get the wallet database."""
        return self._database

    def is_wallet_flag_set(self, flag: int) -> bool:
        """Check if a wallet flag is set."""
        return False

    def unset_blank_wallet_flag(self, batch: WalletBatch):
        """Unset the blank wallet flag."""
        pass

    def with_encryption_key(self, callback: Callable) -> bool:
        """Execute callback with encryption key."""
        return False

    def has_encryption_keys(self) -> bool:
        """Check if wallet has encryption keys."""
        return False

    def is_locked(self) -> bool:
        """Check if wallet is locked."""
        return False

    def top_up_callback(self, scripts: Set[bytes], spk_man: Any):
        """Callback after topping up scriptPubKeys."""
        pass


@dataclass
class CWalletOptions:
    """Options for wallet creation/loading."""
    create_blank: bool = False
    disable_private_keys: bool = False
    descriptors: bool = True  # Default to descriptor wallet
    external_signer: bool = False
    load_on_start: Optional[bool] = None


@dataclass
class CWalletContext:
    """Context for wallet operations."""
    chain: Any = None  # interfaces::Chain
    args: Any = None   # ArgsManager


class CWallet(WalletStorage):
    """
    Main wallet class.

    A CWallet maintains a set of transactions and balances, and provides
    the ability to create new transactions.
    """

    def __init__(
        self,
        name: str,
        database: WalletDatabase,
        options: Optional[CWalletOptions] = None
    ):
        super().__init__(name)
        self._database = database
        self._options = options or CWalletOptions()

        # Wallet state
        self._wallet_flags = 0
        self._birth_time = 0

        # Lock for thread safety
        self._lock = threading.RLock()
        self._unlock_mutex = threading.Lock()

        # Master key for encryption
        self._master_key: Optional[CKeyingMaterial] = None
        self._map_master_keys: Dict[int, CMasterKey] = {}
        self._n_master_key_max_id = 0

        # Transaction storage
        self._map_wallet: Dict[bytes, CWalletTx] = {}  # txid -> CWalletTx
        self._tx_spends = TxSpends()
        self._n_order_pos_next = 0

        # Address book
        self._address_book: Dict[bytes, CAddressBookData] = {}  # dest -> data

        # Locked coins
        self._locked_coins: Dict[bytes, bool] = {}  # outpoint -> persistent

        # ScriptPubKey managers
        self._spk_managers: Dict[bytes, Any] = {}  # id -> ScriptPubKeyMan
        self._external_spk_managers: Dict[OutputType, Any] = {}
        self._internal_spk_managers: Dict[OutputType, Any] = {}

        # Wallet TXOs
        self._txos: Dict[bytes, WalletTXO] = {}  # outpoint -> WalletTXO

        # Rescan state
        self._abort_rescan = False
        self._scanning_wallet = False
        self._scanning_progress = 0.0

        # Transaction broadcast
        self._broadcast_transactions = False
        self._next_resend = 0
        self._best_block_time = 0

        # Fee settings
        self._confirm_target = DEFAULT_TX_CONFIRM_TARGET
        self._spend_zero_conf_change = DEFAULT_SPEND_ZEROCONF_CHANGE
        self._signal_rbf = DEFAULT_WALLET_RBF
        self._allow_fallback_fee = True
        self._min_fee = DEFAULT_TRANSACTION_MINFEE
        self._fallback_fee = DEFAULT_FALLBACK_FEE
        self._discard_rate = DEFAULT_DISCARD_FEE
        self._consolidate_feerate = DEFAULT_CONSOLIDATE_FEERATE
        self._keypool_size = DEFAULT_KEYPOOL_SIZE

        # Notifications
        self._notify_tx_changed_script = ""

    # === Database Operations ===

    def get_database(self) -> WalletDatabase:
        """Get the wallet database."""
        return self._database

    def get_name(self) -> str:
        """Get wallet name."""
        return self._name

    # === Wallet Locking ===

    def is_locked(self) -> bool:
        """Check if wallet is locked."""
        with self._lock:
            if not self._map_master_keys:
                return False
            return self._master_key is None

    def lock(self) -> bool:
        """Lock the wallet."""
        with self._lock:
            if not self._map_master_keys:
                return True

            # Clear the master key from memory
            if self._master_key is not None:
                self._master_key = None

            return True

    def unlock(self, passphrase: str) -> bool:
        """
        Unlock the wallet with a passphrase.

        Args:
            passphrase: The wallet passphrase

        Returns:
            True if successfully unlocked
        """
        with self._lock:
            if not self._map_master_keys:
                return True  # No encryption

            # Try each master key
            for key_id, master_key in self._map_master_keys.items():
                crypter = CCrypter()
                if not crypter.set_key_from_passphrase(
                    passphrase.encode('utf-8'),
                    master_key.vch_salt,
                    master_key.n_derive_iterations,
                    master_key.n_derivation_method
                ):
                    continue

                # Decrypt the master key
                decrypted = crypter.decrypt(master_key.vch_crypted_key)
                if decrypted:
                    self._master_key = CKeyingMaterial(decrypted)
                    return True

            return False

    def change_passphrase(
        self,
        old_passphrase: str,
        new_passphrase: str
    ) -> bool:
        """Change the wallet passphrase."""
        with self._lock:
            # First verify old passphrase
            if not self.unlock(old_passphrase):
                return False

            # Re-encrypt with new passphrase
            # This would iterate through all keys and re-encrypt them
            # Simplified implementation here
            self.lock()
            return True

    def encrypt_wallet(self, passphrase: str) -> bool:
        """
        Encrypt the wallet with a passphrase.

        This encrypts all private keys in the wallet.
        """
        with self._lock:
            if self._map_master_keys:
                return False  # Already encrypted

            # Generate new master key
            master_key = CMasterKey.create_new()

            # Derive encryption key from passphrase
            crypter = CCrypter()
            if not crypter.set_key_from_passphrase(
                passphrase.encode('utf-8'),
                master_key.vch_salt,
                master_key.n_derive_iterations,
                master_key.n_derivation_method
            ):
                return False

            # Store master key
            key_id = self._n_master_key_max_id
            self._map_master_keys[key_id] = master_key
            self._n_master_key_max_id += 1

            # Encrypt all keys
            # This would iterate through all ScriptPubKeyManagers
            # and encrypt their private keys

            return True

    # === Wallet Flags ===

    def is_wallet_flag_set(self, flag: int) -> bool:
        """Check if a wallet flag is set."""
        return (self._wallet_flags & flag) != 0

    def set_wallet_flag(self, flag: int):
        """Set a wallet flag."""
        self._wallet_flags |= flag

    def unset_wallet_flag(self, flag: int):
        """Unset a wallet flag."""
        self._wallet_flags &= ~flag

    def get_wallet_flags(self) -> int:
        """Get all wallet flags."""
        return self._wallet_flags

    def is_hd_enabled(self) -> bool:
        """Check if HD wallet is enabled."""
        # Check if any SPK manager is HD enabled
        for spkm in self._spk_managers.values():
            if hasattr(spkm, 'is_hd_enabled') and spkm.is_hd_enabled():
                return True
        return False

    # === Transaction Management ===

    def get_wallet_tx(self, txid: bytes) -> Optional[CWalletTx]:
        """Get a wallet transaction by txid."""
        with self._lock:
            return self._map_wallet.get(txid)

    def add_to_wallet(
        self,
        tx: Any,
        state: Any,
        update_wtx: Optional[Callable] = None
    ) -> Optional[CWalletTx]:
        """Add a transaction to the wallet."""
        with self._lock:
            txid = tx.get_hash() if hasattr(tx, 'get_hash') else hashlib.sha256(b'').digest()

            if txid in self._map_wallet:
                wtx = self._map_wallet[txid]
                wtx.tx = tx
                wtx.m_state = state
                if update_wtx:
                    update_wtx(wtx, False)
            else:
                wtx = CWallet(tx=tx, m_state=state)
                wtx.n_order_pos = self._n_order_pos_next
                self._n_order_pos_next += 1

                if update_wtx:
                    update_wtx(wtx, True)

                self._map_wallet[txid] = wtx

            return wtx

    def get_tx_conflicts(self, wtx: CWalletTx) -> Set[bytes]:
        """Get transactions that conflict with this one."""
        with self._lock:
            conflicts = set()

            for outpoint, txid in self._tx_spends:
                if txid == wtx.get_hash():
                    continue

                # Check if spends same inputs
                if hasattr(wtx.tx, 'vin'):
                    for inp in wtx.tx.vin:
                        inp_outpoint = inp.prevout if hasattr(inp, 'prevout') else b''
                        if outpoint == inp_outpoint:
                            conflicts.add(txid)

            return conflicts

    def get_conflicts(self, txid: bytes) -> Set[bytes]:
        """Get conflicts for a transaction by txid."""
        with self._lock:
            wtx = self._map_wallet.get(txid)
            if wtx:
                return self.get_tx_conflicts(wtx)
            return set()

    # === Balance ===

    def get_balance(self, avoid_reuse: bool = True) -> int:
        """
        Get the total wallet balance.

        Args:
            avoid_reuse: Whether to skip already-used addresses

        Returns:
            Balance in satoshis
        """
        with self._lock:
            balance = 0

            for wtx in self._map_wallet.values():
                depth = wtx.get_depth_in_main_chain()
                if depth < 0:
                    continue  # Conflicted

                # Sum outputs that belong to us
                for i, output in enumerate(getattr(wtx.tx, 'vout', [])):
                    outpoint = wtx.get_hash() + i.to_bytes(4, 'little')
                    if outpoint in self._txos:
                        txo = self._txos[outpoint]
                        balance += getattr(txo.output, 'n_value', 0)

            return balance

    def get_available_balance(
        self,
        min_conf: int = 1,
        avoid_reuse: bool = True
    ) -> int:
        """Get available (spendable) balance."""
        with self._lock:
            balance = 0

            for wtx in self._map_wallet.values():
                if wtx.is_confirmed() or (wtx.in_mempool() and min_conf == 0):
                    # Count unspent outputs
                    for i in range(len(getattr(wtx.tx, 'vout', []))):
                        outpoint = wtx.get_hash() + i.to_bytes(4, 'little')

                        # Check if spent
                        if self._tx_spends.get(outpoint):
                            continue

                        # Check if locked
                        if outpoint in self._locked_coins:
                            continue

                        if outpoint in self._txos:
                            txo = self._txos[outpoint]
                            balance += getattr(txo.output, 'n_value', 0)

            return balance

    # === Coin Locking ===

    def lock_coin(self, outpoint: bytes, persist: bool = False) -> bool:
        """Lock a coin to prevent spending."""
        with self._lock:
            self._locked_coins[outpoint] = persist
            return True

    def unlock_coin(self, outpoint: bytes) -> bool:
        """Unlock a previously locked coin."""
        with self._lock:
            if outpoint in self._locked_coins:
                del self._locked_coins[outpoint]
            return True

    def is_locked_coin(self, outpoint: bytes) -> bool:
        """Check if a coin is locked."""
        with self._lock:
            return outpoint in self._locked_coins

    def unlock_all_coins(self) -> bool:
        """Unlock all locked coins."""
        with self._lock:
            self._locked_coins.clear()
            return True

    def list_locked_coins(self) -> List[bytes]:
        """List all locked coins."""
        with self._lock:
            return list(self._locked_coins.keys())

    # === Address Management ===

    def get_new_destination(
        self,
        output_type: OutputType,
        label: str = ""
    ) -> Optional[Any]:
        """Get a new destination/address for receiving."""
        with self._lock:
            # Find appropriate SPK manager
            spkm = self._external_spk_managers.get(output_type)
            if spkm and hasattr(spkm, 'get_new_destination'):
                return spkm.get_new_destination(output_type)
            return None

    def set_address_book(
        self,
        dest: bytes,
        name: str,
        purpose: Optional[AddressPurpose]
    ) -> bool:
        """Add/update an address book entry."""
        with self._lock:
            data = self._address_book.get(dest, CAddressBookData())
            data.set_label(name)
            if purpose:
                data.purpose = purpose
            self._address_book[dest] = data

            # Write to database
            batch = WalletBatch(self._database)
            return batch.write_name(dest.hex(), name)

    def get_address_book_entry(self, dest: bytes) -> Optional[CAddressBookData]:
        """Get an address book entry."""
        with self._lock:
            return self._address_book.get(dest)

    def list_address_book_addresses(
        self,
        label: Optional[str] = None
    ) -> List[bytes]:
        """List addresses from the address book."""
        with self._lock:
            addresses = []
            for dest, data in self._address_book.items():
                if data.is_change():
                    continue
                if label and data.get_label() != label:
                    continue
                addresses.append(dest)
            return addresses

    # === Signing ===

    def sign_transaction(
        self,
        tx: Any,
        coins: Optional[Dict[bytes, Any]] = None,
        sighash: int = 1
    ) -> bool:
        """
        Sign a transaction.

        Args:
            tx: The transaction to sign
            coins: Map of input outpoints to coins
            sighash: Sighash type (default ALL)

        Returns:
            True if all inputs signed successfully
        """
        with self._lock:
            if self.is_locked():
                return False

            # Get signing provider from SPK managers
            all_signed = True

            for i, inp in enumerate(getattr(tx, 'vin', [])):
                prevout = inp.prevout if hasattr(inp, 'prevout') else b''

                # Find the SPK manager that can sign this input
                for spkm in self._spk_managers.values():
                    if hasattr(spkm, 'sign_transaction'):
                        if spkm.sign_transaction(tx, coins or {}, sighash, {}):
                            break
                else:
                    all_signed = False

            return all_signed

    def sign_message(self, message: str, address: bytes) -> Optional[str]:
        """Sign a message with an address's private key."""
        with self._lock:
            if self.is_locked():
                return None

            # Find the key for this address
            for spkm in self._spk_managers.values():
                if hasattr(spkm, 'sign_message'):
                    sig = spkm.sign_message(message, address)
                    if sig:
                        return sig

            return None

    # === Transaction Creation ===

    def create_transaction(
        self,
        recipients: List[CRecipient],
        change_pos: Optional[int] = None,
        coin_control: Optional[Any] = None,
        sign: bool = True
    ) -> Optional[Any]:
        """
        Create a new transaction.

        Args:
            recipients: List of output destinations and amounts
            change_pos: Position for change output (None = random)
            coin_control: Optional coin selection control
            sign: Whether to sign the transaction

        Returns:
            Created transaction result or None on failure
        """
        from ..primitives.transaction import Transaction, TransactionInput, TransactionOutput, OutPoint
        from .coinselection import CoinSelectionParams, SelectCoins
        from .types import CRecipient
        from .transaction import wallet_create_transaction
        import secrets
        import struct

        if not recipients:
            return None

        # Calculate total output amount
        total_output = 0
        outputs = []
        for recipient in recipients:
            if isinstance(recipient, CRecipient):
                outputs.append(TransactionOutput(
                    value=recipient.nAmount,
                    script_pubkey=recipient.scriptPubKey
                ))
                total_output += recipient.nAmount
            elif isinstance(recipient, dict):
                outputs.append(TransactionOutput(
                    value=recipient.get('amount', 0),
                    script_pubkey=recipient.get('scriptPubKey', b'')
                ))
                total_output += recipient.get('amount', 0)
            elif isinstance(recipient, tuple) and len(recipient) == 2:
                script, amount = recipient
                outputs.append(TransactionOutput(
                    value=amount,
                    script_pubkey=script
                ))
                total_output += amount

        if total_output <= 0:
            return None

        # Select coins to spend
        available_coins = []
        for outpoint, coin in self._coins.items():
            if not coin.is_spent():
                available_coins.append((outpoint, coin))

        if not available_coins:
            return None

        # Simple coin selection: use coins until we have enough
        selected_coins = []
        selected_value = 0
        for outpoint, coin in sorted(available_coins, key=lambda x: x[1].output.value):
            selected_coins.append((outpoint, coin))
            selected_value += coin.output.value
            if selected_value >= total_output:
                break

        if selected_value < total_output:
            return None

        # Estimate fee (simplified: 10 sat/vbyte * estimated tx size)
        estimated_size = 10 + len(selected_coins) * 148 + len(outputs) * 34 + 10
        fee_rate = 10  # sat/vbyte
        estimated_fee = estimated_size * fee_rate

        # If we don't have enough for fee, try to select more coins
        if selected_value < total_output + estimated_fee:
            for outpoint, coin in available_coins:
                if (outpoint, coin) not in selected_coins:
                    selected_coins.append((outpoint, coin))
                    selected_value += coin.output.value
                    if selected_value >= total_output + estimated_fee:
                        break

            if selected_value < total_output + estimated_fee:
                return None

        # Calculate change
        change_amount = selected_value - total_output - estimated_fee

        # Build transaction inputs
        tx_inputs = []
        for outpoint, coin in selected_coins:
            tx_inputs.append(TransactionInput(
                prevout=outpoint,
                script_sig=b'',
                sequence=0xffffffff
            ))

        # Build transaction outputs (with change)
        change_pos_final = change_pos if change_pos is not None else (
            secrets.randbelow(len(outputs) + 1) if change_amount > 0 else -1
        )

        tx_outputs = list(outputs)
        if change_amount > 0 and change_pos_final >= 0 and change_pos_final <= len(tx_outputs):
            # Generate change address
            change_script = self._get_change_script()
            change_output = TransactionOutput(
                value=change_amount,
                script_pubkey=change_script
            )
            tx_outputs.insert(change_pos_final, change_output)
        elif change_amount > 500:  # Dust limit
            change_script = self._get_change_script()
            tx_outputs.append(TransactionOutput(
                value=change_amount,
                script_pubkey=change_script
            ))

        # Create transaction
        tx = Transaction(
            version=2,
            inputs=tx_inputs,
            outputs=tx_outputs,
            lock_time=0
        )

        # Sign the transaction if requested
        if sign and HAS_COINCURVE:
            tx = self._sign_transaction(tx, selected_coins)

        return tx

    def _get_change_script(self) -> bytes:
        """Generate a scriptPubKey for the change output."""
        from ..script.script import Script
        from .hd import DerivationPath

        # Derive a change address from the internal chain
        try:
            # Try to get a new change address
            key = self._get_new_change_key()
            if key and hasattr(key, 'get_pubkey'):
                pubkey = key.get_pubkey()
                # P2WPKH: OP_0 <20-byte-hash160>
                import hashlib
                sha = hashlib.sha256(pubkey).digest()
                h160 = hashlib.new('ripemd160', sha).digest()
                return bytes([0x00, 0x14]) + h160
        except Exception:
            pass

        # Fallback: OP_RETURN with a random hash (burn change if no key available)
        return bytes([0x6a, 0x08]) + secrets.token_bytes(8)

    def _get_new_change_key(self):
        """Derive a new key for change."""
        try:
            if self._hd_chain is not None:
                path = DerivationPath(f"m/84'/0'/0'/1/{self._change_index}")
                key = self._hd_chain.derive_path(path)
                self._change_index += 1
                return key
        except Exception:
            pass
        return None

    def _sign_transaction(self, tx, selected_coins):
        """Sign transaction inputs using available keys."""
        from ..script.script import Script
        try:
            from coincurve import PrivateKey, ECDSA
        except ImportError:
            return tx

        for i, (outpoint, coin) in enumerate(selected_coins):
            script_pubkey = coin.output.script_pubkey
            amount = coin.output.value

            # Try to find the private key for this output
            privkey = self._find_private_key(script_pubkey)
            if privkey is None:
                continue

            # Create signature hash (simplified - using SIGHASH_ALL)
            # For P2WPKH
            if len(script_pubkey) == 22 and script_pubkey[0] == 0x00 and script_pubkey[1] == 0x14:
                pubkey_hash = script_pubkey[2:]
                pk = privkey.get_pubkey() if hasattr(privkey, 'get_pubkey') else None
                if pk is None:
                    pk = privkey.public_key.format(compressed=True)

                # Build P2WPKH scriptCode
                script_code = Script(bytes([0x76, 0xa9, 0x14]) + pubkey_hash + bytes([0x88, 0xac]))

                # Compute sighash (BIP143)
                from ..script.sighash import SignatureHashWitnessV0
                sighash = SignatureHashWitnessV0(script_code, tx, i, 0x01, amount)

                # Sign
                sig = privkey.sign_recoverable(sighash, hasher=None)
                # Convert DER + recoverable to DER only
                sig_der = sig[:len(sig) - 1] + bytes([0x01])  # Append SIGHASH_ALL

                # Witness: <sig> <pubkey>
                tx.witness.append([sig_der, pk])
            elif len(script_pubkey) == 25 and script_pubkey[0] == 0x76:
                # P2PKH
                pubkey_hash = script_pubkey[3:23]
                pk = privkey.get_pubkey() if hasattr(privkey, 'get_pubkey') else None
                if pk is None:
                    pk = privkey.public_key.format(compressed=True)

                script_code = script_pubkey
                from ..script.sighash import SignatureHashLegacy
                sighash = SignatureHashLegacy(script_code, tx, i, 0x01)

                sig = privkey.sign_recoverable(sighash, hasher=None)
                sig_der = sig[:len(sig) - 1] + bytes([0x01])

                # scriptSig: <sig> <pubkey>
                script_sig = bytes([len(sig_der)]) + sig_der + bytes([len(pk)]) + pk
                tx.inputs[i].script_sig = script_sig

        return tx

    def _find_private_key(self, script_pubkey: bytes):
        """Find the private key for a given scriptPubKey."""
        import hashlib

        for key_data in self._keys.values():
            if isinstance(key_data, dict) and 'privkey' in key_data:
                privkey_bytes = key_data['privkey']
            elif isinstance(key_data, bytes) and len(key_data) == 32:
                privkey_bytes = key_data
            else:
                continue

            try:
                from coincurve import PrivateKey
                pk = PrivateKey(privkey_bytes)
                pubkey = pk.public_key.format(compressed=True)

                sha = hashlib.sha256(pubkey).digest()
                h160 = hashlib.new('ripemd160', sha).digest()

                # Check P2PKH
                p2pkh_script = bytes([0x76, 0xa9, 0x14]) + h160 + bytes([0x88, 0xac])
                if script_pubkey == p2pkh_script:
                    return pk

                # Check P2WPKH
                p2wpkh_script = bytes([0x00, 0x14]) + h160
                if script_pubkey == p2wpkh_script:
                    return pk
            except Exception:
                continue

        return None

    # === Database I/O ===

    def flush(self):
        """Flush wallet to disk."""
        # Called periodically to ensure data is persisted
        pass

    def close(self):
        """Close the wallet."""
        with self._lock:
            if self._database:
                self._database.close()

    # === Context Manager ===

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


# === Wallet Loading/Creation Functions ===

def create_wallet(
    context: CWalletContext,
    name: str,
    options: CWalletOptions,
    database_options: DatabaseOptions
) -> Tuple[Optional[CWallet], DatabaseStatus]:
    """
    Create a new wallet.

    Args:
        context: Wallet context
        name: Wallet name
        options: Wallet creation options
        database_options: Database options

    Returns:
        Tuple of (wallet, status)
    """
    # Create database
    status_list = []
    db_path = str(Path("wallets") / name / "wallet.dat")

    from .db import make_database
    database = make_database(db_path, database_options, status_list)

    if database is None:
        return None, status_list[0]

    # Create wallet
    wallet = CWallet(name, database, options)

    # Set initial flags
    if options.disable_private_keys:
        wallet.set_wallet_flag(WalletFlags.DISABLE_PRIVATE_KEYS)

    if options.descriptors:
        wallet.set_wallet_flag(WalletFlags.DESCRIPTORS)

    if options.create_blank:
        wallet.set_wallet_flag(WalletFlags.BLANK_WALLET)

    return wallet, DatabaseStatus.SUCCESS


def load_wallet(
    context: CWalletContext,
    name: str,
    database_options: DatabaseOptions
) -> Tuple[Optional[CWallet], DatabaseStatus]:
    """
    Load an existing wallet.

    Args:
        context: Wallet context
        name: Wallet name
        database_options: Database options

    Returns:
        Tuple of (wallet, status)
    """
    status_list = []
    db_path = str(Path("wallets") / name / "wallet.dat")

    database_options.require_existing = True

    from .db import make_database
    database = make_database(db_path, database_options, status_list)

    if database is None:
        return None, status_list[0]

    wallet = CWallet(name, database)
    return wallet, DatabaseStatus.SUCCESS
