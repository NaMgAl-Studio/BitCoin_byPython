"""
Unit tests for wallet module.

Tests core wallet functionality including:
- Types and constants
- Encryption/decryption
- Database operations
- HD key derivation
- Coin selection
"""

import os
import sys
import tempfile
import unittest

# Add the source directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from bitcoin.wallet.types import (
    AddressPurpose, OutputType, WalletFlags, DBErrors, DatabaseStatus,
    CKeyMetadata, CHDChain, CAddressBookData, CRecipient,
    TxStateConfirmed, TxStateInMempool, TxStateInactive, TxStateBlockConflicted,
    tx_state_interpret_serialized, purpose_to_string, purpose_from_string,
    DEFAULT_FALLBACK_FEE, DEFAULT_DISCARD_FEE, CHANGE_LOWER, CHANGE_UPPER
)
from bitcoin.wallet.crypter import (
    CCrypter, CMasterKey, CKeyingMaterial, SecureBytes,
    encrypt_secret, decrypt_secret, generate_random_key, generate_random_iv
)
from bitcoin.wallet.db import SQLiteDatabase, SQLiteBatch, DatabaseOptions, is_sqlite_file
from bitcoin.wallet.hd import (
    CExtKey, CExtPubKey, DerivationPath, BIP44Path, BIP49Path, BIP84Path, BIP86Path,
    HARDENED_KEY_START, generate_mnemonic, mnemonic_to_seed, validate_mnemonic,
    key_to_wif, _base58_encode, _base58_decode
)
from bitcoin.wallet.coinselection import (
    COutput, OutputGroup, CoinSelectionParams, CoinEligibilityFilter,
    SelectionResult, SelectionAlgorithm, generate_change_target
)


class TestWalletTypes(unittest.TestCase):
    """Test wallet types and constants."""

    def test_address_purpose(self):
        """Test AddressPurpose enum."""
        self.assertEqual(purpose_to_string(AddressPurpose.RECEIVE), "receive")
        self.assertEqual(purpose_to_string(AddressPurpose.SEND), "send")
        self.assertEqual(purpose_to_string(AddressPurpose.REFUND), "refund")

        self.assertEqual(purpose_from_string("receive"), AddressPurpose.RECEIVE)
        self.assertEqual(purpose_from_string("send"), AddressPurpose.SEND)
        self.assertEqual(purpose_from_string("refund"), AddressPurpose.REFUND)
        self.assertIsNone(purpose_from_string("invalid"))

    def test_wallet_flags(self):
        """Test wallet flags."""
        flags = WalletFlags.AVOID_REUSE | WalletFlags.BLANK_WALLET
        self.assertTrue(WalletFlags.AVOID_REUSE & flags)
        self.assertTrue(WalletFlags.BLANK_WALLET & flags)
        self.assertFalse(WalletFlags.DESCRIPTORS & flags)

    def test_key_metadata(self):
        """Test CKeyMetadata."""
        meta = CKeyMetadata(n_create_time=1234567890)
        self.assertEqual(meta.n_create_time, 1234567890)
        self.assertEqual(meta.n_version, CKeyMetadata.CURRENT_VERSION)
        self.assertEqual(meta.hd_keypath, "")

        meta.set_null()
        self.assertEqual(meta.n_create_time, 0)

    def test_hd_chain(self):
        """Test CHDChain."""
        chain = CHDChain(
            n_external_chain_counter=10,
            n_internal_chain_counter=5,
            seed_id=b'\x01' * 20
        )
        self.assertEqual(chain.n_external_chain_counter, 10)
        self.assertEqual(chain.n_internal_chain_counter, 5)
        self.assertEqual(chain.n_version, CHDChain.CURRENT_VERSION)

    def test_address_book_data(self):
        """Test CAddressBookData."""
        data = CAddressBookData(label="test", purpose=AddressPurpose.RECEIVE)
        self.assertEqual(data.get_label(), "test")
        self.assertFalse(data.is_change())

        change_data = CAddressBookData()
        self.assertTrue(change_data.is_change())
        self.assertEqual(change_data.get_label(), "")

    def test_tx_state(self):
        """Test transaction state."""
        # Confirmed state
        state = TxStateConfirmed(
            confirmed_block_hash=b'\x01' * 32,
            confirmed_block_height=500000,
            position_in_block=10
        )
        self.assertIn("Confirmed", state.to_string())
        self.assertEqual(state.confirmed_block_height, 500000)

        # Mempool state
        mempool_state = TxStateInMempool()
        self.assertEqual(mempool_state.to_string(), "InMempool")

        # Inactive state
        inactive_state = TxStateInactive(abandoned=True)
        self.assertIn("abandoned=1", inactive_state.to_string())

    def test_tx_state_interpret_serialized(self):
        """Test interpreting serialized transaction state."""
        # Null hash + index 0 = Inactive not abandoned
        state = tx_state_interpret_serialized(bytes(32), 0)
        self.assertIsInstance(state, TxStateInactive)
        self.assertFalse(state.abandoned)

        # One hash + index -1 = Inactive abandoned
        state = tx_state_interpret_serialized(b'\xff' * 32, -1)
        self.assertIsInstance(state, TxStateInactive)
        self.assertTrue(state.abandoned)


class TestWalletCrypter(unittest.TestCase):
    """Test wallet encryption."""

    def test_master_key_creation(self):
        """Test master key creation."""
        master_key = CMasterKey.create_new()
        self.assertEqual(len(master_key.vch_salt), 8)
        self.assertEqual(master_key.n_derivation_method, 0)
        self.assertEqual(master_key.n_derive_iterations, CMasterKey.DEFAULT_DERIVE_ITERATIONS)

    def test_master_key_serialization(self):
        """Test master key serialization."""
        master_key = CMasterKey.create_new()
        master_key.vch_crypted_key = b'\x01' * 48

        serialized = master_key.serialize()
        deserialized = CMasterKey.deserialize(serialized)

        self.assertEqual(master_key.vch_salt, deserialized.vch_salt)
        self.assertEqual(master_key.vch_crypted_key, deserialized.vch_crypted_key)

    def test_crypter_key_derivation(self):
        """Test key derivation from passphrase."""
        crypter = CCrypter()
        passphrase = b"test passphrase"
        salt = b'\x01' * 8

        result = crypter.set_key_from_passphrase(passphrase, salt, 25000, 0)
        self.assertTrue(result)

    def test_encryption_decryption(self):
        """Test encrypting and decrypting data."""
        crypter = CCrypter()
        passphrase = b"test passphrase"
        salt = b'\x01' * 8

        # Derive key
        self.assertTrue(crypter.set_key_from_passphrase(passphrase, salt, 25000, 0))

        # Encrypt
        plaintext = b"This is a secret message!"
        ciphertext = crypter.encrypt(plaintext)
        self.assertIsNotNone(ciphertext)
        self.assertNotEqual(plaintext, ciphertext)

        # Decrypt
        decrypted = crypter.decrypt(ciphertext)
        self.assertIsNotNone(decrypted)
        self.assertEqual(plaintext, decrypted)

    def test_encrypt_decrypt_secret(self):
        """Test encrypting and decrypting a secret key."""
        master_key = CKeyingMaterial(generate_random_key())
        secret = b'\x01' * 32  # Private key
        iv = b'\x02' * 32  # IV (hash of public key)

        ciphertext = encrypt_secret(master_key, secret, iv)
        self.assertIsNotNone(ciphertext)

        decrypted = decrypt_secret(master_key, ciphertext, iv)
        self.assertIsNotNone(decrypted)
        self.assertEqual(secret, decrypted)

    def test_secure_bytes(self):
        """Test secure bytes container."""
        data = SecureBytes(b"secret data")
        self.assertEqual(len(data), 11)
        self.assertEqual(bytes(data), b"secret data")


class TestWalletDatabase(unittest.TestCase):
    """Test wallet database operations."""

    def setUp(self):
        """Create a temporary database for testing."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_wallet.dat")

    def tearDown(self):
        """Clean up temporary files."""
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        os.rmdir(self.temp_dir)

    def test_database_creation(self):
        """Test creating a new database."""
        db = SQLiteDatabase(self.db_path)
        db.open()

        self.assertTrue(os.path.exists(self.db_path))
        self.assertEqual(db.filename(), self.db_path)
        self.assertEqual(db.format().name, 'SQLITE')

        db.close()

    def test_database_read_write(self):
        """Test reading and writing to the database."""
        db = SQLiteDatabase(self.db_path)
        db.open()

        batch = db.make_batch()

        # Write data
        key = b"test_key"
        value = b"test_value"
        self.assertTrue(batch.write(key, value))

        # Read data
        read_value = batch.read(key)
        self.assertEqual(read_value, value)

        # Check exists
        self.assertTrue(batch.exists(key))
        self.assertFalse(batch.exists(b"nonexistent"))

        # Erase
        self.assertTrue(batch.erase(key))
        self.assertFalse(batch.exists(key))

        db.close()

    def test_database_transaction(self):
        """Test database transactions."""
        db = SQLiteDatabase(self.db_path)
        db.open()

        batch = db.make_batch()

        # Begin transaction
        self.assertTrue(batch.txn_begin())

        # Write data
        batch.write(b"key1", b"value1")
        batch.write(b"key2", b"value2")

        # Commit
        self.assertTrue(batch.txn_commit())

        # Verify data
        self.assertEqual(batch.read(b"key1"), b"value1")
        self.assertEqual(batch.read(b"key2"), b"value2")

        # Test abort
        batch.txn_begin()
        batch.write(b"key3", b"value3")
        batch.txn_abort()

        self.assertIsNone(batch.read(b"key3"))

        db.close()

    def test_database_cursor(self):
        """Test database cursor iteration."""
        db = SQLiteDatabase(self.db_path)
        db.open()

        batch = db.make_batch()

        # Write multiple entries
        for i in range(5):
            batch.write(f"key{i}".encode(), f"value{i}".encode())

        # Iterate with cursor
        cursor = batch.get_cursor()
        count = 0
        while True:
            status, key, value = cursor.next()
            if status == cursor.Status.DONE:
                break
            count += 1

        self.assertEqual(count, 5)

        db.close()

    def test_is_sqlite_file(self):
        """Test SQLite file detection."""
        # Non-existent file
        self.assertFalse(is_sqlite_file("/nonexistent/file"))

        # Create SQLite file
        db = SQLiteDatabase(self.db_path)
        db.open()
        db.close()

        self.assertTrue(is_sqlite_file(self.db_path))

        # Non-SQLite file
        text_file = os.path.join(self.temp_dir, "test.txt")
        with open(text_file, 'w') as f:
            f.write("Not a SQLite file")
        self.assertFalse(is_sqlite_file(text_file))


class TestHDWallet(unittest.TestCase):
    """Test HD wallet functionality."""

    def test_derivation_path(self):
        """Test derivation path parsing."""
        path = DerivationPath("m/44'/0'/0'/0/0")
        self.assertEqual(len(path.components), 5)
        self.assertEqual(path.components[0], 44 + HARDENED_KEY_START)
        self.assertEqual(path.components[1], HARDENED_KEY_START)
        self.assertEqual(path.components[3], 0)  # Non-hardened

        # Test string conversion
        self.assertEqual(str(path), "m/44'/0'/0'/0/0")

    def test_bip44_path(self):
        """Test BIP44 path helper."""
        external = BIP44Path.external(account=0, index=5)
        self.assertEqual(str(external), "m/44'/0'/0'/0/5")

        internal = BIP44Path.internal(account=0, index=10)
        self.assertEqual(str(internal), "m/44'/0'/0'/1/10")

    def test_bip84_path(self):
        """Test BIP84 path helper."""
        external = BIP84Path.external(account=1, index=0)
        self.assertEqual(str(external), "m/84'/0'/1'/0/0")

    def test_ext_key_from_seed(self):
        """Test master key creation from seed."""
        seed = b'\x01' * 32
        master = CExtKey.from_seed(seed)

        self.assertEqual(master.n_depth, 0)
        self.assertEqual(master.n_child, 0)
        self.assertEqual(len(master.chaincode), 32)
        self.assertEqual(len(master.key), 32)

    def test_ext_key_derivation(self):
        """Test key derivation."""
        seed = b'\x01' * 32
        master = CExtKey.from_seed(seed)

        # Derive child
        child = master.derive(HARDENED_KEY_START + 44)
        self.assertEqual(child.n_depth, 1)
        self.assertEqual(child.n_parent_fingerprint, master.get_fingerprint())

        # Derive path
        path = DerivationPath("m/44'/0'/0'")
        derived = master.derive_path(path)
        self.assertEqual(derived.n_depth, 3)

    def test_ext_key_neuter(self):
        """Test getting extended public key."""
        seed = b'\x01' * 32
        master = CExtKey.from_seed(seed)

        ext_pubkey = master.neuter()
        self.assertEqual(ext_pubkey.n_depth, master.n_depth)
        self.assertEqual(ext_pubkey.chaincode, master.chaincode)
        self.assertEqual(len(ext_pubkey.pubkey), 33)

    def test_mnemonic_generation(self):
        """Test mnemonic generation."""
        mnemonic = generate_mnemonic(128)
        words = mnemonic.split()
        self.assertEqual(len(words), 12)

        # Test 256-bit entropy
        mnemonic = generate_mnemonic(256)
        words = mnemonic.split()
        self.assertEqual(len(words), 24)

    def test_mnemonic_to_seed(self):
        """Test mnemonic to seed conversion."""
        # BIP39 test vector
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        seed = mnemonic_to_seed(mnemonic, "")
        self.assertEqual(len(seed), 64)

        # Test with passphrase
        seed_with_pass = mnemonic_to_seed(mnemonic, "TREZOR")
        self.assertEqual(len(seed_with_pass), 64)
        self.assertNotEqual(seed, seed_with_pass)

    def test_wif_conversion(self):
        """Test WIF conversion."""
        key = b'\x01' * 32

        # Compressed WIF
        wif = key_to_wif(key, compressed=True, testnet=False)
        self.assertTrue(wif.startswith('K') or wif.startswith('L'))

        # Uncompressed WIF
        wif_uncompressed = key_to_wif(key, compressed=False, testnet=False)
        self.assertTrue(wif_uncompressed.startswith('5'))

        # Testnet
        wif_testnet = key_to_wif(key, compressed=True, testnet=True)
        self.assertTrue(wif_testnet.startswith('c'))


class TestCoinSelection(unittest.TestCase):
    """Test coin selection algorithms."""

    def test_coutput(self):
        """Test COutput."""
        output = COutput(
            outpoint=b'\x01' * 36,
            txout=b'\x00' * 8 + b'\x00' * 25,  # Value + script
            depth=6,
            input_bytes=68,
            solvable=True,
            safe=True,
            time=0,
            from_me=True
        )

        # Apply fee
        output.apply_fee(fee_rate=10)
        self.assertEqual(output.get_fee(), 680)  # 68 * 10

    def test_output_group(self):
        """Test OutputGroup."""
        group = OutputGroup()

        output = COutput(
            outpoint=b'\x01' * 36,
            txout=bytes(8) + b'\x00' * 25,
            depth=6,
            input_bytes=68,
            solvable=True,
            safe=True,
            time=0,
            from_me=True
        )
        output.apply_fee(fee_rate=10)

        group.insert(output, ancestors=0, cluster_count=0)

        self.assertEqual(group.depth, 6)
        self.assertTrue(group.from_me)

    def test_selection_result(self):
        """Test SelectionResult."""
        result = SelectionResult(target=10000, algo=SelectionAlgorithm.MANUAL)

        # Create and add output
        output = COutput(
            outpoint=b'\x01' * 36,
            txout=(20000).to_bytes(8, 'little') + b'\x00' * 25,
            depth=6,
            input_bytes=68,
            solvable=True,
            safe=True,
            time=0,
            from_me=True
        )
        output.apply_fee(fee_rate=10)

        group = OutputGroup()
        group.insert(output, 0, 0)

        result.add_input(group)

        self.assertEqual(len(result.selected_inputs), 1)

    def test_change_target_generation(self):
        """Test change target generation."""
        import random
        rng = random.Random(42)  # Deterministic

        target = generate_change_target(100000, 100, rng)
        self.assertGreaterEqual(target, CHANGE_LOWER)
        self.assertLessEqual(target, CHANGE_UPPER + 100)


class TestWalletIntegration(unittest.TestCase):
    """Integration tests for wallet module."""

    def test_wallet_creation_flow(self):
        """Test basic wallet creation flow."""
        # Generate mnemonic
        mnemonic = generate_mnemonic(128)
        self.assertEqual(len(mnemonic.split()), 12)

        # Convert to seed
        seed = mnemonic_to_seed(mnemonic)
        self.assertEqual(len(seed), 64)

        # Create master key
        master_key = CExtKey.from_seed(seed)
        self.assertEqual(master_key.n_depth, 0)

        # Derive account key
        account_path = BIP84Path.account(0)
        account_key = master_key.derive_path(account_path)
        self.assertEqual(account_key.n_depth, 3)

        # Get public key
        ext_pubkey = account_key.neuter()
        self.assertEqual(len(ext_pubkey.pubkey), 33)


if __name__ == '__main__':
    unittest.main()
