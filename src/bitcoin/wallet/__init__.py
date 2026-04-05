"""
Bitcoin Wallet Module.

This module provides comprehensive wallet functionality including:
- HD wallet support (BIP32/39/44)
- Transaction management
- Coin selection algorithms
- Wallet encryption
- SQLite-based persistence

Key Components:
- wallet: Main wallet class and operations
- crypter: Encryption/decryption for wallet keys
- db: Database abstraction layer
- walletdb: Wallet database operations
- hd: Hierarchical deterministic key derivation
- coinselection: Coin selection algorithms
- transaction: Wallet transaction management
- spend: Transaction creation and signing
- types: Type definitions and constants

Reference: Bitcoin Core src/wallet/
"""

# Types and constants
from .types import (
    # Enums
    AddressPurpose,
    OutputType,
    WalletFlags,
    DBErrors,
    DatabaseStatus,
    DatabaseFormat,
    SelectionAlgorithm,

    # Constants
    DEFAULT_FALLBACK_FEE,
    DEFAULT_DISCARD_FEE,
    DEFAULT_TRANSACTION_MINFEE,
    DEFAULT_CONSOLIDATE_FEERATE,
    DEFAULT_KEYPOOL_SIZE,
    DEFAULT_TX_CONFIRM_TARGET,
    DEFAULT_WALLET_RBF,
    DEFAULT_WALLETBROADCAST,
    CHANGE_LOWER,
    CHANGE_UPPER,

    # Data classes
    CRecipient,
    CKeyMetadata,
    CHDChain,
    CAddressBookData,
    WalletTxState,
    TxStateConfirmed,
    TxStateInMempool,
    TxStateBlockConflicted,
    TxStateInactive,
    TxStateUnrecognized,
    DatabaseOptions,
    CreatedTransactionResult,
    WalletDestination,

    # Helper functions
    purpose_to_string,
    purpose_from_string,
    get_algorithm_name,
    tx_state_interpret_serialized,

    # Flag mappings
    WALLET_FLAG_TO_STRING,
    STRING_TO_WALLET_FLAG,
)

# Crypter
from .crypter import (
    # Constants
    WALLET_CRYPTO_KEY_SIZE,
    WALLET_CRYPTO_SALT_SIZE,
    WALLET_CRYPTO_IV_SIZE,

    # Classes
    SecureBytes,
    CKeyingMaterial,
    CMasterKey,
    CCrypter,

    # Functions
    encrypt_secret,
    decrypt_secret,
    decrypt_key,
    generate_random_key,
    generate_random_iv,
    generate_random_salt,
)

# Database
from .db import (
    # Classes
    DatabaseCursor,
    DatabaseBatch,
    WalletDatabase,
    SQLiteDatabase,
    SQLiteBatch,
    SQLiteCursor,

    # Functions
    is_sqlite_file,
    make_database,
    list_databases,
    run_within_txn,

    # Data classes
    DbTxnListener,
)

# Wallet database operations
from .walletdb import (
    # Constants
    DBKeys,

    # Classes
    WalletBatch,
    WalletDescriptor,

    # Functions
    has_legacy_records,
    serialize_outpoint,
    deserialize_outpoint,
    serialize_hd_chain,
    deserialize_hd_chain,
)

# HD Wallet
from .hd import (
    # Path handling
    DerivationPath,
    BIP44Path,
    BIP49Path,
    BIP84Path,
    BIP86Path,

    # Extended keys
    CExtKey,
    CExtPubKey,

    # Mnemonic
    generate_mnemonic,
    mnemonic_to_seed,
    mnemonic_to_ext_key,
    validate_mnemonic,

    # Key utilities
    key_to_wif,
    wif_to_key,

    # Constants
    HARDENED_KEY_START,
    BIP32_EXTKEY_SIZE,
)

# Coin Selection
from .coinselection import (
    # Data classes
    COutput,
    CoinSelectionParams,
    CoinEligibilityFilter,
    OutputGroup,
    Groups,
    OutputGroupTypeMap,
    SelectionResult,

    # Algorithms
    select_coins_bnb,
    coin_grinder,
    select_coins_srd,
    knapsack_solver,
    generate_change_target,
)

# Transaction
from .transaction import (
    # Classes
    CachableAmount,
    CWalletTx,
    WalletTXO,
    TxSpends,
    WalletTxOrderComparator,

    # Functions
    tx_state_string,
    compute_time_smart,
)

# Spend
from .spend import (
    # Data classes
    CCoinControl,
    CoinsResult,
    CoinFilterParams,

    # Functions
    available_coins,
    calculate_maximum_signed_input_size,
    calculate_maximum_signed_tx_size,
    select_coins,
    create_transaction,
    fund_transaction,
    discourage_fee_sniping,
)

# Wallet
from .wallet import (
    # Classes
    WalletStorage,
    CWalletOptions,
    CWalletContext,
    CWallet,

    # Functions
    create_wallet,
    load_wallet,
)


__all__ = [
    # Types
    'AddressPurpose',
    'OutputType',
    'WalletFlags',
    'DBErrors',
    'DatabaseStatus',
    'DatabaseFormat',
    'SelectionAlgorithm',

    # Constants
    'DEFAULT_FALLBACK_FEE',
    'DEFAULT_DISCARD_FEE',
    'DEFAULT_TRANSACTION_MINFEE',
    'DEFAULT_CONSOLIDATE_FEERATE',
    'DEFAULT_KEYPOOL_SIZE',
    'DEFAULT_TX_CONFIRM_TARGET',
    'DEFAULT_WALLET_RBF',
    'DEFAULT_WALLETBROADCAST',
    'CHANGE_LOWER',
    'CHANGE_UPPER',
    'WALLET_CRYPTO_KEY_SIZE',
    'WALLET_CRYPTO_SALT_SIZE',
    'WALLET_CRYPTO_IV_SIZE',
    'HARDENED_KEY_START',
    'BIP32_EXTKEY_SIZE',

    # Data classes
    'CRecipient',
    'CKeyMetadata',
    'CHDChain',
    'CAddressBookData',
    'WalletTxState',
    'TxStateConfirmed',
    'TxStateInMempool',
    'TxStateBlockConflicted',
    'TxStateInactive',
    'TxStateUnrecognized',
    'DatabaseOptions',
    'CreatedTransactionResult',
    'WalletDestination',
    'SecureBytes',
    'CKeyingMaterial',
    'CMasterKey',
    'CCrypter',
    'DbTxnListener',
    'WalletDescriptor',
    'DerivationPath',
    'CExtKey',
    'CExtPubKey',
    'COutput',
    'CoinSelectionParams',
    'CoinEligibilityFilter',
    'OutputGroup',
    'Groups',
    'OutputGroupTypeMap',
    'SelectionResult',
    'CachableAmount',
    'CWalletTx',
    'WalletTXO',
    'TxSpends',
    'WalletTxOrderComparator',
    'CCoinControl',
    'CoinsResult',
    'CoinFilterParams',
    'WalletStorage',
    'CWalletOptions',
    'CWalletContext',
    'CWallet',

    # Classes
    'DatabaseCursor',
    'DatabaseBatch',
    'WalletDatabase',
    'SQLiteDatabase',
    'SQLiteBatch',
    'SQLiteCursor',
    'WalletBatch',

    # Path helpers
    'BIP44Path',
    'BIP49Path',
    'BIP84Path',
    'BIP86Path',

    # Functions
    'purpose_to_string',
    'purpose_from_string',
    'get_algorithm_name',
    'tx_state_interpret_serialized',
    'encrypt_secret',
    'decrypt_secret',
    'decrypt_key',
    'generate_random_key',
    'generate_random_iv',
    'generate_random_salt',
    'is_sqlite_file',
    'make_database',
    'list_databases',
    'run_within_txn',
    'has_legacy_records',
    'serialize_outpoint',
    'deserialize_outpoint',
    'serialize_hd_chain',
    'deserialize_hd_chain',
    'generate_mnemonic',
    'mnemonic_to_seed',
    'mnemonic_to_ext_key',
    'validate_mnemonic',
    'key_to_wif',
    'wif_to_key',
    'select_coins_bnb',
    'coin_grinder',
    'select_coins_srd',
    'knapsack_solver',
    'generate_change_target',
    'tx_state_string',
    'compute_time_smart',
    'available_coins',
    'calculate_maximum_signed_input_size',
    'calculate_maximum_signed_tx_size',
    'select_coins',
    'create_transaction',
    'fund_transaction',
    'discourage_fee_sniping',
    'create_wallet',
    'load_wallet',

    # Constants
    'DBKeys',
    'WALLET_FLAG_TO_STRING',
    'STRING_TO_WALLET_FLAG',
]
