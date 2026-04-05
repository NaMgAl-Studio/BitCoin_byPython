"""
Wallet Types and Constants.

This module defines the core types, enumerations, and constants used
throughout the wallet implementation.

Reference: Bitcoin Core src/wallet/types.h
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Any
import time


class AddressPurpose(Enum):
    """
    Address purpose field that has been stored with wallet sending and
    receiving addresses since BIP70 payment protocol support was added.
    """
    RECEIVE = auto()
    SEND = auto()
    REFUND = auto()  # Never set in current code, may be present in older wallets


class OutputType(Enum):
    """Output type enumeration for different address types."""
    LEGACY = auto()         # P2PKH
    P2SH_SEGWIT = auto()    # P2SH-wrapped SegWit
    BECH32 = auto()         # Native SegWit v0
    BECH32M = auto()        # SegWit v1 (Taproot)
    UNKNOWN = auto()


class WalletFlags:
    """
    Wallet flags that control wallet behavior and capabilities.
    """
    # Avoid reusing addresses for better privacy
    AVOID_REUSE = 1 << 0
    # Blank wallet with no keys
    BLANK_WALLET = 1 << 1
    # Key origin metadata is stored
    KEY_ORIGIN_METADATA = 1 << 2
    # Last hardened xpub is cached
    LAST_HARDENED_XPUB_CACHED = 1 << 3
    # Wallet has no private keys
    DISABLE_PRIVATE_KEYS = 1 << 4
    # Descriptor wallet (modern wallet type)
    DESCRIPTORS = 1 << 5
    # External signer wallet
    EXTERNAL_SIGNER = 1 << 6

    @classmethod
    def known_flags(cls) -> int:
        """Return all known wallet flags."""
        return (
            cls.AVOID_REUSE |
            cls.BLANK_WALLET |
            cls.KEY_ORIGIN_METADATA |
            cls.LAST_HARDENED_XPUB_CACHED |
            cls.DISABLE_PRIVATE_KEYS |
            cls.DESCRIPTORS |
            cls.EXTERNAL_SIGNER
        )

    @classmethod
    def mutable_flags(cls) -> int:
        """Return flags that can be changed after wallet creation."""
        return cls.AVOID_REUSE


# Wallet flag to string mapping
WALLET_FLAG_TO_STRING = {
    WalletFlags.AVOID_REUSE: "avoid_reuse",
    WalletFlags.BLANK_WALLET: "blank",
    WalletFlags.KEY_ORIGIN_METADATA: "key_origin_metadata",
    WalletFlags.LAST_HARDENED_XPUB_CACHED: "last_hardened_xpub_cached",
    WalletFlags.DISABLE_PRIVATE_KEYS: "disable_private_keys",
    WalletFlags.DESCRIPTORS: "descriptor_wallet",
    WalletFlags.EXTERNAL_SIGNER: "external_signer",
}

STRING_TO_WALLET_FLAG = {v: k for k, v in WALLET_FLAG_TO_STRING.items()}


class DBErrors(Enum):
    """
    Error statuses for the wallet database.
    Values are in order of severity.
    """
    LOAD_OK = 0
    NEED_RESCAN = 1
    EXTERNAL_SIGNER_SUPPORT_REQUIRED = 3
    NONCRITICAL_ERROR = 4
    TOO_NEW = 5
    UNKNOWN_DESCRIPTOR = 6
    LOAD_FAIL = 7
    UNEXPECTED_LEGACY_ENTRY = 8
    LEGACY_WALLET = 9
    CORRUPT = 10


class DatabaseStatus(Enum):
    """Database operation status codes."""
    SUCCESS = auto()
    FAILED_BAD_PATH = auto()
    FAILED_BAD_FORMAT = auto()
    FAILED_LEGACY_DISABLED = auto()
    FAILED_ALREADY_LOADED = auto()
    FAILED_ALREADY_EXISTS = auto()
    FAILED_NOT_FOUND = auto()
    FAILED_CREATE = auto()
    FAILED_LOAD = auto()
    FAILED_VERIFY = auto()
    FAILED_ENCRYPT = auto()
    FAILED_INVALID_BACKUP_FILE = auto()
    FAILED_NEW_UNNAMED = auto()


class DatabaseFormat(Enum):
    """Supported database formats."""
    SQLITE = auto()
    BERKELEY_RO = auto()


class SelectionAlgorithm(Enum):
    """Coin selection algorithms."""
    BNB = 0          # Branch and Bound
    KNAPSACK = 1     # Knapsack solver
    SRD = 2          # Single Random Draw
    CG = 3           # Coin Grinder
    MANUAL = 4       # Manual selection


def get_algorithm_name(algo: SelectionAlgorithm) -> str:
    """Get the name of a selection algorithm."""
    names = {
        SelectionAlgorithm.BNB: "bnb",
        SelectionAlgorithm.KNAPSACK: "knapsack",
        SelectionAlgorithm.SRD: "srd",
        SelectionAlgorithm.CG: "coin_grinder",
        SelectionAlgorithm.MANUAL: "manual",
    }
    return names.get(algo, "unknown")


# Wallet constants (amounts in satoshis)
DEFAULT_FALLBACK_FEE = 0           # -fallbackfee default
DEFAULT_DISCARD_FEE = 10000        # -discardfee default (0.0001 BTC)
DEFAULT_TRANSACTION_MINFEE = 1000  # -mintxfee default
DEFAULT_CONSOLIDATE_FEERATE = 10000  # 10 sat/vbyte
DEFAULT_MAX_AVOIDPARTIALSPEND_FEE = 0
HIGH_APS_FEE = 10000               # COIN / 10000
WALLET_INCREMENTAL_RELAY_FEE = 5000
DEFAULT_SPEND_ZEROCONF_CHANGE = True
DEFAULT_WALLET_REJECT_LONG_CHAINS = True
DEFAULT_TX_CONFIRM_TARGET = 6
DEFAULT_WALLET_RBF = True
DEFAULT_WALLETBROADCAST = True
DEFAULT_DISABLE_WALLET = False
DEFAULT_WALLETCROSSCHAIN = False
DEFAULT_TRANSACTION_MAXFEE = 10000000  # COIN / 10 = 0.1 BTC
HIGH_TX_FEE_PER_KB = 100000           # COIN / 100 = 0.001 BTC
HIGH_MAX_TX_FEE = 100 * HIGH_TX_FEE_PER_KB
DUMMY_NESTED_P2WPKH_INPUT_SIZE = 91
DEFAULT_ADDRESS_TYPE = OutputType.BECH32
DEFAULT_KEYPOOL_SIZE = 1000

# Change amount bounds
CHANGE_LOWER = 50000    # 0.0005 BTC - lower bound for change
CHANGE_UPPER = 1000000  # 0.01 BTC - upper bound for change


@dataclass
class CRecipient:
    """
    Represents a transaction recipient.
    """
    dest: Any  # CTxDestination
    n_amount: int  # CAmount in satoshis
    f_subtract_fee_from_amount: bool = False


@dataclass
class CKeyMetadata:
    """
    Metadata for a key in the wallet.
    """
    VERSION_BASIC = 1
    VERSION_WITH_HDDATA = 10
    VERSION_WITH_KEY_ORIGIN = 12
    CURRENT_VERSION = VERSION_WITH_KEY_ORIGIN

    n_version: int = CURRENT_VERSION
    n_create_time: int = 0  # 0 means unknown
    hd_keypath: str = ""    # HD/bip32 keypath
    hd_seed_id: bytes = field(default_factory=lambda: bytes(20))  # CKeyID (20 bytes)
    key_origin: Optional[bytes] = None  # KeyOriginInfo
    has_key_origin: bool = False

    def __post_init__(self):
        if self.key_origin is None:
            self.key_origin = b''

    def set_null(self):
        """Reset to default values."""
        self.n_version = self.CURRENT_VERSION
        self.n_create_time = 0
        self.hd_keypath = ""
        self.hd_seed_id = bytes(20)
        self.key_origin = b''
        self.has_key_origin = False


@dataclass
class CHDChain:
    """
    Simple HD chain data model for legacy wallets.
    """
    VERSION_HD_BASE = 1
    VERSION_HD_CHAIN_SPLIT = 2
    CURRENT_VERSION = VERSION_HD_CHAIN_SPLIT

    n_version: int = CURRENT_VERSION
    n_external_chain_counter: int = 0
    n_internal_chain_counter: int = 0
    seed_id: bytes = field(default_factory=lambda: bytes(20))  # CKeyID
    m_next_external_index: int = 0  # Memory only
    m_next_internal_index: int = 0  # Memory only

    def set_null(self):
        """Reset to default values."""
        self.n_version = self.CURRENT_VERSION
        self.n_external_chain_counter = 0
        self.n_internal_chain_counter = 0
        self.seed_id = bytes(20)

    def __eq__(self, other):
        if not isinstance(other, CHDChain):
            return False
        return self.seed_id == other.seed_id


@dataclass
class WalletTxState:
    """
    Base class for transaction states.
    """
    pass


@dataclass
class TxStateConfirmed(WalletTxState):
    """State of transaction confirmed in a block."""
    confirmed_block_hash: bytes
    confirmed_block_height: int
    position_in_block: int

    def to_string(self) -> str:
        return f"Confirmed (block={self.confirmed_block_hash.hex()}, height={self.confirmed_block_height}, index={self.position_in_block})"


@dataclass
class TxStateInMempool(WalletTxState):
    """State of transaction added to mempool."""
    def to_string(self) -> str:
        return "InMempool"


@dataclass
class TxStateBlockConflicted(WalletTxState):
    """State of rejected transaction that conflicts with a confirmed block."""
    conflicting_block_hash: bytes
    conflicting_block_height: int

    def to_string(self) -> str:
        return f"BlockConflicted (block={self.conflicting_block_hash.hex()}, height={self.conflicting_block_height})"


@dataclass
class TxStateInactive(WalletTxState):
    """
    State of transaction not confirmed or conflicting with a known block
    and not in the mempool.
    """
    abandoned: bool = False

    def to_string(self) -> str:
        return f"Inactive (abandoned={self.abandoned})"


@dataclass
class TxStateUnrecognized(WalletTxState):
    """
    State of transaction loaded in an unrecognized state.
    """
    block_hash: bytes
    index: int

    def to_string(self) -> str:
        return f"Unrecognized (block={self.block_hash.hex()}, index={self.index})"


def tx_state_interpret_serialized(block_hash: bytes, index: int) -> WalletTxState:
    """
    Try to interpret deserialized TxStateUnrecognized data as a recognized state.
    """
    # Null hash (all zeros)
    null_hash = bytes(32)
    # One hash (all ones)
    one_hash = bytes([0xff] * 32)

    if block_hash == null_hash:
        if index == 0:
            return TxStateInactive(abandoned=False)
    elif block_hash == one_hash:
        if index == -1:
            return TxStateInactive(abandoned=True)
    elif index >= 0:
        return TxStateConfirmed(block_hash, -1, index)
    elif index == -1:
        return TxStateBlockConflicted(block_hash, -1)

    return TxStateUnrecognized(block_hash, index)


@dataclass
class CAddressBookData:
    """
    Address book data for storing address metadata.
    """
    # Address label (None for change addresses)
    label: Optional[str] = None
    # Address purpose (receive, send, refund)
    purpose: Optional[AddressPurpose] = None
    # Whether coins with this address have been spent
    previously_spent: bool = False
    # Map of receive requests (request_id -> serialized data)
    receive_requests: dict = field(default_factory=dict)

    def is_change(self) -> bool:
        """Check if this is a change address."""
        return self.label is None

    def get_label(self) -> str:
        """Get the label (empty string if None)."""
        return self.label if self.label else ""

    def set_label(self, name: str):
        """Set the label."""
        self.label = name


def purpose_to_string(purpose: AddressPurpose) -> str:
    """Convert AddressPurpose to string."""
    mapping = {
        AddressPurpose.RECEIVE: "receive",
        AddressPurpose.SEND: "send",
        AddressPurpose.REFUND: "refund",
    }
    return mapping.get(purpose, "unknown")


def purpose_from_string(s: str) -> Optional[AddressPurpose]:
    """Convert string to AddressPurpose."""
    mapping = {
        "receive": AddressPurpose.RECEIVE,
        "send": AddressPurpose.SEND,
        "refund": AddressPurpose.REFUND,
    }
    return mapping.get(s)


@dataclass
class DatabaseOptions:
    """Options for database operations."""
    require_existing: bool = False
    require_create: bool = False
    require_format: Optional[DatabaseFormat] = None
    create_flags: int = 0
    create_passphrase: str = ""
    verify: bool = True
    use_unsafe_sync: bool = False
    use_shared_memory: bool = False
    max_log_mb: int = 100


@dataclass
class CreatedTransactionResult:
    """Result of transaction creation."""
    tx: Any  # CTransactionRef
    fee: int  # CAmount
    fee_calc: Any  # FeeCalculation
    change_pos: Optional[int] = None


@dataclass
class WalletDestination:
    """Destination with optional internal flag."""
    dest: Any  # CTxDestination
    internal: Optional[bool] = None
