# Copyright (c) 2009-2010 Satoshi Nakamoto
# Copyright (c) 2009-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Bitcoin Consensus Parameters

This module defines consensus parameters that influence chain consensus.
Includes activation heights for various soft forks and PoW parameters.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import IntEnum
import struct

from ..crypto.sha256 import SHA256, Hash256


# ============================================================================
# Constants
# ============================================================================

# Locktime threshold: below this value it is interpreted as block number,
# otherwise as UNIX timestamp (Tue Nov 5 00:53:20 1985 UTC)
LOCKTIME_THRESHOLD = 500000000

# Coinbase transaction maturity (100 blocks)
COINBASE_MATURITY = 100

# Witness scale factor for weight calculation
WITNESS_SCALE_FACTOR = 4

# Maximum block weight in weight units (4,000,000)
MAX_BLOCK_WEIGHT = 4000000

# Maximum block size in bytes (1,000,000 for legacy)
MAX_BLOCK_SERIALIZED_SIZE = 4000000

# Maximum number of sigops per block
MAX_BLOCK_SIGOPS_COST = 80000

# Money range
MAX_MONEY = 21000000 * 100000000  # 21 million BTC in satoshis


# ============================================================================
# Deployment Types
# ============================================================================

class BuriedDeployment(IntEnum):
    """
    Buried deployments are those where the activation height has been
    hardcoded into the client implementation long after the consensus
    change has activated. See BIP 90.
    """
    DEPLOYMENT_HEIGHTINCB = -32768  # BIP34
    DEPLOYMENT_CLTV = -32767        # BIP65
    DEPLOYMENT_DERSIG = -32766      # BIP66
    DEPLOYMENT_CSV = -32765         # BIP68/112/113
    DEPLOYMENT_SEGWIT = -32764      # BIP141/143/147


class DeploymentPos(IntEnum):
    """BIP9 version bits deployments."""
    DEPLOYMENT_TESTDUMMY = 0
    MAX_VERSION_BITS_DEPLOYMENTS = 1


def valid_buried_deployment(dep: int) -> bool:
    """Check if buried deployment value is valid."""
    return BuriedDeployment.DEPLOYMENT_HEIGHTINCB <= dep <= BuriedDeployment.DEPLOYMENT_SEGWIT


def valid_deployment_pos(dep: int) -> bool:
    """Check if deployment position is valid."""
    return 0 <= dep < DeploymentPos.MAX_VERSION_BITS_DEPLOYMENTS


# ============================================================================
# BIP9 Deployment
# ============================================================================

@dataclass
class BIP9Deployment:
    """
    Struct for each individual consensus rule change using BIP9.
    
    Attributes:
        bit: Bit position to select the particular bit in nVersion
        start_time: Start MedianTime for version bits miner confirmation
        timeout: Timeout/expiry MedianTime for the deployment attempt
        min_activation_height: Minimum block height for activation
        period: Period of blocks to check signalling
        threshold: Minimum blocks for miner confirmation
    """
    bit: int = 28
    start_time: int = -2  # NEVER_ACTIVE
    timeout: int = -2     # NEVER_ACTIVE
    min_activation_height: int = 0
    period: int = 2016
    threshold: int = 1916
    
    # Special constants
    NO_TIMEOUT: int = field(default=0x7FFFFFFFFFFFFFFF, init=False)
    ALWAYS_ACTIVE: int = field(default=-1, init=False)
    NEVER_ACTIVE: int = field(default=-2, init=False)


# ============================================================================
# Consensus Params
# ============================================================================

@dataclass
class ConsensusParams:
    """
    Parameters that influence chain consensus.
    
    These are the consensus-critical parameters that define how blocks
    and transactions are validated.
    """
    
    # Genesis block hash
    hash_genesis_block: bytes = field(default_factory=lambda: bytes(32))
    
    # Subsidy halving interval (blocks)
    n_subsidy_halving_interval: int = 210000
    
    # Script verify flag exceptions (blocks known to be valid but fail with default flags)
    script_flag_exceptions: Dict[bytes, int] = field(default_factory=dict)
    
    # BIP34 activation height and hash
    bip34_height: int = 227931
    bip34_hash: bytes = field(default_factory=lambda: bytes(32))
    
    # BIP65 activation height (OP_CHECKLOCKTIMEVERIFY)
    bip65_height: int = 388381
    
    # BIP66 activation height (strict DER signatures)
    bip66_height: int = 363725
    
    # CSV activation height (BIP68/112/113)
    csv_height: int = 419328
    
    # SegWit activation height (BIP141/143/147)
    segwit_height: int = 481824
    
    # Minimum BIP9 warning height
    min_bip9_warning_height: int = 0
    
    # BIP9 deployments
    deployments: List[BIP9Deployment] = field(default_factory=list)
    
    # Proof of work parameters
    pow_limit: bytes = field(default_factory=lambda: bytes(32))
    pow_allow_min_difficulty_blocks: bool = False
    enforce_bip94: bool = False  # Timewarp attack mitigation
    pow_no_retargeting: bool = False
    pow_target_spacing: int = 600  # 10 minutes in seconds
    pow_target_timespan: int = 1209600  # 2 weeks in seconds
    
    # Minimum chain work
    minimum_chain_work: bytes = field(default_factory=lambda: bytes(32))
    
    # Default assume valid
    default_assume_valid: bytes = field(default_factory=lambda: bytes(32))
    
    # Signet parameters
    signet_blocks: bool = False
    signet_challenge: bytes = field(default_factory=bytes)
    
    def pow_target_spacing_seconds(self) -> int:
        """Get PoW target spacing in seconds."""
        return self.pow_target_spacing
    
    def difficulty_adjustment_interval(self) -> int:
        """Get the difficulty adjustment interval in blocks."""
        return self.pow_target_timespan // self.pow_target_spacing
    
    def deployment_height(self, dep: BuriedDeployment) -> int:
        """Get the activation height for a buried deployment."""
        if dep == BuriedDeployment.DEPLOYMENT_HEIGHTINCB:
            return self.bip34_height
        elif dep == BuriedDeployment.DEPLOYMENT_CLTV:
            return self.bip65_height
        elif dep == BuriedDeployment.DEPLOYMENT_DERSIG:
            return self.bip66_height
        elif dep == BuriedDeployment.DEPLOYMENT_CSV:
            return self.csv_height
        elif dep == BuriedDeployment.DEPLOYMENT_SEGWIT:
            return self.segwit_height
        return 0x7FFFFFFF  # Max int for unknown


# ============================================================================
# Chain Types
# ============================================================================

class ChainType(IntEnum):
    """Bitcoin chain types."""
    MAIN = 0
    TESTNET = 1
    TESTNET4 = 2
    SIGNET = 3
    REGTEST = 4


def chain_type_to_string(chain_type: ChainType) -> str:
    """Convert chain type to string."""
    return {
        ChainType.MAIN: "main",
        ChainType.TESTNET: "test",
        ChainType.TESTNET4: "testnet4",
        ChainType.SIGNET: "signet",
        ChainType.REGTEST: "regtest",
    }.get(chain_type, "unknown")


# ============================================================================
# Chain Parameters Factory
# ============================================================================

def create_mainnet_params() -> ConsensusParams:
    """Create consensus parameters for Bitcoin mainnet."""
    params = ConsensusParams()
    
    # Genesis block hash
    params.hash_genesis_block = bytes.fromhex(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    )
    
    # Halving interval
    params.n_subsidy_halving_interval = 210000
    
    # BIP34 activation
    params.bip34_height = 227931
    params.bip34_hash = bytes.fromhex(
        "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"
    )
    
    # BIP66 activation
    params.bip66_height = 363725
    
    # BIP65 activation
    params.bip65_height = 388381
    
    # CSV activation
    params.csv_height = 419328
    
    # SegWit activation
    params.segwit_height = 481824
    
    # PoW limit (maximum target)
    # This is the target corresponding to difficulty 1
    params.pow_limit = bytes.fromhex(
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    
    # PoW parameters
    params.pow_target_spacing = 600  # 10 minutes
    params.pow_target_timespan = 1209600  # 2 weeks
    params.pow_allow_min_difficulty_blocks = False
    params.pow_no_retargeting = False
    
    # Minimum chain work (as of a certain height)
    params.minimum_chain_work = bytes.fromhex(
        "000000000000000000000000000000000000000052b2559403c790ab8aa5b6a3"
    )
    
    # Default assume valid block
    params.default_assume_valid = bytes.fromhex(
        "000000000000000000011c5890365e1feda2d5cee5c6f713f39eefb4df4b51af"
    )
    
    return params


def create_testnet_params() -> ConsensusParams:
    """Create consensus parameters for Bitcoin testnet."""
    params = ConsensusParams()
    
    # Genesis block hash
    params.hash_genesis_block = bytes.fromhex(
        "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
    )
    
    # Same halving interval
    params.n_subsidy_halving_interval = 210000
    
    # Lower activation heights (testnet activated earlier)
    params.bip34_height = 21111
    params.bip65_height = 581885
    params.bip66_height = 330776
    params.csv_height = 770112
    params.segwit_height = 834624
    
    # Same PoW limit
    params.pow_limit = bytes.fromhex(
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    
    # Testnet allows min difficulty blocks
    params.pow_allow_min_difficulty_blocks = True
    
    params.pow_target_spacing = 600
    params.pow_target_timespan = 1209600
    
    return params


def create_testnet4_params() -> ConsensusParams:
    """Create consensus parameters for Bitcoin testnet4."""
    params = ConsensusParams()
    
    # Testnet4 genesis block hash
    params.hash_genesis_block = bytes.fromhex(
        "00000000da84f2bafbbc53dee25a72f507e5a2715b4e5a0a7d1e9c0d0e0f0a0b0"
    )
    
    params.n_subsidy_halving_interval = 210000
    
    # Testnet4 has different activation heights
    params.bip34_height = 1
    params.bip65_height = 1
    params.bip66_height = 1
    params.csv_height = 1
    params.segwit_height = 1
    
    params.pow_limit = bytes.fromhex(
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    
    params.pow_allow_min_difficulty_blocks = True
    params.enforce_bip94 = True  # Testnet4 enforces BIP94
    
    params.pow_target_spacing = 600
    params.pow_target_timespan = 1209600
    
    return params


def create_signet_params(challenge: Optional[bytes] = None) -> ConsensusParams:
    """Create consensus parameters for Bitcoin signet."""
    params = ConsensusParams()
    
    # Signet genesis block hash (default)
    params.hash_genesis_block = bytes.fromhex(
        "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
    )
    
    params.n_subsidy_halving_interval = 210000
    
    # Signet has these rules active from genesis
    params.bip34_height = 1
    params.bip65_height = 1
    params.bip66_height = 1
    params.csv_height = 1
    params.segwit_height = 1
    
    params.pow_limit = bytes.fromhex(
        "00000377ae000000000000000000000000000000000000000000000000000000"
    )
    
    params.pow_target_spacing = 600
    params.pow_target_timespan = 1209600
    
    # Signet specific
    params.signet_blocks = True
    params.signet_challenge = challenge if challenge else bytes([0x51])  # OP_TRUE default
    
    return params


def create_regtest_params() -> ConsensusParams:
    """Create consensus parameters for Bitcoin regtest."""
    params = ConsensusParams()
    
    # Regtest genesis block hash
    params.hash_genesis_block = bytes.fromhex(
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    )
    
    params.n_subsidy_halving_interval = 150
    
    # Regtest has all rules active from genesis
    params.bip34_height = 1
    params.bip65_height = 1
    params.bip66_height = 1
    params.csv_height = 1
    params.segwit_height = 1
    
    # Regtest has easy PoW limit
    params.pow_limit = bytes.fromhex(
        "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    
    params.pow_target_spacing = 600
    params.pow_target_timespan = 1209600
    
    # Regtest specifics
    params.pow_allow_min_difficulty_blocks = True
    params.pow_no_retargeting = True
    
    return params


# ============================================================================
# Block Subsidy
# ============================================================================

def get_block_subsidy(height: int, params: ConsensusParams) -> int:
    """
    Calculate the block subsidy at a given height.
    
    Args:
        height: Block height
        params: Consensus parameters
        
    Returns:
        Block subsidy in satoshis
    """
    halvings = height // params.n_subsidy_halving_interval
    
    # Force block reward to zero when right shift is too large
    if halvings >= 64:
        return 0
    
    # Initial subsidy: 50 BTC = 5,000,000,000 satoshis
    subsidy = 50 * 100000000
    
    # Halve the subsidy for each halving interval
    subsidy >>= halvings
    
    return subsidy


# ============================================================================
# Network Magic Bytes
# ============================================================================

@dataclass(frozen=True)
class MessageStartChars:
    """Network magic bytes for message identification."""
    data: bytes  # 4 bytes
    
    def __post_init__(self):
        if len(self.data) != 4:
            raise ValueError("MessageStartChars must be exactly 4 bytes")
    
    def __bytes__(self) -> bytes:
        return self.data


def get_mainnet_magic() -> MessageStartChars:
    """Get mainnet message start bytes."""
    return MessageStartChars(bytes.fromhex("f9beb4d9"))


def get_testnet_magic() -> MessageStartChars:
    """Get testnet message start bytes."""
    return MessageStartChars(bytes.fromhex("0b110907"))


def get_testnet4_magic() -> MessageStartChars:
    """Get testnet4 message start bytes."""
    return MessageStartChars(bytes.fromhex("1c163f28"))


def get_signet_magic() -> MessageStartChars:
    """Get signet message start bytes."""
    return MessageStartChars(bytes.fromhex("0a03cf40"))


def get_regtest_magic() -> MessageStartChars:
    """Get regtest message start bytes."""
    return MessageStartChars(bytes.fromhex("fabfb5da"))


def get_network_for_magic(magic: MessageStartChars) -> Optional[ChainType]:
    """Determine network type from magic bytes."""
    magic_bytes = magic.data
    
    if magic_bytes == get_mainnet_magic().data:
        return ChainType.MAIN
    elif magic_bytes == get_testnet_magic().data:
        return ChainType.TESTNET
    elif magic_bytes == get_testnet4_magic().data:
        return ChainType.TESTNET4
    elif magic_bytes == get_signet_magic().data:
        return ChainType.SIGNET
    elif magic_bytes == get_regtest_magic().data:
        return ChainType.REGTEST
    
    return None
