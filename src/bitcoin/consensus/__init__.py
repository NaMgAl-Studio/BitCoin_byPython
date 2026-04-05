# Copyright (c) 2009-2010 Satoshi Nakamoto
# Copyright (c) 2009-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Bitcoin Consensus Module

This module implements consensus-critical functionality:
- Chain parameters
- Transaction validation
- Block validation
- Proof of work
- UTXO management
"""

from .params import (
    # Constants
    LOCKTIME_THRESHOLD,
    COINBASE_MATURITY,
    WITNESS_SCALE_FACTOR,
    MAX_BLOCK_WEIGHT,
    MAX_BLOCK_SERIALIZED_SIZE,
    MAX_BLOCK_SIGOPS_COST,
    MAX_MONEY,
    
    # Enums
    BuriedDeployment,
    DeploymentPos,
    ChainType,
    
    # Classes
    BIP9Deployment,
    ConsensusParams,
    MessageStartChars,
    
    # Factory functions
    create_mainnet_params,
    create_testnet_params,
    create_testnet4_params,
    create_signet_params,
    create_regtest_params,
    
    # Utility functions
    get_block_subsidy,
    valid_buried_deployment,
    valid_deployment_pos,
    chain_type_to_string,
    get_network_for_magic,
    get_mainnet_magic,
    get_testnet_magic,
    get_testnet4_magic,
    get_signet_magic,
    get_regtest_magic,
)

from .validation import (
    # Constants
    NO_WITNESS_COMMITMENT,
    MINIMUM_WITNESS_COMMITMENT,
    
    # Enums
    TxValidationResult,
    BlockValidationResult,
    
    # Classes
    ValidationState,
    TxValidationState,
    BlockValidationState,
    
    # Functions
    get_transaction_weight,
    get_block_weight,
    get_virtual_size,
    get_witness_commitment_index,
    script_flag_exceptions_for_block,
)

from .tx_check import (
    CheckTransaction,
    CheckTransactionSanity,
    GetValueOut,
    GetTotalSize,
    GetWeight,
    GetVirtualSize,
    HasWitness,
    IsSegwit,
)

from .tx_verify import (
    # Constants
    SEQUENCE_FINAL,
    SEQUENCE_LOCKTIME_TYPE_FLAG,
    SEQUENCE_LOCKTIME_MASK,
    LOCKTIME_VERIFY_SEQUENCE,
    
    # Functions
    IsFinalTx,
    SequenceLocks,
    CalculateSequenceLocks,
    EvaluateSequenceLocks,
    CheckTxInputs,
    GetLegacySigOpCount,
    GetP2SHSigOpCount,
    GetTransactionSigOpCost,
)

from .pow import (
    # Classes
    ArithUint256,
    BlockIndex,
    
    # Functions
    DeriveTarget,
    CheckProofOfWork,
    GetNextWorkRequired,
    CalculateNextWorkRequired,
    PermittedDifficultyTransition,
)

from .amount import (
    MoneyRange,
    MoneyRangeNonNegative,
    FormatMoney,
    ParseMoney,
)

from .consensus import (
    WITNESS_SCALE_FACTOR,
    MAX_BLOCK_WEIGHT,
    MAX_BLOCK_SERIALIZED_SIZE,
    MAX_BLOCK_SIGOPS_COST,
    MAX_MONEY,
    COINBASE_MATURITY,
)

__all__ = [
    # Constants
    'LOCKTIME_THRESHOLD',
    'COINBASE_MATURITY',
    'WITNESS_SCALE_FACTOR',
    'MAX_BLOCK_WEIGHT',
    'MAX_BLOCK_SERIALIZED_SIZE',
    'MAX_BLOCK_SIGOPS_COST',
    'MAX_MONEY',
    'NO_WITNESS_COMMITMENT',
    'MINIMUM_WITNESS_COMMITMENT',
    'SEQUENCE_FINAL',
    'SEQUENCE_LOCKTIME_TYPE_FLAG',
    'SEQUENCE_LOCKTIME_MASK',
    'LOCKTIME_VERIFY_SEQUENCE',
    
    # Enums
    'BuriedDeployment',
    'DeploymentPos',
    'ChainType',
    'TxValidationResult',
    'BlockValidationResult',
    
    # Classes
    'BIP9Deployment',
    'ConsensusParams',
    'MessageStartChars',
    'ValidationState',
    'TxValidationState',
    'BlockValidationState',
    'ArithUint256',
    'BlockIndex',
    
    # Factory functions
    'create_mainnet_params',
    'create_testnet_params',
    'create_testnet4_params',
    'create_signet_params',
    'create_regtest_params',
    
    # Utility functions
    'get_block_subsidy',
    'valid_buried_deployment',
    'valid_deployment_pos',
    'chain_type_to_string',
    'get_network_for_magic',
    'get_mainnet_magic',
    'get_testnet_magic',
    'get_testnet4_magic',
    'get_signet_magic',
    'get_regtest_magic',
    
    # Validation functions
    'get_transaction_weight',
    'get_block_weight',
    'get_virtual_size',
    'get_witness_commitment_index',
    'script_flag_exceptions_for_block',
    
    # Transaction check functions
    'CheckTransaction',
    'CheckTransactionSanity',
    'GetValueOut',
    'GetTotalSize',
    'GetWeight',
    'GetVirtualSize',
    'HasWitness',
    'IsSegwit',
    
    # Transaction verify functions
    'IsFinalTx',
    'SequenceLocks',
    'CalculateSequenceLocks',
    'EvaluateSequenceLocks',
    'CheckTxInputs',
    'GetLegacySigOpCount',
    'GetP2SHSigOpCount',
    'GetTransactionSigOpCost',
    
    # PoW functions
    'DeriveTarget',
    'CheckProofOfWork',
    'GetNextWorkRequired',
    'CalculateNextWorkRequired',
    'PermittedDifficultyTransition',
    
    # Amount functions
    'MoneyRange',
    'MoneyRangeNonNegative',
    'FormatMoney',
    'ParseMoney',
]
