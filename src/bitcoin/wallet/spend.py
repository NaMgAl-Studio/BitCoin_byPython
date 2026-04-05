"""
Wallet Spend Module.

This module provides transaction creation and coin selection
functionality for spending wallet funds.

Reference: Bitcoin Core src/wallet/spend.h, src/wallet/spend.cpp
"""

import random
import hashlib
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Any, Tuple
from enum import Enum

from .types import (
    CRecipient, OutputType, CreatedTransactionResult,
    DEFAULT_TX_CONFIRM_TARGET, HIGH_TX_FEE_PER_KB
)
from .coinselection import (
    COutput, CoinSelectionParams, CoinEligibilityFilter,
    OutputGroup, Groups, SelectionResult,
    select_coins_bnb, coin_grinder, select_coins_srd, knapsack_solver,
    generate_change_target
)


@dataclass
class CCoinControl:
    """
    Control parameters for coin selection.

    Allows fine-grained control over which coins are selected
    and how the transaction is constructed.
    """
    # Selected inputs (if manually specified)
    m_selected_inputs: Set[bytes] = field(default_factory=set)
    # Allow other inputs to be added
    m_allow_other_inputs: bool = True
    # Include unconfirmed inputs from others
    m_include_unsafe_inputs: bool = False
    # Destination for change
    m_dest_change: Optional[bytes] = None
    # Change type override
    m_change_type: Optional[OutputType] = None
    # Whether to subtract fee from outputs
    m_subtract_fee_from_outputs: bool = False
    # Force feerate
    m_feerate: Optional[int] = None
    # Override min confirmations
    m_min_depth: int = 0
    # Maximum weight
    m_max_tx_weight: Optional[int] = None
    # Whether to signal RBF
    m_signal_bip125_rbf: bool = True
    # Fee mode
    m_fee_mode: int = 0
    # Lock unspents
    m_lock_unspents: bool = False

    def has_input(self, outpoint: bytes) -> bool:
        """Check if input is selected."""
        return outpoint in self.m_selected_inputs

    def select(self, outpoint: bytes):
        """Select an input."""
        self.m_selected_inputs.add(outpoint)

    def unselect(self, outpoint: bytes):
        """Unselect an input."""
        self.m_selected_inputs.discard(outpoint)

    def unselect_all(self):
        """Unselect all inputs."""
        self.m_selected_inputs.clear()


@dataclass
class CoinsResult:
    """Container for available coins by output type."""
    coins: Dict[OutputType, List[COutput]] = field(default_factory=dict)
    total_amount: int = 0
    total_effective_amount: Optional[int] = None

    def all(self) -> List[COutput]:
        """Get all coins as a single list."""
        result = []
        for coin_list in self.coins.values():
            result.extend(coin_list)
        return result

    def size(self) -> int:
        """Get total count of coins."""
        return sum(len(v) for v in self.coins.values())

    def types_count(self) -> int:
        """Get count of output types."""
        return len(self.coins)

    def clear(self):
        """Clear all coins."""
        self.coins.clear()
        self.total_amount = 0
        self.total_effective_amount = None

    def add(self, output_type: OutputType, output: COutput):
        """Add a coin."""
        if output_type not in self.coins:
            self.coins[output_type] = []
        self.coins[output_type].append(output)
        self.total_amount += output.n_value
        if output.has_effective_value():
            if self.total_effective_amount is None:
                self.total_effective_amount = 0
            self.total_effective_amount += output.get_effective_value()

    def erase(self, outpoints: Set[bytes]):
        """Remove coins by outpoint."""
        for output_type, coin_list in self.coins.items():
            self.coins[output_type] = [
                c for c in coin_list if c.outpoint not in outpoints
            ]


@dataclass
class CoinFilterParams:
    """Parameters for filtering available coins."""
    min_amount: int = 1
    max_amount: int = 2100000000000000  # MAX_MONEY
    min_sum_amount: int = 2100000000000000
    max_count: int = 0
    include_immature_coinbase: bool = False
    skip_locked: bool = True


def available_coins(
    wallet: Any,
    coin_control: Optional[CCoinControl] = None,
    feerate: Optional[int] = None,
    params: Optional[CoinFilterParams] = None
) -> CoinsResult:
    """
    Get all available coins from the wallet.

    Args:
        wallet: The wallet to get coins from
        coin_control: Optional coin control parameters
        feerate: Optional fee rate for effective value calculation
        params: Filter parameters

    Returns:
        CoinsResult with available coins by type
    """
    result = CoinsResult()
    params = params or CoinFilterParams()

    # Iterate through wallet transactions
    # This is a simplified implementation
    for wtx in wallet._map_wallet.values():
        depth = wtx.get_depth_in_main_chain()

        # Check confirmation requirements
        if coin_control and coin_control.m_min_depth > 0:
            if depth < coin_control.m_min_depth:
                continue

        # Skip immature coinbase if not allowed
        if wtx.is_coinbase() and not params.include_immature_coinbase:
            if wtx.get_blocks_to_maturity() > 0:
                continue

        # Get outputs
        for i, txout in enumerate(getattr(wtx.tx, 'vout', [])):
            # Create outpoint
            outpoint = wtx.get_hash() + i.to_bytes(4, 'little')

            # Skip locked coins
            if params.skip_locked and wallet.is_locked_coin(outpoint):
                continue

            # Skip if already selected (and we're looking for more)
            if coin_control and coin_control.has_input(outpoint):
                continue

            # Check amount bounds
            value = getattr(txout, 'n_value', 0)
            if value < params.min_amount or value > params.max_amount:
                continue

            # Check if this is an output we can spend
            # This would check IsMine
            output = COutput(
                outpoint=outpoint,
                txout=txout,
                depth=depth,
                input_bytes=-1,  # Will be calculated later
                solvable=True,
                safe=True,
                time=wtx.n_time_received,
                from_me=wtx.m_cached_from_me or False
            )

            # Apply fee calculation
            if feerate:
                output.apply_fee(feerate)

            result.add(OutputType.UNKNOWN, output)

            # Check max count
            if params.max_count > 0 and result.size() >= params.max_count:
                break

            # Check min sum
            if result.total_amount >= params.min_sum_amount:
                break

    return result


def calculate_maximum_signed_input_size(
    txout: Any,
    wallet: Any,
    coin_control: Optional[CCoinControl] = None
) -> int:
    """
    Calculate the maximum size of an input spending this output.

    Returns -1 if size cannot be calculated.
    """
    # This would use the script module to estimate signature size
    # Simplified implementation

    # P2WPKH: ~68 vbytes
    # P2PKH: ~148 vbytes
    # P2SH-P2WPKH: ~91 vbytes
    # P2TR: ~57.5 vbytes

    script = getattr(txout, 'script_pub_key', b'')

    if len(script) == 22 and script[0:2] == b'\x00\x14':
        # P2WPKH
        return 68
    elif len(script) == 25 and script[0] == 0x76 and script[1] == 0xa9:
        # P2PKH
        return 148
    elif len(script) == 23 and script[0] == 0xa9:
        # P2SH (could be P2SH-P2WPKH)
        return 91
    elif len(script) == 34 and script[0] == 0x51:
        # P2TR
        return 58

    return -1


def calculate_maximum_signed_tx_size(
    tx: Any,
    wallet: Any,
    coin_control: Optional[CCoinControl] = None
) -> Tuple[int, int]:
    """
    Calculate the maximum size of a signed transaction.

    Returns (vsize, weight) tuple.
    """
    # Base transaction size
    base_size = 10  # version + locktime + input/output counts

    # Add outputs
    for txout in getattr(tx, 'vout', []):
        # Value (8) + script len (1+) + script
        script = getattr(txout, 'script_pub_key', b'')
        base_size += 8 + 1 + len(script)

    # Add inputs (estimate maximum signature size)
    for txin in getattr(tx, 'vin', []):
        base_size += 32 + 4 + 4  # outpoint + sequence
        # Script sig placeholder (max sig)
        base_size += 72 + 1 + 33  # sig + pubkey
        # Witness placeholder
        base_size += 1 + 72 + 1 + 33

    # Weight = base_size * 3 + total_size
    # Simplified: assume native segwit
    weight = base_size * 4
    vsize = (weight + 3) // 4

    return vsize, weight


def group_outputs(
    wallet: Any,
    coins: CoinsResult,
    params: CoinSelectionParams,
    filters: List[CoinEligibilityFilter]
) -> Dict[CoinEligibilityFilter, Dict[OutputType, Groups]]:
    """
    Group coins by filter and output type.
    """
    result = {}

    for filter_ in filters:
        type_groups: Dict[OutputType, Groups] = {}

        for output_type, coin_list in coins.coins.items():
            groups = Groups()

            # Group by script
            script_groups: Dict[bytes, OutputGroup] = {}

            for coin in coin_list:
                # Check eligibility
                if coin.depth < (filter_.conf_mine if coin.from_me else filter_.conf_theirs):
                    continue

                # Get script
                script = coin.txout[8:] if len(coin.txout) > 8 else b''

                if script not in script_groups:
                    script_groups[script] = OutputGroup()

                # Add to group
                script_groups[script].insert(coin, 0, 0)

            # Convert to list
            for group in script_groups.values():
                if group.eligible_for_spending(filter_):
                    groups.positive_group.append(group)

            type_groups[output_type] = groups

        result[filter_] = type_groups

    return result


def attempt_selection(
    wallet: Any,
    target_value: int,
    groups_by_type: Dict[OutputType, Groups],
    params: CoinSelectionParams,
    allow_mixed_output_types: bool = True
) -> Optional[SelectionResult]:
    """
    Attempt coin selection for a target value.

    Tries different algorithms in order of preference.
    """
    best_result: Optional[SelectionResult] = None

    # Try each output type separately first
    for output_type, groups in groups_by_type.items():
        result = choose_selection_result(
            wallet,
            target_value,
            groups,
            params
        )

        if result:
            if best_result is None or result < best_result:
                best_result = result

    # If no result from single types, try mixed
    if best_result is None and allow_mixed_output_types:
        all_groups = Groups()
        for groups in groups_by_type.values():
            all_groups.positive_group.extend(groups.positive_group)

        best_result = choose_selection_result(
            wallet,
            target_value,
            all_groups,
            params
        )

    return best_result


def choose_selection_result(
    wallet: Any,
    target_value: int,
    groups: Groups,
    params: CoinSelectionParams
) -> Optional[SelectionResult]:
    """
    Choose the best selection result using multiple algorithms.
    """
    best_result: Optional[SelectionResult] = None
    max_weight = params.max_tx_weight or 400000

    # Branch and Bound (exact match)
    result = select_coins_bnb(
        groups.positive_group,
        target_value,
        params.cost_of_change,
        max_weight
    )
    if result:
        best_result = result

    # Coin Grinder (minimize fees with change)
    result = coin_grinder(
        groups.positive_group,
        target_value,
        generate_change_target(target_value, params.change_fee, params.rng),
        max_weight
    )
    if result and (best_result is None or result < best_result):
        best_result = result

    # Knapsack (legacy algorithm)
    result = knapsack_solver(
        groups.positive_group,
        target_value,
        generate_change_target(target_value, params.change_fee, params.rng),
        params.rng,
        max_weight
    )
    if result and (best_result is None or result < best_result):
        best_result = result

    # Single Random Draw
    result = select_coins_srd(
        groups.positive_group,
        target_value,
        params.change_fee,
        params.rng,
        max_weight
    )
    if result and (best_result is None or result < best_result):
        best_result = result

    # Calculate waste for the best result
    if best_result:
        best_result.recalculate_waste(
            params.min_viable_change,
            params.cost_of_change,
            params.change_fee
        )

    return best_result


def select_coins(
    wallet: Any,
    available_coins_result: CoinsResult,
    target_value: int,
    coin_control: CCoinControl,
    params: CoinSelectionParams
) -> Optional[SelectionResult]:
    """
    Select coins for a transaction.

    Uses manually selected coins if specified, otherwise automatic selection.
    """
    result = SelectionResult(target=target_value)

    # First, use manually selected coins
    if coin_control.m_selected_inputs:
        for outpoint in coin_control.m_selected_inputs:
            # Find the coin
            for coin_list in available_coins_result.coins.values():
                for coin in coin_list:
                    if coin.outpoint == outpoint:
                        group = OutputGroup()
                        group.insert(coin, 0, 0)
                        result.add_input(group)
                        break

    selected_value = result.get_selected_value()

    # Check if we have enough
    if selected_value >= target_value:
        return result

    # If more coins needed and allowed
    if coin_control.m_allow_other_inputs:
        remaining = target_value - selected_value

        # Filter out already selected
        available = CoinsResult()
        for output_type, coin_list in available_coins_result.coins.items():
            for coin in coin_list:
                if coin.outpoint not in coin_control.m_selected_inputs:
                    available.add(output_type, coin)

        # Run selection for remaining
        groups = Groups()
        for coin_list in available.coins.values():
            for coin in coin_list:
                group = OutputGroup()
                group.insert(coin, 0, 0)
                groups.positive_group.append(group)

        remaining_result = choose_selection_result(
            wallet,
            remaining,
            groups,
            params
        )

        if remaining_result:
            result.merge(remaining_result)
            return result

    return None


def create_transaction(
    wallet: Any,
    recipients: List[CRecipient],
    change_pos: Optional[int],
    coin_control: CCoinControl,
    sign: bool = True
) -> Optional[CreatedTransactionResult]:
    """
    Create a new transaction paying the specified recipients.

    Args:
        wallet: The wallet to create the transaction from
        recipients: List of payment destinations and amounts
        change_pos: Position for change output (None = random)
        coin_control: Coin selection control
        sign: Whether to sign the transaction

    Returns:
        CreatedTransactionResult or None on failure
    """
    # Calculate total output value
    total_output = sum(r.n_amount for r in recipients)

    # Get feerate
    feerate = coin_control.m_feerate or 10  # Default 10 sat/vbyte

    # Get available coins
    filter_params = CoinFilterParams()
    coins = available_coins(wallet, coin_control, feerate, filter_params)

    # Calculate transaction size for fee estimation
    n_outputs = len(recipients) + 1  # +1 for change

    # Set up coin selection parameters
    params = CoinSelectionParams(
        rng=random.Random(),
        change_output_size=34,  # P2WPKH change output
        change_spend_size=68,   # P2WPKH input size
        min_change_target=1000,
        effective_feerate=feerate,
        long_term_feerate=feerate // 2,
        discard_feerate=feerate // 3,
    )

    # Select coins
    result = select_coins(wallet, coins, total_output, coin_control, params)

    if result is None:
        return None  # Insufficient funds

    # Build transaction
    # This would create a CMutableTransaction and add inputs/outputs
    # Simplified placeholder here

    fee = result.get_selected_value() - total_output

    # Check fee
    if fee > HIGH_TX_FEE_PER_KB:
        # High fee warning
        pass

    return CreatedTransactionResult(
        tx=None,  # Would be the actual transaction
        fee=fee,
        fee_calc=None,
        change_pos=change_pos
    )


def fund_transaction(
    wallet: Any,
    tx: Any,
    recipients: List[CRecipient],
    change_pos: Optional[int],
    lock_unspents: bool,
    coin_control: CCoinControl
) -> Optional[CreatedTransactionResult]:
    """
    Add inputs to a transaction to fund it.

    Similar to CreateTransaction but starts with existing outputs.
    """
    # This would take an existing transaction and add inputs
    # to fund the specified outputs

    return create_transaction(wallet, recipients, change_pos, coin_control)


def discourage_fee_sniping(
    tx: Any,
    rng: random.Random,
    chain: Any,
    block_hash: bytes,
    block_height: int
):
    """
    Set a height-based locktime to discourage fee sniping.

    Uses a random value slightly less than current height.
    """
    if chain is None:
        return

    # Set locktime to a recent block height minus a small random value
    # This makes fee sniping slightly less profitable
    locktime = block_height - rng.randint(0, 10)

    if hasattr(tx, 'n_lock_time'):
        tx.n_lock_time = locktime
