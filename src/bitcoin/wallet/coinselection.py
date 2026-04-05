"""
Coin Selection Module.

This module provides coin selection algorithms for creating transactions.

Reference: Bitcoin Core src/wallet/coinselection.h, src/wallet/coinselection.cpp
"""

import random
from dataclasses import dataclass, field
from typing import Optional, List, Set, Dict, Tuple
from enum import Enum, auto

from .types import (
    SelectionAlgorithm, get_algorithm_name,
    CHANGE_LOWER, CHANGE_UPPER, OutputType
)


@dataclass
class COutput:
    """
    A UTXO under consideration for use in funding a new transaction.
    """
    # The outpoint identifying this UTXO
    outpoint: bytes  # COutPoint (36 bytes: 32 txid + 4 index)
    # The output itself
    txout: bytes     # CTxOut serialized
    # Depth in block chain
    depth: int
    # Estimated size as fully-signed input (-1 if unknown)
    input_bytes: int
    # Whether we know how to spend (ignoring lack of keys)
    solvable: bool
    # Whether safe to spend
    safe: bool
    # Transaction time
    time: int
    # Whether from this wallet
    from_me: bool
    # Fee to spend at consolidation feerate
    long_term_fee: int = 0
    # Ancestor bump fees
    ancestor_bump_fees: int = 0

    # Computed values
    _effective_value: Optional[int] = field(default=None, repr=False)
    _fee: Optional[int] = field(default=None, repr=False)

    def __post_init__(self):
        if self.input_bytes < 0:
            self._fee = 0
            self._effective_value = self.n_value

    @property
    def n_value(self) -> int:
        """Get the output value in satoshis."""
        # Parse from txout (first 8 bytes are value)
        if len(self.txout) >= 8:
            return int.from_bytes(self.txout[:8], 'little')
        return 0

    def apply_fee(self, fee_rate: int, fee: Optional[int] = None):
        """
        Apply fee calculation for this output.

        Args:
            fee_rate: Fee rate in sat/vbyte
            fee: Pre-calculated fee (optional)
        """
        if fee is not None:
            self._fee = fee
        elif self.input_bytes >= 0:
            self._fee = self.input_bytes * fee_rate

        if self._fee is not None:
            self._effective_value = self.n_value - self._fee

    def apply_bump_fee(self, bump_fee: int):
        """Apply ancestor bump fee."""
        assert bump_fee >= 0
        self.ancestor_bump_fees = bump_fee
        if self._fee is not None:
            self._fee += bump_fee
        if self._effective_value is not None:
            self._effective_value = self.n_value - self._fee

    def get_fee(self) -> int:
        """Get the fee for this output."""
        assert self._fee is not None
        return self._fee

    def get_effective_value(self) -> int:
        """Get the effective value (value minus fee)."""
        assert self._effective_value is not None
        return self._effective_value

    def has_effective_value(self) -> bool:
        """Check if effective value is calculated."""
        return self._effective_value is not None

    def __lt__(self, other: 'COutput') -> bool:
        return self.outpoint < other.outpoint

    def __str__(self) -> str:
        return f"COutput({self.outpoint.hex()[:16]}..., value={self.n_value}, depth={self.depth})"


@dataclass
class CoinSelectionParams:
    """Parameters for one iteration of coin selection."""
    # Random number generator (seeded)
    rng: random.Random = field(default_factory=random.Random)
    # Size of change output in bytes
    change_output_size: int = 0
    # Size of input to spend change output
    change_spend_size: int = 0
    # Minimum change target
    min_change_target: int = 0
    # Minimum viable change
    min_viable_change: int = 0
    # Cost of creating change output
    change_fee: int = 0
    # Cost of change + future spend
    cost_of_change: int = 0
    # Target feerate
    effective_feerate: int = 0
    # Long-term feerate estimate
    long_term_feerate: int = 0
    # Discard feerate
    discard_feerate: int = 0
    # Transaction size without inputs
    tx_noinputs_size: int = 0
    # Whether subtracting fee from outputs
    subtract_fee_outputs: bool = False
    # Avoid partial spends for privacy
    avoid_partial_spends: bool = False
    # Include unsafe inputs
    include_unsafe_inputs: bool = False
    # Transaction version
    version: int = 2
    # Maximum transaction weight
    max_tx_weight: Optional[int] = None


@dataclass
class CoinEligibilityFilter:
    """Filter for which outputs are eligible for spending."""
    # Minimum confirmations for outputs from self
    conf_mine: int
    # Minimum confirmations from others
    conf_theirs: int
    # Maximum unconfirmed ancestors
    max_ancestors: int
    # Maximum cluster count
    max_cluster_count: int
    # Include partial groups
    include_partial_groups: bool = False

    def __lt__(self, other: 'CoinEligibilityFilter') -> bool:
        return (
            self.conf_mine, self.conf_theirs,
            self.max_ancestors, self.max_cluster_count,
            self.include_partial_groups
        ) < (
            other.conf_mine, other.conf_theirs,
            other.max_ancestors, other.max_cluster_count,
            other.include_partial_groups
        )


@dataclass
class OutputGroup:
    """A group of UTXOs paid to the same output script."""
    # List of outputs in this group
    outputs: List[COutput] = field(default_factory=list)
    # Whether from this wallet
    from_me: bool = True
    # Total value
    value: int = 0
    # Minimum depth
    depth: int = 999
    # Aggregated ancestor count
    ancestors: int = 0
    # Maximum cluster count
    max_cluster_count: int = 0
    # Effective value
    effective_value: int = 0
    # Fee at effective feerate
    fee: int = 0
    # Fee at long-term feerate
    long_term_fee: int = 0
    # Long-term feerate
    long_term_feerate: int = 0
    # Subtract fee from outputs
    subtract_fee_outputs: bool = False
    # Total weight
    weight: int = 0

    def insert(self, output: COutput, ancestors: int, cluster_count: int):
        """Add an output to this group."""
        self.outputs.append(output)
        self.value += output.n_value

        if not output.from_me:
            self.from_me = False

        if output.depth < self.depth:
            self.depth = output.depth

        self.ancestors += ancestors
        if cluster_count > self.max_cluster_count:
            self.max_cluster_count = cluster_count

        if output.has_effective_value():
            self.effective_value += output.get_effective_value()
            self.fee += output.get_fee()

        self.long_term_fee += output.long_term_fee

        if output.input_bytes > 0:
            self.weight += output.input_bytes * 4  # vbytes to weight

    def eligible_for_spending(self, filter_: CoinEligibilityFilter) -> bool:
        """Check if this group is eligible for spending."""
        # Check depth
        min_conf = filter_.conf_mine if self.from_me else filter_.conf_theirs
        if self.depth < min_conf:
            return False

        # Check ancestors
        if self.ancestors > filter_.max_ancestors:
            return False

        # Check cluster count
        if self.max_cluster_count > filter_.max_cluster_count:
            return False

        return True

    def get_selection_amount(self) -> int:
        """Get amount to use for selection."""
        if self.subtract_fee_outputs:
            return self.value
        return self.effective_value


@dataclass
class Groups:
    """Container for output groups."""
    positive_group: List[OutputGroup] = field(default_factory=list)
    mixed_group: List[OutputGroup] = field(default_factory=list)


@dataclass
class OutputGroupTypeMap:
    """Output groups mapped by type."""
    groups_by_type: Dict[OutputType, Groups] = field(default_factory=dict)
    all_groups: Groups = field(default_factory=Groups)

    def push(self, group: OutputGroup, output_type: OutputType,
             insert_positive: bool, insert_mixed: bool):
        """Add a group to the map."""
        if output_type not in self.groups_by_type:
            self.groups_by_type[output_type] = Groups()

        if insert_positive and group.effective_value > 0:
            self.groups_by_type[output_type].positive_group.append(group)
            self.all_groups.positive_group.append(group)

        if insert_mixed:
            self.groups_by_type[output_type].mixed_group.append(group)
            self.all_groups.mixed_group.append(group)

    def types_count(self) -> int:
        """Get count of output types."""
        return len(self.groups_by_type)


@dataclass
class SelectionResult:
    """Result of coin selection."""
    # Selected inputs
    selected_inputs: Set[COutput] = field(default_factory=set)
    # Target value
    target: int = 0
    # Algorithm used
    algo: SelectionAlgorithm = SelectionAlgorithm.MANUAL
    # Use effective value
    use_effective: bool = False
    # Computed waste
    waste: Optional[int] = None
    # Algorithm completed
    algo_completed: bool = True
    # Selections evaluated
    selections_evaluated: int = 0
    # Total weight
    weight: int = 0
    # Bump fee discount
    bump_fee_group_discount: int = 0

    def get_selected_value(self) -> int:
        """Get sum of input values."""
        return sum(o.n_value for o in self.selected_inputs)

    def get_selected_effective_value(self) -> int:
        """Get sum of effective values."""
        return sum(o.get_effective_value() for o in self.selected_inputs)

    def get_total_bump_fees(self) -> int:
        """Get total bump fees."""
        return sum(o.ancestor_bump_fees for o in self.selected_inputs)

    def clear(self):
        """Clear the selection."""
        self.selected_inputs.clear()
        self.weight = 0
        self.bump_fee_group_discount = 0

    def add_input(self, group: OutputGroup):
        """Add all outputs from a group."""
        for output in group.outputs:
            if output in self.selected_inputs:
                raise ValueError("Output already in selection")
            self.selected_inputs.add(output)

        if not self.use_effective:
            self.use_effective = not group.subtract_fee_outputs

        self.weight += group.weight

    def add_inputs(self, inputs: Set[COutput], subtract_fee_outputs: bool):
        """Add multiple inputs."""
        for inp in inputs:
            if inp in self.selected_inputs:
                raise ValueError("Output already in selection")
            self.selected_inputs.add(inp)

            if inp.input_bytes > 0:
                self.weight += inp.input_bytes * 4

        if not subtract_fee_outputs:
            self.use_effective = True

    def set_bump_fee_discount(self, discount: int):
        """Set the bump fee discount."""
        self.bump_fee_group_discount = discount

    def recalculate_waste(
        self,
        min_viable_change: int,
        change_cost: int,
        change_fee: int
    ):
        """
        Calculate and store waste.

        waste = change_cost + inputs * (effective_feerate - long_term_feerate)
                - bump_fee_group_discount
        """
        # Sum (fee - long_term_fee) for all inputs
        fee_diff = sum(
            o.get_fee() - o.long_term_fee
            for o in self.selected_inputs
        )

        # Calculate excess
        excess = self.get_selected_effective_value() - self.target

        if excess > 0:
            if excess >= min_viable_change:
                # There will be change
                self.waste = change_cost + fee_diff - self.bump_fee_group_discount
            else:
                # No change, excess goes to fee
                self.waste = excess + fee_diff - self.bump_fee_group_discount
        else:
            self.waste = fee_diff - self.bump_fee_group_discount

    def get_waste(self) -> int:
        """Get the calculated waste."""
        assert self.waste is not None
        return self.waste

    def set_algo_completed(self, completed: bool):
        """Mark whether algorithm completed."""
        self.algo_completed = completed

    def get_algo_completed(self) -> bool:
        """Check if algorithm completed."""
        return self.algo_completed

    def set_selections_evaluated(self, count: int):
        """Set count of selections evaluated."""
        self.selections_evaluated = count

    def get_selections_evaluated(self) -> int:
        """Get count of selections evaluated."""
        return self.selections_evaluated

    def merge(self, other: 'SelectionResult'):
        """Merge another result into this one."""
        overlap = self.selected_inputs & other.selected_inputs
        if overlap:
            raise ValueError("Overlapping outputs in selection results")

        self.selected_inputs.update(other.selected_inputs)
        self.weight += other.weight
        if other.waste is not None and self.waste is not None:
            self.waste += other.waste
        self.bump_fee_group_discount += other.bump_fee_group_discount

    def get_input_set(self) -> Set[COutput]:
        """Get the set of selected inputs."""
        return self.selected_inputs.copy()

    def get_shuffled_input_vector(self) -> List[COutput]:
        """Get shuffled list of inputs."""
        inputs = list(self.selected_inputs)
        random.shuffle(inputs)
        return inputs

    def get_change(self, min_viable_change: int, change_fee: int) -> int:
        """
        Calculate change amount.

        Returns 0 if no change should be created.
        """
        if self.use_effective:
            change = self.get_selected_effective_value() - self.target
        else:
            change = self.get_selected_value() - self.target

        # Subtract change fee
        change -= change_fee

        if change < min_viable_change:
            return 0

        return change

    def get_target(self) -> int:
        """Get the target value."""
        return self.target

    def get_algo(self) -> SelectionAlgorithm:
        """Get the algorithm used."""
        return self.algo

    def get_weight(self) -> int:
        """Get total weight."""
        return self.weight

    def __lt__(self, other: 'SelectionResult') -> bool:
        return self.waste < other.waste if self.waste is not None else True


def generate_change_target(
    payment_value: int,
    change_fee: int,
    rng: random.Random
) -> int:
    """
    Generate a random change target for privacy.

    The random value is between CHANGE_LOWER and min(2 * payment, CHANGE_UPPER).
    """
    # Base change amount (at least covers fee)
    lower = CHANGE_LOWER
    upper = min(2 * payment_value, CHANGE_UPPER)

    if payment_value <= 25000:
        # For small payments, use fixed lower bound
        return lower + change_fee

    # Random value in range
    random_value = rng.randint(lower, upper)

    return random_value + change_fee


def select_coins_bnb(
    utxo_pool: List[OutputGroup],
    selection_target: int,
    cost_of_change: int,
    max_selection_weight: int
) -> Optional[SelectionResult]:
    """
    Branch and Bound coin selection algorithm.

    Tries to find exact match without creating change.
    """
    # Sort pool by effective value descending
    utxo_pool = sorted(utxo_pool, key=lambda g: g.effective_value, reverse=True)

    n = len(utxo_pool)
    target = selection_target

    # Current selection state
    current_selection = [False] * n
    current_value = 0
    current_weight = 0

    # Best solution so far
    best_selection = None
    best_value = float('inf')

    # Backtracking state
    backtrack_stack = []

    # Start depth-first search
    depth = 0
    forward = True

    max_iterations = 100000  # Limit iterations
    iterations = 0

    while depth >= 0 and iterations < max_iterations:
        iterations += 1

        if forward:
            # Check if current solution is valid
            if current_value >= target and current_weight <= max_selection_weight:
                # Found a valid solution
                if current_value < best_value:
                    best_value = current_value
                    best_selection = current_selection.copy()

                    # Check for exact match
                    if current_value == target:
                        break

            # Try to go deeper
            if depth < n:
                # Include current UTXO
                current_selection[depth] = True
                current_value += utxo_pool[depth].effective_value
                current_weight += utxo_pool[depth].weight

                if current_value <= best_value and current_weight <= max_selection_weight:
                    backtrack_stack.append((depth, current_value, current_weight, True))
                    depth += 1
                else:
                    # Backtrack, try excluding
                    current_selection[depth] = False
                    current_value -= utxo_pool[depth].effective_value
                    current_weight -= utxo_pool[depth].weight

                    if current_value + sum(g.effective_value for g in utxo_pool[depth+1:]) >= target:
                        backtrack_stack.append((depth, current_value, current_weight, False))
                        depth += 1
            else:
                forward = False
        else:
            # Backtrack
            if backtrack_stack:
                prev_depth, prev_value, prev_weight, was_included = backtrack_stack.pop()

                if was_included:
                    # Try excluding instead
                    current_selection[prev_depth] = False
                    current_value = prev_value
                    current_weight = prev_weight

                    if current_value + sum(g.effective_value for g in utxo_pool[prev_depth+1:]) >= target:
                        backtrack_stack.append((prev_depth, current_value, current_weight, False))
                        depth = prev_depth + 1
                        forward = True
                else:
                    depth = prev_depth - 1
                    forward = False
            else:
                depth = -1

    if best_selection is None:
        return None

    # Build result
    result = SelectionResult(target=selection_target, algo=SelectionAlgorithm.BNB)

    for i, selected in enumerate(best_selection):
        if selected:
            result.add_input(utxo_pool[i])

    result.set_algo_completed(iterations < max_iterations)
    result.set_selections_evaluated(iterations)

    return result


def coin_grinder(
    utxo_pool: List[OutputGroup],
    selection_target: int,
    change_target: int,
    max_selection_weight: int
) -> Optional[SelectionResult]:
    """
    Coin Grinder algorithm.

    Minimizes fees while ensuring sufficient change.
    """
    # Sort by effective value ascending (prefer smaller inputs)
    utxo_pool = sorted(utxo_pool, key=lambda g: g.effective_value)

    total_target = selection_target + change_target

    result = SelectionResult(target=selection_target, algo=SelectionAlgorithm.CG)

    current_value = 0
    current_weight = 0

    for group in utxo_pool:
        if current_value >= total_target:
            break

        if current_weight + group.weight > max_selection_weight:
            continue

        result.add_input(group)
        current_value += group.effective_value
        current_weight += group.weight

    if current_value < selection_target:
        return None

    result.set_algo_completed(True)
    return result


def select_coins_srd(
    utxo_pool: List[OutputGroup],
    target_value: int,
    change_fee: int,
    rng: random.Random,
    max_selection_weight: int
) -> Optional[SelectionResult]:
    """
    Single Random Draw algorithm.

    Randomly selects UTXOs until target is met.
    """
    if not utxo_pool:
        return None

    # Shuffle the pool
    pool = utxo_pool.copy()
    rng.shuffle(pool)

    result = SelectionResult(target=target_value, algo=SelectionAlgorithm.SRD)

    current_value = 0
    current_weight = 0

    for group in pool:
        if current_value >= target_value + CHANGE_LOWER:
            break

        if current_weight + group.weight > max_selection_weight:
            # Try to drop smallest and continue
            continue

        result.add_input(group)
        current_value += group.effective_value
        current_weight += group.weight

    if current_value < target_value:
        return None

    result.set_algo_completed(True)
    return result


def knapsack_solver(
    groups: List[OutputGroup],
    target_value: int,
    change_target: int,
    rng: random.Random,
    max_selection_weight: int
) -> Optional[SelectionResult]:
    """
    Original Knapsack coin selection algorithm.

    Tries to minimize change output size.
    """
    if not groups:
        return None

    # Filter groups with positive value
    positive_groups = [g for g in groups if g.effective_value > 0]

    if not positive_groups:
        return None

    # Sort groups randomly for variety
    rng.shuffle(positive_groups)

    total_target = target_value + change_target

    result = SelectionResult(target=target_value, algo=SelectionAlgorithm.KNAPSACK)

    current_value = 0
    current_weight = 0

    # First pass: try exact match
    for group in positive_groups:
        if current_value >= target_value:
            break

        if current_weight + group.weight > max_selection_weight:
            continue

        if current_value + group.effective_value <= total_target + group.fee:
            result.add_input(group)
            current_value += group.effective_value
            current_weight += group.weight

    # Second pass: if not enough, add more
    if current_value < target_value:
        for group in positive_groups:
            if group in result.selected_inputs:
                continue

            if current_value >= target_value:
                break

            if current_weight + group.weight > max_selection_weight:
                continue

            result.add_input(group)
            current_value += group.effective_value
            current_weight += group.weight

    if current_value < target_value:
        return None

    result.set_algo_completed(True)
    return result
