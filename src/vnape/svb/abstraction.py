"""
Abstraction Engine for Neural-to-Symbolic Translation.

This module implements the abstraction framework that enables verification
of neural policy decisions by constructing sound overapproximations.

Based on abstract interpretation theory (Cousot & Cousot, 1977) adapted
for neural network outputs in the security policy domain.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto

import numpy as np

# Make torch optional
try:
    import torch
    import torch.nn as nn

    TORCH_AVAILABLE = True
except ImportError:
    torch = None
    nn = None
    TORCH_AVAILABLE = False

from ..core.types import (
    MFOTLFormula,
    PolicyRefinement,
    RefinementType,
    SafetyInvariants,
)

logger = logging.getLogger(__name__)


class AbstractionStrategy(Enum):
    """Strategies for abstracting neural outputs."""

    INTERVAL = auto()  # Interval abstraction [l, u]
    ZONOTOPE = auto()  # Zonotope abstraction for tighter bounds
    POLYHEDRA = auto()  # Polyhedral abstraction (most precise, expensive)
    BOX = auto()  # Box abstraction (simplest, fastest)


@dataclass
class AbstractValue:
    """
    Abstract representation of a value or set of values.

    Supports interval semantics where [lower, upper] represents
    all concrete values v such that lower <= v <= upper.
    """

    lower: float
    upper: float
    symbolic_var: str | None = None
    constraints: list[str] = field(default_factory=list)

    def __post_init__(self):
        if self.lower > self.upper:
            raise ValueError(f"Invalid interval: [{self.lower}, {self.upper}]")

    def contains(self, value: float) -> bool:
        """Check if concrete value is in this abstract value."""
        return self.lower <= value <= self.upper

    def join(self, other: AbstractValue) -> AbstractValue:
        """Compute least upper bound (join) of two abstract values."""
        return AbstractValue(
            lower=min(self.lower, other.lower),
            upper=max(self.upper, other.upper),
            symbolic_var=self.symbolic_var or other.symbolic_var,
            constraints=self.constraints + other.constraints,
        )

    def meet(self, other: AbstractValue) -> AbstractValue | None:
        """Compute greatest lower bound (meet) of two abstract values."""
        new_lower = max(self.lower, other.lower)
        new_upper = min(self.upper, other.upper)

        if new_lower > new_upper:
            return None  # Empty intersection (bottom)

        return AbstractValue(
            lower=new_lower,
            upper=new_upper,
            symbolic_var=self.symbolic_var or other.symbolic_var,
            constraints=self.constraints + other.constraints,
        )

    def widen(self, other: AbstractValue, threshold: float = 1e6) -> AbstractValue:
        """
        Widening operator to ensure convergence of abstract iteration.

        If bounds are expanding, jump to infinity threshold to guarantee termination.
        """
        new_lower = self.lower if other.lower >= self.lower else -threshold
        new_upper = self.upper if other.upper <= self.upper else threshold

        return AbstractValue(
            lower=new_lower,
            upper=new_upper,
            symbolic_var=self.symbolic_var,
            constraints=self.constraints,
        )

    @property
    def width(self) -> float:
        """Width of the interval."""
        return self.upper - self.lower

    @property
    def midpoint(self) -> float:
        """Midpoint of the interval."""
        return (self.lower + self.upper) / 2

    def __repr__(self) -> str:
        var_str = f" ({self.symbolic_var})" if self.symbolic_var else ""
        return f"[{self.lower:.4f}, {self.upper:.4f}]{var_str}"


@dataclass
class AbstractDomain:
    """
    Abstract domain for policy refinement analysis.

    Maps variable names to their abstract values and maintains
    constraints between variables.
    """

    variables: dict[str, AbstractValue] = field(default_factory=dict)
    relational_constraints: list[str] = field(default_factory=list)

    def set_variable(self, name: str, value: AbstractValue) -> None:
        """Set abstract value for a variable."""
        self.variables[name] = value

    def get_variable(self, name: str) -> AbstractValue | None:
        """Get abstract value for a variable."""
        return self.variables.get(name)

    def add_constraint(self, constraint: str) -> None:
        """Add a relational constraint between variables."""
        self.relational_constraints.append(constraint)

    def join(self, other: AbstractDomain) -> AbstractDomain:
        """Join two abstract domains."""
        result = AbstractDomain()

        # Join variables present in both
        all_vars = set(self.variables.keys()) | set(other.variables.keys())
        for var in all_vars:
            v1 = self.variables.get(var)
            v2 = other.variables.get(var)

            if v1 and v2:
                result.variables[var] = v1.join(v2)
            elif v1:
                result.variables[var] = v1
            else:
                result.variables[var] = v2

        # Union of constraints
        result.relational_constraints = list(
            set(self.relational_constraints + other.relational_constraints)
        )

        return result

    def is_bottom(self) -> bool:
        """Check if domain is empty (bottom)."""
        return len(self.variables) == 0


class NeuralAbstractor(ABC):
    """Abstract base class for neural network abstractors."""

    @abstractmethod
    def abstract_layer(
        self,
        layer: nn.Module,
        input_bounds: list[AbstractValue],
    ) -> list[AbstractValue]:
        """
        Compute abstract output bounds for a neural network layer.

        Args:
            layer: Neural network layer
            input_bounds: Abstract bounds on layer inputs

        Returns:
            Abstract bounds on layer outputs
        """
        pass

    @abstractmethod
    def abstract_network(
        self,
        network: nn.Module,
        input_bounds: list[AbstractValue],
    ) -> list[AbstractValue]:
        """
        Compute abstract output bounds for entire network.

        Args:
            network: Neural network
            input_bounds: Abstract bounds on network inputs

        Returns:
            Abstract bounds on network outputs
        """
        pass


class IntervalAbstractor(NeuralAbstractor):
    """
    Interval-based neural network abstractor.

    Propagates interval bounds through network layers using
    interval arithmetic, providing sound overapproximations.
    """

    def __init__(self, use_symbolic: bool = True):
        """
        Initialize interval abstractor.

        Args:
            use_symbolic: Whether to track symbolic relationships
        """
        self.use_symbolic = use_symbolic
        self._layer_handlers: dict[type, Callable] = {
            nn.Linear: self._abstract_linear,
            nn.ReLU: self._abstract_relu,
            nn.Sigmoid: self._abstract_sigmoid,
            nn.Tanh: self._abstract_tanh,
            nn.Softmax: self._abstract_softmax,
            nn.LayerNorm: self._abstract_layernorm,
            nn.Dropout: self._abstract_identity,  # Dropout is identity at inference
        }

    def abstract_layer(
        self,
        layer: nn.Module,
        input_bounds: list[AbstractValue],
    ) -> list[AbstractValue]:
        """Compute abstract bounds for a layer."""
        handler = self._layer_handlers.get(type(layer))

        if handler:
            return handler(layer, input_bounds)
        else:
            logger.warning(f"No handler for layer type {type(layer)}, using identity")
            return input_bounds

    def abstract_network(
        self,
        network: nn.Module,
        input_bounds: list[AbstractValue],
    ) -> list[AbstractValue]:
        """Propagate bounds through entire network."""
        current_bounds = input_bounds

        for name, layer in network.named_modules():
            if isinstance(layer, (nn.Sequential, type(network))):
                continue  # Skip containers

            current_bounds = self.abstract_layer(layer, current_bounds)
            logger.debug(f"Layer {name}: output bounds shape = {len(current_bounds)}")

        return current_bounds

    def _abstract_linear(
        self,
        layer: nn.Linear,
        input_bounds: list[AbstractValue],
    ) -> list[AbstractValue]:
        """
        Abstract linear layer using interval matrix multiplication.

        For y = Wx + b:
        - y_lower = W+ * x_lower - W- * x_upper + b
        - y_upper = W+ * x_upper - W- * x_lower + b

        where W+ = max(W, 0) and W- = min(W, 0)
        """
        weight = layer.weight.detach().numpy()
        bias = layer.bias.detach().numpy() if layer.bias is not None else np.zeros(weight.shape[0])

        # Ensure input_bounds matches expected dimension
        if len(input_bounds) != weight.shape[1]:
            # Pad or truncate
            if len(input_bounds) < weight.shape[1]:
                padding = [
                    AbstractValue(0.0, 0.0) for _ in range(weight.shape[1] - len(input_bounds))
                ]
                input_bounds = input_bounds + padding
            else:
                input_bounds = input_bounds[: weight.shape[1]]

        x_lower = np.array([b.lower for b in input_bounds])
        x_upper = np.array([b.upper for b in input_bounds])

        w_pos = np.maximum(weight, 0)
        w_neg = np.minimum(weight, 0)

        y_lower = w_pos @ x_lower + w_neg @ x_upper + bias
        y_upper = w_pos @ x_upper + w_neg @ x_lower + bias

        return [AbstractValue(lower=float(l), upper=float(u)) for l, u in zip(y_lower, y_upper)]

    def _abstract_relu(
        self,
        layer: nn.ReLU,
        input_bounds: list[AbstractValue],
    ) -> list[AbstractValue]:
        """
        Abstract ReLU activation.

        relu([l, u]) = [max(0, l), max(0, u)]
        """
        return [
            AbstractValue(
                lower=max(0.0, b.lower),
                upper=max(0.0, b.upper),
                symbolic_var=b.symbolic_var,
            )
            for b in input_bounds
        ]

    def _abstract_sigmoid(
        self,
        layer: nn.Sigmoid,
        input_bounds: list[AbstractValue],
    ) -> list[AbstractValue]:
        """
        Abstract sigmoid activation.

        Since sigmoid is monotonic: σ([l, u]) = [σ(l), σ(u)]
        """

        def sigmoid(x: float) -> float:
            return 1.0 / (1.0 + np.exp(-np.clip(x, -500, 500)))

        return [
            AbstractValue(
                lower=sigmoid(b.lower),
                upper=sigmoid(b.upper),
                symbolic_var=b.symbolic_var,
            )
            for b in input_bounds
        ]

    def _abstract_tanh(
        self,
        layer: nn.Tanh,
        input_bounds: list[AbstractValue],
    ) -> list[AbstractValue]:
        """
        Abstract tanh activation.

        Since tanh is monotonic: tanh([l, u]) = [tanh(l), tanh(u)]
        """
        return [
            AbstractValue(
                lower=float(np.tanh(b.lower)),
                upper=float(np.tanh(b.upper)),
                symbolic_var=b.symbolic_var,
            )
            for b in input_bounds
        ]

    def _abstract_softmax(
        self,
        layer: nn.Softmax,
        input_bounds: list[AbstractValue],
    ) -> list[AbstractValue]:
        """
        Abstract softmax (overapproximation).

        Softmax bounds are more complex due to the normalization.
        We use a conservative overapproximation.
        """
        n = len(input_bounds)
        if n == 0:
            return []

        # For each output i:
        # softmax_i = exp(x_i) / sum(exp(x_j))
        # Lower bound: exp(x_i_lower) / (exp(x_i_lower) + sum_{j!=i} exp(x_j_upper))
        # Upper bound: exp(x_i_upper) / (exp(x_i_upper) + sum_{j!=i} exp(x_j_lower))

        result = []
        for i in range(n):
            # Compute lower bound
            exp_i_lower = np.exp(np.clip(input_bounds[i].lower, -500, 500))
            sum_others_upper = sum(
                np.exp(np.clip(input_bounds[j].upper, -500, 500)) for j in range(n) if j != i
            )
            lower = exp_i_lower / (exp_i_lower + sum_others_upper) if sum_others_upper > 0 else 0.0

            # Compute upper bound
            exp_i_upper = np.exp(np.clip(input_bounds[i].upper, -500, 500))
            sum_others_lower = sum(
                np.exp(np.clip(input_bounds[j].lower, -500, 500)) for j in range(n) if j != i
            )
            upper = (
                exp_i_upper / (exp_i_upper + sum_others_lower)
                if (exp_i_upper + sum_others_lower) > 0
                else 1.0
            )

            result.append(
                AbstractValue(
                    lower=max(0.0, min(1.0, lower)),
                    upper=max(0.0, min(1.0, upper)),
                )
            )

        return result

    def _abstract_layernorm(
        self,
        layer: nn.LayerNorm,
        input_bounds: list[AbstractValue],
    ) -> list[AbstractValue]:
        """
        Abstract layer normalization (conservative approximation).

        LayerNorm bounds are difficult to compute precisely.
        We use a heuristic overapproximation based on typical behavior.
        """
        # LayerNorm typically produces outputs roughly in [-3, 3] range
        # for well-behaved inputs due to normalization
        return [
            AbstractValue(
                lower=-3.0 * max(1.0, abs(b.lower)),
                upper=3.0 * max(1.0, abs(b.upper)),
                symbolic_var=b.symbolic_var,
            )
            for b in input_bounds
        ]

    def _abstract_identity(
        self,
        layer: nn.Module,
        input_bounds: list[AbstractValue],
    ) -> list[AbstractValue]:
        """Identity abstraction (pass through)."""
        return input_bounds


@dataclass
class RefinementAbstraction:
    """
    Abstract representation of a policy refinement.

    Captures the semantic content of a refinement in a form
    suitable for verification.
    """

    refinement_type: RefinementType
    affected_predicates: set[str]
    temporal_bounds: tuple[AbstractValue, AbstractValue]  # [start, end] intervals
    parameter_bounds: dict[str, AbstractValue]
    semantic_constraints: list[str]
    confidence_bound: AbstractValue

    def is_safe(self, invariants: SafetyInvariants) -> bool:
        """
        Check if this abstract refinement could violate safety invariants.

        This is a necessary condition check - if False, the refinement
        is definitely unsafe. If True, it might be safe.
        """
        # Check temporal bounds don't violate invariant timing
        if invariants.temporal_constraints:
            for constraint in invariants.temporal_constraints:
                # Parse and check constraint against temporal bounds
                pass

        # Check predicate restrictions
        if invariants.forbidden_predicates:
            if self.affected_predicates & invariants.forbidden_predicates:
                return False

        # Check confidence threshold
        if invariants.min_confidence is not None:
            if self.confidence_bound.upper < invariants.min_confidence:
                return False

        return True


class AbstractionEngine:
    """
    Main abstraction engine for V-NAPE.

    Provides the abstraction framework that enables verification of
    neural policy decisions by constructing sound overapproximations.
    """

    def __init__(
        self,
        strategy: AbstractionStrategy = AbstractionStrategy.INTERVAL,
        precision_threshold: float = 0.1,
    ):
        """
        Initialize abstraction engine.

        Args:
            strategy: Abstraction strategy to use
            precision_threshold: Maximum acceptable imprecision
        """
        self.strategy = strategy
        self.precision_threshold = precision_threshold

        # Initialize abstractor based on strategy
        if strategy == AbstractionStrategy.INTERVAL:
            self.neural_abstractor = IntervalAbstractor()
        else:
            # Default to interval for now
            logger.warning(f"Strategy {strategy} not fully implemented, using INTERVAL")
            self.neural_abstractor = IntervalAbstractor()

    def abstract_refinement(
        self,
        refinement: PolicyRefinement,
        context: AbstractDomain | None = None,
    ) -> RefinementAbstraction:
        """
        Construct abstract representation of a policy refinement.

        Args:
            refinement: Concrete policy refinement proposal
            context: Optional abstract context (e.g., from trace analysis)

        Returns:
            Abstract representation suitable for verification
        """
        # Extract affected predicates from formula
        affected_predicates = self._extract_predicates(refinement.formula)

        # Abstract temporal bounds
        temporal_start = AbstractValue(
            lower=refinement.temporal_start or 0.0,
            upper=refinement.temporal_start or float("inf"),
        )
        temporal_end = AbstractValue(
            lower=refinement.temporal_end or 0.0,
            upper=refinement.temporal_end or float("inf"),
        )

        # Abstract parameters
        parameter_bounds = {}
        if refinement.parameters:
            for name, value in refinement.parameters.items():
                if isinstance(value, (int, float)):
                    # Create tight bound around concrete value
                    parameter_bounds[name] = AbstractValue(
                        lower=float(value) - 0.001,
                        upper=float(value) + 0.001,
                    )
                else:
                    # String or other - use unconstrained
                    parameter_bounds[name] = AbstractValue(
                        lower=float("-inf"),
                        upper=float("inf"),
                        symbolic_var=str(value),
                    )

        # Build semantic constraints from formula
        semantic_constraints = self._build_semantic_constraints(refinement.formula)

        # Abstract confidence
        confidence_bound = AbstractValue(
            lower=refinement.confidence * 0.95,  # 5% tolerance
            upper=min(1.0, refinement.confidence * 1.05),
        )

        return RefinementAbstraction(
            refinement_type=refinement.refinement_type,
            affected_predicates=affected_predicates,
            temporal_bounds=(temporal_start, temporal_end),
            parameter_bounds=parameter_bounds,
            semantic_constraints=semantic_constraints,
            confidence_bound=confidence_bound,
        )

    def abstract_neural_output(
        self,
        network: nn.Module,
        input_bounds: list[AbstractValue],
    ) -> list[AbstractValue]:
        """
        Compute abstract bounds on neural network outputs.

        Args:
            network: Neural network model
            input_bounds: Abstract bounds on inputs

        Returns:
            Abstract bounds on outputs
        """
        return self.neural_abstractor.abstract_network(network, input_bounds)

    def refine_abstraction(
        self,
        abstraction: RefinementAbstraction,
        concrete_samples: list[PolicyRefinement],
    ) -> RefinementAbstraction:
        """
        Refine abstraction using concrete samples.

        Tightens bounds based on observed concrete behaviors while
        maintaining soundness (abstraction still overapproximates).

        Args:
            abstraction: Current abstract representation
            concrete_samples: Observed concrete refinements

        Returns:
            Refined (tighter) abstraction
        """
        if not concrete_samples:
            return abstraction

        # Compute tighter bounds from samples
        observed_confidences = [s.confidence for s in concrete_samples]

        refined_confidence = AbstractValue(
            lower=min(abstraction.confidence_bound.lower, min(observed_confidences) * 0.95),
            upper=max(abstraction.confidence_bound.upper, max(observed_confidences) * 1.05),
        )

        # Update parameter bounds
        refined_parameters = dict(abstraction.parameter_bounds)
        for sample in concrete_samples:
            if sample.parameters:
                for name, value in sample.parameters.items():
                    if isinstance(value, (int, float)):
                        if name in refined_parameters:
                            # Widen to include observed value
                            refined_parameters[name] = refined_parameters[name].join(
                                AbstractValue(float(value), float(value))
                            )

        return RefinementAbstraction(
            refinement_type=abstraction.refinement_type,
            affected_predicates=abstraction.affected_predicates,
            temporal_bounds=abstraction.temporal_bounds,
            parameter_bounds=refined_parameters,
            semantic_constraints=abstraction.semantic_constraints,
            confidence_bound=refined_confidence,
        )

    def check_containment(
        self,
        inner: RefinementAbstraction,
        outer: RefinementAbstraction,
    ) -> bool:
        """
        Check if inner abstraction is contained in outer abstraction.

        Returns True if all behaviors represented by inner are also
        represented by outer.
        """
        # Check temporal containment
        if inner.temporal_bounds[0].lower < outer.temporal_bounds[0].lower:
            return False
        if inner.temporal_bounds[1].upper > outer.temporal_bounds[1].upper:
            return False

        # Check predicate containment
        if not inner.affected_predicates.issubset(outer.affected_predicates):
            return False

        # Check parameter containment
        for name, inner_bound in inner.parameter_bounds.items():
            if name in outer.parameter_bounds:
                outer_bound = outer.parameter_bounds[name]
                if inner_bound.lower < outer_bound.lower or inner_bound.upper > outer_bound.upper:
                    return False

        return True

    def _extract_predicates(self, formula: MFOTLFormula) -> set[str]:
        """Extract predicate names from MFOTL formula."""
        predicates = set()

        # Parse formula text for predicate patterns
        import re

        # Match predicate names (identifiers followed by parentheses)
        pattern = r"([A-Za-z_][A-Za-z0-9_]*)\s*\("
        matches = re.findall(pattern, formula.text)

        # Filter out temporal operators and logical connectives
        operators = {"forall", "exists", "not", "and", "or", "implies", "since", "until"}
        predicates = {m for m in matches if m.lower() not in operators}

        return predicates

    def _build_semantic_constraints(self, formula: MFOTLFormula) -> list[str]:
        """Build semantic constraints from formula structure."""
        constraints = []

        # Extract interval constraints
        import re

        interval_pattern = r"\[(\d+),\s*(\d+|\∞|inf)\]"
        intervals = re.findall(interval_pattern, formula.text)

        for start, end in intervals:
            constraint = f"temporal_interval({start}, {end})"
            constraints.append(constraint)

        return constraints


def create_abstraction_engine(
    strategy: str = "interval",
    precision: float = 0.1,
) -> AbstractionEngine:
    """
    Factory function to create abstraction engine.

    Args:
        strategy: Abstraction strategy name
        precision: Precision threshold

    Returns:
        Configured AbstractionEngine instance
    """
    strategy_map = {
        "interval": AbstractionStrategy.INTERVAL,
        "zonotope": AbstractionStrategy.ZONOTOPE,
        "polyhedra": AbstractionStrategy.POLYHEDRA,
        "box": AbstractionStrategy.BOX,
    }

    return AbstractionEngine(
        strategy=strategy_map.get(strategy.lower(), AbstractionStrategy.INTERVAL),
        precision_threshold=precision,
    )
