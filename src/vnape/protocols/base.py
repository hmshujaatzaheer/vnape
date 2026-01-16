"""
Base Protocol - Abstract base class for post-quantum cryptographic protocols.

This module provides the foundation for protocol definitions including:
1. State machine representation
2. Transition rules
3. MFOTL policy generation
4. Safety invariant specification

All protocol implementations should inherit from BaseProtocol and
implement the required abstract methods.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

from vnape.pqae.quantum_context import CryptographicPrimitive


class StateType(Enum):
    """Classification of protocol states."""

    INITIAL = auto()  # Starting state
    INTERMEDIATE = auto()  # Processing state
    FINAL = auto()  # Successful completion
    ERROR = auto()  # Error/failure state
    RECOVERY = auto()  # Recovery from error


@dataclass
class ProtocolState:
    """
    Representation of a protocol state.
    """

    name: str
    state_type: StateType
    description: str = ""

    # Required security properties at this state
    security_requirements: list[str] = field(default_factory=list)

    # Variables bound in this state
    bound_variables: list[str] = field(default_factory=list)

    # Timeout for this state (seconds, 0 = no timeout)
    timeout: float = 0.0

    # Whether this state requires key material
    requires_key: bool = False

    # Cryptographic primitives active in this state
    active_primitives: list[CryptographicPrimitive] = field(default_factory=list)

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        if isinstance(other, ProtocolState):
            return self.name == other.name
        return False


@dataclass
class ProtocolTransition:
    """
    Representation of a state transition in the protocol.
    """

    source: str  # Source state name
    target: str  # Target state name
    event: str  # Event that triggers transition

    # Guard condition (MFOTL formula)
    guard: str = "true"

    # Actions to perform during transition
    actions: list[str] = field(default_factory=list)

    # Variables that must be defined for this transition
    required_variables: list[str] = field(default_factory=list)

    # Variables produced by this transition
    produced_variables: list[str] = field(default_factory=list)

    # Cryptographic operations performed
    crypto_operations: list[str] = field(default_factory=list)

    # Timing constraint (max time between source and target)
    max_duration: float | None = None

    def to_mfotl(self) -> str:
        """Convert transition to MFOTL formula."""
        # Basic form: source state → eventually target state
        formula = f"{self.source}(s) → ◇[0,{self.max_duration or 'inf'}] {self.target}(s)"

        # Add guard condition
        if self.guard != "true":
            formula = f"({self.guard}) → ({formula})"

        return formula


class BaseProtocol(ABC):
    """
    Abstract base class for cryptographic protocol definitions.

    Subclasses must implement:
    - get_states(): Return all protocol states
    - get_transitions(): Return all state transitions
    - get_base_policies(): Return MFOTL security policies
    - get_safety_invariants(): Return safety invariants
    """

    def __init__(self, name: str, version: str = "1.0"):
        """
        Initialize base protocol.

        Args:
            name: Protocol name
            version: Protocol version string
        """
        self.name = name
        self.version = version
        self._states: dict[str, ProtocolState] = {}
        self._transitions: list[ProtocolTransition] = []
        self._policies: list[str] = []
        self._invariants: list[str] = []

        # Build protocol structure
        self._build()

    def _build(self):
        """Build internal protocol representation."""
        # Get states from implementation
        for state in self.get_states():
            self._states[state.name] = state

        # Get transitions
        self._transitions = self.get_transitions()

        # Validate transitions reference valid states
        for trans in self._transitions:
            if trans.source not in self._states:
                raise ValueError(f"Transition source '{trans.source}' not in states")
            if trans.target not in self._states:
                raise ValueError(f"Transition target '{trans.target}' not in states")

        # Get policies and invariants
        self._policies = self.get_base_policies()
        self._invariants = self.get_safety_invariants()

    @abstractmethod
    def get_states(self) -> list[ProtocolState]:
        """Return all states in the protocol."""
        pass

    @abstractmethod
    def get_transitions(self) -> list[ProtocolTransition]:
        """Return all transitions in the protocol."""
        pass

    @abstractmethod
    def get_base_policies(self) -> list[str]:
        """Return base MFOTL security policies."""
        pass

    @abstractmethod
    def get_safety_invariants(self) -> list[str]:
        """Return safety invariants as MFOTL formulas."""
        pass

    @abstractmethod
    def get_cryptographic_primitives(self) -> list[CryptographicPrimitive]:
        """Return cryptographic primitives used by the protocol."""
        pass

    def get_initial_states(self) -> list[ProtocolState]:
        """Get all initial states."""
        return [s for s in self._states.values() if s.state_type == StateType.INITIAL]

    def get_final_states(self) -> list[ProtocolState]:
        """Get all final (accepting) states."""
        return [s for s in self._states.values() if s.state_type == StateType.FINAL]

    def get_error_states(self) -> list[ProtocolState]:
        """Get all error states."""
        return [s for s in self._states.values() if s.state_type == StateType.ERROR]

    def get_state(self, name: str) -> ProtocolState | None:
        """Get state by name."""
        return self._states.get(name)

    def get_outgoing_transitions(self, state_name: str) -> list[ProtocolTransition]:
        """Get all transitions originating from a state."""
        return [t for t in self._transitions if t.source == state_name]

    def get_incoming_transitions(self, state_name: str) -> list[ProtocolTransition]:
        """Get all transitions leading to a state."""
        return [t for t in self._transitions if t.target == state_name]

    def generate_state_machine_policy(self) -> str:
        """
        Generate MFOTL policy enforcing valid state machine execution.

        Returns a formula that ensures:
        1. Protocol starts in initial state
        2. Each transition follows the defined rules
        3. No invalid state transitions
        """
        formulas = []

        # Initial state requirement
        initial_states = self.get_initial_states()
        if initial_states:
            initial_names = " ∨ ".join(f"{s.name}(s)" for s in initial_states)
            formulas.append(f"□[0,∞) (SessionStart(s) → ({initial_names}))")

        # Transition rules
        for trans in self._transitions:
            # Each state can only transition via defined transitions
            out_events = [t.event for t in self.get_outgoing_transitions(trans.source)]
            if out_events:
                valid_events = " ∨ ".join(f"{e}(s)" for e in out_events)
                formulas.append(
                    f"□[0,∞) ({trans.source}(s) → ({valid_events} ∨ □[0,∞) {trans.source}(s)))"
                )

        # Final state is absorbing (no further transitions)
        for final in self.get_final_states():
            formulas.append(f"□[0,∞) ({final.name}(s) → □[0,∞) {final.name}(s))")

        return " ∧ ".join(f"({f})" for f in formulas)

    def generate_liveness_policy(self) -> str:
        """
        Generate MFOTL policy ensuring protocol eventually completes.

        Returns formula ensuring eventual termination.
        """
        initial = self.get_initial_states()
        final = self.get_final_states()
        error = self.get_error_states()

        if not initial or not (final or error):
            return "true"

        # Eventually reach final or error state
        terminal_states = final + error
        terminal_disjunction = " ∨ ".join(f"{s.name}(s)" for s in terminal_states)

        # Get maximum timeout from all states
        max_timeout = max(s.timeout for s in self._states.values() if s.timeout > 0)
        if max_timeout == 0:
            max_timeout = 300  # Default 5 minute timeout

        return f"□[0,∞) (SessionStart(s) → ◇[0,{max_timeout}] ({terminal_disjunction}))"

    def generate_timing_policies(self) -> list[str]:
        """Generate timing constraint policies from transitions."""
        policies = []

        for trans in self._transitions:
            if trans.max_duration:
                policies.append(
                    f"□[0,∞) ({trans.source}(s) ∧ {trans.event}(s) → "
                    f"◇[0,{trans.max_duration}] {trans.target}(s))"
                )

        return policies

    def get_all_policies(self) -> list[str]:
        """Get all policies including generated and base policies."""
        all_policies = list(self._policies)
        all_policies.append(self.generate_state_machine_policy())
        all_policies.append(self.generate_liveness_policy())
        all_policies.extend(self.generate_timing_policies())
        all_policies.extend(self._invariants)
        return all_policies

    def validate_trace(self, events: list[tuple[str, str, float]]) -> bool:
        """
        Validate an event trace against the protocol state machine.

        Args:
            events: List of (state, event, timestamp) tuples

        Returns:
            True if trace is valid according to state machine
        """
        if not events:
            return True

        # Check initial state
        initial_state = events[0][0]
        if initial_state not in [s.name for s in self.get_initial_states()]:
            return False

        # Validate each transition
        current_state = initial_state
        for i in range(len(events) - 1):
            _, event, _ = events[i]
            next_state = events[i + 1][0]

            # Find matching transition
            valid_transition = False
            for trans in self.get_outgoing_transitions(current_state):
                if trans.event == event and trans.target == next_state:
                    valid_transition = True
                    break

            if not valid_transition:
                return False

            current_state = next_state

        return True

    def to_dict(self) -> dict[str, Any]:
        """Convert protocol to dictionary representation."""
        return {
            "name": self.name,
            "version": self.version,
            "states": [
                {
                    "name": s.name,
                    "type": s.state_type.name,
                    "description": s.description,
                    "timeout": s.timeout,
                }
                for s in self._states.values()
            ],
            "transitions": [
                {
                    "source": t.source,
                    "target": t.target,
                    "event": t.event,
                    "guard": t.guard,
                    "max_duration": t.max_duration,
                }
                for t in self._transitions
            ],
            "policies": self._policies,
            "invariants": self._invariants,
            "primitives": [p.name for p in self.get_cryptographic_primitives()],
        }

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"name='{self.name}', "
            f"states={len(self._states)}, "
            f"transitions={len(self._transitions)}, "
            f"policies={len(self._policies)})"
        )
