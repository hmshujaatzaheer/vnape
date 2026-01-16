"""
MFOTL Monitor - Runtime monitoring of Metric First-Order Temporal Logic policies.

This module implements an MFOTL monitor that:
1. Processes protocol execution traces incrementally
2. Evaluates temporal formulas against trace events
3. Produces verdicts (SATISFIED, VIOLATED, UNKNOWN) with timing information
4. Supports bounded and unbounded temporal operators

Based on:
- Basin et al. "Monitoring Metric First-Order Temporal Properties" (2015)
- Thesis Section 4.3.1: MFOTL Monitoring Architecture

MFOTL Syntax (Definition 3 from thesis):
    φ ::= r(t₁,...,tₙ) | ¬φ | φ ∧ φ | ∃x.φ | ●ᵢ φ | ○ᵢ φ | φ Sᵢ φ | φ Uᵢ φ

    Where:
    - r(t₁,...,tₙ) is a relation (predicate) over terms
    - ●ᵢ is "previous" with interval I
    - ○ᵢ is "next" with interval I
    - Sᵢ is "since" with interval I
    - Uᵢ is "until" with interval I
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class Verdict(Enum):
    """Monitoring verdict for a formula at a given timestamp."""

    SATISFIED = auto()  # Formula is definitely true
    VIOLATED = auto()  # Formula is definitely false
    UNKNOWN = auto()  # Cannot yet determine (waiting for future events)
    INCONCLUSIVE = auto()  # Not enough information to decide


@dataclass
class TimeInterval:
    """
    Time interval for metric temporal operators.
    Supports both bounded [a, b] and unbounded [a, ∞) intervals.
    """

    lower: float
    upper: float  # Use float('inf') for unbounded
    lower_inclusive: bool = True
    upper_inclusive: bool = True

    def __post_init__(self):
        if self.lower > self.upper:
            raise ValueError(f"Invalid interval: lower ({self.lower}) > upper ({self.upper})")
        if self.lower < 0:
            raise ValueError(f"Interval lower bound must be non-negative: {self.lower}")

    def contains(self, value: float) -> bool:
        """Check if a value falls within this interval."""
        lower_ok = value > self.lower or (self.lower_inclusive and value >= self.lower)
        upper_ok = value < self.upper or (self.upper_inclusive and value <= self.upper)
        return lower_ok and upper_ok

    def is_bounded(self) -> bool:
        """Check if the interval has a finite upper bound."""
        return self.upper < float("inf")

    @classmethod
    def unbounded(cls, lower: float = 0) -> TimeInterval:
        """Create an unbounded interval [lower, ∞)."""
        return cls(lower=lower, upper=float("inf"), upper_inclusive=False)

    @classmethod
    def bounded(cls, lower: float, upper: float) -> TimeInterval:
        """Create a bounded interval [lower, upper]."""
        return cls(lower=lower, upper=upper)

    @classmethod
    def point(cls, value: float) -> TimeInterval:
        """Create a point interval [value, value]."""
        return cls(lower=value, upper=value)

    def __repr__(self) -> str:
        lb = "[" if self.lower_inclusive else "("
        ub = "]" if self.upper_inclusive else ")"
        upper_str = "∞" if self.upper == float("inf") else str(self.upper)
        return f"{lb}{self.lower},{upper_str}{ub}"


class MFOTLOperator(Enum):
    """MFOTL operators."""

    # Propositional
    RELATION = auto()  # r(t₁,...,tₙ)
    TRUE = auto()  # ⊤
    FALSE = auto()  # ⊥
    NOT = auto()  # ¬
    AND = auto()  # ∧
    OR = auto()  # ∨
    IMPLIES = auto()  # →
    IFF = auto()  # ↔
    # First-order
    EXISTS = auto()  # ∃x.φ
    FORALL = auto()  # ∀x.φ
    # Temporal (past)
    PREVIOUS = auto()  # ●ᵢ (previous)
    ONCE = auto()  # ◆ᵢ (once/eventually in past)
    HISTORICALLY = auto()  # ■ᵢ (historically/always in past)
    SINCE = auto()  # Sᵢ
    # Temporal (future)
    NEXT = auto()  # ○ᵢ (next)
    EVENTUALLY = auto()  # ◇ᵢ (eventually in future)
    ALWAYS = auto()  # □ᵢ (always in future)
    UNTIL = auto()  # Uᵢ


@dataclass
class MFOTLFormula:
    """
    Abstract syntax tree node for MFOTL formulas.
    """

    operator: MFOTLOperator
    # For RELATION: predicate name and arguments
    predicate: str | None = None
    arguments: list[Any] = field(default_factory=list)
    # For unary operators (NOT, PREVIOUS, NEXT, etc.): single child
    child: MFOTLFormula | None = None
    # For binary operators (AND, OR, SINCE, UNTIL, etc.): two children
    left: MFOTLFormula | None = None
    right: MFOTLFormula | None = None
    # For quantifiers: variable name and body
    variable: str | None = None
    body: MFOTLFormula | None = None
    # For temporal operators: time interval
    interval: TimeInterval | None = None

    def is_temporal(self) -> bool:
        """Check if this is a temporal operator."""
        return self.operator in {
            MFOTLOperator.PREVIOUS,
            MFOTLOperator.ONCE,
            MFOTLOperator.HISTORICALLY,
            MFOTLOperator.SINCE,
            MFOTLOperator.NEXT,
            MFOTLOperator.EVENTUALLY,
            MFOTLOperator.ALWAYS,
            MFOTLOperator.UNTIL,
        }

    def is_future(self) -> bool:
        """Check if this is a future temporal operator."""
        return self.operator in {
            MFOTLOperator.NEXT,
            MFOTLOperator.EVENTUALLY,
            MFOTLOperator.ALWAYS,
            MFOTLOperator.UNTIL,
        }

    def is_past(self) -> bool:
        """Check if this is a past temporal operator."""
        return self.operator in {
            MFOTLOperator.PREVIOUS,
            MFOTLOperator.ONCE,
            MFOTLOperator.HISTORICALLY,
            MFOTLOperator.SINCE,
        }

    def free_variables(self) -> set[str]:
        """Get free variables in this formula."""
        fv: set[str] = set()

        if self.operator == MFOTLOperator.RELATION:
            for arg in self.arguments:
                if isinstance(arg, str) and not arg.startswith('"'):
                    fv.add(arg)
        elif self.operator in {
            MFOTLOperator.NOT,
            MFOTLOperator.PREVIOUS,
            MFOTLOperator.NEXT,
            MFOTLOperator.ONCE,
            MFOTLOperator.EVENTUALLY,
            MFOTLOperator.HISTORICALLY,
            MFOTLOperator.ALWAYS,
        }:
            if self.child:
                fv = self.child.free_variables()
        elif self.operator in {
            MFOTLOperator.AND,
            MFOTLOperator.OR,
            MFOTLOperator.IMPLIES,
            MFOTLOperator.IFF,
            MFOTLOperator.SINCE,
            MFOTLOperator.UNTIL,
        }:
            if self.left:
                fv = self.left.free_variables()
            if self.right:
                fv = fv.union(self.right.free_variables())
        elif self.operator in {MFOTLOperator.EXISTS, MFOTLOperator.FORALL}:
            if self.body:
                fv = self.body.free_variables()
            if self.variable:
                fv.discard(self.variable)

        return fv

    def __repr__(self) -> str:
        if self.operator == MFOTLOperator.RELATION:
            args = ", ".join(str(a) for a in self.arguments)
            return f"{self.predicate}({args})"
        elif self.operator == MFOTLOperator.TRUE:
            return "⊤"
        elif self.operator == MFOTLOperator.FALSE:
            return "⊥"
        elif self.operator == MFOTLOperator.NOT:
            return f"¬{self.child}"
        elif self.operator == MFOTLOperator.AND:
            return f"({self.left} ∧ {self.right})"
        elif self.operator == MFOTLOperator.OR:
            return f"({self.left} ∨ {self.right})"
        elif self.operator == MFOTLOperator.IMPLIES:
            return f"({self.left} → {self.right})"
        elif self.operator == MFOTLOperator.EXISTS:
            return f"∃{self.variable}.{self.body}"
        elif self.operator == MFOTLOperator.FORALL:
            return f"∀{self.variable}.{self.body}"
        elif self.operator == MFOTLOperator.PREVIOUS:
            return f"●{self.interval}{self.child}"
        elif self.operator == MFOTLOperator.NEXT:
            return f"○{self.interval}{self.child}"
        elif self.operator == MFOTLOperator.ONCE:
            return f"◆{self.interval}{self.child}"
        elif self.operator == MFOTLOperator.EVENTUALLY:
            return f"◇{self.interval}{self.child}"
        elif self.operator == MFOTLOperator.HISTORICALLY:
            return f"■{self.interval}{self.child}"
        elif self.operator == MFOTLOperator.ALWAYS:
            return f"□{self.interval}{self.child}"
        elif self.operator == MFOTLOperator.SINCE:
            return f"({self.left} S{self.interval} {self.right})"
        elif self.operator == MFOTLOperator.UNTIL:
            return f"({self.left} U{self.interval} {self.right})"
        return f"<{self.operator}>"


@dataclass
class TraceEvent:
    """A single event in a protocol execution trace."""

    timestamp: float
    relations: dict[str, list[tuple[Any, ...]]] = field(default_factory=dict)

    def has_relation(self, name: str, args: tuple[Any, ...]) -> bool:
        """Check if this event contains a specific relation tuple."""
        if name not in self.relations:
            return False
        return args in self.relations[name]

    def get_tuples(self, name: str) -> list[tuple[Any, ...]]:
        """Get all tuples for a given relation name."""
        return self.relations.get(name, [])


@dataclass
class MonitorState:
    """
    Internal state of the MFOTL monitor.
    Tracks information needed for incremental monitoring.
    """

    # Current position in the trace
    current_index: int = 0
    current_timestamp: float = 0.0

    # History of events (for past operators)
    event_history: list[TraceEvent] = field(default_factory=list)

    # Memoization tables for subformulas
    # Maps (formula_id, time_index) -> set of satisfying assignments
    memo: dict[tuple[int, int], set[tuple[tuple[str, Any], ...]]] = field(default_factory=dict)

    # Pending obligations for future operators
    # Maps formula_id -> list of (deadline, required_satisfaction)
    obligations: dict[int, list[tuple[float, bool]]] = field(default_factory=dict)

    # Verdict history
    verdicts: list[tuple[float, Verdict]] = field(default_factory=list)


class MFOTLParser:
    """
    Parser for MFOTL formulas from string representation.

    Supports the following syntax:
    - Relations: predicate(arg1, arg2, ...)
    - Boolean: true, false, !φ, φ && ψ, φ || ψ, φ -> ψ
    - Quantifiers: exists x. φ, forall x. φ
    - Past temporal: prev[a,b] φ, once[a,b] φ, hist[a,b] φ, φ since[a,b] ψ
    - Future temporal: next[a,b] φ, eventually[a,b] φ, always[a,b] φ, φ until[a,b] ψ
    - Unicode: ¬, ∧, ∨, →, ∃, ∀, ●, ○, ◆, ◇, ■, □, S, U
    """

    # Token patterns
    INTERVAL_PATTERN = re.compile(r"\[(\d+(?:\.\d+)?),(\d+(?:\.\d+)?|∞|inf)\]")
    RELATION_PATTERN = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)")
    VARIABLE_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")

    def __init__(self):
        self.pos = 0
        self.text = ""

    def parse(self, text: str) -> MFOTLFormula:
        """Parse an MFOTL formula from string."""
        self.text = text.strip()
        self.pos = 0
        result = self._parse_formula()
        self._skip_whitespace()
        if self.pos < len(self.text):
            raise ValueError(
                f"Unexpected characters at position {self.pos}: {self.text[self.pos:]}"
            )
        return result

    def _skip_whitespace(self):
        while self.pos < len(self.text) and self.text[self.pos].isspace():
            self.pos += 1

    def _peek(self, n: int = 1) -> str:
        return self.text[self.pos : self.pos + n]

    def _consume(self, expected: str) -> bool:
        self._skip_whitespace()
        if self.text[self.pos : self.pos + len(expected)] == expected:
            self.pos += len(expected)
            return True
        return False

    def _parse_formula(self) -> MFOTLFormula:
        """Parse a formula (handles binary operators)."""
        self._skip_whitespace()
        left = self._parse_unary()

        self._skip_whitespace()

        # Check for binary operators
        if self._consume("&&") or self._consume("∧"):
            right = self._parse_formula()
            return MFOTLFormula(operator=MFOTLOperator.AND, left=left, right=right)
        elif self._consume("||") or self._consume("∨"):
            right = self._parse_formula()
            return MFOTLFormula(operator=MFOTLOperator.OR, left=left, right=right)
        elif self._consume("->") or self._consume("→"):
            right = self._parse_formula()
            return MFOTLFormula(operator=MFOTLOperator.IMPLIES, left=left, right=right)
        elif self._consume("<->") or self._consume("↔"):
            right = self._parse_formula()
            return MFOTLFormula(operator=MFOTLOperator.IFF, left=left, right=right)
        elif self._peek(5).lower() == "since" or self._consume("S"):
            interval = self._parse_interval()
            right = self._parse_unary()
            return MFOTLFormula(
                operator=MFOTLOperator.SINCE, left=left, right=right, interval=interval
            )
        elif self._peek(5).lower() == "until" or self._consume("U"):
            interval = self._parse_interval()
            right = self._parse_unary()
            return MFOTLFormula(
                operator=MFOTLOperator.UNTIL, left=left, right=right, interval=interval
            )

        return left

    def _parse_unary(self) -> MFOTLFormula:
        """Parse unary formulas (negation, temporal, quantifiers)."""
        self._skip_whitespace()

        # Negation
        if self._consume("!") or self._consume("¬") or self._consume("not "):
            child = self._parse_unary()
            return MFOTLFormula(operator=MFOTLOperator.NOT, child=child)

        # Quantifiers
        if self._consume("exists ") or self._consume("∃"):
            var = self._parse_variable()
            self._consume(".")
            body = self._parse_formula()
            return MFOTLFormula(operator=MFOTLOperator.EXISTS, variable=var, body=body)
        if self._consume("forall ") or self._consume("∀"):
            var = self._parse_variable()
            self._consume(".")
            body = self._parse_formula()
            return MFOTLFormula(operator=MFOTLOperator.FORALL, variable=var, body=body)

        # Past temporal operators
        if self._consume("prev") or self._consume("●"):
            interval = self._parse_interval()
            child = self._parse_unary()
            return MFOTLFormula(operator=MFOTLOperator.PREVIOUS, child=child, interval=interval)
        if self._consume("once") or self._consume("◆"):
            interval = self._parse_interval()
            child = self._parse_unary()
            return MFOTLFormula(operator=MFOTLOperator.ONCE, child=child, interval=interval)
        if self._consume("hist") or self._consume("■"):
            interval = self._parse_interval()
            child = self._parse_unary()
            return MFOTLFormula(operator=MFOTLOperator.HISTORICALLY, child=child, interval=interval)

        # Future temporal operators
        if self._consume("next") or self._consume("○"):
            interval = self._parse_interval()
            child = self._parse_unary()
            return MFOTLFormula(operator=MFOTLOperator.NEXT, child=child, interval=interval)
        if self._consume("eventually") or self._consume("◇"):
            interval = self._parse_interval()
            child = self._parse_unary()
            return MFOTLFormula(operator=MFOTLOperator.EVENTUALLY, child=child, interval=interval)
        if self._consume("always") or self._consume("□"):
            interval = self._parse_interval()
            child = self._parse_unary()
            return MFOTLFormula(operator=MFOTLOperator.ALWAYS, child=child, interval=interval)

        return self._parse_atom()

    def _parse_atom(self) -> MFOTLFormula:
        """Parse atomic formulas (relations, true, false, parenthesized)."""
        self._skip_whitespace()

        # Parenthesized formula
        if self._consume("("):
            formula = self._parse_formula()
            if not self._consume(")"):
                raise ValueError(f"Expected ')' at position {self.pos}")
            return formula

        # Boolean constants
        if self._consume("true") or self._consume("⊤"):
            return MFOTLFormula(operator=MFOTLOperator.TRUE)
        if self._consume("false") or self._consume("⊥"):
            return MFOTLFormula(operator=MFOTLOperator.FALSE)

        # Relation
        return self._parse_relation()

    def _parse_relation(self) -> MFOTLFormula:
        """Parse a relation predicate."""
        self._skip_whitespace()

        # Match predicate name
        match = self.RELATION_PATTERN.match(self.text[self.pos :])
        if not match:
            raise ValueError(
                f"Expected relation at position {self.pos}: {self.text[self.pos:self.pos+20]}"
            )

        predicate = match.group(1)
        args_str = match.group(2)
        self.pos += match.end()

        # Parse arguments
        arguments = []
        if args_str.strip():
            for arg in args_str.split(","):
                arg = arg.strip()
                if arg.startswith('"') and arg.endswith('"'):
                    arguments.append(arg)
                elif arg.isdigit() or (arg.startswith("-") and arg[1:].isdigit()):
                    arguments.append(int(arg))
                elif self._is_float(arg):
                    arguments.append(float(arg))
                else:
                    arguments.append(arg)  # Variable

        return MFOTLFormula(
            operator=MFOTLOperator.RELATION, predicate=predicate, arguments=arguments
        )

    def _parse_interval(self) -> TimeInterval:
        """Parse a time interval [a, b]."""
        self._skip_whitespace()

        match = self.INTERVAL_PATTERN.match(self.text[self.pos :])
        if not match:
            # Default to [0, ∞)
            return TimeInterval.unbounded()

        self.pos += match.end()
        lower = float(match.group(1))
        upper_str = match.group(2)
        upper = float("inf") if upper_str in ("∞", "inf") else float(upper_str)

        return TimeInterval(lower=lower, upper=upper)

    def _parse_variable(self) -> str:
        """Parse a variable name."""
        self._skip_whitespace()

        start = self.pos
        while self.pos < len(self.text) and (
            self.text[self.pos].isalnum() or self.text[self.pos] == "_"
        ):
            self.pos += 1

        var = self.text[start : self.pos]
        if not self.VARIABLE_PATTERN.match(var):
            raise ValueError(f"Invalid variable name: {var}")

        return var

    def _is_float(self, s: str) -> bool:
        try:
            float(s)
            return True
        except ValueError:
            return False


@dataclass
class MonitoringResult:
    """Result of monitoring a formula against a trace event."""

    verdict: Verdict
    timestamp: float
    satisfying_assignments: set[tuple[tuple[str, Any], ...]] = field(default_factory=set)
    explanation: str | None = None
    subformula_verdicts: dict[str, Verdict] = field(default_factory=dict)


class MFOTLMonitor:
    """
    MFOTL Monitor for runtime policy enforcement.

    Implements incremental monitoring algorithm based on:
    - Basin et al. "Monitoring Metric First-Order Temporal Properties" (2015)

    The monitor processes events incrementally and produces verdicts
    as soon as they can be determined.
    """

    def __init__(
        self,
        formula: str | MFOTLFormula,
        domain: dict[str, set[Any]] | None = None,
    ):
        """
        Initialize the MFOTL monitor.

        Args:
            formula: The MFOTL formula to monitor (string or AST)
            domain: Domain for quantified variables {var_name: {possible_values}}
        """
        if isinstance(formula, str):
            parser = MFOTLParser()
            self.formula = parser.parse(formula)
        else:
            self.formula = formula

        self.domain = domain or {}
        self.state = MonitorState()
        self._formula_ids: dict[int, MFOTLFormula] = {}
        self._assign_formula_ids(self.formula)

    def _assign_formula_ids(self, formula: MFOTLFormula, counter: list[int] = None) -> int:
        """Assign unique IDs to all subformulas for memoization."""
        if counter is None:
            counter = [0]

        fid = counter[0]
        counter[0] += 1
        self._formula_ids[fid] = formula

        if formula.child:
            self._assign_formula_ids(formula.child, counter)
        if formula.left:
            self._assign_formula_ids(formula.left, counter)
        if formula.right:
            self._assign_formula_ids(formula.right, counter)
        if formula.body:
            self._assign_formula_ids(formula.body, counter)

        return fid

    def process_event(self, event: TraceEvent) -> MonitoringResult:
        """
        Process a single trace event and update monitor state.

        Args:
            event: The trace event to process

        Returns:
            MonitoringResult with verdict and satisfying assignments
        """
        self.state.event_history.append(event)
        self.state.current_timestamp = event.timestamp
        self.state.current_index = len(self.state.event_history) - 1

        # Evaluate formula
        satisfying = self._evaluate(self.formula, self.state.current_index, {})  # Empty assignment

        # Determine verdict
        if not self.formula.free_variables():
            # Closed formula
            if satisfying:
                verdict = Verdict.SATISFIED
            elif self._has_pending_future_obligations():
                verdict = Verdict.UNKNOWN
            else:
                verdict = Verdict.VIOLATED
        else:
            # Open formula - check if all/some assignments satisfy
            if satisfying:
                verdict = Verdict.SATISFIED
            else:
                verdict = Verdict.UNKNOWN

        self.state.verdicts.append((event.timestamp, verdict))

        return MonitoringResult(
            verdict=verdict,
            timestamp=event.timestamp,
            satisfying_assignments=satisfying,
            explanation=self._generate_explanation(verdict, satisfying),
        )

    def _evaluate(
        self, formula: MFOTLFormula, time_idx: int, assignment: dict[str, Any]
    ) -> set[tuple[tuple[str, Any], ...]]:
        """
        Evaluate a formula at a given time point with an assignment.

        Returns: Set of satisfying extensions to the assignment
        """
        if time_idx < 0 or time_idx >= len(self.state.event_history):
            return set()

        event = self.state.event_history[time_idx]

        if formula.operator == MFOTLOperator.TRUE:
            return {tuple(sorted(assignment.items()))}

        elif formula.operator == MFOTLOperator.FALSE:
            return set()

        elif formula.operator == MFOTLOperator.RELATION:
            return self._evaluate_relation(formula, event, assignment)

        elif formula.operator == MFOTLOperator.NOT:
            child_sat = self._evaluate(formula.child, time_idx, assignment)
            if not child_sat:
                return {tuple(sorted(assignment.items()))}
            return set()

        elif formula.operator == MFOTLOperator.AND:
            left_sat = self._evaluate(formula.left, time_idx, assignment)
            result = set()
            for left_assign in left_sat:
                extended = dict(assignment)
                extended.update(dict(left_assign))
                right_sat = self._evaluate(formula.right, time_idx, extended)
                result.update(right_sat)
            return result

        elif formula.operator == MFOTLOperator.OR:
            left_sat = self._evaluate(formula.left, time_idx, assignment)
            right_sat = self._evaluate(formula.right, time_idx, assignment)
            return left_sat.union(right_sat)

        elif formula.operator == MFOTLOperator.IMPLIES:
            # φ → ψ ≡ ¬φ ∨ ψ
            left_sat = self._evaluate(formula.left, time_idx, assignment)
            if not left_sat:
                return {tuple(sorted(assignment.items()))}
            right_sat = self._evaluate(formula.right, time_idx, assignment)
            return right_sat

        elif formula.operator == MFOTLOperator.EXISTS:
            return self._evaluate_exists(formula, time_idx, assignment)

        elif formula.operator == MFOTLOperator.FORALL:
            return self._evaluate_forall(formula, time_idx, assignment)

        elif formula.operator == MFOTLOperator.PREVIOUS:
            return self._evaluate_previous(formula, time_idx, assignment)

        elif formula.operator == MFOTLOperator.NEXT:
            return self._evaluate_next(formula, time_idx, assignment)

        elif formula.operator == MFOTLOperator.ONCE:
            return self._evaluate_once(formula, time_idx, assignment)

        elif formula.operator == MFOTLOperator.EVENTUALLY:
            return self._evaluate_eventually(formula, time_idx, assignment)

        elif formula.operator == MFOTLOperator.HISTORICALLY:
            return self._evaluate_historically(formula, time_idx, assignment)

        elif formula.operator == MFOTLOperator.ALWAYS:
            return self._evaluate_always(formula, time_idx, assignment)

        elif formula.operator == MFOTLOperator.SINCE:
            return self._evaluate_since(formula, time_idx, assignment)

        elif formula.operator == MFOTLOperator.UNTIL:
            return self._evaluate_until(formula, time_idx, assignment)

        return set()

    def _evaluate_relation(
        self, formula: MFOTLFormula, event: TraceEvent, assignment: dict[str, Any]
    ) -> set[tuple[tuple[str, Any], ...]]:
        """Evaluate a relation predicate against an event."""
        result = set()
        tuples = event.get_tuples(formula.predicate)

        for tup in tuples:
            if len(tup) != len(formula.arguments):
                continue

            extended = dict(assignment)
            match = True

            for i, arg in enumerate(formula.arguments):
                if isinstance(arg, str) and not arg.startswith('"'):
                    # Variable
                    if arg in extended:
                        if extended[arg] != tup[i]:
                            match = False
                            break
                    else:
                        extended[arg] = tup[i]
                else:
                    # Constant
                    if arg != tup[i]:
                        match = False
                        break

            if match:
                result.add(tuple(sorted(extended.items())))

        return result

    def _evaluate_exists(
        self, formula: MFOTLFormula, time_idx: int, assignment: dict[str, Any]
    ) -> set[tuple[tuple[str, Any], ...]]:
        """Evaluate existential quantifier."""
        var = formula.variable
        domain_values = self.domain.get(var, set())

        result = set()
        for value in domain_values:
            extended = dict(assignment)
            extended[var] = value
            body_sat = self._evaluate(formula.body, time_idx, extended)
            for sat in body_sat:
                # Remove the quantified variable from result
                filtered = tuple((k, v) for k, v in sat if k != var)
                result.add(filtered)

        # Also try evaluating without domain restriction
        body_sat = self._evaluate(formula.body, time_idx, assignment)
        for sat in body_sat:
            filtered = tuple((k, v) for k, v in sat if k != var)
            result.add(filtered)

        return result

    def _evaluate_forall(
        self, formula: MFOTLFormula, time_idx: int, assignment: dict[str, Any]
    ) -> set[tuple[tuple[str, Any], ...]]:
        """Evaluate universal quantifier."""
        var = formula.variable
        domain_values = self.domain.get(var, set())

        if not domain_values:
            # Empty domain - vacuously true
            return {tuple(sorted(assignment.items()))}

        all_satisfied = True
        for value in domain_values:
            extended = dict(assignment)
            extended[var] = value
            body_sat = self._evaluate(formula.body, time_idx, extended)
            if not body_sat:
                all_satisfied = False
                break

        if all_satisfied:
            return {tuple(sorted(assignment.items()))}
        return set()

    def _evaluate_previous(
        self, formula: MFOTLFormula, time_idx: int, assignment: dict[str, Any]
    ) -> set[tuple[tuple[str, Any], ...]]:
        """Evaluate previous operator ●[a,b]φ."""
        if time_idx == 0:
            return set()

        interval = formula.interval or TimeInterval.unbounded()
        current_time = self.state.event_history[time_idx].timestamp
        prev_time = self.state.event_history[time_idx - 1].timestamp

        time_diff = current_time - prev_time
        if interval.contains(time_diff):
            return self._evaluate(formula.child, time_idx - 1, assignment)

        return set()

    def _evaluate_next(
        self, formula: MFOTLFormula, time_idx: int, assignment: dict[str, Any]
    ) -> set[tuple[tuple[str, Any], ...]]:
        """Evaluate next operator ○[a,b]φ."""
        if time_idx >= len(self.state.event_history) - 1:
            # Future event not yet observed
            return set()

        interval = formula.interval or TimeInterval.unbounded()
        current_time = self.state.event_history[time_idx].timestamp
        next_time = self.state.event_history[time_idx + 1].timestamp

        time_diff = next_time - current_time
        if interval.contains(time_diff):
            return self._evaluate(formula.child, time_idx + 1, assignment)

        return set()

    def _evaluate_once(
        self, formula: MFOTLFormula, time_idx: int, assignment: dict[str, Any]
    ) -> set[tuple[tuple[str, Any], ...]]:
        """Evaluate once operator ◆[a,b]φ (past eventually)."""
        interval = formula.interval or TimeInterval.unbounded()
        current_time = self.state.event_history[time_idx].timestamp

        result = set()
        for past_idx in range(time_idx + 1):
            past_time = self.state.event_history[past_idx].timestamp
            time_diff = current_time - past_time

            if interval.contains(time_diff):
                child_sat = self._evaluate(formula.child, past_idx, assignment)
                result.update(child_sat)

        return result

    def _evaluate_eventually(
        self, formula: MFOTLFormula, time_idx: int, assignment: dict[str, Any]
    ) -> set[tuple[tuple[str, Any], ...]]:
        """Evaluate eventually operator ◇[a,b]φ (future eventually)."""
        interval = formula.interval or TimeInterval.unbounded()
        current_time = self.state.event_history[time_idx].timestamp

        result = set()
        for future_idx in range(time_idx, len(self.state.event_history)):
            future_time = self.state.event_history[future_idx].timestamp
            time_diff = future_time - current_time

            if time_diff > interval.upper:
                break

            if interval.contains(time_diff):
                child_sat = self._evaluate(formula.child, future_idx, assignment)
                result.update(child_sat)

        return result

    def _evaluate_historically(
        self, formula: MFOTLFormula, time_idx: int, assignment: dict[str, Any]
    ) -> set[tuple[tuple[str, Any], ...]]:
        """Evaluate historically operator ■[a,b]φ (past always)."""
        interval = formula.interval or TimeInterval.unbounded()
        current_time = self.state.event_history[time_idx].timestamp

        for past_idx in range(time_idx + 1):
            past_time = self.state.event_history[past_idx].timestamp
            time_diff = current_time - past_time

            if interval.contains(time_diff):
                child_sat = self._evaluate(formula.child, past_idx, assignment)
                if not child_sat:
                    return set()

        return {tuple(sorted(assignment.items()))}

    def _evaluate_always(
        self, formula: MFOTLFormula, time_idx: int, assignment: dict[str, Any]
    ) -> set[tuple[tuple[str, Any], ...]]:
        """Evaluate always operator □[a,b]φ (future always)."""
        interval = formula.interval or TimeInterval.unbounded()
        current_time = self.state.event_history[time_idx].timestamp

        for future_idx in range(time_idx, len(self.state.event_history)):
            future_time = self.state.event_history[future_idx].timestamp
            time_diff = future_time - current_time

            if time_diff > interval.upper:
                break

            if interval.contains(time_diff):
                child_sat = self._evaluate(formula.child, future_idx, assignment)
                if not child_sat:
                    return set()

        return {tuple(sorted(assignment.items()))}

    def _evaluate_since(
        self, formula: MFOTLFormula, time_idx: int, assignment: dict[str, Any]
    ) -> set[tuple[tuple[str, Any], ...]]:
        """Evaluate since operator φ S[a,b] ψ."""
        interval = formula.interval or TimeInterval.unbounded()
        current_time = self.state.event_history[time_idx].timestamp

        result = set()

        for past_idx in range(time_idx + 1):
            past_time = self.state.event_history[past_idx].timestamp
            time_diff = current_time - past_time

            if not interval.contains(time_diff):
                continue

            # Check if ψ holds at past_idx
            right_sat = self._evaluate(formula.right, past_idx, assignment)

            for right_assign in right_sat:
                extended = dict(right_assign)

                # Check if φ holds at all points between past_idx and time_idx
                all_phi = True
                for between_idx in range(past_idx + 1, time_idx + 1):
                    phi_sat = self._evaluate(formula.left, between_idx, extended)
                    if not phi_sat:
                        all_phi = False
                        break

                if all_phi:
                    result.add(right_assign)

        return result

    def _evaluate_until(
        self, formula: MFOTLFormula, time_idx: int, assignment: dict[str, Any]
    ) -> set[tuple[tuple[str, Any], ...]]:
        """Evaluate until operator φ U[a,b] ψ."""
        interval = formula.interval or TimeInterval.unbounded()
        current_time = self.state.event_history[time_idx].timestamp

        result = set()

        for future_idx in range(time_idx, len(self.state.event_history)):
            future_time = self.state.event_history[future_idx].timestamp
            time_diff = future_time - current_time

            if time_diff > interval.upper:
                break

            if not interval.contains(time_diff):
                continue

            # Check if ψ holds at future_idx
            right_sat = self._evaluate(formula.right, future_idx, assignment)

            for right_assign in right_sat:
                extended = dict(right_assign)

                # Check if φ holds at all points between time_idx and future_idx
                all_phi = True
                for between_idx in range(time_idx, future_idx):
                    phi_sat = self._evaluate(formula.left, between_idx, extended)
                    if not phi_sat:
                        all_phi = False
                        break

                if all_phi:
                    result.add(right_assign)

        return result

    def _has_pending_future_obligations(self) -> bool:
        """Check if there are pending future obligations."""
        if self.formula.is_future():
            if not self.formula.interval or not self.formula.interval.is_bounded():
                return True

            current_time = self.state.current_timestamp
            deadline = current_time + self.formula.interval.upper

            if len(self.state.event_history) > 0:
                last_time = self.state.event_history[-1].timestamp
                if last_time < deadline:
                    return True

        return False

    def _generate_explanation(
        self, verdict: Verdict, satisfying: set[tuple[tuple[str, Any], ...]]
    ) -> str:
        """Generate a human-readable explanation of the verdict."""
        if verdict == Verdict.SATISFIED:
            if satisfying:
                assigns = [dict(s) for s in list(satisfying)[:3]]
                return f"Formula satisfied with assignments: {assigns}"
            return "Formula satisfied"
        elif verdict == Verdict.VIOLATED:
            return "Formula violated - no satisfying assignment found"
        elif verdict == Verdict.UNKNOWN:
            return "Cannot yet determine - waiting for future events"
        else:
            return "Verdict inconclusive"

    def reset(self):
        """Reset the monitor state."""
        self.state = MonitorState()

    def get_verdict_history(self) -> list[tuple[float, Verdict]]:
        """Get the history of verdicts."""
        return self.state.verdicts.copy()
