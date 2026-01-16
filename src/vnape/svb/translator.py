"""
MFOTL to Z3 Translator

Translates Metric First-Order Temporal Logic formulas to Z3 SMT constraints.

The translation process:
1. Parse MFOTL formula into AST
2. Handle temporal operators by unrolling or approximation
3. Translate first-order quantifiers to Z3 equivalents
4. Handle time intervals with arithmetic constraints

Limitations:
- Unbounded temporal operators are approximated with finite bounds
- Some complex nesting patterns may require over-approximation

Reference: Cousot & Cousot (1977) for abstraction principles
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

try:
    import z3
except ImportError:
    z3 = None  # Handle optional dependency


class OperatorType(Enum):
    """Types of MFOTL operators."""

    # Propositional
    NOT = auto()
    AND = auto()
    OR = auto()
    IMPLIES = auto()

    # Quantifiers
    FORALL = auto()
    EXISTS = auto()

    # Past temporal
    PREVIOUS = auto()  # ●[I]
    SINCE = auto()  # S[I]
    ONCE = auto()  # ◆[I]
    HISTORICALLY = auto()  # ■[I]

    # Future temporal
    NEXT = auto()  # ○[I]
    UNTIL = auto()  # U[I]
    EVENTUALLY = auto()  # ◇[I]
    ALWAYS = auto()  # □[I]

    # Predicates
    PREDICATE = auto()
    RELATION = auto()


@dataclass
class TimeInterval:
    """Represents a time interval [lower, upper]."""

    lower: int
    upper: int | None  # None means infinity

    def __str__(self) -> str:
        if self.upper is None:
            return f"[{self.lower},∞)"
        return f"[{self.lower},{self.upper}]"


@dataclass
class ASTNode:
    """AST node for MFOTL formulas."""

    operator: OperatorType
    children: list[ASTNode]
    interval: TimeInterval | None = None
    name: str | None = None  # For predicates and quantified variables
    args: list[str] | None = None  # For predicate arguments


class MFOTLParser:
    """
    Parser for MFOTL formulas.

    Supports the following syntax:
    - Propositional: ¬, ∧, ∨, →
    - Quantifiers: ∀x., ∃x.
    - Temporal: □[a,b], ◇[a,b], ○[a,b], ●[a,b], U[a,b], S[a,b]
    - Predicates: P(x, y, ...)
    - Comparisons: x = y, x < y
    """

    # Operator mappings
    UNARY_TEMPORAL = {
        "□": OperatorType.ALWAYS,
        "◇": OperatorType.EVENTUALLY,
        "○": OperatorType.NEXT,
        "●": OperatorType.PREVIOUS,
        "◆": OperatorType.ONCE,
        "■": OperatorType.HISTORICALLY,
    }

    BINARY_TEMPORAL = {
        "U": OperatorType.UNTIL,
        "S": OperatorType.SINCE,
    }

    def __init__(self):
        self._pos = 0
        self._formula = ""

    def parse(self, formula: str) -> ASTNode:
        """Parse an MFOTL formula string into an AST."""
        self._formula = formula.strip()
        self._pos = 0
        return self._parse_formula()

    def _parse_formula(self) -> ASTNode:
        """Parse a complete formula."""
        self._skip_whitespace()

        # Check for quantifiers
        if self._peek() in ("∀", "∃"):
            return self._parse_quantifier()

        return self._parse_implication()

    def _parse_quantifier(self) -> ASTNode:
        """Parse quantified formula."""
        quant = self._consume()
        op = OperatorType.FORALL if quant == "∀" else OperatorType.EXISTS

        self._skip_whitespace()
        var = self._parse_identifier()

        self._skip_whitespace()
        self._expect(".")

        body = self._parse_formula()

        return ASTNode(operator=op, children=[body], name=var)

    def _parse_implication(self) -> ASTNode:
        """Parse implication (lowest precedence binary operator)."""
        left = self._parse_or()

        self._skip_whitespace()
        if self._peek() == "→":
            self._consume()
            right = self._parse_implication()
            return ASTNode(operator=OperatorType.IMPLIES, children=[left, right])

        return left

    def _parse_or(self) -> ASTNode:
        """Parse disjunction."""
        left = self._parse_and()

        self._skip_whitespace()
        while self._peek() == "∨":
            self._consume()
            right = self._parse_and()
            left = ASTNode(operator=OperatorType.OR, children=[left, right])

        return left

    def _parse_and(self) -> ASTNode:
        """Parse conjunction."""
        left = self._parse_unary()

        self._skip_whitespace()
        while self._peek() == "∧":
            self._consume()
            right = self._parse_unary()
            left = ASTNode(operator=OperatorType.AND, children=[left, right])

        return left

    def _parse_unary(self) -> ASTNode:
        """Parse unary operators (negation, temporal)."""
        self._skip_whitespace()

        # Negation
        if self._peek() == "¬":
            self._consume()
            child = self._parse_unary()
            return ASTNode(operator=OperatorType.NOT, children=[child])

        # Temporal operators
        if self._peek() in self.UNARY_TEMPORAL:
            op_char = self._consume()
            op = self.UNARY_TEMPORAL[op_char]
            interval = self._parse_interval()
            child = self._parse_unary()
            return ASTNode(operator=op, children=[child], interval=interval)

        return self._parse_primary()

    def _parse_interval(self) -> TimeInterval:
        """Parse a time interval [a,b] or [a,∞)."""
        self._skip_whitespace()
        if self._peek() != "[":
            return TimeInterval(0, None)  # Default interval

        self._consume()  # [

        # Parse lower bound
        lower = self._parse_number()

        self._skip_whitespace()
        self._expect(",")

        # Parse upper bound
        self._skip_whitespace()
        if self._peek() == "∞":
            self._consume()
            upper = None
        else:
            upper = self._parse_number()

        self._skip_whitespace()
        if self._peek() in ("]", ")"):
            self._consume()

        return TimeInterval(lower, upper)

    def _parse_primary(self) -> ASTNode:
        """Parse primary expressions (predicates, parenthesized formulas)."""
        self._skip_whitespace()

        # Parenthesized formula
        if self._peek() == "(":
            self._consume()
            node = self._parse_formula()
            self._skip_whitespace()
            self._expect(")")
            return node

        # Predicate
        name = self._parse_identifier()
        self._skip_whitespace()

        if self._peek() == "(":
            # Predicate with arguments
            self._consume()
            args = self._parse_args()
            self._expect(")")
            return ASTNode(operator=OperatorType.PREDICATE, children=[], name=name, args=args)

        # Simple identifier (variable or constant)
        return ASTNode(operator=OperatorType.PREDICATE, children=[], name=name, args=[])

    def _parse_args(self) -> list[str]:
        """Parse predicate arguments."""
        args = []
        self._skip_whitespace()

        if self._peek() == ")":
            return args

        args.append(self._parse_identifier())

        while True:
            self._skip_whitespace()
            if self._peek() != ",":
                break
            self._consume()
            self._skip_whitespace()
            args.append(self._parse_identifier())

        return args

    def _parse_identifier(self) -> str:
        """Parse an identifier (variable or predicate name)."""
        start = self._pos
        while self._pos < len(self._formula) and (
            self._formula[self._pos].isalnum() or self._formula[self._pos] in "_'"
        ):
            self._pos += 1
        return self._formula[start : self._pos]

    def _parse_number(self) -> int:
        """Parse an integer."""
        start = self._pos
        while self._pos < len(self._formula) and self._formula[self._pos].isdigit():
            self._pos += 1
        return int(self._formula[start : self._pos])

    def _skip_whitespace(self) -> None:
        """Skip whitespace characters."""
        while self._pos < len(self._formula) and self._formula[self._pos].isspace():
            self._pos += 1

    def _peek(self) -> str:
        """Peek at current character."""
        if self._pos >= len(self._formula):
            return ""
        return self._formula[self._pos]

    def _consume(self) -> str:
        """Consume and return current character."""
        char = self._peek()
        self._pos += 1
        return char

    def _expect(self, char: str) -> None:
        """Expect and consume a specific character."""
        actual = self._consume()
        if actual != char:
            raise SyntaxError(f"Expected '{char}' but got '{actual}' at position {self._pos}")


class MFOTLToZ3Translator:
    """
    Translates MFOTL formulas to Z3 constraints.

    The translation uses bounded model checking approach:
    - Temporal operators are unrolled for a bounded number of steps
    - Time variables are represented as Z3 integers
    - Predicates are represented as uninterpreted functions

    Args:
        max_time_steps: Maximum time steps for temporal unrolling
        use_approximation: Use over-approximation for soundness

    Example:
        >>> translator = MFOTLToZ3Translator(max_time_steps=100)
        >>> z3_formula = translator.translate("□[0,10] (Active(s) → HasKey(s))")
        >>> solver = z3.Solver()
        >>> solver.add(z3_formula)
        >>> result = solver.check()
    """

    def __init__(self, max_time_steps: int = 1000, use_approximation: bool = True):
        if z3 is None:
            raise ImportError("z3-solver is required for SVB. Install with: pip install z3-solver")

        self.max_time_steps = max_time_steps
        self.use_approximation = use_approximation
        self.parser = MFOTLParser()

        # Z3 sorts
        self.time_sort = z3.IntSort()
        self.value_sort = z3.IntSort()  # Generic value sort

        # Predicate functions (lazily created)
        self._predicates: dict[str, z3.FuncDeclRef] = {}

        # Time variable
        self.time_var = z3.Int("t")

    def translate(self, formula: str | ASTNode, time_var: z3.ArithRef | None = None) -> z3.BoolRef:
        """
        Translate an MFOTL formula to Z3.

        Args:
            formula: MFOTL formula string or AST
            time_var: Current time variable (for recursive calls)

        Returns:
            Z3 boolean formula
        """
        if isinstance(formula, str):
            ast = self.parser.parse(formula)
        else:
            ast = formula

        t = time_var if time_var is not None else self.time_var
        return self._translate_node(ast, t)

    def _translate_node(self, node: ASTNode, t: z3.ArithRef) -> z3.BoolRef:
        """Translate an AST node to Z3."""
        op = node.operator

        # Propositional operators
        if op == OperatorType.NOT:
            return z3.Not(self._translate_node(node.children[0], t))

        if op == OperatorType.AND:
            left = self._translate_node(node.children[0], t)
            right = self._translate_node(node.children[1], t)
            return z3.And(left, right)

        if op == OperatorType.OR:
            left = self._translate_node(node.children[0], t)
            right = self._translate_node(node.children[1], t)
            return z3.Or(left, right)

        if op == OperatorType.IMPLIES:
            left = self._translate_node(node.children[0], t)
            right = self._translate_node(node.children[1], t)
            return z3.Implies(left, right)

        # Quantifiers
        if op == OperatorType.FORALL:
            var = z3.Int(node.name)
            body = self._translate_node(node.children[0], t)
            return z3.ForAll([var], body)

        if op == OperatorType.EXISTS:
            var = z3.Int(node.name)
            body = self._translate_node(node.children[0], t)
            return z3.Exists([var], body)

        # Temporal operators
        if op == OperatorType.ALWAYS:
            return self._translate_always(node, t)

        if op == OperatorType.EVENTUALLY:
            return self._translate_eventually(node, t)

        if op == OperatorType.NEXT:
            return self._translate_next(node, t)

        if op == OperatorType.PREVIOUS:
            return self._translate_previous(node, t)

        # Predicates
        if op == OperatorType.PREDICATE:
            return self._translate_predicate(node, t)

        raise ValueError(f"Unsupported operator: {op}")

    def _translate_always(self, node: ASTNode, t: z3.ArithRef) -> z3.BoolRef:
        """
        Translate □[a,b] φ (always within interval).

        □[a,b] φ ≡ ∀t'. (t + a ≤ t' ≤ t + b) → φ(t')
        """
        interval = node.interval or TimeInterval(0, None)
        child = node.children[0]

        # Create time variable for the interval
        t_prime = z3.Int(f"t_{id(node)}")

        # Translate child at t_prime
        child_at_t_prime = self._translate_node(child, t_prime)

        # Build interval constraint
        lower = t + interval.lower
        if interval.upper is not None:
            upper = t + interval.upper
            interval_constraint = z3.And(t_prime >= lower, t_prime <= upper)
        else:
            # For unbounded, use max_time_steps
            upper = t + self.max_time_steps
            interval_constraint = z3.And(t_prime >= lower, t_prime <= upper)

        # ForAll t' in interval, child holds
        return z3.ForAll([t_prime], z3.Implies(interval_constraint, child_at_t_prime))

    def _translate_eventually(self, node: ASTNode, t: z3.ArithRef) -> z3.BoolRef:
        """
        Translate ◇[a,b] φ (eventually within interval).

        ◇[a,b] φ ≡ ∃t'. (t + a ≤ t' ≤ t + b) ∧ φ(t')
        """
        interval = node.interval or TimeInterval(0, None)
        child = node.children[0]

        t_prime = z3.Int(f"t_{id(node)}")
        child_at_t_prime = self._translate_node(child, t_prime)

        lower = t + interval.lower
        if interval.upper is not None:
            upper = t + interval.upper
            interval_constraint = z3.And(t_prime >= lower, t_prime <= upper)
        else:
            upper = t + self.max_time_steps
            interval_constraint = z3.And(t_prime >= lower, t_prime <= upper)

        return z3.Exists([t_prime], z3.And(interval_constraint, child_at_t_prime))

    def _translate_next(self, node: ASTNode, t: z3.ArithRef) -> z3.BoolRef:
        """Translate ○[a,b] φ (next within interval)."""
        interval = node.interval or TimeInterval(1, 1)
        child = node.children[0]

        # Next with interval [a,b] means at time t + offset for offset in [a,b]
        offset = interval.lower  # Use lower bound
        return self._translate_node(child, t + offset)

    def _translate_previous(self, node: ASTNode, t: z3.ArithRef) -> z3.BoolRef:
        """Translate ●[a,b] φ (previous within interval)."""
        interval = node.interval or TimeInterval(1, 1)
        child = node.children[0]

        offset = interval.lower
        t_past = t - offset

        # Ensure we don't go before time 0
        past_formula = self._translate_node(child, t_past)
        return z3.And(t_past >= 0, past_formula)

    def _translate_predicate(self, node: ASTNode, t: z3.ArithRef) -> z3.BoolRef:
        """Translate a predicate P(args)."""
        name = node.name
        args = node.args or []

        # Get or create predicate function
        if name not in self._predicates:
            # Arity = len(args) + 1 for time
            arity = len(args) + 1
            arg_sorts = [self.value_sort] * len(args) + [self.time_sort]
            self._predicates[name] = z3.Function(name, *arg_sorts, z3.BoolSort())

        pred_func = self._predicates[name]

        # Convert arguments to Z3
        z3_args = [z3.Int(arg) for arg in args]
        z3_args.append(t)

        return pred_func(*z3_args)

    def get_predicate(self, name: str, arity: int) -> z3.FuncDeclRef:
        """Get or create a predicate function declaration."""
        if name not in self._predicates:
            arg_sorts = [self.value_sort] * (arity - 1) + [self.time_sort]
            self._predicates[name] = z3.Function(name, *arg_sorts, z3.BoolSort())
        return self._predicates[name]

    def reset(self) -> None:
        """Reset translator state."""
        self._predicates.clear()
