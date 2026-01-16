"""
V-NAPE Helper Utilities

Provides utility functions for:
- Time interval parsing
- Trace processing
- Policy validation
- Similarity computation
"""

import base64
import gzip
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any


@dataclass
class TimeInterval:
    """Represents a time interval [lower, upper]."""

    lower: float
    upper: float
    lower_inclusive: bool = True
    upper_inclusive: bool = True
    unbounded_upper: bool = False

    def __post_init__(self):
        if not self.unbounded_upper and self.lower > self.upper:
            raise ValueError(f"Invalid interval: lower ({self.lower}) > upper ({self.upper})")

    def contains(self, value: float) -> bool:
        """Check if value is within the interval."""
        if self.unbounded_upper:
            if self.lower_inclusive:
                return value >= self.lower
            return value > self.lower

        lower_ok = value >= self.lower if self.lower_inclusive else value > self.lower
        upper_ok = value <= self.upper if self.upper_inclusive else value < self.upper
        return lower_ok and upper_ok

    def __repr__(self) -> str:
        left = "[" if self.lower_inclusive else "("
        right = "∞)" if self.unbounded_upper else ("]" if self.upper_inclusive else ")")
        upper_str = "" if self.unbounded_upper else str(self.upper)
        return f"{left}{self.lower},{upper_str}{right}"


def parse_time_interval(interval_str: str) -> TimeInterval:
    """
    Parse a time interval string into a TimeInterval object.

    Supported formats:
    - [0,10] - closed interval
    - (0,10) - open interval
    - [0,10) - half-open
    - [0,∞) or [0,inf) - unbounded upper
    - 5s, 5m, 5h, 5d - duration shortcuts

    Args:
        interval_str: String representation of the interval

    Returns:
        TimeInterval object
    """
    interval_str = interval_str.strip()

    # Handle duration shortcuts (return [0, duration])
    duration_match = re.match(r"^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)$", interval_str)
    if duration_match:
        value = float(duration_match.group(1))
        unit = duration_match.group(2)

        multipliers = {
            "ms": 0.001,
            "s": 1.0,
            "m": 60.0,
            "h": 3600.0,
            "d": 86400.0,
        }

        duration = value * multipliers[unit]
        return TimeInterval(0, duration)

    # Handle interval notation
    match = re.match(
        r"^([\[\(])\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?|∞|inf)\s*([\]\)])$", interval_str
    )
    if not match:
        raise ValueError(f"Invalid interval format: {interval_str}")

    left_bracket = match.group(1)
    lower = float(match.group(2))
    upper_str = match.group(3)
    right_bracket = match.group(4)

    lower_inclusive = left_bracket == "["
    unbounded = upper_str in ("∞", "inf")
    upper = float("inf") if unbounded else float(upper_str)
    upper_inclusive = right_bracket == "]" and not unbounded

    return TimeInterval(
        lower=lower,
        upper=upper,
        lower_inclusive=lower_inclusive,
        upper_inclusive=upper_inclusive,
        unbounded_upper=unbounded,
    )


def format_duration(seconds: float, precision: int = 2) -> str:
    """
    Format a duration in seconds to a human-readable string.

    Args:
        seconds: Duration in seconds
        precision: Number of decimal places for the smallest unit

    Returns:
        Formatted duration string
    """
    if seconds < 0:
        return f"-{format_duration(-seconds, precision)}"

    if seconds < 0.001:
        return f"{seconds * 1000000:.{precision}f}μs"
    if seconds < 1:
        return f"{seconds * 1000:.{precision}f}ms"
    if seconds < 60:
        return f"{seconds:.{precision}f}s"
    if seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.{precision}f}m"
    if seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.{precision}f}h"

    days = seconds / 86400
    return f"{days:.{precision}f}d"


def hash_trace(
    events: list[dict[str, Any]],
    include_timestamps: bool = False,
    algorithm: str = "sha256",
) -> str:
    """
    Compute a hash of a trace for comparison and deduplication.

    Args:
        events: List of trace events
        include_timestamps: Whether to include timestamps in the hash
        algorithm: Hash algorithm to use

    Returns:
        Hexadecimal hash string
    """

    def normalize_event(event: dict[str, Any]) -> dict[str, Any]:
        """Normalize an event for consistent hashing."""
        normalized = {
            "name": event.get("name", event.get("event_name", "")),
            "args": event.get("args", event.get("event_args", {})),
        }
        if include_timestamps:
            normalized["timestamp"] = str(event.get("timestamp", ""))
        return normalized

    normalized_events = [normalize_event(e) for e in events]
    serialized = json.dumps(normalized_events, sort_keys=True, default=str)

    hasher = hashlib.new(algorithm)
    hasher.update(serialized.encode("utf-8"))
    return hasher.hexdigest()


def compress_trace(events: list[dict[str, Any]]) -> str:
    """
    Compress a trace to a base64-encoded string for storage.

    Args:
        events: List of trace events

    Returns:
        Base64-encoded compressed string
    """
    serialized = json.dumps(events, separators=(",", ":"), default=str)
    compressed = gzip.compress(serialized.encode("utf-8"))
    return base64.b64encode(compressed).decode("ascii")


def decompress_trace(compressed: str) -> list[dict[str, Any]]:
    """
    Decompress a trace from a base64-encoded string.

    Args:
        compressed: Base64-encoded compressed string

    Returns:
        List of trace events
    """
    raw = base64.b64decode(compressed.encode("ascii"))
    decompressed = gzip.decompress(raw)
    return json.loads(decompressed.decode("utf-8"))


def validate_policy_syntax(policy: str) -> tuple[bool, str | None]:
    """
    Validate the syntax of an MFOTL policy.

    Args:
        policy: MFOTL policy string

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Check for balanced parentheses and brackets
    stack = []
    pairs = {"(": ")", "[": "]", "{": "}"}

    for i, char in enumerate(policy):
        if char in pairs:
            stack.append((char, i))
        elif char in pairs.values():
            if not stack:
                return False, f"Unmatched closing '{char}' at position {i}"
            opening, _ = stack.pop()
            if pairs[opening] != char:
                return False, f"Mismatched brackets at position {i}"

    if stack:
        char, pos = stack[-1]
        return False, f"Unmatched opening '{char}' at position {pos}"

    # Check for valid operators
    valid_operators = {
        "□",
        "◇",
        "○",
        "●",  # Temporal
        "∀",
        "∃",  # Quantifiers
        "→",
        "∧",
        "∨",
        "¬",  # Boolean
        "S",
        "U",  # Since/Until
        "G",
        "F",
        "X",
        "Y",  # Alternative notation
    }

    # Check for time intervals after temporal operators
    temporal_pattern = r"[□◇GFXY]\s*\[(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?|∞|inf)\]"
    for match in re.finditer(temporal_pattern, policy):
        lower = float(match.group(1))
        upper_str = match.group(2)
        if upper_str not in ("∞", "inf"):
            upper = float(upper_str)
            if lower > upper:
                return (
                    False,
                    f"Invalid time interval: lower bound ({lower}) > upper bound ({upper})",
                )

    # Check for predicate syntax
    predicate_pattern = r"([A-Za-z_][A-Za-z0-9_]*)\s*\("
    for match in re.finditer(predicate_pattern, policy):
        predicate_name = match.group(1)
        # Check for matching closing parenthesis
        start = match.end() - 1
        depth = 1
        i = match.end()
        while i < len(policy) and depth > 0:
            if policy[i] == "(":
                depth += 1
            elif policy[i] == ")":
                depth -= 1
            i += 1
        if depth != 0:
            return (
                False,
                f"Unmatched parenthesis for predicate '{predicate_name}'",
            )  # pragma: no cover

    return True, None


def normalize_policy(policy: str) -> str:
    """
    Normalize an MFOTL policy string for consistent comparison.

    Args:
        policy: MFOTL policy string

    Returns:
        Normalized policy string
    """
    # Standardize operator notation
    replacements = {
        "G": "□",  # Globally
        "F": "◇",  # Eventually
        "X": "○",  # Next
        "Y": "●",  # Previous
        "&&": "∧",
        "||": "∨",
        "!": "¬",
        "->": "→",
        "->": "→",
        "forall": "∀",
        "exists": "∃",
    }

    normalized = policy
    for old, new in replacements.items():
        normalized = normalized.replace(old, new)

    # Normalize whitespace
    normalized = re.sub(r"\s+", " ", normalized)
    normalized = re.sub(r"\s*([,\(\)\[\]])\s*", r"\1", normalized)
    normalized = normalized.strip()

    return normalized


def compute_trace_similarity(
    trace1: list[dict[str, Any]],
    trace2: list[dict[str, Any]],
    method: str = "jaccard",
) -> float:
    """
    Compute similarity between two traces.

    Args:
        trace1: First trace (list of events)
        trace2: Second trace (list of events)
        method: Similarity method ('jaccard', 'sequence', 'edit_distance')

    Returns:
        Similarity score between 0 and 1
    """
    if not trace1 and not trace2:
        return 1.0
    if not trace1 or not trace2:
        return 0.0

    def get_event_key(event: dict[str, Any]) -> str:
        """Get a hashable key for an event."""
        name = event.get("name", event.get("event_name", ""))
        args = json.dumps(event.get("args", event.get("event_args", {})), sort_keys=True)
        return f"{name}:{args}"

    if method == "jaccard":
        # Jaccard similarity based on unique events
        set1 = set(get_event_key(e) for e in trace1)
        set2 = set(get_event_key(e) for e in trace2)

        intersection = len(set1 & set2)
        union = len(set1 | set2)

        return intersection / union if union > 0 else 0.0

    elif method == "sequence":
        # Longest common subsequence based similarity
        keys1 = [get_event_key(e) for e in trace1]
        keys2 = [get_event_key(e) for e in trace2]

        m, n = len(keys1), len(keys2)
        dp = [[0] * (n + 1) for _ in range(m + 1)]

        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if keys1[i - 1] == keys2[j - 1]:
                    dp[i][j] = dp[i - 1][j - 1] + 1
                else:
                    dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])

        lcs_length = dp[m][n]
        return (2 * lcs_length) / (m + n)

    elif method == "edit_distance":
        # Levenshtein distance based similarity
        keys1 = [get_event_key(e) for e in trace1]
        keys2 = [get_event_key(e) for e in trace2]

        m, n = len(keys1), len(keys2)
        dp = [[0] * (n + 1) for _ in range(m + 1)]

        for i in range(m + 1):
            dp[i][0] = i
        for j in range(n + 1):
            dp[0][j] = j

        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if keys1[i - 1] == keys2[j - 1]:
                    dp[i][j] = dp[i - 1][j - 1]
                else:
                    dp[i][j] = 1 + min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])

        edit_distance = dp[m][n]
        max_length = max(m, n)
        return 1 - (edit_distance / max_length) if max_length > 0 else 1.0

    else:
        raise ValueError(f"Unknown similarity method: {method}")


def extract_predicates(policy: str) -> list[str]:
    """
    Extract all predicate names from an MFOTL policy.

    Args:
        policy: MFOTL policy string

    Returns:
        List of predicate names
    """
    # Pattern to match predicates: word followed by (
    pattern = r"([A-Za-z_][A-Za-z0-9_]*)\s*\("
    matches = re.findall(pattern, policy)

    # Filter out operators that look like predicates
    operators = {"S", "U", "G", "F", "X", "Y"}
    predicates = [m for m in matches if m not in operators]

    return list(set(predicates))


def extract_variables(policy: str) -> list[str]:
    """
    Extract all variable names from an MFOTL policy.

    Args:
        policy: MFOTL policy string

    Returns:
        List of variable names
    """
    # Variables are lowercase identifiers after quantifiers or in predicates
    quantifier_vars = re.findall(r"[∀∃]\s*([a-z_][a-z0-9_]*)", policy)

    # Also find variables in predicates (lowercase arguments)
    predicate_pattern = r"[A-Za-z_][A-Za-z0-9_]*\s*\(([^)]+)\)"
    for match in re.finditer(predicate_pattern, policy):
        args = match.group(1).split(",")
        for arg in args:
            arg = arg.strip()
            if re.match(r"^[a-z_][a-z0-9_]*$", arg):
                quantifier_vars.append(arg)

    return list(set(quantifier_vars))


def generate_trace_from_template(
    template: list[dict[str, Any]],
    variables: dict[str, Any] | None = None,
    count: int = 1,
) -> list[list[dict[str, Any]]]:
    """
    Generate traces from a template with variable substitution.

    Args:
        template: Template trace with placeholders like {var}
        variables: Dictionary of variable names to value lists
        count: Number of traces to generate

    Returns:
        List of generated traces
    """
    import random

    variables = variables or {}
    traces = []

    for _ in range(count):
        trace = []
        current_vars = {
            k: random.choice(v) if isinstance(v, list) else v for k, v in variables.items()
        }

        for event_template in template:
            event = {}
            for key, value in event_template.items():
                if isinstance(value, str) and "{" in value:
                    # Substitute variables
                    for var_name, var_value in current_vars.items():
                        value = value.replace(f"{{{var_name}}}", str(var_value))
                    event[key] = value
                elif isinstance(value, dict):
                    # Recursively handle nested dicts
                    event[key] = {}
                    for k, v in value.items():
                        if isinstance(v, str) and "{" in v:
                            for var_name, var_value in current_vars.items():
                                v = v.replace(f"{{{var_name}}}", str(var_value))
                        event[key][k] = v
                else:
                    event[key] = value
            trace.append(event)

        traces.append(trace)

    return traces
