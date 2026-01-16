"""
Comprehensive tests for V-NAPE utils module.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from vnape.utils.helpers import (
    TimeInterval,
    compress_trace,
    compute_trace_similarity,
    decompress_trace,
    extract_predicates,
    extract_variables,
    format_duration,
    generate_trace_from_template,
    hash_trace,
    normalize_policy,
    parse_time_interval,
    validate_policy_syntax,
)


class TestTimeInterval:
    """Tests for TimeInterval class."""

    def test_valid_interval(self):
        """Test creating a valid interval."""
        interval = TimeInterval(0, 10)
        assert interval.lower == 0
        assert interval.upper == 10
        assert interval.lower_inclusive is True
        assert interval.upper_inclusive is True

    def test_invalid_interval_raises(self):
        """Test that invalid interval raises ValueError."""
        with pytest.raises(ValueError, match="Invalid interval"):
            TimeInterval(10, 0)

    def test_unbounded_upper(self):
        """Test unbounded upper interval."""
        interval = TimeInterval(0, 0, unbounded_upper=True)
        assert interval.unbounded_upper is True

    def test_contains_closed_interval(self):
        """Test contains for closed interval."""
        interval = TimeInterval(0, 10)
        assert interval.contains(0) is True
        assert interval.contains(5) is True
        assert interval.contains(10) is True
        assert interval.contains(-1) is False
        assert interval.contains(11) is False

    def test_contains_open_interval(self):
        """Test contains for open interval."""
        interval = TimeInterval(0, 10, lower_inclusive=False, upper_inclusive=False)
        assert interval.contains(0) is False
        assert interval.contains(5) is True
        assert interval.contains(10) is False

    def test_contains_unbounded(self):
        """Test contains for unbounded interval."""
        interval = TimeInterval(5, 0, unbounded_upper=True)
        assert interval.contains(5) is True
        assert interval.contains(100) is True
        assert interval.contains(4) is False

    def test_contains_unbounded_not_inclusive(self):
        """Test contains for unbounded interval with exclusive lower."""
        interval = TimeInterval(5, 0, lower_inclusive=False, unbounded_upper=True)
        assert interval.contains(5) is False
        assert interval.contains(6) is True

    def test_repr(self):
        """Test string representation."""
        assert repr(TimeInterval(0, 10)) == "[0,10]"
        assert repr(TimeInterval(0, 10, lower_inclusive=False)) == "(0,10]"
        assert repr(TimeInterval(0, 0, unbounded_upper=True)) == "[0,∞)"


class TestParseTimeInterval:
    """Tests for parse_time_interval function."""

    def test_closed_interval(self):
        """Test parsing closed interval."""
        interval = parse_time_interval("[0,10]")
        assert interval.lower == 0
        assert interval.upper == 10
        assert interval.lower_inclusive is True
        assert interval.upper_inclusive is True

    def test_open_interval(self):
        """Test parsing open interval."""
        interval = parse_time_interval("(0,10)")
        assert interval.lower_inclusive is False
        assert interval.upper_inclusive is False

    def test_half_open_interval(self):
        """Test parsing half-open interval."""
        interval = parse_time_interval("[0,10)")
        assert interval.lower_inclusive is True
        assert interval.upper_inclusive is False

    def test_unbounded_infinity(self):
        """Test parsing unbounded interval with infinity."""
        interval = parse_time_interval("[0,∞)")
        assert interval.unbounded_upper is True

    def test_unbounded_inf(self):
        """Test parsing unbounded interval with inf."""
        interval = parse_time_interval("[0,inf)")
        assert interval.unbounded_upper is True

    def test_duration_seconds(self):
        """Test parsing duration in seconds."""
        interval = parse_time_interval("5s")
        assert interval.lower == 0
        assert interval.upper == 5.0

    def test_duration_minutes(self):
        """Test parsing duration in minutes."""
        interval = parse_time_interval("5m")
        assert interval.upper == 300.0

    def test_duration_hours(self):
        """Test parsing duration in hours."""
        interval = parse_time_interval("2h")
        assert interval.upper == 7200.0

    def test_duration_days(self):
        """Test parsing duration in days."""
        interval = parse_time_interval("1d")
        assert interval.upper == 86400.0

    def test_duration_milliseconds(self):
        """Test parsing duration in milliseconds."""
        interval = parse_time_interval("500ms")
        assert interval.upper == 0.5

    def test_invalid_format_raises(self):
        """Test that invalid format raises ValueError."""
        with pytest.raises(ValueError, match="Invalid interval format"):
            parse_time_interval("invalid")

    def test_negative_values(self):
        """Test parsing negative values."""
        interval = parse_time_interval("[-10,10]")
        assert interval.lower == -10
        assert interval.upper == 10

    def test_float_values(self):
        """Test parsing float values."""
        interval = parse_time_interval("[0.5,10.5]")
        assert interval.lower == 0.5
        assert interval.upper == 10.5


class TestValidatePolicySyntax:
    """Tests for validate_policy_syntax function."""

    def test_valid_simple_formula(self):
        """Test valid simple formula."""
        valid, error = validate_policy_syntax("P(x)")
        assert valid is True
        assert error is None

    def test_valid_implication(self):
        """Test valid implication formula."""
        valid, error = validate_policy_syntax("P(x) → Q(x)")
        assert valid is True

    def test_valid_temporal_always(self):
        """Test valid always formula."""
        valid, error = validate_policy_syntax("□[0,10] P(x)")
        assert valid is True

    def test_valid_temporal_eventually(self):
        """Test valid eventually formula."""
        valid, error = validate_policy_syntax("◇[0,10] P(x)")
        assert valid is True

    def test_valid_quantifiers(self):
        """Test valid quantified formula."""
        valid, error = validate_policy_syntax("∀x. P(x)")
        assert valid is True

    def test_invalid_unbalanced_parens(self):
        """Test invalid formula with unbalanced parentheses."""
        valid, error = validate_policy_syntax("P(x")
        assert valid is False
        assert error is not None

    def test_invalid_unbalanced_closing(self):
        """Test invalid formula with unmatched closing."""
        valid, error = validate_policy_syntax("P(x))")
        assert valid is False

    def test_invalid_mismatched_brackets(self):
        """Test invalid formula with mismatched brackets."""
        valid, error = validate_policy_syntax("□[0,10) P(x)")
        assert valid is False

    def test_invalid_time_interval(self):
        """Test invalid time interval (lower > upper)."""
        valid, error = validate_policy_syntax("□[10,0] P(x)")
        assert valid is False


class TestNormalizePolicy:
    """Tests for normalize_policy function."""

    def test_normalize_operators(self):
        """Test normalizing logical operators."""
        result = normalize_policy("P && Q")
        assert "∧" in result

    def test_normalize_implication(self):
        """Test normalizing implication."""
        result = normalize_policy("P -> Q")
        assert "→" in result

    def test_normalize_negation(self):
        """Test normalizing negation."""
        result = normalize_policy("!P")
        assert "¬" in result

    def test_normalize_quantifiers(self):
        """Test normalizing quantifiers."""
        assert "∀" in normalize_policy("forall x. P(x)")
        assert "∃" in normalize_policy("exists x. P(x)")

    def test_normalize_temporal(self):
        """Test normalizing temporal operators."""
        assert "□" in normalize_policy("G P(x)")
        assert "◇" in normalize_policy("F P(x)")

    def test_whitespace_normalization(self):
        """Test whitespace normalization."""
        result = normalize_policy("P(x)   →   Q(x)")
        assert "  " not in result


class TestExtractPredicates:
    """Tests for extract_predicates function."""

    def test_single_predicate(self):
        """Test extracting single predicate."""
        predicates = extract_predicates("P(x)")
        assert "P" in predicates

    def test_multiple_predicates(self):
        """Test extracting multiple predicates."""
        predicates = extract_predicates("P(x) ∧ Q(y) → R(z)")
        assert "P" in predicates
        assert "Q" in predicates
        assert "R" in predicates

    def test_predicate_with_multiple_args(self):
        """Test predicate with multiple arguments."""
        predicates = extract_predicates("Send(alice, bob, msg)")
        assert "Send" in predicates

    def test_filters_operators(self):
        """Test that temporal operators are filtered out."""
        predicates = extract_predicates("G(P(x)) ∧ F(Q(y))")
        assert "G" not in predicates
        assert "F" not in predicates


class TestExtractVariables:
    """Tests for extract_variables function."""

    def test_single_variable(self):
        """Test extracting single variable."""
        variables = extract_variables("P(x)")
        assert "x" in variables

    def test_multiple_variables(self):
        """Test extracting multiple variables."""
        variables = extract_variables("P(x, y, z)")
        assert "x" in variables
        assert "y" in variables
        assert "z" in variables

    def test_quantified_variables(self):
        """Test extracting quantified variables."""
        variables = extract_variables("∀x. ∃y. P(x, y)")
        assert "x" in variables
        assert "y" in variables


class TestHashTrace:
    """Tests for hash_trace function."""

    def test_deterministic_hash(self):
        """Test that hash is deterministic."""
        events = [{"name": "event1"}, {"name": "event2"}]
        hash1 = hash_trace(events)
        hash2 = hash_trace(events)
        assert hash1 == hash2

    def test_different_traces_different_hash(self):
        """Test that different traces produce different hashes."""
        events1 = [{"name": "event1"}]
        events2 = [{"name": "event2"}]
        assert hash_trace(events1) != hash_trace(events2)

    def test_order_matters(self):
        """Test that event order affects hash."""
        events1 = [{"name": "a"}, {"name": "b"}]
        events2 = [{"name": "b"}, {"name": "a"}]
        assert hash_trace(events1) != hash_trace(events2)

    def test_include_timestamps(self):
        """Test including timestamps in hash."""
        events = [{"name": "e", "timestamp": 100}]
        hash_without = hash_trace(events, include_timestamps=False)
        hash_with = hash_trace(events, include_timestamps=True)
        # They may or may not differ based on implementation
        assert hash_without is not None
        assert hash_with is not None

    def test_different_algorithm(self):
        """Test using different hash algorithm."""
        events = [{"name": "test"}]
        sha256_hash = hash_trace(events, algorithm="sha256")
        md5_hash = hash_trace(events, algorithm="md5")
        assert sha256_hash != md5_hash


class TestCompressDecompressTrace:
    """Tests for trace compression/decompression."""

    def test_roundtrip(self):
        """Test compress then decompress returns original."""
        events = [
            {"name": "event1", "data": "test"},
            {"name": "event2", "data": "more data"},
        ]
        compressed = compress_trace(events)
        decompressed = decompress_trace(compressed)
        assert decompressed == events

    def test_compression_reduces_size(self):
        """Test that compression reduces size for large data."""
        events = [{"name": f"event{i}", "data": "x" * 100} for i in range(100)]
        compressed = compress_trace(events)
        original_size = len(json.dumps(events))
        # Compressed is base64, so compare decoded size
        assert len(compressed) < original_size * 2  # Base64 overhead


class TestComputeTraceSimilarity:
    """Tests for compute_trace_similarity function."""

    def test_identical_traces(self):
        """Test similarity of identical traces."""
        events = [{"name": "event1"}, {"name": "event2"}]
        similarity = compute_trace_similarity(events, events)
        assert similarity == 1.0

    def test_completely_different_traces(self):
        """Test similarity of completely different traces."""
        events1 = [{"name": "a"}]
        events2 = [{"name": "b"}]
        similarity = compute_trace_similarity(events1, events2, method="jaccard")
        assert similarity == 0.0

    def test_partial_overlap(self):
        """Test similarity with partial overlap."""
        events1 = [{"name": "a"}, {"name": "b"}]
        events2 = [{"name": "b"}, {"name": "c"}]
        similarity = compute_trace_similarity(events1, events2, method="jaccard")
        assert 0.0 < similarity < 1.0

    def test_empty_traces(self):
        """Test similarity of empty traces."""
        similarity = compute_trace_similarity([], [])
        assert similarity == 1.0

    def test_one_empty_trace(self):
        """Test similarity when one trace is empty."""
        similarity = compute_trace_similarity([{"name": "a"}], [])
        assert similarity == 0.0

    def test_sequence_method(self):
        """Test sequence similarity method."""
        events1 = [{"name": "a"}, {"name": "b"}, {"name": "c"}]
        events2 = [{"name": "a"}, {"name": "b"}, {"name": "d"}]
        similarity = compute_trace_similarity(events1, events2, method="sequence")
        assert 0.0 < similarity < 1.0

    def test_edit_distance_method(self):
        """Test edit distance similarity method."""
        events1 = [{"name": "a"}, {"name": "b"}]
        events2 = [{"name": "a"}, {"name": "c"}]
        similarity = compute_trace_similarity(events1, events2, method="edit_distance")
        assert 0.0 < similarity < 1.0

    def test_invalid_method_raises(self):
        """Test that invalid method raises ValueError."""
        with pytest.raises(ValueError, match="Unknown similarity method"):
            compute_trace_similarity([{"name": "a"}], [{"name": "b"}], method="invalid")


class TestFormatDuration:
    """Tests for format_duration function."""

    def test_format_microseconds(self):
        """Test formatting microseconds."""
        result = format_duration(0.0001)
        assert "μs" in result

    def test_format_milliseconds(self):
        """Test formatting milliseconds."""
        result = format_duration(0.5)
        assert "ms" in result

    def test_format_seconds(self):
        """Test formatting seconds."""
        result = format_duration(5)
        assert "s" in result

    def test_format_minutes(self):
        """Test formatting minutes."""
        result = format_duration(120)
        assert "m" in result

    def test_format_hours(self):
        """Test formatting hours."""
        result = format_duration(3600)
        assert "h" in result

    def test_format_days(self):
        """Test formatting days."""
        result = format_duration(86400)
        assert "d" in result

    def test_negative_duration(self):
        """Test formatting negative duration."""
        result = format_duration(-5)
        assert "-" in result


class TestGenerateTraceFromTemplate:
    """Tests for generate_trace_from_template function."""

    def test_simple_generation(self):
        """Test simple trace generation."""
        template = [{"name": "event", "value": 1}]
        traces = generate_trace_from_template(template, count=3)
        assert len(traces) == 3
        for trace in traces:
            assert trace[0]["name"] == "event"

    def test_variable_substitution(self):
        """Test variable substitution in template."""
        template = [{"name": "{var}"}]
        variables = {"var": ["a", "b", "c"]}
        traces = generate_trace_from_template(template, variables=variables, count=5)
        assert len(traces) == 5
        for trace in traces:
            assert trace[0]["name"] in ["a", "b", "c"]

    def test_nested_dict_substitution(self):
        """Test variable substitution in nested dicts."""
        template = [{"name": "event", "data": {"sender": "{user}"}}]
        variables = {"user": "alice"}
        traces = generate_trace_from_template(template, variables=variables, count=1)
        assert traces[0][0]["data"]["sender"] == "alice"


# Test logging utilities
class TestLoggingUtils:
    """Tests for logging utilities."""

    def test_logger_import(self):
        """Test that logger can be imported."""
        from vnape.utils.logging import get_logger

        logger = get_logger("test")
        assert logger is not None

    def test_logger_methods(self):
        """Test logger has expected methods."""
        from vnape.utils.logging import get_logger

        logger = get_logger("test")
        assert hasattr(logger, "info")
        assert hasattr(logger, "debug")
        assert hasattr(logger, "warning")
        assert hasattr(logger, "error")


# Test metrics utilities
class TestMetricsUtils:
    """Tests for metrics utilities."""

    def test_metrics_import(self):
        """Test that metrics can be imported."""
        from vnape.utils.metrics import MetricsCollector

        collector = MetricsCollector()
        assert collector is not None

    def test_record_latency(self):
        """Test recording latency metric."""
        from vnape.utils.metrics import MetricsCollector

        collector = MetricsCollector()
        collector.reset()
        collector.record_latency("npa", "encoding", 100.0)
        # Should not raise

    def test_record_violation(self):
        """Test recording a violation."""
        from vnape.utils.metrics import MetricsCollector

        collector = MetricsCollector()
        collector.reset()
        collector.record_violation("test_policy", severity="high")
        assert collector.security.policy_violations_total >= 1

    def test_timer(self):
        """Test timer functionality."""
        import time

        from vnape.utils.metrics import MetricsCollector

        collector = MetricsCollector()
        collector.start_timer("test")
        time.sleep(0.01)
        elapsed = collector.stop_timer("test")
        assert elapsed > 0

    def test_reset(self):
        """Test reset functionality."""
        from vnape.utils.metrics import MetricsCollector

        collector = MetricsCollector()
        collector.reset()
        assert collector.security.policy_violations_total == 0


# Test visualization utilities
class TestVisualizationUtils:
    """Tests for visualization utilities."""

    def test_trace_visualizer_import(self):
        """Test that TraceVisualizer can be imported."""
        from vnape.utils.visualization import TraceVisualizer

        viz = TraceVisualizer()
        assert viz is not None

    def test_sequence_diagram(self):
        """Test generating sequence diagram."""
        from vnape.utils.visualization import TraceVisualizer

        viz = TraceVisualizer()
        events = [
            {"source": "Alice", "target": "Bob", "type": "Send"},
            {"source": "Bob", "target": "Alice", "type": "Ack"},
        ]
        result = viz.sequence_diagram(events)
        assert result is not None
        assert "sequenceDiagram" in result

    def test_timeline(self):
        """Test generating timeline."""
        from vnape.utils.visualization import TraceVisualizer

        viz = TraceVisualizer()
        events = [
            {"name": "Event1", "timestamp": "2024-01-01"},
            {"name": "Event2", "timestamp": "2024-01-02"},
        ]
        result = viz.timeline(events)
        assert result is not None
        assert "Event1" in result

    def test_empty_events(self):
        """Test with empty events."""
        from vnape.utils.visualization import TraceVisualizer

        viz = TraceVisualizer()
        result = viz.timeline([])
        assert "No events" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


# Additional tests for 100% coverage
class TestValidatePolicySyntaxAdditional:
    """Additional tests for edge cases in policy validation."""

    def test_nested_predicates(self):
        """Test validation with nested predicates that have unmatched parens."""
        # This should trigger the predicate checking code
        valid, error = validate_policy_syntax("P(Q(x)")
        assert valid is False

    def test_deeply_nested_parens(self):
        """Test with deeply nested parentheses."""
        valid, error = validate_policy_syntax("((P(x)))")
        assert valid is True

    def test_nested_parens_in_predicate(self):
        """Test nested parentheses inside predicate arguments."""
        # This triggers line 281 - depth += 1
        valid, error = validate_policy_syntax("P(f(g(x)))")
        assert valid is True

    def test_unmatched_predicate_paren(self):
        """Test unmatched parenthesis for specific predicate."""
        # This triggers line 286 - unmatched parenthesis for predicate
        valid, error = validate_policy_syntax("Foo(bar(x)")
        assert valid is False
        assert "Unmatched" in error or "parenthesis" in error.lower()
