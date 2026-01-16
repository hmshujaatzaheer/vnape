"""
V-NAPE Utilities Module

Provides logging, metrics collection, visualization, and helper functions.
"""

from .helpers import (
    compress_trace,
    compute_trace_similarity,
    decompress_trace,
    format_duration,
    hash_trace,
    normalize_policy,
    parse_time_interval,
    validate_policy_syntax,
)
from .logging import (
    LogLevel,
    VNAPELogger,
    configure_logging,
    get_logger,
    log_enforcement_decision,
    log_trace_event,
    log_verification_result,
)
from .metrics import (
    EnforcementMetrics,
    MetricsCollector,
    PerformanceMetrics,
    SecurityMetrics,
    VerificationMetrics,
    get_metrics_collector,
    record_decision,
    record_latency,
    record_violation,
)
from .visualization import (
    MetricsVisualizer,
    PolicyVisualizer,
    ProtocolStateVisualizer,
    TraceVisualizer,
    export_to_html,
    plot_enforcement_timeline,
    plot_quantum_risk_evolution,
    plot_verification_coverage,
)

__all__ = [
    # Logging
    "VNAPELogger",
    "LogLevel",
    "get_logger",
    "configure_logging",
    "log_trace_event",
    "log_enforcement_decision",
    "log_verification_result",
    # Metrics
    "MetricsCollector",
    "PerformanceMetrics",
    "SecurityMetrics",
    "VerificationMetrics",
    "EnforcementMetrics",
    "get_metrics_collector",
    "record_latency",
    "record_decision",
    "record_violation",
    # Visualization
    "TraceVisualizer",
    "PolicyVisualizer",
    "MetricsVisualizer",
    "ProtocolStateVisualizer",
    "plot_enforcement_timeline",
    "plot_quantum_risk_evolution",
    "plot_verification_coverage",
    "export_to_html",
    # Helpers
    "parse_time_interval",
    "format_duration",
    "hash_trace",
    "compress_trace",
    "decompress_trace",
    "validate_policy_syntax",
    "normalize_policy",
    "compute_trace_similarity",
]
