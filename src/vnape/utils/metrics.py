"""
V-NAPE Metrics Collection

Provides comprehensive metrics collection for:
- Performance (latency, throughput)
- Security (violations, threats)
- Verification (coverage, success rates)
- Enforcement (decisions, actions)
"""

import json
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from statistics import mean, median, stdev
from typing import Any, Optional


class MetricType(Enum):
    """Types of metrics."""

    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"
    TIMER = "timer"


@dataclass
class MetricValue:
    """A single metric value with timestamp."""

    value: float
    timestamp: datetime = field(default_factory=datetime.now)
    labels: dict[str, str] = field(default_factory=dict)


@dataclass
class PerformanceMetrics:
    """Performance-related metrics."""

    # Latency metrics (in milliseconds)
    npa_encoding_latency_ms: list[float] = field(default_factory=list)
    npa_pattern_detection_latency_ms: list[float] = field(default_factory=list)
    npa_refinement_generation_latency_ms: list[float] = field(default_factory=list)
    svb_translation_latency_ms: list[float] = field(default_factory=list)
    svb_verification_latency_ms: list[float] = field(default_factory=list)
    pqae_monitoring_latency_ms: list[float] = field(default_factory=list)
    pqae_enforcement_latency_ms: list[float] = field(default_factory=list)
    end_to_end_latency_ms: list[float] = field(default_factory=list)

    # Throughput metrics
    events_processed_per_second: list[float] = field(default_factory=list)
    refinements_per_minute: list[float] = field(default_factory=list)
    verifications_per_minute: list[float] = field(default_factory=list)

    # Resource metrics
    memory_usage_mb: list[float] = field(default_factory=list)
    gpu_memory_usage_mb: list[float] = field(default_factory=list)

    def get_statistics(self, metric_name: str) -> dict[str, float]:
        """Get statistics for a metric."""
        values = getattr(self, metric_name, [])
        if not values:
            return {"count": 0, "mean": 0, "std": 0, "min": 0, "max": 0, "median": 0}
        return {
            "count": len(values),
            "mean": mean(values),
            "std": stdev(values) if len(values) > 1 else 0,
            "min": min(values),
            "max": max(values),
            "median": median(values),
        }


@dataclass
class SecurityMetrics:
    """Security-related metrics."""

    # Violation counts
    policy_violations_total: int = 0
    critical_violations: int = 0
    high_violations: int = 0
    medium_violations: int = 0
    low_violations: int = 0

    # Threat metrics
    quantum_threats_detected: int = 0
    hndl_risks_identified: int = 0
    cryptographic_weaknesses_found: int = 0

    # Violation breakdown by type
    violations_by_policy: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    violations_by_protocol: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    violations_by_action: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Time series
    violations_over_time: list[tuple[datetime, int]] = field(default_factory=list)
    quantum_risk_scores: list[tuple[datetime, float]] = field(default_factory=list)


@dataclass
class VerificationMetrics:
    """Verification-related metrics."""

    # Verification counts
    verifications_total: int = 0
    verifications_sat: int = 0
    verifications_unsat: int = 0
    verifications_unknown: int = 0
    verifications_timeout: int = 0

    # Coverage metrics
    properties_verified: int = 0
    properties_total: int = 0

    # Certificate metrics
    certificates_generated: int = 0
    certificates_validated: int = 0

    # Verification breakdown
    verifications_by_property: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    verification_times_by_property: dict[str, list[float]] = field(
        default_factory=lambda: defaultdict(list)
    )

    @property
    def verification_success_rate(self) -> float:
        """Calculate verification success rate."""
        total = self.verifications_sat + self.verifications_unsat
        if total == 0:
            return 0.0
        return self.verifications_sat / total

    @property
    def coverage_percentage(self) -> float:
        """Calculate property coverage percentage."""
        if self.properties_total == 0:
            return 0.0
        return (self.properties_verified / self.properties_total) * 100


@dataclass
class EnforcementMetrics:
    """Enforcement-related metrics."""

    # Decision counts
    decisions_total: int = 0
    decisions_allow: int = 0
    decisions_block: int = 0
    decisions_delay: int = 0
    decisions_modify: int = 0
    decisions_renegotiate: int = 0
    decisions_terminate: int = 0

    # Quantum adjustment
    quantum_adjusted_decisions: int = 0

    # Confidence distribution
    confidence_scores: list[float] = field(default_factory=list)

    # Decision breakdown
    decisions_by_policy: dict[str, dict[str, int]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(int))
    )
    decisions_by_protocol: dict[str, dict[str, int]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(int))
    )

    # Time series
    decisions_over_time: list[tuple[datetime, str]] = field(default_factory=list)

    @property
    def block_rate(self) -> float:
        """Calculate block rate."""
        if self.decisions_total == 0:
            return 0.0
        return self.decisions_block / self.decisions_total

    @property
    def average_confidence(self) -> float:
        """Calculate average confidence score."""
        if not self.confidence_scores:
            return 0.0
        return mean(self.confidence_scores)


class MetricsCollector:
    """
    Central metrics collector for V-NAPE framework.

    Thread-safe singleton that collects metrics from all components.
    """

    _instance: Optional["MetricsCollector"] = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, "_initialized") and self._initialized:
            return

        self._initialized = True
        self._lock = threading.RLock()

        # Metric containers
        self.performance = PerformanceMetrics()
        self.security = SecurityMetrics()
        self.verification = VerificationMetrics()
        self.enforcement = EnforcementMetrics()

        # Custom metrics
        self._custom_counters: dict[str, int] = defaultdict(int)
        self._custom_gauges: dict[str, float] = {}
        self._custom_histograms: dict[str, list[float]] = defaultdict(list)

        # Timing context
        self._timing_starts: dict[str, float] = {}

        # Start time
        self._start_time = datetime.now()

    def reset(self) -> None:
        """Reset all metrics."""
        with self._lock:
            self.performance = PerformanceMetrics()
            self.security = SecurityMetrics()
            self.verification = VerificationMetrics()
            self.enforcement = EnforcementMetrics()
            self._custom_counters.clear()
            self._custom_gauges.clear()
            self._custom_histograms.clear()
            self._start_time = datetime.now()

    # Performance metrics recording
    def record_latency(self, component: str, operation: str, latency_ms: float) -> None:
        """Record latency for a component operation."""
        with self._lock:
            metric_name = f"{component}_{operation}_latency_ms"
            if hasattr(self.performance, metric_name):
                getattr(self.performance, metric_name).append(latency_ms)
            else:
                self._custom_histograms[metric_name].append(latency_ms)

    def record_throughput(self, metric: str, value: float) -> None:
        """Record throughput metric."""
        with self._lock:
            if hasattr(self.performance, metric):
                getattr(self.performance, metric).append(value)

    def start_timer(self, name: str) -> None:
        """Start a named timer."""
        self._timing_starts[name] = time.perf_counter()

    def stop_timer(self, name: str) -> float:
        """Stop a named timer and return elapsed milliseconds."""
        if name not in self._timing_starts:
            return 0.0
        elapsed_ms = (time.perf_counter() - self._timing_starts[name]) * 1000
        del self._timing_starts[name]
        return elapsed_ms

    def time_operation(self, name: str):
        """Context manager for timing operations."""
        return _TimerContext(self, name)

    # Security metrics recording
    def record_violation(
        self,
        policy: str,
        severity: str = "medium",
        protocol: str | None = None,
        action: str | None = None,
    ) -> None:
        """Record a policy violation."""
        with self._lock:
            self.security.policy_violations_total += 1

            severity_map = {
                "critical": "critical_violations",
                "high": "high_violations",
                "medium": "medium_violations",
                "low": "low_violations",
            }
            if severity.lower() in severity_map:
                attr = severity_map[severity.lower()]
                setattr(self.security, attr, getattr(self.security, attr) + 1)

            self.security.violations_by_policy[policy] += 1
            if protocol:
                self.security.violations_by_protocol[protocol] += 1
            if action:
                self.security.violations_by_action[action] += 1

            self.security.violations_over_time.append(
                (datetime.now(), self.security.policy_violations_total)
            )

    def record_quantum_threat(self, threat_type: str, risk_score: float) -> None:
        """Record a quantum-related threat."""
        with self._lock:
            self.security.quantum_threats_detected += 1
            if threat_type == "hndl":
                self.security.hndl_risks_identified += 1
            elif threat_type == "cryptographic":
                self.security.cryptographic_weaknesses_found += 1

            self.security.quantum_risk_scores.append((datetime.now(), risk_score))

    # Verification metrics recording
    def record_verification(
        self,
        property_name: str,
        result: str,
        verification_time_ms: float,
        certificate_generated: bool = False,
    ) -> None:
        """Record a verification result."""
        with self._lock:
            self.verification.verifications_total += 1

            result_lower = result.lower()
            if result_lower == "sat":
                self.verification.verifications_sat += 1
            elif result_lower == "unsat":
                self.verification.verifications_unsat += 1
            elif result_lower == "unknown":
                self.verification.verifications_unknown += 1
            elif result_lower == "timeout":
                self.verification.verifications_timeout += 1

            self.verification.verifications_by_property[property_name] += 1
            self.verification.verification_times_by_property[property_name].append(
                verification_time_ms
            )

            if certificate_generated:
                self.verification.certificates_generated += 1

    # Enforcement metrics recording
    def record_decision(
        self,
        action: str,
        confidence: float,
        policy: str | None = None,
        protocol: str | None = None,
        quantum_adjusted: bool = False,
    ) -> None:
        """Record an enforcement decision."""
        with self._lock:
            self.enforcement.decisions_total += 1
            self.enforcement.confidence_scores.append(confidence)

            action_map = {
                "allow": "decisions_allow",
                "block": "decisions_block",
                "delay": "decisions_delay",
                "modify": "decisions_modify",
                "renegotiate": "decisions_renegotiate",
                "terminate": "decisions_terminate",
            }
            if action.lower() in action_map:
                attr = action_map[action.lower()]
                setattr(self.enforcement, attr, getattr(self.enforcement, attr) + 1)

            if quantum_adjusted:
                self.enforcement.quantum_adjusted_decisions += 1

            if policy:
                self.enforcement.decisions_by_policy[policy][action] += 1
            if protocol:
                self.enforcement.decisions_by_protocol[protocol][action] += 1

            self.enforcement.decisions_over_time.append((datetime.now(), action))

    # Custom metrics
    def increment_counter(self, name: str, value: int = 1) -> None:
        """Increment a custom counter."""
        with self._lock:
            self._custom_counters[name] += value

    def set_gauge(self, name: str, value: float) -> None:
        """Set a custom gauge value."""
        with self._lock:
            self._custom_gauges[name] = value

    def record_histogram(self, name: str, value: float) -> None:
        """Record a value to a custom histogram."""
        with self._lock:
            self._custom_histograms[name].append(value)

    def get_counter(self, name: str) -> int:
        """Get custom counter value."""
        return self._custom_counters.get(name, 0)

    def get_gauge(self, name: str) -> float | None:
        """Get custom gauge value."""
        return self._custom_gauges.get(name)

    def get_histogram_stats(self, name: str) -> dict[str, float]:
        """Get statistics for a custom histogram."""
        values = self._custom_histograms.get(name, [])
        if not values:
            return {"count": 0, "mean": 0, "std": 0, "min": 0, "max": 0}
        return {
            "count": len(values),
            "mean": mean(values),
            "std": stdev(values) if len(values) > 1 else 0,
            "min": min(values),
            "max": max(values),
        }

    # Summary methods
    def get_summary(self) -> dict[str, Any]:
        """Get a summary of all metrics."""
        with self._lock:
            return {
                "uptime_seconds": (datetime.now() - self._start_time).total_seconds(),
                "performance": {
                    "end_to_end_latency": self.performance.get_statistics("end_to_end_latency_ms"),
                    "npa_encoding_latency": self.performance.get_statistics(
                        "npa_encoding_latency_ms"
                    ),
                    "svb_verification_latency": self.performance.get_statistics(
                        "svb_verification_latency_ms"
                    ),
                },
                "security": {
                    "total_violations": self.security.policy_violations_total,
                    "critical_violations": self.security.critical_violations,
                    "quantum_threats": self.security.quantum_threats_detected,
                },
                "verification": {
                    "total": self.verification.verifications_total,
                    "success_rate": self.verification.verification_success_rate,
                    "coverage": self.verification.coverage_percentage,
                },
                "enforcement": {
                    "total_decisions": self.enforcement.decisions_total,
                    "block_rate": self.enforcement.block_rate,
                    "average_confidence": self.enforcement.average_confidence,
                    "quantum_adjusted": self.enforcement.quantum_adjusted_decisions,
                },
            }

    def export_json(self, filepath: str) -> None:
        """Export all metrics to JSON file."""
        import dataclasses

        def serialize(obj):
            if dataclasses.is_dataclass(obj):
                return dataclasses.asdict(obj)
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, defaultdict):
                return dict(obj)
            return str(obj)

        with self._lock:
            data = {
                "collected_at": datetime.now().isoformat(),
                "uptime_seconds": (datetime.now() - self._start_time).total_seconds(),
                "performance": serialize(self.performance),
                "security": serialize(self.security),
                "verification": serialize(self.verification),
                "enforcement": serialize(self.enforcement),
                "custom_counters": dict(self._custom_counters),
                "custom_gauges": dict(self._custom_gauges),
                "custom_histograms": {k: list(v) for k, v in self._custom_histograms.items()},
            }

        with open(filepath, "w") as f:
            json.dump(data, f, default=serialize, indent=2)


class _TimerContext:
    """Context manager for timing operations."""

    def __init__(self, collector: MetricsCollector, name: str):
        self.collector = collector
        self.name = name
        self.start_time: float = 0

    def __enter__(self):
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed_ms = (time.perf_counter() - self.start_time) * 1000
        self.collector.record_latency(
            component=self.name.split("_")[0],
            operation="_".join(self.name.split("_")[1:]) or "operation",
            latency_ms=elapsed_ms,
        )
        return False


# Global metrics collector instance
_global_collector: MetricsCollector | None = None


def get_metrics_collector() -> MetricsCollector:
    """Get the global metrics collector."""
    global _global_collector
    if _global_collector is None:
        _global_collector = MetricsCollector()
    return _global_collector


# Convenience functions
def record_latency(component: str, operation: str, latency_ms: float) -> None:
    """Record latency using global collector."""
    get_metrics_collector().record_latency(component, operation, latency_ms)


def record_decision(
    action: str,
    confidence: float,
    policy: str | None = None,
    protocol: str | None = None,
    quantum_adjusted: bool = False,
) -> None:
    """Record enforcement decision using global collector."""
    get_metrics_collector().record_decision(action, confidence, policy, protocol, quantum_adjusted)


def record_violation(
    policy: str,
    severity: str = "medium",
    protocol: str | None = None,
    action: str | None = None,
) -> None:
    """Record violation using global collector."""
    get_metrics_collector().record_violation(policy, severity, protocol, action)
