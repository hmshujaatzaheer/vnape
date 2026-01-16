# Monitoring Dashboard Tutorial

This tutorial demonstrates how to set up real-time visualization and monitoring for V-NAPE enforcement activities.

## Overview

V-NAPE's monitoring capabilities provide:

- Real-time enforcement activity visualization
- Policy violation tracking and alerting
- Quantum threat level monitoring
- Performance metrics and latency tracking
- Refinement activity logging

## Prerequisites

```python
from vnape.utils.visualization import (
    TraceVisualizer,
    MetricsVisualizer,
    PolicyVisualizer,
    ProtocolStateVisualizer,
)
from vnape.utils.metrics import MetricsCollector, get_metrics_collector
from vnape.utils.logging import get_logger, configure_logging
```

## Basic Metrics Collection

### Step 1: Configure Metrics Collection

```python
# Get the global metrics collector
metrics = get_metrics_collector()

# Reset metrics for a new monitoring session
metrics.reset()

# Configure logging
configure_logging(level="INFO", format="structured")
logger = get_logger("vnape.monitoring")
```

### Step 2: Instrument Your Enforcement Pipeline

```python
from vnape.pqae.enforcer import ProactiveEnforcer, EnforcementMode

# Create enforcer with metrics enabled
enforcer = ProactiveEnforcer(
    mode=EnforcementMode.PERMISSIVE,
    enable_metrics=True,
)

# Process events - metrics are collected automatically
for event in protocol_events:
    result = enforcer.process_event(event)
    
    # Log enforcement decisions
    logger.info(
        "enforcement_decision",
        event_type=event.event_type,
        permitted=result.permitted,
        latency_ms=result.latency_ms,
    )
```

### Step 3: Access Collected Metrics

```python
# Get performance statistics
perf = metrics.performance.get_statistics("end_to_end_latency_ms")
print(f"Average latency: {perf['mean']:.2f}ms")
print(f"P99 latency: {perf['max']:.2f}ms")

# Get security metrics
print(f"Total violations: {metrics.security.policy_violations_total}")
print(f"Critical violations: {metrics.security.critical_violations}")

# Get enforcement statistics
print(f"Total decisions: {metrics.enforcement.total_decisions}")
print(f"Permit rate: {metrics.enforcement.permit_rate:.2%}")
```

## Visualization

### Trace Timeline Visualization

```python
from vnape.utils.visualization import TraceVisualizer, PlotConfig

# Configure visualization
config = PlotConfig(
    width=1200,
    height=400,
    title="Protocol Execution Timeline",
    theme="light",
)

visualizer = TraceVisualizer(config)

# Generate timeline HTML
timeline_html = visualizer.timeline(
    events=protocol_events,
    highlight_violations=True,
)

# Save to file
with open("timeline.html", "w") as f:
    f.write(timeline_html)
```

### Sequence Diagram Generation

```python
# Generate Mermaid sequence diagram
sequence_diagram = visualizer.sequence_diagram(
    events=protocol_events,
    participants=["Alice", "Bob", "Server"],
)

print(sequence_diagram)
# Output: sequenceDiagram
#     Alice->>Server: KeyExchange
#     Server->>Bob: KeyExchange
#     ...
```

### Metrics Dashboard

```python
from vnape.utils.visualization import MetricsVisualizer

metrics_viz = MetricsVisualizer()

# Generate latency distribution chart
latency_chart = metrics_viz.latency_histogram(
    data=metrics.performance.end_to_end_latency_ms,
    title="Enforcement Latency Distribution",
)

# Generate violation timeline
violation_chart = metrics_viz.violation_timeline(
    violations=metrics.security.violations_over_time,
    title="Policy Violations Over Time",
)

# Generate combined dashboard
dashboard = metrics_viz.dashboard(
    metrics=metrics,
    include_performance=True,
    include_security=True,
    include_enforcement=True,
)

with open("dashboard.html", "w") as f:
    f.write(dashboard)
```

## Real-Time Monitoring

### WebSocket-Based Live Dashboard

```python
import asyncio
from vnape.utils.metrics import MetricsCollector

async def metrics_stream():
    """Stream metrics updates via WebSocket."""
    metrics = get_metrics_collector()
    
    while True:
        yield {
            "timestamp": datetime.now().isoformat(),
            "latency_avg": metrics.performance.get_statistics(
                "end_to_end_latency_ms"
            )["mean"],
            "violations_total": metrics.security.policy_violations_total,
            "decisions_per_sec": metrics.enforcement.decisions_per_second,
            "quantum_threat_level": metrics.security.quantum_threats_detected,
        }
        await asyncio.sleep(1)
```

### Prometheus Integration

Export metrics in Prometheus format:

```python
def prometheus_metrics():
    """Export metrics in Prometheus format."""
    metrics = get_metrics_collector()
    
    lines = [
        "# HELP vnape_enforcement_latency_ms Enforcement latency in milliseconds",
        "# TYPE vnape_enforcement_latency_ms histogram",
        f"vnape_enforcement_latency_ms_sum {sum(metrics.performance.end_to_end_latency_ms)}",
        f"vnape_enforcement_latency_ms_count {len(metrics.performance.end_to_end_latency_ms)}",
        "",
        "# HELP vnape_violations_total Total policy violations",
        "# TYPE vnape_violations_total counter",
        f"vnape_violations_total {metrics.security.policy_violations_total}",
        "",
        "# HELP vnape_quantum_threats Quantum threats detected",
        "# TYPE vnape_quantum_threats counter",
        f"vnape_quantum_threats {metrics.security.quantum_threats_detected}",
    ]
    
    return "\n".join(lines)
```

### Grafana Dashboard Configuration

Example Grafana dashboard JSON:

```json
{
  "dashboard": {
    "title": "V-NAPE Monitoring",
    "panels": [
      {
        "title": "Enforcement Latency",
        "type": "graph",
        "targets": [
          {
            "expr": "vnape_enforcement_latency_ms",
            "legendFormat": "Latency (ms)"
          }
        ]
      },
      {
        "title": "Policy Violations",
        "type": "stat",
        "targets": [
          {
            "expr": "vnape_violations_total",
            "legendFormat": "Total Violations"
          }
        ]
      },
      {
        "title": "Quantum Threat Level",
        "type": "gauge",
        "targets": [
          {
            "expr": "vnape_quantum_threats",
            "legendFormat": "Threats"
          }
        ]
      }
    ]
  }
}
```

## Alerting

### Configure Alert Rules

```python
from vnape.utils.metrics import AlertRule, AlertManager

# Create alert manager
alert_manager = AlertManager()

# Add alert rules
alert_manager.add_rule(AlertRule(
    name="high_violation_rate",
    condition=lambda m: m.security.policy_violations_total > 100,
    severity="critical",
    message="High number of policy violations detected",
))

alert_manager.add_rule(AlertRule(
    name="latency_spike",
    condition=lambda m: m.performance.get_statistics(
        "end_to_end_latency_ms"
    )["mean"] > 50,
    severity="warning",
    message="Enforcement latency exceeds threshold",
))

alert_manager.add_rule(AlertRule(
    name="quantum_threat",
    condition=lambda m: m.security.quantum_threats_detected > 0,
    severity="critical",
    message="Quantum threat indicator detected",
))

# Check alerts
alerts = alert_manager.check(metrics)
for alert in alerts:
    print(f"[{alert.severity}] {alert.name}: {alert.message}")
```

### Webhook Notifications

```python
import requests

def send_alert_webhook(alert):
    """Send alert to webhook endpoint."""
    payload = {
        "severity": alert.severity,
        "name": alert.name,
        "message": alert.message,
        "timestamp": datetime.now().isoformat(),
    }
    
    requests.post(
        "https://your-webhook-endpoint.com/alerts",
        json=payload,
        timeout=5,
    )
```

## Export and Reporting

### Generate Summary Report

```python
def generate_summary_report(metrics: MetricsCollector) -> str:
    """Generate a markdown summary report."""
    report = f"""
# V-NAPE Monitoring Report

Generated: {datetime.now().isoformat()}

## Performance Metrics

| Metric | Value |
|--------|-------|
| Average Latency | {metrics.performance.get_statistics('end_to_end_latency_ms')['mean']:.2f}ms |
| Max Latency | {metrics.performance.get_statistics('end_to_end_latency_ms')['max']:.2f}ms |
| Events Processed | {len(metrics.performance.end_to_end_latency_ms)} |

## Security Metrics

| Metric | Value |
|--------|-------|
| Total Violations | {metrics.security.policy_violations_total} |
| Critical | {metrics.security.critical_violations} |
| High | {metrics.security.high_violations} |
| Quantum Threats | {metrics.security.quantum_threats_detected} |

## Enforcement Statistics

| Metric | Value |
|--------|-------|
| Total Decisions | {metrics.enforcement.total_decisions} |
| Permits | {metrics.enforcement.permits} |
| Blocks | {metrics.enforcement.blocks} |
"""
    return report
```

## Best Practices

1. **Metric Retention**: Configure appropriate retention periods for historical analysis
2. **Alert Tuning**: Start with conservative thresholds and tune based on baseline
3. **Dashboard Access**: Restrict dashboard access to authorized personnel
4. **Performance Impact**: Monitor the monitoring overhead itself
5. **Compliance Logging**: Ensure audit logs meet regulatory requirements

## Next Steps

- [CI/CD Integration](cicd_integration.md) - Integrate monitoring into your pipeline
- [Quantum Assessment](quantum_assessment.md) - Monitor quantum threat levels
