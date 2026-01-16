# Understanding V-NAPE Results

This tutorial explains how to interpret the output from V-NAPE verification and enforcement.

## Result Types

V-NAPE produces several types of results depending on which components you use.

### Monitor Verdicts

The MFOTL monitor produces verdicts for each processed event:

```python
from vnape.pqae.monitor import Verdict

# Possible verdict types
Verdict.SATISFIED     # Policy is satisfied
Verdict.VIOLATED      # Policy violation detected
Verdict.UNKNOWN       # Cannot determine (waiting for future events)
Verdict.INCONCLUSIVE  # Not enough information to decide
```

### Enforcement Results

The enforcer returns detailed results for each event:

```python
from vnape.pqae.enforcer import ProactiveEnforcer, EnforcementMode
from vnape.core.types import ProtocolEvent, EventType

# Create enforcer
enforcer = ProactiveEnforcer(mode=EnforcementMode.PERMISSIVE)

# Process an event
event = ProtocolEvent(
    event_type=EventType.MESSAGE_SEND,
    timestamp=1000,
    relation="MessageSend",
    values={"encrypted": True},
)
result = enforcer.process_event(event)

# Access result fields
print(f"Permitted: {result.permitted}")    # True if event was allowed
print(f"Success: {result.success}")        # Same as permitted
print(f"Action: {result.action}")          # EnforcementAction taken
print(f"Violations: {result.violations}")  # List of detected violations
print(f"Timestamp: {result.timestamp}")    # When decision was made
```

## Interpreting Enforcement Actions

```python
from vnape.core.types import EnforcementAction

# An EnforcementAction has these fields:
action = result.action
if action:
    print(f"Action Type: {action.action_type}")    # PERMIT, BLOCK, MODIFY, DELAY
    print(f"Target: {action.target}")              # What the action applies to
    print(f"Parameters: {action.parameters}")      # Additional parameters
    print(f"Confidence: {action.confidence}")      # Confidence score [0, 1]
```

## Interpreting Violations

Each violation contains detailed information:

```python
for violation in result.violations:
    print(f"Policy: {violation['policy_name']}")
    print(f"Timestamp: {violation['timestamp']}")
    print(f"Severity: {violation['severity']}")
    print(f"Event Data: {violation['event_data']}")
```

### Severity Levels

| Level | Description | Action |
|-------|-------------|--------|
| `critical` | Immediate security risk | Block execution |
| `high` | Significant vulnerability | Block or alert |
| `medium` | Potential issue | Log and alert |
| `low` | Minor concern | Log only |

## Monitoring Results

When using the MFOTLMonitor directly:

```python
from vnape.pqae.monitor import MFOTLMonitor, MFOTLFormula, MonitoringResult
from vnape.core.types import TraceEvent

# Create monitor
formula = MFOTLFormula(formula="KeyExchange(s, k)")
monitor = MFOTLMonitor(formula=formula)

# Process event
event = TraceEvent(
    event_type="key_exchange",
    timestamp=1000.0,
    data={"algorithm": "ML-KEM-768"},
)
result: MonitoringResult = monitor.process_event(event)

# Access result
print(f"Verdict: {result.verdict}")
print(f"Satisfying Assignments: {result.satisfying_assignments}")
```

## Verification Certificates

When using the SVB module, you receive verification certificates:

```python
from vnape.svb.bridge import SymbolicVerificationBridge

svb = SymbolicVerificationBridge()

# Verify a refinement
result = svb.verify_refinement(base_policy, refinement, invariants)

if result.status.value == "accepted":
    print(f"Certificate: {result.certificate}")
    print(f"Composed Policy: {result.composed_policy}")
else:
    print(f"Rejected: {result.status}")
    if result.counterexample:
        print(f"Counterexample: {result.counterexample}")
```

## Metrics and Statistics

Access aggregated metrics after processing:

```python
from vnape.utils.metrics import get_metrics_collector

metrics = get_metrics_collector()

# Performance metrics
perf = metrics.performance.get_statistics("end_to_end_latency_ms")
print(f"Average latency: {perf['mean']:.2f}ms")
print(f"Max latency: {perf['max']:.2f}ms")

# Security metrics
print(f"Violations: {metrics.security.policy_violations_total}")
print(f"Critical: {metrics.security.critical_violations}")
```

## Example: Complete Result Analysis

```python
from vnape.pqae.enforcer import ProactiveEnforcer, EnforcementMode
from vnape.core.types import ProtocolEvent, EventType


def analyze_enforcement(enforcer: ProactiveEnforcer, events: list[ProtocolEvent]):
    """Process events and analyze results."""
    
    print("=" * 50)
    print("V-NAPE VERIFICATION REPORT")
    print("=" * 50)
    
    all_results = []
    violations_found = []
    
    for event in events:
        result = enforcer.process_event(event)
        all_results.append(result)
        
        print(f"\nEvent: {event.relation}")
        print(f"  Permitted: {result.permitted}")
        
        if result.action:
            print(f"  Action: {result.action.action_type}")
        
        if result.violations:
            violations_found.extend(result.violations)
            for v in result.violations:
                print(f"  Violation: {v.get('policy_name', 'unknown')}")
    
    # Summary
    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    
    total = len(all_results)
    permitted = sum(1 for r in all_results if r.permitted)
    blocked = total - permitted
    
    print(f"Total Events: {total}")
    print(f"Permitted: {permitted}")
    print(f"Blocked: {blocked}")
    print(f"Violations: {len(violations_found)}")
    
    status = "PASSED" if blocked == 0 else "FAILED"
    print(f"\nOverall Status: {status}")
    
    return blocked == 0


# Usage
events = [
    ProtocolEvent(EventType.KEY_EXCHANGE, 1000, "KeyExchange", {"alg": "ML-KEM"}),
    ProtocolEvent(EventType.MESSAGE_SEND, 2000, "MessageSend", {"encrypted": True}),
]

enforcer = ProactiveEnforcer(mode=EnforcementMode.STRICT)
success = analyze_enforcement(enforcer, events)
```

## Next Steps

- [Custom Protocols](custom_protocols.md) - Define your own protocols
- [Quantum Assessment](quantum_assessment.md) - Assess quantum vulnerability
