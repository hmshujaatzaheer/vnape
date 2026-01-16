# Quick Start Guide

This guide walks you through using V-NAPE to verify a post-quantum cryptographic protocol trace.

## Basic Verification Pipeline

V-NAPE processes protocol traces through three stages:

1. **NPA (Neural Policy Adaptation)**: Learns patterns and detects anomalies
2. **SVB (Symbolic Verification Bridge)**: Translates to formal logic and verifies
3. **PQAE (Proactive Quantum-Aware Enforcement)**: Monitors and enforces policies

```
Protocol Trace → [NPA] → [SVB] → [PQAE] → Enforcement Decision
```

## Step 1: Create Configuration

```python
from vnape.core.types import SecurityLevel, QuantumSafetyLevel

# Basic configuration
config = VNAPEConfig(
    security_level=SecurityLevel.HIGH,
    quantum_safety_level=QuantumSafetyLevel.HYBRID,
    enable_proactive_enforcement=True
)
```

### Configuration Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `security_level` | Overall security strictness | `HIGH` |
| `quantum_safety_level` | Quantum resistance requirement | `HYBRID` |
| `enable_proactive_enforcement` | Enable PQAE enforcement | `True` |
| `cache_verifications` | Cache verification results | `True` |
| `npa_device` | Device for neural ops (`cpu`/`cuda`) | `cpu` |

## Step 2: Load a Protocol

V-NAPE includes built-in support for iMessage PQ3 and AKMA+:

```python
from vnape.protocols import IMessagePQ3Protocol, AKMAPlusProtocol

# iMessage PQ3 (Apple's post-quantum messaging)
protocol = IMessagePQ3Protocol()

# Or AKMA+ (5G authentication)
# protocol = AKMAPlusProtocol()
```

## Step 3: Create Protocol Traces

A trace represents a sequence of protocol events:

```python
from vnape.core.types import TraceEvent, ProtocolTrace, TemporalInterval

# Create events
events = [
    TraceEvent(
        event_id="e1",
        event_type="KEY_EXCHANGE_INIT",
        timestamp=TemporalInterval(start=0.0, end=0.1),
        state="INITIAL",
        parameters={"algorithm": "ECDH+ML-KEM"},
        security_level=SecurityLevel.HIGH
    ),
    TraceEvent(
        event_id="e2",
        event_type="HYBRID_KEY_AGREEMENT",
        timestamp=TemporalInterval(start=0.1, end=0.3),
        state="KEY_EXCHANGE",
        parameters={"ecdh_curve": "P-256", "kem": "ML-KEM-768"},
        security_level=SecurityLevel.HIGH
    ),
    TraceEvent(
        event_id="e3",
        event_type="SESSION_ESTABLISHED",
        timestamp=TemporalInterval(start=0.3, end=0.4),
        state="ACTIVE",
        parameters={"cipher": "AES-256-GCM"},
        security_level=SecurityLevel.HIGH
    )
]

# Create trace
trace = ProtocolTrace(
    trace_id="trace_001",
    protocol_name="iMessage_PQ3",
    events=events,
    metadata={"session_type": "new"}
)
```

## Step 4: Process the Trace

```python
from vnape import VNAPE

# Create V-NAPE pipeline
vnape = VNAPE(config)
vnape.load_protocol(protocol)

# Process trace
result = vnape.process_trace(trace)
```

## Step 5: Examine Results

### Enforcement Decision

```python
from vnape.core.types import EnforcementAction

if result.enforcement.action == EnforcementAction.ALLOW:
    print("✓ Trace verified as safe")
elif result.enforcement.action == EnforcementAction.DENY:
    print("✗ Trace blocked:", result.enforcement.reason)
elif result.enforcement.action == EnforcementAction.WARN:
    print("⚠ Warning:", result.enforcement.reason)
```

### NPA Results

```python
# Pattern detection results
for pattern in result.npa.detected_patterns:
    print(f"Pattern: {pattern.name}")
    print(f"  Type: {pattern.pattern_type}")
    print(f"  Confidence: {pattern.confidence:.2f}")

# Anomaly scores
for anomaly in result.npa.anomalies:
    print(f"Anomaly at {anomaly.event_id}: {anomaly.score:.3f}")
```

### SVB Verification

```python
# Verification result
print(f"Verified: {result.svb.is_satisfied}")
print(f"Verification time: {result.svb.verification_time:.3f}s")

# Proof certificate
if result.svb.certificate:
    cert = result.svb.certificate
    print(f"Certificate ID: {cert.certificate_id}")
    print(f"Property: {cert.property_verified}")
    print(f"Valid: {cert.is_valid}")
```

### PQAE Monitoring

```python
# Quantum threat assessment
quantum = result.pqae.quantum_context
print(f"HNDL Risk: {quantum.hndl_risk:.2%}")
print(f"Overall Quantum Risk: {quantum.overall_risk:.2%}")

# Policy violations
for violation in result.pqae.violations:
    print(f"Violation: {violation.violation_type}")
    print(f"  Severity: {violation.severity}")
    print(f"  Formula: {violation.formula}")
```

## Complete Example

```python
"""Complete V-NAPE verification example."""

from vnape import VNAPE, VNAPEConfig
from vnape.core.types import (
    SecurityLevel, QuantumSafetyLevel,
    TraceEvent, ProtocolTrace, TemporalInterval,
    EnforcementAction
)
from vnape.protocols import IMessagePQ3Protocol

# 1. Configure
config = VNAPEConfig(
    security_level=SecurityLevel.HIGH,
    quantum_safety_level=QuantumSafetyLevel.HYBRID,
    enable_proactive_enforcement=True
)

# 2. Create pipeline
vnape = VNAPE(config)

# 3. Load protocol
protocol = IMessagePQ3Protocol()
vnape.load_protocol(protocol)

# 4. Create trace
trace = ProtocolTrace(
    trace_id="demo_001",
    protocol_name="iMessage_PQ3",
    events=[
        TraceEvent(
            event_id="e1",
            event_type="KEY_EXCHANGE_INIT",
            timestamp=TemporalInterval(start=0.0, end=0.1),
            state="INITIAL",
            parameters={"algorithm": "ECDH+ML-KEM"},
            security_level=SecurityLevel.HIGH
        ),
        TraceEvent(
            event_id="e2",
            event_type="SESSION_ESTABLISHED",
            timestamp=TemporalInterval(start=0.1, end=0.2),
            state="ACTIVE",
            parameters={},
            security_level=SecurityLevel.HIGH
        )
    ]
)

# 5. Process
result = vnape.process_trace(trace)

# 6. Check result
if result.enforcement.action == EnforcementAction.ALLOW:
    print("✓ Protocol trace verified successfully")
    print(f"  Quantum risk: {result.pqae.quantum_context.overall_risk:.1%}")
else:
    print(f"✗ Verification failed: {result.enforcement.reason}")
```

## Next Steps

- Learn about [Core Concepts](concepts.md)
- Explore [iMessage PQ3 Protocol](protocols/imessage_pq3.md)
- Read about [Quantum Assessment](tutorials/quantum_assessment.md)
- Create a [Custom Protocol](protocols/custom.md)
