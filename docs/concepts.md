# Core Concepts

This document explains the fundamental concepts and architecture of V-NAPE.

## Overview

V-NAPE (Verified Neural Adaptive Policy Enforcement) bridges the gap between neural learning and formal verification for post-quantum cryptographic protocols. It achieves this through three integrated components:

```
┌─────────────────────────────────────────────────────────────────────┐
│                         V-NAPE Pipeline                             │
│                                                                     │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐             │
│  │     NPA     │    │     SVB     │    │    PQAE    │             │
│  │   Neural    │───▶│  Symbolic   │───▶│  Quantum-  │───▶ Decision │
│  │  Learning   │    │Verification │    │   Aware    │             │
│  └─────────────┘    └─────────────┘    └─────────────┘             │
│        │                  │                  │                      │
│        ▼                  ▼                  ▼                      │
│   Patterns           Proofs           Violations                   │
│   Anomalies        Certificates       Enforcement                  │
│   Refinements      Abstractions       Quantum Risk                 │
└─────────────────────────────────────────────────────────────────────┘
```

## Metric First-Order Temporal Logic (MFOTL)

V-NAPE uses MFOTL for specifying and verifying security policies. MFOTL extends first-order logic with temporal operators that can reason about time-bounded properties.

### Temporal Operators

| Operator | Symbol | Meaning |
|----------|--------|---------|
| Always (past) | □[a,b] | Property held at all times in [a,b] ago |
| Eventually (past) | ◇[a,b] | Property held at some time in [a,b] ago |
| Previous | ● | Property held at immediately previous time |
| Since | S[a,b] | φ since ψ within [a,b] time units |
| Always (future) | ■[a,b] | Property will hold at all times in [a,b] |
| Eventually (future) | ◆[a,b] | Property will hold at some time in [a,b] |
| Next | ○ | Property will hold at next time |
| Until | U[a,b] | φ until ψ within [a,b] time units |

### Example Policies

**Key Freshness**: A key must be refreshed within 86400 seconds
```
□[0,∞] (key_used(k) → ◇[0,86400] key_generated(k))
```

**Authentication Before Data**: Cannot send data unless authenticated within last 3600s
```
□[0,∞] (data_sent(d) → ◇[0,3600] authenticated(session))
```

**Quantum Safety**: All key exchanges must use post-quantum algorithms
```
□[0,∞] (key_exchange(k) → pq_algorithm(k))
```

## Neural Policy Adaptation (NPA)

The NPA module learns protocol behavior patterns using neural networks and generates policy refinements.

### Architecture

```
                    ┌─────────────────────────────────────┐
                    │         Neural Policy Adapter        │
                    │                                     │
Protocol     ┌──────┼──────────────────────────────────────┤
Trace   ────▶│ Trace │  ┌─────────────────────────────────┐│
             │Encoder│  │    Attention-Based Detection    ││
             │       │  │  ┌─────────┐  ┌───────────────┐ ││
             │ d_model│  │  │Anomaly  │  │   Temporal    │ ││──▶ Patterns
             │  =256 │  │  │Detector │  │Pattern Detect │ ││    Anomalies
             │       │  │  └─────────┘  └───────────────┘ ││
             │n_heads│  └─────────────────────────────────┘│
             │  =8   │                                     │
             └──────┼──────────────────────────────────────┤
                    │      Refinement Generator            │──▶ Refinements
                    └─────────────────────────────────────┘
```

### Trace Encoding

Events are encoded using:
1. **Event Type Embedding**: Learned embeddings for event types
2. **Positional Encoding**: Sinusoidal encoding for sequence position
3. **Temporal Encoding**: Time interval information
4. **Parameter Encoding**: Event-specific parameters

### Pattern Detection

Multi-head attention mechanisms identify:
- **Anomalous sequences**: Events that deviate from learned patterns
- **Temporal violations**: Timing constraint breaches
- **State inconsistencies**: Invalid state transitions

### Refinement Generation

When patterns or anomalies suggest policy updates, NPA generates MFOTL refinements:

```python
# Example: Learned pattern suggests adding timing constraint
refinement = Refinement(
    original="key_exchange(k)",
    refined="key_exchange(k) ∧ ◇[0,1000] key_confirmation(k)",
    confidence=0.87,
    evidence=["Observed 1000ms timeout in 94% of traces"]
)
```

## Symbolic Verification Bridge (SVB)

SVB translates learned patterns to formal logic and verifies them using SMT solving.

### MFOTL to Z3 Translation

```
MFOTL Formula                    Z3 Representation
─────────────────────────────────────────────────────
□[0,10] P(x)              ForAll([t], Implies(0 <= t <= 10, P(x, t)))
◇[0,10] P(x)              Exists([t], And(0 <= t <= 10, P(x, t)))
P(x) S[0,10] Q(y)         Exists([t1], And(Q(y,t1), ForAll([t2], ...)))
∀x. P(x) → Q(x)           ForAll([x], Implies(P(x), Q(x)))
```

### Abstraction Engine

For scalability, SVB uses Counterexample-Guided Abstraction Refinement (CEGAR):

```
┌─────────────────────────────────────────────────────────────┐
│                      CEGAR Loop                             │
│                                                             │
│   ┌──────────┐     ┌──────────┐     ┌──────────────────┐   │
│   │ Abstract │────▶│  Verify  │────▶│   Counterexample │   │
│   │  Model   │     │          │     │     Analysis     │   │
│   └──────────┘     └──────────┘     └──────────────────┘   │
│        ▲                                    │               │
│        │              ┌─────────────────────┘               │
│        │              ▼                                     │
│   ┌──────────┐   ┌──────────┐                              │
│   │  Refine  │◀──│ Spurious?│                              │
│   │          │   │   Yes    │                              │
│   └──────────┘   └──────────┘                              │
│                       │ No                                  │
│                       ▼                                     │
│              Real Counterexample                            │
└─────────────────────────────────────────────────────────────┘
```

### Proof Certificates

SVB generates cryptographic certificates for verified properties:

```python
certificate = ProofCertificate(
    certificate_id="cert_abc123",
    property_verified="□[0,∞](auth→◇[0,3600]key_fresh)",
    proof_method=ProofMethod.SMT_UNSAT_CORE,
    verification_time=0.234,
    verifier="Z3-4.12.2",
    signature="sha256:a1b2c3..."
)
```

## Proactive Quantum-Aware Enforcement (PQAE)

PQAE monitors protocol execution in real-time and makes quantum-aware enforcement decisions.

### MFOTL Monitoring

The monitor evaluates MFOTL formulas incrementally as events arrive:

```python
# Monitor state maintained across events
monitor = MFOTLMonitor(formula)

for event in trace.events:
    result = monitor.process_event(event)
    if result.violated:
        # Immediate violation detected
        handle_violation(result.violation)
```

### Quantum Threat Context

PQAE assesses cryptographic primitives against quantum capabilities:

```
┌─────────────────────────────────────────────────────────────┐
│                 Quantum Threat Assessment                   │
│                                                             │
│   Primitive        2024 Risk    2030 Risk    CRQC Risk     │
│   ──────────────────────────────────────────────────────── │
│   RSA-2048         Low (10%)    High (60%)   Critical(95%) │
│   ECDH P-256       Low (10%)    High (60%)   Critical(95%) │
│   ML-KEM-768       None (0%)    None (0%)    Low (5%)      │
│   AES-256          None (0%)    Low (5%)     Medium (30%)  │
│   ──────────────────────────────────────────────────────── │
│                                                             │
│   HNDL Risk = f(retention_period, threat_timeline)         │
└─────────────────────────────────────────────────────────────┘
```

### Harvest Now, Decrypt Later (HNDL) Risk

HNDL risk calculation considers:
- Data retention period
- Expected CRQC timeline
- Cryptographic primitive vulnerabilities

```python
hndl_risk = quantum_context.calculate_hndl_risk(
    retention_years=10,
    primitive=Primitive.ECDH,
    data_sensitivity=Sensitivity.HIGH
)
```

### Enforcement Modes

| Mode | Behavior |
|------|----------|
| `STRICT` | Block any policy violation immediately |
| `PERMISSIVE` | Allow violations but log warnings |
| `AUDIT` | Log all decisions without enforcement |

### Enforcement Decision Flow

```
Event Received
      │
      ▼
┌──────────────┐
│ MFOTL Check  │──── Satisfied ────▶ ALLOW
└──────────────┘
      │ Violated
      ▼
┌──────────────┐
│Quantum Risk  │──── Low Risk ─────▶ WARN
│ Assessment   │
└──────────────┘
      │ High Risk
      ▼
┌──────────────┐
│ Enforcement  │──── STRICT ───────▶ DENY
│    Mode      │──── PERMISSIVE ───▶ WARN
│              │──── AUDIT ────────▶ LOG
└──────────────┘
```

## Protocol Abstraction

V-NAPE provides a base class for defining protocols:

```python
class BaseProtocol:
    """Protocol abstraction."""
    
    # Define states
    states: Set[str]
    
    # Define transitions
    transitions: Set[Tuple[str, str, str]]  # (from, event, to)
    
    # Define security policies
    policies: List[PolicyFormula]
    
    # Validate traces
    def validate_trace(self, trace: ProtocolTrace) -> bool: ...
```

### Supported Protocols

**iMessage PQ3**
- Hybrid key exchange (ECDH + ML-KEM-768)
- Double ratchet with PQ rekeying
- 8 protocol states

**AKMA+ (5G Authentication)**
- Key hierarchy (K_AUSF → K_AKMA → K_AF)
- Application Function authentication
- 6 protocol states

## Integration Benefits

The three components create synergistic capabilities:

| Capability | Individual Components | Integrated System |
|------------|----------------------|-------------------|
| Anomaly Detection | NPA: Pattern-based | NPA + SVB: Formally verified patterns |
| Policy Verification | SVB: Static | SVB + PQAE: Runtime monitoring |
| Quantum Safety | PQAE: Threshold-based | Full pipeline: Adaptive + verified |
| Refinement | NPA: Heuristic | NPA + SVB: Formally sound |

## Next Steps

- [NPA Architecture Details](architecture/npa.md)
- [SVB Verification Methods](architecture/svb.md)
- [PQAE Enforcement Strategies](architecture/pqae.md)
- [API Reference](api/core.md)
