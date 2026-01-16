# Policy Refinement Tutorial

This tutorial demonstrates how V-NAPE's Neural Policy Adaptation (NPA) module learns and refines security policies from protocol execution traces.

## Overview

The NPA module provides:

- Automatic pattern detection in execution traces
- Policy refinement proposal generation
- Confidence-based filtering of refinements
- Integration with the Symbolic Verification Bridge (SVB)

## Prerequisites

```python
from vnape.npa.adapter import NeuralPolicyAdapter
from vnape.npa.encoder import TraceEncoder
from vnape.npa.pattern_detector import PatternDetector
from vnape.npa.generator import RefinementGenerator
from vnape.core.types import (
    TraceEvent,
    ExecutionTrace,
    ProtocolEvent,
    EventType,
    PolicyFormula,
    MFOTLFormula,
    PolicyRefinement,
    RefinementType,
)
```

## Basic Policy Refinement

### Step 1: Create an Execution Trace

```python
from datetime import datetime

# Create protocol events
events = [
    ProtocolEvent(
        event_type=EventType.KEY_EXCHANGE,
        timestamp=1000,
        relation="KeyExchange",
        values={"session": "s1", "algorithm": "ML-KEM-768"},
    ),
    ProtocolEvent(
        event_type=EventType.MESSAGE_SEND,
        timestamp=1500,
        relation="MessageSend",
        values={"session": "s1", "msg_id": "m1"},
    ),
    ProtocolEvent(
        event_type=EventType.KEY_RATCHET,
        timestamp=2000,
        relation="KeyRatchet",
        values={"session": "s1", "new_key": "k2"},
    ),
]

# Create execution trace
trace = ExecutionTrace(
    trace_id="trace_001",
    protocol_name="test_protocol",
    events=events,
)
```

### Step 2: Initialize the NPA Module

```python
# Initialize the neural policy adapter
npa = NeuralPolicyAdapter(
    embed_dim=128,
    num_heads=4,
    num_layers=2,
    vocab_size=1000,
    max_seq_length=512,
    confidence_threshold=0.8,
)

# Set vocabulary for event types
npa.set_vocabulary({
    "KeyExchange": 1,
    "MessageSend": 2,
    "KeyRatchet": 3,
    "SessionStart": 4,
    "SessionEnd": 5,
})
```

### Step 3: Propose Refinements

```python
# Generate refinement proposals from the trace
refinements = npa.propose_refinements(
    trace=trace,
    max_refinements=5,
    context={"protocol": "PQ3", "mode": "hybrid"},
)

# Review proposals
for refinement in refinements:
    print(f"Refinement ID: {refinement.refinement_id}")
    print(f"Type: {refinement.refinement_type}")
    print(f"Confidence: {refinement.confidence:.2f}")
    print(f"Delta Formula: {refinement.delta_formula.formula}")
    print(f"Evidence Count: {refinement.evidence_count}")
    print("---")
```

## Anomaly Detection

The NPA module can detect anomalous patterns in traces:

```python
# Detect anomalies in the trace
anomalies = npa.detect_anomalies(
    trace=trace,
    threshold=0.7,
)

for anomaly in anomalies:
    print(f"Pattern: {anomaly.pattern_type}")
    print(f"Score: {anomaly.score:.2f}")
    print(f"Position: {anomaly.position}")
```

## Getting Trace Embeddings

For advanced analysis, get the neural embedding of a trace:

```python
# Get the embedding vector for a trace
embedding = npa.get_trace_embedding(trace)
print(f"Embedding shape: {embedding.shape}")
```

## Refinement Types

V-NAPE supports several types of policy refinements:

```python
from vnape.core.types import RefinementType

# CONJUNCTIVE_EXTENSION: Add additional conditions
# Original: □ (Send(m) → Encrypted(m))
# Refined:  □ (Send(m) → Encrypted(m) ∧ Authenticated(m))

# PARAMETER_TIGHTENING: Tighten time bounds
# Original: ◇[0,3600] Response(r)
# Refined:  ◇[0,1800] Response(r)

# SCOPE_RESTRICTION: Restrict quantification scope
# Original: ∀s. □ Fresh(s)
# Refined:  ∀s. (Active(s) → □ Fresh(s))

# EXCEPTION_ADDITION: Add exception clauses
# Original: □ Encrypted(m)
# Refined:  □ (¬Heartbeat(m) → Encrypted(m))
```

## Verification with SVB

Before applying refinements, verify them with the Symbolic Verification Bridge:

```python
from vnape.svb.bridge import SymbolicVerificationBridge
from vnape.svb.abstraction import PolicyAbstraction

# Initialize SVB
svb = SymbolicVerificationBridge()

# Define safety invariants
invariants = [
    MFOTLFormula(formula="□ (Send(m) → ¬Leaked(m))"),
    MFOTLFormula(formula="□ (KeyExchange(s,k) → Valid(k))"),
]

# Define base policy
base_policy = PolicyFormula(
    formula="□[0,∞) (SessionActive(s) → ◇[0,3600] KeyRatchet(s, k))",
    name="ratchet_freshness",
)

# Verify each refinement
for refinement in refinements:
    result = svb.verify_refinement(
        base_policy=base_policy,
        refinement=refinement,
        invariants=invariants,
    )
    
    if result.status.value == "accepted":
        print(f"✓ Refinement {refinement.refinement_id} verified")
        print(f"  Certificate: {result.certificate}")
    else:
        print(f"✗ Refinement {refinement.refinement_id} rejected")
        if result.counterexample:
            print(f"  Counterexample: {result.counterexample}")
```

## Training the NPA Model

For production use, train the NPA model on your protocol traces:

```python
from vnape.core.types import ExecutionTrace
from pathlib import Path

# Prepare training data
training_traces: list[ExecutionTrace] = [...]  # Your traces
labels: list[int] = [...]  # 0 = normal, 1 = violation

# Train the model
history = npa.fit(
    traces=training_traces,
    labels=labels,
    epochs=100,
    batch_size=32,
    learning_rate=1e-4,
    validation_split=0.2,
)

print(f"Final training loss: {history['train_loss'][-1]:.4f}")
print(f"Final validation loss: {history['val_loss'][-1]:.4f}")

# Save trained model
npa.save(Path("models/npa_trained.pt"))

# Load model later
npa.load(Path("models/npa_trained.pt"))

# Or use class method
loaded_npa = NeuralPolicyAdapter.from_pretrained(
    Path("models/npa_trained.pt"),
    device="cpu",
)
```

## Integration with Enforcement

Use NPA refinements in your enforcement pipeline:

```python
from vnape.pqae.enforcer import ProactiveEnforcer, EnforcementMode

# Create enforcer
enforcer = ProactiveEnforcer(
    mode=EnforcementMode.PERMISSIVE,
)

# Process traces and apply verified refinements
for trace in incoming_traces:
    # Get refinement proposals
    proposals = npa.propose_refinements(trace, max_refinements=3)
    
    # Verify and apply
    for proposal in proposals:
        result = svb.verify_refinement(base_policy, proposal, invariants)
        if result.status.value == "accepted":
            # Apply to enforcer's active policy
            enforcer.apply_refinement(proposal)
            print(f"Applied refinement: {proposal.refinement_id}")
```

## Best Practices

1. **Start Conservative**: Use high confidence thresholds initially (≥0.85)
2. **Always Verify**: Never apply unverified refinements to production
3. **Monitor Refinements**: Log all applied refinements for auditing
4. **Gradual Adoption**: Start in audit mode before strict enforcement
5. **Regular Retraining**: Update NPA model as protocol behavior evolves

## Next Steps

- [CI/CD Integration](cicd_integration.md) - Integrate V-NAPE into your pipeline
- [Monitoring Dashboard](monitoring_dashboard.md) - Visualize refinement activity
