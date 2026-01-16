# Core API Reference

This module contains the core types, interfaces, and configuration for V-NAPE.

## Types

### Enums

```{eval-rst}
.. autoclass:: vnape.core.types.SecurityLevel
   :members:
   :undoc-members:

.. autoclass:: vnape.core.types.QuantumSafetyLevel
   :members:
   :undoc-members:

.. autoclass:: vnape.core.types.ViolationType
   :members:
   :undoc-members:

.. autoclass:: vnape.core.types.EnforcementAction
   :members:
   :undoc-members:
```

### Data Classes

```{eval-rst}
.. autoclass:: vnape.core.types.TemporalInterval
   :members:
   :undoc-members:

.. autoclass:: vnape.core.types.TraceEvent
   :members:
   :undoc-members:

.. autoclass:: vnape.core.types.ProtocolTrace
   :members:
   :undoc-members:

.. autoclass:: vnape.core.types.PolicyFormula
   :members:
   :undoc-members:

.. autoclass:: vnape.core.types.Violation
   :members:
   :undoc-members:

.. autoclass:: vnape.core.types.Refinement
   :members:
   :undoc-members:
```

### Verification Types

```{eval-rst}
.. autoclass:: vnape.core.types.VerificationResult
   :members:
   :undoc-members:

.. autoclass:: vnape.core.types.ProofCertificate
   :members:
   :undoc-members:

.. autoclass:: vnape.core.types.SymbolicConstraint
   :members:
   :undoc-members:
```

### Quantum Types

```{eval-rst}
.. autoclass:: vnape.core.types.QuantumThreat
   :members:
   :undoc-members:

.. autoclass:: vnape.core.types.EnforcementDecision
   :members:
   :undoc-members:

.. autoclass:: vnape.core.types.MonitorState
   :members:
   :undoc-members:
```

## Configuration

```{eval-rst}
.. autoclass:: vnape.core.config.VNAPEConfig
   :members:
   :undoc-members:

.. autoclass:: vnape.core.config.NPAConfig
   :members:
   :undoc-members:

.. autoclass:: vnape.core.config.SVBConfig
   :members:
   :undoc-members:

.. autoclass:: vnape.core.config.PQAEConfig
   :members:
   :undoc-members:
```

## Interfaces

```{eval-rst}
.. autoclass:: vnape.core.interfaces.TraceEncoderInterface
   :members:
   :undoc-members:

.. autoclass:: vnape.core.interfaces.PatternDetectorInterface
   :members:
   :undoc-members:

.. autoclass:: vnape.core.interfaces.RefinementGeneratorInterface
   :members:
   :undoc-members:

.. autoclass:: vnape.core.interfaces.VerificationBridgeInterface
   :members:
   :undoc-members:

.. autoclass:: vnape.core.interfaces.MonitorInterface
   :members:
   :undoc-members:

.. autoclass:: vnape.core.interfaces.EnforcerInterface
   :members:
   :undoc-members:
```

## Usage Examples

### Creating a Trace Event

```python
from vnape.core.types import TraceEvent, TemporalInterval, SecurityLevel

event = TraceEvent(
    event_id="evt_001",
    event_type="KEY_EXCHANGE",
    timestamp=TemporalInterval(start=0.0, end=0.5),
    state="ACTIVE",
    parameters={"algorithm": "ML-KEM-768"},
    security_level=SecurityLevel.HIGH
)
```

### Building a Protocol Trace

```python
from vnape.core.types import ProtocolTrace

trace = ProtocolTrace(
    trace_id="trace_001",
    protocol_name="iMessage_PQ3",
    events=[event1, event2, event3],
    metadata={"session_type": "new", "user_id": "alice"}
)
```

### Defining a Policy

```python
from vnape.core.types import PolicyFormula

policy = PolicyFormula(
    formula="□[0,∞](key_exchange(k) → ◇[0,86400]key_fresh(k))",
    description="Keys must be refreshed within 24 hours",
    severity=ViolationSeverity.HIGH
)
```
