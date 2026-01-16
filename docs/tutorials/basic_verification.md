# Basic Verification Tutorial

This tutorial walks you through verifying your first protocol trace with V-NAPE.

## Prerequisites

- V-NAPE installed (`pip install vnape`)
- Python 3.10 or higher

## Step 1: Import Required Modules

```python
from vnape.core.types import (
    TraceEvent,
    ProtocolTrace,
    ProtocolEvent,
    EventType,
    ExecutionTrace,
)
from vnape.pqae.monitor import MFOTLMonitor, Verdict
from vnape.pqae.enforcer import ProactiveEnforcer, EnforcementMode
```

## Step 2: Create Protocol Events

Protocol events represent actions during protocol execution:

```python
# Create protocol events for the enforcer
events = [
    ProtocolEvent(
        event_type=EventType.SESSION_START,
        timestamp=1000,
        relation="SessionStart",
        values={"session_id": "sess_001"},
    ),
    ProtocolEvent(
        event_type=EventType.KEY_EXCHANGE,
        timestamp=1050,
        relation="KeyExchange",
        values={"algorithm": "ML-KEM-768", "session_id": "sess_001"},
    ),
    ProtocolEvent(
        event_type=EventType.MESSAGE_SEND,
        timestamp=1100,
        relation="MessageSend",
        values={"message_id": "msg_001", "encrypted": True},
    ),
    ProtocolEvent(
        event_type=EventType.KEY_RATCHET,
        timestamp=1500,
        relation="KeyRatchet",
        values={"new_key_id": "key_002", "session_id": "sess_001"},
    ),
]
```

## Step 3: Set Up Enforcement

The ProactiveEnforcer monitors events against MFOTL policies:

```python
# Create enforcer with a base policy
# Policy: All messages must be encrypted
enforcer = ProactiveEnforcer(
    mode=EnforcementMode.PERMISSIVE,  # Log violations but allow execution
    base_policy="□[0,∞) (MessageSend(m) → Encrypted(m))",
)

# Process each event
for event in events:
    result = enforcer.process_event(event)
    print(f"Event: {event.relation}")
    print(f"  Permitted: {result.permitted}")
    print(f"  Action: {result.action}")
```

## Step 4: Understanding Enforcement Modes

V-NAPE supports three enforcement modes:

```python
from vnape.pqae.enforcer import EnforcementMode

# STRICT: Zero-tolerance - blocks any policy violation immediately
strict_enforcer = ProactiveEnforcer(mode=EnforcementMode.STRICT)

# PERMISSIVE: Logs violations, allows with warnings, blocks on threshold
permissive_enforcer = ProactiveEnforcer(mode=EnforcementMode.PERMISSIVE)

# AUDIT: Logging only - no enforcement actions taken
audit_enforcer = ProactiveEnforcer(mode=EnforcementMode.AUDIT)
```

## Step 5: Using the MFOTL Monitor

For direct formula monitoring without enforcement:

```python
from vnape.pqae.monitor import MFOTLMonitor, MFOTLFormula

# Create a trace event
trace_event = TraceEvent(
    event_type="key_exchange",
    timestamp=1000.0,
    data={"algorithm": "ML-KEM-768"},
)

# Create monitor with a formula
formula = MFOTLFormula(formula="KeyExchange(s, k)")
monitor = MFOTLMonitor(formula=formula)

# Process the event
result = monitor.process_event(trace_event)
print(f"Verdict: {result.verdict}")  # Verdict.SATISFIED, VIOLATED, or UNKNOWN
print(f"Satisfying assignments: {result.satisfying_assignments}")
```

## Complete Example

```python
from vnape.core.types import (
    ProtocolEvent,
    EventType,
)
from vnape.pqae.enforcer import ProactiveEnforcer, EnforcementMode


def verify_protocol():
    """Complete verification example."""
    
    # Create test events
    events = [
        ProtocolEvent(
            event_type=EventType.SESSION_START,
            timestamp=1000,
            relation="SessionStart",
            values={"session_id": "s1"},
        ),
        ProtocolEvent(
            event_type=EventType.KEY_EXCHANGE,
            timestamp=1050,
            relation="KeyExchange",
            values={"algorithm": "ML-KEM-768"},
        ),
        ProtocolEvent(
            event_type=EventType.MESSAGE_SEND,
            timestamp=1100,
            relation="MessageSend",
            values={"encrypted": True},
        ),
    ]
    
    # Create enforcer with encryption policy
    enforcer = ProactiveEnforcer(
        mode=EnforcementMode.STRICT,
        base_policy="□[0,∞) (MessageSend(m) → Encrypted(m))",
    )
    
    # Process each event
    results = []
    for event in events:
        result = enforcer.process_event(event)
        results.append(result)
        print(f"{event.relation}: permitted={result.permitted}")
    
    # Check overall result
    all_permitted = all(r.permitted for r in results)
    return all_permitted


if __name__ == "__main__":
    success = verify_protocol()
    print(f"\nVerification complete: {'PASSED' if success else 'FAILED'}")
```

## Expected Output

```
SessionStart: permitted=True
KeyExchange: permitted=True
MessageSend: permitted=True

Verification complete: PASSED
```

## Next Steps

- [Understanding Results](understanding_results.md) - Learn to interpret V-NAPE output
- [Custom Protocols](custom_protocols.md) - Define your own protocol specifications
