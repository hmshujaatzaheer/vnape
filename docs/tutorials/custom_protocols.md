# Custom Protocol Definition

This tutorial shows how to define and verify custom cryptographic protocols with V-NAPE.

## Protocol Structure

V-NAPE protocols consist of:
1. **States** - Protocol phases
2. **Events** - Actions that occur
3. **Transitions** - Valid state changes
4. **Security Properties** - Requirements to enforce

## Step 1: Define Protocol States

```python
from enum import Enum, auto

class MyProtocolState(Enum):
    """States for custom protocol."""
    INIT = auto()
    KEY_EXCHANGE = auto()
    AUTHENTICATED = auto()
    ACTIVE = auto()
    RATCHETING = auto()
    TERMINATED = auto()
```

## Step 2: Define Event Types

```python
from vnape.core.types import EventType

# You can use built-in event types:
# - EventType.KEY_EXCHANGE
# - EventType.KEY_RATCHET
# - EventType.MESSAGE_SEND
# - EventType.MESSAGE_RECEIVE
# - EventType.SESSION_START
# - EventType.SESSION_END
# - EventType.AUTHENTICATION
# - EventType.KEY_DERIVATION
# - EventType.ALGORITHM_SWITCH
# - EventType.CUSTOM
```

## Step 3: Define the Protocol Class

```python
from abc import ABC
from vnape.protocols.base import BaseProtocol, ProtocolState, StateType

class MyCustomProtocol(BaseProtocol):
    """Custom post-quantum protocol implementation."""
    
    def __init__(self):
        super().__init__()
        self.name = "MyCustomProtocol"
        self.version = "1.0.0"
        self._setup_states()
        self._setup_transitions()
    
    def _setup_states(self):
        """Define protocol states."""
        self.states = {
            "init": ProtocolState(
                name="init",
                state_type=StateType.INITIAL,
                description="Initial state",
            ),
            "key_exchange": ProtocolState(
                name="key_exchange",
                state_type=StateType.INTERMEDIATE,
                description="Key exchange in progress",
            ),
            "active": ProtocolState(
                name="active",
                state_type=StateType.INTERMEDIATE,
                description="Session active",
            ),
            "terminated": ProtocolState(
                name="terminated",
                state_type=StateType.FINAL,
                description="Session terminated",
            ),
        }
        self.current_state = self.states["init"]
    
    def _setup_transitions(self):
        """Define valid state transitions."""
        self.valid_transitions = {
            "init": ["key_exchange"],
            "key_exchange": ["active"],
            "active": ["active", "terminated"],  # Can ratchet (stay active) or end
            "terminated": [],
        }
```

## Step 4: Define Security Policies

Security policies are expressed in MFOTL (Metric First-Order Temporal Logic):

```python
from vnape.core.types import PolicyFormula, MFOTLFormula

# Create security policies for your protocol
policies = [
    # Forward secrecy: ratchet within time bound (1 hour = 3600000ms)
    PolicyFormula(
        formula="□[0,∞) (Active(s) → ◇[0,3600000] KeyRatchet(s, k))",
        name="forward_secrecy",
    ),
    
    # Post-quantum key exchange required
    PolicyFormula(
        formula="□[0,∞) (KeyExchange(s, k) → PostQuantum(k))",
        name="pq_key_exchange",
    ),
    
    # All messages must be encrypted
    PolicyFormula(
        formula="□[0,∞) (SendMessage(m) → Encrypted(m))",
        name="encryption_required",
    ),
]
```

## Step 5: Use the Protocol with Enforcement

```python
from vnape.core.types import (
    TraceEvent,
    ProtocolTrace,
    ProtocolEvent,
    EventType,
)
from vnape.pqae.enforcer import ProactiveEnforcer, EnforcementMode

# Create protocol instance
protocol = MyCustomProtocol()

# Create enforcer with a base policy
enforcer = ProactiveEnforcer(
    mode=EnforcementMode.STRICT,
    base_policy="□[0,∞) (KeyExchange(s, k) → PostQuantum(k))",
)

# Create protocol events
events = [
    ProtocolEvent(
        event_type=EventType.SESSION_START,
        timestamp=0,
        relation="SessionStart",
        values={"session_id": "s1"},
    ),
    ProtocolEvent(
        event_type=EventType.KEY_EXCHANGE,
        timestamp=1000,
        relation="KeyExchange",
        values={"session_id": "s1", "algorithm": "ML-KEM-768"},
    ),
    ProtocolEvent(
        event_type=EventType.MESSAGE_SEND,
        timestamp=2000,
        relation="SendMessage",
        values={"session_id": "s1", "msg_id": "m1", "encrypted": True},
    ),
]

# Process each event through enforcer
for event in events:
    result = enforcer.process_event(event)
    print(f"Event: {event.relation}")
    print(f"  Permitted: {result.permitted}")
    print(f"  Action: {result.action}")
    if result.reason:
        print(f"  Reason: {result.reason}")
```

## Complete Example: Simple Key Exchange Protocol

```python
from vnape.protocols.base import BaseProtocol, ProtocolState, StateType
from vnape.core.types import (
    TraceEvent,
    ProtocolTrace,
    ProtocolEvent,
    EventType,
    PolicyFormula,
)
from vnape.pqae.enforcer import ProactiveEnforcer, EnforcementMode


class SimpleKEXProtocol(BaseProtocol):
    """Simple key exchange protocol for demonstration."""
    
    POLICY = "□[0,∞) (Init(s) → ◇[0,5000] KeyExchange(s, k))"
    
    def __init__(self):
        super().__init__()
        self.name = "SimpleKEX"
        self.version = "1.0"


def demo_custom_protocol():
    # Create protocol
    protocol = SimpleKEXProtocol()
    
    # Create test events
    events = [
        ProtocolEvent(
            event_type=EventType.SESSION_START,
            timestamp=0,
            relation="Init",
            values={"session": "s1"},
        ),
        ProtocolEvent(
            event_type=EventType.KEY_EXCHANGE,
            timestamp=1000,
            relation="KeyExchange",
            values={"session": "s1", "algorithm": "ML-KEM-768"},
        ),
        ProtocolEvent(
            event_type=EventType.MESSAGE_SEND,
            timestamp=2000,
            relation="Message",
            values={"session": "s1", "encrypted": True},
        ),
    ]
    
    # Create enforcer with protocol policy
    enforcer = ProactiveEnforcer(
        mode=EnforcementMode.PERMISSIVE,
        base_policy=protocol.POLICY,
    )
    
    # Process events
    results = []
    for event in events:
        result = enforcer.process_event(event)
        results.append(result)
        print(f"{event.relation}: permitted={result.permitted}")
    
    return all(r.permitted for r in results)


if __name__ == "__main__":
    success = demo_custom_protocol()
    print(f"\nProtocol verification: {'PASSED' if success else 'FAILED'}")
```

## Built-in Protocol Examples

V-NAPE includes implementations of real-world protocols:

### iMessage PQ3

```python
from vnape.protocols.imessage_pq3 import IMessagePQ3Protocol

# Load the iMessage PQ3 protocol
protocol = IMessagePQ3Protocol()

# Access protocol properties
print(f"Protocol: {protocol.name}")
print(f"Algorithms: ML-KEM-768, X25519 (hybrid)")
```

### AKMA+ (5G)

```python
from vnape.protocols.akma_plus import AKMAPlusProtocol

# Load the AKMA+ protocol
protocol = AKMAPlusProtocol()

# Access protocol properties  
print(f"Protocol: {protocol.name}")
print(f"Key hierarchy: KAUSF → KAKMA → KAF")
```

## Next Steps

- [Quantum Assessment](quantum_assessment.md) - Assess quantum vulnerability of your protocol
- [Policy Refinement](policy_refinement.md) - Learn and refine policies automatically
