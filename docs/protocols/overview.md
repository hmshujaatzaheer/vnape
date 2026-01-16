# Protocol Support

V-NAPE provides built-in support for post-quantum cryptographic protocols and a framework for defining custom protocols.

## Supported Protocols

### iMessage PQ3

Apple's post-quantum secure messaging protocol introduced in 2024.

**Key Features:**
- Hybrid key exchange (ECDH + ML-KEM-768)
- Double ratchet with post-quantum rekeying
- Forward secrecy and post-compromise security

**States:** INITIAL → KEY_EXCHANGE → KEY_AGREEMENT → SESSION_ACTIVE → RATCHETING → KEY_REFRESH → RE_ESTABLISHMENT → TERMINATED

[Learn more about iMessage PQ3](imessage_pq3.md)

### AKMA+ (5G Authentication Enhancement)

Enhanced 5G authentication with post-quantum support.

**Key Features:**
- Key hierarchy: K_AUSF → K_AKMA → K_AF
- Application Function authentication
- Network slice isolation

**States:** INITIAL → KEY_DERIVATION → APP_KEY_GENERATION → AF_AUTHENTICATION → SESSION_ACTIVE → TERMINATED

[Learn more about AKMA+](akma_plus.md)

## Protocol Comparison

| Feature | iMessage PQ3 | AKMA+ |
|---------|--------------|-------|
| Primary Use | Messaging | 5G Auth |
| Key Exchange | Hybrid ECDH+ML-KEM | Key Derivation |
| PQ Algorithm | ML-KEM-768 | Configurable |
| Ratcheting | Yes | No |
| States | 8 | 6 |

## Custom Protocols

V-NAPE's protocol framework allows defining custom protocols:

```python
from vnape.protocols import BaseProtocol
from vnape.core.types import PolicyFormula

class MyProtocol(BaseProtocol):
    """Custom protocol implementation."""
    
    name = "MyProtocol"
    version = "1.0"
    
    states = {"INIT", "AUTH", "ACTIVE", "CLOSED"}
    
    transitions = {
        ("INIT", "authenticate", "AUTH"),
        ("AUTH", "establish", "ACTIVE"),
        ("ACTIVE", "close", "CLOSED"),
    }
    
    @property
    def security_policies(self) -> list[PolicyFormula]:
        return [
            PolicyFormula(
                formula="□[0,∞](active → ◇[0,3600]auth)",
                description="Active sessions require recent auth"
            )
        ]
```

[Learn more about custom protocols](custom.md)

```{toctree}
:maxdepth: 1
:hidden:

imessage_pq3
akma_plus
custom
```
