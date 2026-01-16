# Quantum Assessment Tutorial

This tutorial demonstrates how to use V-NAPE's quantum threat assessment capabilities to evaluate your protocol's vulnerability to quantum attacks.

## Overview

V-NAPE's PQAE module includes a quantum threat context system that:

- Assesses cryptographic primitives for quantum vulnerability
- Evaluates HNDL (Harvest Now, Decrypt Later) risk levels
- Recommends post-quantum algorithm migrations
- Monitors quantum threat indicators in real-time

## Prerequisites

```python
from vnape.pqae.quantum_context import (
    QuantumThreatContext,
    QuantumCapability,
    QuantumRiskLevel,
    CryptographicPrimitive,
    PrimitiveVulnerability,
    QUANTUM_CAPABILITIES,
)
```

## Basic Quantum Assessment

### Step 1: Create a Quantum Threat Context

```python
# Initialize the quantum threat context with default capabilities
context = QuantumThreatContext()

# Or configure with specific threat assumptions
context = QuantumThreatContext(
    capability=QUANTUM_CAPABILITIES["near_term_2030"],
    data_retention_years=10,  # Data sensitivity window
)
```

### Step 2: Assess Cryptographic Primitives

```python
# Assess a classical algorithm (vulnerable to quantum attacks)
rsa_risk = context.assess_primitive(CryptographicPrimitive.RSA)
print(f"RSA Risk Level: {rsa_risk}")  # QuantumRiskLevel.CRITICAL

ecdh_risk = context.assess_primitive(CryptographicPrimitive.ECDH)
print(f"ECDH Risk Level: {ecdh_risk}")  # QuantumRiskLevel.CRITICAL

# Get detailed vulnerability information
rsa_vuln = context.get_vulnerability(CryptographicPrimitive.RSA)
if rsa_vuln:
    print(f"Quantum Vulnerable: {rsa_vuln.quantum_vulnerable}")
    print(f"Attack Type: {rsa_vuln.attack_type}")
    print(f"Migration Urgency: {rsa_vuln.migration_urgency}")
    print(f"Recommended Replacement: {rsa_vuln.recommended_replacement}")
```

### Step 3: Assess Post-Quantum Algorithms

```python
# Assess ML-KEM (post-quantum safe)
mlkem_risk = context.assess_primitive(CryptographicPrimitive.ML_KEM)
print(f"ML-KEM Risk Level: {mlkem_risk}")  # QuantumRiskLevel.LOW

# Assess ML-DSA signatures
mldsa_risk = context.assess_primitive(CryptographicPrimitive.ML_DSA)
print(f"ML-DSA Risk Level: {mldsa_risk}")  # QuantumRiskLevel.LOW
```

## Understanding Risk Levels

```python
from vnape.pqae.quantum_context import QuantumRiskLevel

# Risk levels from most to least severe:
# - CRITICAL: Immediate migration required
# - HIGH: Migration should begin now
# - MEDIUM: Plan migration within 2-3 years
# - LOW: Quantum-safe, no immediate action needed
# - NONE: No quantum threat

for primitive in CryptographicPrimitive:
    risk = context.assess_primitive(primitive)
    print(f"{primitive.name}: {risk.name}")
```

## Protocol-Level Assessment

Assess an entire protocol's quantum readiness:

```python
from vnape.protocols.imessage_pq3 import IMessagePQ3Protocol

# Load protocol
protocol = IMessagePQ3Protocol()

# Perform comprehensive assessment
assessment = context.assess_protocol(protocol)

print(f"Protocol: {assessment.protocol_name}")
print(f"Overall Risk: {assessment.overall_risk}")
print(f"Vulnerable Primitives: {assessment.vulnerable_primitives}")
print(f"Safe Primitives: {assessment.safe_primitives}")

# Get recommendations
for rec in assessment.recommendations:
    print(f"  - {rec}")
```

## Configuring Quantum Capabilities

Different threat models based on quantum computing timeline:

```python
from vnape.pqae.quantum_context import QUANTUM_CAPABILITIES

# Current (2024) - Limited quantum capabilities
current = QUANTUM_CAPABILITIES["current_2024"]
print(f"Years to CRQC: {current.years_to_crqc}")

# Near-term (2030) - Improved quantum computers
near_term = QUANTUM_CAPABILITIES["near_term_2030"]
print(f"Years to CRQC: {near_term.years_to_crqc}")

# CRQC Ready - Cryptographically relevant quantum computer exists
crqc = QUANTUM_CAPABILITIES["crqc_ready"]
print(f"Years to CRQC: {crqc.years_to_crqc}")

# Use different capability in context
context = QuantumThreatContext(
    capability=near_term,
    data_retention_years=15
)
```

## Registering Custom Vulnerabilities

Add custom primitives or override defaults:

```python
from vnape.pqae.quantum_context import PrimitiveVulnerability, QuantumRiskLevel

# Register a custom primitive vulnerability
context.register_custom_vulnerability(
    primitive=CryptographicPrimitive.NTRU,
    vulnerability=PrimitiveVulnerability(
        quantum_vulnerable=False,
        attack_type=None,
        classical_security_bits=256,
        quantum_security_bits=128,
        migration_urgency=QuantumRiskLevel.LOW,
        recommended_replacement=None,
    )
)
```

## Integration with Enforcement

Use quantum context in your enforcement pipeline:

```python
from vnape.pqae.enforcer import ProactiveEnforcer, EnforcementMode
from vnape.core.types import QuantumContext

# Create quantum-aware enforcer
enforcer = ProactiveEnforcer(
    mode=EnforcementMode.STRICT,
)

# Set quantum context for policy decisions
quantum_ctx = QuantumContext(
    algorithms=["ML-KEM-768", "X25519"],
    quantum_safety_level="hybrid",
    ratchet_required=True,
)

# Process events with quantum awareness
for event in protocol_events:
    result = enforcer.process_event(event)
    if not result.permitted:
        print(f"Blocked: {result.reason}")
```

## Best Practices

1. **Regular Reassessment**: Quantum threat landscape evolves; reassess quarterly
2. **Conservative Timelines**: Assume Q-day could arrive earlier than predicted
3. **Hybrid Deployments**: Use hybrid classical+PQ during transition period
4. **Data Classification**: Prioritize migration based on data sensitivity
5. **Algorithm Agility**: Design systems to support algorithm substitution

## Next Steps

- [Policy Refinement](policy_refinement.md) - Learn how V-NAPE adapts policies
- [Custom Protocols](custom_protocols.md) - Define your own protocol assessments
