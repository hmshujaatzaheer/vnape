# V-NAPE: Verified Neural Adaptive Proactive Enforcement

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/hmshujaatzaheer/vnape/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hmshujaatzaheer/vnape/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/hmshujaatzaheer/vnape/graph/badge.svg?branch=main)](https://codecov.io/gh/hmshujaatzaheer/vnape)

A Framework for Adaptive Runtime Security in Post-Quantum Cryptographic Protocols

## Overview

V-NAPE (Verified Neural Adaptive Proactive Enforcement) is a research framework that addresses the security challenges of post-quantum cryptography transition through three integrated methodologies:

1. **NPA (Neural Policy Adaptation)**: A neural policy adaptation mechanism that learns security-relevant patterns from protocol execution traces using transformer-based architectures.

2. **SVB (Symbolic Verification Bridge)**: A symbolic verification bridge that ensures neural policy decisions satisfy formal correctness criteria through Z3 SMT integration.

3. **PQAE (Proactive Quantum-Aware Enforcement)**: A quantum-aware enforcement engine that extends proactive enforcement capabilities to post-quantum protocol contexts with MFOTL monitoring.

## Key Features

- **Transformer-based trace encoding** for learning protocol execution patterns
- **Z3 SMT integration** for formal verification of neural refinements
- **MFOTL (Metric First-Order Temporal Logic)** monitoring and enforcement
- **Built-in protocol support** for iMessage PQ3 and AKMA+ protocols
- **Configurable enforcement modes**: strict, permissive, and audit
- **Extensible architecture** for custom protocol definitions
- **Certificate generation** for verified policy refinements

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         V-NAPE Framework                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────────┐ │
│  │     NPA      │────▶│     SVB      │────▶│      PQAE        │ │
│  │   Neural     │     │  Symbolic    │     │   Proactive      │ │
│  │   Policy     │     │ Verification │     │  Quantum-Aware   │ │
│  │  Adaptation  │     │    Bridge    │     │  Enforcement     │ │
│  └──────────────┘     └──────────────┘     └──────────────────┘ │
│         │                    │                      │            │
│         ▼                    ▼                      ▼            │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────────┐ │
│  │ Transformer  │     │  Z3 Solver   │     │ MFOTL Monitor    │ │
│  │  Encoder     │     │  Integration │     │ + Enforcer       │ │
│  └──────────────┘     └──────────────┘     └──────────────────┘ │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Installation

### From PyPI (when published)

```bash
pip install vnape
```

### From Source

```bash
git clone https://github.com/hmshujaatzaheer/vnape.git
cd vnape
pip install -e ".[dev]"
```

### Requirements

- Python 3.10+
- PyTorch 2.0+
- Z3 Solver 4.12+
- See `pyproject.toml` for full dependency list

## Quick Start

### Basic Usage

```python
from vnape import VNAPE
from vnape.protocols import IMessagePQ3Protocol

# Initialize the framework
vnape = VNAPE()

# Load iMessage PQ3 protocol
protocol = IMessagePQ3Protocol()
vnape.load_protocol(protocol)

# Define base policy (MFOTL formula)
base_policy = """
    □[0,∞) (SessionActive(s) → ◇[0,δ] KeyRatchet(s, k'))
"""
vnape.set_base_policy(base_policy)

# Process execution trace
trace = protocol.simulate_execution(num_events=1000)
result = vnape.enforce(trace)

print(f"Enforcement result: {result.status}")
print(f"Violations detected: {len(result.violations)}")
print(f"Actions taken: {len(result.actions)}")
```

### Using Individual Components

#### NPA: Neural Policy Adaptation

```python
from vnape.npa import NeuralPolicyAdapter, TraceEncoder

# Initialize encoder and adapter
encoder = TraceEncoder(
    embed_dim=256,
    num_heads=8,
    num_layers=6
)
adapter = NeuralPolicyAdapter(encoder)

# Train on execution traces
adapter.fit(training_traces, epochs=100)

# Generate policy refinements
refinements = adapter.propose_refinements(new_trace)
for ref in refinements:
    print(f"Refinement: {ref.formula}")
    print(f"Confidence: {ref.confidence:.3f}")
```

#### SVB: Symbolic Verification Bridge

```python
from vnape.svb import SymbolicVerificationBridge, SafetyInvariants

# Initialize verification bridge
svb = SymbolicVerificationBridge()

# Define safety invariants
invariants = SafetyInvariants([
    "∀s. SessionActive(s) → HasValidKey(s)",
    "∀s,k. KeyUsed(s,k) → KeyValid(k)"
])

# Verify a refinement
result = svb.verify(
    base_policy=base_policy,
    refinement=proposed_refinement,
    invariants=invariants
)

if result.accepted:
    print(f"Certificate: {result.certificate}")
else:
    print(f"Counterexample: {result.counterexample}")
```

#### PQAE: Proactive Quantum-Aware Enforcement

```python
from vnape.pqae import ProactiveEnforcer, EnforcementMode, QuantumContext

# Configure quantum threat context
quantum_ctx = QuantumContext(
    active_algorithms=["ML-KEM-768", "ML-DSA-65"],
    hybrid_mode=True,
    threat_level="elevated"
)

# Initialize enforcer
enforcer = ProactiveEnforcer(
    mode=EnforcementMode.STRICT,
    quantum_context=quantum_ctx
)

# Enforce policy on event stream
for event in event_stream:
    action = enforcer.process(event)
    if action.type == "block":
        print(f"Blocked event: {event}")
    elif action.type == "modify":
        print(f"Modified event: {event} -> {action.modified_event}")
```

## Protocol Support

### iMessage PQ3

Full support for Apple's iMessage PQ3 protocol with:
- X25519 + ML-KEM hybrid key exchange
- Ratcheting key derivation
- Forward secrecy verification

```python
from vnape.protocols import IMessagePQ3Protocol

protocol = IMessagePQ3Protocol(
    ratchet_interval=100,  # messages between ratchets
    hybrid_mode=True
)
```

### AKMA+ (5G Authentication)

Support for AKMA+ protocol with:
- Mutual authentication enforcement
- Identifier privacy
- Key derivation compliance

```python
from vnape.protocols import AKMAPlusProtocol

protocol = AKMAPlusProtocol(
    pq_algorithm="ML-KEM-768",
    network_type="5G-SA"
)
```

### Custom Protocols

```python
from vnape.protocols import BaseProtocol, ProtocolEvent

class MyProtocol(BaseProtocol):
    def __init__(self):
        super().__init__(name="MyProtocol")
        
    def define_events(self):
        return [
            ProtocolEvent("KeyExchange", ["session_id", "key_id"]),
            ProtocolEvent("MessageSend", ["session_id", "msg_id"]),
            ProtocolEvent("SessionClose", ["session_id"])
        ]
    
    def define_policies(self):
        return {
            "key_freshness": "□[0,T] (KeyExchange(s,k) → ◇[0,δ] KeyRotate(s,k'))",
            "session_cleanup": "◇[0,τ] (SessionClose(s) → ¬∃m. MessageSend(s,m))"
        }
```

## Configuration

### Environment Variables

```bash
export VNAPE_LOG_LEVEL=INFO
export VNAPE_DEVICE=cuda  # or cpu
export VNAPE_Z3_TIMEOUT=30000  # milliseconds
export VNAPE_ENFORCEMENT_MODE=strict  # strict, permissive, audit
```

### Configuration File

```yaml
# vnape.yaml
npa:
  model:
    embed_dim: 256
    num_heads: 8
    num_layers: 6
    dropout: 0.1
  training:
    batch_size: 32
    learning_rate: 0.0001
    epochs: 100

svb:
  z3_timeout: 30000
  abstraction_level: 2
  generate_certificates: true

pqae:
  mode: strict
  buffer_size: 10000
  adaptation_threshold: 0.8
  quantum_context:
    active_algorithms:
      - ML-KEM-768
      - ML-DSA-65
    hybrid_mode: true
```

## Command Line Interface

```bash
# Analyze a protocol trace
vnape analyze trace.json --policy policy.mfotl

# Train NPA model
vnape train --traces traces/ --output model.pt

# Verify a policy refinement
vnape verify --base policy.mfotl --refinement delta.mfotl --invariants safety.mfotl

# Run enforcement simulation
vnape enforce --protocol imessage-pq3 --mode strict --events 10000
```

## Evaluation Metrics

| Category | Metric | Target |
|----------|--------|--------|
| Correctness | Soundness preservation | 100% |
| Correctness | False positive rate | <1% |
| Performance | Enforcement latency | <10ms per event |
| Performance | Adaptation latency | <100ms per refinement |
| Performance | Memory overhead | <2× baseline |
| Effectiveness | Violation detection rate | >95% |
| Effectiveness | Adaptation relevance | >80% useful refinements |
| Effectiveness | Policy convergence | <1000 events |

## Research Context

This framework is developed as part of PhD research building upon:

- **Proactive Enforcement**: Basin, Hublet et al. (CAV 2024, 2025)
- **Post-Quantum Protocol Analysis**: Linker, Sasse, Basin (USENIX Security 2025)
- **Neural Network Verification**: Katz et al. (Reluplex), Wang et al. (Beta-CROWN)

## Citation

If you use V-NAPE in your research, please cite:

```bibtex
@misc{zaheer2026vnape,
  author = {Zaheer, H M Shujaat},
  title = {V-NAPE: Verified Neural Adaptive Proactive Enforcement},
  year = {2026},
  publisher = {GitHub},
  howpublished = {\url{https://github.com/hmshujaatzaheer/vnape}}
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Acknowledgments

- Prof. David Basin and the Information Security Group at ETH Zürich
- The TAMARIN and MonPoly teams for foundational work on protocol verification
- The post-quantum cryptography research community

## Contact

H M Shujaat Zaheer - [GitHub](https://github.com/hmshujaatzaheer)

Project Link: [https://github.com/hmshujaatzaheer/vnape](https://github.com/hmshujaatzaheer/vnape)
