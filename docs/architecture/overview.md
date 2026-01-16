# Architecture Overview

V-NAPE's architecture combines neural learning, symbolic verification, and quantum-aware enforcement into a unified pipeline.

## System Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              V-NAPE System                                   │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                         Input Layer                                    │  │
│  │  Protocol Traces ─────────────────────────────────▶ Configuration      │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                    │                                         │
│                                    ▼                                         │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                 Neural Policy Adaptation (NPA)                         │  │
│  │                                                                        │  │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐            │  │
│  │  │    Trace     │───▶│   Pattern    │───▶│  Refinement  │            │  │
│  │  │   Encoder    │    │  Detection   │    │  Generation  │            │  │
│  │  └──────────────┘    └──────────────┘    └──────────────┘            │  │
│  │                                                                        │  │
│  │  Outputs: Encoded traces, Detected patterns, Anomaly scores,          │  │
│  │           Policy refinements                                          │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                    │                                         │
│                                    ▼                                         │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │              Symbolic Verification Bridge (SVB)                        │  │
│  │                                                                        │  │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐            │  │
│  │  │   MFOTL→Z3   │───▶│  Abstraction │───▶│ Certificate  │            │  │
│  │  │  Translator  │    │    Engine    │    │  Generator   │            │  │
│  │  └──────────────┘    └──────────────┘    └──────────────┘            │  │
│  │                                                                        │  │
│  │  Outputs: Z3 formulas, Verification results, Proof certificates       │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                    │                                         │
│                                    ▼                                         │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │           Proactive Quantum-Aware Enforcement (PQAE)                   │  │
│  │                                                                        │  │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐            │  │
│  │  │    MFOTL     │───▶│   Quantum    │───▶│ Enforcement  │            │  │
│  │  │   Monitor    │    │   Context    │    │    Oracle    │            │  │
│  │  └──────────────┘    └──────────────┘    └──────────────┘            │  │
│  │                                                                        │  │
│  │  Outputs: Violations, Quantum risk assessment, Enforcement decisions  │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                    │                                         │
│                                    ▼                                         │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                         Output Layer                                   │  │
│  │  ◀─────── Enforcement Decision ──────────────────────────────────────  │  │
│  │  ◀─────── Proof Certificates ────────────────────────────────────────  │  │
│  │  ◀─────── Quantum Risk Report ───────────────────────────────────────  │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Data Flow

### Forward Pass (Verification)

1. **Input**: Protocol trace + configuration
2. **NPA**: Encode → Detect patterns → Score anomalies
3. **SVB**: Translate to Z3 → Verify → Generate certificate
4. **PQAE**: Monitor → Assess quantum risk → Decide enforcement

### Feedback Loop (Refinement)

1. **Patterns**: NPA detected patterns → SVB formal verification
2. **Violations**: PQAE violations → NPA refinement learning
3. **Certificates**: SVB certificates → PQAE enforcement oracle

## Component Details

- [NPA Architecture](npa.md) - Neural components and training
- [SVB Architecture](svb.md) - Verification and abstraction
- [PQAE Architecture](pqae.md) - Monitoring and enforcement

## Design Principles

### Modularity
Each component operates independently and can be replaced or extended.

### Formal Guarantees
Neural outputs are verified symbolically before affecting enforcement.

### Quantum Awareness
All decisions consider current and projected quantum capabilities.

### Adaptivity
The system learns from traces and refines policies over time.

```{toctree}
:maxdepth: 1
:hidden:

npa
svb
pqae
```
