"""
V-NAPE PQAE Module - Proactive Quantum-Aware Enforcement.

This module implements the runtime enforcement component of V-NAPE that:
1. Monitors protocol execution against MFOTL policies
2. Enforces verified policy refinements in real-time
3. Adapts enforcement strategies based on quantum threat context
4. Provides proactive defense against emerging PQC threats

Key Components:
- MFOTLMonitor: Runtime monitoring of metric first-order temporal logic policies
- ProactiveEnforcer: Enforcement engine with configurable modes (STRICT/PERMISSIVE/AUDIT)
- QuantumThreatContext: Contextual information about quantum computational threats
- EnforcementOracle: Decision engine for enforcement actions

Architecture (from thesis Section 4.3):
    ┌─────────────────────────────────────────────────────────────┐
    │                    PQAE Module                               │
    │  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
    │  │   MFOTL     │  │   Proactive  │  │  Quantum Threat     │ │
    │  │   Monitor   │──│   Enforcer   │──│  Context Manager    │ │
    │  └─────────────┘  └──────────────┘  └─────────────────────┘ │
    │         │                │                    │              │
    │         ▼                ▼                    ▼              │
    │  ┌─────────────────────────────────────────────────────────┐│
    │  │              Enforcement Oracle                          ││
    │  └─────────────────────────────────────────────────────────┘│
    └─────────────────────────────────────────────────────────────┘
"""

from vnape.pqae.enforcer import (
    EnforcementDecision,
    EnforcementOracle,
    ProactiveEnforcer,
)
from vnape.pqae.monitor import (
    MFOTLMonitor,
    MonitoringResult,
    MonitorState,
    Verdict,
)
from vnape.pqae.quantum_context import (
    QuantumCapability,
    QuantumRiskLevel,
    QuantumThreatContext,
    ThreatAssessment,
)

__all__ = [
    # Monitor
    "MFOTLMonitor",
    "MonitorState",
    "MonitoringResult",
    "Verdict",
    # Enforcer
    "ProactiveEnforcer",
    "EnforcementOracle",
    "EnforcementDecision",
    # Quantum Context
    "QuantumThreatContext",
    "ThreatAssessment",
    "QuantumCapability",
    "QuantumRiskLevel",
]
