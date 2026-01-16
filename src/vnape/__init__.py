"""
V-NAPE: Verified Neural Adaptive Proactive Enforcement

A Framework for Adaptive Runtime Security in Post-Quantum Cryptographic Protocols.

This package provides three integrated components:
- NPA (Neural Policy Adaptation): Learns policy refinements from protocol traces
- SVB (Symbolic Verification Bridge): Verifies neural refinements against safety invariants
- PQAE (Proactive Quantum-Aware Enforcement): Enforces policies on PQ protocols

Example:
    >>> from vnape import VNAPE
    >>> from vnape.protocols import IMessagePQ3Protocol
    >>>
    >>> vnape = VNAPE()
    >>> protocol = IMessagePQ3Protocol()
    >>> vnape.load_protocol(protocol)
    >>> result = vnape.enforce(trace)
"""

import importlib.util
from typing import TYPE_CHECKING

__version__ = "0.1.0"
__author__ = "H M Shujaat Zaheer"
__email__ = "shujaat.zaheer@example.com"

# Check for optional dependencies
TORCH_AVAILABLE = importlib.util.find_spec("torch") is not None
Z3_AVAILABLE = importlib.util.find_spec("z3") is not None

# Always available: core types
from vnape.core.types import (
    ActionType,
    Counterexample,
    EncoderOutput,
    EnforcementAction,
    # Enums
    EnforcementMode,
    EnforcementResult,
    EventType,
    ExecutionTrace,
    MFOTLFormula,
    ModelConfig,
    PolicyRefinement,
    PolicyViolation,
    # Data models
    ProtocolEvent,
    RefinementProposal,
    RefinementType,
    # Generic
    Result,
    SafetyInvariants,
    ThreatLevel,
    # Dataclasses
    TrainingConfig,
    VerificationCertificate,
    VerificationResult,
    VerificationStatus,
)

__all__ = [
    # Enums (always available)
    "EnforcementMode",
    "EventType",
    "ActionType",
    "VerificationStatus",
    "ThreatLevel",
    "RefinementType",
    # Data models
    "ProtocolEvent",
    "ExecutionTrace",
    "MFOTLFormula",
    "PolicyRefinement",
    "VerificationCertificate",
    "Counterexample",
    "VerificationResult",
    "QuantumThreatContext",
    "EnforcementAction",
    "PolicyViolation",
    "EnforcementResult",
    "SafetyInvariants",
    # Dataclasses
    "TrainingConfig",
    "ModelConfig",
    "EncoderOutput",
    "RefinementProposal",
    # Generic
    "Result",
    # Dependency availability flags
    "TORCH_AVAILABLE",
    "Z3_AVAILABLE",
]

# Conditionally import torch-dependent modules
if TORCH_AVAILABLE:
    from vnape.core.framework import VNAPE
    from vnape.npa import NeuralPolicyAdapter, TraceEncoder
    from vnape.pqae import ProactiveEnforcer, QuantumThreatContext

    __all__.extend(
        [
            "VNAPE",
            "NeuralPolicyAdapter",
            "TraceEncoder",
            "ProactiveEnforcer",
            "QuantumThreatContext",
        ]
    )

# Conditionally import z3-dependent modules
if Z3_AVAILABLE:
    from vnape.svb import SafetyInvariants, SymbolicVerificationBridge

    __all__.extend(
        [
            "SymbolicVerificationBridge",
            "SafetyInvariants",
        ]
    )
