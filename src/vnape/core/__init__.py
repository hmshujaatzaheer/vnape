"""
V-NAPE Core Module

Core components and types for the V-NAPE framework.
"""

from vnape.core.framework import VNAPE, VNAPEConfig
from vnape.core.types import (
    ActionType,
    Counterexample,
    EncoderOutput,
    EnforcementAction,
    EnforcementMode,
    EnforcementResult,
    EventType,
    ExecutionTrace,
    MFOTLFormula,
    ModelConfig,
    PolicyRefinement,
    PolicyViolation,
    ProtocolEvent,
    QuantumContext,
    RefinementProposal,
    RefinementType,
    Result,
    SafetyInvariants,
    ThreatLevel,
    TrainingConfig,
    VerificationCertificate,
    VerificationResult,
    VerificationStatus,
)

__all__ = [
    # Framework
    "VNAPE",
    "VNAPEConfig",
    # Types
    "ActionType",
    "Counterexample",
    "EncoderOutput",
    "EnforcementAction",
    "EnforcementMode",
    "EnforcementResult",
    "EventType",
    "ExecutionTrace",
    "MFOTLFormula",
    "ModelConfig",
    "PolicyRefinement",
    "PolicyViolation",
    "ProtocolEvent",
    "QuantumContext",
    "RefinementProposal",
    "RefinementType",
    "Result",
    "SafetyInvariants",
    "ThreatLevel",
    "TrainingConfig",
    "VerificationCertificate",
    "VerificationResult",
    "VerificationStatus",
]
