"""
SVB: Symbolic Verification Bridge Module

This module implements the symbolic verification bridge that ensures
neural policy refinements satisfy formal safety invariants before
being applied to enforcement.

Components:
- SymbolicVerificationBridge: Main verification interface
- MFOTLToZ3Translator: Translates MFOTL formulas to Z3 constraints
- AbstractionEngine: Creates sound abstractions of neural refinements
- CertificateGenerator: Produces verification certificates

The verification process:
1. Compose refinement with base policy: φ_r = φ_base ⊕ Δφ
2. Abstract to SMT-compatible form: α_r = α(φ_r)
3. Check invariants: ∀I ∈ Invariants. SMT(α_r → I) = SAT
4. Generate certificate if verified

Example:
    >>> from vnape.svb import SymbolicVerificationBridge, SafetyInvariants
    >>> svb = SymbolicVerificationBridge()
    >>> invariants = SafetyInvariants(["∀s. Active(s) → HasKey(s)"])
    >>> result = svb.verify(base_policy, refinement, invariants)
    >>> if result.accepted:
    ...     print(f"Certificate: {result.certificate.certificate_id}")
"""

# Translator is always available (no torch dependency)
# Re-export SafetyInvariants from core
from vnape.core.types import SafetyInvariants

# Certificate module doesn't need torch
from .certificate import (
    Certificate,
    CertificateGenerator,
    CertificateStore,
    CertificateType,
    ProofStep,
    VerificationStatus,
    VerificationTrace,
)
from .translator import (
    ASTNode,
    MFOTLParser,
    MFOTLToZ3Translator,
    OperatorType,
    TimeInterval,
)

# Try to import torch-dependent modules
try:
    from .abstraction import (
        AbstractDomain,
        AbstractionEngine,
        AbstractionStrategy,
        AbstractValue,
        IntervalAbstractor,
        NeuralAbstractor,
        RefinementAbstraction,
        create_abstraction_engine,
    )
    from .bridge import (
        ComposedPolicy,
        CompositionOperator,
        SymbolicVerificationBridge,
        VerificationConfig,
        VerificationJob,
        VerificationMode,
        create_svb,
    )

    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    # Provide stub references for type checking
    AbstractionEngine = None
    AbstractionStrategy = None
    AbstractValue = None
    AbstractDomain = None
    RefinementAbstraction = None
    NeuralAbstractor = None
    IntervalAbstractor = None
    create_abstraction_engine = None
    SymbolicVerificationBridge = None
    VerificationConfig = None
    VerificationMode = None
    CompositionOperator = None
    ComposedPolicy = None
    VerificationJob = None
    create_svb = None

__all__ = [
    # Translator (always available)
    "MFOTLToZ3Translator",
    "MFOTLParser",
    "ASTNode",
    "OperatorType",
    "TimeInterval",
    # Certificate (always available)
    "Certificate",
    "CertificateGenerator",
    "CertificateStore",
    "CertificateType",
    "VerificationStatus",
    "VerificationTrace",
    "ProofStep",
    # Core types
    "SafetyInvariants",
    # Torch-dependent (may be None)
    "AbstractionEngine",
    "AbstractionStrategy",
    "AbstractValue",
    "AbstractDomain",
    "RefinementAbstraction",
    "NeuralAbstractor",
    "IntervalAbstractor",
    "create_abstraction_engine",
    "SymbolicVerificationBridge",
    "VerificationConfig",
    "VerificationMode",
    "CompositionOperator",
    "ComposedPolicy",
    "VerificationJob",
    "create_svb",
    "TORCH_AVAILABLE",
]
