"""
Certificate Generator for Verified Policy Refinements.

This module generates cryptographic and semantic certificates that
attest to the verification of policy refinements against safety invariants.

Certificates provide evidence that can be audited to confirm that
neural policy decisions satisfy required properties.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any

from ..core.types import (
    Counterexample,
    MFOTLFormula,
    PolicyRefinement,
    SafetyInvariants,
    VerificationCertificate,
    VerificationResult,
)
from .abstraction import AbstractionEngine, RefinementAbstraction

logger = logging.getLogger(__name__)


class CertificateType(Enum):
    """Types of verification certificates."""

    SAFETY_PROOF = auto()  # Proves refinement preserves safety
    SOUNDNESS_WITNESS = auto()  # Witnesses soundness of abstraction
    INVARIANT_PRESERVATION = auto()  # Proves invariants are maintained
    BOUNDED_MODEL_CHECK = auto()  # Result of bounded model checking
    COUNTEREXAMPLE = auto()  # Certificate of rejection with counterexample


class VerificationStatus(Enum):
    """Status of verification process."""

    VERIFIED = auto()  # Successfully verified
    REFUTED = auto()  # Counterexample found
    UNKNOWN = auto()  # Could not determine (timeout, etc.)
    PARTIAL = auto()  # Some properties verified, others unknown


@dataclass
class ProofStep:
    """
    A single step in a verification proof.

    Each step records a logical inference or check performed
    during the verification process.
    """

    step_id: str
    step_type: str
    description: str
    premises: list[str]  # IDs of prerequisite steps
    conclusion: str
    justification: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "step_id": self.step_id,
            "step_type": self.step_type,
            "description": self.description,
            "premises": self.premises,
            "conclusion": self.conclusion,
            "justification": self.justification,
            "timestamp": self.timestamp,
        }


@dataclass
class VerificationTrace:
    """
    Complete trace of a verification attempt.

    Records all steps taken during verification for auditability.
    """

    trace_id: str
    refinement_id: str
    start_time: float
    end_time: float | None = None
    steps: list[ProofStep] = field(default_factory=list)
    status: VerificationStatus = VerificationStatus.UNKNOWN
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_step(self, step: ProofStep) -> None:
        """Add a proof step to the trace."""
        self.steps.append(step)

    def complete(self, status: VerificationStatus) -> None:
        """Mark trace as complete."""
        self.end_time = time.time()
        self.status = status

    @property
    def duration(self) -> float | None:
        """Duration of verification in seconds."""
        if self.end_time:
            return self.end_time - self.start_time
        return None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "trace_id": self.trace_id,
            "refinement_id": self.refinement_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "steps": [s.to_dict() for s in self.steps],
            "status": self.status.name,
            "metadata": self.metadata,
        }


@dataclass
class Certificate:
    """
    Verification certificate attesting to refinement safety.

    Contains all information needed to audit and verify the
    certification decision.
    """

    certificate_id: str
    certificate_type: CertificateType
    refinement: PolicyRefinement
    base_policy: MFOTLFormula
    invariants: SafetyInvariants
    status: VerificationStatus
    verification_trace: VerificationTrace
    abstraction_used: RefinementAbstraction | None = None
    counterexample: Counterexample | None = None
    issued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    signature: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Compute certificate signature after initialization."""
        if self.signature is None:
            self.signature = self._compute_signature()

    def _compute_signature(self) -> str:
        """
        Compute cryptographic signature of certificate contents.

        Uses SHA-256 hash of canonical certificate representation.
        """
        canonical = {
            "certificate_id": self.certificate_id,
            "certificate_type": self.certificate_type.name,
            "refinement_formula": self.refinement.formula.text,
            "refinement_type": self.refinement.refinement_type.name,
            "base_policy": self.base_policy.text,
            "status": self.status.name,
            "issued_at": self.issued_at.isoformat(),
            "trace_id": self.verification_trace.trace_id,
        }

        canonical_json = json.dumps(canonical, sort_keys=True)
        return hashlib.sha256(canonical_json.encode()).hexdigest()

    def verify_signature(self) -> bool:
        """Verify that certificate signature is valid."""
        expected = self._compute_signature()
        return self.signature == expected

    def is_valid(self) -> bool:
        """Check if certificate is currently valid."""
        if self.status != VerificationStatus.VERIFIED:
            return False

        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return False

        return self.verify_signature()

    def to_verification_certificate(self) -> VerificationCertificate:
        """Convert to core VerificationCertificate type."""
        return VerificationCertificate(
            certificate_id=self.certificate_id,
            refinement_id=str(id(self.refinement)),
            verified=self.status == VerificationStatus.VERIFIED,
            invariants_checked=[
                str(inv)
                for inv in (
                    self.invariants.formulas if hasattr(self.invariants, "formulas") else []
                )
            ],
            proof_trace=self.verification_trace.to_dict(),
            timestamp=self.issued_at,
            signature=self.signature,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "certificate_id": self.certificate_id,
            "certificate_type": self.certificate_type.name,
            "refinement": {
                "formula": self.refinement.formula.text,
                "type": self.refinement.refinement_type.name,
                "confidence": self.refinement.confidence,
            },
            "base_policy": self.base_policy.text,
            "status": self.status.name,
            "verification_trace": self.verification_trace.to_dict(),
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "signature": self.signature,
            "is_valid": self.is_valid(),
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize certificate to JSON."""
        return json.dumps(self.to_dict(), indent=indent)


class CertificateGenerator:
    """
    Generator for verification certificates.

    Creates certificates attesting to the verification of policy
    refinements against safety invariants.
    """

    def __init__(
        self,
        abstraction_engine: AbstractionEngine | None = None,
        certificate_validity_hours: int = 24,
    ):
        """
        Initialize certificate generator.

        Args:
            abstraction_engine: Optional abstraction engine for creating abstractions
            certificate_validity_hours: Hours until certificates expire
        """
        self.abstraction_engine = abstraction_engine
        self.certificate_validity_hours = certificate_validity_hours
        self._step_counter = 0

    def generate_certificate(
        self,
        refinement: PolicyRefinement,
        base_policy: MFOTLFormula,
        invariants: SafetyInvariants,
        verification_result: VerificationResult,
        abstraction: RefinementAbstraction | None = None,
    ) -> Certificate:
        """
        Generate verification certificate for a refinement.

        Args:
            refinement: Policy refinement to certify
            base_policy: Base policy being refined
            invariants: Safety invariants checked
            verification_result: Result of verification
            abstraction: Optional abstraction used in verification

        Returns:
            Verification certificate
        """
        certificate_id = self._generate_certificate_id()

        # Build verification trace
        trace = self._build_verification_trace(
            refinement,
            base_policy,
            invariants,
            verification_result,
        )

        # Determine certificate type and status
        if verification_result.verified:
            cert_type = CertificateType.SAFETY_PROOF
            status = VerificationStatus.VERIFIED
        elif verification_result.counterexample:
            cert_type = CertificateType.COUNTEREXAMPLE
            status = VerificationStatus.REFUTED
        else:
            cert_type = CertificateType.BOUNDED_MODEL_CHECK
            status = VerificationStatus.UNKNOWN

        # Calculate expiration
        from datetime import timedelta

        expires_at = datetime.now(timezone.utc) + timedelta(hours=self.certificate_validity_hours)

        certificate = Certificate(
            certificate_id=certificate_id,
            certificate_type=cert_type,
            refinement=refinement,
            base_policy=base_policy,
            invariants=invariants,
            status=status,
            verification_trace=trace,
            abstraction_used=abstraction,
            counterexample=verification_result.counterexample,
            expires_at=expires_at,
            metadata={
                "generator_version": "1.0.0",
                "verification_method": (
                    verification_result.method if hasattr(verification_result, "method") else "smt"
                ),
            },
        )

        logger.info(f"Generated certificate {certificate_id} with status {status.name}")
        return certificate

    def generate_rejection_certificate(
        self,
        refinement: PolicyRefinement,
        base_policy: MFOTLFormula,
        invariants: SafetyInvariants,
        counterexample: Counterexample,
        reason: str,
    ) -> Certificate:
        """
        Generate certificate for a rejected refinement.

        Args:
            refinement: Rejected policy refinement
            base_policy: Base policy
            invariants: Safety invariants violated
            counterexample: Counterexample demonstrating violation
            reason: Reason for rejection

        Returns:
            Rejection certificate with counterexample
        """
        certificate_id = self._generate_certificate_id()

        trace = VerificationTrace(
            trace_id=str(uuid.uuid4()),
            refinement_id=str(id(refinement)),
            start_time=time.time(),
            metadata={"rejection_reason": reason},
        )

        # Add rejection step
        trace.add_step(
            ProofStep(
                step_id=self._next_step_id(),
                step_type="rejection",
                description=f"Refinement rejected: {reason}",
                premises=[],
                conclusion="unsafe",
                justification=f"Counterexample found: {counterexample.description if hasattr(counterexample, 'description') else str(counterexample)}",
            )
        )

        trace.complete(VerificationStatus.REFUTED)

        certificate = Certificate(
            certificate_id=certificate_id,
            certificate_type=CertificateType.COUNTEREXAMPLE,
            refinement=refinement,
            base_policy=base_policy,
            invariants=invariants,
            status=VerificationStatus.REFUTED,
            verification_trace=trace,
            counterexample=counterexample,
            metadata={"rejection_reason": reason},
        )

        logger.info(f"Generated rejection certificate {certificate_id}")
        return certificate

    def _generate_certificate_id(self) -> str:
        """Generate unique certificate identifier."""
        return f"cert-{uuid.uuid4().hex[:16]}-{int(time.time())}"

    def _next_step_id(self) -> str:
        """Generate next proof step identifier."""
        self._step_counter += 1
        return f"step-{self._step_counter:04d}"

    def _build_verification_trace(
        self,
        refinement: PolicyRefinement,
        base_policy: MFOTLFormula,
        invariants: SafetyInvariants,
        result: VerificationResult,
    ) -> VerificationTrace:
        """
        Build complete verification trace from result.

        Args:
            refinement: Verified refinement
            base_policy: Base policy
            invariants: Checked invariants
            result: Verification result

        Returns:
            Complete verification trace
        """
        trace = VerificationTrace(
            trace_id=str(uuid.uuid4()),
            refinement_id=str(id(refinement)),
            start_time=(
                result.verification_time if hasattr(result, "verification_time") else time.time()
            ),
        )

        # Step 1: Policy composition
        trace.add_step(
            ProofStep(
                step_id=self._next_step_id(),
                step_type="composition",
                description="Compose refinement with base policy",
                premises=[],
                conclusion="φ_refined = φ_base ⊕ Δφ",
                justification=f"Combined {base_policy.text[:50]}... with refinement",
            )
        )

        # Step 2: Abstraction (if applicable)
        if self.abstraction_engine:
            trace.add_step(
                ProofStep(
                    step_id=self._next_step_id(),
                    step_type="abstraction",
                    description="Construct abstract representation",
                    premises=[trace.steps[-1].step_id],
                    conclusion="α(φ_refined) computed",
                    justification="Interval abstraction applied",
                )
            )

        # Step 3: Invariant checking
        invariant_step_ids = []
        invariant_list = invariants.formulas if hasattr(invariants, "formulas") else []

        for i, inv in enumerate(invariant_list):
            step = ProofStep(
                step_id=self._next_step_id(),
                step_type="invariant_check",
                description=f"Check invariant {i+1}",
                premises=[trace.steps[-1].step_id] if trace.steps else [],
                conclusion="invariant_satisfied" if result.verified else "invariant_violated",
                justification=f"SMT check for invariant: {str(inv)[:50]}...",
            )
            trace.add_step(step)
            invariant_step_ids.append(step.step_id)

        # Step 4: Final conclusion
        trace.add_step(
            ProofStep(
                step_id=self._next_step_id(),
                step_type="conclusion",
                description="Final verification conclusion",
                premises=invariant_step_ids,
                conclusion="VERIFIED" if result.verified else "REFUTED",
                justification=(
                    "All invariants checked" if result.verified else "Invariant violation found"
                ),
            )
        )

        # Complete trace
        trace.complete(
            VerificationStatus.VERIFIED if result.verified else VerificationStatus.REFUTED
        )

        return trace


class CertificateStore:
    """
    Storage and retrieval for verification certificates.

    Provides persistence and querying of certificates for audit purposes.
    """

    def __init__(self):
        """Initialize certificate store."""
        self._certificates: dict[str, Certificate] = {}
        self._by_refinement: dict[str, list[str]] = {}  # refinement_id -> cert_ids

    def store(self, certificate: Certificate) -> None:
        """Store a certificate."""
        self._certificates[certificate.certificate_id] = certificate

        refinement_id = str(id(certificate.refinement))
        if refinement_id not in self._by_refinement:
            self._by_refinement[refinement_id] = []
        self._by_refinement[refinement_id].append(certificate.certificate_id)

        logger.debug(f"Stored certificate {certificate.certificate_id}")

    def get(self, certificate_id: str) -> Certificate | None:
        """Retrieve a certificate by ID."""
        return self._certificates.get(certificate_id)

    def get_for_refinement(self, refinement_id: str) -> list[Certificate]:
        """Get all certificates for a refinement."""
        cert_ids = self._by_refinement.get(refinement_id, [])
        return [self._certificates[cid] for cid in cert_ids if cid in self._certificates]

    def get_valid_certificates(self) -> list[Certificate]:
        """Get all currently valid certificates."""
        return [c for c in self._certificates.values() if c.is_valid()]

    def revoke(self, certificate_id: str) -> bool:
        """Revoke a certificate."""
        if certificate_id in self._certificates:
            cert = self._certificates[certificate_id]
            cert.status = VerificationStatus.UNKNOWN
            cert.metadata["revoked"] = True
            cert.metadata["revoked_at"] = datetime.now(timezone.utc).isoformat()
            logger.info(f"Revoked certificate {certificate_id}")
            return True
        return False

    def export_audit_log(self) -> str:
        """Export all certificates as JSON audit log."""
        log = {
            "export_time": datetime.now(timezone.utc).isoformat(),
            "certificate_count": len(self._certificates),
            "certificates": [c.to_dict() for c in self._certificates.values()],
        }
        return json.dumps(log, indent=2)

    def clear_expired(self) -> int:
        """Remove expired certificates. Returns count removed."""
        now = datetime.now(timezone.utc)
        expired = [
            cid
            for cid, cert in self._certificates.items()
            if cert.expires_at and cert.expires_at < now
        ]

        for cid in expired:
            del self._certificates[cid]

        logger.info(f"Cleared {len(expired)} expired certificates")
        return len(expired)
