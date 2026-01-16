"""
Core type definitions for the V-NAPE framework.

This module defines the fundamental data structures used across all components:
- Protocol events and traces
- Policy specifications and refinements
- Verification and enforcement results
- Quantum security contexts
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


# =============================================================================
# Enumerations
# =============================================================================


class EnforcementMode(str, Enum):
    """Enforcement operation mode for PQAE."""

    STRICT = "strict"
    """Immediately block policy-violating events."""

    PERMISSIVE = "permissive"
    """Allow events but log violations for later analysis."""

    AUDIT = "audit"
    """Passive monitoring only; no enforcement actions taken."""


class EventType(str, Enum):
    """Types of protocol events."""

    KEY_EXCHANGE = "key_exchange"
    KEY_RATCHET = "key_ratchet"
    MESSAGE_SEND = "message_send"
    MESSAGE_RECEIVE = "message_receive"
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    AUTHENTICATION = "authentication"
    KEY_DERIVATION = "key_derivation"
    ALGORITHM_SWITCH = "algorithm_switch"
    CUSTOM = "custom"


class ActionType(str, Enum):
    """Types of enforcement actions."""

    PERMIT = "permit"
    BLOCK = "block"
    MODIFY = "modify"
    DELAY = "delay"
    ALERT = "alert"


class VerificationStatus(str, Enum):
    """Status of SMT verification."""

    ACCEPTED = "accepted"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


class ThreatLevel(str, Enum):
    """Quantum threat assessment level."""

    LOW = "low"
    MODERATE = "moderate"
    ELEVATED = "elevated"
    HIGH = "high"
    CRITICAL = "critical"


class RefinementType(str, Enum):
    """Type of policy refinement."""

    CONJUNCTIVE_EXTENSION = "conjunctive_extension"
    """Add conjunctive clause to existing policy."""

    PARAMETER_TIGHTENING = "parameter_tightening"
    """Tighten time bounds or thresholds."""

    SCOPE_RESTRICTION = "scope_restriction"
    """Restrict the scope of quantification."""

    EXCEPTION_ADDITION = "exception_addition"
    """Add exception clause for specific patterns."""


# =============================================================================
# Base Event and Trace Types
# =============================================================================


class ProtocolEvent(BaseModel):
    """
    A single protocol execution event.

    Corresponds to a timestamped tuple (t, r, v̄) where:
    - t: timestamp
    - r: relation name
    - v̄: tuple of values

    Attributes:
        timestamp: Event occurrence time in milliseconds
        event_type: Category of the event
        relation: MFOTL relation name
        values: Dictionary of event parameters
        session_id: Associated session identifier
        metadata: Additional event metadata
    """

    timestamp: int = Field(..., description="Event timestamp in milliseconds")
    event_type: EventType = Field(..., description="Type of protocol event")
    relation: str = Field(..., description="MFOTL relation name")
    values: dict[str, Any] = Field(default_factory=dict, description="Event parameters")
    session_id: str | None = Field(None, description="Associated session ID")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    class Config:
        frozen = True

    def to_mfotl_tuple(self) -> str:
        """Convert to MFOTL tuple representation."""
        args = ", ".join(str(v) for v in self.values.values())
        return f"@{self.timestamp} {self.relation}({args})"


class ExecutionTrace(BaseModel):
    """
    A sequence of protocol execution events.

    Represents a complete or partial protocol execution that can be
    used for monitoring, enforcement, or training.

    Attributes:
        trace_id: Unique identifier for this trace
        events: Ordered sequence of protocol events
        protocol_name: Name of the protocol that generated this trace
        start_time: Trace collection start time
        end_time: Trace collection end time (None if ongoing)
        metadata: Additional trace metadata
    """

    trace_id: str = Field(..., description="Unique trace identifier")
    events: list[ProtocolEvent] = Field(default_factory=list, description="Ordered events")
    protocol_name: str = Field(..., description="Source protocol name")
    start_time: datetime = Field(default_factory=datetime.now, description="Collection start")
    end_time: datetime | None = Field(None, description="Collection end")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Trace metadata")

    def __len__(self) -> int:
        return len(self.events)

    def __iter__(self):
        return iter(self.events)

    def __getitem__(self, idx: int) -> ProtocolEvent:
        return self.events[idx]

    def append(self, event: ProtocolEvent) -> None:
        """Add an event to the trace."""
        self.events.append(event)

    def window(self, start_ts: int, end_ts: int) -> list[ProtocolEvent]:
        """Get events within a time window."""
        return [e for e in self.events if start_ts <= e.timestamp <= end_ts]


# =============================================================================
# Policy and Refinement Types
# =============================================================================


class MFOTLFormula(BaseModel):
    """
    An MFOTL (Metric First-Order Temporal Logic) formula.

    Supports the following operators:
    - Propositional: ¬, ∧, ∨, →
    - Quantifiers: ∀, ∃
    - Past temporal: ●[I] (previous), S[I] (since), ◆[I] (once), ■[I] (historically)
    - Future temporal: ○[I] (next), U[I] (until), ◇[I] (eventually), □[I] (always)

    Attributes:
        formula: String representation of the MFOTL formula
        name: Optional human-readable name
        description: Optional description of the property
        free_variables: List of free variables in the formula
        time_bounds: Extracted time interval bounds
    """

    formula: str = Field(..., description="MFOTL formula string")
    name: str | None = Field(None, description="Human-readable name")
    description: str | None = Field(None, description="Property description")
    free_variables: list[str] = Field(default_factory=list, description="Free variables")
    time_bounds: list[tuple[int, int | None]] = Field(
        default_factory=list, description="Time interval bounds"
    )

    def __str__(self) -> str:
        return self.formula

    def compose(self, other: MFOTLFormula, operator: str = "∧") -> MFOTLFormula:
        """Compose with another formula using the given operator."""
        return MFOTLFormula(
            formula=f"({self.formula}) {operator} ({other.formula})",
            name=f"{self.name or 'φ1'} {operator} {other.name or 'φ2'}",
            free_variables=list(set(self.free_variables + other.free_variables)),
        )


class PolicyRefinement(BaseModel):
    """
    A proposed refinement to an existing policy.

    Generated by the NPA component and verified by SVB before
    being applied to enforcement.

    Attributes:
        refinement_id: Unique identifier
        delta_formula: The refinement formula (Δφ)
        refinement_type: Category of refinement
        confidence: NPA confidence score [0, 1]
        evidence_count: Number of trace events supporting this refinement
        source_pattern: Pattern that triggered this refinement
        created_at: Timestamp of creation
    """

    refinement_id: str = Field(..., description="Unique refinement ID")
    delta_formula: MFOTLFormula = Field(..., description="Refinement formula Δφ")
    refinement_type: RefinementType = Field(..., description="Type of refinement")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    evidence_count: int = Field(0, ge=0, description="Supporting evidence count")
    source_pattern: str | None = Field(None, description="Source pattern description")
    created_at: datetime = Field(default_factory=datetime.now, description="Creation time")

    def is_high_confidence(self, threshold: float = 0.8) -> bool:
        """Check if confidence exceeds threshold."""
        return self.confidence >= threshold


# =============================================================================
# Verification Types
# =============================================================================


class VerificationCertificate(BaseModel):
    """
    A certificate proving that a refinement satisfies safety invariants.

    Generated by SVB upon successful verification.

    Attributes:
        certificate_id: Unique identifier
        refinement_id: ID of the verified refinement
        invariants_checked: List of invariants verified against
        proof_sketch: High-level proof structure
        z3_model: Serialized Z3 proof (if available)
        generated_at: Certificate generation time
        valid_until: Expiration time (None for permanent)
    """

    certificate_id: str = Field(..., description="Unique certificate ID")
    refinement_id: str = Field(..., description="Verified refinement ID")
    invariants_checked: list[str] = Field(..., description="Checked invariant names")
    proof_sketch: str | None = Field(None, description="High-level proof structure")
    z3_model: str | None = Field(None, description="Serialized Z3 proof")
    generated_at: datetime = Field(default_factory=datetime.now, description="Generation time")
    valid_until: datetime | None = Field(None, description="Certificate expiration")


class Counterexample(BaseModel):
    """
    A counterexample demonstrating a refinement violates an invariant.

    Generated by SVB when verification fails.

    Attributes:
        invariant_violated: Name of the violated invariant
        witness_trace: Example trace demonstrating the violation
        variable_assignment: Z3 variable assignments in the counterexample
        explanation: Human-readable explanation
    """

    invariant_violated: str = Field(..., description="Violated invariant name")
    witness_trace: list[dict[str, Any]] = Field(..., description="Counterexample trace")
    variable_assignment: dict[str, Any] = Field(..., description="Variable assignments")
    explanation: str | None = Field(None, description="Human-readable explanation")


class VerificationResult(BaseModel):
    """
    Result of SVB verification.

    Attributes:
        status: Verification outcome
        accepted: Whether the refinement was accepted
        certificate: Proof certificate (if accepted)
        counterexample: Counterexample (if rejected)
        verification_time_ms: Time taken for verification
        z3_statistics: Z3 solver statistics
    """

    status: VerificationStatus = Field(..., description="Verification status")
    accepted: bool = Field(..., description="Whether refinement was accepted")
    certificate: VerificationCertificate | None = Field(None, description="Proof certificate")
    counterexample: Counterexample | None = Field(None, description="Counterexample if rejected")
    verification_time_ms: int = Field(0, ge=0, description="Verification time in ms")
    z3_statistics: dict[str, Any] = Field(default_factory=dict, description="Z3 stats")


# =============================================================================
# Enforcement Types
# =============================================================================


class QuantumContext(BaseModel):
    """
    Post-quantum security context for enforcement decisions.

    Captures the current quantum threat landscape and active
    cryptographic configuration.

    Attributes:
        active_algorithms: Currently active PQ algorithms
        hybrid_mode: Whether hybrid classical+PQ mode is active
        threat_level: Current quantum threat assessment
        ratchet_requirements: Key ratcheting configuration
        last_updated: Context update timestamp
    """

    active_algorithms: list[str] = Field(
        default_factory=lambda: ["ML-KEM-768", "ML-DSA-65"],
        description="Active PQ algorithms",
    )
    hybrid_mode: bool = Field(True, description="Hybrid mode active")
    threat_level: ThreatLevel = Field(ThreatLevel.MODERATE, description="Threat level")
    ratchet_requirements: dict[str, Any] = Field(default_factory=dict, description="Ratchet config")
    last_updated: datetime = Field(default_factory=datetime.now, description="Last update")

    def requires_immediate_ratchet(self) -> bool:
        """Check if current threat level requires immediate key ratchet."""
        return self.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)


class EnforcementAction(BaseModel):
    """
    An action taken by the PQAE enforcer.

    Attributes:
        action_type: Category of action (permit, block, modify, delay, alert)
        event_id: ID of the event being acted upon
        target: Target of the action
        reason: Explanation for the action
        parameters: Additional action parameters
        confidence: Confidence score for this action
        modified_event: Modified event (for MODIFY actions)
        delay_ms: Delay duration (for DELAY actions)
        timestamp: When the action was taken
    """

    action_type: ActionType | str = Field(..., description="Type of enforcement action")
    event_id: str = Field("", description="Target event ID")
    target: str = Field("", description="Action target")
    reason: str = Field("", description="Action explanation")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Action parameters")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Confidence score")
    modified_event: ProtocolEvent | None = Field(None, description="Modified event")
    delay_ms: int | None = Field(None, description="Delay duration")
    timestamp: datetime = Field(default_factory=datetime.now, description="Action time")


class PolicyViolation(BaseModel):
    """
    A detected policy violation.

    Attributes:
        violation_id: Unique violation identifier
        policy_name: Name of the violated policy
        formula: The violated MFOTL formula
        violating_events: Events that caused the violation
        detection_time: When the violation was detected
        timestamp: Event timestamp when violation occurred
        event_data: Data from the violating event
        severity: Violation severity level
    """

    violation_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), description="Unique violation ID"
    )
    policy_name: str = Field(..., description="Violated policy name")
    formula: str = Field("", description="Violated formula")
    violating_events: list[str] = Field(default_factory=list, description="Violating event IDs")
    detection_time: datetime = Field(default_factory=datetime.now, description="Detection time")
    timestamp: int | float = Field(0, description="Event timestamp")
    event_data: Any = Field(None, description="Violating event data")
    severity: str = Field("medium", description="Severity level")


class EnforcementResult(BaseModel):
    """
    Result of enforcement for a single event or trace.

    Attributes:
        action: The enforcement action taken
        success: Whether the event was permitted (not blocked)
        permitted: Alias for success - True if event was allowed
        violations: Any detected violations
        timestamp: When the enforcement decision was made
        reason: Explanation for the decision
        status: Overall enforcement status (for aggregate results)
        events_processed: Total events processed (for aggregate results)
        actions: All enforcement actions taken (for aggregate results)
        adaptations_applied: Policy adaptations that were applied
        processing_time_ms: Total processing time
        statistics: Additional enforcement statistics
    """

    # Single event result fields
    action: EnforcementAction | None = Field(None, description="Action taken")
    success: bool = Field(True, description="Whether event was permitted")
    violations: list[Any] = Field(default_factory=list, description="Violations")
    timestamp: datetime | None = Field(None, description="Decision timestamp")
    reason: str | None = Field(None, description="Decision reason")

    # Aggregate result fields
    status: str = Field("success", description="Overall status")
    events_processed: int = Field(0, ge=0, description="Events processed")
    actions: list[EnforcementAction] = Field(default_factory=list, description="Actions taken")
    adaptations_applied: list[str] = Field(default_factory=list, description="Applied adaptations")
    processing_time_ms: int = Field(0, ge=0, description="Processing time")
    statistics: dict[str, Any] = Field(default_factory=dict, description="Statistics")

    @property
    def permitted(self) -> bool:
        """Alias for success - returns True if event was allowed."""
        return self.success

    @property
    def violation_count(self) -> int:
        return len(self.violations)

    @property
    def action_count(self) -> int:
        return len(self.actions) + (1 if self.action else 0)


# =============================================================================
# Training and Model Types
# =============================================================================


@dataclass
class TrainingConfig:
    """Configuration for NPA model training."""

    batch_size: int = 32
    learning_rate: float = 1e-4
    epochs: int = 100
    warmup_steps: int = 1000
    weight_decay: float = 0.01
    gradient_clip: float = 1.0
    early_stopping_patience: int = 10
    validation_split: float = 0.1
    device: str = "cuda"


@dataclass
class ModelConfig:
    """Configuration for NPA transformer model."""

    embed_dim: int = 256
    num_heads: int = 8
    num_layers: int = 6
    ff_dim: int = 1024
    dropout: float = 0.1
    max_seq_length: int = 2048
    vocab_size: int = 10000
    num_relations: int = 100
    positional_encoding: str = "sinusoidal"


@dataclass
class EncoderOutput:
    """Output from the trace encoder."""

    embeddings: Any  # torch.Tensor
    attention_weights: Any | None = None  # torch.Tensor
    hidden_states: list[Any] | None = None  # list[torch.Tensor]


@dataclass
class RefinementProposal:
    """A refinement proposal from the NPA generator."""

    refinement: PolicyRefinement
    logits: Any  # torch.Tensor
    attention_pattern: Any | None = None  # torch.Tensor


# =============================================================================
# Utility Types
# =============================================================================


class Result(BaseModel, Generic[T]):
    """Generic result wrapper with success/failure semantics."""

    success: bool
    value: T | None = None
    error: str | None = None

    @classmethod
    def ok(cls, value: T) -> Result[T]:
        return cls(success=True, value=value)

    @classmethod
    def err(cls, error: str) -> Result[T]:
        return cls(success=False, error=error)

    def unwrap(self) -> T:
        if not self.success or self.value is None:
            raise ValueError(f"Cannot unwrap failed result: {self.error}")
        return self.value

    def unwrap_or(self, default: T) -> T:
        return self.value if self.success and self.value is not None else default


class SafetyInvariants(BaseModel):
    """
    Collection of safety invariants for verification.

    These invariants must hold for any policy refinement to be accepted.
    """

    invariants: list[MFOTLFormula] = Field(..., description="Safety invariant formulas")
    names: list[str] = Field(default_factory=list, description="Invariant names")

    def __init__(self, formulas: list[str] | list[MFOTLFormula], **data):
        if formulas and isinstance(formulas[0], str):
            formulas = [MFOTLFormula(formula=f) for f in formulas]
        super().__init__(invariants=formulas, **data)

    def __iter__(self):
        return iter(self.invariants)

    def __len__(self):
        return len(self.invariants)


# =============================================================================
# Additional Enums for Test Compatibility
# =============================================================================


class SecurityLevel(str, Enum):
    """Security level classification."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class QuantumSafetyLevel(str, Enum):
    """Quantum safety classification for cryptographic primitives."""

    CLASSICAL = "classical"
    """Classical cryptography, vulnerable to quantum attacks."""

    HYBRID = "hybrid"
    """Hybrid classical + post-quantum approach."""

    POST_QUANTUM = "post_quantum"
    """Full post-quantum cryptography."""


class ViolationType(str, Enum):
    """Types of policy violations detected."""

    TEMPORAL = "temporal"
    """Violation of temporal constraints."""

    SEQUENCE = "sequence"
    """Violation of event sequence requirements."""

    INVARIANT = "invariant"
    """Violation of safety invariants."""

    QUANTUM_SAFETY = "quantum_safety"
    """Violation of quantum safety requirements."""

    AUTHENTICATION = "authentication"
    """Authentication-related violation."""

    KEY_MANAGEMENT = "key_management"
    """Key management violation."""


class CertificateType(str, Enum):
    """Types of verification certificates."""

    SAFETY = "safety"
    """Certificate proving safety properties."""

    LIVENESS = "liveness"
    """Certificate proving liveness properties."""

    REFINEMENT = "refinement"
    """Certificate proving refinement correctness."""


class AbstractionLevel(str, Enum):
    """Abstraction levels for verification."""

    CONCRETE = "concrete"
    PREDICATE = "predicate"
    TEMPORAL = "temporal"
    INTERVAL = "interval"


# =============================================================================
# Additional Data Models for Test Compatibility
# =============================================================================


class TemporalInterval(BaseModel):
    """Time interval with optional bounds."""

    start: float = Field(..., description="Start time (seconds)")
    end: float | None = Field(default=None, description="End time (None = unbounded)")

    def contains(self, timestamp: float) -> bool:
        """Check if timestamp is within interval."""
        if self.end is None:
            return timestamp >= self.start
        return self.start <= timestamp <= self.end

    def overlaps(self, other: TemporalInterval) -> bool:
        """Check if intervals overlap."""
        if self.end is None and other.end is None:
            return True
        if self.end is None:
            return other.end >= self.start
        if other.end is None:
            return self.end >= other.start
        return self.start <= other.end and other.start <= self.end

    @property
    def duration(self) -> float | None:
        """Get duration (None if unbounded)."""
        if self.end is None:
            return None
        return self.end - self.start


class TraceEvent(BaseModel):
    """Single event in a protocol trace."""

    event_type: str = Field(..., description="Type of the event")
    timestamp: float = Field(..., description="Event timestamp")
    data: dict[str, Any] = Field(default_factory=dict, description="Event data")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Event metadata")
    security_level: SecurityLevel = Field(default=SecurityLevel.MEDIUM)


class ProtocolTrace(BaseModel):
    """Sequence of protocol events."""

    events: list[TraceEvent] = Field(default_factory=list)
    protocol_name: str = Field(default="unknown")
    session_id: str | None = None
    start_time: float | None = None
    end_time: float | None = None

    def __len__(self) -> int:
        return len(self.events)

    def __iter__(self):
        return iter(self.events)

    def append(self, event: TraceEvent) -> None:
        self.events.append(event)

    @property
    def duration(self) -> float | None:
        if not self.events:
            return None
        return self.events[-1].timestamp - self.events[0].timestamp


class PolicyFormula(BaseModel):
    """Policy formula in MFOTL syntax."""

    formula: str = Field(..., description="MFOTL formula string")
    name: str = Field(default="unnamed", description="Policy name")
    description: str = Field(default="", description="Human-readable description")
    priority: int = Field(default=0, description="Priority (higher = more important)")


class Violation(BaseModel):
    """Detected policy violation."""

    violation_type: ViolationType = Field(...)
    formula: PolicyFormula = Field(...)
    timestamp: float = Field(...)
    evidence: dict[str, Any] = Field(default_factory=dict)
    severity: float = Field(default=0.5, ge=0.0, le=1.0)
    description: str = Field(default="")


class Refinement(BaseModel):
    """Policy refinement proposal."""

    original_formula: PolicyFormula = Field(...)
    refined_formula: PolicyFormula = Field(...)
    refinement_type: RefinementType = Field(...)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    rationale: str = Field(default="")


class PatternSignature(BaseModel):
    """Signature of a detected pattern in traces."""

    pattern_id: str = Field(...)
    pattern_type: str = Field(...)
    frequency: int = Field(default=1)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    features: dict[str, Any] = Field(default_factory=dict)


class AnomalyScore(BaseModel):
    """Anomaly detection score."""

    score: float = Field(..., ge=0.0, le=1.0)
    components: dict[str, float] = Field(default_factory=dict)
    threshold: float = Field(default=0.5)
    is_anomaly: bool = Field(default=False)


@dataclass
class NPAState:
    """Internal state of Neural Policy Adapter."""

    learned_patterns: list[PatternSignature] = field(default_factory=list)
    refinement_history: list[Refinement] = field(default_factory=list)
    current_confidence: float = 0.0
    training_steps: int = 0


class SymbolicConstraint(BaseModel):
    """Constraint for symbolic verification."""

    constraint_type: str = Field(...)
    expression: str = Field(...)
    variables: list[str] = Field(default_factory=list)
    is_satisfied: bool | None = None


class ProofCertificate(BaseModel):
    """Certificate of proof from verification."""

    certificate_type: CertificateType = Field(...)
    formula: str = Field(...)
    proof_steps: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    is_valid: bool = Field(default=False)
    generated_at: datetime = Field(default_factory=datetime.now)


class QuantumThreat(BaseModel):
    """Quantum threat assessment."""

    primitive: str = Field(..., description="Cryptographic primitive assessed")
    threat_level: ThreatLevel = Field(...)
    vulnerability_score: float = Field(..., ge=0.0, le=1.0)
    recommended_action: str = Field(default="")
    timeline: str = Field(default="unknown")


class EnforcementDecision(BaseModel):
    """Decision from enforcement oracle."""

    action: ActionType = Field(...)
    reason: str = Field(default="")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    violations: list[Violation] = Field(default_factory=list)
    alternative_actions: list[ActionType] = Field(default_factory=list)


@dataclass
class MonitorState:
    """State of the MFOTL monitor."""

    current_timestamp: float = 0.0
    formula_states: dict[str, Any] = field(default_factory=dict)
    pending_violations: list[Violation] = field(default_factory=list)
    processed_events: int = 0
