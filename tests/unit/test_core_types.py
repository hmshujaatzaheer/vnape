"""
Unit tests for V-NAPE core types module.

Tests all Pydantic models, enums, and type definitions used throughout the framework.
"""

from dataclasses import is_dataclass

import pytest

from vnape.core.types import (
    AbstractionLevel,
    ActionType,
    AnomalyScore,
    CertificateType,
    Counterexample,
    EnforcementAction,
    EnforcementDecision,
    EnforcementMode,
    EnforcementResult,
    EventType,
    ExecutionTrace,
    MFOTLFormula,
    ModelConfig,
    MonitorState,
    NPAState,
    # NPA Types
    PatternSignature,
    PolicyFormula,
    PolicyViolation,
    ProofCertificate,
    # Main Protocol Types
    ProtocolEvent,
    ProtocolTrace,
    QuantumContext,
    QuantumSafetyLevel,
    # PQAE Types
    QuantumThreat,
    Refinement,
    RefinementType,
    # Utility Types
    Result,
    SafetyInvariants,
    # Enums
    SecurityLevel,
    # SVB Types
    SymbolicConstraint,
    # Core Models
    TemporalInterval,
    ThreatLevel,
    TraceEvent,
    TrainingConfig,
    VerificationCertificate,
    VerificationResult,
    VerificationStatus,
    Violation,
    ViolationType,
)


class TestSecurityLevel:
    """Tests for SecurityLevel enum."""

    def test_security_level_values(self):
        """Verify all security levels exist."""
        assert SecurityLevel.LOW.value == "low"
        assert SecurityLevel.MEDIUM.value == "medium"
        assert SecurityLevel.HIGH.value == "high"
        assert SecurityLevel.CRITICAL.value == "critical"

    def test_security_level_ordering(self):
        """Verify security levels can be compared."""
        levels = [
            SecurityLevel.LOW,
            SecurityLevel.MEDIUM,
            SecurityLevel.HIGH,
            SecurityLevel.CRITICAL,
        ]
        assert len(set(levels)) == 4


class TestQuantumSafetyLevel:
    """Tests for QuantumSafetyLevel enum."""

    def test_quantum_safety_values(self):
        """Verify quantum safety levels."""
        assert QuantumSafetyLevel.CLASSICAL.value == "classical"
        assert QuantumSafetyLevel.HYBRID.value == "hybrid"
        assert QuantumSafetyLevel.POST_QUANTUM.value == "post_quantum"

    def test_quantum_safety_comparison(self):
        """Verify levels are distinct."""
        assert QuantumSafetyLevel.CLASSICAL != QuantumSafetyLevel.POST_QUANTUM


class TestViolationType:
    """Tests for ViolationType enum."""

    def test_violation_types(self):
        """Verify all violation types exist."""
        types = [
            ViolationType.TEMPORAL,
            ViolationType.SEQUENCE,
            ViolationType.INVARIANT,
            ViolationType.QUANTUM_SAFETY,
            ViolationType.AUTHENTICATION,
            ViolationType.KEY_MANAGEMENT,
        ]
        assert len(types) == 6


class TestThreatLevel:
    """Tests for ThreatLevel enum."""

    def test_threat_levels(self):
        """Verify all threat levels exist."""
        assert ThreatLevel.LOW.value == "low"
        assert ThreatLevel.MODERATE.value == "moderate"
        assert ThreatLevel.ELEVATED.value == "elevated"
        assert ThreatLevel.HIGH.value == "high"
        assert ThreatLevel.CRITICAL.value == "critical"


class TestActionType:
    """Tests for ActionType enum."""

    def test_action_types(self):
        """Verify all action types exist."""
        assert ActionType.PERMIT.value == "permit"
        assert ActionType.BLOCK.value == "block"
        assert ActionType.MODIFY.value == "modify"
        assert ActionType.DELAY.value == "delay"
        assert ActionType.ALERT.value == "alert"


class TestEventType:
    """Tests for EventType enum."""

    def test_event_types(self):
        """Verify core event types exist."""
        assert EventType.KEY_EXCHANGE.value == "key_exchange"
        assert EventType.MESSAGE_SEND.value == "message_send"
        assert EventType.SESSION_START.value == "session_start"
        assert EventType.KEY_RATCHET.value == "key_ratchet"


class TestTemporalInterval:
    """Tests for TemporalInterval model."""

    def test_bounded_interval(self):
        """Test bounded interval creation."""
        interval = TemporalInterval(start=0.0, end=10.0)
        assert interval.start == 0.0
        assert interval.end == 10.0
        assert interval.duration == 10.0

    def test_unbounded_interval(self):
        """Test unbounded interval creation."""
        interval = TemporalInterval(start=0.0, end=None)
        assert interval.start == 0.0
        assert interval.end is None
        assert interval.duration is None

    def test_interval_contains(self):
        """Test contains method."""
        interval = TemporalInterval(start=0.0, end=10.0)
        assert interval.contains(5.0)
        assert interval.contains(0.0)
        assert interval.contains(10.0)
        assert not interval.contains(11.0)
        assert not interval.contains(-1.0)

    def test_unbounded_contains(self):
        """Test contains for unbounded interval."""
        interval = TemporalInterval(start=5.0, end=None)
        assert interval.contains(5.0)
        assert interval.contains(100.0)
        assert not interval.contains(4.0)

    def test_interval_overlaps(self):
        """Test overlaps method."""
        i1 = TemporalInterval(start=0.0, end=10.0)
        i2 = TemporalInterval(start=5.0, end=15.0)
        i3 = TemporalInterval(start=20.0, end=30.0)

        assert i1.overlaps(i2)
        assert i2.overlaps(i1)
        assert not i1.overlaps(i3)


class TestTraceEvent:
    """Tests for TraceEvent model."""

    def test_event_creation(self):
        """Test basic event creation."""
        event = TraceEvent(
            event_type="session_init",
            timestamp=100.0,
            data={"session_id": "abc123", "user": "alice"},
        )
        assert event.event_type == "session_init"
        assert event.timestamp == 100.0
        assert event.data["session_id"] == "abc123"
        assert event.security_level == SecurityLevel.MEDIUM  # default

    def test_event_with_security_level(self):
        """Test event with custom security level."""
        event = TraceEvent(
            event_type="key_exchange",
            timestamp=200.0,
            security_level=SecurityLevel.HIGH,
            metadata={"quantum_safe": True},
        )
        assert event.security_level == SecurityLevel.HIGH
        assert event.metadata["quantum_safe"] is True

    def test_event_ordering_by_timestamp(self):
        """Test that events can be compared by timestamp."""
        e1 = TraceEvent(event_type="E1", timestamp=100.0)
        e2 = TraceEvent(event_type="E2", timestamp=200.0)
        assert e1.timestamp < e2.timestamp


class TestProtocolTrace:
    """Tests for ProtocolTrace model."""

    def test_trace_creation(self):
        """Test basic trace creation."""
        events = [
            TraceEvent(event_type="start", timestamp=0.0),
            TraceEvent(event_type="end", timestamp=100.0),
        ]
        trace = ProtocolTrace(events=events, protocol_name="test_protocol", session_id="session123")
        assert len(trace) == 2
        assert trace.protocol_name == "test_protocol"

    def test_trace_duration(self):
        """Test trace duration calculation."""
        events = [
            TraceEvent(event_type="start", timestamp=0.0),
            TraceEvent(event_type="middle", timestamp=50.0),
            TraceEvent(event_type="end", timestamp=100.0),
        ]
        trace = ProtocolTrace(events=events)
        assert trace.duration == 100.0

    def test_empty_trace(self):
        """Test empty trace."""
        trace = ProtocolTrace()
        assert len(trace) == 0
        assert trace.duration is None

    def test_trace_iteration(self):
        """Test iterating over trace events."""
        events = [TraceEvent(event_type=f"event_{i}", timestamp=float(i)) for i in range(5)]
        trace = ProtocolTrace(events=events)

        collected = list(trace)
        assert len(collected) == 5
        assert collected[0].event_type == "event_0"

    def test_trace_append(self):
        """Test appending events to trace."""
        trace = ProtocolTrace()
        trace.append(TraceEvent(event_type="first", timestamp=0.0))
        trace.append(TraceEvent(event_type="second", timestamp=1.0))
        assert len(trace) == 2


class TestProtocolEvent:
    """Tests for main ProtocolEvent model."""

    def test_protocol_event_creation(self):
        """Test creating a ProtocolEvent."""
        event = ProtocolEvent(
            timestamp=1000,
            event_type=EventType.KEY_EXCHANGE,
            relation="key_exchange",
            values={"algorithm": "ML-KEM-768", "key_id": "k1"},
            session_id="sess123",
        )
        assert event.timestamp == 1000
        assert event.event_type == EventType.KEY_EXCHANGE
        assert event.relation == "key_exchange"

    def test_protocol_event_mfotl_tuple(self):
        """Test MFOTL tuple conversion."""
        event = ProtocolEvent(
            timestamp=500,
            event_type=EventType.MESSAGE_SEND,
            relation="msg_send",
            values={"sender": "alice", "receiver": "bob"},
        )
        mfotl = event.to_mfotl_tuple()
        assert "@500" in mfotl
        assert "msg_send" in mfotl


class TestExecutionTrace:
    """Tests for ExecutionTrace model."""

    def test_execution_trace_creation(self):
        """Test creating an ExecutionTrace."""
        trace = ExecutionTrace(trace_id="trace001", protocol_name="iMessage-PQ3", events=[])
        assert trace.trace_id == "trace001"
        assert len(trace) == 0

    def test_execution_trace_window(self):
        """Test window method for filtering events."""
        events = [
            ProtocolEvent(timestamp=i * 100, event_type=EventType.MESSAGE_SEND, relation="msg")
            for i in range(10)
        ]
        trace = ExecutionTrace(trace_id="t1", protocol_name="test", events=events)

        windowed = trace.window(200, 500)
        assert len(windowed) == 4  # timestamps 200, 300, 400, 500


class TestPolicyFormula:
    """Tests for PolicyFormula model."""

    def test_formula_creation(self):
        """Test basic formula creation."""
        formula = PolicyFormula(
            formula="□[0,∞) (key_exchange(k) → ◇[0,30] authenticated(k))",
            name="auth_requirement",
            description="Keys must be authenticated within 30 time units",
        )
        assert formula.formula.startswith("□")
        assert formula.name == "auth_requirement"

    def test_formula_with_priority(self):
        """Test formula with priority."""
        formula = PolicyFormula(formula="◇[0,10] complete", priority=100)
        assert formula.priority == 100


class TestMFOTLFormula:
    """Tests for MFOTLFormula model."""

    def test_mfotl_formula_creation(self):
        """Test MFOTL formula creation."""
        formula = MFOTLFormula(
            formula="∀x. key_exchange(x) → ◇[0,60] confirmed(x)",
            name="key_confirmation",
            free_variables=["x"],
        )
        assert str(formula) == formula.formula
        assert "x" in formula.free_variables

    def test_formula_composition(self):
        """Test composing two formulas."""
        f1 = MFOTLFormula(formula="P", name="P")
        f2 = MFOTLFormula(formula="Q", name="Q")

        composed = f1.compose(f2, "∧")
        assert "(P)" in composed.formula
        assert "(Q)" in composed.formula


class TestViolation:
    """Tests for Violation model."""

    def test_violation_creation(self):
        """Test creating a violation."""
        formula = PolicyFormula(formula="□[0,∞) safe")
        violation = Violation(
            violation_type=ViolationType.TEMPORAL,
            formula=formula,
            timestamp=500.0,
            evidence={"event": "unsafe_op"},
            severity=0.8,
        )
        assert violation.violation_type == ViolationType.TEMPORAL
        assert violation.severity == 0.8

    def test_violation_with_evidence(self):
        """Test violation with detailed evidence."""
        formula = PolicyFormula(formula="authenticated")
        violation = Violation(
            violation_type=ViolationType.AUTHENTICATION,
            formula=formula,
            timestamp=100.0,
            evidence={
                "expected": "authenticated",
                "actual": "unauthenticated",
                "session_id": "s123",
            },
            description="Authentication check failed",
        )
        assert "expected" in violation.evidence
        assert violation.description != ""


class TestRefinement:
    """Tests for Refinement model."""

    def test_refinement_creation(self):
        """Test creating a refinement."""
        original = PolicyFormula(formula="P")
        refined = PolicyFormula(formula="P ∧ Q")

        refinement = Refinement(
            original_formula=original,
            refined_formula=refined,
            refinement_type=RefinementType.CONJUNCTIVE_EXTENSION,
            confidence=0.85,
            rationale="Adding constraint Q based on observed patterns",
        )
        assert refinement.confidence == 0.85
        assert refinement.refinement_type == RefinementType.CONJUNCTIVE_EXTENSION

    def test_refinement_confidence_bounds(self):
        """Test confidence must be in [0, 1]."""
        original = PolicyFormula(formula="P")
        refined = PolicyFormula(formula="P'")

        with pytest.raises(Exception):  # Pydantic validation
            Refinement(
                original_formula=original,
                refined_formula=refined,
                refinement_type=RefinementType.PARAMETER_TIGHTENING,
                confidence=1.5,  # Invalid
            )


class TestPatternSignature:
    """Tests for PatternSignature model."""

    def test_pattern_creation(self):
        """Test creating a pattern signature."""
        pattern = PatternSignature(
            pattern_id="pat_001",
            pattern_type="temporal_sequence",
            frequency=42,
            confidence=0.92,
            features={"length": 5, "events": ["A", "B", "C"]},
        )
        assert pattern.pattern_id == "pat_001"
        assert pattern.frequency == 42
        assert pattern.confidence == 0.92


class TestAnomalyScore:
    """Tests for AnomalyScore model."""

    def test_anomaly_score_creation(self):
        """Test creating an anomaly score."""
        score = AnomalyScore(
            score=0.75,
            components={"temporal": 0.8, "structural": 0.7},
            threshold=0.5,
            is_anomaly=True,
        )
        assert score.score == 0.75
        assert score.is_anomaly is True

    def test_anomaly_threshold(self):
        """Test anomaly with different thresholds."""
        score = AnomalyScore(score=0.4, threshold=0.5, is_anomaly=False)
        assert not score.is_anomaly

        score2 = AnomalyScore(score=0.6, threshold=0.5, is_anomaly=True)
        assert score2.is_anomaly


class TestSymbolicConstraint:
    """Tests for SymbolicConstraint model."""

    def test_constraint_creation(self):
        """Test creating a symbolic constraint."""
        constraint = SymbolicConstraint(
            constraint_type="temporal_bound", expression="t1 < t2 + 30", variables=["t1", "t2"]
        )
        assert constraint.expression == "t1 < t2 + 30"
        assert len(constraint.variables) == 2


class TestVerificationResult:
    """Tests for VerificationResult model."""

    def test_sat_result(self):
        """Test satisfiable result."""
        cert = VerificationCertificate(
            certificate_id="cert_001", refinement_id="ref_001", invariants_checked=["safety_inv_1"]
        )
        result = VerificationResult(
            status=VerificationStatus.ACCEPTED,
            accepted=True,
            certificate=cert,
            verification_time_ms=150,
        )
        assert result.accepted
        assert result.certificate is not None

    def test_unsat_result(self):
        """Test unsatisfiable result."""
        counterex = Counterexample(
            invariant_violated="safety_1",
            witness_trace=[{"event": "bad"}],
            variable_assignment={"x": 1},
            explanation="Safety violated at step 3",
        )
        result = VerificationResult(
            status=VerificationStatus.REJECTED, accepted=False, counterexample=counterex
        )
        assert not result.accepted
        assert result.counterexample is not None


class TestProofCertificate:
    """Tests for ProofCertificate model."""

    def test_certificate_creation(self):
        """Test creating a proof certificate."""
        cert = ProofCertificate(
            certificate_type=CertificateType.SAFETY,
            formula="□[0,∞) P",
            proof_steps=["step1: assume P", "step2: derive □P"],
            assumptions=["P holds initially"],
            is_valid=True,
        )
        assert cert.certificate_type == CertificateType.SAFETY
        assert cert.is_valid
        assert len(cert.proof_steps) == 2


class TestQuantumThreat:
    """Tests for QuantumThreat model."""

    def test_threat_assessment(self):
        """Test quantum threat assessment for RSA."""
        threat = QuantumThreat(
            primitive="RSA-2048",
            threat_level=ThreatLevel.CRITICAL,
            vulnerability_score=0.95,
            recommended_action="Migrate to ML-KEM",
            timeline="2030-2035",
        )
        assert threat.primitive == "RSA-2048"
        assert threat.threat_level == ThreatLevel.CRITICAL
        assert threat.vulnerability_score == 0.95

    def test_pq_safe_primitive(self):
        """Test PQ-safe primitive assessment."""
        threat = QuantumThreat(
            primitive="ML-KEM-768",
            threat_level=ThreatLevel.LOW,
            vulnerability_score=0.05,
            recommended_action="No action needed",
        )
        assert threat.threat_level == ThreatLevel.LOW


class TestQuantumContext:
    """Tests for QuantumContext model."""

    def test_context_creation(self):
        """Test creating a quantum context."""
        ctx = QuantumContext(
            active_algorithms=["ML-KEM-768", "ML-DSA-65"],
            hybrid_mode=True,
            threat_level=ThreatLevel.MODERATE,
        )
        assert "ML-KEM-768" in ctx.active_algorithms
        assert ctx.hybrid_mode

    def test_immediate_ratchet_requirement(self):
        """Test ratchet requirement based on threat level."""
        ctx_moderate = QuantumContext(threat_level=ThreatLevel.MODERATE)
        ctx_critical = QuantumContext(threat_level=ThreatLevel.CRITICAL)

        assert not ctx_moderate.requires_immediate_ratchet()
        assert ctx_critical.requires_immediate_ratchet()


class TestEnforcementDecision:
    """Tests for EnforcementDecision model."""

    def test_allow_decision(self):
        """Test permit decision."""
        decision = EnforcementDecision(
            action=ActionType.PERMIT, reason="All policies satisfied", confidence=0.99
        )
        assert decision.action == ActionType.PERMIT
        assert decision.confidence == 0.99

    def test_block_decision(self):
        """Test block decision with violations."""
        formula = PolicyFormula(formula="safe")
        violation = Violation(
            violation_type=ViolationType.SEQUENCE, formula=formula, timestamp=100.0
        )
        decision = EnforcementDecision(
            action=ActionType.BLOCK,
            reason="Security policy violated",
            violations=[violation],
            alternative_actions=[ActionType.MODIFY, ActionType.DELAY],
        )
        assert decision.action == ActionType.BLOCK
        assert len(decision.violations) == 1
        assert len(decision.alternative_actions) == 2


class TestEnforcementResult:
    """Tests for EnforcementResult model."""

    def test_result_creation(self):
        """Test creating an enforcement result."""
        result = EnforcementResult(status="success", events_processed=100, processing_time_ms=250)
        assert result.events_processed == 100
        assert result.violation_count == 0
        assert result.action_count == 0

    def test_result_with_violations(self):
        """Test result with violations and actions."""
        violation = PolicyViolation(
            violation_id="v1",
            policy_name="auth_policy",
            formula="auth_required",
            violating_events=["e1", "e2"],
        )
        action = EnforcementAction(
            action_type=ActionType.ALERT, event_id="e1", reason="Unauthenticated event"
        )
        result = EnforcementResult(violations=[violation], actions=[action], events_processed=50)
        assert result.violation_count == 1
        assert result.action_count == 1


class TestMonitorState:
    """Tests for MonitorState dataclass."""

    def test_monitor_state_creation(self):
        """Test creating a monitor state."""
        assert is_dataclass(MonitorState)
        state = MonitorState(current_timestamp=500.0, processed_events=100)
        assert state.current_timestamp == 500.0
        assert state.processed_events == 100


class TestNPAState:
    """Tests for NPAState dataclass."""

    def test_npa_state_creation(self):
        """Test creating NPA state."""
        assert is_dataclass(NPAState)
        state = NPAState(training_steps=1000, current_confidence=0.85)
        assert state.training_steps == 1000
        assert len(state.learned_patterns) == 0


class TestResultType:
    """Tests for generic Result type."""

    def test_ok_result(self):
        """Test successful result."""
        result = Result.ok("success_value")
        assert result.success
        assert result.unwrap() == "success_value"

    def test_err_result(self):
        """Test error result."""
        result = Result.err("something went wrong")
        assert not result.success
        assert result.error == "something went wrong"

        with pytest.raises(ValueError):
            result.unwrap()

    def test_unwrap_or(self):
        """Test unwrap_or with default."""
        ok_result = Result.ok(42)
        err_result = Result.err("error")

        assert ok_result.unwrap_or(0) == 42
        assert err_result.unwrap_or(0) == 0


class TestSafetyInvariants:
    """Tests for SafetyInvariants model."""

    def test_invariants_from_strings(self):
        """Test creating invariants from formula strings."""
        invariants = SafetyInvariants(
            formulas=["□[0,∞) safe", "◇[0,60] complete"], names=["safety", "completion"]
        )
        assert len(invariants) == 2
        assert invariants.names == ["safety", "completion"]

    def test_invariants_iteration(self):
        """Test iterating over invariants."""
        invariants = SafetyInvariants(
            formulas=[MFOTLFormula(formula="P"), MFOTLFormula(formula="Q")]
        )
        formulas = list(invariants)
        assert len(formulas) == 2


class TestConfigDataclasses:
    """Tests for configuration dataclasses."""

    def test_training_config(self):
        """Test TrainingConfig defaults."""
        config = TrainingConfig()
        assert config.batch_size == 32
        assert config.learning_rate == 1e-4
        assert config.epochs == 100

    def test_model_config(self):
        """Test ModelConfig defaults."""
        config = ModelConfig()
        assert config.embed_dim == 256
        assert config.num_heads == 8
        assert config.num_layers == 6


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    @pytest.mark.parametrize("timestamp", [0.0, 1e10, 0.001])
    def test_valid_timestamps(self, timestamp):
        """Test valid timestamp values."""
        event = TraceEvent(event_type="test", timestamp=timestamp)
        assert event.timestamp == timestamp

    @pytest.mark.parametrize("confidence", [0.0, 0.5, 1.0])
    def test_valid_confidence_values(self, confidence):
        """Test confidence bounds."""
        score = AnomalyScore(score=confidence, threshold=0.5)
        assert 0.0 <= score.score <= 1.0

    @pytest.mark.parametrize(
        "formula",
        [
            "□[0,∞) P",
            "◇[0,30] Q",
            "∀x. P(x) → Q(x)",
            "P S[0,10] Q",
            "P U[0,∞) Q",
        ],
    )
    def test_formula_patterns(self, formula):
        """Test various MFOTL formula patterns."""
        f = MFOTLFormula(formula=formula)
        assert f.formula == formula


class TestEnumCompleteness:
    """Tests to verify enum completeness."""

    def test_enforcement_mode_completeness(self):
        """Test all enforcement modes."""
        modes = list(EnforcementMode)
        assert EnforcementMode.STRICT in modes
        assert EnforcementMode.PERMISSIVE in modes
        assert EnforcementMode.AUDIT in modes
        assert len(modes) == 3

    def test_verification_status_completeness(self):
        """Test all verification statuses."""
        statuses = list(VerificationStatus)
        assert VerificationStatus.ACCEPTED in statuses
        assert VerificationStatus.REJECTED in statuses
        assert VerificationStatus.TIMEOUT in statuses
        assert VerificationStatus.UNKNOWN in statuses
        assert len(statuses) == 4

    def test_certificate_type_completeness(self):
        """Test all certificate types."""
        types = list(CertificateType)
        assert CertificateType.SAFETY in types
        assert CertificateType.LIVENESS in types
        assert CertificateType.REFINEMENT in types
        assert len(types) == 3

    def test_abstraction_level_completeness(self):
        """Test all abstraction levels."""
        levels = list(AbstractionLevel)
        assert AbstractionLevel.CONCRETE in levels
        assert AbstractionLevel.PREDICATE in levels
        assert AbstractionLevel.TEMPORAL in levels
        assert AbstractionLevel.INTERVAL in levels
        assert len(levels) == 4


# Additional tests for 100% coverage
class TestExecutionTraceAdditional:
    """Additional tests for ExecutionTrace to cover missing lines."""

    def test_trace_iteration(self):
        """Test iterating over trace events."""
        event1 = ProtocolEvent(
            event_type=EventType.MESSAGE_SEND,
            timestamp=100,
            relation="Send",
            values={"msg": "hello"},
        )
        event2 = ProtocolEvent(
            event_type=EventType.MESSAGE_RECEIVE,
            timestamp=200,
            relation="Recv",
            values={"msg": "world"},
        )
        trace = ExecutionTrace(trace_id="test-1", protocol_name="test", events=[event1, event2])

        events = list(trace)
        assert len(events) == 2
        assert events[0].relation == "Send"

    def test_trace_indexing(self):
        """Test indexing trace events."""
        event1 = ProtocolEvent(
            event_type=EventType.MESSAGE_SEND, timestamp=100, relation="Send", values={}
        )
        event2 = ProtocolEvent(
            event_type=EventType.MESSAGE_RECEIVE, timestamp=200, relation="Recv", values={}
        )
        trace = ExecutionTrace(trace_id="test-2", protocol_name="test", events=[event1, event2])

        assert trace[0].relation == "Send"
        assert trace[1].relation == "Recv"

    def test_trace_append(self):
        """Test appending events to trace."""
        trace = ExecutionTrace(trace_id="test-3", protocol_name="test", events=[])
        event = ProtocolEvent(
            event_type=EventType.MESSAGE_SEND, timestamp=100, relation="NewEvent", values={}
        )
        trace.append(event)

        assert len(trace.events) == 1
        assert trace.events[0].relation == "NewEvent"


class TestPolicyRefinementAdditional:
    """Additional tests for PolicyRefinement."""

    def test_is_high_confidence(self):
        """Test high confidence check."""
        from vnape.core.types import PolicyRefinement

        refinement = PolicyRefinement(
            refinement_id="r1",
            delta_formula=MFOTLFormula(formula="P(x)"),
            refinement_type=RefinementType.CONJUNCTIVE_EXTENSION,
            confidence=0.9,
        )
        assert refinement.is_high_confidence(threshold=0.8) is True
        assert refinement.is_high_confidence(threshold=0.95) is False


class TestTemporalIntervalOverlaps:
    """Tests for TemporalInterval overlaps method."""

    def test_both_unbounded_overlaps(self):
        """Test overlap when both intervals are unbounded."""
        interval1 = TemporalInterval(start=0, end=None)
        interval2 = TemporalInterval(start=5, end=None)
        assert interval1.overlaps(interval2) is True

    def test_first_unbounded_overlaps(self):
        """Test overlap when first interval is unbounded."""
        interval1 = TemporalInterval(start=0, end=None)
        interval2 = TemporalInterval(start=5, end=10)
        assert interval1.overlaps(interval2) is True

    def test_second_unbounded_overlaps(self):
        """Test overlap when second interval is unbounded."""
        interval1 = TemporalInterval(start=0, end=10)
        interval2 = TemporalInterval(start=5, end=None)
        assert interval1.overlaps(interval2) is True

    def test_no_overlap(self):
        """Test non-overlapping intervals."""
        interval1 = TemporalInterval(start=0, end=5)
        interval2 = TemporalInterval(start=10, end=15)
        assert interval1.overlaps(interval2) is False
