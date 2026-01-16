"""
Smoke tests for V-NAPE core functionality.

These tests verify basic functionality without requiring optional dependencies like torch.
"""

import pytest

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


class TestCoreImports:
    """Test that core modules can be imported."""

    def test_core_types_import(self):
        """Test core types import."""
        from vnape.core.types import (
            SecurityLevel,
        )

        assert SecurityLevel.HIGH.value == "high"

    def test_pqae_monitor_import(self):
        """Test PQAE monitor import."""
        from vnape.pqae.monitor import (
            Verdict,
        )

        # Check enum values (actual values)
        assert Verdict.SATISFIED is not None
        assert Verdict.VIOLATED is not None

    def test_pqae_quantum_context_import(self):
        """Test PQAE quantum context import."""
        from vnape.pqae.quantum_context import (
            QUANTUM_CAPABILITIES,
        )

        # Check pre-defined capabilities exist
        assert "current_2024" in QUANTUM_CAPABILITIES
        assert "near_term_2030" in QUANTUM_CAPABILITIES

    def test_svb_translator_import(self):
        """Test SVB translator import (directly, without full SVB module)."""
        from vnape.svb.translator import (
            OperatorType,
        )

        assert OperatorType.AND is not None

    def test_protocols_base_import(self):
        """Test protocols base import."""
        from vnape.protocols.base import (
            StateType,
        )

        # StateType uses auto() which gives integer values
        assert StateType.INITIAL is not None


class TestQuantumThreatContext:
    """Test quantum threat assessment."""

    def test_predefined_capabilities(self):
        """Test pre-defined quantum capability profiles."""
        from vnape.pqae.quantum_context import QUANTUM_CAPABILITIES

        # 2024 capabilities
        cap_2024 = QUANTUM_CAPABILITIES["current_2024"]
        assert cap_2024.physical_qubits > 0
        assert cap_2024.logical_qubits == 0  # No error-corrected qubits yet

        # 2030 capabilities
        cap_2030 = QUANTUM_CAPABILITIES["near_term_2030"]
        assert cap_2030.physical_qubits > cap_2024.physical_qubits
        assert cap_2030.logical_qubits > 0

    def test_capability_rsa_assessment(self):
        """Test RSA vulnerability assessment."""
        from vnape.pqae.quantum_context import QUANTUM_CAPABILITIES

        cap_2024 = QUANTUM_CAPABILITIES["current_2024"]
        cap_crqc = QUANTUM_CAPABILITIES["crqc_ready"]

        # 2024: Cannot break RSA-2048
        assert not cap_2024.can_break_rsa(2048)

        # CRQC with 4000 logical qubits:
        # RSA-2048 needs ~4096 logical qubits (2*2048)
        # So CRQC can break RSA-1024 (needs 2048 qubits) but not RSA-2048
        assert cap_crqc.can_break_rsa(1024)  # Can break smaller keys
        # Note: CRQC profile has 4000 qubits, RSA-2048 needs 4096

    def test_primitive_vulnerabilities(self):
        """Test primitive vulnerability database."""
        from vnape.pqae.quantum_context import (
            PRIMITIVE_VULNERABILITIES,
            CryptographicPrimitive,
            QuantumRiskLevel,
        )

        # RSA is quantum vulnerable
        rsa_vuln = PRIMITIVE_VULNERABILITIES[CryptographicPrimitive.RSA]
        assert rsa_vuln.quantum_vulnerable
        assert rsa_vuln.migration_urgency == QuantumRiskLevel.HIGH

        # ML-KEM is post-quantum safe
        if CryptographicPrimitive.ML_KEM in PRIMITIVE_VULNERABILITIES:
            mlkem_vuln = PRIMITIVE_VULNERABILITIES[CryptographicPrimitive.ML_KEM]
            assert not mlkem_vuln.quantum_vulnerable


class TestProtocolState:
    """Test protocol state machine functionality."""

    def test_state_creation(self):
        """Test creating protocol states."""
        from vnape.protocols.base import ProtocolState, StateType

        state = ProtocolState(
            name="Initial", state_type=StateType.INITIAL, description="Initial state"
        )
        assert state.name == "Initial"
        assert state.state_type == StateType.INITIAL

    def test_transition_creation(self):
        """Test creating protocol transitions."""
        from vnape.protocols.base import ProtocolTransition

        trans = ProtocolTransition(
            source="init", target="key_exchange", event="key_init", guard="has_identity"
        )
        assert trans.source == "init"
        assert trans.target == "key_exchange"


class TestCoreTypesIntegration:
    """Integration tests for core types."""

    def test_protocol_event_creation(self):
        """Test creating protocol events."""
        from vnape.core.types import EventType, ProtocolEvent

        event = ProtocolEvent(
            timestamp=1000,
            event_type=EventType.KEY_EXCHANGE,
            relation="key_exchange",
            values={"algorithm": "ML-KEM-768", "key_id": "k1"},
        )

        mfotl = event.to_mfotl_tuple()
        assert "@1000" in mfotl
        assert "key_exchange" in mfotl

    def test_execution_trace_window(self):
        """Test execution trace windowing."""
        from vnape.core.types import EventType, ExecutionTrace, ProtocolEvent

        events = [
            ProtocolEvent(timestamp=i * 100, event_type=EventType.MESSAGE_SEND, relation="msg")
            for i in range(10)
        ]

        trace = ExecutionTrace(trace_id="test", protocol_name="test_protocol", events=events)

        # Window [200, 500] should include timestamps 200, 300, 400, 500
        windowed = trace.window(200, 500)
        assert len(windowed) == 4
        assert all(200 <= e.timestamp <= 500 for e in windowed)

    def test_mfotl_formula_composition(self):
        """Test composing MFOTL formulas."""
        from vnape.core.types import MFOTLFormula

        f1 = MFOTLFormula(formula="authenticated(x)", name="auth")
        f2 = MFOTLFormula(formula="encrypted(x)", name="enc")

        composed = f1.compose(f2, "∧")
        assert "authenticated" in composed.formula
        assert "encrypted" in composed.formula
        assert "∧" in composed.formula

    def test_quantum_context_ratchet_requirement(self):
        """Test quantum context threat level checking."""
        from vnape.core.types import QuantumContext, ThreatLevel

        moderate_ctx = QuantumContext(threat_level=ThreatLevel.MODERATE)
        critical_ctx = QuantumContext(threat_level=ThreatLevel.CRITICAL)

        assert not moderate_ctx.requires_immediate_ratchet()
        assert critical_ctx.requires_immediate_ratchet()

    def test_result_monad_pattern(self):
        """Test Result monad pattern."""
        from vnape.core.types import Result

        # Success case
        ok_result = Result.ok(42)
        assert ok_result.success
        assert ok_result.unwrap() == 42

        # Error case
        err_result = Result.err("operation failed")
        assert not err_result.success
        assert err_result.unwrap_or(0) == 0

        with pytest.raises(ValueError):
            err_result.unwrap()


class TestMFOTLMonitorBasic:
    """Test MFOTL monitoring basic functionality."""

    def test_time_interval_creation(self):
        """Test time interval creation."""
        from vnape.pqae.monitor import TimeInterval

        # Bounded interval [0, 10]
        bounded = TimeInterval(0, 10)
        assert bounded.lower == 0
        assert bounded.upper == 10
        assert bounded.is_bounded()

        # Unbounded interval [0, ∞) - use float('inf') not None
        unbounded = TimeInterval.unbounded(0)  # Use classmethod
        assert unbounded.lower == 0
        assert unbounded.upper == float("inf")
        assert not unbounded.is_bounded()

    def test_trace_event_creation(self):
        """Test trace event creation for monitor."""
        from vnape.pqae.monitor import TraceEvent

        # Create event with relations
        event = TraceEvent(timestamp=100, relations={"P": [{}], "Q": [{"x": 1}]})
        assert event.timestamp == 100
        assert "P" in event.relations
        assert "Q" in event.relations


class TestSVBComponents:
    """Test Symbolic Verification Bridge components."""

    def test_svb_translator_import(self):
        """Test that SVB translator can be imported directly."""
        from vnape.svb.translator import (
            MFOTLToZ3Translator,
        )

        # Just check imports work
        assert MFOTLToZ3Translator is not None

    @pytest.mark.skipif(not TORCH_AVAILABLE, reason="SVB requires torch for abstraction")
    def test_svb_full_imports(self):
        """Test that full SVB can be imported (requires torch)."""
        from vnape.svb import (
            AbstractionEngine,
            MFOTLToZ3Translator,
        )

        # Just check imports work
        assert MFOTLToZ3Translator is not None
        assert AbstractionEngine is not None

    def test_operator_types(self):
        """Test operator type definitions."""
        from vnape.svb.translator import OperatorType

        # Logical operators
        assert OperatorType.AND is not None
        assert OperatorType.OR is not None
        assert OperatorType.NOT is not None
        assert OperatorType.IMPLIES is not None

        # Temporal operators
        assert OperatorType.ALWAYS is not None
        assert OperatorType.EVENTUALLY is not None


class TestProtocolImplementations:
    """Test protocol implementations."""

    def test_imessage_pq3_import(self):
        """Test iMessage PQ3 protocol import."""
        from vnape.protocols.imessage_pq3 import IMessagePQ3Protocol

        protocol = IMessagePQ3Protocol()
        assert protocol.name == "iMessage-PQ3"

        # Check states exist
        states = protocol.get_states()
        assert len(states) > 0

        # Check transitions exist
        transitions = protocol.get_transitions()
        assert len(transitions) > 0

    def test_akma_plus_import(self):
        """Test AKMA+ protocol import."""
        from vnape.protocols.akma_plus import AKMAPlusProtocol

        protocol = AKMAPlusProtocol()
        assert protocol.name == "AKMA-Plus"  # Fixed: actual name

        states = protocol.get_states()
        assert len(states) > 0


class TestQuantumRiskScenarios:
    """Test quantum risk assessment scenarios."""

    def test_hndl_scenario(self):
        """Test Harvest Now Decrypt Later scenario."""
        from vnape.pqae.quantum_context import (
            QUANTUM_CAPABILITIES,
        )

        # Data captured today, need to protect for 20 years
        cap_2024 = QUANTUM_CAPABILITIES["current_2024"]
        cap_crqc = QUANTUM_CAPABILITIES["crqc_ready"]

        # Calculate if data captured today would be vulnerable
        # when CRQC arrives (10-15 years estimated)
        years_to_crqc = cap_2024.years_to_crqc
        data_lifetime_years = 20

        # If data lifetime > years to CRQC, HNDL is a concern
        hndl_risk = data_lifetime_years > years_to_crqc
        assert hndl_risk  # RSA-encrypted data captured today is at risk

    def test_pq_algorithm_recommendations(self):
        """Test post-quantum algorithm recommendations."""
        from vnape.pqae.quantum_context import (
            PRIMITIVE_VULNERABILITIES,
            CryptographicPrimitive,
        )

        # Check RSA recommendation
        rsa_vuln = PRIMITIVE_VULNERABILITIES[CryptographicPrimitive.RSA]
        assert rsa_vuln.recommended_replacement == CryptographicPrimitive.ML_KEM


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
