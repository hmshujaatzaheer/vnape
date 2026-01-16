"""
Unit tests for V-NAPE Protocol implementations.

Tests aligned with actual implementation API.
"""

import pytest

from vnape.protocols.base import BaseProtocol, ProtocolState, StateType


# ============================================================================
# Base Protocol Tests
# ============================================================================


class TestBaseProtocol:
    """Tests for base protocol class."""

    def test_base_protocol_is_abstract(self):
        """Test that BaseProtocol is abstract."""
        with pytest.raises(TypeError):
            BaseProtocol(name="test")

    def test_base_protocol_has_required_methods(self):
        """Test BaseProtocol has required abstract methods."""
        assert hasattr(BaseProtocol, 'get_states')
        assert hasattr(BaseProtocol, 'get_transitions')
        assert hasattr(BaseProtocol, 'get_base_policies')
        assert hasattr(BaseProtocol, 'get_safety_invariants')
        assert hasattr(BaseProtocol, 'get_cryptographic_primitives')


# ============================================================================
# Protocol State Tests
# ============================================================================


class TestProtocolState:
    """Tests for protocol state."""

    def test_state_creation(self):
        """Test state creation."""
        state = ProtocolState(
            name="Initial",
            state_type=StateType.INITIAL,
            description="Initial state",
        )
        assert state.name == "Initial"
        assert state.state_type == StateType.INITIAL

    def test_state_equality(self):
        """Test state equality."""
        state1 = ProtocolState(name="Test", state_type=StateType.INTERMEDIATE)
        state2 = ProtocolState(name="Test", state_type=StateType.FINAL)
        # States are equal by name
        assert state1 == state2


# ============================================================================
# iMessage PQ3 Protocol Tests - Using CORRECT API
# ============================================================================


class TestIMessagePQ3Protocol:
    """Tests for iMessage PQ3 protocol."""

    @pytest.fixture
    def protocol(self):
        """Create PQ3 protocol instance."""
        from vnape.protocols.imessage_pq3 import IMessagePQ3Protocol
        return IMessagePQ3Protocol()

    def test_protocol_initialization(self, protocol):
        """Test protocol initializes correctly."""
        assert protocol.name == "iMessage-PQ3"

    def test_get_states(self, protocol):
        """Test getting protocol states."""
        states = protocol.get_states()
        assert len(states) > 0
        state_names = [s.name for s in states]
        assert "Idle" in state_names  # Implementation uses "Idle" as initial state

    def test_get_transitions(self, protocol):
        """Test getting protocol transitions."""
        transitions = protocol.get_transitions()
        assert len(transitions) > 0

    def test_get_cryptographic_primitives(self, protocol):
        """Test getting cryptographic primitives."""
        primitives = protocol.get_cryptographic_primitives()
        assert len(primitives) > 0

    def test_get_base_policies(self, protocol):
        """Test getting base policies."""
        policies = protocol.get_base_policies()
        assert len(policies) > 0

    def test_get_safety_invariants(self, protocol):
        """Test getting safety invariants."""
        invariants = protocol.get_safety_invariants()
        assert len(invariants) > 0

    def test_initial_state(self, protocol):
        """Test initial state."""
        initial = protocol.get_initial_states()[0]
        assert initial is not None
        assert initial.name == "Idle"  # Implementation uses "Idle"

    def test_final_states(self, protocol):
        """Test final states."""
        final_states = protocol.get_final_states()
        assert len(final_states) > 0


# ============================================================================
# AKMA+ Protocol Tests - Using CORRECT API
# ============================================================================


class TestAKMAPlusProtocol:
    """Tests for AKMA+ protocol."""

    @pytest.fixture
    def protocol(self):
        """Create AKMA+ protocol instance."""
        from vnape.protocols.akma_plus import AKMAPlusProtocol
        return AKMAPlusProtocol()

    def test_protocol_initialization(self, protocol):
        """Test protocol initializes correctly."""
        assert protocol.name == "AKMA-Plus"  # Implementation uses "AKMA-Plus"

    def test_get_states(self, protocol):
        """Test getting protocol states."""
        states = protocol.get_states()
        assert len(states) > 0

    def test_get_transitions(self, protocol):
        """Test getting protocol transitions."""
        transitions = protocol.get_transitions()
        assert len(transitions) > 0

    def test_get_cryptographic_primitives(self, protocol):
        """Test getting cryptographic primitives."""
        primitives = protocol.get_cryptographic_primitives()
        assert len(primitives) > 0
