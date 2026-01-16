"""
V-NAPE Test Configuration and Fixtures

Provides shared fixtures for unit and integration tests.
"""

import shutil
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

# ============================================================================
# TRACE FIXTURES
# ============================================================================


@pytest.fixture
def sample_trace_events() -> list[dict[str, Any]]:
    """Sample trace events for testing."""
    base_time = datetime(2024, 1, 1, 12, 0, 0)
    return [
        {
            "timestamp": base_time,
            "name": "SessionInit",
            "args": {"session_id": "sess_001", "client_id": "client_a"},
        },
        {
            "timestamp": base_time + timedelta(seconds=1),
            "name": "KeyExchange",
            "args": {"session_id": "sess_001", "algorithm": "X25519+ML-KEM-768"},
        },
        {
            "timestamp": base_time + timedelta(seconds=2),
            "name": "SessionEstablished",
            "args": {"session_id": "sess_001"},
        },
        {
            "timestamp": base_time + timedelta(seconds=5),
            "name": "MessageSent",
            "args": {"session_id": "sess_001", "message_id": "msg_001"},
        },
        {
            "timestamp": base_time + timedelta(seconds=6),
            "name": "MessageReceived",
            "args": {"session_id": "sess_001", "message_id": "msg_001"},
        },
    ]


@pytest.fixture
def violation_trace_events() -> list[dict[str, Any]]:
    """Trace events containing a policy violation."""
    base_time = datetime(2024, 1, 1, 12, 0, 0)
    return [
        {
            "timestamp": base_time,
            "name": "SessionInit",
            "args": {"session_id": "sess_002", "client_id": "client_b"},
        },
        {
            "timestamp": base_time + timedelta(seconds=1),
            "name": "KeyExchange",
            "args": {"session_id": "sess_002", "algorithm": "RSA-2048"},  # Weak!
        },
        {
            "timestamp": base_time + timedelta(seconds=2),
            "name": "SessionEstablished",
            "args": {"session_id": "sess_002"},
        },
        # Missing key ratchet - violation of forward secrecy
        {
            "timestamp": base_time + timedelta(seconds=300),
            "name": "MessageSent",
            "args": {"session_id": "sess_002", "message_id": "msg_100"},
        },
    ]


@pytest.fixture
def empty_trace() -> list[dict[str, Any]]:
    """Empty trace for edge case testing."""
    return []


@pytest.fixture
def large_trace() -> list[dict[str, Any]]:
    """Large trace for performance testing."""
    base_time = datetime(2024, 1, 1, 12, 0, 0)
    events = []
    for i in range(1000):
        events.append(
            {
                "timestamp": base_time + timedelta(seconds=i),
                "name": f"Event_{i % 10}",
                "args": {"index": i, "session_id": "sess_large"},
            }
        )
    return events


# ============================================================================
# POLICY FIXTURES
# ============================================================================


@pytest.fixture
def sample_policies() -> dict[str, str]:
    """Sample MFOTL policies for testing."""
    return {
        "forward_secrecy": "□[0,∞) (SessionActive(s) → ◇[0,50] KeyRatchet(s))",
        "authentication": "∀s. SessionInit(s) → ◇[0,30] Authenticated(s)",
        "quantum_resistance": "□[0,∞) (KeyExchange(s,alg) → QuantumSafe(alg))",
        "key_freshness": "□[0,∞) (KeyUsed(k) → ¬●[0,3600] KeyUsed(k))",
        "simple": "□[0,∞) P(x)",
        "nested": "□[0,∞) (A(x) → ◇[0,10] (B(x) ∧ ◇[0,5] C(x)))",
    }


@pytest.fixture
def invalid_policies() -> list[str]:
    """Invalid policies for error handling tests."""
    return [
        "□[10,5] P(x)",  # Invalid interval (lower > upper)
        "□[0,∞) (P(x)",  # Unbalanced parentheses
        "□[0,∞) P(x) →",  # Incomplete expression
        "",  # Empty policy
    ]


# ============================================================================
# PROTOCOL FIXTURES
# ============================================================================


@pytest.fixture
def imessage_pq3_states() -> list[str]:
    """iMessage PQ3 protocol states."""
    return [
        "IDLE",
        "IKE_INIT",
        "IKE_RESPONSE",
        "IKE_COMPLETE",
        "SESSION_ESTABLISHING",
        "SESSION_ACTIVE",
        "RATCHETING",
        "SESSION_TERMINATED",
    ]


@pytest.fixture
def imessage_pq3_transitions() -> list[dict[str, str]]:
    """iMessage PQ3 protocol transitions."""
    return [
        {"from": "IDLE", "to": "IKE_INIT", "event": "InitiateSession"},
        {"from": "IKE_INIT", "to": "IKE_RESPONSE", "event": "ReceiveResponse"},
        {"from": "IKE_RESPONSE", "to": "IKE_COMPLETE", "event": "CompleteHandshake"},
        {"from": "IKE_COMPLETE", "to": "SESSION_ESTABLISHING", "event": "EstablishSession"},
        {"from": "SESSION_ESTABLISHING", "to": "SESSION_ACTIVE", "event": "SessionReady"},
        {"from": "SESSION_ACTIVE", "to": "RATCHETING", "event": "InitiateRatchet"},
        {"from": "RATCHETING", "to": "SESSION_ACTIVE", "event": "RatchetComplete"},
        {"from": "SESSION_ACTIVE", "to": "SESSION_TERMINATED", "event": "TerminateSession"},
    ]


# ============================================================================
# QUANTUM CONTEXT FIXTURES
# ============================================================================


@pytest.fixture
def current_quantum_context() -> dict[str, Any]:
    """Current (2024) quantum context."""
    return {
        "capability_profile": "current_2024",
        "data_retention_years": 10.0,
        "threat_model": "hndl",
        "expected_crqc_years": 10,
    }


@pytest.fixture
def near_term_quantum_context() -> dict[str, Any]:
    """Near-term (2030) quantum context."""
    return {
        "capability_profile": "near_term_2030",
        "data_retention_years": 15.0,
        "threat_model": "aggressive",
        "expected_crqc_years": 5,
    }


# ============================================================================
# TEMPORARY DIRECTORY FIXTURES
# ============================================================================


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test outputs."""
    temp_path = Path(tempfile.mkdtemp())
    yield temp_path
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def output_file(temp_dir):
    """Create a temporary output file path."""
    return temp_dir / "output.json"


# ============================================================================
# MOCK FIXTURES
# ============================================================================


@pytest.fixture
def mock_verification_result() -> dict[str, Any]:
    """Mock verification result."""
    return {
        "result": "SAT",
        "verification_time_ms": 45.3,
        "property": "forward_secrecy",
        "counterexample": None,
        "certificate": {"type": "proof", "steps": 12},
    }


@pytest.fixture
def mock_enforcement_decision() -> dict[str, Any]:
    """Mock enforcement decision."""
    return {
        "action": "ALLOW",
        "confidence": 0.95,
        "policy": "forward_secrecy",
        "quantum_adjusted": False,
        "quantum_risk_score": 0.15,
        "reason": "Policy satisfied",
    }


# ============================================================================
# CONFIGURATION
# ============================================================================


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "requires_z3: marks tests that require Z3 solver")
    config.addinivalue_line("markers", "requires_torch: marks tests that require PyTorch")
