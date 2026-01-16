"""
iMessage PQ3 Protocol - Apple's Post-Quantum Secure Messaging Protocol.

Implementation based on:
- Apple Security Research Blog: "iMessage with PQ3" (2024)
- Thesis Section 5.1: iMessage PQ3 Case Study

PQ3 Features:
1. Hybrid post-quantum key exchange (X25519 + ML-KEM-768)
2. Periodic key ratcheting for post-compromise security
3. Post-quantum authentication via ML-DSA signatures
4. Backward secrecy through ratcheting

Protocol Flow:
1. Initial Key Exchange (IKE) - Establishes shared secrets
2. Session Establishment - Creates session keys from IKE material
3. Message Exchange - Encrypted with session keys
4. Key Ratcheting - Periodic re-keying for forward secrecy
5. Session Termination - Clean key destruction

Security Properties:
- SP1: Forward Secrecy (future key compromise doesn't reveal past messages)
- SP2: Post-Compromise Security (automatic recovery from key compromise)
- SP3: Quantum Resistance (secure against quantum adversaries)
- SP4: Backward Secrecy (past key compromise doesn't reveal future messages)
"""

from __future__ import annotations

from enum import Enum, auto

from vnape.pqae.quantum_context import CryptographicPrimitive
from vnape.protocols.base import (
    BaseProtocol,
    ProtocolState,
    ProtocolTransition,
    StateType,
)


class PQ3State(Enum):
    """States in the iMessage PQ3 protocol."""

    IDLE = auto()  # No active session
    IKE_INIT = auto()  # Initial key exchange initiated
    IKE_RESPONSE = auto()  # Waiting for IKE response
    IKE_COMPLETE = auto()  # IKE completed
    SESSION_ESTABLISHING = auto()  # Session establishment in progress
    SESSION_ACTIVE = auto()  # Active session, can exchange messages
    RATCHETING = auto()  # Key ratcheting in progress
    RATCHET_COMPLETE = auto()  # Ratchet completed
    SESSION_TERMINATING = auto()  # Session termination in progress
    SESSION_TERMINATED = auto()  # Session cleanly terminated
    ERROR_KEY_MISMATCH = auto()  # Key verification failed
    ERROR_TIMEOUT = auto()  # Protocol timeout
    ERROR_QUANTUM_THREAT = auto()  # Quantum threat detected


class PQ3Event(Enum):
    """Events in the iMessage PQ3 protocol."""

    START_SESSION = auto()
    SEND_IKE_INIT = auto()
    RECV_IKE_RESPONSE = auto()
    VERIFY_IKE = auto()
    ESTABLISH_SESSION = auto()
    SESSION_READY = auto()
    SEND_MESSAGE = auto()
    RECV_MESSAGE = auto()
    TRIGGER_RATCHET = auto()
    RATCHET_COMPLETE = auto()
    TERMINATE_SESSION = auto()
    SESSION_ENDED = auto()
    KEY_MISMATCH = auto()
    TIMEOUT = auto()
    QUANTUM_ALERT = auto()


class IMessagePQ3Protocol(BaseProtocol):
    """
    iMessage PQ3 Post-Quantum Secure Messaging Protocol.

    This implementation defines the protocol state machine,
    security policies, and safety invariants for V-NAPE enforcement.
    """

    # Protocol timing constants (seconds)
    IKE_TIMEOUT = 30.0
    SESSION_TIMEOUT = 300.0
    RATCHET_INTERVAL = 50.0  # Ratchet every ~50 messages
    MESSAGE_TIMEOUT = 5.0

    def __init__(self):
        super().__init__(name="iMessage-PQ3", version="1.0-pq3")

    def get_states(self) -> list[ProtocolState]:
        """Define all PQ3 protocol states."""
        return [
            ProtocolState(
                name="Idle",
                state_type=StateType.INITIAL,
                description="No active session, awaiting session initiation",
                security_requirements=["device_authenticated"],
                timeout=0,
            ),
            ProtocolState(
                name="IKE_Init",
                state_type=StateType.INTERMEDIATE,
                description="Initial key exchange initiated, sent ephemeral keys",
                security_requirements=["device_authenticated", "ephemeral_key_generated"],
                bound_variables=["ek_x25519", "ek_mlkem"],
                timeout=self.IKE_TIMEOUT,
                requires_key=True,
                active_primitives=[
                    CryptographicPrimitive.ECDH,
                    CryptographicPrimitive.ML_KEM,
                ],
            ),
            ProtocolState(
                name="IKE_Response",
                state_type=StateType.INTERMEDIATE,
                description="Received IKE response, verifying peer keys",
                security_requirements=["peer_key_received", "signature_valid"],
                bound_variables=["ek_x25519", "ek_mlkem", "peer_ek_x25519", "peer_ek_mlkem"],
                timeout=self.IKE_TIMEOUT,
                requires_key=True,
                active_primitives=[
                    CryptographicPrimitive.ECDH,
                    CryptographicPrimitive.ML_KEM,
                    CryptographicPrimitive.ML_DSA,
                ],
            ),
            ProtocolState(
                name="IKE_Complete",
                state_type=StateType.INTERMEDIATE,
                description="IKE completed, shared secrets established",
                security_requirements=["shared_secret_computed", "keys_verified"],
                bound_variables=["shared_secret", "ek_x25519", "ek_mlkem"],
                timeout=self.SESSION_TIMEOUT,
                requires_key=True,
                active_primitives=[
                    CryptographicPrimitive.AES_256,
                ],
            ),
            ProtocolState(
                name="SessionEstablishing",
                state_type=StateType.INTERMEDIATE,
                description="Deriving session keys from shared secrets",
                security_requirements=["shared_secret_computed", "kdf_executed"],
                bound_variables=["session_key", "mac_key"],
                timeout=self.SESSION_TIMEOUT,
                requires_key=True,
                active_primitives=[
                    CryptographicPrimitive.AES_256,
                    CryptographicPrimitive.SHA3_256,
                ],
            ),
            ProtocolState(
                name="SessionActive",
                state_type=StateType.INTERMEDIATE,
                description="Active session, can exchange encrypted messages",
                security_requirements=[
                    "session_key_valid",
                    "forward_secrecy",
                    "quantum_resistance",
                ],
                bound_variables=["session_key", "mac_key", "message_counter"],
                timeout=self.SESSION_TIMEOUT,
                requires_key=True,
                active_primitives=[
                    CryptographicPrimitive.AES_256,
                    CryptographicPrimitive.SHA3_256,
                ],
            ),
            ProtocolState(
                name="Ratcheting",
                state_type=StateType.INTERMEDIATE,
                description="Performing key ratchet for post-compromise security",
                security_requirements=[
                    "old_key_destroyed",
                    "new_key_generated",
                    "backward_secrecy",
                ],
                bound_variables=["old_session_key", "new_session_key", "ratchet_count"],
                timeout=self.MESSAGE_TIMEOUT,
                requires_key=True,
                active_primitives=[
                    CryptographicPrimitive.ML_KEM,
                    CryptographicPrimitive.SHA3_256,
                ],
            ),
            ProtocolState(
                name="RatchetComplete",
                state_type=StateType.INTERMEDIATE,
                description="Ratchet completed, old keys destroyed",
                security_requirements=[
                    "new_key_active",
                    "old_key_destroyed",
                    "post_compromise_security",
                ],
                bound_variables=["session_key", "mac_key", "ratchet_count"],
                timeout=self.SESSION_TIMEOUT,
                requires_key=True,
                active_primitives=[
                    CryptographicPrimitive.AES_256,
                    CryptographicPrimitive.SHA3_256,
                ],
            ),
            ProtocolState(
                name="SessionTerminating",
                state_type=StateType.INTERMEDIATE,
                description="Terminating session, destroying key material",
                security_requirements=["termination_signal_sent"],
                bound_variables=["session_key"],
                timeout=self.MESSAGE_TIMEOUT,
                requires_key=True,
                active_primitives=[],
            ),
            ProtocolState(
                name="SessionTerminated",
                state_type=StateType.FINAL,
                description="Session cleanly terminated, all keys destroyed",
                security_requirements=["all_keys_destroyed", "session_logged"],
                timeout=0,
            ),
            ProtocolState(
                name="ErrorKeyMismatch",
                state_type=StateType.ERROR,
                description="Key verification failed - potential MITM",
                security_requirements=["alert_generated", "session_aborted"],
                timeout=0,
            ),
            ProtocolState(
                name="ErrorTimeout",
                state_type=StateType.ERROR,
                description="Protocol timeout - peer unresponsive",
                security_requirements=["keys_destroyed", "session_aborted"],
                timeout=0,
            ),
            ProtocolState(
                name="ErrorQuantumThreat",
                state_type=StateType.ERROR,
                description="Quantum threat detected - elevated security required",
                security_requirements=[
                    "quantum_alert_generated",
                    "session_aborted",
                    "force_pq_only",
                ],
                timeout=0,
            ),
        ]

    def get_transitions(self) -> list[ProtocolTransition]:
        """Define all PQ3 protocol transitions."""
        return [
            # Session initiation
            ProtocolTransition(
                source="Idle",
                target="IKE_Init",
                event="StartSession",
                guard="DeviceAuthenticated(s)",
                actions=["generate_ephemeral_x25519", "generate_ephemeral_mlkem"],
                produced_variables=["ek_x25519", "ek_mlkem"],
                crypto_operations=["X25519_keygen", "ML_KEM_keygen"],
                max_duration=5.0,
            ),
            # IKE flow
            ProtocolTransition(
                source="IKE_Init",
                target="IKE_Response",
                event="RecvIKEResponse",
                guard="ValidSignature(s, peer_sig)",
                required_variables=["ek_x25519", "ek_mlkem"],
                produced_variables=["peer_ek_x25519", "peer_ek_mlkem"],
                crypto_operations=["ML_DSA_verify"],
                max_duration=self.IKE_TIMEOUT,
            ),
            ProtocolTransition(
                source="IKE_Response",
                target="IKE_Complete",
                event="VerifyIKE",
                guard="KeysMatch(s) ∧ SignatureValid(s)",
                required_variables=["ek_x25519", "ek_mlkem", "peer_ek_x25519", "peer_ek_mlkem"],
                produced_variables=["shared_secret"],
                crypto_operations=["X25519_dh", "ML_KEM_decaps", "KDF"],
                max_duration=5.0,
            ),
            # Session establishment
            ProtocolTransition(
                source="IKE_Complete",
                target="SessionEstablishing",
                event="EstablishSession",
                required_variables=["shared_secret"],
                produced_variables=["session_key", "mac_key"],
                crypto_operations=["HKDF_expand"],
                max_duration=5.0,
            ),
            ProtocolTransition(
                source="SessionEstablishing",
                target="SessionActive",
                event="SessionReady",
                required_variables=["session_key", "mac_key"],
                produced_variables=["message_counter"],
                max_duration=5.0,
            ),
            # Message exchange (self-loop on SessionActive)
            ProtocolTransition(
                source="SessionActive",
                target="SessionActive",
                event="SendMessage",
                guard="MessageCounter(s, n) ∧ n < ratchet_threshold",
                required_variables=["session_key", "mac_key", "message_counter"],
                crypto_operations=["AES_GCM_encrypt"],
                max_duration=self.MESSAGE_TIMEOUT,
            ),
            ProtocolTransition(
                source="SessionActive",
                target="SessionActive",
                event="RecvMessage",
                guard="ValidMAC(s, msg) ∧ ValidSequence(s, seq)",
                required_variables=["session_key", "mac_key"],
                crypto_operations=["AES_GCM_decrypt", "MAC_verify"],
                max_duration=self.MESSAGE_TIMEOUT,
            ),
            # Key ratcheting
            ProtocolTransition(
                source="SessionActive",
                target="Ratcheting",
                event="TriggerRatchet",
                guard="MessageCounter(s, n) ∧ n >= ratchet_threshold",
                required_variables=["session_key", "message_counter"],
                produced_variables=["old_session_key", "new_session_key"],
                crypto_operations=["ML_KEM_encaps", "HKDF"],
                max_duration=10.0,
            ),
            ProtocolTransition(
                source="Ratcheting",
                target="RatchetComplete",
                event="RatchetComplete",
                guard="NewKeyActive(s) ∧ OldKeyDestroyed(s)",
                required_variables=["new_session_key"],
                produced_variables=["ratchet_count"],
                actions=["destroy_old_key", "reset_message_counter"],
                max_duration=5.0,
            ),
            ProtocolTransition(
                source="RatchetComplete",
                target="SessionActive",
                event="ResumeSession",
                required_variables=["session_key", "ratchet_count"],
                max_duration=5.0,
            ),
            # Session termination
            ProtocolTransition(
                source="SessionActive",
                target="SessionTerminating",
                event="TerminateSession",
                required_variables=["session_key"],
                actions=["send_termination_signal"],
                max_duration=5.0,
            ),
            ProtocolTransition(
                source="RatchetComplete",
                target="SessionTerminating",
                event="TerminateSession",
                required_variables=["session_key"],
                actions=["send_termination_signal"],
                max_duration=5.0,
            ),
            ProtocolTransition(
                source="SessionTerminating",
                target="SessionTerminated",
                event="SessionEnded",
                actions=["destroy_all_keys", "log_session"],
                max_duration=5.0,
            ),
            # Error transitions
            ProtocolTransition(
                source="IKE_Response",
                target="ErrorKeyMismatch",
                event="KeyMismatch",
                guard="¬KeysMatch(s) ∨ ¬SignatureValid(s)",
                actions=["alert_mitm", "destroy_keys", "abort_session"],
            ),
            ProtocolTransition(
                source="IKE_Init",
                target="ErrorTimeout",
                event="Timeout",
                guard=f"ElapsedTime(s) > {self.IKE_TIMEOUT}",
                actions=["destroy_keys", "abort_session"],
            ),
            ProtocolTransition(
                source="IKE_Response",
                target="ErrorTimeout",
                event="Timeout",
                guard=f"ElapsedTime(s) > {self.IKE_TIMEOUT}",
                actions=["destroy_keys", "abort_session"],
            ),
            ProtocolTransition(
                source="SessionActive",
                target="ErrorQuantumThreat",
                event="QuantumAlert",
                guard="QuantumThreatDetected(s)",
                actions=["alert_quantum", "force_renegotiation", "abort_session"],
            ),
        ]

    def get_base_policies(self) -> list[str]:
        """
        Define base MFOTL security policies for PQ3.

        These policies encode the security requirements from the thesis:
        - P1: Forward Secrecy
        - P2: Post-Compromise Security
        - P3: Key Freshness
        - P4: Authentication
        - P5: Quantum Resistance
        """
        return [
            # P1: Forward Secrecy - Session keys cannot be derived from long-term keys alone
            "□[0,∞) (SessionActive(s) → ◇[0,0] EphemeralKeyUsed(s))",
            # P2: Post-Compromise Security - Regular ratcheting ensures recovery
            f"□[0,∞) (SessionActive(s) ∧ MessageCounter(s, n) ∧ n >= {int(self.RATCHET_INTERVAL)} → "
            f"◇[0,10] Ratcheting(s))",
            # P3: Key Freshness - Keys must be periodically refreshed
            f"□[0,∞) (SessionActive(s) → ◇[0,{self.RATCHET_INTERVAL * 2}] "
            f"(RatchetComplete(s) ∨ SessionTerminated(s)))",
            # P4: Authentication - All messages must come from authenticated peers
            "□[0,∞) (RecvMessage(s, m) → ◆[0,∞) (ValidMAC(s, m) ∧ ValidSignature(s, peer)))",
            # P5: Quantum Resistance - PQ primitives must be used throughout
            "□[0,∞) (IKE_Init(s) → ML_KEM_Used(s) ∧ ML_DSA_Used(s))",
            # P6: Key Destruction - Old keys must be destroyed after ratcheting
            "□[0,∞) (RatchetComplete(s) → ◆[0,0] OldKeyDestroyed(s))",
            # P7: Session Integrity - Session cannot be hijacked
            "□[0,∞) (SessionActive(s) → ¬∃s'. s ≠ s' ∧ SessionActive(s') ∧ SameSessionId(s, s'))",
            # P8: Termination Guarantee - Sessions eventually terminate
            "□[0,∞) (SessionActive(s) → ◇[0,3600] (SessionTerminated(s) ∨ ErrorState(s)))",
        ]

    def get_safety_invariants(self) -> list[str]:
        """
        Define safety invariants that must always hold.

        These are stronger than policies - violation indicates critical failure.
        """
        return [
            # SI1: Never use classical-only key exchange in active session
            "□[0,∞) ¬(SessionActive(s) ∧ ¬ML_KEM_Used(s))",
            # SI2: Never have session without authentication
            "□[0,∞) ¬(SessionActive(s) ∧ ¬PeerAuthenticated(s))",
            # SI3: Never have multiple active sessions with same ID
            "□[0,∞) ¬(∃s1, s2. s1 ≠ s2 ∧ SessionActive(s1) ∧ SessionActive(s2) ∧ "
            "SameSessionId(s1, s2))",
            # SI4: Never skip IKE phase
            "□[0,∞) ¬(SessionActive(s) ∧ ¬◆[0,∞) IKE_Complete(s))",
            # SI5: Never continue after quantum threat detection
            "□[0,∞) (ErrorQuantumThreat(s) → □[0,∞) ¬SessionActive(s))",
        ]

    def get_cryptographic_primitives(self) -> list[CryptographicPrimitive]:
        """Return cryptographic primitives used by PQ3."""
        return [
            # Key Exchange
            CryptographicPrimitive.X25519_ML_KEM,  # Hybrid KEM
            CryptographicPrimitive.ECDH,  # X25519 classical
            CryptographicPrimitive.ML_KEM,  # Post-quantum KEM
            # Signatures
            CryptographicPrimitive.ML_DSA,  # Post-quantum signatures
            # Symmetric
            CryptographicPrimitive.AES_256,  # Encryption
            CryptographicPrimitive.SHA3_256,  # Hashing/KDF
        ]

    def get_ratchet_policy(self, threshold: int = 50) -> str:
        """
        Generate a customized ratchet policy with specific threshold.

        Args:
            threshold: Number of messages before ratchet is required

        Returns:
            MFOTL formula enforcing ratcheting policy
        """
        return (
            f"□[0,∞) (SessionActive(s) ∧ MessageCounter(s, n) ∧ n >= {threshold} → "
            f"◇[0,10] Ratcheting(s))"
        )

    def get_timing_policy(self, ike_timeout: float = None, session_timeout: float = None) -> str:
        """
        Generate customized timing policies.

        Args:
            ike_timeout: IKE phase timeout in seconds
            session_timeout: Session timeout in seconds

        Returns:
            MFOTL formula enforcing timing constraints
        """
        ike_t = ike_timeout or self.IKE_TIMEOUT
        session_t = session_timeout or self.SESSION_TIMEOUT

        return (
            f"□[0,∞) (IKE_Init(s) → ◇[0,{ike_t}] (IKE_Complete(s) ∨ ErrorState(s))) ∧ "
            f"□[0,∞) (SessionActive(s) → ◇[0,{session_t}] (SessionTerminated(s) ∨ Ratcheting(s)))"
        )
