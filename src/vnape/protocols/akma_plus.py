"""
AKMA+ Protocol - Enhanced 5G Authentication and Key Management for Applications.

Implementation based on:
- 3GPP TS 33.535: Authentication and Key Management for Applications (AKMA)
- Thesis Section 5.2: AKMA+ Case Study

AKMA+ Enhancements over standard AKMA:
1. Post-quantum key derivation using ML-KEM
2. Enhanced application function authentication
3. Formal verification of key hierarchy
4. Quantum-resistant key transport

Protocol Architecture:
    UE (User Equipment)
        ↓↑ AKMA Primary Authentication
    AUSF (Authentication Server Function)
        ↓↑ Key Derivation
    AAnF (AKMA Anchor Function)
        ↓↑ Application Key Generation
    AF (Application Function)

Key Hierarchy:
    KAUSF → KAKMA → KAF
    Where:
    - KAUSF: Root key from 5G-AKA
    - KAKMA: AKMA anchor key
    - KAF: Application-specific key

Security Properties:
- SP1: Key Separation (different apps get different keys)
- SP2: Key Confidentiality (keys not exposed to network)
- SP3: Mutual Authentication (UE and AF authenticated)
- SP4: Quantum Resistance (PQ KEM for key transport)
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


class AKMAState(Enum):
    """States in the AKMA+ protocol."""

    # UE States
    UE_IDLE = auto()
    UE_AUTH_INITIATED = auto()
    UE_AUTH_VERIFIED = auto()
    UE_KAKMA_DERIVED = auto()
    UE_KAF_REQUESTED = auto()
    UE_KAF_RECEIVED = auto()
    UE_SESSION_ACTIVE = auto()

    # Network States
    NET_AWAITING_AUTH = auto()
    NET_AUTH_CHALLENGE_SENT = auto()
    NET_AUTH_COMPLETE = auto()
    NET_KAKMA_STORED = auto()

    # Application States
    AF_AWAITING_KEY = auto()
    AF_KEY_RECEIVED = auto()
    AF_SESSION_READY = auto()

    # Error States
    ERROR_AUTH_FAILED = auto()
    ERROR_KEY_DERIVATION_FAILED = auto()
    ERROR_AF_UNREACHABLE = auto()
    ERROR_QUANTUM_THREAT = auto()


class AKMAEvent(Enum):
    """Events in the AKMA+ protocol."""

    # Authentication Events
    START_AUTH = auto()
    SEND_AUTH_REQUEST = auto()
    RECV_AUTH_CHALLENGE = auto()
    SEND_AUTH_RESPONSE = auto()
    RECV_AUTH_CONFIRM = auto()
    AUTH_SUCCESS = auto()
    AUTH_FAILURE = auto()

    # Key Derivation Events
    DERIVE_KAKMA = auto()
    KAKMA_DERIVED = auto()
    REQUEST_KAF = auto()
    DERIVE_KAF = auto()
    KAF_READY = auto()

    # Session Events
    START_APP_SESSION = auto()
    SESSION_ESTABLISHED = auto()
    SEND_APP_DATA = auto()
    RECV_APP_DATA = auto()
    TERMINATE_SESSION = auto()

    # Error Events
    TIMEOUT = auto()
    QUANTUM_ALERT = auto()


class AKMAPlusProtocol(BaseProtocol):
    """
    AKMA+ Enhanced 5G Authentication and Key Management Protocol.

    This implementation defines the protocol state machine,
    security policies, and safety invariants for V-NAPE enforcement.

    Key additions over standard AKMA:
    1. ML-KEM for key transport to AAnF
    2. ML-DSA for AF authentication
    3. Stronger key separation guarantees
    """

    # Protocol timing constants (seconds)
    AUTH_TIMEOUT = 10.0
    KEY_DERIVATION_TIMEOUT = 5.0
    SESSION_TIMEOUT = 3600.0  # 1 hour
    KAF_VALIDITY = 86400.0  # 24 hours

    # Key lengths (bits)
    KAUSF_LENGTH = 256
    KAKMA_LENGTH = 256
    KAF_LENGTH = 256

    def __init__(self):
        super().__init__(name="AKMA-Plus", version="5G-R18-PQ")

    def get_states(self) -> list[ProtocolState]:
        """Define all AKMA+ protocol states."""
        return [
            # UE States
            ProtocolState(
                name="UE_Idle",
                state_type=StateType.INITIAL,
                description="UE not engaged in AKMA",
                security_requirements=["usim_authenticated"],
                timeout=0,
            ),
            ProtocolState(
                name="UE_AuthInitiated",
                state_type=StateType.INTERMEDIATE,
                description="UE initiated primary authentication",
                security_requirements=["auth_vector_valid"],
                bound_variables=["supi", "auth_vector"],
                timeout=self.AUTH_TIMEOUT,
                active_primitives=[
                    CryptographicPrimitive.AES_128,
                ],
            ),
            ProtocolState(
                name="UE_AuthVerified",
                state_type=StateType.INTERMEDIATE,
                description="Primary authentication verified",
                security_requirements=["mutual_auth_complete", "kausf_derived"],
                bound_variables=["supi", "kausf"],
                timeout=self.KEY_DERIVATION_TIMEOUT,
                requires_key=True,
                active_primitives=[
                    CryptographicPrimitive.AES_256,
                    CryptographicPrimitive.SHA_256,
                ],
            ),
            ProtocolState(
                name="UE_KAKMA_Derived",
                state_type=StateType.INTERMEDIATE,
                description="KAKMA key derived at UE",
                security_requirements=["kakma_valid", "a_kid_generated"],
                bound_variables=["kakma", "a_kid"],
                timeout=self.SESSION_TIMEOUT,
                requires_key=True,
                active_primitives=[
                    CryptographicPrimitive.AES_256,
                    CryptographicPrimitive.SHA3_256,
                ],
            ),
            ProtocolState(
                name="UE_KAF_Requested",
                state_type=StateType.INTERMEDIATE,
                description="UE requested application key",
                security_requirements=["af_id_valid", "request_signed"],
                bound_variables=["kakma", "af_id", "request_nonce"],
                timeout=self.KEY_DERIVATION_TIMEOUT,
                requires_key=True,
                active_primitives=[
                    CryptographicPrimitive.ML_KEM,
                    CryptographicPrimitive.ML_DSA,
                ],
            ),
            ProtocolState(
                name="UE_KAF_Received",
                state_type=StateType.INTERMEDIATE,
                description="UE received application key",
                security_requirements=["kaf_valid", "kaf_fresh"],
                bound_variables=["kaf", "af_id", "kaf_expiry"],
                timeout=self.KAF_VALIDITY,
                requires_key=True,
                active_primitives=[
                    CryptographicPrimitive.AES_256,
                ],
            ),
            ProtocolState(
                name="UE_SessionActive",
                state_type=StateType.INTERMEDIATE,
                description="Active application session",
                security_requirements=["kaf_valid", "session_bound", "app_authenticated"],
                bound_variables=["kaf", "session_id", "af_id"],
                timeout=self.SESSION_TIMEOUT,
                requires_key=True,
                active_primitives=[
                    CryptographicPrimitive.AES_256,
                    CryptographicPrimitive.SHA3_256,
                ],
            ),
            # Network States
            ProtocolState(
                name="NET_AwaitingAuth",
                state_type=StateType.INTERMEDIATE,
                description="Network awaiting authentication request",
                security_requirements=["ausf_available", "aanf_available"],
                timeout=self.AUTH_TIMEOUT,
            ),
            ProtocolState(
                name="NET_AuthChallengeSent",
                state_type=StateType.INTERMEDIATE,
                description="Authentication challenge sent to UE",
                security_requirements=["auth_vector_generated", "challenge_fresh"],
                bound_variables=["auth_vector", "rand", "autn"],
                timeout=self.AUTH_TIMEOUT,
                active_primitives=[
                    CryptographicPrimitive.AES_128,
                ],
            ),
            ProtocolState(
                name="NET_AuthComplete",
                state_type=StateType.INTERMEDIATE,
                description="Network authentication complete",
                security_requirements=["res_verified", "kausf_stored"],
                bound_variables=["supi", "kausf"],
                timeout=self.KEY_DERIVATION_TIMEOUT,
                requires_key=True,
            ),
            ProtocolState(
                name="NET_KAKMA_Stored",
                state_type=StateType.INTERMEDIATE,
                description="KAKMA stored in AAnF",
                security_requirements=["kakma_stored", "a_kid_registered"],
                bound_variables=["kakma", "a_kid", "supi"],
                timeout=self.KAF_VALIDITY,
                requires_key=True,
                active_primitives=[
                    CryptographicPrimitive.AES_256,
                ],
            ),
            # Application Function States
            ProtocolState(
                name="AF_AwaitingKey",
                state_type=StateType.INTERMEDIATE,
                description="AF awaiting key from AAnF",
                security_requirements=["af_registered", "af_authenticated"],
                bound_variables=["af_id"],
                timeout=self.KEY_DERIVATION_TIMEOUT,
                active_primitives=[
                    CryptographicPrimitive.ML_DSA,
                ],
            ),
            ProtocolState(
                name="AF_KeyReceived",
                state_type=StateType.INTERMEDIATE,
                description="AF received application key",
                security_requirements=["kaf_valid", "key_binding_verified"],
                bound_variables=["kaf", "a_kid", "af_id"],
                timeout=self.KAF_VALIDITY,
                requires_key=True,
                active_primitives=[
                    CryptographicPrimitive.AES_256,
                ],
            ),
            ProtocolState(
                name="AF_SessionReady",
                state_type=StateType.FINAL,
                description="AF ready for application session",
                security_requirements=["kaf_valid", "ue_authenticated", "session_keys_derived"],
                bound_variables=["session_key", "af_id"],
                timeout=self.SESSION_TIMEOUT,
                requires_key=True,
            ),
            # Error States
            ProtocolState(
                name="ErrorAuthFailed",
                state_type=StateType.ERROR,
                description="Authentication failed",
                security_requirements=["auth_failure_logged"],
                timeout=0,
            ),
            ProtocolState(
                name="ErrorKeyDerivationFailed",
                state_type=StateType.ERROR,
                description="Key derivation failed",
                security_requirements=["kdf_failure_logged", "keys_destroyed"],
                timeout=0,
            ),
            ProtocolState(
                name="ErrorAFUnreachable",
                state_type=StateType.ERROR,
                description="Application function unreachable",
                security_requirements=["af_failure_logged"],
                timeout=0,
            ),
            ProtocolState(
                name="ErrorQuantumThreat",
                state_type=StateType.ERROR,
                description="Quantum threat detected",
                security_requirements=[
                    "quantum_alert_generated",
                    "session_aborted",
                    "force_pq_only",
                ],
                timeout=0,
            ),
        ]

    def get_transitions(self) -> list[ProtocolTransition]:
        """Define all AKMA+ protocol transitions."""
        return [
            # UE Authentication Flow
            ProtocolTransition(
                source="UE_Idle",
                target="UE_AuthInitiated",
                event="StartAuth",
                guard="USIM_Valid(ue)",
                actions=["generate_suci", "initiate_5g_aka"],
                produced_variables=["supi", "auth_vector"],
                crypto_operations=["ECIES_encrypt"],
                max_duration=5.0,
            ),
            ProtocolTransition(
                source="UE_AuthInitiated",
                target="UE_AuthVerified",
                event="AuthSuccess",
                guard="RES_Valid(ue) ∧ AUTN_Valid(ue)",
                required_variables=["supi", "auth_vector"],
                produced_variables=["kausf"],
                crypto_operations=["5G_AKA", "KDF"],
                max_duration=self.AUTH_TIMEOUT,
            ),
            # KAKMA Derivation
            ProtocolTransition(
                source="UE_AuthVerified",
                target="UE_KAKMA_Derived",
                event="DeriveKAKMA",
                guard="KAUSF_Valid(ue)",
                required_variables=["kausf"],
                produced_variables=["kakma", "a_kid"],
                crypto_operations=["KDF_KAKMA"],
                max_duration=self.KEY_DERIVATION_TIMEOUT,
            ),
            # KAF Request (PQ-enhanced)
            ProtocolTransition(
                source="UE_KAKMA_Derived",
                target="UE_KAF_Requested",
                event="RequestKAF",
                guard="KAKMA_Valid(ue) ∧ AF_Registered(af_id)",
                required_variables=["kakma", "a_kid"],
                produced_variables=["af_id", "request_nonce"],
                crypto_operations=["ML_KEM_encaps", "request_sign"],
                max_duration=self.KEY_DERIVATION_TIMEOUT,
            ),
            ProtocolTransition(
                source="UE_KAF_Requested",
                target="UE_KAF_Received",
                event="KAFReady",
                guard="KAF_Response_Valid(ue) ∧ ML_DSA_Verify(af_sig)",
                required_variables=["kakma", "af_id", "request_nonce"],
                produced_variables=["kaf", "kaf_expiry"],
                crypto_operations=["ML_KEM_decaps", "KDF_KAF", "ML_DSA_verify"],
                max_duration=self.KEY_DERIVATION_TIMEOUT,
            ),
            # Session Establishment
            ProtocolTransition(
                source="UE_KAF_Received",
                target="UE_SessionActive",
                event="StartAppSession",
                guard="KAF_Valid(ue) ∧ ¬KAF_Expired(ue)",
                required_variables=["kaf", "af_id"],
                produced_variables=["session_id"],
                crypto_operations=["session_key_derive"],
                max_duration=5.0,
            ),
            # Application Data Exchange (self-loops)
            ProtocolTransition(
                source="UE_SessionActive",
                target="UE_SessionActive",
                event="SendAppData",
                guard="Session_Valid(ue, s)",
                required_variables=["kaf", "session_id"],
                crypto_operations=["AES_GCM_encrypt"],
                max_duration=5.0,
            ),
            ProtocolTransition(
                source="UE_SessionActive",
                target="UE_SessionActive",
                event="RecvAppData",
                guard="Session_Valid(ue, s) ∧ MAC_Valid(msg)",
                required_variables=["kaf", "session_id"],
                crypto_operations=["AES_GCM_decrypt"],
                max_duration=5.0,
            ),
            # Network Side Transitions
            ProtocolTransition(
                source="NET_AwaitingAuth",
                target="NET_AuthChallengeSent",
                event="RecvAuthRequest",
                guard="SUCI_Valid(net, suci)",
                produced_variables=["auth_vector", "rand", "autn"],
                crypto_operations=["generate_auth_vector"],
                max_duration=self.AUTH_TIMEOUT,
            ),
            ProtocolTransition(
                source="NET_AuthChallengeSent",
                target="NET_AuthComplete",
                event="RecvAuthResponse",
                guard="RES_Matches(net, res)",
                required_variables=["auth_vector"],
                produced_variables=["supi", "kausf"],
                crypto_operations=["verify_res", "derive_kausf"],
                max_duration=self.AUTH_TIMEOUT,
            ),
            ProtocolTransition(
                source="NET_AuthComplete",
                target="NET_KAKMA_Stored",
                event="StoreKAKMA",
                guard="KAUSF_Valid(net)",
                required_variables=["kausf", "supi"],
                produced_variables=["kakma", "a_kid"],
                crypto_operations=["KDF_KAKMA", "store_aanf"],
                max_duration=self.KEY_DERIVATION_TIMEOUT,
            ),
            # AF Side Transitions
            ProtocolTransition(
                source="AF_AwaitingKey",
                target="AF_KeyReceived",
                event="RecvKAF",
                guard="ML_KEM_Valid(kaf_enc) ∧ AAnF_Authenticated(aanf)",
                required_variables=["af_id"],
                produced_variables=["kaf", "a_kid"],
                crypto_operations=["ML_KEM_decaps", "verify_aanf_sig"],
                max_duration=self.KEY_DERIVATION_TIMEOUT,
            ),
            ProtocolTransition(
                source="AF_KeyReceived",
                target="AF_SessionReady",
                event="SessionEstablished",
                guard="KAF_Valid(af) ∧ UE_Authenticated(af, ue)",
                required_variables=["kaf", "a_kid"],
                produced_variables=["session_key"],
                crypto_operations=["derive_session_key"],
                max_duration=5.0,
            ),
            # Error Transitions
            ProtocolTransition(
                source="UE_AuthInitiated",
                target="ErrorAuthFailed",
                event="AuthFailure",
                guard="¬RES_Valid(ue) ∨ ¬AUTN_Valid(ue)",
                actions=["log_auth_failure", "clear_auth_state"],
            ),
            ProtocolTransition(
                source="NET_AuthChallengeSent",
                target="ErrorAuthFailed",
                event="AuthFailure",
                guard="¬RES_Matches(net, res)",
                actions=["log_auth_failure", "alert_security"],
            ),
            ProtocolTransition(
                source="UE_KAF_Requested",
                target="ErrorKeyDerivationFailed",
                event="KDFFailure",
                guard="¬KAF_Response_Valid(ue)",
                actions=["log_kdf_failure", "destroy_kakma"],
            ),
            ProtocolTransition(
                source="UE_KAF_Requested",
                target="ErrorAFUnreachable",
                event="Timeout",
                guard=f"ElapsedTime(ue) > {self.KEY_DERIVATION_TIMEOUT}",
                actions=["log_af_timeout"],
            ),
            ProtocolTransition(
                source="UE_SessionActive",
                target="ErrorQuantumThreat",
                event="QuantumAlert",
                guard="QuantumThreatDetected(ue)",
                actions=["alert_quantum", "terminate_session", "force_pq_rekey"],
            ),
        ]

    def get_base_policies(self) -> list[str]:
        """
        Define base MFOTL security policies for AKMA+.

        These policies encode the security requirements:
        - P1: Key Separation
        - P2: Key Confidentiality
        - P3: Mutual Authentication
        - P4: Key Freshness
        - P5: Quantum Resistance
        """
        return [
            # P1: Key Separation - Different AFs get different keys
            "□[0,∞) (∀af1, af2. af1 ≠ af2 → KAF(ue, af1) ≠ KAF(ue, af2))",
            # P2: Key Confidentiality - Keys never transmitted in clear
            "□[0,∞) (KAF_Derived(ue, kaf) → ¬KeyTransmittedClear(kaf))",
            # P3: Mutual Authentication - Both parties authenticated
            "□[0,∞) (UE_SessionActive(ue) → "
            "◆[0,∞) (UE_Authenticated(ue) ∧ AF_Authenticated(af)))",
            # P4: Key Freshness - Keys derived recently
            f"□[0,∞) (UE_SessionActive(ue) → " f"◆[0,{self.KAF_VALIDITY}] KAF_Derived(ue, kaf))",
            # P5: Quantum Resistance - PQ primitives used for key transport
            "□[0,∞) (KAF_Requested(ue) → ML_KEM_Used(ue))",
            # P6: A-KID Uniqueness - Each session has unique A-KID
            "□[0,∞) (∀s1, s2. s1 ≠ s2 ∧ A_KID(s1, kid) → ¬A_KID(s2, kid))",
            # P7: KAKMA Lifetime - KAKMA must not exceed KAUSF lifetime
            "□[0,∞) (KAKMA_Derived(ue) → ◆[0,0] KAUSF_Valid(ue))",
            # P8: AF Authorization - AF must be pre-registered
            "□[0,∞) (KAF_Request(ue, af_id) → AF_Registered(af_id))",
        ]

    def get_safety_invariants(self) -> list[str]:
        """
        Define safety invariants that must always hold.

        Violations indicate critical security failures.
        """
        return [
            # SI1: Never use classical-only key transport for KAF
            "□[0,∞) ¬(KAF_Derived(ue) ∧ ¬ML_KEM_Used(ue))",
            # SI2: Never have session without authenticated AF
            "□[0,∞) ¬(UE_SessionActive(ue) ∧ ¬AF_Authenticated(af))",
            # SI3: Never reuse A-KID
            "□[0,∞) ¬(∃s1, s2. s1 ≠ s2 ∧ A_KID(s1, kid) ∧ A_KID(s2, kid))",
            # SI4: Never derive KAF without valid KAKMA
            "□[0,∞) ¬(KAF_Derived(ue) ∧ ¬KAKMA_Valid(ue))",
            # SI5: Never continue after authentication failure
            "□[0,∞) (ErrorAuthFailed(ue) → □[0,∞) ¬UE_SessionActive(ue))",
            # SI6: AAnF must verify AF before sending KAF
            "□[0,∞) (KAF_Sent(aanf, af) → ◆[0,0] AF_Verified(aanf, af))",
        ]

    def get_cryptographic_primitives(self) -> list[CryptographicPrimitive]:
        """Return cryptographic primitives used by AKMA+."""
        return [
            # Primary Authentication (5G-AKA base)
            CryptographicPrimitive.AES_128,  # MILENAGE functions
            # Key Derivation
            CryptographicPrimitive.SHA_256,  # Base KDF
            CryptographicPrimitive.SHA3_256,  # Enhanced KDF
            CryptographicPrimitive.AES_256,  # Key encryption
            # Post-Quantum Enhancements
            CryptographicPrimitive.ML_KEM,  # Key transport
            CryptographicPrimitive.ML_DSA,  # AF authentication
        ]

    def get_key_hierarchy_policy(self) -> str:
        """
        Generate policy enforcing proper key hierarchy.

        Returns MFOTL formula ensuring:
        KAUSF → KAKMA → KAF derivation order
        """
        return (
            "□[0,∞) ("
            "(KAKMA_Derived(ue) → ◆[0,0] KAUSF_Valid(ue)) ∧ "
            "(KAF_Derived(ue, af) → ◆[0,0] KAKMA_Valid(ue))"
            ")"
        )

    def get_af_authorization_policy(self, allowed_afs: list[str] = None) -> str:
        """
        Generate policy restricting KAF derivation to authorized AFs.

        Args:
            allowed_afs: List of allowed AF identifiers

        Returns:
            MFOTL formula restricting AF access
        """
        if allowed_afs:
            af_list = " ∨ ".join(f'af_id = "{af}"' for af in allowed_afs)
            return f"□[0,∞) (KAF_Request(ue, af_id) → ({af_list}))"
        return "□[0,∞) (KAF_Request(ue, af_id) → AF_Registered(af_id))"

    def get_lifetime_policy(self, kakma_lifetime: float = None, kaf_lifetime: float = None) -> str:
        """
        Generate key lifetime enforcement policy.

        Args:
            kakma_lifetime: KAKMA validity period in seconds
            kaf_lifetime: KAF validity period in seconds

        Returns:
            MFOTL formula enforcing key lifetimes
        """
        kakma_t = kakma_lifetime or self.KAF_VALIDITY
        kaf_t = kaf_lifetime or self.KAF_VALIDITY

        return (
            f"□[0,∞) ("
            f"(KAKMA_Valid(ue) → ◇[0,{kakma_t}] (¬KAKMA_Valid(ue) ∨ KAKMA_Refreshed(ue))) ∧ "
            f"(KAF_Valid(ue, af) → ◇[0,{kaf_t}] (¬KAF_Valid(ue, af) ∨ KAF_Refreshed(ue, af)))"
            f")"
        )
