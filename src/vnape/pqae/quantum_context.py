"""
Quantum Threat Context - Contextual information for quantum-aware enforcement.

This module provides:
1. Quantum capability assessment (what quantum computers can currently do)
2. Threat level classification based on cryptographic primitives
3. Risk scoring for protocols under quantum attack scenarios
4. Proactive migration recommendations

Based on Thesis Section 4.3.2: Quantum-Aware Enforcement Strategies

Quantum Threat Model:
- HARVEST_NOW_DECRYPT_LATER: Current data captured for future quantum decryption
- QUANTUM_KEY_RECOVERY: Direct quantum attack on key exchange
- QUANTUM_SIGNATURE_FORGERY: Quantum attack on digital signatures
- QUANTUM_RNG_PREDICTION: Quantum-enhanced random number prediction
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any


class QuantumRiskLevel(Enum):
    """Risk level classification for quantum threats."""

    CRITICAL = auto()  # Immediate action required
    HIGH = auto()  # Urgent migration recommended
    MEDIUM = auto()  # Plan for migration
    LOW = auto()  # Monitor developments
    MINIMAL = auto()  # No immediate concern


class QuantumThreatType(Enum):
    """Types of quantum threats to cryptographic protocols."""

    HARVEST_NOW_DECRYPT_LATER = auto()  # Data harvesting for future decryption
    KEY_RECOVERY = auto()  # Direct attack on key exchange
    SIGNATURE_FORGERY = auto()  # Attack on digital signatures
    RNG_PREDICTION = auto()  # Quantum-enhanced RNG prediction
    ALGORITHM_BREAK = auto()  # Complete algorithm compromise
    SIDE_CHANNEL_ENHANCED = auto()  # Quantum-enhanced side channel attacks


class CryptographicPrimitive(Enum):
    """Cryptographic primitives and their quantum vulnerability."""

    # Asymmetric - Vulnerable to Shor's algorithm
    RSA = auto()
    DSA = auto()
    ECDSA = auto()
    ECDH = auto()
    DH = auto()
    ELGAMAL = auto()

    # Post-Quantum Key Encapsulation
    ML_KEM = auto()  # NIST FIPS 203 (Kyber)
    BIKE = auto()
    HQC = auto()
    FRODOKEM = auto()
    NTRU = auto()
    SIKE = auto()  # Broken, for historical reference

    # Post-Quantum Signatures
    ML_DSA = auto()  # NIST FIPS 204 (Dilithium)
    SLH_DSA = auto()  # NIST FIPS 205 (SPHINCS+)
    FALCON = auto()

    # Symmetric - Grover's algorithm impact (halved security)
    AES_128 = auto()
    AES_256 = auto()
    CHACHA20 = auto()
    SHA_256 = auto()
    SHA_384 = auto()
    SHA3_256 = auto()

    # Hybrid schemes
    X25519_ML_KEM = auto()  # ECDH + ML-KEM hybrid
    RSA_ML_KEM = auto()  # RSA + ML-KEM hybrid


@dataclass
class QuantumCapability:
    """
    Current quantum computing capability assessment.
    Based on publicly available information about quantum hardware.
    """

    # Logical qubits available (error-corrected)
    logical_qubits: int = 0

    # Physical qubits available (raw)
    physical_qubits: int = 1000

    # Estimated gate fidelity (0-1)
    gate_fidelity: float = 0.99

    # Coherence time in microseconds
    coherence_time_us: float = 100.0

    # Estimated years until cryptographically-relevant quantum computer (CRQC)
    years_to_crqc: float = 10.0

    # Assessment date
    assessment_date: datetime = field(default_factory=datetime.now)

    # Source of assessment
    source: str = "default_estimate"

    def can_break_rsa(self, key_size: int) -> bool:
        """Estimate if current capability can break RSA of given key size."""
        # Shor's algorithm needs ~2n logical qubits for n-bit RSA
        required_qubits = 2 * key_size
        return self.logical_qubits >= required_qubits

    def can_break_ecc(self, curve_bits: int) -> bool:
        """Estimate if current capability can break ECC of given curve size."""
        # Shor's algorithm needs ~2n logical qubits for n-bit ECC
        required_qubits = 2 * curve_bits
        return self.logical_qubits >= required_qubits

    def grover_speedup_bits(self) -> int:
        """Calculate effective security reduction from Grover's algorithm."""
        # Grover provides quadratic speedup, halving effective key size
        # But needs sufficient qubits and gate operations
        if self.logical_qubits < 128:
            return 0
        return min(64, self.logical_qubits // 2)  # Conservative estimate

    def effective_symmetric_security(self, nominal_bits: int) -> int:
        """Calculate effective symmetric key security accounting for Grover."""
        reduction = self.grover_speedup_bits()
        return max(64, nominal_bits - reduction)


# Pre-defined quantum capability profiles
QUANTUM_CAPABILITIES = {
    "current_2024": QuantumCapability(
        logical_qubits=0,
        physical_qubits=1000,
        gate_fidelity=0.995,
        coherence_time_us=100,
        years_to_crqc=10,
        source="NIST PQC Assessment 2024",
    ),
    "near_term_2030": QuantumCapability(
        logical_qubits=50,
        physical_qubits=10000,
        gate_fidelity=0.999,
        coherence_time_us=1000,
        years_to_crqc=5,
        source="Projected near-term advancement",
    ),
    "crqc_ready": QuantumCapability(
        logical_qubits=4000,
        physical_qubits=1000000,
        gate_fidelity=0.9999,
        coherence_time_us=100000,
        years_to_crqc=0,
        source="Hypothetical CRQC",
    ),
}


@dataclass
class PrimitiveVulnerability:
    """Vulnerability assessment for a cryptographic primitive."""

    primitive: CryptographicPrimitive
    quantum_vulnerable: bool
    attack_type: QuantumThreatType
    current_security_bits: int
    post_quantum_security_bits: int  # After quantum attacks
    migration_urgency: QuantumRiskLevel
    recommended_replacement: CryptographicPrimitive | None = None
    notes: str = ""


# Vulnerability database for common primitives
PRIMITIVE_VULNERABILITIES: dict[CryptographicPrimitive, PrimitiveVulnerability] = {
    # RSA family - Fully vulnerable to Shor
    CryptographicPrimitive.RSA: PrimitiveVulnerability(
        primitive=CryptographicPrimitive.RSA,
        quantum_vulnerable=True,
        attack_type=QuantumThreatType.KEY_RECOVERY,
        current_security_bits=112,  # RSA-2048
        post_quantum_security_bits=0,
        migration_urgency=QuantumRiskLevel.HIGH,
        recommended_replacement=CryptographicPrimitive.ML_KEM,
        notes="Vulnerable to Shor's algorithm; migrate to ML-KEM/ML-DSA",
    ),
    # ECC family - Fully vulnerable to Shor
    CryptographicPrimitive.ECDH: PrimitiveVulnerability(
        primitive=CryptographicPrimitive.ECDH,
        quantum_vulnerable=True,
        attack_type=QuantumThreatType.KEY_RECOVERY,
        current_security_bits=128,  # P-256
        post_quantum_security_bits=0,
        migration_urgency=QuantumRiskLevel.HIGH,
        recommended_replacement=CryptographicPrimitive.ML_KEM,
        notes="Vulnerable to Shor's algorithm",
    ),
    CryptographicPrimitive.ECDSA: PrimitiveVulnerability(
        primitive=CryptographicPrimitive.ECDSA,
        quantum_vulnerable=True,
        attack_type=QuantumThreatType.SIGNATURE_FORGERY,
        current_security_bits=128,
        post_quantum_security_bits=0,
        migration_urgency=QuantumRiskLevel.HIGH,
        recommended_replacement=CryptographicPrimitive.ML_DSA,
        notes="Vulnerable to Shor's algorithm",
    ),
    # Post-Quantum KEMs - Secure
    CryptographicPrimitive.ML_KEM: PrimitiveVulnerability(
        primitive=CryptographicPrimitive.ML_KEM,
        quantum_vulnerable=False,
        attack_type=QuantumThreatType.ALGORITHM_BREAK,
        current_security_bits=192,  # ML-KEM-768
        post_quantum_security_bits=192,
        migration_urgency=QuantumRiskLevel.MINIMAL,
        notes="NIST FIPS 203 standardized; based on Module-LWE",
    ),
    # Post-Quantum Signatures - Secure
    CryptographicPrimitive.ML_DSA: PrimitiveVulnerability(
        primitive=CryptographicPrimitive.ML_DSA,
        quantum_vulnerable=False,
        attack_type=QuantumThreatType.SIGNATURE_FORGERY,
        current_security_bits=192,  # ML-DSA-65
        post_quantum_security_bits=192,
        migration_urgency=QuantumRiskLevel.MINIMAL,
        notes="NIST FIPS 204 standardized; based on Module-LWE",
    ),
    CryptographicPrimitive.SLH_DSA: PrimitiveVulnerability(
        primitive=CryptographicPrimitive.SLH_DSA,
        quantum_vulnerable=False,
        attack_type=QuantumThreatType.SIGNATURE_FORGERY,
        current_security_bits=192,
        post_quantum_security_bits=192,
        migration_urgency=QuantumRiskLevel.MINIMAL,
        notes="NIST FIPS 205 standardized; hash-based signatures",
    ),
    # Symmetric - Partially affected by Grover
    CryptographicPrimitive.AES_128: PrimitiveVulnerability(
        primitive=CryptographicPrimitive.AES_128,
        quantum_vulnerable=True,
        attack_type=QuantumThreatType.ALGORITHM_BREAK,
        current_security_bits=128,
        post_quantum_security_bits=64,  # Grover halves security
        migration_urgency=QuantumRiskLevel.MEDIUM,
        recommended_replacement=CryptographicPrimitive.AES_256,
        notes="Grover's algorithm halves effective security; use AES-256",
    ),
    CryptographicPrimitive.AES_256: PrimitiveVulnerability(
        primitive=CryptographicPrimitive.AES_256,
        quantum_vulnerable=True,
        attack_type=QuantumThreatType.ALGORITHM_BREAK,
        current_security_bits=256,
        post_quantum_security_bits=128,  # Grover halves security
        migration_urgency=QuantumRiskLevel.LOW,
        notes="128-bit post-quantum security is sufficient",
    ),
    # Hybrid schemes - Best of both worlds
    CryptographicPrimitive.X25519_ML_KEM: PrimitiveVulnerability(
        primitive=CryptographicPrimitive.X25519_ML_KEM,
        quantum_vulnerable=False,
        attack_type=QuantumThreatType.KEY_RECOVERY,
        current_security_bits=256,
        post_quantum_security_bits=192,
        migration_urgency=QuantumRiskLevel.MINIMAL,
        notes="Hybrid scheme; secure if either component remains secure",
    ),
}


@dataclass
class ThreatAssessment:
    """
    Complete threat assessment for a protocol or system.
    """

    # Overall risk level
    overall_risk: QuantumRiskLevel

    # Individual primitive assessments
    primitive_risks: dict[CryptographicPrimitive, QuantumRiskLevel] = field(default_factory=dict)

    # Identified vulnerabilities
    vulnerabilities: list[PrimitiveVulnerability] = field(default_factory=list)

    # Estimated time until risk becomes critical
    time_to_critical: timedelta = field(default_factory=lambda: timedelta(days=3650))

    # Data sensitivity classification
    data_retention_years: float = 10.0

    # Harvest-now-decrypt-later risk score (0-100)
    hndl_risk_score: float = 0.0

    # Recommended actions
    recommendations: list[str] = field(default_factory=list)

    # Compliance requirements affected
    compliance_impacts: list[str] = field(default_factory=list)

    # Assessment metadata
    assessment_timestamp: datetime = field(default_factory=datetime.now)
    quantum_capability_assumed: str = "current_2024"

    def get_worst_primitive_risk(self) -> QuantumRiskLevel:
        """Get the highest risk level among all primitives."""
        if not self.primitive_risks:
            return QuantumRiskLevel.MINIMAL
        return min(self.primitive_risks.values(), key=lambda x: x.value)

    def needs_immediate_action(self) -> bool:
        """Check if immediate action is required."""
        return self.overall_risk in {QuantumRiskLevel.CRITICAL, QuantumRiskLevel.HIGH}


class QuantumThreatContext:
    """
    Context manager for quantum threat awareness in protocol enforcement.

    Provides:
    1. Current quantum capability assessment
    2. Protocol vulnerability analysis
    3. Risk-adjusted enforcement decisions
    4. Migration path recommendations
    """

    def __init__(
        self,
        capability_profile: str = "current_2024",
        data_retention_years: float = 10.0,
        compliance_frameworks: list[str] | None = None,
    ):
        """
        Initialize quantum threat context.

        Args:
            capability_profile: Name of quantum capability profile to use
            data_retention_years: How long data must remain confidential
            compliance_frameworks: Applicable compliance frameworks (e.g., "NIST", "GDPR")
        """
        self.capability = QUANTUM_CAPABILITIES.get(
            capability_profile, QUANTUM_CAPABILITIES["current_2024"]
        )
        self.data_retention_years = data_retention_years
        self.compliance_frameworks = compliance_frameworks or []
        self._custom_vulnerabilities: dict[CryptographicPrimitive, PrimitiveVulnerability] = {}

    def register_custom_vulnerability(
        self, primitive: CryptographicPrimitive, vulnerability: PrimitiveVulnerability
    ):
        """Register a custom vulnerability assessment for a primitive."""
        self._custom_vulnerabilities[primitive] = vulnerability

    def get_vulnerability(self, primitive: CryptographicPrimitive) -> PrimitiveVulnerability | None:
        """Get vulnerability information for a primitive."""
        if primitive in self._custom_vulnerabilities:
            return self._custom_vulnerabilities[primitive]
        return PRIMITIVE_VULNERABILITIES.get(primitive)

    def assess_primitive(self, primitive: CryptographicPrimitive) -> QuantumRiskLevel:
        """Assess quantum risk for a single primitive."""
        vuln = self.get_vulnerability(primitive)
        if vuln is None:
            return QuantumRiskLevel.MEDIUM  # Unknown primitive

        # Adjust risk based on data retention requirements
        if vuln.quantum_vulnerable:
            years_to_crqc = self.capability.years_to_crqc

            if self.data_retention_years > years_to_crqc:
                # Data must remain secure longer than CRQC timeline
                return QuantumRiskLevel.CRITICAL
            elif self.data_retention_years > years_to_crqc * 0.7:
                return QuantumRiskLevel.HIGH
            elif self.data_retention_years > years_to_crqc * 0.5:
                return QuantumRiskLevel.MEDIUM

        return vuln.migration_urgency

    def assess_protocol(
        self, primitives: list[CryptographicPrimitive], protocol_name: str = "unknown"
    ) -> ThreatAssessment:
        """
        Perform comprehensive threat assessment for a protocol.

        Args:
            primitives: List of cryptographic primitives used by the protocol
            protocol_name: Name of the protocol for reporting

        Returns:
            Complete threat assessment
        """
        primitive_risks = {}
        vulnerabilities = []
        recommendations = []

        # Assess each primitive
        for primitive in primitives:
            risk = self.assess_primitive(primitive)
            primitive_risks[primitive] = risk

            vuln = self.get_vulnerability(primitive)
            if vuln:
                vulnerabilities.append(vuln)

                if vuln.quantum_vulnerable and vuln.recommended_replacement:
                    recommendations.append(
                        f"Replace {primitive.name} with {vuln.recommended_replacement.name}"
                    )

        # Calculate overall risk
        if not primitive_risks:
            overall_risk = QuantumRiskLevel.MINIMAL
        else:
            # Worst primitive determines overall risk
            overall_risk = min(primitive_risks.values(), key=lambda x: x.value)

        # Calculate HNDL risk score
        hndl_score = self._calculate_hndl_risk(primitives)

        # Calculate time to critical
        time_to_critical = timedelta(days=int(self.capability.years_to_crqc * 365))

        # Add compliance-based recommendations
        compliance_impacts = []
        if "NIST" in self.compliance_frameworks:
            if any(
                p in {CryptographicPrimitive.RSA, CryptographicPrimitive.ECDH} for p in primitives
            ):
                recommendations.append("NIST recommends transitioning to PQC by 2035")
                compliance_impacts.append("NIST SP 800-208 PQC Migration")

        return ThreatAssessment(
            overall_risk=overall_risk,
            primitive_risks=primitive_risks,
            vulnerabilities=vulnerabilities,
            time_to_critical=time_to_critical,
            data_retention_years=self.data_retention_years,
            hndl_risk_score=hndl_score,
            recommendations=recommendations,
            compliance_impacts=compliance_impacts,
            quantum_capability_assumed=self.capability.source,
        )

    def _calculate_hndl_risk(self, primitives: list[CryptographicPrimitive]) -> float:
        """
        Calculate Harvest-Now-Decrypt-Later risk score.

        Higher scores indicate greater risk of data being captured now
        and decrypted when quantum computers are available.
        """
        score = 0.0

        # Base score from data retention requirement
        retention_factor = self.data_retention_years / self.capability.years_to_crqc
        score += min(50.0, retention_factor * 25)

        # Add score for vulnerable primitives
        for primitive in primitives:
            vuln = self.get_vulnerability(primitive)
            if vuln and vuln.quantum_vulnerable:
                if vuln.attack_type == QuantumThreatType.KEY_RECOVERY:
                    score += 30.0  # Key exchange vulnerable - high risk
                elif vuln.attack_type == QuantumThreatType.SIGNATURE_FORGERY:
                    score += 15.0  # Signature vulnerable - moderate risk

        # Reduce score for post-quantum primitives
        pq_primitives = [
            CryptographicPrimitive.ML_KEM,
            CryptographicPrimitive.ML_DSA,
            CryptographicPrimitive.SLH_DSA,
            CryptographicPrimitive.X25519_ML_KEM,
        ]
        for primitive in primitives:
            if primitive in pq_primitives:
                score = max(0.0, score - 20.0)

        return min(100.0, max(0.0, score))

    def get_enforcement_adjustment(self, threat_assessment: ThreatAssessment) -> dict[str, Any]:
        """
        Get enforcement parameter adjustments based on threat assessment.

        Returns a dictionary of enforcement parameter modifications.
        """
        adjustments = {}

        if threat_assessment.overall_risk == QuantumRiskLevel.CRITICAL:
            adjustments["enforcement_mode"] = "STRICT"
            adjustments["allow_fallback"] = False
            adjustments["require_pqc"] = True
            adjustments["log_level"] = "DEBUG"

        elif threat_assessment.overall_risk == QuantumRiskLevel.HIGH:
            adjustments["enforcement_mode"] = "STRICT"
            adjustments["allow_fallback"] = False
            adjustments["require_pqc"] = True
            adjustments["log_level"] = "INFO"

        elif threat_assessment.overall_risk == QuantumRiskLevel.MEDIUM:
            adjustments["enforcement_mode"] = "PERMISSIVE"
            adjustments["allow_fallback"] = True
            adjustments["require_pqc"] = False
            adjustments["log_level"] = "WARNING"

        else:
            adjustments["enforcement_mode"] = "AUDIT"
            adjustments["allow_fallback"] = True
            adjustments["require_pqc"] = False
            adjustments["log_level"] = "INFO"

        # Adjust based on HNDL risk
        if threat_assessment.hndl_risk_score > 70:
            adjustments["encrypt_logs"] = True
            adjustments["minimize_metadata"] = True

        return adjustments

    def recommend_migration_path(
        self, current_primitives: list[CryptographicPrimitive]
    ) -> list[tuple[CryptographicPrimitive, CryptographicPrimitive, str]]:
        """
        Recommend migration path from current to post-quantum primitives.

        Returns list of (current, recommended, rationale) tuples.
        """
        migrations = []

        for primitive in current_primitives:
            vuln = self.get_vulnerability(primitive)
            if vuln and vuln.quantum_vulnerable and vuln.recommended_replacement:
                rationale = f"{vuln.notes}; {vuln.migration_urgency.name} urgency"
                migrations.append((primitive, vuln.recommended_replacement, rationale))

        # Sort by urgency
        urgency_order = {
            QuantumRiskLevel.CRITICAL: 0,
            QuantumRiskLevel.HIGH: 1,
            QuantumRiskLevel.MEDIUM: 2,
            QuantumRiskLevel.LOW: 3,
            QuantumRiskLevel.MINIMAL: 4,
        }

        def get_urgency(migration: tuple) -> int:
            vuln = self.get_vulnerability(migration[0])
            if vuln:
                return urgency_order.get(vuln.migration_urgency, 5)
            return 5

        migrations.sort(key=get_urgency)

        return migrations

    def update_capability(self, capability: QuantumCapability):
        """Update the quantum capability assessment."""
        self.capability = capability

    def to_dict(self) -> dict[str, Any]:
        """Convert context to dictionary for serialization."""
        return {
            "capability": {
                "logical_qubits": self.capability.logical_qubits,
                "physical_qubits": self.capability.physical_qubits,
                "years_to_crqc": self.capability.years_to_crqc,
                "source": self.capability.source,
            },
            "data_retention_years": self.data_retention_years,
            "compliance_frameworks": self.compliance_frameworks,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> QuantumThreatContext:
        """Create context from dictionary."""
        ctx = cls(
            data_retention_years=data.get("data_retention_years", 10.0),
            compliance_frameworks=data.get("compliance_frameworks", []),
        )

        if "capability" in data:
            cap_data = data["capability"]
            ctx.capability = QuantumCapability(
                logical_qubits=cap_data.get("logical_qubits", 0),
                physical_qubits=cap_data.get("physical_qubits", 1000),
                years_to_crqc=cap_data.get("years_to_crqc", 10.0),
                source=cap_data.get("source", "custom"),
            )

        return ctx
