"""
V-NAPE Basic Usage Example

This example demonstrates the fundamental usage of the V-NAPE framework
for verifying and enforcing security policies on cryptographic protocols.
"""

from vnape import VNAPE, VNAPEConfig
from vnape.core.types import TraceEvent, ProtocolTrace, PolicyFormula
from vnape.protocols import IMessagePQ3Protocol
from vnape.pqae import QuantumThreatContext, EnforcementMode


def main():
    """Demonstrate basic V-NAPE usage."""
    
    print("=" * 60)
    print("V-NAPE Framework - Basic Usage Example")
    print("=" * 60)
    
    # =========================================================================
    # Step 1: Configure V-NAPE
    # =========================================================================
    print("\n[1] Configuring V-NAPE...")
    
    # Create quantum threat context
    quantum_ctx = QuantumThreatContext(
        capability_profile="current_2024",
        data_retention_years=10.0,  # Data must remain secure for 10 years
        risk_tolerance=0.1
    )
    
    # Configure V-NAPE with all components
    config = VNAPEConfig(
        quantum_context=quantum_ctx,
        enforcement_mode=EnforcementMode.STRICT
    )
    
    vnape = VNAPE(config)
    print("  ✓ V-NAPE configured with quantum-aware enforcement")
    
    # =========================================================================
    # Step 2: Load Protocol Definition
    # =========================================================================
    print("\n[2] Loading protocol definition...")
    
    protocol = IMessagePQ3Protocol()
    vnape.load_protocol(protocol)
    
    print(f"  ✓ Loaded protocol: {protocol.name}")
    print(f"  ✓ Protocol version: {protocol.version}")
    print(f"  ✓ Quantum safety level: {protocol.quantum_safety.value}")
    
    # Show base policies
    policies = protocol.get_base_policies()
    print(f"  ✓ Loaded {len(policies)} base policies:")
    for p in policies[:3]:  # Show first 3
        print(f"      - {p.name}")
    
    # =========================================================================
    # Step 3: Create Protocol Trace
    # =========================================================================
    print("\n[3] Creating protocol trace...")
    
    # Simulate a valid iMessage PQ3 session
    trace = ProtocolTrace(
        protocol_name="iMessagePQ3",
        events=[
            TraceEvent(
                name="IKE_Init",
                timestamp=0.0,
                parameters={
                    "initiator": "alice",
                    "ephemeral_x25519": "pk_alice_x25519",
                    "session_id": "session_001"
                },
                quantum_safe=True
            ),
            TraceEvent(
                name="IKE_Response",
                timestamp=50.0,
                parameters={
                    "responder": "bob",
                    "ephemeral_x25519": "pk_bob_x25519",
                    "ml_kem_ciphertext": "ct_ml_kem_768",
                    "session_id": "session_001"
                },
                quantum_safe=True
            ),
            TraceEvent(
                name="IKE_Complete",
                timestamp=100.0,
                parameters={
                    "session_key_established": True,
                    "session_id": "session_001"
                },
                quantum_safe=True
            ),
            TraceEvent(
                name="Session_Active",
                timestamp=150.0,
                parameters={
                    "session_id": "session_001",
                    "cipher_suite": "ChaCha20-Poly1305"
                },
                quantum_safe=True
            ),
            TraceEvent(
                name="Message_Sent",
                timestamp=200.0,
                parameters={
                    "session_id": "session_001",
                    "message_id": "msg_001",
                    "encrypted": True
                },
                quantum_safe=True
            ),
        ],
        session_id="session_001"
    )
    
    print(f"  ✓ Created trace with {len(trace.events)} events")
    print(f"  ✓ Trace duration: {trace.duration()}ms")
    
    # =========================================================================
    # Step 4: Process Trace Through V-NAPE
    # =========================================================================
    print("\n[4] Processing trace through V-NAPE pipeline...")
    
    result = vnape.process_trace(trace, generate_certificates=True)
    
    # Show NPA analysis
    npa_result = result.get("npa_analysis", {})
    print(f"\n  [NPA - Neural Policy Adaptation]")
    print(f"    - Patterns detected: {npa_result.get('patterns_detected', 0)}")
    print(f"    - Anomalies found: {npa_result.get('anomalies_detected', 0)}")
    print(f"    - Suggested refinements: {npa_result.get('refinements_suggested', 0)}")
    
    # Show SVB verification
    svb_result = result.get("svb_verification", {})
    print(f"\n  [SVB - Symbolic Verification Bridge]")
    print(f"    - Verification status: {svb_result.get('status', 'N/A')}")
    print(f"    - Properties verified: {svb_result.get('properties_verified', 0)}")
    print(f"    - Verification time: {svb_result.get('time_ms', 0):.2f}ms")
    
    # Show PQAE enforcement
    pqae_result = result.get("pqae_enforcement", {})
    print(f"\n  [PQAE - Proactive Quantum-Aware Enforcement]")
    decision = pqae_result.get("final_decision")
    if decision:
        print(f"    - Action: {decision.action.value}")
        print(f"    - Confidence: {decision.confidence:.2%}")
        print(f"    - Quantum risk factor: {decision.quantum_risk_factor:.2%}")
    print(f"    - Violations detected: {pqae_result.get('violation_count', 0)}")
    
    # =========================================================================
    # Step 5: Check Results
    # =========================================================================
    print("\n[5] Analyzing results...")
    
    if decision and decision.action.value == "ALLOW":
        print("\n  ✅ RESULT: Trace ALLOWED")
        print("     Protocol execution conforms to all security policies.")
    else:
        print("\n  ❌ RESULT: Trace BLOCKED or FLAGGED")
        print("     Review violations and adjust protocol implementation.")
    
    # Show any violations
    violations = result.get("violations", [])
    if violations:
        print(f"\n  Violations ({len(violations)}):")
        for v in violations:
            print(f"    - [{v.severity.value}] {v.policy_name}: {v.description}")
    
    # =========================================================================
    # Step 6: Get Certificates (if verification passed)
    # =========================================================================
    if svb_result.get("status") == "verified":
        print("\n[6] Proof certificates generated:")
        certs = svb_result.get("certificates", [])
        for cert in certs[:2]:  # Show first 2
            print(f"    - {cert.certificate_type.value}: {cert.property_proven[:50]}...")
    
    print("\n" + "=" * 60)
    print("Example complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
