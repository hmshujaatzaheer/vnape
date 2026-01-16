"""
V-NAPE Quantum Threat Assessment Example

This example demonstrates how to use V-NAPE's quantum context manager
to assess cryptographic protocols for quantum vulnerability and plan
post-quantum migration strategies.
"""

from vnape.pqae.quantum_context import (
    QuantumThreatContext,
    QuantumCapability,
    PrimitiveVulnerability,
    ThreatAssessment,
)
from datetime import datetime


def main():
    """Demonstrate quantum threat assessment capabilities."""
    
    print("=" * 60)
    print("V-NAPE Framework - Quantum Threat Assessment")
    print("=" * 60)
    
    # =========================================================================
    # Part 1: Assess Individual Cryptographic Primitives
    # =========================================================================
    print("\n[Part 1] Cryptographic Primitive Vulnerability Assessment")
    print("-" * 50)
    
    primitives = [
        "RSA-2048",
        "RSA-4096",
        "ECDH-P256",
        "ECDH-P384",
        "X25519",
        "ML-KEM-768",
        "ML-KEM-1024",
        "ML-DSA-65",
        "AES-128",
        "AES-256",
        "SHA-256",
        "SHA-384",
    ]
    
    print("\n  Primitive          | Quantum Vulnerable | Est. Break Year | HNDL Risk")
    print("  " + "-" * 70)
    
    for primitive in primitives:
        vuln = PrimitiveVulnerability.for_primitive(primitive)
        
        vulnerable = "Yes" if vuln.quantum_vulnerable else "No"
        break_year = vuln.estimated_break_year if vuln.quantum_vulnerable else "N/A"
        
        # Calculate HNDL risk for sensitive data
        context = QuantumThreatContext(
            capability_profile="current_2024",
            data_retention_years=15.0
        )
        hndl = context.calculate_hndl_risk(
            primitive=primitive,
            data_sensitivity="high",
            retention_years=15.0
        )
        
        print(f"  {primitive:<18} | {vulnerable:<18} | {str(break_year):<15} | {hndl:.1%}")
    
    # =========================================================================
    # Part 2: Compare Quantum Capability Profiles
    # =========================================================================
    print("\n[Part 2] Quantum Computing Capability Profiles")
    print("-" * 50)
    
    profiles = [
        ("Current (2024)", QuantumCapability.current_2024()),
        ("Near-term (2030)", QuantumCapability.near_term_2030()),
        ("CRQC Ready", QuantumCapability.crqc_ready()),
    ]
    
    print("\n  Profile            | Logical Qubits | Error Rate | Can Break RSA-2048")
    print("  " + "-" * 65)
    
    for name, cap in profiles:
        can_break_rsa = cap.logical_qubits >= 4000 and cap.error_rate < 0.001
        can_break = "Yes" if can_break_rsa else "No"
        print(f"  {name:<18} | {cap.logical_qubits:>14} | {cap.error_rate:>10.4f} | {can_break:<17}")
    
    # =========================================================================
    # Part 3: Full Protocol Assessment
    # =========================================================================
    print("\n[Part 3] Protocol Security Assessment")
    print("-" * 50)
    
    protocols_to_assess = [
        {
            "name": "Legacy TLS 1.2",
            "key_exchange": "ECDHE-P256",
            "signature": "RSA-2048",
            "encryption": "AES-128-GCM",
        },
        {
            "name": "Modern TLS 1.3",
            "key_exchange": "X25519",
            "signature": "ECDSA-P256",
            "encryption": "AES-256-GCM",
        },
        {
            "name": "PQ-Hybrid TLS",
            "key_exchange": "X25519 + ML-KEM-768",
            "signature": "ML-DSA-65",
            "encryption": "AES-256-GCM",
        },
    ]
    
    # Create context for assessment
    context = QuantumThreatContext(
        capability_profile="current_2024",
        data_retention_years=10.0,
        risk_tolerance=0.1
    )
    
    for protocol in protocols_to_assess:
        print(f"\n  Protocol: {protocol['name']}")
        print(f"    Key Exchange: {protocol['key_exchange']}")
        print(f"    Signature: {protocol['signature']}")
        print(f"    Encryption: {protocol['encryption']}")
        
        assessment = context.assess_protocol(protocol)
        
        print(f"\n    Assessment Results:")
        print(f"      Current Risk:  {assessment.current_risk:.1%}")
        print(f"      HNDL Risk:     {assessment.hndl_risk:.1%}")
        
        if assessment.recommended_migration:
            print(f"      Migration:     {assessment.recommended_migration}")
        else:
            print(f"      Migration:     Not required (already PQ-safe)")
        
        # Risk level indicator
        if assessment.hndl_risk > 0.7:
            print(f"      ⚠️  HIGH RISK - Immediate migration recommended")
        elif assessment.hndl_risk > 0.3:
            print(f"      ⚡ MODERATE RISK - Plan migration within 2-3 years")
        else:
            print(f"      ✅ LOW RISK - Protocol is quantum-resistant")
    
    # =========================================================================
    # Part 4: Harvest-Now-Decrypt-Later (HNDL) Analysis
    # =========================================================================
    print("\n[Part 4] HNDL (Harvest-Now-Decrypt-Later) Risk Analysis")
    print("-" * 50)
    
    print("\n  Scenario: Highly sensitive data (government/financial)")
    print("  Data must remain confidential for varying periods.")
    print()
    
    retention_periods = [5, 10, 15, 20, 25, 30]
    
    print("  Retention  | RSA-2048 | ECDH-P256 | ML-KEM-768")
    print("  " + "-" * 50)
    
    for years in retention_periods:
        context = QuantumThreatContext(
            capability_profile="current_2024",
            data_retention_years=float(years)
        )
        
        rsa_risk = context.calculate_hndl_risk("RSA-2048", "critical", float(years))
        ecc_risk = context.calculate_hndl_risk("ECDH-P256", "critical", float(years))
        pq_risk = context.calculate_hndl_risk("ML-KEM-768", "critical", float(years))
        
        print(f"  {years:>3} years  | {rsa_risk:>8.1%} | {ecc_risk:>9.1%} | {pq_risk:>10.1%}")
    
    # =========================================================================
    # Part 5: Migration Timeline Recommendations
    # =========================================================================
    print("\n[Part 5] Post-Quantum Migration Timeline")
    print("-" * 50)
    
    print("""
  Based on current quantum computing progress and data sensitivity:
  
  ┌─────────────────────────────────────────────────────────────────┐
  │                     MIGRATION TIMELINE                          │
  ├─────────────────────────────────────────────────────────────────┤
  │                                                                 │
  │  2024-2025: Begin Assessment                                    │
  │    • Inventory all cryptographic usage                          │
  │    • Identify highest-risk systems                              │
  │    • Test PQ algorithms in non-production                       │
  │                                                                 │
  │  2025-2027: Hybrid Deployment                                   │
  │    • Deploy hybrid classical+PQ for key exchange               │
  │    • Maintain backward compatibility                            │
  │    • Monitor NIST standardization progress                      │
  │                                                                 │
  │  2027-2030: Full PQ Transition                                  │
  │    • Migrate signatures to ML-DSA                               │
  │    • Phase out classical-only connections                       │
  │    • Update all long-term keys                                  │
  │                                                                 │
  │  2030+: Continuous Monitoring                                   │
  │    • Track quantum computing advances                           │
  │    • Adjust security levels as needed                           │
  │    • Prepare for next-gen PQ algorithms                         │
  │                                                                 │
  └─────────────────────────────────────────────────────────────────┘
    """)
    
    print("\n" + "=" * 60)
    print("Quantum threat assessment complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
