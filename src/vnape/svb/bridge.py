"""
Symbolic Verification Bridge (SVB) for V-NAPE.

This module provides the main interface for verifying neural policy
refinements against safety invariants using SMT solving and abstract
interpretation techniques.

The SVB ensures that neural policy decisions satisfy required formal
correctness criteria before being applied to enforcement.

Based on the methodology described in Section 4.2 of the V-NAPE proposal.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

try:
    import z3

    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False

from ..core.types import (
    Counterexample,
    MFOTLFormula,
    PolicyRefinement,
    RefinementType,
    SafetyInvariants,
    VerificationResult,
)
from .abstraction import (
    AbstractionStrategy,
    create_abstraction_engine,
)
from .certificate import (
    Certificate,
    CertificateGenerator,
    CertificateStore,
)
from .translator import MFOTLToZ3Translator

logger = logging.getLogger(__name__)


class VerificationMode(Enum):
    """Modes for verification process."""

    STRICT = auto()  # All invariants must be verified
    PERMISSIVE = auto()  # Some invariants may be unknown
    BOUNDED = auto()  # Use bounded model checking with timeout
    ABSTRACT = auto()  # Use abstract interpretation only


class CompositionOperator(Enum):
    """Operators for composing policies with refinements."""

    CONJUNCTION = auto()  # φ_base ∧ Δφ (strengthening)
    CONDITIONAL = auto()  # condition → Δφ ∧ ¬condition → φ_base
    OVERRIDE = auto()  # Δφ takes precedence over φ_base
    MERGE = auto()  # Intelligent merging based on refinement type


@dataclass
class VerificationConfig:
    """Configuration for verification process."""

    mode: VerificationMode = VerificationMode.STRICT
    timeout_ms: int = 5000
    max_unroll_depth: int = 10
    abstraction_strategy: AbstractionStrategy = AbstractionStrategy.INTERVAL
    use_incremental_smt: bool = True
    cache_results: bool = True
    generate_certificates: bool = True
    certificate_validity_hours: int = 24


@dataclass
class ComposedPolicy:
    """
    Result of composing a base policy with a refinement.

    Contains both the composed formula and metadata about
    the composition process.
    """

    formula: MFOTLFormula
    base_policy: MFOTLFormula
    refinement: PolicyRefinement
    composition_operator: CompositionOperator
    composition_time: float

    def __repr__(self) -> str:
        return f"ComposedPolicy({self.formula.text[:50]}..., op={self.composition_operator.name})"


@dataclass
class VerificationJob:
    """
    A verification job to be processed.

    Encapsulates all information needed to verify a refinement.
    """

    job_id: str
    refinement: PolicyRefinement
    base_policy: MFOTLFormula
    invariants: SafetyInvariants
    config: VerificationConfig
    submitted_at: float = field(default_factory=time.time)
    started_at: float | None = None
    completed_at: float | None = None
    result: VerificationResult | None = None
    certificate: Certificate | None = None


class SymbolicVerificationBridge:
    """
    Main Symbolic Verification Bridge for V-NAPE.

    Provides the interface for verifying neural policy refinements
    against safety invariants using SMT solving and abstraction.

    Architecture (matching Figure 3 in proposal):
    1. Compose: Combine base policy with refinement
    2. Abstract: Create abstract representation if needed
    3. SMT Check: Verify against invariants
    4. Certificate: Generate proof certificate
    """

    def __init__(
        self,
        config: VerificationConfig | None = None,
    ):
        """
        Initialize Symbolic Verification Bridge.

        Args:
            config: Verification configuration
        """
        self.config = config or VerificationConfig()

        # Initialize components
        self._translator = MFOTLToZ3Translator(max_time_steps=self.config.max_unroll_depth)
        self._abstraction_engine = create_abstraction_engine(
            strategy=self.config.abstraction_strategy.name.lower(),
            precision=0.1,
        )
        self._certificate_generator = CertificateGenerator(
            abstraction_engine=self._abstraction_engine,
            certificate_validity_hours=self.config.certificate_validity_hours,
        )
        self._certificate_store = CertificateStore()

        # Result cache
        self._cache: dict[str, VerificationResult] = {}

        # Statistics
        self._stats = {
            "total_verifications": 0,
            "verified_count": 0,
            "refuted_count": 0,
            "unknown_count": 0,
            "total_time_ms": 0.0,
            "cache_hits": 0,
        }

        logger.info(f"Initialized SVB with mode={self.config.mode.name}")

    def verify(
        self,
        refinement: PolicyRefinement,
        base_policy: MFOTLFormula,
        invariants: SafetyInvariants,
    ) -> tuple[VerificationResult, Certificate | None]:
        """
        Verify a policy refinement against safety invariants.

        This is the main entry point for verification. It follows
        the flow described in Figure 3 of the proposal:

        1. Compose refinement with base policy
        2. Abstract the composed policy (if configured)
        3. Check against invariants using SMT
        4. Generate certificate

        Args:
            refinement: Policy refinement to verify
            base_policy: Base policy being refined
            invariants: Safety invariants that must be preserved

        Returns:
            Tuple of (verification result, certificate if generated)
        """
        start_time = time.time()
        self._stats["total_verifications"] += 1

        # Check cache
        cache_key = self._compute_cache_key(refinement, base_policy, invariants)
        if self.config.cache_results and cache_key in self._cache:
            self._stats["cache_hits"] += 1
            logger.debug("Cache hit for verification")
            cached_result = self._cache[cache_key]
            return cached_result, None

        try:
            # Step 1: Compose refinement with base policy
            composed = self._compose_policy(refinement, base_policy)
            logger.debug(f"Composed policy: {composed.formula.text[:100]}...")

            # Step 2: Create abstraction if using abstract mode
            abstraction = None
            if self.config.mode == VerificationMode.ABSTRACT:
                abstraction = self._abstraction_engine.abstract_refinement(refinement)

                # Quick safety check on abstraction
                if not abstraction.is_safe(invariants):
                    result = VerificationResult(
                        verified=False,
                        invariants_satisfied=[],
                        invariants_violated=["abstraction_safety_check"],
                        counterexample=Counterexample(
                            trace=[],
                            violation_point=0,
                            violated_formula="abstraction safety",
                            description="Abstraction failed safety check",
                        ),
                    )
                    self._stats["refuted_count"] += 1
                    return result, None

            # Step 3: SMT verification
            result = self._verify_with_smt(composed, invariants)

            # Update statistics
            elapsed_ms = (time.time() - start_time) * 1000
            self._stats["total_time_ms"] += elapsed_ms

            if result.verified:
                self._stats["verified_count"] += 1
            elif result.counterexample:
                self._stats["refuted_count"] += 1
            else:
                self._stats["unknown_count"] += 1

            # Cache result
            if self.config.cache_results:
                self._cache[cache_key] = result

            # Step 4: Generate certificate
            certificate = None
            if self.config.generate_certificates:
                certificate = self._certificate_generator.generate_certificate(
                    refinement=refinement,
                    base_policy=base_policy,
                    invariants=invariants,
                    verification_result=result,
                    abstraction=abstraction,
                )
                self._certificate_store.store(certificate)

            logger.info(
                f"Verification completed in {elapsed_ms:.2f}ms: "
                f"{'VERIFIED' if result.verified else 'REFUTED' if result.counterexample else 'UNKNOWN'}"
            )

            return result, certificate

        except Exception as e:
            logger.error(f"Verification failed with error: {e}")
            result = VerificationResult(
                verified=False,
                invariants_satisfied=[],
                invariants_violated=[],
                error=str(e),
            )
            return result, None

    def verify_batch(
        self,
        refinements: list[PolicyRefinement],
        base_policy: MFOTLFormula,
        invariants: SafetyInvariants,
    ) -> list[tuple[VerificationResult, Certificate | None]]:
        """
        Verify multiple refinements in batch.

        Args:
            refinements: List of refinements to verify
            base_policy: Base policy
            invariants: Safety invariants

        Returns:
            List of (result, certificate) tuples
        """
        results = []
        for refinement in refinements:
            result = self.verify(refinement, base_policy, invariants)
            results.append(result)
        return results

    def check_invariant(
        self,
        composed_policy: ComposedPolicy,
        invariant: MFOTLFormula,
    ) -> tuple[bool, Counterexample | None]:
        """
        Check if composed policy satisfies a single invariant.

        Args:
            composed_policy: Composed policy to check
            invariant: Invariant to verify

        Returns:
            Tuple of (satisfied, counterexample if not)
        """
        if not Z3_AVAILABLE:
            logger.warning("Z3 not available, returning unknown")
            return False, None

        # Create fresh context for this check
        context = TranslationContext()

        # Translate policy and invariant
        policy_z3 = self._translator.translate(composed_policy.formula, context)
        invariant_z3 = self._translator.translate(invariant, context)

        # Check: policy ∧ ¬invariant is UNSAT means policy → invariant
        solver = z3.Solver()
        solver.set("timeout", self.config.timeout_ms)

        solver.add(policy_z3.formula)
        solver.add(z3.Not(invariant_z3.formula))

        result = solver.check()

        if result == z3.unsat:
            # Policy implies invariant
            return True, None
        elif result == z3.sat:
            # Found counterexample
            model = solver.model()
            counterexample = self._extract_counterexample(model, context, invariant)
            return False, counterexample
        else:
            # Unknown (timeout, etc.)
            return False, None

    def get_certificate(self, certificate_id: str) -> Certificate | None:
        """Retrieve a certificate by ID."""
        return self._certificate_store.get(certificate_id)

    def get_statistics(self) -> dict[str, Any]:
        """Get verification statistics."""
        stats = dict(self._stats)
        if stats["total_verifications"] > 0:
            stats["verification_rate"] = stats["verified_count"] / stats["total_verifications"]
            stats["avg_time_ms"] = stats["total_time_ms"] / stats["total_verifications"]
        return stats

    def clear_cache(self) -> None:
        """Clear verification result cache."""
        self._cache.clear()
        logger.info("Cleared verification cache")

    def _compose_policy(
        self,
        refinement: PolicyRefinement,
        base_policy: MFOTLFormula,
    ) -> ComposedPolicy:
        """
        Compose refinement with base policy.

        The composition operator is chosen based on refinement type:
        - STRENGTHENING: Use conjunction (φ_base ∧ Δφ)
        - EXCEPTION: Use conditional
        - TEMPORAL: Merge temporal constraints
        - PARAMETER: Override parameters
        """
        start_time = time.time()

        # Determine composition operator
        if refinement.refinement_type == RefinementType.STRENGTHENING:
            op = CompositionOperator.CONJUNCTION
            composed_text = f"({base_policy.text}) ∧ ({refinement.formula.text})"
        elif refinement.refinement_type == RefinementType.EXCEPTION:
            op = CompositionOperator.CONDITIONAL
            # Exception: If condition in refinement, apply refinement, else base
            composed_text = f"({refinement.formula.text}) ∨ ({base_policy.text})"
        elif refinement.refinement_type == RefinementType.TEMPORAL_CONSTRAINT:
            op = CompositionOperator.MERGE
            # Merge temporal constraints by conjunction
            composed_text = f"({base_policy.text}) ∧ ({refinement.formula.text})"
        else:
            # Default to conjunction
            op = CompositionOperator.CONJUNCTION
            composed_text = f"({base_policy.text}) ∧ ({refinement.formula.text})"

        composed_formula = MFOTLFormula(
            text=composed_text,
            variables=list(
                set((base_policy.variables or []) + (refinement.formula.variables or []))
            ),
            predicates=list(
                set((base_policy.predicates or []) + (refinement.formula.predicates or []))
            ),
        )

        return ComposedPolicy(
            formula=composed_formula,
            base_policy=base_policy,
            refinement=refinement,
            composition_operator=op,
            composition_time=time.time() - start_time,
        )

    def _verify_with_smt(
        self,
        composed: ComposedPolicy,
        invariants: SafetyInvariants,
    ) -> VerificationResult:
        """
        Verify composed policy against invariants using SMT.

        Args:
            composed: Composed policy
            invariants: Safety invariants

        Returns:
            Verification result
        """
        if not Z3_AVAILABLE:
            logger.warning("Z3 not available, returning unverified result")
            return VerificationResult(
                verified=False,
                invariants_satisfied=[],
                invariants_violated=[],
                error="Z3 solver not available",
            )

        satisfied = []
        violated = []
        counterexample = None

        # Get invariant formulas
        invariant_formulas = []
        if hasattr(invariants, "formulas") and invariants.formulas:
            invariant_formulas = invariants.formulas
        elif hasattr(invariants, "temporal_constraints") and invariants.temporal_constraints:
            invariant_formulas = [MFOTLFormula(text=tc) for tc in invariants.temporal_constraints]

        if not invariant_formulas:
            # No invariants to check - trivially satisfied
            logger.debug("No invariants to check, trivially satisfied")
            return VerificationResult(
                verified=True,
                invariants_satisfied=[],
                invariants_violated=[],
            )

        # Check each invariant
        for i, inv in enumerate(invariant_formulas):
            inv_formula = inv if isinstance(inv, MFOTLFormula) else MFOTLFormula(text=str(inv))

            sat, cex = self.check_invariant(composed, inv_formula)

            if sat:
                satisfied.append(f"invariant_{i}")
            else:
                violated.append(f"invariant_{i}")
                if cex and counterexample is None:
                    counterexample = cex

                # In strict mode, fail fast
                if self.config.mode == VerificationMode.STRICT:
                    break

        # Determine overall result
        if self.config.mode == VerificationMode.STRICT:
            verified = len(violated) == 0 and len(satisfied) == len(invariant_formulas)
        else:  # PERMISSIVE or BOUNDED
            verified = len(violated) == 0

        return VerificationResult(
            verified=verified,
            invariants_satisfied=satisfied,
            invariants_violated=violated,
            counterexample=counterexample,
        )

    def _extract_counterexample(
        self,
        model: z3.ModelRef,
        context: TranslationContext,
        violated_invariant: MFOTLFormula,
    ) -> Counterexample:
        """
        Extract counterexample trace from Z3 model.

        Args:
            model: Z3 satisfying model
            context: Translation context with variable mappings
            violated_invariant: The invariant that was violated

        Returns:
            Counterexample with trace
        """
        trace = []

        # Extract values for time variables
        for var_name, z3_var in context.variables.items():
            try:
                value = model.eval(z3_var, model_completion=True)
                trace.append(
                    {
                        "variable": var_name,
                        "value": str(value),
                    }
                )
            except Exception:
                pass

        # Extract predicate evaluations
        for pred_name, pred_func in context.predicates.items():
            try:
                # Get predicate arity and evaluate
                trace.append(
                    {
                        "predicate": pred_name,
                        "status": "counterexample",
                    }
                )
            except Exception:
                pass

        return Counterexample(
            trace=trace,
            violation_point=0,
            violated_formula=violated_invariant.text,
            description=f"Counterexample found for invariant: {violated_invariant.text[:100]}...",
        )

    def _compute_cache_key(
        self,
        refinement: PolicyRefinement,
        base_policy: MFOTLFormula,
        invariants: SafetyInvariants,
    ) -> str:
        """Compute cache key for verification result."""
        import hashlib

        key_parts = [
            refinement.formula.text,
            refinement.refinement_type.name,
            base_policy.text,
            str(invariants),
        ]

        key_string = "|".join(key_parts)
        return hashlib.md5(key_string.encode(), usedforsecurity=False).hexdigest()  # nosec B324


def create_svb(
    mode: str = "strict",
    timeout_ms: int = 5000,
    generate_certificates: bool = True,
) -> SymbolicVerificationBridge:
    """
    Factory function to create SVB instance.

    Args:
        mode: Verification mode (strict/permissive/bounded/abstract)
        timeout_ms: SMT solver timeout
        generate_certificates: Whether to generate certificates

    Returns:
        Configured SVB instance
    """
    mode_map = {
        "strict": VerificationMode.STRICT,
        "permissive": VerificationMode.PERMISSIVE,
        "bounded": VerificationMode.BOUNDED,
        "abstract": VerificationMode.ABSTRACT,
    }

    config = VerificationConfig(
        mode=mode_map.get(mode.lower(), VerificationMode.STRICT),
        timeout_ms=timeout_ms,
        generate_certificates=generate_certificates,
    )

    return SymbolicVerificationBridge(config)
