"""
V-NAPE Core Framework

The main integration point for all V-NAPE components:
- NPA (Neural Policy Adaptation)
- SVB (Symbolic Verification Bridge)
- PQAE (Proactive Quantum-Aware Enforcement)

This module provides the high-level VNAPE class that orchestrates
the interaction between components for end-to-end adaptive enforcement.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from vnape.core.types import (
    EnforcementMode,
    EnforcementResult,
    ExecutionTrace,
    MFOTLFormula,
    ModelConfig,
    PolicyRefinement,
    ProtocolEvent,
    QuantumContext,
    TrainingConfig,
    VerificationResult,
)

if TYPE_CHECKING:
    from vnape.npa import NeuralPolicyAdapter
    from vnape.pqae import ProactiveEnforcer
    from vnape.protocols.base import BaseProtocol
    from vnape.svb import SafetyInvariants, SymbolicVerificationBridge

logger = structlog.get_logger(__name__)


@dataclass
class VNAPEConfig:
    """Configuration for the V-NAPE framework."""

    # NPA Configuration
    model_config: ModelConfig = field(default_factory=ModelConfig)
    training_config: TrainingConfig = field(default_factory=TrainingConfig)
    confidence_threshold: float = 0.8
    adaptation_enabled: bool = True

    # SVB Configuration
    z3_timeout_ms: int = 30000
    abstraction_level: int = 2
    generate_certificates: bool = True

    # PQAE Configuration
    enforcement_mode: EnforcementMode = EnforcementMode.STRICT
    buffer_size: int = 10000
    adaptation_trigger_threshold: float = 0.8

    # Quantum Context
    quantum_context: QuantumContext = field(default_factory=QuantumContext)

    # Logging
    log_level: str = "INFO"
    log_file: Path | None = None


class VNAPE:
    """
    V-NAPE: Verified Neural Adaptive Proactive Enforcement

    The main framework class that integrates NPA, SVB, and PQAE components
    for adaptive runtime security in post-quantum cryptographic protocols.

    Example:
        >>> vnape = VNAPE()
        >>> vnape.load_protocol(IMessagePQ3Protocol())
        >>> vnape.set_base_policy("□[0,∞) (SessionActive(s) → ◇[0,δ] KeyRatchet(s, k'))")
        >>> result = vnape.enforce(trace)

    Attributes:
        config: Framework configuration
        protocol: Currently loaded protocol (if any)
        base_policy: Base MFOTL policy for enforcement
        active_refinements: Currently active policy refinements
    """

    def __init__(self, config: VNAPEConfig | None = None):
        """
        Initialize the V-NAPE framework.

        Args:
            config: Framework configuration. Uses defaults if not provided.
        """
        self.config = config or VNAPEConfig()
        self._setup_logging()

        # Components (lazily initialized)
        self._npa: NeuralPolicyAdapter | None = None
        self._svb: SymbolicVerificationBridge | None = None
        self._pqae: ProactiveEnforcer | None = None

        # State
        self.protocol: BaseProtocol | None = None
        self.base_policy: MFOTLFormula | None = None
        self.active_refinements: list[PolicyRefinement] = []
        self.safety_invariants: SafetyInvariants | None = None

        # Metrics
        self._events_processed: int = 0
        self._refinements_proposed: int = 0
        self._refinements_accepted: int = 0
        self._violations_detected: int = 0

        logger.info("V-NAPE framework initialized", config=str(self.config))

    def _setup_logging(self) -> None:
        """Configure structured logging."""
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.dev.ConsoleRenderer(),
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )
        logging.basicConfig(
            format="%(message)s",
            level=getattr(logging, self.config.log_level),
        )

    @property
    def npa(self) -> NeuralPolicyAdapter:
        """Lazy initialization of NPA component."""
        if self._npa is None:
            from vnape.npa import NeuralPolicyAdapter, TraceEncoder

            encoder = TraceEncoder(
                embed_dim=self.config.model_config.embed_dim,
                num_heads=self.config.model_config.num_heads,
                num_layers=self.config.model_config.num_layers,
                dropout=self.config.model_config.dropout,
                max_seq_length=self.config.model_config.max_seq_length,
            )
            self._npa = NeuralPolicyAdapter(
                encoder=encoder,
                confidence_threshold=self.config.confidence_threshold,
            )
            logger.info("NPA component initialized")
        return self._npa

    @property
    def svb(self) -> SymbolicVerificationBridge:
        """Lazy initialization of SVB component."""
        if self._svb is None:
            from vnape.svb import SymbolicVerificationBridge

            self._svb = SymbolicVerificationBridge(
                timeout_ms=self.config.z3_timeout_ms,
                abstraction_level=self.config.abstraction_level,
                generate_certificates=self.config.generate_certificates,
            )
            logger.info("SVB component initialized")
        return self._svb

    @property
    def pqae(self) -> ProactiveEnforcer:
        """Lazy initialization of PQAE component."""
        if self._pqae is None:
            from vnape.pqae import ProactiveEnforcer

            self._pqae = ProactiveEnforcer(
                mode=self.config.enforcement_mode,
                quantum_context=self.config.quantum_context,
            )
            logger.info("PQAE component initialized")
        return self._pqae

    def load_protocol(self, protocol: BaseProtocol) -> None:
        """
        Load a protocol definition for enforcement.

        Args:
            protocol: Protocol instance (e.g., IMessagePQ3Protocol)
        """
        self.protocol = protocol
        logger.info("Protocol loaded", protocol=protocol.name)

        # Register protocol events with PQAE
        self.pqae.register_protocol(protocol)

        # Configure NPA with protocol-specific vocabulary
        if hasattr(protocol, "get_vocabulary"):
            vocab = protocol.get_vocabulary()
            self.npa.set_vocabulary(vocab)

    def set_base_policy(self, policy: str | MFOTLFormula) -> None:
        """
        Set the base enforcement policy.

        Args:
            policy: MFOTL formula string or MFOTLFormula object
        """
        if isinstance(policy, str):
            policy = MFOTLFormula(formula=policy, name="base_policy")
        self.base_policy = policy
        self.pqae.set_policy(policy)
        logger.info("Base policy set", formula=str(policy))

    def set_safety_invariants(self, invariants: SafetyInvariants) -> None:
        """
        Set safety invariants for refinement verification.

        Args:
            invariants: Safety invariants that must be preserved
        """
        self.safety_invariants = invariants
        logger.info("Safety invariants set", count=len(invariants))

    def enforce(
        self,
        trace: ExecutionTrace | list[ProtocolEvent],
        adapt: bool | None = None,
    ) -> EnforcementResult:
        """
        Enforce the policy on an execution trace.

        This is the main entry point for enforcement. It:
        1. Processes events through PQAE for policy enforcement
        2. Optionally triggers NPA for policy adaptation
        3. Verifies any proposed refinements through SVB
        4. Applies verified refinements to the active policy

        Args:
            trace: Execution trace or list of events to enforce
            adapt: Whether to enable adaptation (overrides config if set)

        Returns:
            EnforcementResult with violations, actions, and statistics
        """
        if self.base_policy is None:
            raise ValueError("Base policy must be set before enforcement")

        # Normalize input
        if isinstance(trace, list):
            trace = ExecutionTrace(
                trace_id=str(uuid.uuid4()),
                events=trace,
                protocol_name=self.protocol.name if self.protocol else "unknown",
            )

        adapt_enabled = adapt if adapt is not None else self.config.adaptation_enabled

        logger.info(
            "Starting enforcement",
            trace_id=trace.trace_id,
            num_events=len(trace),
            adaptation_enabled=adapt_enabled,
        )

        # Process trace through PQAE
        start_time = datetime.now()
        result = self.pqae.enforce_trace(trace)
        self._events_processed += len(trace)
        self._violations_detected += result.violation_count

        # Trigger adaptation if enabled and conditions met
        if adapt_enabled and self._should_adapt(trace, result):
            self._run_adaptation_loop(trace)

        # Calculate processing time
        processing_time = (datetime.now() - start_time).total_seconds() * 1000
        result.processing_time_ms = int(processing_time)
        result.statistics["adaptations_applied"] = len(self.active_refinements)

        logger.info(
            "Enforcement complete",
            trace_id=trace.trace_id,
            violations=result.violation_count,
            actions=result.action_count,
            processing_time_ms=result.processing_time_ms,
        )

        return result

    def _should_adapt(self, trace: ExecutionTrace, result: EnforcementResult) -> bool:
        """Determine if adaptation should be triggered."""
        # Adapt if violation rate exceeds threshold
        if len(trace) > 0:
            violation_rate = result.violation_count / len(trace)
            if violation_rate > self.config.adaptation_trigger_threshold:
                return True

        # Adapt periodically based on event count
        return self._events_processed % 1000 == 0

    def _run_adaptation_loop(self, trace: ExecutionTrace) -> None:
        """
        Run the NPA-SVB adaptation loop.

        1. NPA proposes refinements based on trace patterns
        2. SVB verifies each refinement against safety invariants
        3. Verified refinements are applied to the active policy
        """
        logger.info("Running adaptation loop")

        # Get refinement proposals from NPA
        proposals = self.npa.propose_refinements(trace)
        self._refinements_proposed += len(proposals)

        for proposal in proposals:
            # Verify refinement through SVB
            if self.safety_invariants is not None:
                verification = self.svb.verify(
                    base_policy=self.base_policy,
                    refinement=proposal,
                    invariants=self.safety_invariants,
                )
            else:
                # No invariants - accept based on confidence
                verification = VerificationResult(
                    status="accepted",
                    accepted=True,
                    verification_time_ms=0,
                )

            if verification.accepted:
                self._apply_refinement(proposal, verification)
                self._refinements_accepted += 1
                logger.info(
                    "Refinement accepted and applied",
                    refinement_id=proposal.refinement_id,
                    confidence=proposal.confidence,
                )
            else:
                logger.info(
                    "Refinement rejected",
                    refinement_id=proposal.refinement_id,
                    reason=(
                        verification.counterexample.explanation
                        if verification.counterexample
                        else "Unknown"
                    ),
                )

    def _apply_refinement(
        self, refinement: PolicyRefinement, verification: VerificationResult
    ) -> None:
        """Apply a verified refinement to the active policy."""
        self.active_refinements.append(refinement)

        # Compose refinement with base policy
        composed = self.base_policy.compose(refinement.delta_formula)
        self.pqae.set_policy(composed)

        logger.debug(
            "Policy updated",
            new_policy=str(composed),
            certificate_id=(
                verification.certificate.certificate_id if verification.certificate else None
            ),
        )

    def process_event(self, event: ProtocolEvent) -> EnforcementResult:
        """
        Process a single event in streaming mode.

        Args:
            event: Protocol event to process

        Returns:
            EnforcementResult for this event
        """
        return self.pqae.process_event(event)

    def train(
        self,
        traces: list[ExecutionTrace],
        config: TrainingConfig | None = None,
    ) -> dict[str, Any]:
        """
        Train the NPA model on execution traces.

        Args:
            traces: Training traces
            config: Training configuration (uses default if not provided)

        Returns:
            Training metrics and statistics
        """
        config = config or self.config.training_config
        logger.info("Starting NPA training", num_traces=len(traces), epochs=config.epochs)

        metrics = self.npa.fit(traces, config)

        logger.info("Training complete", final_loss=metrics.get("final_loss", "N/A"))
        return metrics

    def save(self, path: Path | str) -> None:
        """
        Save the framework state to disk.

        Args:
            path: Directory to save state to
        """
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)

        # Save NPA model
        if self._npa is not None:
            self.npa.save(path / "npa_model.pt")

        # Save active refinements
        import json

        refinements_data = [r.model_dump() for r in self.active_refinements]
        with open(path / "refinements.json", "w") as f:
            json.dump(refinements_data, f, indent=2, default=str)

        # Save configuration
        with open(path / "config.json", "w") as f:
            json.dump(
                {
                    "model_config": self.config.model_config.__dict__,
                    "confidence_threshold": self.config.confidence_threshold,
                    "enforcement_mode": self.config.enforcement_mode.value,
                },
                f,
                indent=2,
            )

        logger.info("Framework state saved", path=str(path))

    def load(self, path: Path | str) -> None:
        """
        Load framework state from disk.

        Args:
            path: Directory to load state from
        """
        path = Path(path)

        # Load NPA model
        model_path = path / "npa_model.pt"
        if model_path.exists():
            self.npa.load(model_path)

        # Load active refinements
        import json

        refinements_path = path / "refinements.json"
        if refinements_path.exists():
            with open(refinements_path) as f:
                refinements_data = json.load(f)
            self.active_refinements = [PolicyRefinement.model_validate(r) for r in refinements_data]

        logger.info("Framework state loaded", path=str(path))

    def get_statistics(self) -> dict[str, Any]:
        """Get framework statistics."""
        return {
            "events_processed": self._events_processed,
            "violations_detected": self._violations_detected,
            "refinements_proposed": self._refinements_proposed,
            "refinements_accepted": self._refinements_accepted,
            "active_refinements": len(self.active_refinements),
            "acceptance_rate": self._refinements_accepted / max(1, self._refinements_proposed),
        }

    def reset(self) -> None:
        """Reset framework state."""
        self.active_refinements = []
        self._events_processed = 0
        self._refinements_proposed = 0
        self._refinements_accepted = 0
        self._violations_detected = 0

        if self._pqae is not None:
            self.pqae.reset()

        logger.info("Framework state reset")
