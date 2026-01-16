"""
Proactive Enforcer - Runtime enforcement engine for V-NAPE.

This module implements:
1. Policy enforcement with configurable modes (STRICT/PERMISSIVE/AUDIT)
2. Real-time decision making based on MFOTL monitoring verdicts
3. Integration with quantum threat context for risk-adjusted enforcement
4. Enforcement action generation and execution

Based on Thesis Section 4.3.3: Enforcement Strategies and Algorithm 2

Enforcement Modes:
- STRICT: Block all policy violations immediately
- PERMISSIVE: Log violations but allow execution with warnings
- AUDIT: Log only, no enforcement actions taken
"""

from __future__ import annotations

import copy
import logging
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any

from vnape.core.types import (
    EnforcementAction,
    EnforcementMode,
    EnforcementResult,
    ExecutionTrace,
    PolicyRefinement,
    PolicyViolation,
    ProtocolEvent,
    ThreatLevel,
)
from vnape.pqae.monitor import (
    MFOTLMonitor,
    MFOTLParser,
    TraceEvent,
    Verdict,
)
from vnape.pqae.quantum_context import (
    QuantumRiskLevel,
    QuantumThreatContext,
    ThreatAssessment,
)

logger = logging.getLogger(__name__)


class ActionType(Enum):
    """Types of enforcement actions."""

    ALLOW = auto()  # Allow the operation to proceed
    BLOCK = auto()  # Block the operation
    DELAY = auto()  # Delay the operation for further checks
    MODIFY = auto()  # Modify the operation parameters
    LOG = auto()  # Log the operation for audit
    ALERT = auto()  # Generate an alert
    TERMINATE = auto()  # Terminate the session
    RENEGOTIATE = auto()  # Force protocol renegotiation


@dataclass
class EnforcementDecision:
    """
    Decision output from the enforcement oracle.
    """

    action: ActionType

    # Confidence in the decision (0.0 - 1.0)
    confidence: float = 1.0

    # Reason for the decision
    reason: str = ""

    # Affected protocol events
    affected_events: list[str] = field(default_factory=list)

    # Suggested modifications (for MODIFY action)
    modifications: dict[str, Any] = field(default_factory=dict)

    # Delay duration in seconds (for DELAY action)
    delay_seconds: float = 0.0

    # Alert severity (for ALERT action)
    alert_severity: str = "INFO"

    # Timestamp of decision
    timestamp: datetime = field(default_factory=datetime.now)

    # Source monitor verdict that triggered this decision
    source_verdict: Verdict | None = None

    # Quantum risk adjustment applied
    quantum_adjusted: bool = False

    def is_blocking(self) -> bool:
        """Check if this decision blocks execution."""
        return self.action in {ActionType.BLOCK, ActionType.TERMINATE}

    def requires_response(self) -> bool:
        """Check if this decision requires a response to the system."""
        return self.action not in {ActionType.ALLOW, ActionType.LOG}


class EnforcementOracle(ABC):
    """
    Abstract base for enforcement decision making.

    The oracle takes monitoring verdicts and produces enforcement decisions
    based on configured policies and risk context.
    """

    @abstractmethod
    def decide(self, verdict: Verdict, context: dict[str, Any]) -> EnforcementDecision:
        """
        Make an enforcement decision based on a verdict.

        Args:
            verdict: The monitoring verdict
            context: Additional context (event details, history, etc.)

        Returns:
            Enforcement decision
        """
        pass


class DefaultEnforcementOracle(EnforcementOracle):
    """
    Default enforcement oracle with configurable mode and thresholds.
    """

    def __init__(
        self,
        mode: EnforcementMode = EnforcementMode.PERMISSIVE,
        violation_threshold: int = 3,
        alert_on_unknown: bool = True,
    ):
        """
        Initialize the default oracle.

        Args:
            mode: Enforcement mode (STRICT/PERMISSIVE/AUDIT)
            violation_threshold: Number of violations before escalation
            alert_on_unknown: Whether to generate alerts for UNKNOWN verdicts
        """
        self.mode = mode
        self.violation_threshold = violation_threshold
        self.alert_on_unknown = alert_on_unknown
        self._violation_count = 0

    def decide(self, verdict: Verdict, context: dict[str, Any]) -> EnforcementDecision:
        """Make enforcement decision based on verdict and mode."""

        if verdict == Verdict.SATISFIED:
            return EnforcementDecision(
                action=ActionType.ALLOW,
                confidence=1.0,
                reason="Policy satisfied",
                source_verdict=verdict,
            )

        elif verdict == Verdict.VIOLATED:
            self._violation_count += 1

            if self.mode == EnforcementMode.STRICT:
                return EnforcementDecision(
                    action=ActionType.BLOCK,
                    confidence=1.0,
                    reason=f"Policy violation in STRICT mode (count: {self._violation_count})",
                    source_verdict=verdict,
                )

            elif self.mode == EnforcementMode.PERMISSIVE:
                if self._violation_count >= self.violation_threshold:
                    return EnforcementDecision(
                        action=ActionType.BLOCK,
                        confidence=0.9,
                        reason=f"Violation threshold exceeded ({self._violation_count}/{self.violation_threshold})",
                        source_verdict=verdict,
                    )
                return EnforcementDecision(
                    action=ActionType.ALERT,
                    confidence=0.8,
                    reason=f"Policy violation in PERMISSIVE mode (count: {self._violation_count})",
                    alert_severity="WARNING",
                    source_verdict=verdict,
                )

            else:  # AUDIT mode
                return EnforcementDecision(
                    action=ActionType.LOG,
                    confidence=1.0,
                    reason=f"Policy violation logged (AUDIT mode, count: {self._violation_count})",
                    source_verdict=verdict,
                )

        elif verdict == Verdict.UNKNOWN:
            if self.alert_on_unknown and self.mode != EnforcementMode.AUDIT:
                return EnforcementDecision(
                    action=ActionType.DELAY,
                    confidence=0.5,
                    reason="Waiting for additional events to determine verdict",
                    delay_seconds=1.0,
                    source_verdict=verdict,
                )
            return EnforcementDecision(
                action=ActionType.ALLOW,
                confidence=0.5,
                reason="Verdict unknown, allowing with reduced confidence",
                source_verdict=verdict,
            )

        else:  # INCONCLUSIVE
            return EnforcementDecision(
                action=ActionType.LOG,
                confidence=0.3,
                reason="Verdict inconclusive",
                source_verdict=verdict,
            )

    def reset_violation_count(self):
        """Reset the violation counter."""
        self._violation_count = 0


class QuantumAwareOracle(EnforcementOracle):
    """
    Enforcement oracle that adjusts decisions based on quantum threat context.
    """

    def __init__(self, base_oracle: EnforcementOracle, quantum_context: QuantumThreatContext):
        """
        Initialize quantum-aware oracle.

        Args:
            base_oracle: Underlying oracle for base decisions
            quantum_context: Quantum threat context for risk adjustment
        """
        self.base_oracle = base_oracle
        self.quantum_context = quantum_context
        self._threat_assessment: ThreatAssessment | None = None

    def set_threat_assessment(self, assessment: ThreatAssessment):
        """Set current threat assessment for decision adjustment."""
        self._threat_assessment = assessment

    def decide(self, verdict: Verdict, context: dict[str, Any]) -> EnforcementDecision:
        """Make quantum-risk-adjusted enforcement decision."""

        # Get base decision
        decision = self.base_oracle.decide(verdict, context)

        # Apply quantum risk adjustments
        if self._threat_assessment:
            decision = self._apply_quantum_adjustment(decision, context)

        return decision

    def _apply_quantum_adjustment(
        self, decision: EnforcementDecision, context: dict[str, Any]
    ) -> EnforcementDecision:
        """Apply quantum threat context adjustments to decision."""

        if not self._threat_assessment:
            return decision

        adjusted = copy.copy(decision)
        adjusted.quantum_adjusted = True

        risk_level = self._threat_assessment.overall_risk

        # Escalate ALLOW decisions in high-risk contexts
        if decision.action == ActionType.ALLOW:
            if risk_level == QuantumRiskLevel.CRITICAL:
                # Even allowed operations get logged in critical risk
                adjusted.action = ActionType.LOG
                adjusted.reason += " [CRITICAL quantum risk: operation logged]"
            elif risk_level == QuantumRiskLevel.HIGH:
                # Reduce confidence in high risk scenarios
                adjusted.confidence *= 0.8
                adjusted.reason += " [HIGH quantum risk: reduced confidence]"

        # Escalate ALERT decisions in high-risk contexts
        elif decision.action == ActionType.ALERT:
            if risk_level in {QuantumRiskLevel.CRITICAL, QuantumRiskLevel.HIGH}:
                adjusted.action = ActionType.BLOCK
                adjusted.reason += f" [Escalated due to {risk_level.name} quantum risk]"
                adjusted.alert_severity = "CRITICAL"

        # Add delay in medium risk scenarios for additional verification
        elif decision.action == ActionType.DELAY:
            if risk_level == QuantumRiskLevel.CRITICAL:
                adjusted.delay_seconds *= 3.0
                adjusted.reason += " [Extended delay due to CRITICAL quantum risk]"
            elif risk_level == QuantumRiskLevel.HIGH:
                adjusted.delay_seconds *= 2.0
                adjusted.reason += " [Extended delay due to HIGH quantum risk]"

        # Enhance logging in all scenarios with quantum risk info
        if self._threat_assessment.hndl_risk_score > 50:
            if "hndl_risk" not in adjusted.modifications:
                adjusted.modifications["hndl_risk_score"] = self._threat_assessment.hndl_risk_score

        return adjusted


@dataclass
class EnforcementState:
    """State maintained by the proactive enforcer."""

    # Current enforcement mode
    mode: EnforcementMode = EnforcementMode.PERMISSIVE

    # Active policies being enforced
    active_policies: list[str] = field(default_factory=list)

    # Currently active monitors
    monitors: dict[str, MFOTLMonitor] = field(default_factory=dict)

    # Decision history
    decision_history: list[EnforcementDecision] = field(default_factory=list)

    # Violation log
    violations: list[PolicyViolation] = field(default_factory=list)

    # Session statistics
    events_processed: int = 0
    violations_detected: int = 0
    decisions_made: int = 0
    blocks_issued: int = 0

    # Start time
    start_time: datetime = field(default_factory=datetime.now)


class ProactiveEnforcer:
    """
    Main proactive enforcement engine for V-NAPE.

    Implements Algorithm 2 from the thesis:
    1. Monitor protocol events against MFOTL policies
    2. Make enforcement decisions based on monitoring verdicts
    3. Apply quantum threat context adjustments
    4. Execute enforcement actions
    5. Generate verified refinements for adaptation

    The enforcer operates in three modes:
    - STRICT: Zero-tolerance for policy violations
    - PERMISSIVE: Allow with warnings, block on threshold
    - AUDIT: Log only, no enforcement
    """

    def __init__(
        self,
        mode: EnforcementMode = EnforcementMode.PERMISSIVE,
        quantum_context: QuantumThreatContext | None = None,
        base_policy: str | None = None,
    ):
        """
        Initialize the proactive enforcer.

        Args:
            mode: Enforcement mode
            quantum_context: Optional quantum threat context
            base_policy: Optional base MFOTL policy string
        """
        self.mode = mode
        self.quantum_context = quantum_context
        self.state = EnforcementState(mode=mode)

        # Initialize oracle
        base_oracle = DefaultEnforcementOracle(mode=mode)
        if quantum_context:
            self.oracle = QuantumAwareOracle(base_oracle, quantum_context)
        else:
            self.oracle = base_oracle

        # Parser for MFOTL formulas
        self.parser = MFOTLParser()

        # Action handlers
        self._action_handlers: dict[ActionType, Callable] = {}

        # Callbacks for events
        self._on_violation: Callable[[PolicyViolation], None] | None = None
        self._on_decision: Callable[[EnforcementDecision], None] | None = None

        # Add base policy if provided
        if base_policy:
            self.add_policy("base", base_policy)

        logger.info(f"ProactiveEnforcer initialized in {mode.name} mode")

    def register_protocol(self, protocol) -> None:
        """
        Register a protocol for enforcement.
        
        Loads the protocol's base policies into the enforcer.
        Policies that cannot be parsed (e.g., with Unicode operators)
        are skipped gracefully.
        
        Args:
            protocol: Protocol instance with get_base_policies() method
        """
        registered = 0
        for i, policy in enumerate(protocol.get_base_policies()):
            try:
                self.add_policy(f"{protocol.name}_policy_{i}", policy)
                registered += 1
            except ValueError as e:
                # Skip policies that can't be parsed (e.g., Unicode operators)
                logger.debug(f"Skipped policy {i}: {e}")
        logger.info(f"Registered protocol: {protocol.name} ({registered} policies)")

    def add_policy(self, name: str, formula: str):
        """
        Add a policy to be enforced.

        Args:
            name: Unique name for the policy
            formula: MFOTL formula string
        """
        try:
            parsed = self.parser.parse(formula)
            monitor = MFOTLMonitor(parsed)
            self.state.monitors[name] = monitor
            self.state.active_policies.append(name)
            logger.info(f"Added policy '{name}': {formula}")
        except Exception as e:
            logger.error(f"Failed to add policy '{name}': {e}")
            raise

    def remove_policy(self, name: str):
        """Remove a policy from enforcement."""
        if name in self.state.monitors:
            del self.state.monitors[name]
            self.state.active_policies.remove(name)
            logger.info(f"Removed policy '{name}'")

    def apply_refinement(self, refinement: PolicyRefinement) -> bool:
        """
        Apply a verified policy refinement.

        Args:
            refinement: The policy refinement to apply

        Returns:
            True if refinement was applied successfully
        """
        if not refinement.verification_status:
            logger.warning(f"Refusing to apply unverified refinement: {refinement.name}")
            return False

        try:
            # Add as new policy or modify existing
            self.add_policy(f"refinement_{refinement.name}", refinement.mfotl_formula)
            logger.info(f"Applied refinement: {refinement.name}")
            return True
        except Exception as e:
            logger.error(f"Failed to apply refinement: {e}")
            return False

    def process_event(self, event: ProtocolEvent) -> EnforcementResult:
        """
        Process a single protocol event through all active policies.

        This is the main entry point for runtime enforcement.

        Args:
            event: Protocol event to process

        Returns:
            Enforcement result with decision and any actions taken
        """
        self.state.events_processed += 1

        # Convert to trace event format
        trace_event = self._to_trace_event(event)

        # Monitor against all active policies
        verdicts: dict[str, Verdict] = {}
        for name, monitor in self.state.monitors.items():
            try:
                result = monitor.process_event(trace_event)
                verdicts[name] = result.verdict
            except Exception as e:
                logger.error(f"Error monitoring policy '{name}': {e}")
                verdicts[name] = Verdict.INCONCLUSIVE

        # Aggregate verdicts
        aggregated_verdict = self._aggregate_verdicts(verdicts)

        # Make enforcement decision
        decision = self.oracle.decide(
            aggregated_verdict,
            {
                "event": event,
                "verdicts": verdicts,
                "history_length": len(self.state.decision_history),
            },
        )

        self.state.decisions_made += 1
        self.state.decision_history.append(decision)

        # Execute decision
        action_result = self._execute_decision(decision, event)

        # Record violation if applicable
        if aggregated_verdict == Verdict.VIOLATED:
            self.state.violations_detected += 1
            violation = PolicyViolation(
                policy_name=",".join(k for k, v in verdicts.items() if v == Verdict.VIOLATED),
                timestamp=event.timestamp,
                event_data=event.model_dump() if hasattr(event, "model_dump") else str(event),
                severity=self._verdict_to_threat_level(aggregated_verdict),
            )
            self.state.violations.append(violation)

            if self._on_violation:
                self._on_violation(violation)

        # Trigger decision callback
        if self._on_decision:
            self._on_decision(decision)

        # Build result
        enforcement_action = EnforcementAction(
            action_type=decision.action.name,
            target="event",
            parameters=decision.modifications,
            confidence=decision.confidence,
        )

        return EnforcementResult(
            action=enforcement_action,
            success=not decision.is_blocking(),
            violations=(
                [v.model_dump() for v in self.state.violations[-1:]]
                if self.state.violations
                else []
            ),
            timestamp=datetime.now(),
        )

    def process_trace(self, trace: ExecutionTrace) -> list[EnforcementResult]:
        """
        Process an entire execution trace.

        Args:
            trace: Execution trace to process

        Returns:
            List of enforcement results for each event
        """
        results = []
        for event in trace.events:
            result = self.process_event(event)
            results.append(result)

            # Stop processing if blocked
            if not result.success and self.mode == EnforcementMode.STRICT:
                logger.warning("Trace processing halted due to enforcement block")
                break

        return results

    def _to_trace_event(self, event: ProtocolEvent) -> TraceEvent:
        """Convert ProtocolEvent to MFOTL TraceEvent format."""
        relations: dict[str, list[tuple[Any, ...]]] = {}

        # Add event type as a relation
        relations[event.event_type] = [(event.session_id,)]

        # Add data fields as relations
        for key, value in event.data.items():
            relation_name = f"{event.event_type}_{key}"
            if isinstance(value, (list, tuple)):
                relations[relation_name] = [tuple(value)]
            else:
                relations[relation_name] = [(event.session_id, value)]

        # Add source as relation
        relations["source"] = [(event.session_id, event.source)]

        return TraceEvent(timestamp=event.timestamp, relations=relations)

    def _aggregate_verdicts(self, verdicts: dict[str, Verdict]) -> Verdict:
        """
        Aggregate multiple policy verdicts into a single verdict.

        Strategy: Most restrictive verdict wins
        """
        if not verdicts:
            return Verdict.UNKNOWN

        verdict_values = list(verdicts.values())

        # Priority: VIOLATED > UNKNOWN > INCONCLUSIVE > SATISFIED
        if Verdict.VIOLATED in verdict_values:
            return Verdict.VIOLATED
        elif Verdict.UNKNOWN in verdict_values:
            return Verdict.UNKNOWN
        elif Verdict.INCONCLUSIVE in verdict_values:
            return Verdict.INCONCLUSIVE
        else:
            return Verdict.SATISFIED

    def _execute_decision(
        self, decision: EnforcementDecision, event: ProtocolEvent
    ) -> dict[str, Any]:
        """Execute an enforcement decision."""
        result: dict[str, Any] = {"decision": decision.action.name}

        if decision.action == ActionType.BLOCK:
            self.state.blocks_issued += 1
            logger.warning(f"BLOCKED: {decision.reason}")
            result["blocked"] = True

        elif decision.action == ActionType.TERMINATE:
            self.state.blocks_issued += 1
            logger.critical(f"TERMINATE: {decision.reason}")
            result["terminated"] = True

        elif decision.action == ActionType.ALERT:
            logger.warning(f"ALERT [{decision.alert_severity}]: {decision.reason}")
            result["alert_raised"] = True

        elif decision.action == ActionType.DELAY:
            logger.info(f"DELAY ({decision.delay_seconds}s): {decision.reason}")
            result["delayed"] = True
            result["delay_seconds"] = decision.delay_seconds

        elif decision.action == ActionType.LOG:
            logger.info(f"LOG: {decision.reason}")
            result["logged"] = True

        elif decision.action == ActionType.ALLOW:
            result["allowed"] = True

        # Call registered handler if exists
        if decision.action in self._action_handlers:
            handler_result = self._action_handlers[decision.action](decision, event)
            result["handler_result"] = handler_result

        return result

    def _verdict_to_threat_level(self, verdict: Verdict) -> ThreatLevel:
        """Convert verdict to threat level."""
        if verdict == Verdict.VIOLATED:
            if self.mode == EnforcementMode.STRICT:
                return ThreatLevel.CRITICAL
            return ThreatLevel.HIGH
        elif verdict == Verdict.UNKNOWN:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW

    def register_action_handler(
        self, action: ActionType, handler: Callable[[EnforcementDecision, ProtocolEvent], Any]
    ):
        """Register a custom handler for an action type."""
        self._action_handlers[action] = handler

    def on_violation(self, callback: Callable[[PolicyViolation], None]):
        """Register callback for policy violations."""
        self._on_violation = callback

    def on_decision(self, callback: Callable[[EnforcementDecision], None]):
        """Register callback for enforcement decisions."""
        self._on_decision = callback

    def set_mode(self, mode: EnforcementMode):
        """Change enforcement mode."""
        self.mode = mode
        self.state.mode = mode

        # Update oracle mode if it's a DefaultEnforcementOracle
        if isinstance(self.oracle, DefaultEnforcementOracle):
            self.oracle.mode = mode
        elif isinstance(self.oracle, QuantumAwareOracle):
            if isinstance(self.oracle.base_oracle, DefaultEnforcementOracle):
                self.oracle.base_oracle.mode = mode

        logger.info(f"Enforcement mode changed to {mode.name}")

    def update_quantum_assessment(self, assessment: ThreatAssessment):
        """Update quantum threat assessment."""
        if isinstance(self.oracle, QuantumAwareOracle):
            self.oracle.set_threat_assessment(assessment)
            logger.info(f"Updated quantum assessment: {assessment.overall_risk.name} risk")

    def get_statistics(self) -> dict[str, Any]:
        """Get enforcement statistics."""
        uptime = (datetime.now() - self.state.start_time).total_seconds()

        return {
            "mode": self.mode.name,
            "uptime_seconds": uptime,
            "events_processed": self.state.events_processed,
            "violations_detected": self.state.violations_detected,
            "decisions_made": self.state.decisions_made,
            "blocks_issued": self.state.blocks_issued,
            "active_policies": len(self.state.active_policies),
            "policy_names": self.state.active_policies,
            "violation_rate": (
                self.state.violations_detected / self.state.events_processed
                if self.state.events_processed > 0
                else 0.0
            ),
            "block_rate": (
                self.state.blocks_issued / self.state.decisions_made
                if self.state.decisions_made > 0
                else 0.0
            ),
        }

    def get_violation_summary(self) -> dict[str, Any]:
        """Get summary of detected violations."""
        by_policy: dict[str, int] = {}
        by_severity: dict[str, int] = {}

        for violation in self.state.violations:
            # Count by policy
            policy = violation.policy_name
            by_policy[policy] = by_policy.get(policy, 0) + 1

            # Count by severity
            severity = violation.severity.name
            by_severity[severity] = by_severity.get(severity, 0) + 1

        return {
            "total": len(self.state.violations),
            "by_policy": by_policy,
            "by_severity": by_severity,
            "recent": [
                {
                    "policy": v.policy_name,
                    "timestamp": v.timestamp,
                    "severity": v.severity.name,
                }
                for v in self.state.violations[-10:]  # Last 10
            ],
        }

    def reset(self):
        """Reset enforcer state."""
        # Keep policies but reset state
        monitors = self.state.monitors
        policies = self.state.active_policies

        self.state = EnforcementState(mode=self.mode)
        self.state.monitors = monitors
        self.state.active_policies = policies

        # Reset oracle state
        if isinstance(self.oracle, DefaultEnforcementOracle):
            self.oracle.reset_violation_count()
        elif isinstance(self.oracle, QuantumAwareOracle):
            if isinstance(self.oracle.base_oracle, DefaultEnforcementOracle):
                self.oracle.base_oracle.reset_violation_count()

        logger.info("Enforcer state reset")

    def export_state(self) -> dict[str, Any]:
        """Export enforcer state for persistence."""
        return {
            "mode": self.mode.name,
            "policies": {
                name: str(monitor.formula) for name, monitor in self.state.monitors.items()
            },
            "statistics": self.get_statistics(),
            "violations": self.get_violation_summary(),
        }

    @classmethod
    def from_state(
        cls, state: dict[str, Any], quantum_context: QuantumThreatContext | None = None
    ) -> ProactiveEnforcer:
        """Create enforcer from exported state."""
        mode = EnforcementMode[state.get("mode", "PERMISSIVE")]
        enforcer = cls(mode=mode, quantum_context=quantum_context)

        # Restore policies
        for name, formula in state.get("policies", {}).items():
            enforcer.add_policy(name, formula)

        return enforcer
