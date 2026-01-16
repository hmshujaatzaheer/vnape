"""
Refinement Generator for Neural Policy Adaptation

Generates MFOTL policy refinements from detected patterns.
Translates neural pattern detections into formal temporal logic
formulas that can extend or modify the base policy.

Refinement Types:
1. Conjunctive Extension: φ_base ∧ φ_new
2. Parameter Tightening: Reduce time bounds
3. Scope Restriction: Add quantifier constraints
4. Exception Addition: Add exception clauses

Reference: Section 4.1 of the V-NAPE proposal
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import torch
import torch.nn as nn
import torch.nn.functional as F

from vnape.core.types import (
    MFOTLFormula,
    PolicyRefinement,
    RefinementType,
)
from vnape.npa.pattern_detector import DetectedPattern, PatternType


@dataclass
class RefinementTemplate:
    """Template for generating MFOTL refinements."""

    template_id: str
    refinement_type: RefinementType
    formula_template: str
    description: str
    applicable_patterns: list[PatternType]
    parameters: dict[str, Any]


# Standard refinement templates
REFINEMENT_TEMPLATES = [
    RefinementTemplate(
        template_id="temporal_constraint",
        refinement_type=RefinementType.PARAMETER_TIGHTENING,
        formula_template="□[0,{interval}] ({condition} → ◇[0,{deadline}] {consequence})",
        description="Add temporal deadline constraint",
        applicable_patterns=[PatternType.TEMPORAL_ANOMALY],
        parameters={"interval": 1000, "deadline": 100},
    ),
    RefinementTemplate(
        template_id="sequence_constraint",
        refinement_type=RefinementType.CONJUNCTIVE_EXTENSION,
        formula_template="□[0,∞) ({event_a} → ○[0,{gap}] {event_b})",
        description="Enforce event sequence ordering",
        applicable_patterns=[PatternType.SEQUENCE_ANOMALY],
        parameters={"gap": 50},
    ),
    RefinementTemplate(
        template_id="value_constraint",
        refinement_type=RefinementType.SCOPE_RESTRICTION,
        formula_template="∀{var}. ({predicate}({var}) ∧ {condition}) → {consequence}",
        description="Add value-based constraint",
        applicable_patterns=[PatternType.VALUE_ANOMALY],
        parameters={},
    ),
    RefinementTemplate(
        template_id="frequency_constraint",
        refinement_type=RefinementType.PARAMETER_TIGHTENING,
        formula_template="□[0,{window}] (¬∃>{count} {var}. {predicate}({var}))",
        description="Limit event frequency",
        applicable_patterns=[PatternType.FREQUENCY_ANOMALY],
        parameters={"window": 1000, "count": 10},
    ),
    RefinementTemplate(
        template_id="missing_event",
        refinement_type=RefinementType.CONJUNCTIVE_EXTENSION,
        formula_template="□[0,∞) ({trigger} → ◇[0,{timeout}] {required_event})",
        description="Require expected event",
        applicable_patterns=[PatternType.MISSING_EVENT],
        parameters={"timeout": 500},
    ),
    RefinementTemplate(
        template_id="exception_clause",
        refinement_type=RefinementType.EXCEPTION_ADDITION,
        formula_template="□[0,∞) (({condition} ∧ ¬{exception}) → {consequence})",
        description="Add exception to existing rule",
        applicable_patterns=[PatternType.SEQUENCE_ANOMALY, PatternType.VALUE_ANOMALY],
        parameters={},
    ),
]


class RefinementDecoder(nn.Module):
    """
    Neural decoder for generating refinement specifications.

    Takes pattern features and generates:
    1. Template selection logits
    2. Parameter values
    3. Confidence score
    """

    def __init__(
        self,
        embed_dim: int = 256,
        num_templates: int = 6,
        max_params: int = 10,
    ):
        super().__init__()

        self.embed_dim = embed_dim
        self.num_templates = num_templates
        self.max_params = max_params

        # Template selection head
        self.template_selector = nn.Sequential(
            nn.Linear(embed_dim, embed_dim // 2),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(embed_dim // 2, num_templates),
        )

        # Parameter generation head
        self.param_generator = nn.Sequential(
            nn.Linear(embed_dim + num_templates, embed_dim),
            nn.ReLU(),
            nn.Linear(embed_dim, max_params),
        )

        # Confidence estimation head
        self.confidence_estimator = nn.Sequential(
            nn.Linear(embed_dim, embed_dim // 4),
            nn.ReLU(),
            nn.Linear(embed_dim // 4, 1),
            nn.Sigmoid(),
        )

    def forward(
        self,
        pattern_features: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Generate refinement specifications.

        Args:
            pattern_features: (batch_size, embed_dim) aggregated pattern features

        Returns:
            Tuple of (template_logits, parameters, confidence)
        """
        # Select template
        template_logits = self.template_selector(pattern_features)
        template_probs = F.softmax(template_logits, dim=-1)

        # Generate parameters conditioned on template
        param_input = torch.cat([pattern_features, template_probs], dim=-1)
        parameters = self.param_generator(param_input)

        # Estimate confidence
        confidence = self.confidence_estimator(pattern_features)

        return template_logits, parameters, confidence


class FormulaBuilder:
    """
    Builds MFOTL formulas from templates and parameters.

    Handles:
    - Template instantiation with learned parameters
    - Formula composition
    - Syntax validation
    """

    def __init__(self, templates: list[RefinementTemplate] | None = None):
        self.templates = templates or REFINEMENT_TEMPLATES
        self.template_map = {t.template_id: t for t in self.templates}

    def build_formula(
        self,
        template_id: str,
        params: dict[str, Any],
        context: dict[str, str] | None = None,
    ) -> MFOTLFormula:
        """
        Build an MFOTL formula from a template.

        Args:
            template_id: ID of the template to use
            params: Parameter values
            context: Variable name context (predicates, etc.)

        Returns:
            Constructed MFOTLFormula
        """
        template = self.template_map.get(template_id)
        if template is None:
            raise ValueError(f"Unknown template: {template_id}")

        # Merge default params with provided
        all_params = {**template.parameters, **params}

        # Add context variables
        if context:
            all_params.update(context)

        # Build formula string
        try:
            formula_str = template.formula_template.format(**all_params)
        except KeyError:
            # Missing parameter - use placeholder
            formula_str = template.formula_template
            for key in all_params:
                formula_str = formula_str.replace(f"{{{key}}}", str(all_params[key]))

        return MFOTLFormula(
            formula=formula_str,
            name=template.template_id,
            description=template.description,
        )

    def build_from_pattern(
        self,
        pattern: DetectedPattern,
        trace_context: dict[str, Any] | None = None,
    ) -> MFOTLFormula:
        """
        Build a formula appropriate for a detected pattern.

        Args:
            pattern: Detected pattern
            trace_context: Context from the trace (event names, etc.)

        Returns:
            Appropriate MFOTLFormula
        """
        # Find applicable templates
        applicable = [t for t in self.templates if pattern.pattern_type in t.applicable_patterns]

        if not applicable:
            # Default to conjunctive extension
            applicable = [t for t in self.templates if t.template_id == "sequence_constraint"]

        template = applicable[0]

        # Extract context from pattern
        context = trace_context or {}
        if pattern.metadata:
            context.update(pattern.metadata)

        # Build with default parameters scaled by confidence
        params = {
            k: int(v * (1.0 + (1.0 - pattern.confidence))) if isinstance(v, (int, float)) else v
            for k, v in template.parameters.items()
        }

        return self.build_formula(template.template_id, params, context)


class RefinementGenerator(nn.Module):
    """
    Main refinement generation module.

    Combines pattern detection results with neural decoding
    to produce verified policy refinement proposals.

    Architecture:
    1. Pattern aggregation: Combine multiple patterns
    2. Context encoding: Encode trace/policy context
    3. Refinement decoding: Generate refinement specifications
    4. Formula building: Convert to MFOTL formulas

    Args:
        embed_dim: Dimension of pattern embeddings
        num_templates: Number of refinement templates
        confidence_threshold: Minimum confidence for proposals

    Example:
        >>> generator = RefinementGenerator(embed_dim=256)
        >>> patterns = detector.detect(embeddings)
        >>> refinements = generator.generate(patterns, trace_context)
        >>> for ref in refinements:
        ...     print(f"{ref.delta_formula}: {ref.confidence:.2f}")
    """

    def __init__(
        self,
        embed_dim: int = 256,
        num_templates: int = 6,
        confidence_threshold: float = 0.6,
    ):
        super().__init__()

        self.embed_dim = embed_dim
        self.num_templates = num_templates
        self.confidence_threshold = confidence_threshold

        # Pattern aggregation
        self.pattern_aggregator = nn.Sequential(
            nn.Linear(embed_dim, embed_dim),
            nn.ReLU(),
            nn.Linear(embed_dim, embed_dim),
        )

        # Context encoder
        self.context_encoder = nn.Sequential(
            nn.Linear(embed_dim, embed_dim),
            nn.ReLU(),
        )

        # Refinement decoder
        self.decoder = RefinementDecoder(embed_dim, num_templates)

        # Formula builder
        self.formula_builder = FormulaBuilder()

        # Attention for pattern aggregation
        self.pattern_attention = nn.MultiheadAttention(
            embed_dim=embed_dim,
            num_heads=4,
            batch_first=True,
        )

    def aggregate_patterns(
        self,
        pattern_embeddings: torch.Tensor,
        pattern_scores: torch.Tensor,
    ) -> torch.Tensor:
        """
        Aggregate multiple pattern embeddings.

        Args:
            pattern_embeddings: (num_patterns, embed_dim)
            pattern_scores: (num_patterns,) confidence scores

        Returns:
            Aggregated pattern embedding (embed_dim,)
        """
        if pattern_embeddings.size(0) == 0:
            return torch.zeros(self.embed_dim, device=pattern_embeddings.device)

        # Weight by scores
        weights = F.softmax(pattern_scores, dim=0).unsqueeze(-1)
        weighted = pattern_embeddings * weights

        # Apply aggregation
        aggregated = self.pattern_aggregator(weighted.sum(dim=0))

        return aggregated

    def forward(
        self,
        pattern_embeddings: torch.Tensor,
        pattern_scores: torch.Tensor,
        context_embedding: torch.Tensor | None = None,
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Generate refinement specifications.

        Args:
            pattern_embeddings: (batch_size, num_patterns, embed_dim)
            pattern_scores: (batch_size, num_patterns)
            context_embedding: (batch_size, embed_dim) optional context

        Returns:
            Tuple of (template_logits, parameters, confidence)
        """
        batch_size = pattern_embeddings.size(0)

        # Aggregate patterns per batch
        aggregated = []
        for b in range(batch_size):
            agg = self.aggregate_patterns(pattern_embeddings[b], pattern_scores[b])
            aggregated.append(agg)
        aggregated = torch.stack(aggregated)

        # Add context if provided
        if context_embedding is not None:
            context_enc = self.context_encoder(context_embedding)
            aggregated = aggregated + context_enc

        # Decode refinements
        template_logits, parameters, confidence = self.decoder(aggregated)

        return template_logits, parameters, confidence

    def generate(
        self,
        patterns: list[DetectedPattern],
        trace_context: dict[str, Any] | None = None,
        max_refinements: int = 5,
    ) -> list[PolicyRefinement]:
        """
        Generate policy refinements from detected patterns.

        Args:
            patterns: List of detected patterns
            trace_context: Context from the analyzed trace
            max_refinements: Maximum number of refinements to generate

        Returns:
            List of PolicyRefinement proposals
        """
        if not patterns:
            return []

        refinements = []

        # Group patterns by type
        patterns_by_type: dict[PatternType, list[DetectedPattern]] = {}
        for p in patterns:
            if p.pattern_type not in patterns_by_type:
                patterns_by_type[p.pattern_type] = []
            patterns_by_type[p.pattern_type].append(p)

        # Generate refinement for each pattern type
        for pattern_type, type_patterns in patterns_by_type.items():
            if len(refinements) >= max_refinements:
                break

            # Take highest confidence pattern of this type
            best_pattern = max(type_patterns, key=lambda p: p.confidence)

            if best_pattern.confidence < self.confidence_threshold:
                continue

            # Build formula
            try:
                formula = self.formula_builder.build_from_pattern(
                    best_pattern,
                    trace_context,
                )

                # Determine refinement type
                applicable_templates = [
                    t
                    for t in self.formula_builder.templates
                    if pattern_type in t.applicable_patterns
                ]
                ref_type = (
                    applicable_templates[0].refinement_type
                    if applicable_templates
                    else RefinementType.CONJUNCTIVE_EXTENSION
                )

                refinement = PolicyRefinement(
                    refinement_id=str(uuid.uuid4()),
                    delta_formula=formula,
                    refinement_type=ref_type,
                    confidence=best_pattern.confidence,
                    evidence_count=len(type_patterns),
                    source_pattern=best_pattern.description,
                    created_at=datetime.now(),
                )

                refinements.append(refinement)

            except Exception:
                # Log but continue
                pass

        # Sort by confidence
        refinements.sort(key=lambda r: r.confidence, reverse=True)

        return refinements[:max_refinements]

    def generate_from_embeddings(
        self,
        embeddings: torch.Tensor,
        scores: torch.Tensor,
        trace_context: dict[str, Any] | None = None,
    ) -> list[PolicyRefinement]:
        """
        Generate refinements directly from embeddings (end-to-end).

        Args:
            embeddings: Pattern embeddings from encoder
            scores: Anomaly scores
            trace_context: Trace context

        Returns:
            List of PolicyRefinement proposals
        """
        # Get template predictions
        template_logits, params, confidence = self.forward(
            embeddings.unsqueeze(0), scores.unsqueeze(0)
        )

        template_idx = template_logits.argmax(dim=-1).item()
        conf_val = confidence.item()

        if conf_val < self.confidence_threshold:
            return []

        # Map index to template
        templates = self.formula_builder.templates
        if template_idx >= len(templates):
            template_idx = 0

        template = templates[template_idx]

        # Extract parameters
        param_values = params[0].tolist()
        param_dict = {}
        for i, (key, _) in enumerate(template.parameters.items()):
            if i < len(param_values):
                param_dict[key] = int(abs(param_values[i]) * 1000)  # Scale

        # Build formula
        formula = self.formula_builder.build_formula(
            template.template_id,
            param_dict,
            trace_context,
        )

        return [
            PolicyRefinement(
                refinement_id=str(uuid.uuid4()),
                delta_formula=formula,
                refinement_type=template.refinement_type,
                confidence=conf_val,
                evidence_count=1,
                source_pattern=f"Neural prediction (template: {template.template_id})",
                created_at=datetime.now(),
            )
        ]
