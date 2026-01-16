"""
Pattern Detector for Neural Policy Adaptation

Identifies security-relevant patterns in encoded protocol traces.
Uses attention-based anomaly detection to find:
1. Temporal anomalies (unusual event timing)
2. Sequence anomalies (unexpected event orderings)
3. Value anomalies (unusual parameter values)
4. Missing event patterns (expected events that don't occur)

These detected patterns form the basis for policy refinement proposals.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Any

import torch
import torch.nn as nn
import torch.nn.functional as F


class PatternType(Enum):
    """Types of detectable security patterns."""

    TEMPORAL_ANOMALY = auto()
    SEQUENCE_ANOMALY = auto()
    VALUE_ANOMALY = auto()
    MISSING_EVENT = auto()
    FREQUENCY_ANOMALY = auto()
    CORRELATION_BREAK = auto()


@dataclass
class DetectedPattern:
    """A detected security-relevant pattern."""

    pattern_type: PatternType
    event_indices: list[int]
    confidence: float
    description: str
    attention_scores: torch.Tensor | None = None
    metadata: dict[str, Any] | None = None


class AttentionAnomalyDetector(nn.Module):
    """
    Uses self-attention patterns to detect anomalies.

    Normal behavior creates predictable attention patterns.
    Anomalies manifest as unusual attention distributions.
    """

    def __init__(self, embed_dim: int, num_heads: int = 4):
        super().__init__()
        self.embed_dim = embed_dim
        self.num_heads = num_heads

        # Learn "normal" attention patterns
        self.query_proj = nn.Linear(embed_dim, embed_dim)
        self.key_proj = nn.Linear(embed_dim, embed_dim)
        self.value_proj = nn.Linear(embed_dim, embed_dim)

        # Anomaly scoring
        self.anomaly_scorer = nn.Sequential(
            nn.Linear(embed_dim, embed_dim // 2),
            nn.ReLU(),
            nn.Linear(embed_dim // 2, 1),
        )

        # Pattern classification
        self.pattern_classifier = nn.Linear(embed_dim, len(PatternType))

    def forward(
        self,
        embeddings: torch.Tensor,
        attention_mask: torch.Tensor | None = None,
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Detect anomalies in embeddings.

        Args:
            embeddings: (batch_size, seq_len, embed_dim)
            attention_mask: (batch_size, seq_len)

        Returns:
            Tuple of (anomaly_scores, pattern_logits, attention_weights)
        """
        batch_size, seq_len, _ = embeddings.shape

        # Compute attention
        Q = self.query_proj(embeddings)
        K = self.key_proj(embeddings)
        V = self.value_proj(embeddings)

        # Scaled dot-product attention
        scale = self.embed_dim**0.5
        attention_scores = torch.matmul(Q, K.transpose(-2, -1)) / scale

        if attention_mask is not None:
            # Mask out padded positions
            mask = attention_mask.unsqueeze(1).unsqueeze(2)
            attention_scores = attention_scores.masked_fill(~mask, float("-inf"))

        attention_weights = F.softmax(attention_scores, dim=-1)
        context = torch.matmul(attention_weights, V)

        # Compute anomaly scores for each position
        anomaly_scores = self.anomaly_scorer(context).squeeze(-1)

        # Classify pattern types
        pattern_logits = self.pattern_classifier(context)

        return anomaly_scores, pattern_logits, attention_weights


class TemporalPatternDetector(nn.Module):
    """
    Detects temporal patterns and anomalies.

    Learns expected timing relationships between events and
    flags deviations from normal temporal patterns.
    """

    def __init__(self, embed_dim: int, hidden_dim: int = 128):
        super().__init__()

        # Temporal difference encoder
        self.time_diff_encoder = nn.Sequential(
            nn.Linear(1, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, embed_dim),
        )

        # LSTM for sequence modeling
        self.lstm = nn.LSTM(
            input_size=embed_dim,
            hidden_size=hidden_dim,
            num_layers=2,
            batch_first=True,
            bidirectional=True,
        )

        # Output projection
        self.output_proj = nn.Linear(hidden_dim * 2, embed_dim)

        # Anomaly detection head
        self.anomaly_head = nn.Sequential(
            nn.Linear(embed_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim, 1),
            nn.Sigmoid(),
        )

    def forward(
        self,
        embeddings: torch.Tensor,
        timestamps: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        """
        Detect temporal anomalies.

        Args:
            embeddings: (batch_size, seq_len, embed_dim)
            timestamps: (batch_size, seq_len)

        Returns:
            Tuple of (temporal_features, anomaly_scores)
        """
        batch_size, seq_len, _ = embeddings.shape

        # Compute time differences
        time_diffs = torch.zeros_like(timestamps, dtype=torch.float)
        time_diffs[:, 1:] = (timestamps[:, 1:] - timestamps[:, :-1]).float()
        time_diffs = time_diffs.unsqueeze(-1)  # (batch, seq, 1)

        # Encode time differences
        time_features = self.time_diff_encoder(time_diffs)

        # Combine with embeddings
        combined = embeddings + time_features

        # Process through LSTM
        lstm_out, _ = self.lstm(combined)
        temporal_features = self.output_proj(lstm_out)

        # Detect anomalies
        anomaly_scores = self.anomaly_head(temporal_features).squeeze(-1)

        return temporal_features, anomaly_scores


class SequencePatternDetector(nn.Module):
    """
    Detects sequence patterns and ordering anomalies.

    Learns expected event sequences and detects when
    events occur in unexpected orders.
    """

    def __init__(self, embed_dim: int, num_patterns: int = 64):
        super().__init__()

        # Learnable pattern prototypes
        self.pattern_prototypes = nn.Parameter(torch.randn(num_patterns, embed_dim))

        # Pattern matching network
        self.pattern_matcher = nn.Sequential(
            nn.Linear(embed_dim * 2, embed_dim),
            nn.ReLU(),
            nn.Linear(embed_dim, num_patterns),
        )

        # Sequence model
        self.gru = nn.GRU(
            input_size=embed_dim,
            hidden_size=embed_dim,
            num_layers=2,
            batch_first=True,
        )

        # Prediction head (next event prediction)
        self.predictor = nn.Linear(embed_dim, embed_dim)

        # Anomaly scoring
        self.anomaly_scorer = nn.Sequential(
            nn.Linear(embed_dim, embed_dim // 2),
            nn.ReLU(),
            nn.Linear(embed_dim // 2, 1),
            nn.Sigmoid(),
        )

    def forward(
        self,
        embeddings: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Detect sequence anomalies.

        Args:
            embeddings: (batch_size, seq_len, embed_dim)

        Returns:
            Tuple of (pattern_matches, predictions, anomaly_scores)
        """
        batch_size, seq_len, embed_dim = embeddings.shape

        # Process sequence
        gru_out, _ = self.gru(embeddings)

        # Predict next event (shifted)
        predictions = self.predictor(gru_out[:, :-1, :])
        actual_next = embeddings[:, 1:, :]

        # Compute prediction error as anomaly signal
        prediction_error = F.mse_loss(predictions, actual_next, reduction="none")
        prediction_error = prediction_error.mean(dim=-1)  # (batch, seq-1)

        # Pad to match original sequence length
        anomaly_scores = torch.zeros(batch_size, seq_len, device=embeddings.device)
        anomaly_scores[:, 1:] = prediction_error

        # Match against pattern prototypes
        # Expand for broadcasting: (batch, seq, 1, embed) vs (1, 1, patterns, embed)
        expanded_embed = embeddings.unsqueeze(2)
        expanded_proto = self.pattern_prototypes.unsqueeze(0).unsqueeze(0)

        # Compute similarity
        similarity = F.cosine_similarity(expanded_embed, expanded_proto, dim=-1)
        pattern_matches = F.softmax(similarity, dim=-1)

        return pattern_matches, predictions, anomaly_scores


class PatternDetector(nn.Module):
    """
    Main pattern detection module combining multiple detectors.

    Integrates:
    1. Attention-based anomaly detection
    2. Temporal pattern detection
    3. Sequence pattern detection

    Produces unified pattern detection results for refinement generation.

    Args:
        embed_dim: Dimension of input embeddings
        num_heads: Number of attention heads
        num_patterns: Number of learnable sequence patterns

    Example:
        >>> detector = PatternDetector(embed_dim=256)
        >>> patterns = detector.detect(embeddings, timestamps)
        >>> for p in patterns:
        ...     print(f"{p.pattern_type}: {p.description} ({p.confidence:.2f})")
    """

    def __init__(
        self,
        embed_dim: int = 256,
        num_heads: int = 4,
        num_patterns: int = 64,
        anomaly_threshold: float = 0.7,
    ):
        super().__init__()

        self.embed_dim = embed_dim
        self.anomaly_threshold = anomaly_threshold

        # Component detectors
        self.attention_detector = AttentionAnomalyDetector(embed_dim, num_heads)
        self.temporal_detector = TemporalPatternDetector(embed_dim)
        self.sequence_detector = SequencePatternDetector(embed_dim, num_patterns)

        # Fusion layer
        self.fusion = nn.Sequential(
            nn.Linear(embed_dim * 3, embed_dim),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(embed_dim, embed_dim),
        )

        # Final anomaly aggregation
        self.final_scorer = nn.Sequential(
            nn.Linear(3, 16),  # 3 anomaly scores from each detector
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid(),
        )

        # Pattern type classification
        self.type_classifier = nn.Linear(embed_dim, len(PatternType))

    def forward(
        self,
        embeddings: torch.Tensor,
        timestamps: torch.Tensor | None = None,
        attention_mask: torch.Tensor | None = None,
    ) -> tuple[torch.Tensor, torch.Tensor, dict[str, torch.Tensor]]:
        """
        Forward pass for pattern detection.

        Args:
            embeddings: (batch_size, seq_len, embed_dim)
            timestamps: (batch_size, seq_len) - optional
            attention_mask: (batch_size, seq_len) - optional

        Returns:
            Tuple of:
                - combined_features: (batch_size, seq_len, embed_dim)
                - anomaly_scores: (batch_size, seq_len)
                - component_outputs: dict with intermediate results
        """
        batch_size, seq_len, _ = embeddings.shape
        device = embeddings.device

        # Default timestamps if not provided
        if timestamps is None:
            timestamps = torch.arange(seq_len, device=device).unsqueeze(0).expand(batch_size, -1)

        # Run component detectors
        attn_scores, attn_patterns, attn_weights = self.attention_detector(
            embeddings, attention_mask
        )
        temporal_features, temporal_scores = self.temporal_detector(embeddings, timestamps)
        pattern_matches, seq_preds, seq_scores = self.sequence_detector(embeddings)

        # Fuse features
        combined_features = self.fusion(
            torch.cat([embeddings, temporal_features, embeddings], dim=-1)
        )

        # Aggregate anomaly scores
        stacked_scores = torch.stack([attn_scores, temporal_scores, seq_scores], dim=-1)
        final_scores = self.final_scorer(stacked_scores).squeeze(-1)

        # Collect component outputs
        component_outputs = {
            "attention_scores": attn_scores,
            "attention_weights": attn_weights,
            "attention_patterns": attn_patterns,
            "temporal_features": temporal_features,
            "temporal_scores": temporal_scores,
            "pattern_matches": pattern_matches,
            "sequence_predictions": seq_preds,
            "sequence_scores": seq_scores,
        }

        return combined_features, final_scores, component_outputs

    def detect(
        self,
        embeddings: torch.Tensor,
        timestamps: torch.Tensor | None = None,
        attention_mask: torch.Tensor | None = None,
        threshold: float | None = None,
    ) -> list[DetectedPattern]:
        """
        Detect patterns and return structured results.

        Args:
            embeddings: Encoded trace embeddings
            timestamps: Event timestamps
            attention_mask: Padding mask
            threshold: Anomaly threshold (default: self.anomaly_threshold)

        Returns:
            List of detected patterns
        """
        threshold = threshold or self.anomaly_threshold

        with torch.no_grad():
            features, scores, outputs = self.forward(embeddings, timestamps, attention_mask)

        patterns = []
        batch_size, seq_len, _ = embeddings.shape

        for b in range(batch_size):
            # Find positions exceeding threshold
            anomalous_positions = (scores[b] > threshold).nonzero(as_tuple=True)[0]

            for pos in anomalous_positions:
                pos_idx = pos.item()
                score = scores[b, pos_idx].item()

                # Determine pattern type based on which detector contributed most
                attn_contrib = outputs["attention_scores"][b, pos_idx].item()
                temp_contrib = outputs["temporal_scores"][b, pos_idx].item()
                seq_contrib = outputs["sequence_scores"][b, pos_idx].item()

                if temp_contrib >= max(attn_contrib, seq_contrib):
                    pattern_type = PatternType.TEMPORAL_ANOMALY
                    desc = f"Temporal anomaly at position {pos_idx}"
                elif seq_contrib >= max(attn_contrib, temp_contrib):
                    pattern_type = PatternType.SEQUENCE_ANOMALY
                    desc = f"Sequence anomaly at position {pos_idx}"
                else:
                    pattern_type = PatternType.VALUE_ANOMALY
                    desc = f"Value/attention anomaly at position {pos_idx}"

                patterns.append(
                    DetectedPattern(
                        pattern_type=pattern_type,
                        event_indices=[pos_idx],
                        confidence=score,
                        description=desc,
                        attention_scores=outputs["attention_weights"][b, :, pos_idx, :],
                        metadata={
                            "attention_contrib": attn_contrib,
                            "temporal_contrib": temp_contrib,
                            "sequence_contrib": seq_contrib,
                            "batch_idx": b,
                        },
                    )
                )

        return patterns

    def compute_loss(
        self,
        embeddings: torch.Tensor,
        timestamps: torch.Tensor,
        labels: torch.Tensor | None = None,
        attention_mask: torch.Tensor | None = None,
    ) -> torch.Tensor:
        """
        Compute training loss.

        Args:
            embeddings: Input embeddings
            timestamps: Event timestamps
            labels: Ground truth anomaly labels (optional, for supervised training)
            attention_mask: Padding mask

        Returns:
            Loss tensor
        """
        features, scores, outputs = self.forward(embeddings, timestamps, attention_mask)

        if labels is not None:
            # Supervised loss
            return F.binary_cross_entropy(scores, labels.float())
        else:
            # Self-supervised: predict sequence, penalize high variance
            seq_preds = outputs["sequence_predictions"]

            # Reconstruction loss (shifted)
            target = embeddings[:, 1:, :]
            recon_loss = F.mse_loss(seq_preds, target)

            # Temporal smoothness regularization
            score_diff = (scores[:, 1:] - scores[:, :-1]).abs()
            smooth_loss = score_diff.mean()

            return recon_loss + 0.1 * smooth_loss
