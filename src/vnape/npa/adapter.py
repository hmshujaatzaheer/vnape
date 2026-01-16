"""
Neural Policy Adapter

The main NPA component that integrates trace encoding, pattern detection,
and refinement generation into a unified interface for policy adaptation.

This implements Algorithm 1 from the V-NAPE proposal:
1. Encode trace using transformer-based encoder
2. Detect deviations/patterns using attention-based detector
3. Generate refinements using template-based generator
4. Compute confidence for each refinement

Example:
    >>> adapter = NeuralPolicyAdapter(encoder)
    >>> adapter.fit(training_traces)
    >>> refinements = adapter.propose_refinements(trace)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset

from vnape.core.types import (
    ExecutionTrace,
    PolicyRefinement,
    TrainingConfig,
)
from vnape.npa.encoder import TraceEncoder
from vnape.npa.generator import RefinementGenerator
from vnape.npa.pattern_detector import DetectedPattern, PatternDetector

logger = logging.getLogger(__name__)


class TraceDataset(Dataset):
    """PyTorch dataset for execution traces."""

    def __init__(
        self,
        traces: list[ExecutionTrace],
        encoder: TraceEncoder,
        max_length: int = 2048,
    ):
        self.traces = traces
        self.encoder = encoder
        self.max_length = max_length

    def __len__(self) -> int:
        return len(self.traces)

    def __getitem__(self, idx: int) -> dict[str, torch.Tensor]:
        trace = self.traces[idx]
        events = trace.events[: self.max_length]

        # Preprocess
        timestamps, relation_ids, numeric, strings, types = self.encoder._preprocess_trace(events)

        return {
            "timestamps": timestamps.squeeze(0),
            "relation_ids": relation_ids.squeeze(0),
            "numeric_values": numeric.squeeze(0),
            "string_hashes": strings.squeeze(0),
            "type_indicators": types.squeeze(0),
            "length": len(events),
        }


def collate_traces(batch: list[dict[str, torch.Tensor]]) -> dict[str, torch.Tensor]:
    """Collate function for variable-length traces."""
    max_len = max(item["length"] for item in batch)
    batch_size = len(batch)

    # Initialize padded tensors
    timestamps = torch.zeros(batch_size, max_len, dtype=torch.long)
    relation_ids = torch.zeros(batch_size, max_len, dtype=torch.long)
    numeric_values = torch.zeros(batch_size, max_len, 10)
    string_hashes = torch.zeros(batch_size, max_len, 10, dtype=torch.long)
    type_indicators = torch.zeros(batch_size, max_len, dtype=torch.long)
    attention_mask = torch.zeros(batch_size, max_len, dtype=torch.bool)

    for i, item in enumerate(batch):
        length = item["length"]
        timestamps[i, :length] = item["timestamps"][:length]
        relation_ids[i, :length] = item["relation_ids"][:length]
        numeric_values[i, :length] = item["numeric_values"][:length]
        string_hashes[i, :length] = item["string_hashes"][:length]
        type_indicators[i, :length] = item["type_indicators"][:length]
        attention_mask[i, :length] = True

    return {
        "timestamps": timestamps,
        "relation_ids": relation_ids,
        "numeric_values": numeric_values,
        "string_hashes": string_hashes,
        "type_indicators": type_indicators,
        "attention_mask": attention_mask,
    }


class NeuralPolicyAdapter(nn.Module):
    """
    Neural Policy Adapter (NPA) - Main Component

    Integrates trace encoding, pattern detection, and refinement generation
    for adaptive policy learning from protocol execution traces.

    The NPA component:
    1. Learns normal protocol behavior patterns from traces
    2. Detects anomalies and security-relevant deviations
    3. Generates policy refinement proposals with confidence scores
    4. Adapts to protocol-specific vocabularies and patterns

    Args:
        encoder: TraceEncoder instance for trace encoding
        detector: PatternDetector instance (created if not provided)
        generator: RefinementGenerator instance (created if not provided)
        confidence_threshold: Minimum confidence for refinement proposals
        device: Computation device (cuda/cpu)

    Attributes:
        encoder: Trace encoding transformer
        detector: Pattern detection module
        generator: Refinement generation module
        is_trained: Whether the model has been trained

    Example:
        >>> encoder = TraceEncoder(embed_dim=256, num_heads=8, num_layers=6)
        >>> adapter = NeuralPolicyAdapter(encoder, confidence_threshold=0.8)
        >>>
        >>> # Train on historical traces
        >>> adapter.fit(training_traces, epochs=100)
        >>>
        >>> # Propose refinements for new traces
        >>> refinements = adapter.propose_refinements(new_trace)
        >>> for ref in refinements:
        ...     print(f"Refinement: {ref.delta_formula}")
        ...     print(f"Confidence: {ref.confidence:.3f}")
        ...     print(f"Type: {ref.refinement_type}")
    """

    def __init__(
        self,
        encoder: TraceEncoder | None = None,
        detector: PatternDetector | None = None,
        generator: RefinementGenerator | None = None,
        confidence_threshold: float = 0.8,
        device: str = "cpu",
    ):
        super().__init__()

        # Get embed_dim from encoder or use default
        embed_dim = encoder.embed_dim if encoder else 256

        # Initialize components
        self.encoder = encoder or TraceEncoder(embed_dim=embed_dim)
        self.detector = detector or PatternDetector(embed_dim=embed_dim)
        self.generator = generator or RefinementGenerator(
            embed_dim=embed_dim,
            confidence_threshold=confidence_threshold,
        )

        self.confidence_threshold = confidence_threshold
        self.device = torch.device(device)
        self.is_trained = False

        # Move to device
        self.to(self.device)

        # Vocabulary for protocol-specific terms
        self._vocabulary: dict[str, int] = {}

        # Training state
        self._optimizer: optim.Optimizer | None = None
        self._scheduler: optim.lr_scheduler.LRScheduler | None = None
        self._best_loss = float("inf")

    def to(self, device: torch.device | str) -> NeuralPolicyAdapter:
        """Move adapter to device."""
        self.device = torch.device(device) if isinstance(device, str) else device
        self.encoder.to(self.device)
        self.detector.to(self.device)
        self.generator.to(self.device)
        return super().to(device)

    def set_vocabulary(self, vocabulary: dict[str, int]) -> None:
        """
        Set protocol-specific vocabulary for relation encoding.

        Args:
            vocabulary: Mapping from relation names to indices
        """
        self._vocabulary = vocabulary
        for relation, idx in vocabulary.items():
            self.encoder.relation_encoder.add_relation(relation)

    def forward(
        self,
        trace: ExecutionTrace | list[dict[str, torch.Tensor]],
        return_patterns: bool = False,
    ) -> tuple[torch.Tensor, torch.Tensor, list[DetectedPattern] | None]:
        """
        Forward pass through the NPA pipeline.

        Args:
            trace: Execution trace or batch of preprocessed tensors
            return_patterns: Whether to return detected patterns

        Returns:
            Tuple of (features, anomaly_scores, patterns)
        """
        # Encode trace
        if isinstance(trace, ExecutionTrace):
            encoder_output = self.encoder(trace)
            embeddings = encoder_output.embeddings
            timestamps = None
            attention_mask = None
        else:
            # Batch input
            encoder_output = self.encoder(
                timestamps=trace["timestamps"].to(self.device),
                relation_ids=trace["relation_ids"].to(self.device),
                numeric_values=trace["numeric_values"].to(self.device),
                string_hashes=trace["string_hashes"].to(self.device),
                type_indicators=trace["type_indicators"].to(self.device),
                attention_mask=trace.get("attention_mask", None),
            )
            embeddings = encoder_output.embeddings
            timestamps = trace["timestamps"].to(self.device)
            attention_mask = trace.get("attention_mask", None)
            if attention_mask is not None:
                attention_mask = attention_mask.to(self.device)

        # Detect patterns
        features, scores, _ = self.detector(
            embeddings,
            timestamps=timestamps,
            attention_mask=attention_mask,
        )

        # Optionally return patterns
        patterns = None
        if return_patterns:
            patterns = self.detector.detect(embeddings, timestamps, attention_mask)

        return features, scores, patterns

    def fit(
        self,
        traces: list[ExecutionTrace],
        config: TrainingConfig | None = None,
        validation_traces: list[ExecutionTrace] | None = None,
    ) -> dict[str, Any]:
        """
        Train the NPA model on execution traces.

        Uses self-supervised learning to learn normal protocol behavior:
        - Sequence prediction (predict next event)
        - Temporal prediction (predict timing)
        - Reconstruction objectives

        Args:
            traces: Training traces
            config: Training configuration
            validation_traces: Optional validation traces

        Returns:
            Training metrics dictionary
        """
        config = config or TrainingConfig()

        logger.info(f"Training NPA on {len(traces)} traces for {config.epochs} epochs")

        # Create dataset and dataloader
        dataset = TraceDataset(traces, self.encoder, config.batch_size)
        dataloader = DataLoader(
            dataset,
            batch_size=config.batch_size,
            shuffle=True,
            collate_fn=collate_traces,
            num_workers=0,
        )

        # Validation dataloader
        val_dataloader = None
        if validation_traces:
            val_dataset = TraceDataset(validation_traces, self.encoder)
            val_dataloader = DataLoader(
                val_dataset,
                batch_size=config.batch_size,
                shuffle=False,
                collate_fn=collate_traces,
            )

        # Setup optimizer
        self._optimizer = optim.AdamW(
            self.parameters(),
            lr=config.learning_rate,
            weight_decay=config.weight_decay,
        )

        # Learning rate scheduler
        self._scheduler = optim.lr_scheduler.CosineAnnealingWarmRestarts(
            self._optimizer,
            T_0=10,
            T_mult=2,
        )

        # Training loop
        self.train()
        metrics = {
            "train_losses": [],
            "val_losses": [],
            "epochs_trained": 0,
        }

        for epoch in range(config.epochs):
            epoch_loss = 0.0
            num_batches = 0

            for batch in dataloader:
                self._optimizer.zero_grad()

                # Forward pass
                features, scores, _ = self.forward(batch)

                # Compute loss
                timestamps = batch["timestamps"].to(self.device)
                attention_mask = batch["attention_mask"].to(self.device)
                loss = self.detector.compute_loss(
                    features,
                    timestamps,
                    attention_mask=attention_mask,
                )

                # Backward pass
                loss.backward()

                # Gradient clipping
                torch.nn.utils.clip_grad_norm_(self.parameters(), config.gradient_clip)

                self._optimizer.step()
                self._scheduler.step()

                epoch_loss += loss.item()
                num_batches += 1

            avg_loss = epoch_loss / max(1, num_batches)
            metrics["train_losses"].append(avg_loss)

            # Validation
            if val_dataloader is not None:
                val_loss = self._validate(val_dataloader)
                metrics["val_losses"].append(val_loss)

                # Early stopping check
                if val_loss < self._best_loss:
                    self._best_loss = val_loss
                    metrics["best_epoch"] = epoch

            if epoch % 10 == 0:
                logger.info(f"Epoch {epoch}: loss={avg_loss:.4f}")

        metrics["epochs_trained"] = config.epochs
        metrics["final_loss"] = metrics["train_losses"][-1]
        self.is_trained = True

        logger.info(f"Training complete. Final loss: {metrics['final_loss']:.4f}")
        return metrics

    def _validate(self, dataloader: DataLoader) -> float:
        """Run validation and return average loss."""
        self.eval()
        total_loss = 0.0
        num_batches = 0

        with torch.no_grad():
            for batch in dataloader:
                features, scores, _ = self.forward(batch)
                timestamps = batch["timestamps"].to(self.device)
                attention_mask = batch["attention_mask"].to(self.device)
                loss = self.detector.compute_loss(
                    features, timestamps, attention_mask=attention_mask
                )
                total_loss += loss.item()
                num_batches += 1

        self.train()
        return total_loss / max(1, num_batches)

    def propose_refinements(
        self,
        trace: ExecutionTrace,
        max_refinements: int = 5,
        context: dict[str, Any] | None = None,
    ) -> list[PolicyRefinement]:
        """
        Propose policy refinements based on trace analysis.

        This is the main inference method that:
        1. Encodes the trace
        2. Detects anomalous patterns
        3. Generates refinement proposals
        4. Filters by confidence threshold

        Args:
            trace: Execution trace to analyze
            max_refinements: Maximum number of refinements to return
            context: Additional context for refinement generation

        Returns:
            List of PolicyRefinement proposals sorted by confidence
        """
        self.eval()

        with torch.no_grad():
            # Forward pass with pattern detection
            features, scores, patterns = self.forward(trace, return_patterns=True)

            if patterns:
                # Pattern-based generation
                refinements = self.generator.generate(
                    patterns,
                    trace_context=context,
                    max_refinements=max_refinements,
                )
            else:
                # Direct embedding-based generation
                refinements = self.generator.generate_from_embeddings(
                    features.squeeze(0),
                    scores.squeeze(0),
                    trace_context=context,
                )

        # Filter by confidence
        refinements = [r for r in refinements if r.confidence >= self.confidence_threshold]

        # Sort by confidence
        refinements.sort(key=lambda r: r.confidence, reverse=True)

        return refinements[:max_refinements]

    def detect_anomalies(
        self,
        trace: ExecutionTrace,
        threshold: float | None = None,
    ) -> list[DetectedPattern]:
        """
        Detect anomalies in a trace without generating refinements.

        Useful for monitoring and alerting.

        Args:
            trace: Execution trace to analyze
            threshold: Anomaly threshold (uses detector default if not provided)

        Returns:
            List of detected anomalous patterns
        """
        self.eval()

        with torch.no_grad():
            encoder_output = self.encoder(trace)
            patterns = self.detector.detect(
                encoder_output.embeddings,
                threshold=threshold,
            )

        return patterns

    def get_trace_embedding(self, trace: ExecutionTrace) -> torch.Tensor:
        """
        Get the embedding representation of a trace.

        Useful for clustering, similarity analysis, etc.

        Args:
            trace: Execution trace

        Returns:
            Trace embedding tensor
        """
        self.eval()

        with torch.no_grad():
            encoder_output = self.encoder(trace)
            # Mean pooling over sequence
            embedding = encoder_output.embeddings.mean(dim=1)

        return embedding

    def save(self, path: Path | str) -> None:
        """
        Save the NPA model state.

        Args:
            path: Path to save the model
        """
        path = Path(path)

        torch.save(
            {
                "encoder_state": self.encoder.state_dict(),
                "detector_state": self.detector.state_dict(),
                "generator_state": self.generator.state_dict(),
                "vocabulary": self._vocabulary,
                "confidence_threshold": self.confidence_threshold,
                "is_trained": self.is_trained,
                "config": {
                    "embed_dim": self.encoder.embed_dim,
                    "num_heads": self.encoder.num_heads,
                    "num_layers": self.encoder.num_layers,
                },
            },
            path,
        )

        logger.info(f"NPA model saved to {path}")

    def load(self, path: Path | str) -> None:
        """
        Load NPA model state.

        Args:
            path: Path to load from
        """
        path = Path(path)
        checkpoint = torch.load(path, map_location=self.device, weights_only=False)  # nosec B614

        self.encoder.load_state_dict(checkpoint["encoder_state"])
        self.detector.load_state_dict(checkpoint["detector_state"])
        self.generator.load_state_dict(checkpoint["generator_state"])
        self._vocabulary = checkpoint.get("vocabulary", {})
        self.confidence_threshold = checkpoint.get("confidence_threshold", 0.8)
        self.is_trained = checkpoint.get("is_trained", True)

        logger.info(f"NPA model loaded from {path}")

    @classmethod
    def from_pretrained(cls, path: Path | str, device: str = "cpu") -> NeuralPolicyAdapter:
        """
        Load a pretrained NPA model.

        Args:
            path: Path to the saved model
            device: Device to load to

        Returns:
            Loaded NeuralPolicyAdapter
        """
        checkpoint = torch.load(path, map_location=device, weights_only=False)  # nosec B614
        config = checkpoint.get("config", {})

        encoder = TraceEncoder(
            embed_dim=config.get("embed_dim", 256),
            num_heads=config.get("num_heads", 8),
            num_layers=config.get("num_layers", 6),
        )

        adapter = cls(encoder=encoder, device=device)
        adapter.load(path)

        return adapter
