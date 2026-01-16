"""
Trace Encoder for Neural Policy Adaptation

Implements the trace encoding function F: T → R^{n×d} that transforms
protocol execution traces into tensor representations suitable for
transformer processing.

The encoding combines three components:
1. Temporal encoding: Captures timing relationships between events
2. Relation encoding: Embeds event types and relations
3. Value encoding: Represents event parameter values

Reference: Algorithm 1 in the V-NAPE proposal
"""

from __future__ import annotations

import math
from typing import Any

import torch
import torch.nn as nn

from vnape.core.types import EncoderOutput, ExecutionTrace, ProtocolEvent


class PositionalEncoding(nn.Module):
    """
    Sinusoidal positional encoding as in "Attention Is All You Need" (Vaswani et al., 2017).

    For position pos and dimension i:
        PE(pos, 2i) = sin(pos / 10000^(2i/d_model))
        PE(pos, 2i+1) = cos(pos / 10000^(2i/d_model))
    """

    def __init__(self, embed_dim: int, max_len: int = 5000, dropout: float = 0.1):
        super().__init__()
        self.dropout = nn.Dropout(p=dropout)

        # Create positional encoding matrix
        pe = torch.zeros(max_len, embed_dim)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(
            torch.arange(0, embed_dim, 2).float() * (-math.log(10000.0) / embed_dim)
        )

        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0)  # Shape: (1, max_len, embed_dim)

        self.register_buffer("pe", pe)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: Tensor of shape (batch_size, seq_len, embed_dim)

        Returns:
            Tensor with positional encoding added
        """
        x = x + self.pe[:, : x.size(1), :]
        return self.dropout(x)


class TemporalEncoding(nn.Module):
    """
    Encodes temporal relationships between events.

    Uses learnable embeddings based on:
    1. Absolute timestamp (quantized into buckets)
    2. Relative time differences from previous event
    3. Time since session start
    """

    def __init__(self, embed_dim: int, num_buckets: int = 100):
        super().__init__()
        self.embed_dim = embed_dim
        self.num_buckets = num_buckets

        # Absolute time bucket embedding
        self.abs_time_embedding = nn.Embedding(num_buckets, embed_dim // 3)

        # Relative time embedding
        self.rel_time_embedding = nn.Embedding(num_buckets, embed_dim // 3)

        # Session time embedding
        self.session_time_embedding = nn.Embedding(num_buckets, embed_dim // 3 + embed_dim % 3)

        # Linear projection to combine
        self.projection = nn.Linear(embed_dim, embed_dim)

    def _quantize_time(self, timestamps: torch.Tensor, max_val: float = 1e6) -> torch.Tensor:
        """Quantize timestamps into buckets using log-scale."""
        # Clamp to avoid log(0)
        clamped = torch.clamp(timestamps.float(), min=1.0)
        # Log-scale quantization
        log_times = torch.log(clamped) / math.log(max_val) * (self.num_buckets - 1)
        return torch.clamp(log_times.long(), 0, self.num_buckets - 1)

    def forward(
        self,
        timestamps: torch.Tensor,
        session_starts: torch.Tensor | None = None,
    ) -> torch.Tensor:
        """
        Args:
            timestamps: Event timestamps (batch_size, seq_len)
            session_starts: Session start timestamps (batch_size,)

        Returns:
            Temporal embeddings (batch_size, seq_len, embed_dim)
        """
        batch_size, seq_len = timestamps.shape

        # Absolute time encoding
        abs_buckets = self._quantize_time(timestamps)
        abs_embed = self.abs_time_embedding(abs_buckets)

        # Relative time encoding (time since previous event)
        rel_times = torch.zeros_like(timestamps)
        rel_times[:, 1:] = timestamps[:, 1:] - timestamps[:, :-1]
        rel_buckets = self._quantize_time(rel_times)
        rel_embed = self.rel_time_embedding(rel_buckets)

        # Session time encoding
        if session_starts is not None:
            session_times = timestamps - session_starts.unsqueeze(1)
        else:
            session_times = timestamps - timestamps[:, 0:1]
        session_buckets = self._quantize_time(session_times)
        session_embed = self.session_time_embedding(session_buckets)

        # Combine all temporal components
        combined = torch.cat([abs_embed, rel_embed, session_embed], dim=-1)
        return self.projection(combined)


class RelationEncoder(nn.Module):
    """
    Encodes event relations (MFOTL predicate names).

    Maps relation names to learnable embeddings.
    """

    def __init__(self, embed_dim: int, vocab_size: int = 1000):
        super().__init__()
        self.embed_dim = embed_dim
        self.vocab_size = vocab_size

        # Relation name embedding
        self.relation_embedding = nn.Embedding(vocab_size, embed_dim)

        # Special tokens
        self.pad_token = 0
        self.unk_token = 1

        # Vocabulary mapping (built during training)
        self.relation_to_idx: dict[str, int] = {
            "<PAD>": 0,
            "<UNK>": 1,
        }
        self.idx_to_relation: dict[int, str] = {
            0: "<PAD>",
            1: "<UNK>",
        }
        self._next_idx = 2

    def add_relation(self, relation: str) -> int:
        """Add a new relation to the vocabulary."""
        if relation not in self.relation_to_idx:
            if self._next_idx >= self.vocab_size:
                return self.unk_token
            self.relation_to_idx[relation] = self._next_idx
            self.idx_to_relation[self._next_idx] = relation
            self._next_idx += 1
        return self.relation_to_idx[relation]

    def encode_relations(self, relations: list[str]) -> torch.Tensor:
        """Encode a list of relation names to indices."""
        indices = [self.relation_to_idx.get(r, self.unk_token) for r in relations]
        return torch.tensor(indices, dtype=torch.long)

    def forward(self, relation_ids: torch.Tensor) -> torch.Tensor:
        """
        Args:
            relation_ids: Tensor of relation indices (batch_size, seq_len)

        Returns:
            Relation embeddings (batch_size, seq_len, embed_dim)
        """
        return self.relation_embedding(relation_ids)


class ValueEncoder(nn.Module):
    """
    Encodes event parameter values.

    Handles different value types:
    - Numeric values: Normalized and projected
    - String values: Hashed and embedded
    - Complex values: Serialized and processed through MLP
    """

    def __init__(self, embed_dim: int, max_values: int = 10, hidden_dim: int = 128):
        super().__init__()
        self.embed_dim = embed_dim
        self.max_values = max_values

        # Numeric value projection
        self.numeric_projection = nn.Linear(max_values, hidden_dim)

        # String value embedding (hash-based)
        self.string_embedding = nn.Embedding(10000, hidden_dim)

        # Type indicator embedding
        self.type_embedding = nn.Embedding(4, hidden_dim // 4)  # numeric, string, bool, none

        # Combine values
        self.combine_mlp = nn.Sequential(
            nn.Linear(hidden_dim * 2 + hidden_dim // 4, embed_dim),
            nn.ReLU(),
            nn.Linear(embed_dim, embed_dim),
        )

    def _hash_string(self, s: str, mod: int = 10000) -> int:
        """Simple hash function for strings."""
        return hash(s) % mod

    def encode_values(
        self, values: list[dict[str, Any]]
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Encode a list of value dictionaries.

        Returns:
            Tuple of (numeric_values, string_hashes, type_indicators)
        """
        batch_size = len(values)
        numeric = torch.zeros(batch_size, self.max_values)
        strings = torch.zeros(batch_size, self.max_values, dtype=torch.long)
        types = torch.zeros(batch_size, dtype=torch.long)

        for i, val_dict in enumerate(values):
            for j, (key, val) in enumerate(list(val_dict.items())[: self.max_values]):
                if isinstance(val, (int, float)):
                    numeric[i, j] = float(val)
                    types[i] = 0
                elif isinstance(val, str):
                    strings[i, j] = self._hash_string(val)
                    types[i] = 1
                elif isinstance(val, bool):
                    numeric[i, j] = float(val)
                    types[i] = 2

        return numeric, strings, types

    def forward(
        self,
        numeric_values: torch.Tensor,
        string_hashes: torch.Tensor,
        type_indicators: torch.Tensor,
    ) -> torch.Tensor:
        """
        Args:
            numeric_values: (batch_size, seq_len, max_values)
            string_hashes: (batch_size, seq_len, max_values)
            type_indicators: (batch_size, seq_len)

        Returns:
            Value embeddings (batch_size, seq_len, embed_dim)
        """
        batch_size, seq_len, _ = numeric_values.shape

        # Encode numeric values
        numeric_embed = self.numeric_projection(numeric_values)

        # Encode string values (sum of hash embeddings)
        string_embed = self.string_embedding(string_hashes).mean(dim=-2)

        # Type indicators
        type_embed = self.type_embedding(type_indicators)

        # Combine
        combined = torch.cat([numeric_embed, string_embed, type_embed], dim=-1)
        return self.combine_mlp(combined)


class TraceEncoder(nn.Module):
    """
    Main trace encoder implementing F: T → R^{n×d}.

    Combines temporal, relation, and value encodings through a
    transformer encoder to produce context-aware event representations.

    Architecture:
    1. Input embedding: temporal + relation + value encodings
    2. Positional encoding
    3. Transformer encoder layers
    4. Optional output projection

    Args:
        embed_dim: Dimension of embeddings (d in the paper)
        num_heads: Number of attention heads
        num_layers: Number of transformer layers
        ff_dim: Feed-forward dimension (default: 4 * embed_dim)
        dropout: Dropout probability
        max_seq_length: Maximum sequence length
        vocab_size: Size of relation vocabulary

    Example:
        >>> encoder = TraceEncoder(embed_dim=256, num_heads=8, num_layers=6)
        >>> trace = ExecutionTrace(...)
        >>> output = encoder(trace)
        >>> print(output.embeddings.shape)  # (1, seq_len, 256)
    """

    def __init__(
        self,
        embed_dim: int = 256,
        num_heads: int = 8,
        num_layers: int = 6,
        ff_dim: int | None = None,
        dropout: float = 0.1,
        max_seq_length: int = 2048,
        vocab_size: int = 1000,
    ):
        super().__init__()

        self.embed_dim = embed_dim
        self.num_heads = num_heads
        self.num_layers = num_layers
        self.ff_dim = ff_dim or embed_dim * 4
        self.dropout = dropout
        self.max_seq_length = max_seq_length
        self.vocab_size = vocab_size

        # Component encoders
        self.temporal_encoder = TemporalEncoding(embed_dim)
        self.relation_encoder = RelationEncoder(embed_dim, vocab_size)
        self.value_encoder = ValueEncoder(embed_dim)

        # Combine component embeddings
        self.input_projection = nn.Linear(embed_dim * 3, embed_dim)

        # Positional encoding
        self.positional_encoding = PositionalEncoding(embed_dim, max_seq_length, dropout)

        # Transformer encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim,
            nhead=num_heads,
            dim_feedforward=self.ff_dim,
            dropout=dropout,
            activation="gelu",
            batch_first=True,
            norm_first=True,
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)

        # Layer normalization
        self.final_norm = nn.LayerNorm(embed_dim)

        # Device tracking
        self._device = torch.device("cpu")

    def to(self, device: torch.device | str) -> TraceEncoder:
        """Move encoder to device."""
        self._device = torch.device(device) if isinstance(device, str) else device
        return super().to(device)

    def _preprocess_trace(
        self, trace: ExecutionTrace | list[ProtocolEvent]
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Preprocess a trace into tensor inputs.

        Returns:
            Tuple of (timestamps, relation_ids, numeric_values, string_hashes, type_indicators)
        """
        events = trace.events if isinstance(trace, ExecutionTrace) else trace
        seq_len = len(events)

        # Extract timestamps
        timestamps = torch.tensor([e.timestamp for e in events], dtype=torch.long)

        # Extract and encode relations
        relations = [e.relation for e in events]
        for r in relations:
            self.relation_encoder.add_relation(r)
        relation_ids = self.relation_encoder.encode_relations(relations)

        # Extract values
        values = [e.values for e in events]
        numeric, strings, types = self.value_encoder.encode_values(values)

        return (
            timestamps.unsqueeze(0),  # (1, seq_len)
            relation_ids.unsqueeze(0),  # (1, seq_len)
            numeric.unsqueeze(0),  # (1, seq_len, max_values)
            strings.unsqueeze(0),  # (1, seq_len, max_values)
            types.unsqueeze(0),  # (1, seq_len)
        )

    def forward(
        self,
        trace: ExecutionTrace | list[ProtocolEvent] | None = None,
        timestamps: torch.Tensor | None = None,
        relation_ids: torch.Tensor | None = None,
        numeric_values: torch.Tensor | None = None,
        string_hashes: torch.Tensor | None = None,
        type_indicators: torch.Tensor | None = None,
        attention_mask: torch.Tensor | None = None,
        return_attention: bool = False,
    ) -> EncoderOutput:
        """
        Encode a trace or pre-processed tensors.

        Args:
            trace: ExecutionTrace or list of events (preprocessed if tensors provided)
            timestamps: Pre-processed timestamps
            relation_ids: Pre-processed relation indices
            numeric_values: Pre-processed numeric values
            string_hashes: Pre-processed string hashes
            type_indicators: Pre-processed type indicators
            attention_mask: Mask for padded positions
            return_attention: Whether to return attention weights

        Returns:
            EncoderOutput with embeddings and optional attention weights
        """
        # Preprocess trace if provided directly
        if trace is not None:
            timestamps, relation_ids, numeric_values, string_hashes, type_indicators = (
                self._preprocess_trace(trace)
            )

        # Move to device
        timestamps = timestamps.to(self._device)
        relation_ids = relation_ids.to(self._device)
        numeric_values = numeric_values.to(self._device)
        string_hashes = string_hashes.to(self._device)
        type_indicators = type_indicators.to(self._device)

        # Get component embeddings
        temporal_embed = self.temporal_encoder(timestamps)
        relation_embed = self.relation_encoder(relation_ids)
        value_embed = self.value_encoder(numeric_values, string_hashes, type_indicators)

        # Combine embeddings
        combined = torch.cat([temporal_embed, relation_embed, value_embed], dim=-1)
        x = self.input_projection(combined)

        # Add positional encoding
        x = self.positional_encoding(x)

        # Transformer encoding
        if attention_mask is not None:
            # Convert to transformer's expected mask format
            src_key_padding_mask = ~attention_mask.bool()
            x = self.transformer(x, src_key_padding_mask=src_key_padding_mask)
        else:
            x = self.transformer(x)

        # Final normalization
        x = self.final_norm(x)

        return EncoderOutput(
            embeddings=x,
            attention_weights=None,  # Would need custom transformer to capture
            hidden_states=None,
        )

    def encode_batch(
        self,
        traces: list[ExecutionTrace],
        max_length: int | None = None,
    ) -> EncoderOutput:
        """
        Encode a batch of traces with padding.

        Args:
            traces: List of traces to encode
            max_length: Maximum sequence length (default: length of longest trace)

        Returns:
            EncoderOutput with batched embeddings
        """
        max_length = max_length or max(len(t) for t in traces)
        max_length = min(max_length, self.max_seq_length)

        batch_size = len(traces)

        # Initialize tensors
        timestamps = torch.zeros(batch_size, max_length, dtype=torch.long)
        relation_ids = torch.zeros(batch_size, max_length, dtype=torch.long)
        numeric_values = torch.zeros(batch_size, max_length, 10)
        string_hashes = torch.zeros(batch_size, max_length, 10, dtype=torch.long)
        type_indicators = torch.zeros(batch_size, max_length, dtype=torch.long)
        attention_mask = torch.zeros(batch_size, max_length, dtype=torch.bool)

        # Fill tensors
        for i, trace in enumerate(traces):
            events = trace.events[:max_length]
            seq_len = len(events)

            # Timestamps
            timestamps[i, :seq_len] = torch.tensor([e.timestamp for e in events])

            # Relations
            relations = [e.relation for e in events]
            for r in relations:
                self.relation_encoder.add_relation(r)
            relation_ids[i, :seq_len] = self.relation_encoder.encode_relations(relations)

            # Values
            values = [e.values for e in events]
            num, strs, types = self.value_encoder.encode_values(values)
            numeric_values[i, :seq_len] = num
            string_hashes[i, :seq_len] = strs
            type_indicators[i, :seq_len] = types

            # Mask
            attention_mask[i, :seq_len] = True

        return self.forward(
            timestamps=timestamps,
            relation_ids=relation_ids,
            numeric_values=numeric_values,
            string_hashes=string_hashes,
            type_indicators=type_indicators,
            attention_mask=attention_mask,
        )

    def save(self, path: str) -> None:
        """Save encoder state."""
        torch.save(
            {
                "state_dict": self.state_dict(),
                "config": {
                    "embed_dim": self.embed_dim,
                    "num_heads": self.num_heads,
                    "num_layers": self.num_layers,
                    "ff_dim": self.ff_dim,
                    "dropout": self.dropout,
                    "max_seq_length": self.max_seq_length,
                    "vocab_size": self.vocab_size,
                },
                "relation_vocab": self.relation_encoder.relation_to_idx,
            },
            path,
        )

    @classmethod
    def load(cls, path: str, device: str = "cpu") -> TraceEncoder:
        """Load encoder from file."""
        checkpoint = torch.load(path, map_location=device, weights_only=False)  # nosec B614
        encoder = cls(**checkpoint["config"])
        encoder.load_state_dict(checkpoint["state_dict"])
        encoder.relation_encoder.relation_to_idx = checkpoint["relation_vocab"]
        encoder.relation_encoder.idx_to_relation = {
            v: k for k, v in checkpoint["relation_vocab"].items()
        }
        encoder.relation_encoder._next_idx = len(checkpoint["relation_vocab"])
        return encoder.to(device)
