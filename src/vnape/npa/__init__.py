"""
NPA: Neural Policy Adaptation Module

This module implements the neural policy adaptation component of V-NAPE.
It uses transformer-based architectures to learn security-relevant patterns
from protocol execution traces and generate policy refinement proposals.

Components:
- TraceEncoder: Encodes execution traces for neural processing
- PatternDetector: Identifies security-relevant patterns in traces
- RefinementGenerator: Generates MFOTL policy refinements
- NeuralPolicyAdapter: High-level API integrating all components

Example:
    >>> from vnape.npa import NeuralPolicyAdapter, TraceEncoder
    >>> encoder = TraceEncoder(embed_dim=256, num_heads=8, num_layers=6)
    >>> adapter = NeuralPolicyAdapter(encoder)
    >>> adapter.fit(training_traces)
    >>> refinements = adapter.propose_refinements(new_trace)
"""

from vnape.npa.adapter import NeuralPolicyAdapter
from vnape.npa.encoder import TraceEncoder
from vnape.npa.generator import RefinementGenerator
from vnape.npa.pattern_detector import PatternDetector

__all__ = [
    "NeuralPolicyAdapter",
    "TraceEncoder",
    "RefinementGenerator",
    "PatternDetector",
]
