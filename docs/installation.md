# Installation

## Requirements

V-NAPE requires Python 3.10 or higher.

### Core Dependencies

- **PyTorch** (≥2.0): Neural network operations
- **Z3 Solver** (≥4.12): Symbolic verification
- **Pydantic** (≥2.0): Data validation
- **NumPy** (≥1.24): Numerical operations

### Optional Dependencies

- **CUDA**: GPU acceleration for neural components
- **Sphinx**: Documentation building
- **pytest**: Testing

## Installation Methods

### From PyPI (Recommended)

```bash
pip install vnape
```

### From Source

```bash
git clone https://github.com/shujaat-zaheer/vnape.git
cd vnape
pip install -e ".[dev]"
```

### With GPU Support

```bash
pip install vnape[gpu]
```

### Development Installation

```bash
git clone https://github.com/shujaat-zaheer/vnape.git
cd vnape
pip install -e ".[dev,docs,test]"
```

## Verifying Installation

```python
import vnape

# Check version
print(f"V-NAPE version: {vnape.__version__}")

# Verify components
from vnape.core.types import SecurityLevel, QuantumSafetyLevel
from vnape.npa import NeuralPolicyAdapter
from vnape.svb import SymbolicVerificationBridge
from vnape.pqae import ProactiveEnforcer

print("✓ All components loaded successfully")
```

## Z3 Solver Installation

V-NAPE requires the Z3 SMT solver. It's typically installed automatically with the pip package, but if you encounter issues:

### Linux

```bash
# Ubuntu/Debian
sudo apt-get install z3 libz3-dev

# Or via pip
pip install z3-solver
```

### macOS

```bash
brew install z3
pip install z3-solver
```

### Windows

```bash
pip install z3-solver
```

## GPU Setup (Optional)

For GPU acceleration of neural components:

1. Install CUDA toolkit (11.8 or 12.x recommended)
2. Install PyTorch with CUDA support:

```bash
pip install torch --index-url https://download.pytorch.org/whl/cu118
```

3. Verify GPU availability:

```python
import torch
print(f"CUDA available: {torch.cuda.is_available()}")
print(f"Device: {torch.cuda.get_device_name(0)}")
```

## Troubleshooting

### ImportError: No module named 'z3'

```bash
pip install z3-solver
```

### CUDA out of memory

Reduce batch size in NPA configuration:

```python
config = NPAConfig(batch_size=16)  # Default is 32
```

### Slow verification

Enable caching in SVB:

```python
svb = SymbolicVerificationBridge(cache_enabled=True)
```

## Next Steps

- Follow the [Quick Start Guide](quickstart.md) to run your first verification
- Read about [Core Concepts](concepts.md) to understand V-NAPE's architecture
- Explore [Protocol Support](protocols/overview.md) for iMessage PQ3 and AKMA+
