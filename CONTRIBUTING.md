# Contributing to V-NAPE

Thank you for your interest in contributing to V-NAPE! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. We expect all contributors to:

- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community
- Show empathy towards other community members

## How to Contribute

### Reporting Bugs

Before reporting a bug, please:

1. Check the [existing issues](https://github.com/shujaat-zaheer/vnape/issues) to avoid duplicates
2. Try the latest version to see if the bug has been fixed
3. Collect information about the bug (stack trace, version, OS, Python version)

When reporting, please include:

```markdown
**Description**: Clear description of the bug

**To Reproduce**:
1. Step one
2. Step two
3. ...

**Expected Behavior**: What you expected to happen

**Actual Behavior**: What actually happened

**Environment**:
- V-NAPE version:
- Python version:
- OS:
- PyTorch version:
- Z3 version:

**Additional Context**: Any other relevant information
```

### Suggesting Features

Feature suggestions are welcome! Please:

1. Check existing issues and discussions for similar ideas
2. Describe the feature and its use case clearly
3. Explain why this would benefit the project

### Pull Requests

#### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/shujaat-zaheer/vnape.git
cd vnape

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev,test,docs]"

# Install pre-commit hooks
pre-commit install
```

#### Development Workflow

1. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/bug-description
   ```

2. **Make your changes** following our coding standards

3. **Write tests** for any new functionality

4. **Run the test suite**:
   ```bash
   # Run all tests
   pytest tests/ -v
   
   # Run specific test file
   pytest tests/unit/test_npa.py -v
   
   # Run with coverage
   pytest tests/ --cov=vnape --cov-report=html
   ```

5. **Check code style**:
   ```bash
   # Format code
   black src/ tests/
   
   # Check linting
   ruff check src/ tests/
   
   # Type checking
   mypy src/vnape
   ```

6. **Commit your changes**:
   ```bash
   git commit -m "feat: add quantum risk visualization"
   ```

7. **Push and create PR**:
   ```bash
   git push origin feature/your-feature-name
   ```

### Commit Message Guidelines

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Formatting, no code change
- `refactor`: Code change that neither fixes nor adds
- `perf`: Performance improvement
- `test`: Adding or updating tests
- `chore`: Build process or auxiliary tools

**Examples**:
```
feat(npa): add attention visualization for anomaly detection
fix(svb): correct MFOTL since operator translation
docs(readme): add quantum assessment example
test(pqae): add HNDL risk calculation tests
```

## Coding Standards

### Python Style

- Follow [PEP 8](https://pep8.org/)
- Use [Black](https://black.readthedocs.io/) for formatting (line length 88)
- Use [Ruff](https://github.com/astral-sh/ruff) for linting
- Use type hints for all function signatures

### Documentation

- Use Google-style docstrings
- Include examples in docstrings when helpful
- Update documentation for any API changes

```python
def verify_trace(
    self,
    trace: ProtocolTrace,
    policy: PolicyFormula,
    timeout: float = 30.0
) -> VerificationResult:
    """Verify a protocol trace against a policy.
    
    Args:
        trace: The protocol trace to verify.
        policy: The MFOTL policy formula.
        timeout: Verification timeout in seconds.
    
    Returns:
        VerificationResult containing satisfaction status and proof.
    
    Raises:
        VerificationTimeout: If verification exceeds timeout.
        InvalidPolicyError: If policy formula is malformed.
    
    Example:
        >>> result = svb.verify_trace(trace, safety_policy)
        >>> if result.is_satisfied:
        ...     print("Policy satisfied!")
    """
```

### Testing

- Aim for >80% code coverage
- Write unit tests for all new functions
- Include integration tests for component interactions
- Use pytest fixtures for common setup
- Mark slow tests with `@pytest.mark.slow`

```python
import pytest
from vnape.core.types import SecurityLevel

class TestSecurityLevel:
    """Tests for SecurityLevel enum."""
    
    def test_ordering(self):
        """Security levels should be properly ordered."""
        assert SecurityLevel.LOW < SecurityLevel.MEDIUM
        assert SecurityLevel.MEDIUM < SecurityLevel.HIGH
        assert SecurityLevel.HIGH < SecurityLevel.CRITICAL
    
    @pytest.mark.parametrize("level,expected", [
        (SecurityLevel.LOW, 1),
        (SecurityLevel.MEDIUM, 2),
        (SecurityLevel.HIGH, 3),
        (SecurityLevel.CRITICAL, 4),
    ])
    def test_values(self, level, expected):
        """Security level values should match expected."""
        assert level.value == expected
```

## Project Structure

```
vnape/
├── src/vnape/
│   ├── core/           # Core types and interfaces
│   ├── npa/            # Neural Policy Adaptation
│   ├── svb/            # Symbolic Verification Bridge
│   ├── pqae/           # Proactive Quantum-Aware Enforcement
│   ├── protocols/      # Protocol implementations
│   └── utils/          # Utilities
├── tests/
│   ├── unit/           # Unit tests
│   └── integration/    # Integration tests
├── docs/               # Documentation
├── examples/           # Usage examples
└── benchmarks/         # Performance benchmarks
```

## Review Process

1. **Automated Checks**: All PRs must pass CI (tests, linting, type checks)
2. **Code Review**: At least one maintainer approval required
3. **Documentation**: API changes require documentation updates
4. **Tests**: New features require tests; bug fixes should include regression tests

### What We Look For

- **Correctness**: Does it work as intended?
- **Tests**: Are there adequate tests?
- **Documentation**: Is it documented?
- **Style**: Does it follow our conventions?
- **Performance**: Any performance implications?
- **Security**: Any security considerations?

## Release Process

Releases follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking API changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, backward compatible

## Getting Help

- **Issues**: For bugs and feature requests
- **Discussions**: For questions and general discussion
- **Email**: shujaat.zaheer@example.com for sensitive matters

## Recognition

Contributors will be recognized in:
- The project README
- Release notes
- Annual contributor acknowledgments

Thank you for contributing to V-NAPE!
