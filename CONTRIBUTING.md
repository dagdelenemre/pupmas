# Contributing to PUPMAS

Thank you for your interest in contributing to PUPMAS!

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with:
- A clear title and description
- Steps to reproduce
- Expected behavior
- Actual behavior
- System information

### Suggesting Features

Feature requests are welcome! Please include:
- Clear description of the feature
- Use cases
- Potential implementation approach

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`make test`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Code Style

- Follow PEP 8 guidelines
- Use type hints where appropriate
- Add docstrings to functions and classes
- Keep functions focused and modular
- Write tests for new features

### Testing

- Add unit tests for new functionality
- Ensure all tests pass before submitting PR
- Aim for high code coverage

## Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/pupmas.git
cd pupmas

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .

# Run tests
make test
```

## Code of Conduct

- Be respectful and constructive
- Focus on the code, not the person
- Accept constructive criticism gracefully
- Help others learn and grow

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
