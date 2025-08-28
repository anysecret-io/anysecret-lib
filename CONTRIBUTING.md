# Contributing to AnySecret.io

Thank you for your interest in contributing to AnySecret.io! 

## How to Contribute

### For Small Changes (Documentation, Bug Fixes)
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### For Large Changes
Please open an issue first to discuss what you would like to change. This helps ensure your contribution aligns with the project's direction and prevents duplicate work.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/anysecret-io/anysecret-lib.git
cd anysecret-lib

# Install dependencies
pip install -e .
pip install -r requirements-dev.txt

# Run tests
pytest
```

## Pull Request Process

1. Ensure all tests pass
2. Update documentation as needed
3. Add tests for new functionality
4. Follow existing code style and conventions
5. Update the CHANGELOG.md with your changes

## Sync Process

**Note**: This repository is synchronized from our main development repository. PRs are reviewed and merged here, then synchronized back to our main codebase. This process typically takes 24-48 hours.

## Code of Conduct

Please be respectful and constructive in all interactions. We aim to maintain a welcoming community for all contributors.

## Questions?

Feel free to open an issue for any questions or reach out at opensource@anysecret.io