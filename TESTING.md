# Testing Guide for AnySecret

This document describes the test structure and how to run tests for the AnySecret project.

## Test Structure

### Core Test Files

- **`test_basic.py`** - Smoke tests for basic functionality
- **`test_cli_commands.py`** - CLI command and interface tests  
- **`test_config_manager.py`** - Unified configuration manager tests
- **`test_file_providers.py`** - File-based provider tests (env, encrypted files)
- **`test_*_provider.py`** - Cloud provider specific tests (AWS, GCP, Azure, Vault)
- **`test_*_parameter_manager.py`** - Parameter manager tests

### Test Categories

#### 🚀 Smoke Tests (Fast)
Basic functionality verification without external dependencies.

```bash
python run_tests.py smoke
```

#### 🖥️ CLI Tests
Command-line interface functionality and user experience.

```bash  
python run_tests.py cli
```

#### 🔧 Unit Tests
Core component testing with mocking.

```bash
python run_tests.py unit
```

#### 🔗 Integration Tests (Slow)
End-to-end workflows and provider integration.

```bash
python run_tests.py integration
```

## Running Tests

### Using the Test Runner (Recommended)

```bash
# Quick smoke tests
python run_tests.py smoke

# CLI functionality 
python run_tests.py cli

# All tests
python run_tests.py all

# Specific test file
python run_tests.py file tests/test_basic.py
```

### Using pytest directly

```bash
# All tests
pytest

# Specific test file
pytest tests/test_basic.py

# Specific test class
pytest tests/test_cli_commands.py::TestCLIBasics

# Stop on first failure
pytest -x

# Verbose output
pytest -v

# Run tests matching pattern
pytest -k "test_cli"
```

## Test Results Summary

### ✅ Currently Passing (Production Ready)

#### Core Functionality
- **Secret Manager Types** - All provider types available
- **Factory Pattern** - Manager creation and detection
- **File Providers** - Env file and encrypted file managers  
- **Basic Operations** - Get, set, list, health check
- **Error Handling** - Proper exceptions and error messages

#### CLI Interface  
- **Help System** - All help commands working with Rich formatting
- **Core Commands** - version, info, patterns, classify
- **Subcommands** - config, bulk, providers, read, write
- **Global Options** - debug, format, quiet, profile options
- **Provider Integration** - List and status commands

#### File Operations
- **Env File Manager** - Load, parse, async operations
- **Encrypted Files** - Round-trip encryption/decryption
- **Error Scenarios** - Missing files, wrong passwords
- **Integration Workflows** - End-to-end file management

### 🚧 Areas Needing Attention

#### Cloud Provider Tests
Some cloud provider tests may need updates for new CLI structure:
- AWS provider integration tests
- GCP provider integration tests  
- Azure provider integration tests
- Kubernetes integration tests

These tests exist but may need verification with current codebase structure.

#### Advanced CLI Features
- Bulk import/export with real data
- Profile management workflows
- Multi-cloud operations
- Complex configuration scenarios

## Test Configuration

### Pytest Settings (pyproject.toml)
```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = ["--strict-markers", "--strict-config", "-v"]
markers = [
    "asyncio: marks tests as async",
    "unit: marks tests as unit tests", 
    "integration: marks tests as integration tests",
    "slow: marks tests as slow running",
]
asyncio_mode = "auto"
```

### Test Fixtures
- **`conftest.py`** - Shared fixtures and configuration
- **`temp_dir`** - Temporary directory for file tests
- **`clean_env`** - Clean environment variables
- **`mock_gcp_credentials`** - Mock GCP authentication
- **`mock_aws_credentials`** - Mock AWS authentication

## Writing New Tests

### Test Naming Convention
- Test files: `test_<component>.py`
- Test classes: `Test<Component>`  
- Test methods: `test_<functionality>`

### Example Test Structure
```python
class TestMyFeature:
    """Test my feature functionality"""

    def test_basic_functionality(self):
        """Test basic feature works"""
        # Arrange
        # Act  
        # Assert
        
    @pytest.mark.asyncio
    async def test_async_functionality(self):
        """Test async feature works"""
        # Async test code
        
    @pytest.mark.slow  
    def test_integration_scenario(self):
        """Test integration scenario (marked as slow)"""
        # Integration test code
```

### CLI Test Pattern
```python
from typer.testing import CliRunner
from anysecret.cli.cli import app

def test_my_cli_command():
    """Test CLI command"""
    runner = CliRunner()
    result = runner.invoke(app, ["my-command", "--option"])
    
    assert result.exit_code == 0
    assert "expected output" in result.stdout
```

## Continuous Integration

### GitHub Actions (Recommended)
```yaml
- name: Run Tests
  run: |
    pip install -e .
    python run_tests.py smoke
    python run_tests.py cli
    python run_tests.py unit
```

### Local Development
```bash
# Before committing
python run_tests.py smoke
python run_tests.py cli

# Full test suite (slower)  
python run_tests.py all
```

## Test Data and Fixtures

### Temporary Files
Tests use Python's `tempfile` module for creating temporary test data:
- `.env` files for testing env file managers
- `.json.enc` files for testing encrypted file managers
- Configuration files for testing profile management

### Mock Data
- **Credentials** - Fake but properly formatted cloud credentials
- **Responses** - Mock API responses for cloud provider tests
- **Configuration** - Sample configuration data for various scenarios

## Debugging Failed Tests

### Common Issues
1. **Missing Dependencies** - Install test dependencies: `pip install -e .[dev]`
2. **Environment Variables** - Tests clean environment, may affect some tests
3. **File Permissions** - Temporary file creation/cleanup issues
4. **Async Issues** - Use `@pytest.mark.asyncio` for async tests

### Debug Commands
```bash
# Run with maximum verbosity
pytest -vvv tests/test_failing.py

# Show print statements
pytest -s tests/test_failing.py

# Debug specific test
pytest --pdb tests/test_failing.py::test_method

# Show slowest tests
pytest --durations=10
```

## Performance Considerations

### Fast Tests (< 1 second)
- Basic component initialization
- File parsing and validation
- CLI help and version commands
- Mock-based unit tests

### Medium Tests (1-5 seconds)  
- File I/O operations
- CLI command execution
- Configuration loading/validation

### Slow Tests (> 5 seconds)
- Cloud provider integration
- End-to-end workflows
- Network operations
- Large file operations

Use `@pytest.mark.slow` for tests that take significant time.

---

## Summary

The test suite provides comprehensive coverage of:
- ✅ **Core functionality** - All basic operations working
- ✅ **CLI interface** - Complete command-line experience
- ✅ **File operations** - Local development workflows  
- ✅ **Error handling** - Proper error scenarios
- 🚧 **Cloud integration** - May need updates for new structure

Use `python run_tests.py smoke` for quick validation and `python run_tests.py all` for comprehensive testing.