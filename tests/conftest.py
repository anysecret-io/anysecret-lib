# tests/conftest.py
"""
Pytest configuration and shared fixtures
"""
import pytest
import asyncio
import tempfile
import os
from pathlib import Path

def pytest_configure(config):
    config.addinivalue_line("markers", "slow: marks tests as slow running")

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests"""
    with tempfile.TemporaryDirectory() as temp_path:
        yield Path(temp_path)


@pytest.fixture
def clean_env():
    """Clean environment variables for tests"""
    original_env = dict(os.environ)

    # Clear any secret manager related env vars
    env_vars_to_clear = [
        'SECRET_MANAGER_TYPE',
        'GCP_PROJECT_ID',
        'AWS_ACCESS_KEY_ID',
        'AWS_SECRET_ACCESS_KEY',
        'GOOGLE_APPLICATION_CREDENTIALS',
        'ENCRYPTED_SECRETS_FILE',
        'SECRETS_PASSWORD'
    ]

    for var in env_vars_to_clear:
        os.environ.pop(var, None)

    yield

    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def mock_gcp_credentials(monkeypatch, temp_dir):
    """Mock GCP credentials for testing"""
    fake_credentials = {
        "type": "service_account",
        "project_id": "test-project",
        "private_key_id": "test-key-id",
        "private_key": "-----BEGIN PRIVATE KEY-----\nfake-key\n-----END PRIVATE KEY-----\n",
        "client_email": "test@test-project.iam.gserviceaccount.com",
        "client_id": "test-client-id",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token"
    }

    # Create fake credentials file
    creds_file = temp_dir / "fake-gcp-credentials.json"
    import json
    with open(creds_file, 'w') as f:
        json.dump(fake_credentials, f)

    # Set environment variable
    monkeypatch.setenv('GOOGLE_APPLICATION_CREDENTIALS', str(creds_file))

    return fake_credentials


@pytest.fixture
def mock_aws_credentials(monkeypatch):
    """Mock AWS credentials for testing"""
    monkeypatch.setenv('AWS_ACCESS_KEY_ID', 'test-access-key')
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'test-secret-key')
    monkeypatch.setenv('AWS_DEFAULT_REGION', 'us-east-1')

    return {
        'aws_access_key_id': 'test-access-key',
        'aws_secret_access_key': 'test-secret-key',
        'region_name': 'us-east-1'
    }