# tests/test_file_providers.py
"""
Tests for file-based secret managers
"""
import pytest
import tempfile
import json
import logging
from pathlib import Path
from anysecret.providers.file import (
    EnvFileSecretManager,
    EncryptedFileSecretManager,
    create_encrypted_secrets_file
)
from anysecret.secret_manager import SecretNotFoundException, SecretManagerException


class TestEnvFileSecretManager:
    """Test EnvFileSecretManager"""

    @pytest.fixture
    def temp_env_file(self):
        """Create temporary .env file for testing"""
        content = """
# Test environment file
DATABASE_PASSWORD=secret123
API_KEY=abc-def-ghi
DATABASE_HOST=localhost
API_TIMEOUT=30

# Comment line
EMPTY_LINE_ABOVE=true
QUOTED_VALUE="quoted string"
SINGLE_QUOTED='single quoted'
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(content.strip())
            temp_path = Path(f.name)

        yield temp_path
        temp_path.unlink()  # cleanup

    def test_load_env_file(self, temp_env_file):
        """Test loading secrets from env file"""
        config = {'file_path': str(temp_env_file)}
        manager = EnvFileSecretManager(config)

        # Check secrets were loaded
        assert len(manager.secrets) == 7
        assert manager.secrets['DATABASE_PASSWORD'] == 'secret123'
        assert manager.secrets['API_KEY'] == 'abc-def-ghi'
        assert manager.secrets['DATABASE_HOST'] == 'localhost'
        assert manager.secrets['API_TIMEOUT'] == '30'

    def test_quoted_values(self, temp_env_file):
        """Test quoted values are handled correctly"""
        config = {'file_path': str(temp_env_file)}
        manager = EnvFileSecretManager(config)

        assert manager.secrets['QUOTED_VALUE'] == 'quoted string'
        assert manager.secrets['SINGLE_QUOTED'] == 'single quoted'

    @pytest.mark.asyncio
    async def test_get_secret(self, temp_env_file):
        """Test getting a secret"""
        config = {'file_path': str(temp_env_file)}
        manager = EnvFileSecretManager(config)

        secret_value = await manager.get_secret('DATABASE_PASSWORD')
        assert secret_value == 'secret123'

    @pytest.mark.asyncio
    async def test_get_secret_with_metadata(self, temp_env_file):
        """Test getting secret with metadata"""
        config = {'file_path': str(temp_env_file)}
        manager = EnvFileSecretManager(config)

        secret = await manager.get_secret_with_metadata('API_KEY')
        assert secret.value == 'abc-def-ghi'
        assert secret.key == 'API_KEY'
        assert secret.metadata['source'] == 'env_file'
        assert secret.metadata['file_path'] == str(temp_env_file)

    @pytest.mark.asyncio
    async def test_get_nonexistent_secret(self, temp_env_file):
        """Test getting non-existent secret raises exception"""
        config = {'file_path': str(temp_env_file)}
        manager = EnvFileSecretManager(config)

        with pytest.raises(SecretNotFoundException):
            await manager.get_secret('NONEXISTENT_KEY')

    @pytest.mark.asyncio
    async def test_get_secrets_by_prefix(self, temp_env_file):
        """Test getting secrets by prefix"""
        config = {'file_path': str(temp_env_file)}
        manager = EnvFileSecretManager(config)

        database_secrets = await manager.get_secrets_by_prefix('DATABASE_')
        assert len(database_secrets) == 2
        assert database_secrets['DATABASE_PASSWORD'] == 'secret123'
        assert database_secrets['DATABASE_HOST'] == 'localhost'

    @pytest.mark.asyncio
    async def test_list_secrets(self, temp_env_file):
        """Test listing all secrets"""
        config = {'file_path': str(temp_env_file)}
        manager = EnvFileSecretManager(config)

        all_secrets = await manager.list_secrets()
        assert len(all_secrets) == 7
        assert 'DATABASE_PASSWORD' in all_secrets
        assert 'API_KEY' in all_secrets

    @pytest.mark.asyncio
    async def test_list_secrets_with_prefix(self, temp_env_file):
        """Test listing secrets with prefix filter"""
        config = {'file_path': str(temp_env_file)}
        manager = EnvFileSecretManager(config)

        api_secrets = await manager.list_secrets('API_')
        assert len(api_secrets) == 2
        assert 'API_KEY' in api_secrets
        assert 'API_TIMEOUT' in api_secrets

    @pytest.mark.asyncio
    async def test_health_check(self, temp_env_file):
        """Test health check"""
        config = {'file_path': str(temp_env_file)}
        manager = EnvFileSecretManager(config)

        assert await manager.health_check() is True

    @pytest.mark.asyncio
    async def test_health_check_missing_file(self):
        """Test health check with missing file"""
        config = {'file_path': '/nonexistent/path/.env'}
        manager = EnvFileSecretManager(config)

        assert await manager.health_check() is False

    def test_missing_env_file_warning(self, caplog):
        """Test warning when env file is missing"""
        with caplog.at_level(logging.WARNING):
            config = {'file_path': '/nonexistent/.env'}
            EnvFileSecretManager(config)

            assert "Env file not found" in caplog.text


class TestEncryptedFileSecretManager:
    """Test EncryptedFileSecretManager"""

    @pytest.fixture
    def test_secrets(self):
        """Test secrets data"""
        return {
            'database_password': 'super-secret-123',
            'api_key': 'sk-test-key-456',
            'jwt_secret': 'jwt-signing-key'
        }

    @pytest.fixture
    def temp_encrypted_file(self, test_secrets):
        """Create temporary encrypted file for testing"""
        password = 'test-password-123'

        # Create temporary JSON input file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as json_file:
            json.dump(test_secrets, json_file)
            json_path = Path(json_file.name)

        # Create temporary encrypted output file path
        with tempfile.NamedTemporaryFile(suffix='.json.enc', delete=False) as f:
            temp_path = Path(f.name)

        try:
            # Encrypt the JSON file
            create_encrypted_secrets_file(
                input_file=json_path,
                output_file=temp_path,
                password=password
            )
        finally:
            json_path.unlink()  # cleanup temp JSON file

        yield temp_path, password
        temp_path.unlink()  # cleanup

    def test_encryption_requires_password_or_key(self):
        """Test that encryption requires password or key"""
        config = {'file_path': 'test.enc'}

        with pytest.raises(SecretManagerException, match="Either 'encryption_key' or 'password' must be provided"):
            EncryptedFileSecretManager(config)

    def test_load_encrypted_file(self, temp_encrypted_file, test_secrets):
        """Test loading encrypted file"""
        temp_path, password = temp_encrypted_file

        config = {'file_path': str(temp_path), 'password': password}
        manager = EncryptedFileSecretManager(config)

        assert len(manager.secrets) == len(test_secrets)
        assert manager.secrets['database_password'] == test_secrets['database_password']

    def test_wrong_password(self, temp_encrypted_file):
        """Test wrong password raises exception"""
        temp_path, _ = temp_encrypted_file

        config = {'file_path': str(temp_path), 'password': 'wrong-password'}

        with pytest.raises(SecretManagerException, match="Failed to decrypt"):
            EncryptedFileSecretManager(config)

    @pytest.mark.asyncio
    async def test_get_secret_encrypted(self, temp_encrypted_file, test_secrets):
        """Test getting secret from encrypted file"""
        temp_path, password = temp_encrypted_file

        config = {'file_path': str(temp_path), 'password': password}
        manager = EncryptedFileSecretManager(config)

        secret_value = await manager.get_secret('database_password')
        assert secret_value == test_secrets['database_password']

    @pytest.mark.asyncio
    async def test_get_secret_with_metadata_encrypted(self, temp_encrypted_file):
        """Test getting secret with metadata from encrypted file"""
        temp_path, password = temp_encrypted_file

        config = {'file_path': str(temp_path), 'password': password}
        manager = EncryptedFileSecretManager(config)

        secret = await manager.get_secret_with_metadata('api_key')
        assert secret.key == 'api_key'
        assert secret.metadata['source'] == 'encrypted_file'
        assert secret.metadata['encrypted'] is True

    @pytest.mark.asyncio
    async def test_health_check_encrypted(self, temp_encrypted_file):
        """Test health check for encrypted file"""
        temp_path, password = temp_encrypted_file

        config = {'file_path': str(temp_path), 'password': password}
        manager = EncryptedFileSecretManager(config)

        assert await manager.health_check() is True


class TestCreateEncryptedSecretsFile:
    """Test utility function for creating encrypted files"""

    def test_create_from_json(self):
        """Test creating encrypted file from JSON input"""
        test_secrets = {'key1': 'value1', 'key2': 'value2'}

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as input_file:
            json.dump(test_secrets, input_file)
            input_path = Path(input_file.name)

        with tempfile.NamedTemporaryFile(suffix='.enc', delete=False) as output_file:
            output_path = Path(output_file.name)

        try:
            create_encrypted_secrets_file(
                input_file=input_path,
                output_file=output_path,
                password='test-password'
            )

            # Verify encrypted file was created and can be decrypted
            config = {'file_path': str(output_path), 'password': 'test-password'}
            manager = EncryptedFileSecretManager(config)

            assert len(manager.secrets) == 2
            assert manager.secrets['key1'] == 'value1'

        finally:
            input_path.unlink()
            output_path.unlink()

    def test_create_from_env(self):
        """Test creating encrypted file from .env input"""
        env_content = "KEY1=value1\nKEY2=value2\n"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as input_file:
            input_file.write(env_content)
            input_path = Path(input_file.name)

        with tempfile.NamedTemporaryFile(suffix='.enc', delete=False) as output_file:
            output_path = Path(output_file.name)

        try:
            create_encrypted_secrets_file(
                input_file=input_path,
                output_file=output_path,
                password='test-password'
            )

            # Verify encrypted file was created
            config = {'file_path': str(output_path), 'password': 'test-password'}
            manager = EncryptedFileSecretManager(config)

            assert manager.secrets['KEY1'] == 'value1'
            assert manager.secrets['KEY2'] == 'value2'

        finally:
            input_path.unlink()
            output_path.unlink()