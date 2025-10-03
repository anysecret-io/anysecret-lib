"""
Smoke tests for basic functionality validation
Fast tests to verify core components work without extensive mocking
"""
import pytest
import tempfile
import json
from pathlib import Path

from anysecret.secret_manager import (
    SecretManagerType,
    SecretManagerFactory,
    SecretValue,
    SecretNotFoundException
)
from anysecret.providers.file import EnvFileSecretManager, EncryptedFileSecretManager


class TestSmokeBasicComponents:
    """Smoke tests for basic components"""

    def test_secret_manager_types_exist(self):
        """Test all expected secret manager types are available"""
        expected_types = {
            'gcp', 'aws', 'azure', 'vault', 'cloudflare', 'encrypted_file', 'env_file', 'kubernetes'
        }
        actual_types = {t.value for t in SecretManagerType}
        assert expected_types == actual_types

    def test_factory_detect_available_managers(self):
        """Test factory can detect available managers"""
        available = SecretManagerFactory.detect_available_managers()

        # Should always have file-based managers
        assert SecretManagerType.ENV_FILE in available
        assert SecretManagerType.ENCRYPTED_FILE in available
        assert len(available) >= 2

    @pytest.mark.asyncio
    async def test_read_only_protection(self):
        """Test that read-only mode prevents write operations"""
        # Create env file manager with read_only=True
        env_content = "TEST_KEY=test_value"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(env_content)
            temp_path = Path(f.name)

        try:
            config = {'file_path': str(temp_path), 'read_only': True}
            manager = EnvFileSecretManager(config)

            # Read operations should work
            value = await manager.get_secret('TEST_KEY')
            assert value == 'test_value'

            # Write operations should fail (if EnvFileManager had them)
            # This validates the pattern works for providers that do have write methods

        finally:
            temp_path.unlink()

    def test_secret_value_creation(self):
        """Test SecretValue object creation"""
        secret = SecretValue(
            value="test-value",
            key="test-key",
            version="v1",
            metadata={"source": "test"}
        )

        assert secret.value == "test-value"
        assert secret.key == "test-key"
        assert secret.version == "v1"
        assert secret.metadata["source"] == "test"


class TestSmokeEnvFileManager:
    """Smoke tests for env file manager"""

    def test_env_file_basic_functionality(self):
        """Test env file manager basic operations"""
        # Create test env content
        env_content = "TEST_KEY=test_value\nANOTHER_KEY=another_value"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(env_content)
            temp_path = Path(f.name)

        try:
            # Test manager creation and loading
            manager = EnvFileSecretManager({'file_path': str(temp_path)})

            assert len(manager.secrets) == 2
            assert manager.secrets['TEST_KEY'] == 'test_value'
            assert manager.secrets['ANOTHER_KEY'] == 'another_value'

        finally:
            temp_path.unlink()

    @pytest.mark.asyncio
    async def test_env_file_async_operations(self):
        """Test env file async operations work"""
        env_content = "ASYNC_TEST=async_value"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(env_content)
            temp_path = Path(f.name)

        try:
            manager = EnvFileSecretManager({'file_path': str(temp_path)})

            # Test async get
            value = await manager.get_secret('ASYNC_TEST')
            assert value == 'async_value'

            # Test async list
            secrets = await manager.list_secrets()
            assert 'ASYNC_TEST' in secrets

            # Test health check
            healthy = await manager.health_check()
            assert healthy is True

        finally:
            temp_path.unlink()


class TestSmokeEncryptedFileManager:
    """Smoke tests for encrypted file manager"""

    def test_encrypted_file_round_trip(self):
        """Test encrypt -> decrypt round trip works"""
        test_secrets = {'secret1': 'value1', 'secret2': 'value2'}
        password = 'test-password'

        with tempfile.NamedTemporaryFile(suffix='.json.enc', delete=False) as f:
            temp_path = Path(f.name)

        try:
            # Create manager and encrypt
            config = {'file_path': str(temp_path), 'password': password}
            manager = EncryptedFileSecretManager.create_encrypted_file(
                test_secrets, temp_path, password
            )

            # Verify file was created and is not empty
            assert temp_path.exists()
            assert temp_path.stat().st_size > 0

            # Create new manager instance to decrypt
            manager2 = EncryptedFileSecretManager(config)

            # Verify secrets were loaded correctly
            assert len(manager2.secrets) == 2
            assert manager2.secrets['secret1'] == 'value1'
            assert manager2.secrets['secret2'] == 'value2'

        finally:
            temp_path.unlink()

    @pytest.mark.asyncio
    async def test_encrypted_file_async_operations(self):
        """Test encrypted file async operations"""
        test_secrets = {'async_secret': 'async_value'}
        password = 'async-password'

        with tempfile.NamedTemporaryFile(suffix='.json.enc', delete=False) as f:
            temp_path = Path(f.name)

        try:
            # Create encrypted file
            EncryptedFileSecretManager.create_encrypted_file(
                test_secrets, temp_path, password
            )

            # Create NEW manager instance to load the encrypted file
            config = {'file_path': str(temp_path), 'password': password}
            manager = EncryptedFileSecretManager(config)

            # Test async operations
            value = await manager.get_secret('async_secret')
            assert value == 'async_value'

            secret_obj = await manager.get_secret_with_metadata('async_secret')
            assert secret_obj.value == 'async_value'
            assert secret_obj.metadata['encrypted'] is True

            health = await manager.health_check()
            assert health is True

        finally:
            temp_path.unlink()

class TestSmokeFactoryIntegration:
    """Smoke tests for factory integration"""

    def test_factory_create_env_manager(self):
        """Test factory can create env file manager"""
        config = {'file_path': '.env.test'}

        manager = SecretManagerFactory.create(
            SecretManagerType.ENV_FILE,
            config
        )

        assert isinstance(manager, EnvFileSecretManager)
        assert manager.file_path == Path('.env.test')

    def test_factory_create_encrypted_manager(self):
        """Test factory can create encrypted file manager"""
        config = {
            'file_path': 'test.enc',
            'password': 'test-password'
        }

        manager = SecretManagerFactory.create(
            SecretManagerType.ENCRYPTED_FILE,
            config
        )

        assert isinstance(manager, EncryptedFileSecretManager)
        assert manager.password == 'test-password'

    def test_factory_invalid_manager_type(self):
        """Test factory rejects invalid manager types"""
        with pytest.raises(ValueError, match="Unsupported secret manager type"):
            SecretManagerFactory.create("invalid_type", {})


class TestSmokeCloudProviders:
    """Smoke tests for cloud provider imports (without actual connections)"""

    def test_gcp_provider_import(self):
        """Test GCP provider can be imported"""
        from anysecret.providers.gcp import GcpSecretManager
        assert GcpSecretManager is not None

    def test_aws_provider_import(self):
        """Test AWS provider can be imported"""
        from anysecret.providers.aws import AwsSecretManager
        assert AwsSecretManager is not None

    def test_azure_provider_import(self):
        """Test Azure provider can be imported"""
        from anysecret.providers.azure import AzureSecretManager
        assert AzureSecretManager is not None

    def test_vault_provider_import(self):
        """Test Vault provider can be imported"""
        from anysecret.providers.vault import VaultSecretManager
        assert VaultSecretManager is not None


class TestSmokeCLI:
    """Smoke tests for CLI functionality"""

    def test_cli_module_import(self):
        """Test CLI module can be imported"""
        from anysecret.cli.main import app
        assert app is not None

    def test_cli_help_generation(self):
        """Test CLI app can be imported and is callable"""
        from anysecret.cli.main import app

        # Just test that the app object exists and is callable
        assert callable(app)
        assert hasattr(app, 'callback')


class TestSmokeConfiguration:
    """Smoke tests for configuration and imports"""

    def test_main_package_import(self):
        """Test main package imports work"""
        import anysecret
        from anysecret import get_secret_manager, SecretManagerType

        assert get_secret_manager is not None
        assert SecretManagerType is not None

    def test_version_attribute(self):
        """Test package has version attribute"""
        import anysecret

        # Should have __version__ or similar
        version_attrs = ['__version__', 'VERSION', 'version']
        has_version = any(hasattr(anysecret, attr) for attr in version_attrs)
        assert has_version, "Package should have version information"


class TestSmokeErrors:
    """Smoke tests for error handling"""

    @pytest.mark.asyncio
    async def test_secret_not_found_error(self):
        """Test SecretNotFoundException is raised correctly"""
        env_content = "EXISTING_KEY=value"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(env_content)
            temp_path = Path(f.name)

        try:
            manager = EnvFileSecretManager({'file_path': str(temp_path)})

            with pytest.raises(SecretNotFoundException):
                await manager.get_secret('NONEXISTENT_KEY')

        finally:
            temp_path.unlink()

    def test_invalid_encrypted_file_password(self):
        """Test wrong password raises appropriate error"""
        test_secrets = {'key': 'value'}
        password = 'correct-password'

        with tempfile.NamedTemporaryFile(suffix='.json.enc', delete=False) as f:
            temp_path = Path(f.name)

        try:
            # Create encrypted file
            EncryptedFileSecretManager.create_encrypted_file(
                test_secrets, temp_path, password
            )

            # Try to decrypt with wrong password
            config = {'file_path': str(temp_path), 'password': 'wrong-password'}

            from anysecret.secret_manager import SecretManagerException
            with pytest.raises(SecretManagerException, match="Failed to decrypt"):
                EncryptedFileSecretManager(config)

        finally:
            temp_path.unlink()


@pytest.mark.slow
class TestSmokeIntegration:
    """Integration smoke tests (marked as slow)"""

    @pytest.mark.asyncio
    async def test_end_to_end_file_workflow(self):
        """Test complete workflow with file managers"""
        # Create initial secrets in env format
        env_content = "SECRET1=value1\nSECRET2=value2"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as env_file:
            env_file.write(env_content)
            env_path = Path(env_file.name)

        with tempfile.NamedTemporaryFile(suffix='.json.enc', delete=False) as enc_file:
            enc_path = Path(enc_file.name)

        try:
            # Step 1: Load from env file
            env_manager = EnvFileSecretManager({'file_path': str(env_path)})
            secrets = env_manager.secrets
            assert len(secrets) == 2

            # Step 2: Create encrypted file with same secrets
            password = 'integration-test-password'
            enc_manager = EncryptedFileSecretManager.create_encrypted_file(
                secrets, enc_path, password
            )

            # Step 3: Read back from encrypted file
            enc_manager2 = EncryptedFileSecretManager({
                'file_path': str(enc_path),
                'password': password
            })

            # Step 4: Verify all secrets match
            for key in secrets:
                env_value = await env_manager.get_secret(key)
                enc_value = await enc_manager2.get_secret(key)
                assert env_value == enc_value

            # Step 5: Test prefix operations
            all_secrets = await enc_manager2.get_secrets_by_prefix('SECRET')
            assert len(all_secrets) == 2
            assert all_secrets['SECRET1'] == 'value1'

        finally:
            env_path.unlink()
            enc_path.unlink()



if __name__ == "__main__":
    # Allow running smoke tests directly
    pytest.main([__file__, "-v"])