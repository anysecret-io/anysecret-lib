# tests/test_azure_provider.py
"""
Tests for Azure Key Vault provider
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from anysecret.providers.azure import AzureSecretManager
from anysecret.secret_manager import (
    SecretNotFoundException,
    SecretManagerException,
    SecretManagerConnectionException
)


class TestAzureSecretManager:
    """Test AzureSecretManager"""

    @pytest.fixture
    def mock_azure_dependencies(self):
        """Mock Azure dependencies"""
        with patch('anysecret.providers.azure.HAS_AZURE', True):
            with patch('anysecret.providers.azure.SecretClient') as mock_client_class, \
                    patch('anysecret.providers.azure.DefaultAzureCredential') as mock_default_cred, \
                    patch('anysecret.providers.azure.ClientSecretCredential') as mock_client_cred:
                # Mock client instance
                mock_client = Mock()
                mock_client_class.return_value = mock_client

                # Mock credentials
                mock_default_credential = Mock()
                mock_client_credential = Mock()
                mock_default_cred.return_value = mock_default_credential
                mock_client_cred.return_value = mock_client_credential

                yield mock_client, mock_client_class, mock_default_cred, mock_client_cred

    def test_init_without_azure_raises_error(self):
        """Test initialization without Azure dependencies raises error"""
        with patch('anysecret.providers.azure.HAS_AZURE', False):
            with pytest.raises(SecretManagerException, match="requires 'azure-keyvault-secrets'"):
                AzureSecretManager({})

    def test_init_missing_vault_url_raises_error(self, mock_azure_dependencies):
        """Test initialization without vault URL raises error"""
        mock_client, mock_client_class, mock_default_cred, mock_client_cred = mock_azure_dependencies

        config = {}
        with pytest.raises(SecretManagerException, match="'vault_url' is required"):
            AzureSecretManager(config)

    def test_init_with_default_credentials(self, mock_azure_dependencies):
        """Test initialization with default credential chain"""
        mock_client, mock_client_class, mock_default_cred, mock_client_cred = mock_azure_dependencies

        config = {'vault_url': 'https://test-vault.vault.azure.net/'}
        manager = AzureSecretManager(config)

        assert manager.vault_url == 'https://test-vault.vault.azure.net/'
        assert manager._client == mock_client

        # Should use default credential
        mock_default_cred.assert_called_once()
        mock_client_cred.assert_not_called()

    def test_init_with_service_principal(self, mock_azure_dependencies):
        """Test initialization with service principal credentials"""
        mock_client, mock_client_class, mock_default_cred, mock_client_cred = mock_azure_dependencies

        config = {
            'vault_url': 'https://test-vault.vault.azure.net/',
            'client_id': 'test-client-id',
            'client_secret': 'test-client-secret',
            'tenant_id': 'test-tenant-id'
        }
        manager = AzureSecretManager(config)

        assert manager.client_id == 'test-client-id'
        assert manager.client_secret == 'test-client-secret'
        assert manager.tenant_id == 'test-tenant-id'

        # Should use client secret credential
        mock_client_cred.assert_called_once_with(
            tenant_id='test-tenant-id',
            client_id='test-client-id',
            client_secret='test-client-secret'
        )
        mock_default_cred.assert_not_called()

    def test_init_connection_error(self, mock_azure_dependencies):
        """Test initialization with connection error"""
        mock_client, mock_client_class, mock_default_cred, mock_client_cred = mock_azure_dependencies

        mock_client_class.side_effect = Exception("Connection failed")

        config = {'vault_url': 'https://test-vault.vault.azure.net/'}
        with pytest.raises(SecretManagerConnectionException, match="Failed to initialize Azure Key Vault client"):
            AzureSecretManager(config)

    @pytest.mark.asyncio
    async def test_get_secret_with_metadata(self, mock_azure_dependencies):
        """Test getting secret with metadata"""
        mock_client, mock_client_class, mock_default_cred, mock_client_cred = mock_azure_dependencies

        # Mock KeyVaultSecret object
        mock_secret = Mock()
        mock_secret.value = 'secret-value-123'
        mock_secret.id = 'https://test-vault.vault.azure.net/secrets/test-secret/version123'
        mock_secret.properties.version = 'version123'
        mock_secret.properties.content_type = 'text/plain'
        mock_secret.properties.enabled = True
        mock_secret.properties.created_on = Mock()
        mock_secret.properties.created_on.isoformat.return_value = '2024-01-01T00:00:00Z'
        mock_secret.properties.tags = {'env': 'test', 'team': 'backend'}

        mock_client.get_secret.return_value = mock_secret

        config = {'vault_url': 'https://test-vault.vault.azure.net/'}
        manager = AzureSecretManager(config)

        secret = await manager.get_secret_with_metadata('test-secret')

        assert secret.value == 'secret-value-123'
        assert secret.key == 'test-secret'
        assert secret.version == 'version123'
        assert secret.created_at == '2024-01-01T00:00:00Z'
        assert secret.metadata['source'] == 'azure_key_vault'
        assert secret.metadata['content_type'] == 'text/plain'
        assert secret.metadata['enabled'] is True
        assert secret.metadata['tags'] == {'env': 'test', 'team': 'backend'}

        mock_client.get_secret.assert_called_once_with('test-secret')

    @pytest.mark.asyncio
    async def test_get_secret_not_found(self, mock_azure_dependencies):
        """Test getting non-existent secret"""
        mock_client, mock_client_class, mock_default_cred, mock_client_cred = mock_azure_dependencies

        from anysecret.providers.azure import ResourceNotFoundError
        mock_client.get_secret.side_effect = ResourceNotFoundError('Secret not found')

        config = {'vault_url': 'https://test-vault.vault.azure.net/'}
        manager = AzureSecretManager(config)

        with pytest.raises(SecretNotFoundException, match="Secret 'missing-secret' not found"):
            await manager.get_secret_with_metadata('missing-secret')

    @pytest.mark.asyncio
    async def test_get_secret_access_denied(self, mock_azure_dependencies):
        """Test access denied error"""
        mock_client, mock_client_class, mock_default_cred, mock_client_cred = mock_azure_dependencies

        from anysecret.providers.azure import HttpResponseError
        response = Mock()
        response.status_code = 403
        error = HttpResponseError(response=response)
        mock_client.get_secret.side_effect = error

        config = {'vault_url': 'https://test-vault.vault.azure.net/'}
        manager = AzureSecretManager(config)

        with pytest.raises(SecretManagerException, match="Access denied to secret"):
            await manager.get_secret_with_metadata('protected-secret')

    @pytest.mark.asyncio
    async def test_list_secrets(self, mock_azure_dependencies):
        """Test listing secrets"""
        mock_client, mock_client_class, mock_default_cred, mock_client_cred = mock_azure_dependencies

        # Mock secret properties
        mock_prop1 = Mock()
        mock_prop1.name = 'database-password'
        mock_prop2 = Mock()
        mock_prop2.name = 'api-key'
        mock_prop3 = Mock()
        mock_prop3.name = 'jwt-secret'

        mock_client.list_properties_of_secrets.return_value = [mock_prop1, mock_prop2, mock_prop3]

        config = {'vault_url': 'https://test-vault.vault.azure.net/'}
        manager = AzureSecretManager(config)

        secrets = await manager.list_secrets()

        assert len(secrets) == 3
        assert 'api-key' in secrets
        assert 'database-password' in secrets
        assert 'jwt-secret' in secrets
        assert secrets == ['api-key', 'database-password', 'jwt-secret']  # Should be sorted

    @pytest.mark.asyncio
    async def test_list_secrets_with_prefix(self, mock_azure_dependencies):
        """Test listing secrets with prefix filter"""
        mock_client, mock_client_class, mock_default_cred, mock_client_cred = mock_azure_dependencies

        mock_prop1 = Mock()
        mock_prop1.name = 'database-password'
        mock_prop2 = Mock()
        mock_prop2.name = 'database-host'
        mock_prop3 = Mock()
        mock_prop3.name = 'api-key'

        mock_client.list_properties_of_secrets.return_value = [mock_prop1, mock_prop2, mock_prop3]

        config = {'vault_url': 'https://test-vault.vault.azure.net/'}
        manager = AzureSecretManager(config)

        database_secrets = await manager.list_secrets('database')

        assert len(database_secrets) == 2
        assert 'database-password' in database_secrets
        assert 'database-host' in database_secrets
        assert 'api-key' not in database_secrets

    @pytest.mark.asyncio
    async def test_get_secrets_by_prefix(self, mock_azure_dependencies):
        """Test getting secrets by prefix"""
        mock_client, mock_client_class, mock_default_cred, mock_client_cred = mock_azure_dependencies

        # Mock list_properties_of_secrets
        mock_prop1 = Mock()
        mock_prop1.name = 'auth-jwt-secret'
        mock_prop2 = Mock()
        mock_prop2.name = 'auth-oauth-key'
        mock_prop3 = Mock()
        mock_prop3.name = 'database-password'

        mock_client.list_properties_of_secrets.return_value = [mock_prop1, mock_prop2, mock_prop3]

        # Mock get_secrets_batch
        async def mock_get_secrets_batch(keys):
            return {
                'auth-jwt-secret': 'jwt-value',
                'auth-oauth-key': 'oauth-value'
            }

        config = {'vault_url': 'https://test-vault.vault.azure.net/'}
        manager = AzureSecretManager(config)

        with patch.object(manager, 'get_secrets_batch', side_effect=mock_get_secrets_batch):
            auth_secrets = await manager.get_secrets_by_prefix('auth')

            assert len(auth_secrets) == 2
            assert auth_secrets['auth-jwt-secret'] == 'jwt-value'
            assert auth_secrets['auth-oauth-key'] == 'oauth-value'

    @pytest.mark.asyncio
    async def test_health_check_success(self, mock_azure_dependencies):
        """Test successful health check"""
        mock_client, mock_client_class, mock_default_cred, mock_client_cred = mock_azure_dependencies

        mock_client.list_properties_of_secrets.return_value = iter([])  # Empty iterator

        config = {'vault_url': 'https://test-vault.vault.azure.net/'}
        manager = AzureSecretManager(config)

        result = await manager.health_check()

        assert result is True

    @pytest.mark.asyncio
    async def test_health_check_failure(self, mock_azure_dependencies):
        """Test health check failure"""
        mock_client, mock_client_class, mock_default_cred, mock_client_cred = mock_azure_dependencies

        from anysecret.providers.azure import HttpResponseError
        response = Mock()
        response.status_code = 403
        mock_client.list_properties_of_secrets.side_effect = HttpResponseError(response=response)

        config = {'vault_url': 'https://test-vault.vault.azure.net/'}
        manager = AzureSecretManager(config)

        result = await manager.health_check()

        assert result is False

    @pytest.mark.asyncio
    async def test_create_secret(self, mock_azure_dependencies):
        """Test creating a new secret"""
        mock_client, mock_client_class, mock_default_cred, mock_client_cred = mock_azure_dependencies

        config = {'vault_url': 'https://test-vault.vault.azure.net/'}
        manager = AzureSecretManager(config)

        result = await manager.create_secret(
            'new-secret',
            'secret-value',
            content_type='text/plain',
            tags={'env': 'test'}
        )

        assert result is True
        mock_client.set_secret.assert_called_once_with(
            name='new-secret',
            value='secret-value',
            content_type='text/plain',
            tags={'env': 'test'}
        )

    @pytest.mark.asyncio
    async def test_create_secret_conflict(self, mock_azure_dependencies):
        """Test creating secret that conflicts"""
        mock_client, mock_client_class, mock_default_cred, mock_client_cred = mock_azure_dependencies

        from anysecret.providers.azure import HttpResponseError
        response = Mock()
        response.status_code = 409
        mock_client.set_secret.side_effect = HttpResponseError(response=response)

        config = {'vault_url': 'https://test-vault.vault.azure.net/'}
        manager = AzureSecretManager(config)

        with pytest.raises(SecretManagerException, match="already exists"):
            await manager.create_secret('existing-secret', 'value')

    @pytest.mark.asyncio
    async def test_update_secret(self, mock_azure_dependencies):
        """Test updating existing secret"""
        mock_client, mock_client_class, mock_default_cred, mock_client_cred = mock_azure_dependencies

        config = {'vault_url': 'https://test-vault.vault.azure.net/'}
        manager = AzureSecretManager(config)

        result = await manager.update_secret('existing-secret', 'new-value')

        assert result is True
        mock_client.set_secret.assert_called_once_with(
            name='existing-secret',
            value='new-value'
        )

    @pytest.mark.asyncio
    async def test_update_secret_not_found(self, mock_azure_dependencies):
        """Test updating non-existent secret"""
        mock_client, mock_client_class, mock_default_cred, mock_client_cred = mock_azure_dependencies

        from anysecret.providers.azure import ResourceNotFoundError
        mock_client.set_secret.side_effect = ResourceNotFoundError('Secret not found')

        config = {'vault_url': 'https://test-vault.vault.azure.net/'}
        manager = AzureSecretManager(config)

        with pytest.raises(SecretNotFoundException, match="Secret 'missing-secret' not found for update"):
            await manager.update_secret('missing-secret', 'value')

    @pytest.mark.asyncio
    async def test_delete_secret(self, mock_azure_dependencies):
        """Test deleting a secret"""
        mock_client, mock_client_class, mock_default_cred, mock_client_cred = mock_azure_dependencies

        # Mock the delete operation
        mock_delete_operation = Mock()
        mock_delete_operation.result.return_value = Mock()
        mock_client.begin_delete_secret.return_value = mock_delete_operation

        config = {'vault_url': 'https://test-vault.vault.azure.net/'}
        manager = AzureSecretManager(config)

        result = await manager.delete_secret('test-secret')

        assert result is True
        mock_client.begin_delete_secret.assert_called_once_with(name='test-secret')

    @pytest.mark.asyncio
    async def test_get_secret_versions(self, mock_azure_dependencies):
        """Test getting secret versions"""
        mock_client, mock_client_class, mock_default_cred, mock_client_cred = mock_azure_dependencies

        # Mock version properties
        mock_version1 = Mock()
        mock_version1.version = 'version1'
        mock_version1.enabled = True
        mock_version1.created_on = Mock()
        mock_version1.created_on.isoformat.return_value = '2024-01-01T00:00:00Z'
        mock_version1.updated_on = None
        mock_version1.expires_on = None
        mock_version1.tags = {'version': 'v1'}

        mock_version2 = Mock()
        mock_version2.version = 'version2'
        mock_version2.enabled = True
        mock_version2.created_on = Mock()
        mock_version2.created_on.isoformat.return_value = '2024-01-02T00:00:00Z'
        mock_version2.updated_on = None
        mock_version2.expires_on = None
        mock_version2.tags = None

        mock_client.list_properties_of_secret_versions.return_value = [mock_version1, mock_version2]

        config = {'vault_url': 'https://test-vault.vault.azure.net/'}
        manager = AzureSecretManager(config)

        versions = await manager.get_secret_versions('test-secret')

        assert len(versions) == 2
        # Should be sorted by created_on descending (newest first)
        assert versions[0]['version'] == 'version2'
        assert versions[0]['created_on'] == '2024-01-02T00:00:00Z'
        assert versions[1]['version'] == 'version1'
        assert versions[1]['tags'] == {'version': 'v1'}

    def test_repr(self, mock_azure_dependencies):
        """Test string representation"""
        mock_client, mock_client_class, mock_default_cred, mock_client_cred = mock_azure_dependencies

        config = {'vault_url': 'https://my-vault.vault.azure.net/'}
        manager = AzureSecretManager(config)

        assert repr(manager) == "AzureSecretManager(vault='my-vault')"