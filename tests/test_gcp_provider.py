# tests/test_gcp_provider.py
"""
Tests for GCP Secret Manager provider
"""
import pytest
from unittest.mock import Mock, patch, AsyncMock
from anysecret.providers.gcp import GcpSecretManager
from anysecret.secret_manager import (
    SecretNotFoundException,
    SecretManagerException,
    SecretManagerConnectionException
)


class TestGcpSecretManager:
    """Test GcpSecretManager"""

    @pytest.fixture
    def mock_gcp_dependencies(self):
        """Mock GCP dependencies"""
        with patch('anysecret.providers.gcp.HAS_GCP', True):
            with patch('anysecret.providers.gcp.secretmanager') as mock_sm, \
                    patch('anysecret.providers.gcp.gcp_auth') as mock_auth:
                # Mock the client
                mock_client = Mock()
                mock_sm.SecretManagerServiceClient.return_value = mock_client

                # Mock auth detection
                mock_auth.return_value = (Mock(), 'test-project-123')

                yield mock_client, mock_sm, mock_auth

    def test_init_without_gcp_raises_error(self):
        """Test initialization without GCP dependencies raises error"""
        with patch('anysecret.providers.gcp.HAS_GCP', False):
            with pytest.raises(SecretManagerException, match="requires 'google-cloud-secret-manager' package"):
                GcpSecretManager({})

    def test_init_with_explicit_project_id(self, mock_gcp_dependencies):
        """Test initialization with explicit project ID"""
        mock_client, mock_sm, mock_auth = mock_gcp_dependencies

        config = {'project_id': 'my-test-project'}
        manager = GcpSecretManager(config)

        assert manager.project_id == 'my-test-project'
        assert manager._client == mock_client

    def test_init_auto_detect_project_id(self, mock_gcp_dependencies):
        """Test initialization with auto-detected project ID"""
        mock_client, mock_sm, mock_auth = mock_gcp_dependencies

        config = {}
        manager = GcpSecretManager(config)

        assert manager.project_id == 'test-project-123'
        mock_auth.assert_called_once()

    def test_init_failed_project_detection(self, mock_gcp_dependencies):
        """Test initialization when project detection fails"""
        mock_client, mock_sm, mock_auth = mock_gcp_dependencies
        mock_auth.return_value = (Mock(), None)

        config = {}
        with pytest.raises(SecretManagerException, match="Could not auto-detect project ID"):
            GcpSecretManager(config)

    def test_init_with_credentials_path(self, mock_gcp_dependencies):
        """Test initialization with credentials path"""
        mock_client, mock_sm, mock_auth = mock_gcp_dependencies

        config = {
            'project_id': 'test-project',
            'credentials_path': '/path/to/credentials.json'
        }

        manager = GcpSecretManager(config)
        assert manager.credentials_path == '/path/to/credentials.json'
        # Don't test environment variable side effects

    @pytest.mark.asyncio
    async def test_get_secret_with_metadata(self, mock_gcp_dependencies):
        """Test getting secret with metadata"""
        mock_client, mock_sm, mock_auth = mock_gcp_dependencies

        # Mock successful response
        mock_response = Mock()
        mock_response.payload.data = b'secret-value-123'
        mock_response.name = 'projects/test-project/secrets/test-secret/versions/1'
        mock_response.create_time = None

        mock_client.access_secret_version.return_value = mock_response

        config = {'project_id': 'test-project'}
        manager = GcpSecretManager(config)

        secret = await manager.get_secret_with_metadata('test-secret')

        assert secret.value == 'secret-value-123'
        assert secret.key == 'test-secret'
        assert secret.version == '1'
        assert secret.metadata['source'] == 'gcp_secret_manager'
        assert secret.metadata['project_id'] == 'test-project'

        # Verify correct API call
        mock_client.access_secret_version.assert_called_once()
        call_args = mock_client.access_secret_version.call_args[0][0]
        assert call_args['name'] == 'projects/test-project/secrets/test-secret/versions/latest'

    @pytest.mark.asyncio
    async def test_get_secret_not_found(self, mock_gcp_dependencies):
        """Test getting non-existent secret raises SecretNotFoundException"""
        mock_client, mock_sm, mock_auth = mock_gcp_dependencies

        from google.api_core import exceptions as gcp_exceptions
        mock_client.access_secret_version.side_effect = gcp_exceptions.NotFound('Secret not found')

        config = {'project_id': 'test-project'}
        manager = GcpSecretManager(config)

        with pytest.raises(SecretNotFoundException, match="Secret 'missing-secret' not found"):
            await manager.get_secret_with_metadata('missing-secret')

    @pytest.mark.asyncio
    async def test_get_secret_permission_denied(self, mock_gcp_dependencies):
        """Test permission denied error"""
        mock_client, mock_sm, mock_auth = mock_gcp_dependencies

        from google.api_core import exceptions as gcp_exceptions
        mock_client.access_secret_version.side_effect = gcp_exceptions.PermissionDenied('Access denied')

        config = {'project_id': 'test-project'}
        manager = GcpSecretManager(config)

        with pytest.raises(SecretManagerException, match="Permission denied accessing secret"):
            await manager.get_secret_with_metadata('protected-secret')

    @pytest.mark.asyncio
    async def test_list_secrets(self, mock_gcp_dependencies):
        """Test listing secrets"""
        mock_client, mock_sm, mock_auth = mock_gcp_dependencies

        # Mock secrets response
        mock_secret1 = Mock()
        mock_secret1.name = 'projects/test-project/secrets/database-password'
        mock_secret2 = Mock()
        mock_secret2.name = 'projects/test-project/secrets/api-key'

        mock_client.list_secrets.return_value = [mock_secret1, mock_secret2]

        config = {'project_id': 'test-project'}
        manager = GcpSecretManager(config)

        secrets = await manager.list_secrets()

        assert len(secrets) == 2
        assert 'database-password' in secrets
        assert 'api-key' in secrets
        assert secrets == ['api-key', 'database-password']  # Should be sorted

    @pytest.mark.asyncio
    async def test_list_secrets_with_prefix(self, mock_gcp_dependencies):
        """Test listing secrets with prefix filter"""
        mock_client, mock_sm, mock_auth = mock_gcp_dependencies

        # Mock secrets response
        mock_secret1 = Mock()
        mock_secret1.name = 'projects/test-project/secrets/database-password'
        mock_secret2 = Mock()
        mock_secret2.name = 'projects/test-project/secrets/database-host'
        mock_secret3 = Mock()
        mock_secret3.name = 'projects/test-project/secrets/api-key'

        mock_client.list_secrets.return_value = [mock_secret1, mock_secret2, mock_secret3]

        config = {'project_id': 'test-project'}
        manager = GcpSecretManager(config)

        database_secrets = await manager.list_secrets('database')

        assert len(database_secrets) == 2
        assert 'database-password' in database_secrets
        assert 'database-host' in database_secrets
        assert 'api-key' not in database_secrets

    @pytest.mark.asyncio
    async def test_get_secrets_by_prefix(self, mock_gcp_dependencies):
        """Test getting secrets by prefix"""
        mock_client, mock_sm, mock_auth = mock_gcp_dependencies

        # Mock list_secrets response
        mock_secret1 = Mock()
        mock_secret1.name = 'projects/test-project/secrets/auth-jwt-secret'
        mock_secret2 = Mock()
        mock_secret2.name = 'projects/test-project/secrets/auth-oauth-key'

        mock_client.list_secrets.return_value = [mock_secret1, mock_secret2]

        # Mock get_secret responses
        async def mock_get_secret_batch(keys):
            return {
                'auth-jwt-secret': 'jwt-secret-value',
                'auth-oauth-key': 'oauth-key-value'
            }

        config = {'project_id': 'test-project'}
        manager = GcpSecretManager(config)

        # Patch get_secrets_batch since it's inherited
        with patch.object(manager, 'get_secrets_batch', side_effect=mock_get_secret_batch):
            auth_secrets = await manager.get_secrets_by_prefix('auth')

            assert len(auth_secrets) == 2
            assert auth_secrets['auth-jwt-secret'] == 'jwt-secret-value'
            assert auth_secrets['auth-oauth-key'] == 'oauth-key-value'

    @pytest.mark.asyncio
    async def test_health_check_success(self, mock_gcp_dependencies):
        """Test successful health check"""
        mock_client, mock_sm, mock_auth = mock_gcp_dependencies

        mock_client.list_secrets.return_value = []

        config = {'project_id': 'test-project'}
        manager = GcpSecretManager(config)

        result = await manager.health_check()

        assert result is True
        mock_client.list_secrets.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_check_failure(self, mock_gcp_dependencies):
        """Test health check failure"""
        mock_client, mock_sm, mock_auth = mock_gcp_dependencies

        from google.api_core import exceptions as gcp_exceptions
        mock_client.list_secrets.side_effect = gcp_exceptions.PermissionDenied('Access denied')

        config = {'project_id': 'test-project'}
        manager = GcpSecretManager(config)

        result = await manager.health_check()

        assert result is False

    @pytest.mark.asyncio
    async def test_create_secret(self, mock_gcp_dependencies):
        """Test creating a new secret"""
        mock_client, mock_sm, mock_auth = mock_gcp_dependencies

        mock_secret = Mock()
        mock_secret.name = 'projects/test-project/secrets/new-secret'
        mock_client.create_secret.return_value = mock_secret

        config = {'project_id': 'test-project'}
        manager = GcpSecretManager(config)

        result = await manager.create_secret('new-secret', 'secret-value', {'env': 'test'})

        assert result is True

        # Verify API calls
        assert mock_client.create_secret.called
        assert mock_client.add_secret_version.called

    @pytest.mark.asyncio
    async def test_create_secret_already_exists(self, mock_gcp_dependencies):
        """Test creating secret that already exists"""
        mock_client, mock_sm, mock_auth = mock_gcp_dependencies

        from google.api_core import exceptions as gcp_exceptions
        mock_client.create_secret.side_effect = gcp_exceptions.AlreadyExists('Secret exists')

        config = {'project_id': 'test-project'}
        manager = GcpSecretManager(config)

        with pytest.raises(SecretManagerException, match="Secret 'existing-secret' already exists"):
            await manager.create_secret('existing-secret', 'value')

    @pytest.mark.asyncio
    async def test_update_secret(self, mock_gcp_dependencies):
        """Test updating existing secret"""
        mock_client, mock_sm, mock_auth = mock_gcp_dependencies

        config = {'project_id': 'test-project'}
        manager = GcpSecretManager(config)

        result = await manager.update_secret('existing-secret', 'new-value')

        assert result is True
        mock_client.add_secret_version.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_secret_not_found(self, mock_gcp_dependencies):
        """Test updating non-existent secret"""
        mock_client, mock_sm, mock_auth = mock_gcp_dependencies

        from google.api_core import exceptions as gcp_exceptions
        mock_client.add_secret_version.side_effect = gcp_exceptions.NotFound('Secret not found')

        config = {'project_id': 'test-project'}
        manager = GcpSecretManager(config)

        with pytest.raises(SecretNotFoundException, match="Secret 'missing-secret' not found for update"):
            await manager.update_secret('missing-secret', 'value')

    def test_repr(self, mock_gcp_dependencies):
        """Test string representation"""
        mock_client, mock_sm, mock_auth = mock_gcp_dependencies

        config = {'project_id': 'my-project'}
        manager = GcpSecretManager(config)

        assert repr(manager) == "GcpSecretManager(project_id='my-project')"

    @pytest.mark.asyncio
    async def test_get_secret_metadata(self, mock_gcp_dependencies):
        """Test getting secret metadata"""
        mock_client, mock_sm, mock_auth = mock_gcp_dependencies

        # Mock secret metadata
        mock_secret = Mock()
        mock_secret.name = 'projects/test-project/secrets/test-secret'
        mock_secret.labels = {'env': 'test', 'team': 'backend'}
        mock_secret.create_time = Mock()
        mock_secret.create_time.isoformat.return_value = '2024-01-01T00:00:00Z'
        mock_secret.etag = 'abc123'

        mock_client.list_secrets.return_value = [mock_secret]

        config = {'project_id': 'test-project'}
        manager = GcpSecretManager(config)

        metadata = await manager._get_secret_metadata('test-secret')

        assert metadata['labels'] == {'env': 'test', 'team': 'backend'}
        assert metadata['created_at'] == '2024-01-01T00:00:00Z'
        assert metadata['updated_at'] == 'abc123'

    def test_build_secret_path(self, mock_gcp_dependencies):
        """Test building secret path"""
        mock_client, mock_sm, mock_auth = mock_gcp_dependencies

        config = {'project_id': 'test-project'}
        manager = GcpSecretManager(config)

        path = manager._build_secret_path('my-secret')
        assert path == 'projects/test-project/secrets/my-secret/versions/latest'

        path_with_version = manager._build_secret_path('my-secret', 'v5')
        assert path_with_version == 'projects/test-project/secrets/my-secret/versions/v5'