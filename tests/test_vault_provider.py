# tests/test_vault_provider.py
"""
Tests for HashiCorp Vault provider
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from anysecret.providers.vault import VaultSecretManager
from anysecret.secret_manager import (
    SecretNotFoundException,
    SecretManagerException,
    SecretManagerConnectionException
)


class TestVaultSecretManager:
    """Test VaultSecretManager"""

    @pytest.fixture
    def mock_vault_dependencies(self):
        """Mock Vault dependencies"""
        with patch('anysecret.providers.vault.HAS_VAULT', True):
            with patch('hvac.Client') as mock_client_class:
                # Mock client instance
                mock_client = Mock()
                mock_client_class.return_value = mock_client
                mock_client.is_authenticated.return_value = True
                mock_client.sys.is_initialized.return_value = True
                mock_client.sys.is_sealed.return_value = False

                # Mock KV interfaces
                mock_client.secrets.kv.v1 = Mock()
                mock_client.secrets.kv.v2 = Mock()
                mock_client.auth.approle = Mock()
                mock_client.auth.userpass = Mock()
                mock_client.auth.jwt = Mock()

                yield mock_client, mock_client_class

    def test_init_without_vault_raises_error(self):
        """Test initialization without Vault dependencies raises error"""
        with patch('anysecret.providers.vault.HAS_VAULT', False):
            with pytest.raises(SecretManagerException, match="requires 'hvac' package"):
                VaultSecretManager({})

    def test_init_default_config(self, mock_vault_dependencies):
        """Test initialization with default configuration"""
        mock_client, mock_client_class = mock_vault_dependencies

        config = {'token': 'test-token'}
        manager = VaultSecretManager(config)

        assert manager.vault_url == 'http://localhost:8200'
        assert manager.mount_point == 'secret'
        assert manager.kv_version == 2
        assert manager.token == 'test-token'
        assert manager._client == mock_client

    def test_init_custom_config(self, mock_vault_dependencies):
        """Test initialization with custom configuration"""
        mock_client, mock_client_class = mock_vault_dependencies

        config = {
            'vault_url': 'https://vault.example.com:8200',
            'mount_point': 'kv',
            'kv_version': 1,
            'token': 'custom-token',
            'verify_tls': False
        }
        manager = VaultSecretManager(config)

        assert manager.vault_url == 'https://vault.example.com:8200'
        assert manager.mount_point == 'kv'
        assert manager.kv_version == 1
        assert manager.verify_tls is False

    def test_init_approle_auth(self, mock_vault_dependencies):
        """Test initialization with AppRole authentication"""
        mock_client, mock_client_class = mock_vault_dependencies

        # Mock AppRole login response
        mock_client.auth.approle.login.return_value = {
            'auth': {'client_token': 'approle-token-123'}
        }

        config = {
            'role_id': 'test-role-id',
            'secret_id': 'test-secret-id'
        }
        manager = VaultSecretManager(config)

        mock_client.auth.approle.login.assert_called_once_with(
            role_id='test-role-id',
            secret_id='test-secret-id'
        )
        assert mock_client.token == 'approle-token-123'

    def test_init_userpass_auth(self, mock_vault_dependencies):
        """Test initialization with userpass authentication"""
        mock_client, mock_client_class = mock_vault_dependencies

        mock_client.auth.userpass.login.return_value = {
            'auth': {'client_token': 'userpass-token-123'}
        }

        config = {
            'username': 'testuser',
            'password': 'testpass'
        }
        manager = VaultSecretManager(config)

        mock_client.auth.userpass.login.assert_called_once_with(
            username='testuser',
            password='testpass'
        )

    def test_init_jwt_auth(self, mock_vault_dependencies):
        """Test initialization with JWT authentication"""
        mock_client, mock_client_class = mock_vault_dependencies

        mock_client.auth.jwt.login.return_value = {
            'auth': {'client_token': 'jwt-token-123'}
        }

        config = {
            'jwt_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...',
            'role': 'my-role'
        }
        manager = VaultSecretManager(config)

        mock_client.auth.jwt.login.assert_called_once_with(
            jwt='eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...',
            role='my-role'
        )

    def test_init_authentication_failed(self, mock_vault_dependencies):
        """Test initialization when authentication fails"""
        mock_client, mock_client_class = mock_vault_dependencies

        mock_client.is_authenticated.return_value = False

        config = {'token': 'invalid-token'}
        with pytest.raises(SecretManagerConnectionException, match="Vault authentication failed"):
            VaultSecretManager(config)

    def test_init_no_auth_method(self, mock_vault_dependencies):
        """Test initialization without any authentication method"""
        mock_client, mock_client_class = mock_vault_dependencies

        mock_client.token = None

        config = {}
        with pytest.raises(SecretManagerException, match="No Vault authentication method provided"):
            VaultSecretManager(config)

    @pytest.mark.asyncio
    async def test_get_secret_kv_v2_single_value(self, mock_vault_dependencies):
        """Test getting single-value secret from KV v2"""
        mock_client, mock_client_class = mock_vault_dependencies

        # Mock KV v2 response
        mock_response = {
            'data': {
                'data': {'value': 'secret-value-123'},
                'metadata': {
                    'version': 1,
                    'created_time': '2024-01-01T00:00:00Z'
                }
            }
        }
        mock_client.secrets.kv.v2.read_secret_version.return_value = mock_response

        config = {'token': 'test-token', 'kv_version': 2}
        manager = VaultSecretManager(config)

        secret = await manager.get_secret_with_metadata('test-secret')

        assert secret.value == 'secret-value-123'
        assert secret.key == 'test-secret'
        assert secret.version == '1'
        assert secret.created_at == '2024-01-01T00:00:00Z'
        assert secret.metadata['source'] == 'hashicorp_vault'
        assert secret.metadata['kv_version'] == 2
        assert secret.metadata['is_multi_value'] is False

    @pytest.mark.asyncio
    async def test_get_secret_kv_v2_multi_value(self, mock_vault_dependencies):
        """Test getting multi-value secret from KV v2"""
        mock_client, mock_client_class = mock_vault_dependencies

        mock_response = {
            'data': {
                'data': {
                    'username': 'admin',
                    'password': 'secret123',
                    'host': 'db.example.com'
                },
                'metadata': {'version': 2}
            }
        }
        mock_client.secrets.kv.v2.read_secret_version.return_value = mock_response

        config = {'token': 'test-token', 'kv_version': 2}
        manager = VaultSecretManager(config)

        secret = await manager.get_secret_with_metadata('db-config')

        # Multi-value should be JSON encoded
        import json
        expected_value = json.dumps({
            'username': 'admin',
            'password': 'secret123',
            'host': 'db.example.com'
        })
        assert secret.value == expected_value
        assert secret.metadata['is_multi_value'] is True
        assert secret.metadata['keys'] == ['username', 'password', 'host']

    @pytest.mark.asyncio
    async def test_get_secret_kv_v1(self, mock_vault_dependencies):
        """Test getting secret from KV v1"""
        mock_client, mock_client_class = mock_vault_dependencies

        mock_response = {
            'data': {'value': 'kv1-secret-value'}
        }
        mock_client.secrets.kv.v1.read_secret.return_value = mock_response

        config = {'token': 'test-token', 'kv_version': 1}
        manager = VaultSecretManager(config)

        secret = await manager.get_secret_with_metadata('test-secret')

        assert secret.value == 'kv1-secret-value'
        assert secret.metadata['kv_version'] == 1
        assert secret.version is None  # KV v1 doesn't have versions

    @pytest.mark.asyncio
    async def test_get_secret_not_found(self, mock_vault_dependencies):
        """Test getting non-existent secret"""
        mock_client, mock_client_class = mock_vault_dependencies

        from hvac.exceptions import InvalidPath
        mock_client.secrets.kv.v2.read_secret_version.side_effect = InvalidPath('Path not found')

        config = {'token': 'test-token'}
        manager = VaultSecretManager(config)

        with pytest.raises(SecretNotFoundException, match="Secret 'missing-secret' not found"):
            await manager.get_secret_with_metadata('missing-secret')

    @pytest.mark.asyncio
    async def test_get_secret_access_denied(self, mock_vault_dependencies):
        """Test access denied error"""
        mock_client, mock_client_class = mock_vault_dependencies

        from hvac.exceptions import Forbidden
        mock_client.secrets.kv.v2.read_secret_version.side_effect = Forbidden('Access denied')

        config = {'token': 'test-token'}
        manager = VaultSecretManager(config)

        with pytest.raises(SecretManagerException, match="Access denied to secret"):
            await manager.get_secret_with_metadata('protected-secret')

    @pytest.mark.asyncio
    async def test_list_secrets_kv_v2(self, mock_vault_dependencies):
        """Test listing secrets in KV v2"""
        mock_client, mock_client_class = mock_vault_dependencies

        # Mock recursive listing responses
        def mock_list_secrets(path="", mount_point="secret"):
            if path == "":
                return {
                    'data': {
                        'keys': ['database-password', 'api/', 'jwt-secret']
                    }
                }
            elif path == "api":
                return {
                    'data': {
                        'keys': ['key1', 'key2']
                    }
                }
            return None

        mock_client.secrets.kv.v2.list_secrets.side_effect = mock_list_secrets

        config = {'token': 'test-token', 'kv_version': 2}
        manager = VaultSecretManager(config)

        secrets = await manager.list_secrets()

        assert 'database-password' in secrets
        assert 'jwt-secret' in secrets
        assert 'api/key1' in secrets
        assert 'api/key2' in secrets

    @pytest.mark.asyncio
    async def test_list_secrets_with_prefix(self, mock_vault_dependencies):
        """Test listing secrets with prefix filter"""
        mock_client, mock_client_class = mock_vault_dependencies

        mock_client.secrets.kv.v2.list_secrets.return_value = {
            'data': {
                'keys': ['database-password', 'database-host', 'api-key']
            }
        }

        config = {'token': 'test-token'}
        manager = VaultSecretManager(config)

        database_secrets = await manager.list_secrets('database')

        assert len(database_secrets) == 2
        assert 'database-password' in database_secrets
        assert 'database-host' in database_secrets
        assert 'api-key' not in database_secrets

    @pytest.mark.asyncio
    async def test_health_check_success(self, mock_vault_dependencies):
        """Test successful health check"""
        mock_client, mock_client_class = mock_vault_dependencies

        mock_client.sys.is_initialized.return_value = True
        mock_client.sys.is_sealed.return_value = False
        mock_client.is_authenticated.return_value = True

        config = {'token': 'test-token'}
        manager = VaultSecretManager(config)

        result = await manager.health_check()

        assert result is True

    @pytest.mark.asyncio
    async def test_health_check_sealed(self, mock_vault_dependencies):
        """Test health check when Vault is sealed"""
        mock_client, mock_client_class = mock_vault_dependencies

        mock_client.sys.is_sealed.return_value = True

        config = {'token': 'test-token'}
        manager = VaultSecretManager(config)

        result = await manager.health_check()

        assert result is False

    @pytest.mark.asyncio
    async def test_create_secret_kv_v2_single_value(self, mock_vault_dependencies):
        """Test creating single-value secret in KV v2"""
        mock_client, mock_client_class = mock_vault_dependencies

        config = {'token': 'test-token', 'kv_version': 2}
        manager = VaultSecretManager(config)

        result = await manager.create_secret('new-secret', 'secret-value')

        assert result is True
        mock_client.secrets.kv.v2.create_or_update_secret.assert_called_once_with(
            path='new-secret',
            secret={'value': 'secret-value'},
            mount_point='secret'
        )

    @pytest.mark.asyncio
    async def test_create_secret_kv_v2_multi_value(self, mock_vault_dependencies):
        """Test creating multi-value secret in KV v2"""
        mock_client, mock_client_class = mock_vault_dependencies

        config = {'token': 'test-token', 'kv_version': 2}
        manager = VaultSecretManager(config)

        secret_data = {
            'username': 'admin',
            'password': 'secret123'
        }

        result = await manager.create_secret('db-creds', secret_data)

        assert result is True
        mock_client.secrets.kv.v2.create_or_update_secret.assert_called_once_with(
            path='db-creds',
            secret=secret_data,
            mount_point='secret'
        )

    @pytest.mark.asyncio
    async def test_create_secret_kv_v1(self, mock_vault_dependencies):
        """Test creating secret in KV v1"""
        mock_client, mock_client_class = mock_vault_dependencies

        config = {'token': 'test-token', 'kv_version': 1}
        manager = VaultSecretManager(config)

        result = await manager.create_secret('kv1-secret', 'value')

        assert result is True
        mock_client.secrets.kv.v1.create_or_update_secret.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_secret_kv_v2_soft(self, mock_vault_dependencies):
        """Test soft deleting secret in KV v2"""
        mock_client, mock_client_class = mock_vault_dependencies

        config = {'token': 'test-token', 'kv_version': 2}
        manager = VaultSecretManager(config)

        result = await manager.delete_secret('test-secret', destroy=False)

        assert result is True
        mock_client.secrets.kv.v2.delete_metadata_and_all_versions.assert_called_once_with(
            path='test-secret',
            mount_point='secret'
        )

    @pytest.mark.asyncio
    async def test_delete_secret_kv_v2_destroy(self, mock_vault_dependencies):
        """Test permanently destroying secret in KV v2"""
        mock_client, mock_client_class = mock_vault_dependencies

        config = {'token': 'test-token', 'kv_version': 2}
        manager = VaultSecretManager(config)

        result = await manager.delete_secret('test-secret', destroy=True)

        assert result is True
        mock_client.secrets.kv.v2.destroy_secret_versions.assert_called_once_with(
            path='test-secret',
            versions=None,  # All versions
            mount_point='secret'
        )

    @pytest.mark.asyncio
    async def test_get_secret_versions(self, mock_vault_dependencies):
        """Test getting secret versions (KV v2 only)"""
        mock_client, mock_client_class = mock_vault_dependencies

        mock_response = {
            'data': {
                'versions': {
                    '1': {
                        'created_time': '2024-01-01T00:00:00Z',
                        'deletion_time': None,
                        'destroyed': False
                    },
                    '2': {
                        'created_time': '2024-01-02T00:00:00Z',
                        'deletion_time': '2024-01-03T00:00:00Z',
                        'destroyed': False
                    }
                }
            }
        }
        mock_client.secrets.kv.v2.read_secret_metadata.return_value = mock_response

        config = {'token': 'test-token', 'kv_version': 2}
        manager = VaultSecretManager(config)

        versions = await manager.get_secret_versions('test-secret')

        assert len(versions) == 2
        # Should be sorted by version descending
        assert versions[0]['version'] == 2
        assert versions[1]['version'] == 1

    @pytest.mark.asyncio
    async def test_get_secret_versions_kv_v1_error(self, mock_vault_dependencies):
        """Test getting secret versions with KV v1 (should fail)"""
        mock_client, mock_client_class = mock_vault_dependencies

        config = {'token': 'test-token', 'kv_version': 1}
        manager = VaultSecretManager(config)

        with pytest.raises(SecretManagerException, match="Secret versions are only available in KV v2"):
            await manager.get_secret_versions('test-secret')

    def test_build_secret_path_kv_v2(self, mock_vault_dependencies):
        """Test building secret path for KV v2"""
        mock_client, mock_client_class = mock_vault_dependencies

        config = {'token': 'test-token', 'kv_version': 2, 'mount_point': 'kv'}
        manager = VaultSecretManager(config)

        path = manager._build_secret_path('my/secret')
        assert path == 'kv/data/my/secret'

    def test_build_secret_path_kv_v1(self, mock_vault_dependencies):
        """Test building secret path for KV v1"""
        mock_client, mock_client_class = mock_vault_dependencies

        config = {'token': 'test-token', 'kv_version': 1, 'mount_point': 'secret'}
        manager = VaultSecretManager(config)

        path = manager._build_secret_path('my/secret')
        assert path == 'secret/my/secret'

    def test_repr(self, mock_vault_dependencies):
        """Test string representation"""
        mock_client, mock_client_class = mock_vault_dependencies

        config = {
            'token': 'test-token',
            'vault_url': 'https://vault.example.com:8200',
            'mount_point': 'kv'
        }
        manager = VaultSecretManager(config)

        assert repr(manager) == "VaultSecretManager(url='vault.example.com:8200', mount='kv')"