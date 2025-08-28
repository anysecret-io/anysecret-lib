# tests/test_aws_provider.py
"""
Tests for AWS Secrets Manager provider
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from anysecret.providers.aws import AwsSecretManager
from anysecret.secret_manager import (
    SecretNotFoundException,
    SecretManagerException,
    SecretManagerConnectionException
)


class TestAwsSecretManager:
    """Test AwsSecretManager"""

    @pytest.fixture
    def mock_aws_dependencies(self):
        """Mock AWS dependencies"""
        with patch('anysecret.providers.aws.HAS_AWS', True):
            with patch('boto3.Session') as mock_session_class:
                # Mock session and client
                mock_session = Mock()
                mock_client = Mock()
                mock_session.client.return_value = mock_client
                mock_session_class.return_value = mock_session

                yield mock_client, mock_session, mock_session_class

    def test_init_without_aws_raises_error(self):
        """Test initialization without AWS dependencies raises error"""
        with patch('anysecret.providers.aws.HAS_AWS', False):
            with pytest.raises(SecretManagerException, match="requires 'boto3' package"):
                AwsSecretManager({})

    def test_init_default_config(self, mock_aws_dependencies):
        """Test initialization with default configuration"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        config = {}
        manager = AwsSecretManager(config)

        assert manager.region_name == 'us-east-1'
        assert manager.aws_access_key_id is None
        assert manager.aws_secret_access_key is None
        assert manager._client == mock_client

    def test_init_with_explicit_credentials(self, mock_aws_dependencies):
        """Test initialization with explicit credentials"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        config = {
            'region_name': 'us-west-2',
            'aws_access_key_id': 'test-key-id',
            'aws_secret_access_key': 'test-secret-key',
            'aws_session_token': 'test-session-token'
        }
        manager = AwsSecretManager(config)

        assert manager.region_name == 'us-west-2'
        assert manager.aws_access_key_id == 'test-key-id'
        assert manager.aws_secret_access_key == 'test-secret-key'
        assert manager.aws_session_token == 'test-session-token'

    def test_init_with_endpoint_url(self, mock_aws_dependencies):
        """Test initialization with custom endpoint (for LocalStack)"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        config = {
            'endpoint_url': 'http://localhost:4566'
        }
        manager = AwsSecretManager(config)

        assert manager.endpoint_url == 'http://localhost:4566'
        # Verify client was called with endpoint_url
        mock_session.client.assert_called_once_with('secretsmanager', endpoint_url='http://localhost:4566')

    def test_init_credential_error(self, mock_aws_dependencies):
        """Test initialization with credential errors"""
        mock_client, mock_session, mock_session_class = mock_aws_dependencies

        from botocore.exceptions import NoCredentialsError
        # Make the session.client() call raise the error instead
        mock_session.client.side_effect = NoCredentialsError()

        config = {}
        with pytest.raises(SecretManagerConnectionException, match="AWS credentials not found"):
            AwsSecretManager(config)

    @pytest.mark.asyncio
    async def test_get_secret_with_metadata_string(self, mock_aws_dependencies):
        """Test getting secret with string value"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        # Mock successful response with SecretString
        mock_response = {
            'SecretString': 'my-secret-value',
            'VersionId': 'version-123',
            'CreatedDate': Mock()
        }
        mock_response['CreatedDate'].isoformat.return_value = '2024-01-01T00:00:00Z'
        mock_client.get_secret_value.return_value = mock_response

        config = {}
        manager = AwsSecretManager(config)

        secret = await manager.get_secret_with_metadata('test-secret')

        assert secret.value == 'my-secret-value'
        assert secret.key == 'test-secret'
        assert secret.version == 'version-123'
        assert secret.created_at == '2024-01-01T00:00:00Z'
        assert secret.metadata['source'] == 'aws_secrets_manager'
        assert secret.metadata['region'] == 'us-east-1'
        assert secret.metadata['is_json'] is False

    @pytest.mark.asyncio
    async def test_get_secret_with_metadata_json(self, mock_aws_dependencies):
        """Test getting secret with JSON value"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        json_secret = '{"username": "admin", "password": "secret123"}'
        mock_response = {
            'SecretString': json_secret,
            'VersionId': 'version-456'
        }
        mock_client.get_secret_value.return_value = mock_response

        config = {}
        manager = AwsSecretManager(config)

        secret = await manager.get_secret_with_metadata('db-credentials')

        assert secret.value == json_secret
        assert secret.metadata['is_json'] is True
        assert secret.metadata['json_keys'] == ['username', 'password']

    @pytest.mark.asyncio
    async def test_get_secret_with_metadata_binary(self, mock_aws_dependencies):
        """Test getting secret with binary value"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        # Mock response with SecretBinary
        mock_response = {
            'SecretBinary': b'binary-secret-data',
            'VersionId': 'version-789'
        }
        mock_client.get_secret_value.return_value = mock_response

        config = {}
        manager = AwsSecretManager(config)

        secret = await manager.get_secret_with_metadata('binary-secret')

        assert secret.value == 'binary-secret-data'  # Should be decoded

    @pytest.mark.asyncio
    async def test_get_secret_not_found(self, mock_aws_dependencies):
        """Test getting non-existent secret"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        from botocore.exceptions import ClientError
        error_response = {
            'Error': {
                'Code': 'ResourceNotFoundException',
                'Message': 'Secret not found'
            }
        }
        mock_client.get_secret_value.side_effect = ClientError(error_response, 'GetSecretValue')

        config = {}
        manager = AwsSecretManager(config)

        with pytest.raises(SecretNotFoundException, match="Secret 'missing-secret' not found"):
            await manager.get_secret_with_metadata('missing-secret')

    @pytest.mark.asyncio
    async def test_get_secret_access_denied(self, mock_aws_dependencies):
        """Test access denied error"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        from botocore.exceptions import ClientError
        error_response = {
            'Error': {
                'Code': 'AccessDeniedException',
                'Message': 'Access denied'
            }
        }
        mock_client.get_secret_value.side_effect = ClientError(error_response, 'GetSecretValue')

        config = {}
        manager = AwsSecretManager(config)

        with pytest.raises(SecretManagerException, match="Access denied to secret"):
            await manager.get_secret_with_metadata('protected-secret')

    @pytest.mark.asyncio
    async def test_get_secret_no_value(self, mock_aws_dependencies):
        """Test secret with no value"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        # Response with neither SecretString nor SecretBinary
        mock_response = {
            'VersionId': 'version-empty'
        }
        mock_client.get_secret_value.return_value = mock_response

        config = {}
        manager = AwsSecretManager(config)

        with pytest.raises(SecretManagerException, match="has no value"):
            await manager.get_secret_with_metadata('empty-secret')

    @pytest.mark.asyncio
    async def test_list_secrets(self, mock_aws_dependencies):
        """Test listing secrets"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        # Mock paginator
        mock_paginator = Mock()
        mock_client.get_paginator.return_value = mock_paginator

        # Mock paginated response
        mock_page1 = {
            'SecretList': [
                {'Name': 'database-password'},
                {'Name': 'api-key'}
            ]
        }
        mock_page2 = {
            'SecretList': [
                {'Name': 'jwt-secret'}
            ]
        }
        mock_paginator.paginate.return_value = [mock_page1, mock_page2]

        config = {}
        manager = AwsSecretManager(config)

        secrets = await manager.list_secrets()

        assert len(secrets) == 3
        assert 'api-key' in secrets
        assert 'database-password' in secrets
        assert 'jwt-secret' in secrets
        assert secrets == ['api-key', 'database-password', 'jwt-secret']  # Should be sorted

    @pytest.mark.asyncio
    async def test_list_secrets_with_prefix(self, mock_aws_dependencies):
        """Test listing secrets with prefix filter"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        mock_paginator = Mock()
        mock_client.get_paginator.return_value = mock_paginator

        mock_page = {
            'SecretList': [
                {'Name': 'database-password'},
                {'Name': 'database-host'},
                {'Name': 'api-key'}
            ]
        }
        mock_paginator.paginate.return_value = [mock_page]

        config = {}
        manager = AwsSecretManager(config)

        database_secrets = await manager.list_secrets('database')

        assert len(database_secrets) == 2
        assert 'database-password' in database_secrets
        assert 'database-host' in database_secrets
        assert 'api-key' not in database_secrets

    @pytest.mark.asyncio
    async def test_list_secrets_access_denied(self, mock_aws_dependencies):
        """Test list secrets with access denied"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        from botocore.exceptions import ClientError
        error_response = {
            'Error': {
                'Code': 'AccessDeniedException',
                'Message': 'Access denied'
            }
        }
        mock_paginator = Mock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.side_effect = ClientError(error_response, 'ListSecrets')

        config = {}
        manager = AwsSecretManager(config)

        with pytest.raises(SecretManagerException, match="Access denied listing secrets"):
            await manager.list_secrets()

    @pytest.mark.asyncio
    async def test_get_secrets_by_prefix(self, mock_aws_dependencies):
        """Test getting secrets by prefix"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        # Mock list_secrets response
        mock_paginator = Mock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_page = {
            'SecretList': [
                {'Name': 'auth-jwt-secret'},
                {'Name': 'auth-oauth-key'},
                {'Name': 'database-password'}
            ]
        }
        mock_paginator.paginate.return_value = [mock_page]

        # Mock get_secrets_batch
        async def mock_get_secrets_batch(keys):
            return {
                'auth-jwt-secret': 'jwt-value',
                'auth-oauth-key': 'oauth-value'
            }

        config = {}
        manager = AwsSecretManager(config)

        with patch.object(manager, 'get_secrets_batch', side_effect=mock_get_secrets_batch):
            auth_secrets = await manager.get_secrets_by_prefix('auth')

            assert len(auth_secrets) == 2
            assert auth_secrets['auth-jwt-secret'] == 'jwt-value'
            assert auth_secrets['auth-oauth-key'] == 'oauth-value'

    @pytest.mark.asyncio
    async def test_health_check_success(self, mock_aws_dependencies):
        """Test successful health check"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        mock_client.list_secrets.return_value = {'SecretList': []}

        config = {}
        manager = AwsSecretManager(config)

        result = await manager.health_check()

        assert result is True
        mock_client.list_secrets.assert_called_once_with({'MaxResults': 1})

    @pytest.mark.asyncio
    async def test_health_check_failure(self, mock_aws_dependencies):
        """Test health check failure"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        from botocore.exceptions import ClientError
        error_response = {
            'Error': {
                'Code': 'UnauthorizedOperation',
                'Message': 'Not authorized'
            }
        }
        mock_client.list_secrets.side_effect = ClientError(error_response, 'ListSecrets')

        config = {}
        manager = AwsSecretManager(config)

        result = await manager.health_check()

        assert result is False

    @pytest.mark.asyncio
    async def test_create_secret(self, mock_aws_dependencies):
        """Test creating a new secret"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        config = {}
        manager = AwsSecretManager(config)

        result = await manager.create_secret('new-secret', 'secret-value', 'Test description')

        assert result is True
        mock_client.create_secret.assert_called_once_with({
            'Name': 'new-secret',
            'SecretString': 'secret-value',
            'Description': 'Test description'
        })

    @pytest.mark.asyncio
    async def test_create_secret_already_exists(self, mock_aws_dependencies):
        """Test creating secret that already exists"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        from botocore.exceptions import ClientError
        error_response = {
            'Error': {
                'Code': 'ResourceExistsException',
                'Message': 'Secret already exists'
            }
        }
        mock_client.create_secret.side_effect = ClientError(error_response, 'CreateSecret')

        config = {}
        manager = AwsSecretManager(config)

        with pytest.raises(SecretManagerException, match="Secret 'existing-secret' already exists"):
            await manager.create_secret('existing-secret', 'value')

    @pytest.mark.asyncio
    async def test_update_secret(self, mock_aws_dependencies):
        """Test updating existing secret"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        config = {}
        manager = AwsSecretManager(config)

        result = await manager.update_secret('existing-secret', 'new-value')

        assert result is True
        mock_client.update_secret.assert_called_once_with({
            'SecretId': 'existing-secret',
            'SecretString': 'new-value'
        })

    @pytest.mark.asyncio
    async def test_update_secret_not_found(self, mock_aws_dependencies):
        """Test updating non-existent secret"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        from botocore.exceptions import ClientError
        error_response = {
            'Error': {
                'Code': 'ResourceNotFoundException',
                'Message': 'Secret not found'
            }
        }
        mock_client.update_secret.side_effect = ClientError(error_response, 'UpdateSecret')

        config = {}
        manager = AwsSecretManager(config)

        with pytest.raises(SecretNotFoundException, match="Secret 'missing-secret' not found for update"):
            await manager.update_secret('missing-secret', 'value')

    def test_repr(self, mock_aws_dependencies):
        """Test string representation"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        config = {'region_name': 'eu-west-1'}
        manager = AwsSecretManager(config)

        assert repr(manager) == "AwsSecretManager(region='eu-west-1')"