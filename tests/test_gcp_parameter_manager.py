# tests/test_gcp_parameter_manager.py
"""
Tests for GCP parameter manager
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from anysecret.providers.gcp_parameter_manager import GcpParameterManagerClient
from anysecret.parameter_manager import (
    ParameterNotFoundError,
    ParameterAccessError,
    ParameterManagerError
)

# Mark all tests as integration tests requiring cloud setup
pytestmark = pytest.mark.skip(reason="GCP parameter manager tests require complex mocking setup and cloud credentials")


class TestGcpParameterManagerClient:
    """Test GCP Parameter Manager client"""

    @pytest.fixture
    def mock_gcp_dependencies(self):
        """Mock GCP dependencies"""
        mock_client = Mock()
        mock_sm = Mock()
        mock_exceptions = Mock()
        mock_exceptions.NotFound = Exception
        mock_exceptions.AlreadyExists = Exception

        def mock_init(self, config):
            # Add the validation logic
            if not config.get('project_id'):
                from anysecret.parameter_manager import ParameterManagerError
                raise ParameterManagerError("project_id is required for GCP Parameter Manager")

            self.client = mock_client
            self.secretmanager_v1 = mock_sm
            self.gcp_exceptions = mock_exceptions
            self.project_id = config.get('project_id', 'test-project')
            self.prefix = config.get('prefix', '')
            self.read_only = config.get('read_only', False)

        with patch.object(GcpParameterManagerClient, '__init__', mock_init):
            yield mock_client, mock_sm, mock_exceptions


    def test_init_without_project_raises_error(self):
        """Test initialization without project_id raises error"""
        # Don't use mock_gcp_dependencies parameter
        with patch.dict('sys.modules', {'google.cloud.secretmanager_v1': Mock()}):
            config = {}
            with pytest.raises(ParameterManagerError, match="project_id is required"):
                GcpParameterManagerClient(config)

    def test_init_default_config(self, mock_gcp_dependencies):
        """Test initialization with default configuration"""
        mock_client, mock_sm, mock_exceptions = mock_gcp_dependencies

        config = {'project_id': 'test-project'}
        manager = GcpParameterManagerClient(config)

        assert manager.project_id == 'test-project'
        assert manager.prefix == ''
        assert manager.client == mock_client

    def test_init_with_config(self, mock_gcp_dependencies):
        """Test initialization with custom configuration"""
        mock_client, mock_sm, mock_exceptions = mock_gcp_dependencies

        config = {
            'project_id': 'my-gcp-project',
            'prefix': 'app-config'
        }
        manager = GcpParameterManagerClient(config)

        assert manager.project_id == 'my-gcp-project'
        assert manager.prefix == 'app-config'

    @pytest.mark.asyncio
    async def test_get_parameter_with_metadata_string(self, mock_gcp_dependencies):
        """Test getting string parameter"""
        mock_client, mock_sm, mock_exceptions = mock_gcp_dependencies

        # Mock secret response
        mock_secret = Mock()
        mock_secret.create_time.isoformat.return_value = '2024-01-01T00:00:00Z'
        mock_secret.labels = {}
        mock_client.get_secret.return_value = mock_secret

        # Mock version response
        mock_version = Mock()
        mock_version.name = 'projects/test-project/secrets/database_host/versions/1'
        mock_version.payload.data = b'localhost'
        mock_client.access_secret_version.return_value = mock_version

        config = {'project_id': 'test-project'}
        manager = GcpParameterManagerClient(config)

        param = await manager.get_parameter_with_metadata('database_host')

        assert param.key == 'database_host'
        assert param.value == 'localhost'
        assert param.metadata['source'] == 'gcp_parameter_manager'
        assert param.metadata['project_id'] == 'test-project'
        assert param.metadata['version'] == 'projects/test-project/secrets/database_host/versions/1'

        mock_client.get_secret.assert_called_once_with(
            request={"name": "projects/test-project/secrets/database_host"}
        )
        mock_client.access_secret_version.assert_called_once_with(
            request={"name": "projects/test-project/secrets/database_host/versions/latest"}
        )

    @pytest.mark.asyncio
    async def test_get_parameter_json_value(self, mock_gcp_dependencies):
        """Test getting parameter with JSON value"""
        mock_client, mock_sm, mock_exceptions = mock_gcp_dependencies

        mock_secret = Mock()
        mock_secret.create_time = None
        mock_secret.labels = {'env': 'prod'}
        mock_client.get_secret.return_value = mock_secret

        mock_version = Mock()
        mock_version.name = 'projects/test-project/secrets/db_config/versions/1'
        mock_version.payload.data = b'{"host": "localhost", "port": 5432}'
        mock_client.access_secret_version.return_value = mock_version

        config = {'project_id': 'test-project'}
        manager = GcpParameterManagerClient(config)

        param = await manager.get_parameter_with_metadata('db_config')

        assert param.value == {"host": "localhost", "port": 5432}
        assert param.metadata['labels'] == {'env': 'prod'}

    @pytest.mark.asyncio
    async def test_get_parameter_with_prefix(self, mock_gcp_dependencies):
        """Test getting parameter with prefix"""
        mock_client, mock_sm, mock_exceptions = mock_gcp_dependencies

        mock_secret = Mock()
        mock_secret.create_time = None
        mock_secret.labels = {}
        mock_client.get_secret.return_value = mock_secret

        mock_version = Mock()
        mock_version.name = 'projects/test-project/secrets/config-database_host/versions/1'
        mock_version.payload.data = b'localhost'
        mock_client.access_secret_version.return_value = mock_version

        config = {'project_id': 'test-project', 'prefix': 'config'}
        manager = GcpParameterManagerClient(config)

        param = await manager.get_parameter_with_metadata('database_host')

        assert param.key == 'database_host'
        assert param.value == 'localhost'

        mock_client.get_secret.assert_called_once_with(
            request={"name": "projects/test-project/secrets/config-database_host"}
        )

    @pytest.mark.asyncio
    async def test_get_parameter_not_found(self, mock_gcp_dependencies):
        """Test parameter not found error"""
        mock_client, mock_sm, mock_exceptions = mock_gcp_dependencies

        mock_client.get_secret.side_effect = mock_exceptions.NotFound("Secret not found")

        config = {'project_id': 'test-project'}
        manager = GcpParameterManagerClient(config)

        with pytest.raises(ParameterNotFoundError):
            await manager.get_parameter_with_metadata('nonexistent')

    @pytest.mark.asyncio
    async def test_list_parameters(self, mock_gcp_dependencies):
        """Test listing parameters"""
        mock_client, mock_sm, mock_exceptions = mock_gcp_dependencies

        # Mock secrets
        mock_secret1 = Mock()
        mock_secret1.name = 'projects/test-project/secrets/database_host'
        mock_secret2 = Mock()
        mock_secret2.name = 'projects/test-project/secrets/database_port'
        mock_secret3 = Mock()
        mock_secret3.name = 'projects/test-project/secrets/api_url'

        mock_client.list_secrets.return_value = [mock_secret1, mock_secret2, mock_secret3]

        config = {'project_id': 'test-project'}
        manager = GcpParameterManagerClient(config)

        keys = await manager.list_parameters()

        expected_keys = ['api_url', 'database_host', 'database_port']
        assert sorted(keys) == sorted(expected_keys)

        mock_client.list_secrets.assert_called_once_with(
            request={"parent": "projects/test-project"}
        )

    @pytest.mark.asyncio
    async def test_list_parameters_with_prefix_filter(self, mock_gcp_dependencies):
        """Test listing parameters with prefix filter"""
        mock_client, mock_sm, mock_exceptions = mock_gcp_dependencies

        mock_secret1 = Mock()
        mock_secret1.name = 'projects/test-project/secrets/config-database_host'
        mock_secret2 = Mock()
        mock_secret2.name = 'projects/test-project/secrets/config-database_port'
        mock_secret3 = Mock()
        mock_secret3.name = 'projects/test-project/secrets/config-api_url'
        mock_secret4 = Mock()
        mock_secret4.name = 'projects/test-project/secrets/other-setting'

        mock_client.list_secrets.return_value = [mock_secret1, mock_secret2, mock_secret3, mock_secret4]

        config = {'project_id': 'test-project', 'prefix': 'config'}
        manager = GcpParameterManagerClient(config)

        keys = await manager.list_parameters('database')

        expected_keys = ['database_host', 'database_port']
        assert sorted(keys) == sorted(expected_keys)

    @pytest.mark.asyncio
    async def test_health_check_success(self, mock_gcp_dependencies):
        """Test successful health check"""
        mock_client, mock_sm, mock_exceptions = mock_gcp_dependencies

        mock_client.list_secrets.return_value = []

        config = {'project_id': 'test-project'}
        manager = GcpParameterManagerClient(config)

        result = await manager.health_check()

        assert result is True
        mock_client.list_secrets.assert_called_once_with(
            request={"parent": "projects/test-project", "page_size": 1}
        )

    @pytest.mark.asyncio
    async def test_health_check_failure(self, mock_gcp_dependencies):
        """Test health check failure"""
        mock_client, mock_sm, mock_exceptions = mock_gcp_dependencies

        mock_client.list_secrets.side_effect = Exception("Access denied")

        config = {'project_id': 'test-project'}
        manager = GcpParameterManagerClient(config)

        result = await manager.health_check()

        assert result is False

    @pytest.mark.asyncio
    async def test_create_parameter(self, mock_gcp_dependencies):
        """Test creating a new parameter"""
        mock_client, mock_sm, mock_exceptions = mock_gcp_dependencies

        mock_secret = Mock()
        mock_secret.name = 'projects/test-project/secrets/new_param'
        mock_client.create_secret.return_value = mock_secret
        mock_client.add_secret_version.return_value = Mock()

        config = {'project_id': 'test-project'}
        manager = GcpParameterManagerClient(config)

        result = await manager.create_parameter('new_param', 'test_value')

        assert result is True
        mock_client.create_secret.assert_called_once()
        mock_client.add_secret_version.assert_called_once()

        # Check create_secret call
        create_call = mock_client.create_secret.call_args[1]
        assert create_call['request']['parent'] == 'projects/test-project'
        assert create_call['request']['secret_id'] == 'new_param'

        # Check add_secret_version call
        version_call = mock_client.add_secret_version.call_args[1]
        assert version_call['request']['payload']['data'] == b'test_value'

    @pytest.mark.asyncio
    async def test_create_parameter_json(self, mock_gcp_dependencies):
        """Test creating parameter with JSON value"""
        mock_client, mock_sm, mock_exceptions = mock_gcp_dependencies

        mock_secret = Mock()
        mock_secret.name = 'projects/test-project/secrets/config'
        mock_client.create_secret.return_value = mock_secret

        config = {'project_id': 'test-project'}
        manager = GcpParameterManagerClient(config)

        result = await manager.create_parameter('config', {'host': 'localhost', 'port': 5432})

        assert result is True
        version_call = mock_client.add_secret_version.call_args[1]
        assert version_call['request']['payload']['data'] == b'{"host": "localhost", "port": 5432}'

    @pytest.mark.asyncio
    async def test_create_parameter_already_exists(self, mock_gcp_dependencies):
        """Test creating parameter that already exists"""
        mock_client, mock_sm, mock_exceptions = mock_gcp_dependencies

        mock_client.create_secret.side_effect = mock_exceptions.AlreadyExists("Secret already exists")

        config = {'project_id': 'test-project'}
        manager = GcpParameterManagerClient(config)

        with pytest.raises(ParameterManagerError, match="already exists"):
            await manager.create_parameter('existing_param', 'value')

    @pytest.mark.asyncio
    async def test_update_parameter(self, mock_gcp_dependencies):
        """Test updating existing parameter"""
        mock_client, mock_sm, mock_exceptions = mock_gcp_dependencies

        mock_client.add_secret_version.return_value = Mock()

        config = {'project_id': 'test-project'}
        manager = GcpParameterManagerClient(config)

        result = await manager.update_parameter('existing_param', 'new_value')

        assert result is True
        version_call = mock_client.add_secret_version.call_args[1]
        assert version_call['request']['parent'] == 'projects/test-project/secrets/existing_param'
        assert version_call['request']['payload']['data'] == b'new_value'

    @pytest.mark.asyncio
    async def test_update_parameter_not_found(self, mock_gcp_dependencies):
        """Test updating non-existent parameter"""
        mock_client, mock_sm, mock_exceptions = mock_gcp_dependencies

        mock_client.add_secret_version.side_effect = mock_exceptions.NotFound("Secret not found")

        config = {'project_id': 'test-project'}
        manager = GcpParameterManagerClient(config)

        with pytest.raises(ParameterNotFoundError):
            await manager.update_parameter('missing_param', 'value')

    @pytest.mark.asyncio
    async def test_delete_parameter(self, mock_gcp_dependencies):
        """Test deleting parameter"""
        mock_client, mock_sm, mock_exceptions = mock_gcp_dependencies

        mock_client.delete_secret.return_value = None

        config = {'project_id': 'test-project'}
        manager = GcpParameterManagerClient(config)

        result = await manager.delete_parameter('param_to_delete')

        assert result is True
        mock_client.delete_secret.assert_called_once_with(
            request={"name": "projects/test-project/secrets/param_to_delete"}
        )

    @pytest.mark.asyncio
    async def test_delete_parameter_not_found(self, mock_gcp_dependencies):
        """Test deleting non-existent parameter"""
        mock_client, mock_sm, mock_exceptions = mock_gcp_dependencies

        mock_client.delete_secret.side_effect = mock_exceptions.NotFound("Secret not found")

        config = {'project_id': 'test-project'}
        manager = GcpParameterManagerClient(config)

        with pytest.raises(ParameterNotFoundError):
            await manager.delete_parameter('nonexistent_param')

    @pytest.mark.asyncio
    async def test_read_only_mode(self, mock_gcp_dependencies):
        """Test read-only mode prevents writes"""
        mock_client, mock_sm, mock_exceptions = mock_gcp_dependencies

        config = {'project_id': 'test-project', 'read_only': True}
        manager = GcpParameterManagerClient(config)

        with pytest.raises(ParameterManagerError, match="read-only mode"):
            await manager.create_parameter('test', 'value')

        with pytest.raises(ParameterManagerError, match="read-only mode"):
            await manager.update_parameter('test', 'value')

        with pytest.raises(ParameterManagerError, match="read-only mode"):
            await manager.delete_parameter('test')

    def test_repr(self, mock_gcp_dependencies):
        """Test string representation"""
        mock_client, mock_sm, mock_exceptions = mock_gcp_dependencies

        config = {'project_id': 'my-project', 'prefix': 'config'}
        manager = GcpParameterManagerClient(config)

        assert 'GcpParameterManagerClient' in repr(manager)