# tests/test_azure_parameter_manager.py
"""
Tests for Azure parameter manager
"""
import pytest
from unittest.mock import Mock, patch
from anysecret.providers.azure_parameter_manager import AzureAppConfigurationManager
from anysecret.parameter_manager import (
    ParameterNotFoundError,
    ParameterAccessError,
    ParameterManagerError
)


class TestAzureAppConfigurationManager:
    """Test Azure App Configuration manager"""

    @pytest.fixture
    def mock_azure_dependencies(self):
        """Mock Azure dependencies"""
        with patch('anysecret.providers.azure_parameter_manager.HAS_AZURE', True):
            mock_client = Mock()
            mock_credential = Mock()
            
            # Create a mock client class with from_connection_string method
            mock_client_class = Mock(return_value=mock_client)
            mock_client_class.from_connection_string.return_value = mock_client
            
            mock_credential_class = Mock(return_value=mock_credential)

            # Mock the Azure classes in the provider module
            azure_module = __import__('anysecret.providers.azure_parameter_manager', fromlist=['AzureAppConfigurationClient'])
            with patch.object(azure_module, 'AzureAppConfigurationClient', mock_client_class), \
                 patch.object(azure_module, 'DefaultAzureCredential', mock_credential_class):
                yield mock_client

    def test_init_without_azure_raises_error(self):
        """Test initialization without Azure dependencies raises error"""
        with patch('anysecret.providers.azure_parameter_manager.HAS_AZURE', False):
            with pytest.raises(ParameterManagerError, match="azure-appconfiguration and azure-identity are required"):
                AzureAppConfigurationManager({})

    def test_init_without_connection_or_endpoint_raises_error(self, mock_azure_dependencies):
        """Test initialization without connection string or endpoint raises error"""
        mock_client = mock_azure_dependencies

        config = {}
        with pytest.raises(ParameterManagerError, match="Either 'connection_string' or 'endpoint' is required"):
            AzureAppConfigurationManager(config)

    def test_init_with_connection_string(self, mock_azure_dependencies):
        """Test initialization with connection string"""
        mock_client = mock_azure_dependencies

        config = {'connection_string': 'Endpoint=https://test.azconfig.io;Id=test;Secret=test'}
        manager = AzureAppConfigurationManager(config)

        assert manager.connection_string == config['connection_string']
        assert manager.endpoint is None
        assert manager.label == 'Production'
        assert manager.prefix == ''

    def test_init_with_endpoint(self, mock_azure_dependencies):
        """Test initialization with endpoint"""
        mock_client = mock_azure_dependencies

        config = {
            'endpoint': 'https://test.azconfig.io',
            'label': 'Staging',
            'prefix': 'myapp'
        }
        manager = AzureAppConfigurationManager(config)

        assert manager.endpoint == 'https://test.azconfig.io'
        assert manager.connection_string is None
        assert manager.label == 'Staging'
        assert manager.prefix == 'myapp'

    @pytest.mark.asyncio
    async def test_get_parameter_with_metadata_string(self, mock_azure_dependencies):
        """Test getting string parameter"""
        mock_client = mock_azure_dependencies

        # Mock configuration setting
        mock_setting = Mock()
        mock_setting.value = 'localhost'
        mock_setting.label = 'Production'
        mock_setting.content_type = 'text/plain'
        mock_setting.etag = 'etag123'
        mock_setting.last_modified.isoformat.return_value = '2024-01-01T00:00:00Z'
        mock_setting.tags = {'env': 'prod'}
        mock_setting.read_only = False

        mock_client.get_configuration_setting.return_value = mock_setting

        config = {'connection_string': 'test_connection'}
        manager = AzureAppConfigurationManager(config)

        param = await manager.get_parameter_with_metadata('database_host')

        assert param.key == 'database_host'
        assert param.value == 'localhost'
        assert param.metadata['source'] == 'azure_app_configuration'
        assert param.metadata['label'] == 'Production'
        assert param.metadata['content_type'] == 'text/plain'
        assert param.metadata['tags'] == {'env': 'prod'}

        mock_client.get_configuration_setting.assert_called_once_with(
            key='database_host',
            label='Production'
        )

    @pytest.mark.asyncio
    async def test_get_parameter_json_value(self, mock_azure_dependencies):
        """Test getting parameter with JSON value"""
        mock_client = mock_azure_dependencies

        mock_setting = Mock()
        mock_setting.value = '{"host": "localhost", "port": 5432}'
        mock_setting.label = 'Production'
        mock_setting.content_type = 'application/json'
        mock_setting.etag = 'etag456'
        mock_setting.last_modified = None
        mock_setting.tags = {}
        mock_setting.read_only = False

        mock_client.get_configuration_setting.return_value = mock_setting

        config = {'connection_string': 'test_connection'}
        manager = AzureAppConfigurationManager(config)

        param = await manager.get_parameter_with_metadata('db_config')

        assert param.value == {"host": "localhost", "port": 5432}
        assert param.metadata['content_type'] == 'application/json'

    @pytest.mark.asyncio
    async def test_get_parameter_with_prefix(self, mock_azure_dependencies):
        """Test getting parameter with prefix"""
        mock_client = mock_azure_dependencies

        mock_setting = Mock()
        mock_setting.value = 'test_value'
        mock_setting.label = 'Production'
        mock_setting.content_type = 'text/plain'
        mock_setting.etag = 'etag789'
        mock_setting.last_modified = None
        mock_setting.tags = None
        mock_setting.read_only = False

        mock_client.get_configuration_setting.return_value = mock_setting

        config = {'connection_string': 'test_connection', 'prefix': 'app/config'}
        manager = AzureAppConfigurationManager(config)

        param = await manager.get_parameter_with_metadata('database_host')

        assert param.key == 'database_host'
        assert param.value == 'test_value'

        mock_client.get_configuration_setting.assert_called_once_with(
            key='app/config/database_host',
            label='Production'
        )

    @pytest.mark.asyncio
    async def test_get_parameter_not_found(self, mock_azure_dependencies):
        """Test parameter not found error"""
        mock_client = mock_azure_dependencies

        mock_client.get_configuration_setting.side_effect = Exception("ResourceNotFoundError")

        config = {'connection_string': 'test_connection'}
        manager = AzureAppConfigurationManager(config)
        manager.ResourceNotFoundError = Exception

        with pytest.raises(ParameterNotFoundError):
            await manager.get_parameter_with_metadata('nonexistent')

    @pytest.mark.asyncio
    async def test_list_parameters(self, mock_azure_dependencies):
        """Test listing parameters"""
        mock_client = mock_azure_dependencies

        # Mock configuration settings
        mock_setting1 = Mock()
        mock_setting1.key = 'database_host'
        mock_setting2 = Mock()
        mock_setting2.key = 'database_port'
        mock_setting3 = Mock()
        mock_setting3.key = 'api_url'

        mock_client.list_configuration_settings.return_value = [
            mock_setting1, mock_setting2, mock_setting3
        ]

        config = {'connection_string': 'test_connection'}
        manager = AzureAppConfigurationManager(config)

        keys = await manager.list_parameters()

        expected_keys = ['api_url', 'database_host', 'database_port']
        assert sorted(keys) == sorted(expected_keys)

        mock_client.list_configuration_settings.assert_called_once_with(
            key_filter=None,
            label_filter='Production'
        )

    @pytest.mark.asyncio
    async def test_list_parameters_with_prefix_filter(self, mock_azure_dependencies):
        """Test listing parameters with prefix filter"""
        mock_client = mock_azure_dependencies

        mock_setting1 = Mock()
        mock_setting1.key = 'database_host'
        mock_setting2 = Mock()
        mock_setting2.key = 'database_port'

        mock_client.list_configuration_settings.return_value = [mock_setting1, mock_setting2]

        config = {'connection_string': 'test_connection'}
        manager = AzureAppConfigurationManager(config)

        keys = await manager.list_parameters('database')

        expected_keys = ['database_host', 'database_port']
        assert sorted(keys) == sorted(expected_keys)

        mock_client.list_configuration_settings.assert_called_once_with(
            key_filter='database*',
            label_filter='Production'
        )

    @pytest.mark.asyncio
    async def test_health_check_success(self, mock_azure_dependencies):
        """Test successful health check"""
        mock_client = mock_azure_dependencies

        mock_client.list_configuration_settings.return_value = []

        config = {'connection_string': 'test_connection'}
        manager = AzureAppConfigurationManager(config)

        result = await manager.health_check()

        assert result is True
        mock_client.list_configuration_settings.assert_called_once_with(
            label_filter='Production',
            top=1
        )

    @pytest.mark.asyncio
    async def test_health_check_failure(self, mock_azure_dependencies):
        """Test health check failure"""
        mock_client = mock_azure_dependencies

        mock_client.list_configuration_settings.side_effect = Exception("Access denied")

        config = {'connection_string': 'test_connection'}
        manager = AzureAppConfigurationManager(config)

        result = await manager.health_check()

        assert result is False

    @pytest.mark.asyncio
    async def test_create_parameter(self, mock_azure_dependencies):
        """Test creating a new parameter"""
        mock_client = mock_azure_dependencies

        # Mock that parameter doesn't exist
        mock_client.get_configuration_setting.side_effect = Exception("ResourceNotFoundError")
        mock_client.set_configuration_setting.return_value = None

        config = {'connection_string': 'test_connection'}
        manager = AzureAppConfigurationManager(config)
        manager.ResourceNotFoundError = Exception

        with patch('anysecret.providers.azure_parameter_manager.ConfigurationSetting') as mock_setting_class:
            result = await manager.create_parameter('new_param', 'test_value')

        assert result is True
        mock_client.set_configuration_setting.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_parameter_json(self, mock_azure_dependencies):
        """Test creating parameter with JSON value"""
        mock_client = mock_azure_dependencies

        mock_client.get_configuration_setting.side_effect = Exception("ResourceNotFoundError")

        config = {'connection_string': 'test_connection'}
        manager = AzureAppConfigurationManager(config)
        manager.ResourceNotFoundError = Exception

        with patch('anysecret.providers.azure_parameter_manager.ConfigurationSetting') as mock_setting_class:
            result = await manager.create_parameter('config', {'host': 'localhost', 'port': 5432})

        assert result is True
        # Verify JSON serialization in the ConfigurationSetting call
        call_args = mock_setting_class.call_args[1]
        assert call_args['value'] == '{"host": "localhost", "port": 5432}'
        assert call_args['content_type'] == 'application/json'


    @pytest.mark.asyncio
    async def test_update_parameter(self, mock_azure_dependencies):
        """Test updating existing parameter"""
        mock_client = mock_azure_dependencies

        mock_client.set_configuration_setting.return_value = None

        config = {'connection_string': 'test_connection'}
        manager = AzureAppConfigurationManager(config)

        with patch('anysecret.providers.azure_parameter_manager.ConfigurationSetting') as mock_setting_class:
            result = await manager.update_parameter('existing_param', 'new_value')

        assert result is True
        mock_client.set_configuration_setting.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_parameter(self, mock_azure_dependencies):
        """Test deleting parameter"""
        mock_client = mock_azure_dependencies

        mock_client.delete_configuration_setting.return_value = None

        config = {'connection_string': 'test_connection'}
        manager = AzureAppConfigurationManager(config)

        result = await manager.delete_parameter('param_to_delete')

        assert result is True
        mock_client.delete_configuration_setting.assert_called_once_with(
            key='param_to_delete',
            label='Production'
        )

    @pytest.mark.asyncio
    async def test_delete_parameter_not_found(self, mock_azure_dependencies):
        """Test deleting non-existent parameter"""
        mock_client = mock_azure_dependencies

        mock_client.delete_configuration_setting.side_effect = Exception("ResourceNotFoundError")

        config = {'connection_string': 'test_connection'}
        manager = AzureAppConfigurationManager(config)
        manager.ResourceNotFoundError = Exception

        with pytest.raises(ParameterNotFoundError):
            await manager.delete_parameter('nonexistent_param')

    @pytest.mark.asyncio
    async def test_read_only_mode(self, mock_azure_dependencies):
        """Test read-only mode prevents writes"""
        mock_client = mock_azure_dependencies

        config = {'connection_string': 'test_connection', 'read_only': True}
        manager = AzureAppConfigurationManager(config)

        with pytest.raises(ParameterManagerError, match="read-only mode"):
            await manager.create_parameter('test', 'value')

        with pytest.raises(ParameterManagerError, match="read-only mode"):
            await manager.update_parameter('test', 'value')

        with pytest.raises(ParameterManagerError, match="read-only mode"):
            await manager.delete_parameter('test')

    def test_repr(self, mock_azure_dependencies):
        """Test string representation"""
        mock_client = mock_azure_dependencies

        config = {'connection_string': 'test_connection', 'label': 'Development'}
        manager = AzureAppConfigurationManager(config)

        assert 'AzureAppConfigurationManager' in repr(manager)