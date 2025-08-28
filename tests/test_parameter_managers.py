# tests/test_parameter_managers.py
"""
Tests for parameter manager providers
"""
import pytest
import json
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from anysecret.parameter_manager import (
    ParameterManagerFactory,
    ParameterManagerType,
    ParameterValue,
    ParameterNotFoundError,
    ParameterAccessError,
    ParameterManagerError
)
from anysecret.providers.file_parameter_manager import FileJsonParameterManager, FileYamlParameterManager
from anysecret.providers.aws_parameter_manager import AwsParameterStoreManager


class TestParameterManagerFactory:
    """Test parameter manager factory"""

    def test_create_file_json_manager(self):
        """Test creating file JSON parameter manager"""
        factory = ParameterManagerFactory()
        config = {'file_path': 'test.json'}

        manager = factory.create_manager(ParameterManagerType.FILE_JSON, config)
        assert isinstance(manager, FileJsonParameterManager)
        assert manager.file_path == Path('test.json')

    def test_create_manager_with_string_type(self):
        """Test creating manager with string type"""
        factory = ParameterManagerFactory()
        config = {'file_path': 'test.json'}

        manager = factory.create_manager('file_json', config)
        assert isinstance(manager, FileJsonParameterManager)

    def test_create_manager_invalid_type(self):
        """Test creating manager with invalid type"""
        factory = ParameterManagerFactory()
        config = {}

        with pytest.raises(ParameterManagerError):
            factory.create_manager('invalid_type', config)

    def test_detect_available_managers(self):
        """Test detecting available parameter managers"""
        factory = ParameterManagerFactory()
        available = factory.detect_available_managers()

        assert ParameterManagerType.FILE_JSON in available
        assert ParameterManagerType.FILE_YAML in available


class TestFileJsonParameterManager:
    """Test JSON file parameter manager"""

    @pytest.fixture
    def temp_file(self):
        """Create temporary JSON file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            test_data = {
                'database': {
                    'host': 'localhost',
                    'port': 5432,
                    'timeout': 30
                },
                'api_url': 'https://api.example.com',
                'debug_mode': True,
                'features': ['feature1', 'feature2']
            }
            json.dump(test_data, f)
            temp_path = f.name

        yield temp_path

        if os.path.exists(temp_path):
            os.unlink(temp_path)

    @pytest.fixture
    def manager(self, temp_file):
        """Create file parameter manager"""
        config = {'file_path': temp_file}
        return FileJsonParameterManager(config)

    @pytest.mark.asyncio
    async def test_get_parameter_with_metadata_simple(self, manager):
        """Test getting simple parameter"""
        param = await manager.get_parameter_with_metadata('api_url')

        assert param.key == 'api_url'
        assert param.value == 'https://api.example.com'
        assert param.metadata['type'] == 'json_file'
        assert param.metadata['source'].endswith('.json')

    @pytest.mark.asyncio
    async def test_get_parameter_with_metadata_nested(self, manager):
        """Test getting nested parameter"""
        param = await manager.get_parameter_with_metadata('database.host')

        assert param.key == 'database.host'
        assert param.value == 'localhost'

        port_param = await manager.get_parameter_with_metadata('database.port')
        assert port_param.value == 5432

    @pytest.mark.asyncio
    async def test_get_parameter_not_found(self, manager):
        """Test getting non-existent parameter"""
        with pytest.raises(ParameterNotFoundError):
            await manager.get_parameter_with_metadata('nonexistent')

    @pytest.mark.asyncio
    async def test_get_parameter_convenience_method(self, manager):
        """Test convenience get_parameter method"""
        value = await manager.get_parameter('debug_mode')
        assert value is True

    @pytest.mark.asyncio
    async def test_list_parameters(self, manager):
        """Test listing all parameters"""
        keys = await manager.list_parameters()

        expected_keys = [
            'api_url',
            'database.host',
            'database.port',
            'database.timeout',
            'debug_mode',
            'features'
        ]

        for key in expected_keys:
            assert key in keys

    @pytest.mark.asyncio
    async def test_list_parameters_with_prefix(self, manager):
        """Test listing parameters with prefix"""
        keys = await manager.list_parameters('database')

        assert 'database.host' in keys
        assert 'database.port' in keys
        assert 'database.timeout' in keys
        assert 'api_url' not in keys

    @pytest.mark.asyncio
    async def test_health_check(self, manager):
        """Test health check"""
        result = await manager.health_check()
        assert result is True

    @pytest.mark.asyncio
    async def test_create_parameter(self, manager):
        """Test creating new parameter"""
        success = await manager.create_parameter('new_config', 'test_value')
        assert success is True

        value = await manager.get_parameter('new_config')
        assert value == 'test_value'

    @pytest.mark.asyncio
    async def test_create_parameter_nested(self, manager):
        """Test creating nested parameter"""
        success = await manager.create_parameter('cache.redis.host', 'redis.example.com')
        assert success is True

        value = await manager.get_parameter('cache.redis.host')
        assert value == 'redis.example.com'

    @pytest.mark.asyncio
    async def test_create_parameter_already_exists(self, manager):
        """Test creating parameter that already exists"""
        with pytest.raises(ParameterManagerError):
            await manager.create_parameter('api_url', 'new_value')

    @pytest.mark.asyncio
    async def test_update_parameter(self, manager):
        """Test updating existing parameter"""
        success = await manager.update_parameter('debug_mode', False)
        assert success is True

        value = await manager.get_parameter('debug_mode')
        assert value is False

    @pytest.mark.asyncio
    async def test_delete_parameter(self, manager):
        """Test deleting parameter"""
        success = await manager.delete_parameter('debug_mode')
        assert success is True

        with pytest.raises(ParameterNotFoundError):
            await manager.get_parameter('debug_mode')

    @pytest.mark.asyncio
    async def test_read_only_mode(self, temp_file):
        """Test read-only mode prevents writes"""
        config = {'file_path': temp_file, 'read_only': True}
        manager = FileJsonParameterManager(config)

        with pytest.raises(ParameterManagerError, match="read-only mode"):
            await manager.create_parameter('test', 'value')

        with pytest.raises(ParameterManagerError, match="read-only mode"):
            await manager.update_parameter('api_url', 'new_value')

        with pytest.raises(ParameterManagerError, match="read-only mode"):
            await manager.delete_parameter('api_url')


class TestFileYamlParameterManager:
    """Test YAML file parameter manager"""

    @pytest.fixture
    def temp_yaml_file(self):
        """Create temporary YAML file"""
        yaml_content = '''
database:
  host: localhost
  port: 5432
  timeout: 30

api_url: https://api.example.com
debug_mode: true
features:
  - feature1
  - feature2
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            temp_path = f.name

        yield temp_path

        if os.path.exists(temp_path):
            os.unlink(temp_path)

    @pytest.fixture
    def yaml_manager(self, temp_yaml_file):
        """Create YAML parameter manager"""
        config = {'file_path': temp_yaml_file}
        return FileYamlParameterManager(config)

    @pytest.mark.asyncio
    async def test_yaml_get_parameter(self, yaml_manager):
        """Test getting parameters from YAML file"""
        param = await yaml_manager.get_parameter_with_metadata('api_url')

        assert param.key == 'api_url'
        assert param.value == 'https://api.example.com'
        assert param.metadata['type'] == 'yaml_file'

    @pytest.mark.asyncio
    async def test_yaml_nested_parameter(self, yaml_manager):
        """Test getting nested parameters from YAML"""
        host = await yaml_manager.get_parameter('database.host')
        assert host == 'localhost'

        port = await yaml_manager.get_parameter('database.port')
        assert port == 5432

    def test_yaml_missing_dependency(self):
        """Test handling missing PyYAML dependency"""
        with patch.dict('sys.modules', {'yaml': None}):
            with pytest.raises(ParameterManagerError, match="PyYAML is required"):
                FileYamlParameterManager({'file_path': 'test.yaml'})


class TestAwsParameterStoreManager:
    """Test AWS Parameter Store manager"""

    @pytest.fixture
    def mock_aws_dependencies(self):
        """Mock AWS dependencies"""
        with patch('boto3.Session') as mock_session_class:
            mock_session = Mock()
            mock_client = Mock()
            mock_session.client.return_value = mock_client
            mock_session_class.return_value = mock_session

            yield mock_client, mock_session, mock_session_class

    def test_init_without_boto3_raises_error(self):
        """Test initialization without boto3 raises error"""
        with patch.dict('sys.modules', {'boto3': None}):
            with pytest.raises(ParameterManagerError, match="boto3 is required"):
                AwsParameterStoreManager({})

    def test_init_default_config(self, mock_aws_dependencies):
        """Test initialization with default configuration"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        config = {}
        manager = AwsParameterStoreManager(config)

        assert manager.region == 'us-east-1'
        assert manager.prefix == ''
        assert manager.ssm_client == mock_client

    def test_init_with_config(self, mock_aws_dependencies):
        """Test initialization with custom configuration"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        config = {
            'region': 'us-west-2',
            'prefix': '/myapp/',
            'aws_access_key_id': 'test-key',
            'aws_secret_access_key': 'test-secret'
        }
        manager = AwsParameterStoreManager(config)

        assert manager.region == 'us-west-2'
        assert manager.prefix == '/myapp/'

    @pytest.mark.asyncio
    async def test_get_parameter_with_metadata_string(self, mock_aws_dependencies):
        """Test getting string parameter"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        mock_response = {
            'Parameter': {
                'Name': '/test/app/database_host',
                'Value': 'db.example.com',
                'Type': 'String',
                'Version': 1,
                'LastModifiedDate': Mock(),
                'ARN': 'arn:aws:ssm:us-east-1:123456789012:parameter/test/app/database_host'
            }
        }
        mock_response['Parameter']['LastModifiedDate'].isoformat.return_value = '2024-01-01T00:00:00Z'
        mock_client.get_parameter.return_value = mock_response

        config = {'prefix': '/test/app/'}
        manager = AwsParameterStoreManager(config)

        param = await manager.get_parameter_with_metadata('database_host')

        assert param.key == 'database_host'
        assert param.value == 'db.example.com'
        assert param.metadata['type'] == 'String'
        assert param.metadata['version'] == 1
        assert param.metadata['source'] == 'aws_parameter_store'
        assert param.metadata['region'] == 'us-east-1'

        mock_client.get_parameter.assert_called_once_with(
            Name='/test/app/database_host',
            WithDecryption=True
        )

    @pytest.mark.asyncio
    async def test_get_parameter_json_value(self, mock_aws_dependencies):
        """Test getting parameter with JSON value"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        json_value = '{"host": "localhost", "port": 5432}'
        mock_response = {
            'Parameter': {
                'Name': '/test/app/db_config',
                'Value': json_value,
                'Type': 'String',
                'Version': 1
            }
        }
        mock_client.get_parameter.return_value = mock_response

        config = {'prefix': '/test/app/'}
        manager = AwsParameterStoreManager(config)

        param = await manager.get_parameter_with_metadata('db_config')

        assert param.value == {"host": "localhost", "port": 5432}

    @pytest.mark.asyncio
    async def test_get_parameter_string_list(self, mock_aws_dependencies):
        """Test getting StringList parameter"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        mock_response = {
            'Parameter': {
                'Name': '/test/app/allowed_hosts',
                'Value': 'host1.com,host2.com,host3.com',
                'Type': 'StringList',
                'Version': 1
            }
        }
        mock_client.get_parameter.return_value = mock_response

        config = {'prefix': '/test/app/'}
        manager = AwsParameterStoreManager(config)

        param = await manager.get_parameter_with_metadata('allowed_hosts')

        assert param.value == ['host1.com', 'host2.com', 'host3.com']

    @pytest.mark.asyncio
    async def test_get_parameter_not_found(self, mock_aws_dependencies):
        """Test parameter not found error"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        from botocore.exceptions import ClientError
        error_response = {
            'Error': {
                'Code': 'ParameterNotFound',
                'Message': 'Parameter not found'
            }
        }
        mock_client.get_parameter.side_effect = ClientError(error_response, 'GetParameter')

        config = {}
        manager = AwsParameterStoreManager(config)

        with pytest.raises(ParameterNotFoundError):
            await manager.get_parameter_with_metadata('nonexistent')

    @pytest.mark.asyncio
    async def test_list_parameters(self, mock_aws_dependencies):
        """Test listing parameters"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        mock_paginator = Mock()
        mock_client.get_paginator.return_value = mock_paginator

        mock_paginator.paginate.return_value = [
            {
                'Parameters': [
                    {'Name': '/test/app/database_host'},
                    {'Name': '/test/app/database_port'},
                    {'Name': '/test/app/api_key'}
                ]
            }
        ]

        config = {'prefix': '/test/app/'}
        manager = AwsParameterStoreManager(config)

        keys = await manager.list_parameters()

        expected_keys = ['database_host', 'database_port', 'api_key']
        assert sorted(keys) == sorted(expected_keys)

    @pytest.mark.asyncio
    async def test_create_parameter(self, mock_aws_dependencies):
        """Test creating parameter"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        mock_client.put_parameter.return_value = {}

        config = {'prefix': '/test/app/'}
        manager = AwsParameterStoreManager(config)

        success = await manager.create_parameter('new_config', 'test_value')

        assert success is True
        mock_client.put_parameter.assert_called_once()

        call_args = mock_client.put_parameter.call_args[1]
        assert call_args['Name'] == '/test/app/new_config'
        assert call_args['Value'] == 'test_value'
        assert call_args['Type'] == 'String'
        assert call_args['Overwrite'] is False

    @pytest.mark.asyncio
    async def test_health_check(self, mock_aws_dependencies):
        """Test health check"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        mock_client.describe_parameters.return_value = {'Parameters': []}

        config = {}
        manager = AwsParameterStoreManager(config)

        result = await manager.health_check()
        assert result is True

        mock_client.describe_parameters.assert_called_once_with(MaxResults=1)

    def test_repr(self, mock_aws_dependencies):
        """Test string representation"""
        mock_client, mock_session, mock_boto3 = mock_aws_dependencies

        config = {'region': 'eu-west-1', 'prefix': '/myapp/'}
        manager = AwsParameterStoreManager(config)

        assert 'AwsParameterStoreManager' in repr(manager)


class TestParameterValue:
    """Test ParameterValue class"""

    def test_parameter_value_creation(self):
        """Test creating ParameterValue"""
        metadata = {'source': 'test', 'type': 'string'}
        param = ParameterValue('test_key', 'test_value', metadata)

        assert param.key == 'test_key'
        assert param.value == 'test_value'
        assert param.metadata == metadata

    def test_parameter_value_string_representation(self):
        """Test string representation"""
        param = ParameterValue('test_key', 'test_value')
        assert str(param) == 'test_value'

    def test_parameter_value_repr(self):
        """Test repr representation"""
        param = ParameterValue('test_key', 'test_value')
        expected = "ParameterValue(key='test_key', value='test_value', metadata={})"
        assert repr(param) == expected