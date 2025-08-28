# tests/test_config_manager.py
"""
Tests for unified configuration manager
"""
import pytest
import tempfile
import json
from unittest.mock import AsyncMock, Mock, patch

from anysecret.config_manager import ConfigManager, ConfigValue
from anysecret.parameter_manager import ParameterManagerError
from anysecret.secret_manager import SecretManagerType
from anysecret.parameter_manager import ParameterManagerType

class TestConfigManager:
    """Test unified configuration manager"""

    @pytest.fixture
    def temp_secret_file(self):
        """Create temporary file for secrets"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write("DATABASE_PASSWORD=secret123\n")
            f.write("API_TOKEN=token456\n")
            temp_path = f.name

        yield temp_path

        import os
        if os.path.exists(temp_path):
            os.unlink(temp_path)

    @pytest.fixture
    def temp_param_file(self):
        """Create temporary JSON file for parameters"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            test_data = {
                'database': {
                    'host': 'localhost',
                    'port': 5432,
                    'timeout': 30
                },
                'api_url': 'https://api.example.com',
                'debug_mode': True
            }
            json.dump(test_data, f)
            temp_path = f.name

        yield temp_path

        import os
        if os.path.exists(temp_path):
            os.unlink(temp_path)

    @pytest.fixture
    def config_manager(self, temp_secret_file, temp_param_file):
        """Create unified config manager"""
        secret_config = {
            'type': SecretManagerType.ENV_FILE,
            'file_path': temp_secret_file
        }

        parameter_config = {
            'type': ParameterManagerType.FILE_JSON,
            'file_path': temp_param_file
        }

        return ConfigManager(secret_config, parameter_config)

    def test_classify_key_secret_patterns(self, config_manager):
        """Test key classification for secrets"""
        secret_keys = [
            'database_password',
            'api_token',
            'auth_key',
            'user_secret',
            'jwt_credential',
            'oauth_auth'
        ]

        for key in secret_keys:
            assert config_manager.classify_key(key) is True

    def test_classify_key_parameter_patterns(self, config_manager):
        """Test key classification for parameters"""
        parameter_keys = [
            'database_host',
            'api_timeout',
            'connection_limit',
            'server_port',
            'service_url',
            'cache_config',
            'retry_setting'
        ]

        for key in parameter_keys:
            assert config_manager.classify_key(key) is False

    def test_classify_key_with_hint(self, config_manager):
        """Test key classification with manual hints"""
        assert config_manager.classify_key('database_host', 'secret') is True
        assert config_manager.classify_key('api_token', 'parameter') is False

        assert config_manager.classify_key('test_key', 'secrets') is True
        assert config_manager.classify_key('test_key', 'true') is True
        assert config_manager.classify_key('test_key', 'SECRET') is True

    def test_classify_key_default_behavior(self, config_manager):
        """Test default classification for ambiguous keys"""
        ambiguous_keys = [
            'some_config_value',
            'random_setting',
            'application_data'
        ]

        for key in ambiguous_keys:
            assert config_manager.classify_key(key) is False

    @pytest.mark.asyncio
    async def test_get_with_auto_routing(self, config_manager):
        """Test getting values with automatic routing"""
        param_value = await config_manager.get('database.host')
        assert param_value == 'localhost'

        secret_value = await config_manager.get('DATABASE_PASSWORD')
        assert secret_value == 'secret123'

    @pytest.mark.asyncio
    async def test_get_with_metadata(self, config_manager):
        """Test getting values with metadata"""
        param_config = await config_manager.get_with_metadata('api_url')
        assert isinstance(param_config, ConfigValue)
        assert param_config.key == 'api_url'
        assert param_config.value == 'https://api.example.com'
        assert param_config.is_secret is False

        secret_config = await config_manager.get_with_metadata('API_TOKEN')
        assert isinstance(secret_config, ConfigValue)
        assert secret_config.key == 'API_TOKEN'
        assert secret_config.value == 'token456'
        assert secret_config.is_secret is True

    @pytest.mark.asyncio
    async def test_explicit_get_methods(self, config_manager):
        """Test explicit get_secret and get_parameter methods"""
        host = await config_manager.get_parameter('database.host')
        assert host == 'localhost'

        password = await config_manager.get_secret('DATABASE_PASSWORD')
        assert password == 'secret123'

    @pytest.mark.asyncio
    async def test_get_config_by_prefix(self, config_manager):
        """Test getting configuration by prefix"""
        config = await config_manager.get_config_by_prefix('database')

        # Just check that we get some config back
        assert isinstance(config, dict)

        # Check for any keys that contain 'database'
        database_keys = [key for key in config.keys() if 'database' in key.lower()]
        assert len(database_keys) > 0

    @pytest.mark.asyncio
    async def test_list_all_keys(self, config_manager):
        """Test listing all configuration keys"""
        keys = await config_manager.list_all_keys()

        assert 'secrets' in keys
        assert 'parameters' in keys

        assert 'DATABASE_PASSWORD' in keys['secrets']
        assert 'API_TOKEN' in keys['secrets']
        assert 'database.host' in keys['parameters']
        assert 'api_url' in keys['parameters']

    @pytest.mark.asyncio
    async def test_health_check(self, config_manager):
        """Test health check of both managers"""
        health = await config_manager.health_check()

        assert 'secrets' in health
        assert 'parameters' in health
        assert 'overall' in health

        assert health['secrets'] is True
        assert health['parameters'] is True
        assert health['overall'] is True

    def test_get_classification_info(self, config_manager):
        """Test getting classification pattern information"""
        info = config_manager.get_classification_info()

        assert 'secret_patterns' in info
        assert 'parameter_patterns' in info

        assert '.*_secret$' in info['secret_patterns']
        assert '.*_password$' in info['secret_patterns']
        assert '.*_config$' in info['parameter_patterns']
        assert '.*_timeout$' in info['parameter_patterns']

    def test_custom_patterns(self):
        """Test custom classification patterns"""
        secret_config = {
            'type': SecretManagerType.ENV_FILE,  # Use ENV_FILE instead
            'file_path': 'secrets.env',
            'secret_patterns': ['.*_custom_secret$']
        }

        parameter_config = {
            'type': ParameterManagerType.FILE_JSON,
            'file_path': 'params.json',
            'parameter_patterns': ['.*_custom_param$']
        }

        manager = ConfigManager(secret_config, parameter_config)

        assert manager.classify_key('my_custom_secret') is True
        assert manager.classify_key('my_custom_param') is False

    def test_config_value_string_representation(self):
        """Test ConfigValue string representations"""
        param = ConfigValue('test_key', 'test_value', False)
        assert str(param) == 'test_value'

        secret = ConfigValue('secret_key', 'secret_value', True)
        assert str(secret) == '[SECRET]'

        param_repr = repr(param)
        assert 'test_key' in param_repr
        assert 'test_value' in param_repr
        assert 'is_secret=False' in param_repr

        secret_repr = repr(secret)
        assert 'secret_key' in secret_repr
        assert '[SECRET]' in secret_repr
        assert 'is_secret=True' in secret_repr


class TestConfigManagerErrorHandling:
    """Test error handling in ConfigManager"""

    def test_missing_secret_manager_type(self):
        """Test error when secret manager type is missing"""
        secret_config = {}
        parameter_config = {'type': 'file_json'}

        with pytest.raises(ParameterManagerError, match="Secret manager type is required"):
            ConfigManager(secret_config, parameter_config)

    def test_missing_parameter_manager_type(self):
        secret_config = {'type': SecretManagerType.ENCRYPTED_FILE}  # was 'file_json'
        parameter_config = {}

        with pytest.raises(ParameterManagerError, match="Parameter manager type is required"):
            ConfigManager(secret_config, parameter_config)

    @pytest.mark.asyncio
    async def test_graceful_error_handling_in_prefix_search(self):
        """Test that prefix search handles errors gracefully"""
        secret_config = {
            'type': SecretManagerType.ENV_FILE,  # Change from ENCRYPTED_FILE
            'file_path': '/nonexistent/secrets.env'
        }
        parameter_config = {
            'type': ParameterManagerType.FILE_JSON,
            'file_path': '/nonexistent/params.json'
        }

        manager = ConfigManager(secret_config, parameter_config)

        config = await manager.get_config_by_prefix('test')
        assert isinstance(config, dict)