# tests/test_kubernetes_parameter_manager.py
"""
Tests for Kubernetes parameter manager
"""
import pytest
from unittest.mock import Mock, patch
from anysecret.providers.kubernetes_parameter_manager import KubernetesConfigMapManager
from anysecret.parameter_manager import (
    ParameterNotFoundError,
    ParameterAccessError,
    ParameterManagerError
)


class TestKubernetesConfigMapManager:
    """Test Kubernetes ConfigMap manager"""

    @pytest.fixture
    def mock_k8s_dependencies(self):
        """Mock Kubernetes dependencies"""
        mock_v1_api = Mock()
        mock_client = Mock()
        mock_config = Mock()

        mock_client.CoreV1Api.return_value = mock_v1_api
        mock_client.V1ConfigMap = Mock()
        mock_client.V1ObjectMeta = Mock()

        def mock_init(self, config):
            self.v1 = mock_v1_api
            self.k8s_client = mock_client
            self.k8s_config = mock_config
            self.ApiException = Exception
            self.namespace = config.get('namespace', 'default')
            self.configmap_name = config.get('configmap_name', 'app-config')
            self.key_prefix = config.get('key_prefix', '')
            self.read_only = config.get('read_only', False)

        with patch.object(KubernetesConfigMapManager, '__init__', mock_init):
            yield mock_v1_api, mock_client, mock_config

    def test_init_without_k8s_raises_error(self):
        """Test initialization without Kubernetes client raises error"""
        with patch.dict('sys.modules', {'kubernetes': None}):
            with pytest.raises(ParameterManagerError, match="kubernetes is required"):
                KubernetesConfigMapManager({})

    def test_init_default_config(self, mock_k8s_dependencies):
        """Test initialization with default configuration"""
        mock_v1_api, mock_client, mock_config = mock_k8s_dependencies

        config = {}
        manager = KubernetesConfigMapManager(config)

        assert manager.namespace == 'default'
        assert manager.configmap_name == 'app-config'
        assert manager.key_prefix == ''

    def test_init_with_config(self, mock_k8s_dependencies):
        """Test initialization with custom configuration"""
        mock_v1_api, mock_client, mock_config = mock_k8s_dependencies

        config = {
            'namespace': 'production',
            'configmap_name': 'myapp-config',
            'key_prefix': 'app.config'
        }
        manager = KubernetesConfigMapManager(config)

        assert manager.namespace == 'production'
        assert manager.configmap_name == 'myapp-config'
        assert manager.key_prefix == 'app.config'

    @pytest.mark.asyncio
    async def test_get_parameter_with_metadata_string(self, mock_k8s_dependencies):
        """Test getting string parameter"""
        mock_v1_api, mock_client, mock_config = mock_k8s_dependencies

        # Mock ConfigMap response
        mock_configmap = Mock()
        mock_configmap.data = {
            'database_host': 'localhost',
            'database_port': '5432'
        }
        mock_v1_api.read_namespaced_config_map.return_value = mock_configmap

        config = {}
        manager = KubernetesConfigMapManager(config)

        param = await manager.get_parameter_with_metadata('database_host')

        assert param.key == 'database_host'
        assert param.value == 'localhost'
        assert param.metadata['source'] == 'kubernetes_configmap'
        assert param.metadata['namespace'] == 'default'
        assert param.metadata['configmap_name'] == 'app-config'

        mock_v1_api.read_namespaced_config_map.assert_called_once_with(
            name='app-config',
            namespace='default'
        )

    @pytest.mark.asyncio
    async def test_get_parameter_json_value(self, mock_k8s_dependencies):
        """Test getting parameter with JSON value"""
        mock_v1_api, mock_client, mock_config = mock_k8s_dependencies

        mock_configmap = Mock()
        mock_configmap.data = {
            'db_config': '{"host": "localhost", "port": 5432}'
        }
        mock_v1_api.read_namespaced_config_map.return_value = mock_configmap

        config = {}
        manager = KubernetesConfigMapManager(config)

        param = await manager.get_parameter_with_metadata('db_config')

        assert param.value == {"host": "localhost", "port": 5432}

    @pytest.mark.asyncio
    async def test_get_parameter_with_prefix(self, mock_k8s_dependencies):
        """Test getting parameter with key prefix"""
        mock_v1_api, mock_client, mock_config = mock_k8s_dependencies

        mock_configmap = Mock()
        mock_configmap.data = {
            'app.config.database_host': 'localhost'
        }
        mock_v1_api.read_namespaced_config_map.return_value = mock_configmap

        config = {'key_prefix': 'app.config'}
        manager = KubernetesConfigMapManager(config)

        param = await manager.get_parameter_with_metadata('database_host')

        assert param.key == 'database_host'
        assert param.value == 'localhost'
        assert param.metadata['key'] == 'app.config.database_host'

    @pytest.mark.asyncio
    async def test_get_parameter_configmap_not_found(self, mock_k8s_dependencies):
        """Test parameter when ConfigMap doesn't exist"""
        mock_v1_api, mock_client, mock_config = mock_k8s_dependencies

        # Mock 404 exception
        mock_exception = Exception("Not found")
        mock_exception.status = 404
        mock_v1_api.read_namespaced_config_map.side_effect = mock_exception

        config = {}
        manager = KubernetesConfigMapManager(config)
        manager.ApiException = type(mock_exception)

        with pytest.raises(ParameterNotFoundError, match="ConfigMap 'app-config' not found"):
            await manager.get_parameter_with_metadata('database_host')

    @pytest.mark.asyncio
    async def test_get_parameter_not_found(self, mock_k8s_dependencies):
        """Test parameter not found in ConfigMap"""
        mock_v1_api, mock_client, mock_config = mock_k8s_dependencies

        mock_configmap = Mock()
        mock_configmap.data = {'other_key': 'other_value'}
        mock_v1_api.read_namespaced_config_map.return_value = mock_configmap

        config = {}
        manager = KubernetesConfigMapManager(config)

        with pytest.raises(ParameterNotFoundError, match="Parameter 'nonexistent' not found"):
            await manager.get_parameter_with_metadata('nonexistent')

    @pytest.mark.asyncio
    async def test_list_parameters(self, mock_k8s_dependencies):
        """Test listing parameters"""
        mock_v1_api, mock_client, mock_config = mock_k8s_dependencies

        mock_configmap = Mock()
        mock_configmap.data = {
            'database_host': 'localhost',
            'database_port': '5432',
            'api_url': 'https://api.example.com'
        }
        mock_v1_api.read_namespaced_config_map.return_value = mock_configmap

        config = {}
        manager = KubernetesConfigMapManager(config)

        keys = await manager.list_parameters()

        expected_keys = ['api_url', 'database_host', 'database_port']
        assert sorted(keys) == sorted(expected_keys)

    @pytest.mark.asyncio
    async def test_list_parameters_with_prefix_filter(self, mock_k8s_dependencies):
        """Test listing parameters with prefix filter"""
        mock_v1_api, mock_client, mock_config = mock_k8s_dependencies

        mock_configmap = Mock()
        mock_configmap.data = {
            'database_host': 'localhost',
            'database_port': '5432',
            'api_url': 'https://api.example.com'
        }
        mock_v1_api.read_namespaced_config_map.return_value = mock_configmap

        config = {}
        manager = KubernetesConfigMapManager(config)

        keys = await manager.list_parameters('database')

        expected_keys = ['database_host', 'database_port']
        assert sorted(keys) == sorted(expected_keys)

    @pytest.mark.asyncio
    async def test_list_parameters_empty_configmap(self, mock_k8s_dependencies):
        """Test listing parameters when ConfigMap doesn't exist"""
        mock_v1_api, mock_client, mock_config = mock_k8s_dependencies

        mock_exception = Exception("Not found")
        mock_exception.status = 404
        mock_v1_api.read_namespaced_config_map.side_effect = mock_exception

        config = {}
        manager = KubernetesConfigMapManager(config)
        manager.ApiException = type(mock_exception)

        keys = await manager.list_parameters()
        assert keys == []

    @pytest.mark.asyncio
    async def test_health_check_success(self, mock_k8s_dependencies):
        """Test successful health check"""
        mock_v1_api, mock_client, mock_config = mock_k8s_dependencies

        mock_v1_api.list_namespaced_config_map.return_value = Mock()

        config = {}
        manager = KubernetesConfigMapManager(config)

        result = await manager.health_check()

        assert result is True
        mock_v1_api.list_namespaced_config_map.assert_called_once_with(
            namespace='default',
            limit=1
        )

    @pytest.mark.asyncio
    async def test_health_check_failure(self, mock_k8s_dependencies):
        """Test health check failure"""
        mock_v1_api, mock_client, mock_config = mock_k8s_dependencies

        mock_v1_api.list_namespaced_config_map.side_effect = Exception("Access denied")

        config = {}
        manager = KubernetesConfigMapManager(config)

        result = await manager.health_check()

        assert result is False

    @pytest.mark.asyncio
    async def test_create_parameter_existing_configmap(self, mock_k8s_dependencies):
        """Test creating parameter in existing ConfigMap"""
        mock_v1_api, mock_client, mock_config = mock_k8s_dependencies

        # Mock existing ConfigMap
        mock_configmap = Mock()
        mock_configmap.data = {'existing_key': 'existing_value'}
        mock_v1_api.read_namespaced_config_map.return_value = mock_configmap

        # Mock ConfigMap update
        mock_v1_api.patch_namespaced_config_map.return_value = Mock()

        config = {}
        manager = KubernetesConfigMapManager(config)

        result = await manager.create_parameter('new_param', 'test_value')

        assert result is True
        mock_v1_api.patch_namespaced_config_map.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_parameter_json(self, mock_k8s_dependencies):
        """Test creating parameter with JSON value"""
        mock_v1_api, mock_client, mock_config = mock_k8s_dependencies

        # Mock ConfigMap doesn't exist - need to patch _get_configmap directly
        config = {}
        manager = KubernetesConfigMapManager(config)

        with patch.object(manager, '_get_configmap', return_value=None):
            with patch.object(manager, '_create_or_update_configmap') as mock_update:
                result = await manager.create_parameter('config', {'host': 'localhost', 'port': 5432})

        assert result is True
        mock_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_parameter_already_exists(self, mock_k8s_dependencies):
        """Test creating parameter that already exists"""
        mock_v1_api, mock_client, mock_config = mock_k8s_dependencies

        mock_configmap = Mock()
        mock_configmap.data = {'existing_param': 'existing_value'}
        mock_v1_api.read_namespaced_config_map.return_value = mock_configmap

        config = {}
        manager = KubernetesConfigMapManager(config)

        with pytest.raises(ParameterManagerError, match="already exists"):
            await manager.create_parameter('existing_param', 'new_value')

    @pytest.mark.asyncio
    async def test_update_parameter(self, mock_k8s_dependencies):
        """Test updating existing parameter"""
        mock_v1_api, mock_client, mock_config = mock_k8s_dependencies

        mock_configmap = Mock()
        mock_configmap.data = {'existing_param': 'old_value'}
        mock_v1_api.read_namespaced_config_map.return_value = mock_configmap

        mock_v1_api.patch_namespaced_config_map.return_value = Mock()

        config = {}
        manager = KubernetesConfigMapManager(config)

        result = await manager.update_parameter('existing_param', 'new_value')

        assert result is True
        mock_v1_api.patch_namespaced_config_map.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_parameter(self, mock_k8s_dependencies):
        """Test deleting parameter"""
        mock_v1_api, mock_client, mock_config = mock_k8s_dependencies

        mock_configmap = Mock()
        mock_configmap.data = {'param_to_delete': 'value', 'keep_param': 'keep_value'}
        mock_v1_api.read_namespaced_config_map.return_value = mock_configmap

        mock_v1_api.patch_namespaced_config_map.return_value = Mock()

        config = {}
        manager = KubernetesConfigMapManager(config)

        result = await manager.delete_parameter('param_to_delete')

        assert result is True
        mock_v1_api.patch_namespaced_config_map.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_parameter_not_found(self, mock_k8s_dependencies):
        """Test deleting non-existent parameter"""
        mock_v1_api, mock_client, mock_config = mock_k8s_dependencies

        mock_configmap = Mock()
        mock_configmap.data = {'other_param': 'other_value'}
        mock_v1_api.read_namespaced_config_map.return_value = mock_configmap

        config = {}
        manager = KubernetesConfigMapManager(config)

        with pytest.raises(ParameterNotFoundError):
            await manager.delete_parameter('nonexistent_param')

    @pytest.mark.asyncio
    async def test_read_only_mode(self, mock_k8s_dependencies):
        """Test read-only mode prevents writes"""
        mock_v1_api, mock_client, mock_config = mock_k8s_dependencies

        config = {'read_only': True}
        manager = KubernetesConfigMapManager(config)

        with pytest.raises(ParameterManagerError, match="read-only mode"):
            await manager.create_parameter('test', 'value')

        with pytest.raises(ParameterManagerError, match="read-only mode"):
            await manager.update_parameter('test', 'value')

        with pytest.raises(ParameterManagerError, match="read-only mode"):
            await manager.delete_parameter('test')

    def test_repr(self, mock_k8s_dependencies):
        """Test string representation"""
        mock_v1_api, mock_client, mock_config = mock_k8s_dependencies

        config = {'namespace': 'production', 'configmap_name': 'myapp-config'}
        manager = KubernetesConfigMapManager(config)

        assert 'KubernetesConfigMapManager' in repr(manager)