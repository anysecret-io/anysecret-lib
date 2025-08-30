"""
Enhanced Configuration and Dependency Injection Setup
Supports both secrets and parameters with unified ConfigManager
"""
import os
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
import logging

from .secret_manager import (
    SecretManagerType,
    SecretManagerFactory,
    SecretManagerInterface
)
from .parameter_manager import (
    ParameterManagerType,
    ParameterManagerFactory,
    ParameterManagerInterface
)
from .config_manager import ConfigManager

logger = logging.getLogger(__name__)


@dataclass
class SecretManagerConfig:
    """Configuration for secret manager setup"""
    manager_type: SecretManagerType
    config: Dict[str, Any] = field(default_factory=dict)
    fallback_type: Optional[SecretManagerType] = None
    fallback_config: Dict[str, Any] = field(default_factory=dict)
    enable_caching: bool = True
    cache_ttl: int = 300


@dataclass
class ParameterManagerConfig:
    """Configuration for parameter manager setup"""
    manager_type: ParameterManagerType
    config: Dict[str, Any] = field(default_factory=dict)
    fallback_type: Optional[ParameterManagerType] = None
    fallback_config: Dict[str, Any] = field(default_factory=dict)
    enable_caching: bool = True
    cache_ttl: int = 300


@dataclass
class UnifiedConfig:
    """Unified configuration for both secrets and parameters"""
    secret_config: SecretManagerConfig
    parameter_config: ParameterManagerConfig
    custom_secret_patterns: list = field(default_factory=list)
    custom_parameter_patterns: list = field(default_factory=list)


class ConfigAutoDetect:
    """Auto-detection of optimal configuration based on environment"""

    @staticmethod
    def detect_cloud_provider() -> Optional[str]:
        """Detect which cloud provider we're running on"""
        # Check GCP
        try:
            import requests
            response = requests.get(
                'http://metadata.google.internal/computeMetadata/v1/project/project-id',
                headers={'Metadata-Flavor': 'Google'},
                timeout=2
            )
            if response.status_code == 200:
                logger.info("Detected Google Cloud Platform")
                return 'gcp'
        except:
            pass

        # Check AWS
        try:
            import requests
            response = requests.get(
                'http://169.254.169.254/latest/meta-data/instance-id',
                timeout=2
            )
            if response.status_code == 200:
                logger.info("Detected Amazon Web Services")
                return 'aws'
        except:
            pass

        # Check Azure
        try:
            import requests
            response = requests.get(
                'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                headers={'Metadata': 'true'},
                timeout=2
            )
            if response.status_code == 200:
                logger.info("Detected Microsoft Azure")
                return 'azure'
        except:
            pass

        return None

    @staticmethod
    def detect_kubernetes() -> bool:
        """Detect if running in Kubernetes"""
        return (
            os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount/token') or
            os.getenv('KUBERNETES_SERVICE_HOST') is not None
        )

    @staticmethod
    def get_recommended_config() -> UnifiedConfig:
        """Get recommended configuration based on environment"""

        # Check for explicit configuration
        secret_type = os.getenv('SECRET_MANAGER_TYPE', '').lower()
        param_type = os.getenv('PARAMETER_MANAGER_TYPE', '').lower()

        if secret_type or param_type:
            return ConfigBuilder.build_from_env(secret_type, param_type)

        # Auto-detect environment
        cloud_provider = ConfigAutoDetect.detect_cloud_provider()
        is_kubernetes = ConfigAutoDetect.detect_kubernetes()

        if cloud_provider and is_kubernetes:
            logger.info(f"Detected {cloud_provider} + Kubernetes environment")
            return ConfigBuilder.build_cloud_kubernetes(cloud_provider)
        elif cloud_provider:
            logger.info(f"Detected {cloud_provider} cloud environment")
            return ConfigBuilder.build_cloud_native(cloud_provider)
        elif is_kubernetes:
            logger.info("Detected Kubernetes environment")
            return ConfigBuilder.build_kubernetes_native()
        else:
            logger.info("Using local development configuration")
            return ConfigBuilder.build_local_development()


class ConfigBuilder:
    """Builder for unified configurations"""

    @staticmethod
    def build_from_env(secret_type: str = '', param_type: str = '') -> UnifiedConfig:
        """Build configuration from explicit environment variables"""

        # Map strings to enum types
        secret_mapping = {
            'aws': SecretManagerType.AWS,
            'gcp': SecretManagerType.GCP,
            'azure': SecretManagerType.AZURE,
            'vault': SecretManagerType.VAULT,
            'kubernetes': SecretManagerType.KUBERNETES,
            'encrypted_file': SecretManagerType.ENCRYPTED_FILE,
            'env_file': SecretManagerType.ENV_FILE
        }

        param_mapping = {
            'aws': ParameterManagerType.AWS_PARAMETER_STORE,
            'gcp': ParameterManagerType.GCP_CONFIG_CONNECTOR,
            'azure': ParameterManagerType.AZURE_APP_CONFIGURATION,
            'kubernetes': ParameterManagerType.KUBERNETES_CONFIGMAP,
            'file_json': ParameterManagerType.FILE_JSON,
            'file_yaml': ParameterManagerType.FILE_YAML
        }

        # Use defaults if not specified
        if not secret_type:
            cloud = ConfigAutoDetect.detect_cloud_provider()
            secret_type = cloud or 'env_file'

        if not param_type:
            cloud = ConfigAutoDetect.detect_cloud_provider()
            param_type = cloud or 'file_json'

        secret_manager_type = secret_mapping.get(secret_type, SecretManagerType.ENV_FILE)
        param_manager_type = param_mapping.get(param_type, ParameterManagerType.FILE_JSON)

        secret_config = ConfigBuilder._build_secret_config(secret_manager_type)
        param_config = ConfigBuilder._build_parameter_config(param_manager_type)

        return UnifiedConfig(secret_config, param_config)

    @staticmethod
    def build_cloud_native(cloud_provider: str) -> UnifiedConfig:
        """Build configuration for pure cloud deployment"""

        cloud_mapping = {
            'aws': {
                'secret': SecretManagerType.AWS,
                'param': ParameterManagerType.AWS_PARAMETER_STORE
            },
            'gcp': {
                'secret': SecretManagerType.GCP,
                'param': ParameterManagerType.GCP_CONFIG_CONNECTOR
            },
            'azure': {
                'secret': SecretManagerType.AZURE,
                'param': ParameterManagerType.AZURE_APP_CONFIGURATION
            }
        }

        mapping = cloud_mapping.get(cloud_provider, {
            'secret': SecretManagerType.ENV_FILE,
            'param': ParameterManagerType.FILE_JSON
        })

        secret_config = ConfigBuilder._build_secret_config(mapping['secret'])
        param_config = ConfigBuilder._build_parameter_config(mapping['param'])

        # Add file-based fallbacks
        secret_config.fallback_type = SecretManagerType.ENV_FILE
        secret_config.fallback_config = {'file_path': '.env'}
        param_config.fallback_type = ParameterManagerType.FILE_JSON
        param_config.fallback_config = {'file_path': 'parameters.json'}

        return UnifiedConfig(secret_config, param_config)

    @staticmethod
    def build_cloud_kubernetes(cloud_provider: str) -> UnifiedConfig:
        """Build configuration for cloud + Kubernetes hybrid"""

        # Use cloud for secrets (more secure/managed)
        cloud_config = ConfigBuilder.build_cloud_native(cloud_provider)

        # Use Kubernetes for parameters (faster access)
        cloud_config.parameter_config = ParameterManagerConfig(
            manager_type=ParameterManagerType.KUBERNETES_CONFIGMAP,
            config={
                'namespace': os.getenv('K8S_NAMESPACE', 'default'),
                'configmap_name': os.getenv('K8S_CONFIGMAP_NAME', 'app-config')
            },
            fallback_type=ParameterManagerType.FILE_JSON,
            fallback_config={'file_path': 'parameters.json'}
        )

        return cloud_config

    @staticmethod
    def build_kubernetes_native() -> UnifiedConfig:
        """Build configuration for Kubernetes-only deployment"""

        secret_config = SecretManagerConfig(
            manager_type=SecretManagerType.KUBERNETES,
            config={
                'namespace': os.getenv('K8S_NAMESPACE', 'default'),
                'secret_name': os.getenv('K8S_SECRET_NAME', 'app-secrets')
            },
            fallback_type=SecretManagerType.ENV_FILE,
            fallback_config={'file_path': '.env'}
        )

        param_config = ParameterManagerConfig(
            manager_type=ParameterManagerType.KUBERNETES_CONFIGMAP,
            config={
                'namespace': os.getenv('K8S_NAMESPACE', 'default'),
                'configmap_name': os.getenv('K8S_CONFIGMAP_NAME', 'app-config')
            },
            fallback_type=ParameterManagerType.FILE_JSON,
            fallback_config={'file_path': 'parameters.json'}
        )

        return UnifiedConfig(secret_config, param_config)

    @staticmethod
    def build_local_development() -> UnifiedConfig:
        """Build configuration for local development"""

        # Auto-detect local files
        if os.path.exists('secrets.json.enc'):
            secret_config = SecretManagerConfig(
                manager_type=SecretManagerType.ENCRYPTED_FILE,
                config={
                    'file_path': 'secrets.json.enc',
                    'password': os.getenv('SECRETS_PASSWORD'),
                    'encryption_key': os.getenv('SECRETS_ENCRYPTION_KEY'),
                    'salt': os.getenv('SECRETS_SALT', 'anysecret_salt_2024')
                }
            )
        else:
            secret_config = SecretManagerConfig(
                manager_type=SecretManagerType.ENV_FILE,
                config={'file_path': os.getenv('ENV_FILE', '.env')}
            )

        # Auto-detect parameter files
        if os.path.exists('config.yaml'):
            param_config = ParameterManagerConfig(
                manager_type=ParameterManagerType.FILE_YAML,
                config={'file_path': 'config.yaml'}
            )
        else:
            param_config = ParameterManagerConfig(
                manager_type=ParameterManagerType.FILE_JSON,
                config={'file_path': os.getenv('PARAMETERS_FILE', 'parameters.json')}
            )

        return UnifiedConfig(secret_config, param_config)

    @staticmethod
    def _build_secret_config(manager_type: SecretManagerType) -> SecretManagerConfig:
        """Build secret manager configuration"""

        if manager_type == SecretManagerType.AWS:
            config = {
                'region_name': os.getenv('AWS_DEFAULT_REGION', 'us-east-1'),
                'aws_access_key_id': os.getenv('AWS_ACCESS_KEY_ID'),
                'aws_secret_access_key': os.getenv('AWS_SECRET_ACCESS_KEY'),
                'cache_ttl': int(os.getenv('SECRET_CACHE_TTL', '300'))
            }
        elif manager_type == SecretManagerType.GCP:
            config = {
                'project_id': os.getenv('GCP_PROJECT_ID'),
                'credentials_path': os.getenv('GOOGLE_APPLICATION_CREDENTIALS'),
                'cache_ttl': int(os.getenv('SECRET_CACHE_TTL', '300'))
            }
        elif manager_type == SecretManagerType.AZURE:
            config = {
                'vault_url': os.getenv('AZURE_KEY_VAULT_URL'),
                'client_id': os.getenv('AZURE_CLIENT_ID'),
                'client_secret': os.getenv('AZURE_CLIENT_SECRET'),
                'tenant_id': os.getenv('AZURE_TENANT_ID'),
                'cache_ttl': int(os.getenv('SECRET_CACHE_TTL', '300'))
            }
        elif manager_type == SecretManagerType.VAULT:
            config = {
                'url': os.getenv('VAULT_ADDR', 'http://localhost:8200'),
                'token': os.getenv('VAULT_TOKEN'),
                'mount_point': os.getenv('VAULT_MOUNT_POINT', 'secret'),
                'cache_ttl': int(os.getenv('SECRET_CACHE_TTL', '300'))
            }
        elif manager_type == SecretManagerType.KUBERNETES:
            config = {
                'namespace': os.getenv('K8S_NAMESPACE', 'default'),
                'secret_name': os.getenv('K8S_SECRET_NAME', 'app-secrets')
            }
        elif manager_type == SecretManagerType.ENCRYPTED_FILE:
            config = {
                'file_path': os.getenv('ENCRYPTED_SECRETS_FILE', 'secrets.json.enc'),
                'password': os.getenv('SECRETS_PASSWORD'),
                'encryption_key': os.getenv('SECRETS_ENCRYPTION_KEY'),
                'salt': os.getenv('SECRETS_SALT', 'anysecret_salt_2024')
            }
        else:  # ENV_FILE
            config = {'file_path': os.getenv('ENV_FILE', '.env')}

        return SecretManagerConfig(manager_type=manager_type, config=config)

    @staticmethod
    def _build_parameter_config(manager_type: ParameterManagerType) -> ParameterManagerConfig:
        """Build parameter manager configuration"""

        if manager_type == ParameterManagerType.AWS_PARAMETER_STORE:
            config = {
                'region': os.getenv('AWS_DEFAULT_REGION', 'us-east-1'),
                'aws_access_key_id': os.getenv('AWS_ACCESS_KEY_ID'),
                'aws_secret_access_key': os.getenv('AWS_SECRET_ACCESS_KEY'),
                'prefix': os.getenv('AWS_PARAMETER_PREFIX', '/app/')
            }
        elif manager_type == ParameterManagerType.GCP_CONFIG_CONNECTOR:
            config = {
                'project_id': os.getenv('GCP_PROJECT_ID'),
                'prefix': os.getenv('GCP_PARAMETER_PREFIX', 'config')
            }
        elif manager_type == ParameterManagerType.AZURE_APP_CONFIGURATION:
            config = {
                'connection_string': os.getenv('AZURE_APP_CONFIG_CONNECTION_STRING'),
                'endpoint': os.getenv('AZURE_APP_CONFIG_ENDPOINT'),
                'label': os.getenv('AZURE_APP_CONFIG_LABEL', 'Production')
            }
        elif manager_type == ParameterManagerType.KUBERNETES_CONFIGMAP:
            config = {
                'namespace': os.getenv('K8S_NAMESPACE', 'default'),
                'configmap_name': os.getenv('K8S_CONFIGMAP_NAME', 'app-config')
            }
        elif manager_type == ParameterManagerType.FILE_YAML:
            config = {'file_path': os.getenv('PARAMETERS_YAML', 'config.yaml')}
        else:  # FILE_JSON
            config = {'file_path': os.getenv('PARAMETERS_JSON', 'parameters.json')}

        return ParameterManagerConfig(manager_type=manager_type, config=config)


class UnifiedConfigProvider:
    """Dependency injection provider for unified configuration management"""

    def __init__(self, config: Optional[UnifiedConfig] = None):
        self.config = config or ConfigAutoDetect.get_recommended_config()
        self._config_manager: Optional[ConfigManager] = None
        self._secret_manager: Optional[SecretManagerInterface] = None
        self._parameter_manager: Optional[ParameterManagerInterface] = None
        self._initialized = False

    async def get_config_manager(self) -> ConfigManager:
        """Get the unified configuration manager instance"""
        if not self._initialized:
            await self._initialize()
        return self._config_manager

    async def get_secret_manager(self) -> SecretManagerInterface:
        """Get the secret manager instance"""
        if not self._initialized:
            await self._initialize()
        return self._secret_manager

    async def get_parameter_manager(self) -> ParameterManagerInterface:
        """Get the parameter manager instance"""
        if not self._initialized:
            await self._initialize()
        return self._parameter_manager

    async def _initialize(self):
        """Initialize all managers with fallback support"""

        # Initialize secret manager
        secret_factory = SecretManagerFactory()
        try:
            logger.info(f"Initializing secret manager: {self.config.secret_config.manager_type}")
            self._secret_manager = secret_factory.create(
                self.config.secret_config.manager_type,
                self.config.secret_config.config
            )

            if not await self._secret_manager.health_check():
                raise Exception("Secret manager health check failed")

        except Exception as e:
            logger.warning(f"Primary secret manager failed: {e}")
            if self.config.secret_config.fallback_type:
                logger.info(f"Trying fallback secret manager: {self.config.secret_config.fallback_type}")
                self._secret_manager = secret_factory.create(
                    self.config.secret_config.fallback_type,
                    self.config.secret_config.fallback_config
                )
                if not await self._secret_manager.health_check():
                    raise Exception("Fallback secret manager failed")
            else:
                raise

        # Initialize parameter manager
        parameter_factory = ParameterManagerFactory()
        try:
            logger.info(f"Initializing parameter manager: {self.config.parameter_config.manager_type}")
            self._parameter_manager = parameter_factory.create_manager(
                self.config.parameter_config.manager_type,
                self.config.parameter_config.config
            )

            if not await self._parameter_manager.health_check():
                raise Exception("Parameter manager health check failed")

        except Exception as e:
            logger.warning(f"Primary parameter manager failed: {e}")
            if self.config.parameter_config.fallback_type:
                logger.info(f"Trying fallback parameter manager: {self.config.parameter_config.fallback_type}")
                self._parameter_manager = parameter_factory.create_manager(
                    self.config.parameter_config.fallback_type,
                    self.config.parameter_config.fallback_config
                )
                if not await self._parameter_manager.health_check():
                    raise Exception("Fallback parameter manager failed")
            else:
                raise

        # Create unified config manager
        secret_config = self.config.secret_config.config.copy()
        secret_config['type'] = self.config.secret_config.manager_type.value
        
        parameter_config = self.config.parameter_config.config.copy()
        parameter_config['type'] = self.config.parameter_config.manager_type.value
        
        self._config_manager = ConfigManager(
            secret_config,
            parameter_config
        )

        # Apply custom patterns
        if self.config.custom_secret_patterns:
            self._config_manager.custom_secret_patterns = self.config.custom_secret_patterns
            self._config_manager._compile_patterns()

        self._initialized = True
        logger.info("Unified configuration system initialized successfully")


# Global provider instance
_unified_provider: Optional[UnifiedConfigProvider] = None


def get_unified_provider() -> UnifiedConfigProvider:
    """Get global unified configuration provider"""
    global _unified_provider
    if _unified_provider is None:
        _unified_provider = UnifiedConfigProvider()
    return _unified_provider


def set_unified_config(config: UnifiedConfig):
    """Set global unified configuration"""
    global _unified_provider
    _unified_provider = UnifiedConfigProvider(config)


async def get_config_manager() -> ConfigManager:
    """Get configured unified configuration manager"""
    # Ensure configuration is loaded from CLI config or environment
    from .config_loader import ensure_initialized
    ensure_initialized()
    
    provider = get_unified_provider()
    return await provider.get_config_manager()


async def get_secret_manager() -> SecretManagerInterface:
    """Get configured secret manager"""
    provider = get_unified_provider()
    return await provider.get_secret_manager()


async def get_parameter_manager() -> ParameterManagerInterface:
    """Get configured parameter manager"""
    provider = get_unified_provider()
    return await provider.get_parameter_manager()


# Convenience functions
def load_config() -> Dict[str, Any]:
    """Load configuration in legacy format for backward compatibility"""
    provider = get_unified_provider()
    return {
        'type': provider.config.secret_config.manager_type.value,
        **provider.config.secret_config.config,
        'parameters': {
            'type': provider.config.parameter_config.manager_type.value,
            **provider.config.parameter_config.config
        }
    }


# Environment configuration helpers
def configure_for_aws():
    """Configure for AWS deployment"""
    config = ConfigBuilder.build_cloud_native('aws')
    set_unified_config(config)


def configure_for_gcp():
    """Configure for GCP deployment"""
    config = ConfigBuilder.build_cloud_native('gcp')
    set_unified_config(config)


def configure_for_azure():
    """Configure for Azure deployment"""
    config = ConfigBuilder.build_cloud_native('azure')
    set_unified_config(config)


def configure_for_kubernetes():
    """Configure for Kubernetes deployment"""
    config = ConfigBuilder.build_kubernetes_native()
    set_unified_config(config)