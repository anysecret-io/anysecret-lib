# File: anysecret/parameter_manager.py

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union
from enum import Enum
import json
import logging
import asyncio

logger = logging.getLogger(__name__)


class ParameterValue:
    """Represents a parameter with its metadata"""

    def __init__(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None):
        self.key = key
        self.value = value
        self.metadata = metadata or {}

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return f"ParameterValue(key='{self.key}', value='{self.value}', metadata={self.metadata})"


class ParameterManagerType(Enum):
    """Available parameter manager types"""
    FILE_JSON = "file_json"
    FILE_YAML = "file_yaml"
    AWS_PARAMETER_STORE = "aws_parameter_store"
    GCP_CONFIG_CONNECTOR = "gcp_config_connector"
    AZURE_APP_CONFIGURATION = "azure_app_configuration"
    KUBERNETES_CONFIGMAP = "kubernetes_configmap"


class ParameterManagerError(Exception):
    """Base exception for parameter manager errors"""
    pass


class ParameterNotFoundError(ParameterManagerError):
    """Raised when a parameter is not found"""
    pass


class ParameterAccessError(ParameterManagerError):
    """Raised when there's an access error"""
    pass


class ParameterManagerInterface(ABC):
    """Abstract interface for parameter managers"""

    @abstractmethod
    async def get_parameter(self, key: str) -> Any:
        """
        Get a single parameter value by key

        Args:
            key: Parameter key/name

        Returns:
            Parameter value (can be string, number, boolean, dict, list, etc.)

        Raises:
            ParameterNotFoundError: If parameter doesn't exist
            ParameterAccessError: For access/permission errors
            ParameterManagerError: For other errors
        """
        pass

    @abstractmethod
    async def get_parameter_with_metadata(self, key: str) -> ParameterValue:
        """
        Get a parameter with its metadata

        Args:
            key: Parameter key/name

        Returns:
            ParameterValue object with metadata
        """
        pass

    @abstractmethod
    async def get_parameters_by_prefix(self, prefix: str) -> Dict[str, Any]:
        """
        Get all parameters with a given prefix

        Args:
            prefix: Key prefix to search for

        Returns:
            Dictionary of key-value pairs
        """
        pass

    @abstractmethod
    async def list_parameters(self, prefix: Optional[str] = None) -> List[str]:
        """
        List all available parameter keys

        Args:
            prefix: Optional prefix to filter by

        Returns:
            List of parameter keys
        """
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check if the parameter manager is accessible

        Returns:
            True if healthy, False otherwise
        """
        pass

    async def get_parameters_batch(self, keys: List[str]) -> Dict[str, Any]:
        """
        Get multiple parameters in a batch (default implementation)

        Args:
            keys: List of parameter keys

        Returns:
            Dictionary of key-value pairs
        """
        results = {}
        tasks = []

        for key in keys:
            tasks.append(self._get_parameter_safe(key))

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for key, response in zip(keys, responses):
            if isinstance(response, Exception):
                logger.warning(f"Failed to get parameter '{key}': {response}")
            else:
                results[key] = response

        return results

    async def _get_parameter_safe(self, key: str) -> Optional[Any]:
        """Safe parameter retrieval that doesn't raise exceptions"""
        try:
            return await self.get_parameter(key)
        except Exception as e:
            logger.error(f"Error retrieving parameter '{key}': {e}")
            return None

    # Write operations (optional - providers can raise NotImplementedError)
    async def create_parameter(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Create a new parameter"""
        raise NotImplementedError("Create operation not supported by this provider")

    async def update_parameter(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Update an existing parameter"""
        raise NotImplementedError("Update operation not supported by this provider")

    async def delete_parameter(self, key: str) -> bool:
        """Delete a parameter"""
        raise NotImplementedError("Delete operation not supported by this provider")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}()"


class BaseParameterManager(ParameterManagerInterface):
    """Base class with common functionality"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.read_only = config.get('read_only', False)

    def _check_write_allowed(self):
        """Check if write operations are allowed"""
        if self.read_only:
            raise ParameterManagerError("Write operations disabled in read-only mode")

    async def get_parameter(self, key: str) -> Any:
        """Get a parameter value (convenience method)"""
        param_value = await self.get_parameter_with_metadata(key)
        return param_value.value

    async def get_parameters_by_prefix(self, prefix: str) -> Dict[str, Any]:
        """Get all parameters with a given prefix"""
        keys = await self.list_parameters(prefix)
        result = {}
        for key in keys:
            try:
                result[key] = await self.get_parameter(key)
            except Exception as e:
                logger.warning(f"Failed to get parameter {key}: {e}")
        return result

    # Write operations with read-only check
    async def create_parameter(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Create a new parameter"""
        self._check_write_allowed()
        raise NotImplementedError("Create operation not supported by this provider")

    async def update_parameter(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Update an existing parameter"""
        self._check_write_allowed()
        raise NotImplementedError("Update operation not supported by this provider")

    async def delete_parameter(self, key: str) -> bool:
        """Delete a parameter"""
        self._check_write_allowed()
        raise NotImplementedError("Delete operation not supported by this provider")


class ParameterManagerFactory:
    """Factory for creating parameter managers"""

    def __init__(self):
        self._managers = {
            ParameterManagerType.FILE_JSON: self._create_file_json_manager,
            ParameterManagerType.FILE_YAML: self._create_file_yaml_manager,
            ParameterManagerType.AWS_PARAMETER_STORE: self._create_aws_parameter_store,
            ParameterManagerType.GCP_CONFIG_CONNECTOR: self._create_gcp_config_connector,
            ParameterManagerType.AZURE_APP_CONFIGURATION: self._create_azure_app_configuration,
            ParameterManagerType.KUBERNETES_CONFIGMAP: self._create_kubernetes_configmap,
        }

    def create_manager(self, manager_type: Union[str, ParameterManagerType],
                       config: Dict[str, Any]) -> BaseParameterManager:
        """Create a parameter manager of the specified type"""
        if isinstance(manager_type, str):
            try:
                manager_type = ParameterManagerType(manager_type)
            except ValueError:
                raise ParameterManagerError(f"Unknown parameter manager type: {manager_type}")

        creator = self._managers.get(manager_type)
        if not creator:
            raise ParameterManagerError(f"Parameter manager type {manager_type} not supported")

        return creator(config)

    def detect_available_managers(self) -> List[ParameterManagerType]:
        """Detect which parameter managers are available based on dependencies"""
        available = []

        # File managers are always available
        available.extend([
            ParameterManagerType.FILE_JSON,
            ParameterManagerType.FILE_YAML
        ])

        # Check for cloud provider dependencies
        try:
            import boto3
            available.append(ParameterManagerType.AWS_PARAMETER_STORE)
        except ImportError:
            pass

        try:
            from google.cloud import secretmanager
            available.append(ParameterManagerType.GCP_CONFIG_CONNECTOR)
        except ImportError:
            pass

        try:
            from azure.identity import DefaultAzureCredential
            from azure.appconfiguration import AzureAppConfigurationClient
            available.append(ParameterManagerType.AZURE_APP_CONFIGURATION)
        except ImportError:
            pass

        try:
            from kubernetes import client, config as k8s_config
            available.append(ParameterManagerType.KUBERNETES_CONFIGMAP)
        except ImportError:
            pass

        return available

    def _create_file_json_manager(self, config: Dict[str, Any]) -> BaseParameterManager:
        from .providers.file_parameter_manager import FileJsonParameterManager
        return FileJsonParameterManager(config)

    def _create_file_yaml_manager(self, config: Dict[str, Any]) -> BaseParameterManager:
        from .providers.file_parameter_manager import FileYamlParameterManager
        return FileYamlParameterManager(config)

    def _create_aws_parameter_store(self, config: Dict[str, Any]) -> BaseParameterManager:
        from .providers.aws_parameter_manager import AwsParameterStoreManager
        return AwsParameterStoreManager(config)

    def _create_gcp_config_connector(self, config: Dict[str, Any]) -> BaseParameterManager:
        from .providers.gcp_parameter_manager import GcpConfigConnectorManager
        return GcpConfigConnectorManager(config)

    def _create_azure_app_configuration(self, config: Dict[str, Any]) -> BaseParameterManager:
        from .providers.azure_parameter_manager import AzureAppConfigurationManager
        return AzureAppConfigurationManager(config)

    def _create_kubernetes_configmap(self, config: Dict[str, Any]) -> BaseParameterManager:
        from .providers.kubernetes_parameter_manager import KubernetesConfigMapManager
        return KubernetesConfigMapManager(config)


# Global factory instance
parameter_manager_factory = ParameterManagerFactory()