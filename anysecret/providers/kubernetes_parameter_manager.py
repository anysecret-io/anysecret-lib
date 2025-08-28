# File: anysecret/providers/kubernetes_parameter_manager.py

import asyncio
import json
import base64
from typing import Any, Dict, List, Optional
import logging

from ..parameter_manager import (
    BaseParameterManager,
    ParameterValue,
    ParameterNotFoundError,
    ParameterAccessError,
    ParameterManagerError
)

logger = logging.getLogger(__name__)


class KubernetesConfigMapManager(BaseParameterManager):
    """Parameter manager using Kubernetes ConfigMaps"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

        try:
            from kubernetes import client, config as k8s_config
            from kubernetes.client.rest import ApiException

            self.k8s_client = client
            self.k8s_config = k8s_config
            self.ApiException = ApiException
        except ImportError:
            raise ParameterManagerError(
                "kubernetes is required for Kubernetes ConfigMap manager. "
                "Install with: pip install kubernetes"
            )

        self.namespace = config.get('namespace', 'default')
        self.configmap_name = config.get('configmap_name', 'app-config')
        self.key_prefix = config.get('key_prefix', '')

        try:
            # Try to load in-cluster config first, fallback to kubeconfig
            try:
                self.k8s_config.load_incluster_config()
            except self.k8s_config.ConfigException:
                self.k8s_config.load_kube_config()

            self.v1 = self.k8s_client.CoreV1Api()
        except Exception as e:
            raise ParameterManagerError(f"Failed to initialize Kubernetes client: {e}")

    def _get_full_key(self, key: str) -> str:
        """Get the full parameter key with prefix"""
        if self.key_prefix:
            return f"{self.key_prefix.rstrip('.')}.{key.lstrip('.')}"
        return key

    def _strip_prefix(self, full_key: str) -> str:
        """Remove prefix from parameter key"""
        if self.key_prefix and full_key.startswith(self.key_prefix):
            stripped = full_key[len(self.key_prefix):].lstrip('.')
            return stripped
        return full_key

    async def _get_configmap(self) -> Optional[Dict[str, Any]]:
        """Get the ConfigMap data"""
        try:
            loop = asyncio.get_event_loop()
            configmap = await loop.run_in_executor(
                None,
                lambda: self.v1.read_namespaced_config_map(
                    name=self.configmap_name,
                    namespace=self.namespace
                )
            )
            return configmap.data or {}
        except self.ApiException as e:
            if e.status == 404:
                return None
            raise ParameterAccessError(f"Failed to get ConfigMap: {e}")
        except Exception as e:
            raise ParameterAccessError(f"Failed to get ConfigMap: {e}")

    async def _create_or_update_configmap(self, data: Dict[str, str]):
        """Create or update the ConfigMap with new data"""
        try:
            loop = asyncio.get_event_loop()

            # Create ConfigMap object
            configmap = self.k8s_client.V1ConfigMap(
                metadata=self.k8s_client.V1ObjectMeta(
                    name=self.configmap_name,
                    namespace=self.namespace,
                    labels={'managed-by': 'anysecret'}
                ),
                data=data
            )

            # Try to update first, create if it doesn't exist
            try:
                await loop.run_in_executor(
                    None,
                    lambda: self.v1.patch_namespaced_config_map(
                        name=self.configmap_name,
                        namespace=self.namespace,
                        body=configmap
                    )
                )
            except self.ApiException as e:
                if e.status == 404:
                    # ConfigMap doesn't exist, create it
                    await loop.run_in_executor(
                        None,
                        lambda: self.v1.create_namespaced_config_map(
                            namespace=self.namespace,
                            body=configmap
                        )
                    )
                else:
                    raise

        except Exception as e:
            raise ParameterAccessError(f"Failed to update ConfigMap: {e}")

    async def get_parameter_with_metadata(self, key: str) -> ParameterValue:
        """Get a parameter from Kubernetes ConfigMap"""
        full_key = self._get_full_key(key)

        configmap_data = await self._get_configmap()
        if configmap_data is None:
            raise ParameterNotFoundError(f"ConfigMap '{self.configmap_name}' not found")

        if full_key not in configmap_data:
            raise ParameterNotFoundError(f"Parameter '{key}' not found in ConfigMap")

        value_str = configmap_data[full_key]

        # Try to parse as JSON
        try:
            value = json.loads(value_str)
        except json.JSONDecodeError:
            value = value_str

        metadata = {
            'source': 'kubernetes_configmap',
            'namespace': self.namespace,
            'configmap_name': self.configmap_name,
            'key': full_key
        }

        return ParameterValue(key, value, metadata)

    async def list_parameters(self, prefix: Optional[str] = None) -> List[str]:
        """List parameters from Kubernetes ConfigMap"""
        configmap_data = await self._get_configmap()
        if configmap_data is None:
            return []

        keys = []
        for full_key in configmap_data.keys():
            key = self._strip_prefix(full_key)

            # Apply prefix filter if provided
            if prefix and not key.startswith(prefix):
                continue

            keys.append(key)

        return sorted(keys)

    async def health_check(self) -> bool:
        """Check if Kubernetes ConfigMap is accessible"""
        try:
            # Try to list ConfigMaps in the namespace
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.v1.list_namespaced_config_map(
                    namespace=self.namespace,
                    limit=1
                )
            )
            return True
        except Exception as e:
            logger.error(f"Kubernetes ConfigMap health check failed: {e}")
            return False

    async def create_parameter(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Create a parameter in Kubernetes ConfigMap"""
        self._check_write_allowed()

        full_key = self._get_full_key(key)

        # Get current ConfigMap data
        configmap_data = await self._get_configmap()
        if configmap_data is None:
            configmap_data = {}

        # Check if parameter already exists
        if full_key in configmap_data:
            raise ParameterManagerError(f"Parameter '{key}' already exists")

        # Serialize value
        if isinstance(value, (dict, list)):
            value_str = json.dumps(value)
        else:
            value_str = str(value)

        # Add new parameter
        configmap_data[full_key] = value_str

        # Update ConfigMap
        await self._create_or_update_configmap(configmap_data)

        return True

    async def update_parameter(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Update an existing parameter"""
        self._check_write_allowed()

        full_key = self._get_full_key(key)

        # Get current ConfigMap data
        configmap_data = await self._get_configmap()
        if configmap_data is None:
            configmap_data = {}

        # Serialize value
        if isinstance(value, (dict, list)):
            value_str = json.dumps(value)
        else:
            value_str = str(value)

        # Update parameter
        configmap_data[full_key] = value_str

        # Update ConfigMap
        await self._create_or_update_configmap(configmap_data)

        return True

    async def delete_parameter(self, key: str) -> bool:
        """Delete a parameter from Kubernetes ConfigMap"""
        self._check_write_allowed()

        full_key = self._get_full_key(key)

        # Get current ConfigMap data
        configmap_data = await self._get_configmap()
        if configmap_data is None or full_key not in configmap_data:
            raise ParameterNotFoundError(f"Parameter '{key}' not found")

        # Remove parameter
        del configmap_data[full_key]

        # Update ConfigMap
        await self._create_or_update_configmap(configmap_data)

        return True