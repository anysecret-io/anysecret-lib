"""
Kubernetes Secrets implementation
"""
import asyncio
import base64
import os
from typing import Dict, List, Optional, Any
import logging

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException

    HAS_KUBERNETES = True
except ImportError:
    HAS_KUBERNETES = False

from ..secret_manager import (
    BaseSecretManager,
    SecretValue,
    SecretNotFoundException,
    SecretManagerException,
    SecretManagerConnectionException
)

logger = logging.getLogger(__name__)


class KubernetesSecretManager(BaseSecretManager):
    """Kubernetes Secrets implementation"""

    def __init__(self, config_dict: Dict[str, Any]):
        if not HAS_KUBERNETES:
            raise SecretManagerException(
                "Kubernetes provider requires 'kubernetes' package. "
                "Install with: pip install kubernetes"
            )

        super().__init__(config_dict)

        self.namespace = config_dict.get('namespace', 'default')
        self.kubeconfig_path = config_dict.get('kubeconfig_path')
        self.in_cluster = config_dict.get('in_cluster', False)
        self.context = config_dict.get('context')

        # Label selectors for filtering secrets
        self.label_selector = config_dict.get('label_selector')

        # Secret name prefix for scoping
        self.secret_prefix = config_dict.get('secret_prefix', '')

        # Initialize Kubernetes client
        self._client = None
        self._initialize_client()

    def _initialize_client(self):
        """Initialize the Kubernetes client"""
        try:
            if self.in_cluster:
                # Load in-cluster configuration (when running inside a pod)
                config.load_incluster_config()
                logger.info("Using in-cluster Kubernetes configuration")
            elif self.kubeconfig_path:
                # Load configuration from specific kubeconfig file
                config.load_kube_config(config_file=self.kubeconfig_path, context=self.context)
                logger.info(f"Using kubeconfig from {self.kubeconfig_path}")
            else:
                # Load configuration from default location (~/.kube/config)
                config.load_kube_config(context=self.context)
                logger.info("Using default kubeconfig")

            self._client = client.CoreV1Api()

            logger.info(f"Kubernetes client initialized for namespace: {self.namespace}")

        except Exception as e:
            raise SecretManagerConnectionException(f"Failed to initialize Kubernetes client: {e}")

    def _build_secret_name(self, key: str) -> str:
        """Build full secret name with prefix"""
        if self.secret_prefix:
            return f"{self.secret_prefix}-{key}"
        return key

    def _extract_secret_name(self, full_name: str) -> str:
        """Extract logical secret name by removing prefix"""
        if self.secret_prefix and full_name.startswith(f"{self.secret_prefix}-"):
            return full_name[len(f"{self.secret_prefix}-"):]
        return full_name

    async def get_secret_with_metadata(self, key: str) -> SecretValue:
        """Get secret with metadata from Kubernetes"""
        try:
            loop = asyncio.get_event_loop()
            secret_name = self._build_secret_name(key)

            # Get secret from Kubernetes
            secret = await loop.run_in_executor(
                None,
                self._client.read_namespaced_secret,
                secret_name,
                self.namespace
            )

            if not secret.data:
                raise SecretNotFoundException(f"Secret '{key}' has no data")

            # Kubernetes secrets can have multiple data keys
            # For single key, return its value
            # For multiple keys, return JSON representation
            secret_data = {}
            for data_key, encoded_value in secret.data.items():
                decoded_value = base64.b64decode(encoded_value).decode('utf-8')
                secret_data[data_key] = decoded_value

            if len(secret_data) == 1:
                # Single key - return just the value
                secret_value = list(secret_data.values())[0]
            else:
                # Multiple keys - return JSON
                import json
                secret_value = json.dumps(secret_data)

            # Extract metadata
            metadata = {
                'source': 'kubernetes_secrets',
                'namespace': self.namespace,
                'secret_name': secret_name,
                'type': secret.type or 'Opaque',
                'labels': dict(secret.metadata.labels) if secret.metadata.labels else {},
                'annotations': dict(secret.metadata.annotations) if secret.metadata.annotations else {},
                'is_multi_key': len(secret_data) > 1,
                'data_keys': list(secret_data.keys()),
                'uid': secret.metadata.uid
            }

            return SecretValue(
                value=secret_value,
                key=key,
                version=secret.metadata.resource_version,
                created_at=secret.metadata.creation_timestamp.isoformat() if secret.metadata.creation_timestamp else None,
                metadata=metadata
            )

        except ApiException as e:
            if e.status == 404:
                raise SecretNotFoundException(f"Secret '{key}' not found in namespace '{self.namespace}'")
            elif e.status == 403:
                raise SecretManagerException(f"Access denied to secret '{key}': {e.reason}")
            else:
                raise SecretManagerException(f"Kubernetes API error retrieving secret '{key}': {e.reason}")
        except Exception as e:
            raise SecretManagerException(f"Failed to retrieve secret '{key}' from Kubernetes: {e}")

    async def get_secrets_by_prefix(self, prefix: str) -> Dict[str, str]:
        """Get all secrets with given prefix"""
        try:
            # List all secrets first
            all_secrets = await self.list_secrets()

            # Filter by prefix
            matching_keys = [key for key in all_secrets if key.startswith(prefix)]

            # Get values in batch
            return await self.get_secrets_batch(matching_keys)

        except Exception as e:
            raise SecretManagerException(f"Failed to get secrets by prefix '{prefix}': {e}")

    async def list_secrets(self, prefix: Optional[str] = None) -> List[str]:
        """List all secret names"""
        try:
            loop = asyncio.get_event_loop()

            # Build field selector and label selector
            field_selector = None
            label_selector = self.label_selector

            # List secrets in namespace
            secret_list = await loop.run_in_executor(
                None,
                self._client.list_namespaced_secret,
                self.namespace,
                field_selector=field_selector,
                label_selector=label_selector
            )

            secret_names = []
            for secret in secret_list.items:
                logical_name = self._extract_secret_name(secret.metadata.name)

                if prefix is None or logical_name.startswith(prefix):
                    secret_names.append(logical_name)

            return sorted(secret_names)

        except ApiException as e:
            if e.status == 403:
                raise SecretManagerException(f"Access denied listing secrets: {e.reason}")
            else:
                raise SecretManagerException(f"Kubernetes API error listing secrets: {e.reason}")
        except Exception as e:
            raise SecretManagerException(f"Failed to list secrets: {e}")

    async def health_check(self) -> bool:
        """Check if Kubernetes API is accessible"""
        try:
            loop = asyncio.get_event_loop()

            # Try to list secrets with limit to minimize response
            await loop.run_in_executor(
                None,
                self._client.list_namespaced_secret,
                self.namespace,
                limit=1
            )

            return True

        except Exception as e:
            logger.error(f"Kubernetes health check failed: {e}")
            return False

    async def create_secret(self, key: str, value: Any, secret_type: str = "Opaque",
                            labels: Optional[Dict[str, str]] = None,
                            annotations: Optional[Dict[str, str]] = None) -> bool:
        """
        Create a new secret in Kubernetes

        Args:
            key: Logical secret name
            value: Secret value (can be string or dict for multi-key secrets)
            secret_type: Kubernetes secret type (Opaque, kubernetes.io/tls, etc.)
            labels: Labels to apply to the secret
            annotations: Annotations to apply to the secret

        Returns:
            True if successful
        """
        self._check_write_allowed()
        try:
            loop = asyncio.get_event_loop()
            secret_name = self._build_secret_name(key)

            # Prepare secret data
            if isinstance(value, dict):
                # Multi-key secret
                secret_data = {}
                for data_key, data_value in value.items():
                    encoded_value = base64.b64encode(str(data_value).encode('utf-8')).decode('utf-8')
                    secret_data[data_key] = encoded_value
            else:
                # Single-key secret (use 'value' as the key name)
                encoded_value = base64.b64encode(str(value).encode('utf-8')).decode('utf-8')
                secret_data = {'value': encoded_value}

            # Create secret object
            secret = client.V1Secret(
                api_version="v1",
                kind="Secret",
                metadata=client.V1ObjectMeta(
                    name=secret_name,
                    namespace=self.namespace,
                    labels=labels or {},
                    annotations=annotations or {}
                ),
                type=secret_type,
                data=secret_data
            )

            # Create secret in Kubernetes
            await loop.run_in_executor(
                None,
                self._client.create_namespaced_secret,
                self.namespace,
                secret
            )

            logger.info(f"Created secret '{key}' in Kubernetes namespace '{self.namespace}'")
            return True

        except ApiException as e:
            if e.status == 409:
                raise SecretManagerException(f"Secret '{key}' already exists")
            elif e.status == 403:
                raise SecretManagerException(f"Access denied creating secret '{key}': {e.reason}")
            else:
                raise SecretManagerException(f"Kubernetes API error creating secret '{key}': {e.reason}")
        except Exception as e:
            raise SecretManagerException(f"Failed to create secret '{key}': {e}")

    async def update_secret(self, key: str, value: Any) -> bool:
        """
        Update an existing secret with new value

        Args:
            key: Logical secret name
            value: New secret value

        Returns:
            True if successful
        """
        self._check_write_allowed()
        try:
            loop = asyncio.get_event_loop()
            secret_name = self._build_secret_name(key)

            # Get existing secret to preserve metadata
            existing_secret = await loop.run_in_executor(
                None,
                self._client.read_namespaced_secret,
                secret_name,
                self.namespace
            )

            # Prepare new secret data
            if isinstance(value, dict):
                secret_data = {}
                for data_key, data_value in value.items():
                    encoded_value = base64.b64encode(str(data_value).encode('utf-8')).decode('utf-8')
                    secret_data[data_key] = encoded_value
            else:
                encoded_value = base64.b64encode(str(value).encode('utf-8')).decode('utf-8')
                secret_data = {'value': encoded_value}

            # Update secret data
            existing_secret.data = secret_data

            # Update secret in Kubernetes
            await loop.run_in_executor(
                None,
                self._client.replace_namespaced_secret,
                secret_name,
                self.namespace,
                existing_secret
            )

            # Clear cache
            if key in self._cache:
                del self._cache[key]

            logger.info(f"Updated secret '{key}' in Kubernetes namespace '{self.namespace}'")
            return True

        except ApiException as e:
            if e.status == 404:
                raise SecretNotFoundException(f"Secret '{key}' not found for update")
            elif e.status == 403:
                raise SecretManagerException(f"Access denied updating secret '{key}': {e.reason}")
            else:
                raise SecretManagerException(f"Kubernetes API error updating secret '{key}': {e.reason}")
        except Exception as e:
            raise SecretManagerException(f"Failed to update secret '{key}': {e}")

    async def delete_secret(self, key: str) -> bool:
        """
        Delete a secret from Kubernetes

        Args:
            key: Logical secret name

        Returns:
            True if successful
        """
        self._check_write_allowed()
        try:
            loop = asyncio.get_event_loop()
            secret_name = self._build_secret_name(key)

            # Delete secret from Kubernetes
            await loop.run_in_executor(
                None,
                self._client.delete_namespaced_secret,
                secret_name,
                self.namespace
            )

            # Clear cache
            if key in self._cache:
                del self._cache[key]

            logger.info(f"Deleted secret '{key}' from Kubernetes namespace '{self.namespace}'")
            return True

        except ApiException as e:
            if e.status == 404:
                raise SecretNotFoundException(f"Secret '{key}' not found for deletion")
            elif e.status == 403:
                raise SecretManagerException(f"Access denied deleting secret '{key}': {e.reason}")
            else:
                raise SecretManagerException(f"Kubernetes API error deleting secret '{key}': {e.reason}")
        except Exception as e:
            raise SecretManagerException(f"Failed to delete secret '{key}': {e}")

    async def create_tls_secret(self, key: str, cert_data: str, key_data: str,
                                labels: Optional[Dict[str, str]] = None) -> bool:
        """
        Create a TLS secret in Kubernetes

        Args:
            key: Logical secret name
            cert_data: PEM-encoded certificate
            key_data: PEM-encoded private key
            labels: Optional labels

        Returns:
            True if successful
        """
        self._check_write_allowed()
        tls_data = {
            'tls.crt': cert_data,
            'tls.key': key_data
        }

        return await self.create_secret(
            key=key,
            value=tls_data,
            secret_type='kubernetes.io/tls',
            labels=labels
        )

    async def create_docker_registry_secret(self, key: str, server: str, username: str,
                                            password: str, email: Optional[str] = None,
                                            labels: Optional[Dict[str, str]] = None) -> bool:
        """
        Create a Docker registry secret in Kubernetes

        Args:
            key: Logical secret name
            server: Docker registry server
            username: Registry username
            password: Registry password
            email: Optional email address
            labels: Optional labels

        Returns:
            True if successful
        """
        self._check_write_allowed()
        import json

        # Create .dockerconfigjson content
        docker_config = {
            "auths": {
                server: {
                    "username": username,
                    "password": password,
                    "email": email or "",
                    "auth": base64.b64encode(f"{username}:{password}".encode()).decode()
                }
            }
        }

        registry_data = {
            '.dockerconfigjson': json.dumps(docker_config)
        }

        return await self.create_secret(
            key=key,
            value=registry_data,
            secret_type='kubernetes.io/dockerconfigjson',
            labels=labels
        )

    def __repr__(self) -> str:
        return f"KubernetesSecretManager(namespace='{self.namespace}')"