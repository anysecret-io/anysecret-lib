# File: anysecret/providers/gcp_parameter_manager.py

import asyncio
import json
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


class GcpParameterManagerClient(BaseParameterManager):
    """Parameter manager using Google Cloud Parameter Manager"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

        try:
            from google.cloud import secretmanager_v1
            from google.api_core import exceptions as gcp_exceptions
            self.secretmanager_v1 = secretmanager_v1
            self.gcp_exceptions = gcp_exceptions
        except ImportError:
            raise ParameterManagerError(
                "google-cloud-secret-manager is required. Install with: pip install google-cloud-secret-manager"
            )

        self.project_id = config.get('project_id')
        if not self.project_id:
            raise ParameterManagerError("project_id is required for GCP Parameter Manager")

        self.prefix = config.get('prefix', '')

        try:
            self.client = self.secretmanager_v1.SecretManagerServiceClient()
        except Exception as e:
            raise ParameterManagerError(f"Failed to initialize GCP Parameter Manager client: {e}")

    def _get_full_name(self, key: str) -> str:
        """Get the full parameter name with prefix"""
        if self.prefix:
            full_key = f"{self.prefix.rstrip('/')}-{key.lstrip('/')}"
        else:
            full_key = key
        return f"projects/{self.project_id}/secrets/{full_key}"

    def _strip_prefix(self, secret_name: str) -> str:
        """Remove prefix from secret name to get key"""
        # Extract secret ID from full name: projects/{project}/secrets/{secret_id}
        secret_id = secret_name.split('/')[-1]

        if self.prefix:
            prefix_with_dash = f"{self.prefix.rstrip('/')}-"
            if secret_id.startswith(prefix_with_dash):
                return secret_id[len(prefix_with_dash):]
        return secret_id

    async def get_parameter_with_metadata(self, key: str) -> ParameterValue:
        """Get a parameter from GCP Parameter Manager"""
        secret_name = self._get_full_name(key)

        try:
            loop = asyncio.get_event_loop()

            # Get the secret
            secret_response = await loop.run_in_executor(
                None,
                lambda: self.client.get_secret(request={"name": secret_name})
            )

            # Get the latest version
            version_name = f"{secret_name}/versions/latest"
            version_response = await loop.run_in_executor(
                None,
                lambda: self.client.access_secret_version(request={"name": version_name})
            )

            # Extract value
            payload = version_response.payload.data.decode('utf-8')

            # Try to parse as JSON
            try:
                value = json.loads(payload)
            except json.JSONDecodeError:
                value = payload

            metadata = {
                'source': 'gcp_parameter_manager',
                'project_id': self.project_id,
                'secret_name': secret_name,
                'version': version_response.name,
                'created': secret_response.create_time.isoformat() if secret_response.create_time else None,
                'labels': dict(secret_response.labels) if secret_response.labels else {}
            }

            return ParameterValue(key, value, metadata)

        except self.gcp_exceptions.NotFound:
            raise ParameterNotFoundError(f"Parameter '{key}' not found in GCP Parameter Manager")
        except Exception as e:
            if "not found" in str(e).lower() or "404" in str(e):
                raise ParameterNotFoundError(f"Parameter '{key}' not found")
            raise ParameterAccessError(f"Failed to get parameter '{key}': {e}")

    async def list_parameters(self, prefix: Optional[str] = None) -> List[str]:
        """List parameters from GCP Parameter Manager"""
        try:
            loop = asyncio.get_event_loop()

            project_path = f"projects/{self.project_id}"

            # List all secrets in the project
            secrets = await loop.run_in_executor(
                None,
                lambda: self.client.list_secrets(request={"parent": project_path})
            )

            keys = []
            for secret in secrets:
                key = self._strip_prefix(secret.name)

                # Apply prefix filter if provided
                if prefix and not key.startswith(prefix):
                    continue

                keys.append(key)

            return sorted(keys)

        except Exception as e:
            raise ParameterAccessError(f"Failed to list parameters: {e}")

    async def health_check(self) -> bool:
        """Check if GCP Parameter Manager is accessible"""
        try:
            loop = asyncio.get_event_loop()

            # Try to list secrets (lightweight operation)
            project_path = f"projects/{self.project_id}"
            await loop.run_in_executor(
                None,
                lambda: list(self.client.list_secrets(request={"parent": project_path, "page_size": 1}))
            )
            return True
        except Exception as e:
            logger.error(f"GCP Parameter Manager health check failed: {e}")
            return False

    async def create_parameter(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Create a parameter in GCP Parameter Manager"""
        self._check_write_allowed()

        secret_name = self._get_full_name(key)
        project_path = f"projects/{self.project_id}"
        secret_id = secret_name.split('/')[-1]

        try:
            loop = asyncio.get_event_loop()

            # Serialize value
            if isinstance(value, (dict, list)):
                payload = json.dumps(value).encode('utf-8')
            else:
                payload = str(value).encode('utf-8')

            # Create the secret
            secret_request = {
                'parent': project_path,
                'secret_id': secret_id,
                'secret': {
                    'labels': metadata or {},
                    'replication': {'automatic': {}}
                }
            }

            secret = await loop.run_in_executor(
                None,
                lambda: self.client.create_secret(request=secret_request)
            )

            # Add the secret version
            version_request = {
                'parent': secret.name,
                'payload': {'data': payload}
            }

            await loop.run_in_executor(
                None,
                lambda: self.client.add_secret_version(request=version_request)
            )

            return True

        except self.gcp_exceptions.AlreadyExists:
            raise ParameterManagerError(f"Parameter '{key}' already exists")
        except Exception as e:
            if "already exists" in str(e).lower():
                raise ParameterManagerError(f"Parameter '{key}' already exists")
            raise ParameterAccessError(f"Failed to create parameter '{key}': {e}")

    async def update_parameter(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Update a parameter in GCP Parameter Manager"""
        self._check_write_allowed()

        secret_name = self._get_full_name(key)

        try:
            loop = asyncio.get_event_loop()

            # Serialize value
            if isinstance(value, (dict, list)):
                payload = json.dumps(value).encode('utf-8')
            else:
                payload = str(value).encode('utf-8')

            # Add new version to existing secret
            version_request = {
                'parent': secret_name,
                'payload': {'data': payload}
            }

            await loop.run_in_executor(
                None,
                lambda: self.client.add_secret_version(request=version_request)
            )

            return True

        except self.gcp_exceptions.NotFound:
            raise ParameterNotFoundError(f"Parameter '{key}' not found for update")
        except Exception as e:
            if "not found" in str(e).lower():
                raise ParameterNotFoundError(f"Parameter '{key}' not found for update")
            raise ParameterAccessError(f"Failed to update parameter '{key}': {e}")

    async def delete_parameter(self, key: str) -> bool:
        """Delete a parameter from GCP Parameter Manager"""
        self._check_write_allowed()

        secret_name = self._get_full_name(key)

        try:
            loop = asyncio.get_event_loop()

            await loop.run_in_executor(
                None,
                lambda: self.client.delete_secret(request={"name": secret_name})
            )

            return True

        except self.gcp_exceptions.NotFound:
            raise ParameterNotFoundError(f"Parameter '{key}' not found")
        except Exception as e:
            if "not found" in str(e).lower():
                raise ParameterNotFoundError(f"Parameter '{key}' not found")
            raise ParameterAccessError(f"Failed to delete parameter '{key}': {e}")


# Alias for backward compatibility
GcpConfigConnectorManager = GcpParameterManagerClient