"""
Google Cloud Secret Manager implementation
"""
import asyncio
from typing import Dict, List, Optional, Any
import logging
from datetime import datetime

try:
    from google.cloud import secretmanager
    from google.api_core import exceptions as gcp_exceptions
    from google.auth import default as gcp_auth

    HAS_GCP = True
except ImportError:
    HAS_GCP = False

from ..secret_manager import (
    BaseSecretManager,
    SecretValue,
    SecretNotFoundException,
    SecretManagerException,
    SecretManagerConnectionException
)

logger = logging.getLogger(__name__)


class GcpSecretManager(BaseSecretManager):
    """Google Cloud Secret Manager implementation"""

    def __init__(self, config: Dict[str, Any]):
        if not HAS_GCP:
            raise SecretManagerException(
                "Google Cloud Secret Manager requires 'google-cloud-secret-manager' package. "
                "Install with: pip install google-cloud-secret-manager"
            )

        super().__init__(config)

        self.project_id = config.get('project_id')
        self.credentials_path = config.get('credentials_path')
        self.location = config.get('location', 'global')

        # Initialize client
        self._client = None
        self._initialize_client()

        # Auto-detect project ID if not provided
        if not self.project_id:
            self.project_id = self._detect_project_id()

    def _initialize_client(self):
        """Initialize the GCP Secret Manager client"""
        try:
            if self.credentials_path:
                # Use specific credentials file
                import os
                os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = self.credentials_path

            self._client = secretmanager.SecretManagerServiceClient()
            logger.info("GCP Secret Manager client initialized")

        except Exception as e:
            raise SecretManagerConnectionException(f"Failed to initialize GCP client: {e}")

    def _detect_project_id(self) -> str:
        """Auto-detect GCP project ID"""
        try:
            credentials, project_id = gcp_auth()
            if project_id:
                logger.info(f"Auto-detected GCP project ID: {project_id}")
                return project_id
            else:
                raise SecretManagerException(
                    "Could not auto-detect project ID. Please provide 'project_id' in config."
                )
        except Exception as e:
            raise SecretManagerException(f"Failed to detect project ID: {e}")

    def _build_secret_path(self, key: str, version: str = "latest") -> str:
        """Build the full secret path for GCP"""
        return f"projects/{self.project_id}/secrets/{key}/versions/{version}"

    async def get_secret_with_metadata(self, key: str) -> SecretValue:
        """Get secret with metadata from GCP"""
        try:
            # Build the resource name
            name = self._build_secret_path(key)

            # Make the request in a thread to avoid blocking
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                self._client.access_secret_version,
                {"name": name}
            )

            # Extract secret value
            secret_value = response.payload.data.decode("UTF-8")

            # Get additional metadata
            secret_metadata = await self._get_secret_metadata(key)

            return SecretValue(
                value=secret_value,
                key=key,
                version=response.name.split("/")[-1],
                created_at=secret_metadata.get('created_at'),  # Get from metadata instead
                metadata={
                    'source': 'gcp_secret_manager',
                    'project_id': self.project_id,
                    'secret_name': key,
                    **secret_metadata
                }
            )

        except gcp_exceptions.NotFound:
            raise SecretNotFoundException(f"Secret '{key}' not found in GCP Secret Manager")
        except gcp_exceptions.PermissionDenied as e:
            raise SecretManagerException(f"Permission denied accessing secret '{key}': {e}")
        except Exception as e:
            raise SecretManagerException(f"Failed to retrieve secret '{key}' from GCP: {e}")

    async def _get_secret_metadata(self, key: str) -> Dict[str, Any]:
        """Get metadata for a secret"""
        try:
            loop = asyncio.get_event_loop()
            parent = f"projects/{self.project_id}"

            # List secrets to find the one we want
            request = {"parent": parent}
            response = await loop.run_in_executor(
                None,
                self._client.list_secrets,
                request
            )

            for secret in response:
                if secret.name.endswith(f"/secrets/{key}"):
                    return {
                        'labels': dict(secret.labels) if secret.labels else {},
                        'created_at': secret.create_time.isoformat() if secret.create_time else None,
                        'updated_at': secret.etag or None,
                    }

            return {}

        except Exception as e:
            logger.warning(f"Failed to get metadata for secret '{key}': {e}")
            return {}

    async def get_secrets_by_prefix(self, prefix: str) -> Dict[str, str]:
        """Get all secrets with given prefix"""
        try:
            # List all secrets
            all_secrets = await self.list_secrets()

            # Filter by prefix and fetch values
            matching_keys = [key for key in all_secrets if key.startswith(prefix)]

            return await self.get_secrets_batch(matching_keys)

        except Exception as e:
            raise SecretManagerException(f"Failed to get secrets by prefix '{prefix}': {e}")

    async def list_secrets(self, prefix: Optional[str] = None) -> List[str]:
        """List all secret keys"""
        try:
            loop = asyncio.get_event_loop()
            parent = f"projects/{self.project_id}"

            request = {"parent": parent}
            response = await loop.run_in_executor(
                None,
                self._client.list_secrets,
                request
            )

            secret_names = []
            for secret in response:
                # Extract secret name from full path
                secret_name = secret.name.split("/")[-1]

                if prefix is None or secret_name.startswith(prefix):
                    secret_names.append(secret_name)

            return sorted(secret_names)

        except Exception as e:
            raise SecretManagerException(f"Failed to list secrets: {e}")

    async def health_check(self) -> bool:
        """Check if GCP Secret Manager is accessible"""
        try:
            logger.info(f"Starting GCP health check for project {self.project_id}")
            
            # Quick check - just verify client exists and project is set
            if not self._client or not self.project_id:
                logger.error(f"Missing client or project_id: client={self._client}, project={self.project_id}")
                return False
            
            # Try a lightweight operation
            loop = asyncio.get_event_loop()
            parent = f"projects/{self.project_id}"
            
            # Try to list with minimal response and timeout
            request = {"parent": parent, "page_size": 1}
            result = await loop.run_in_executor(
                None,
                lambda: list(self._client.list_secrets(request=request, timeout=10.0))
            )
            
            logger.info(f"GCP health check passed for project {self.project_id}")
            return True

        except Exception as e:
            logger.error(f"GCP Secret Manager health check failed: {e}")
            return False

    async def create_secret(self, key: str, value: str, labels: Optional[Dict[str, str]] = None) -> bool:
        """
        Create a new secret in GCP Secret Manager

        Args:
            key: Secret name
            value: Secret value
            labels: Optional labels for the secret

        Returns:
            True if successful
        """
        self._check_write_allowed()
        try:
            loop = asyncio.get_event_loop()
            parent = f"projects/{self.project_id}"

            # Create the secret with replication policy
            secret_request = {
                "parent": parent,
                "secret_id": key,
                "secret": {
                    "labels": labels or {},
                    "replication": {
                        "automatic": {}  # Use automatic replication
                    }
                }
            }

            secret = await loop.run_in_executor(
                None,
                self._client.create_secret,
                secret_request
            )

            # Add the secret version with the actual value
            version_request = {
                "parent": secret.name,
                "payload": {"data": value.encode("UTF-8")}
            }

            await loop.run_in_executor(
                None,
                self._client.add_secret_version,
                version_request
            )

            logger.info(f"Created secret '{key}' in GCP Secret Manager")
            return True

        except gcp_exceptions.AlreadyExists:
            raise SecretManagerException(f"Secret '{key}' already exists")
        except Exception as e:
            raise SecretManagerException(f"Failed to create secret '{key}': {e}")

    async def update_secret(self, key: str, value: str) -> bool:
        """
        Update an existing secret with a new version

        Args:
            key: Secret name
            value: New secret value

        Returns:
            True if successful
        """
        self._check_write_allowed()
        try:
            loop = asyncio.get_event_loop()
            parent = f"projects/{self.project_id}/secrets/{key}"

            # Add new version
            request = {
                "parent": parent,
                "payload": {"data": value.encode("UTF-8")}
            }

            await loop.run_in_executor(
                None,
                self._client.add_secret_version,
                request
            )

            # Clear cache for this key
            if key in self._cache:
                del self._cache[key]

            logger.info(f"Updated secret '{key}' in GCP Secret Manager")
            return True

        except gcp_exceptions.NotFound:
            raise SecretNotFoundException(f"Secret '{key}' not found for update")
        except Exception as e:
            raise SecretManagerException(f"Failed to update secret '{key}': {e}")

    def __repr__(self) -> str:
        return f"GcpSecretManager(project_id='{self.project_id}')"

    async def delete_secret(self, key: str) -> bool:
        """
        Delete a secret from GCP Secret Manager

        Args:
            key: Secret name

        Returns:
            True if successful
        """
        self._check_write_allowed()

        try:
            loop = asyncio.get_event_loop()
            parent = f"projects/{self.project_id}/secrets/{key}"

            await loop.run_in_executor(
                None,
                self._client.delete_secret,
                {"name": parent}
            )

            # Clear cache for this key
            if key in self._cache:
                del self._cache[key]

            logger.info(f"Deleted secret '{key}' from GCP Secret Manager")
            return True

        except gcp_exceptions.NotFound:
            raise SecretNotFoundException(f"Secret '{key}' not found for deletion")
        except gcp_exceptions.PermissionDenied as e:
            raise SecretManagerException(f"Access denied deleting secret '{key}': {e}")
        except Exception as e:
            raise SecretManagerException(f"Failed to delete secret '{key}': {e}")

