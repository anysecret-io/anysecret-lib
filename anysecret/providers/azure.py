"""
Azure Key Vault implementation
"""
import asyncio
from typing import Dict, List, Optional, Any
import logging
from datetime import datetime

try:
    from azure.keyvault.secrets import SecretClient
    from azure.identity import DefaultAzureCredential, ClientSecretCredential
    from azure.core.exceptions import ResourceNotFoundError, HttpResponseError
    HAS_AZURE = True
except ImportError:
    HAS_AZURE = False

from ..secret_manager import (
    BaseSecretManager,
    SecretValue,
    SecretNotFoundException,
    SecretManagerException,
    SecretManagerConnectionException
)

logger = logging.getLogger(__name__)


class AzureSecretManager(BaseSecretManager):
    """Azure Key Vault implementation"""

    def __init__(self, config: Dict[str, Any]):
        if not HAS_AZURE:
            raise SecretManagerException(
                "Azure Key Vault requires 'azure-keyvault-secrets' and 'azure-identity' packages. "
                "Install with: pip install azure-keyvault-secrets azure-identity"
            )

        super().__init__(config)

        self.vault_url = config.get('vault_url')
        if not self.vault_url:
            raise SecretManagerException("'vault_url' is required for Azure Key Vault")

        # Authentication options
        self.client_id = config.get('client_id')
        self.client_secret = config.get('client_secret')
        self.tenant_id = config.get('tenant_id')

        # Initialize client
        self._client = None
        self._initialize_client()

    def _initialize_client(self):
        """Initialize the Azure Key Vault client"""
        try:
            # Choose credential type based on configuration
            if self.client_id and self.client_secret and self.tenant_id:
                # Service Principal authentication
                credential = ClientSecretCredential(
                    tenant_id=self.tenant_id,
                    client_id=self.client_id,
                    client_secret=self.client_secret
                )
                logger.info("Using Azure service principal authentication")
            else:
                # Default credential chain (managed identity, Azure CLI, etc.)
                credential = DefaultAzureCredential()
                logger.info("Using Azure default credential chain")

            self._client = SecretClient(
                vault_url=self.vault_url,
                credential=credential
            )

            logger.info(f"Azure Key Vault client initialized for: {self.vault_url}")

        except Exception as e:
            raise SecretManagerConnectionException(f"Failed to initialize Azure Key Vault client: {e}")

    async def get_secret_with_metadata(self, key: str) -> SecretValue:
        """Get secret with metadata from Azure Key Vault"""
        try:
            loop = asyncio.get_event_loop()

            # Get secret value
            secret = await loop.run_in_executor(
                None,
                self._client.get_secret,
                key
            )

            # Azure returns KeyVaultSecret object
            secret_value = secret.value

            # Extract metadata
            metadata = {
                'source': 'azure_key_vault',
                'vault_url': self.vault_url,
                'key_id': secret.id,
                'content_type': secret.properties.content_type,
                'enabled': secret.properties.enabled,
                'tags': dict(secret.properties.tags) if secret.properties.tags else {}
            }

            return SecretValue(
                value=secret_value,
                key=key,
                version=secret.properties.version,
                created_at=secret.properties.created_on.isoformat() if secret.properties.created_on else None,
                metadata=metadata
            )

        except ResourceNotFoundError:
            raise SecretNotFoundException(f"Secret '{key}' not found in Azure Key Vault")
        except HttpResponseError as e:
            if e.status_code == 403:
                raise SecretManagerException(f"Access denied to secret '{key}': {e}")
            else:
                raise SecretManagerException(f"Azure error retrieving secret '{key}': {e}")
        except Exception as e:
            raise SecretManagerException(f"Failed to retrieve secret '{key}' from Azure: {e}")

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

            # Azure returns a paged collection
            def _list_secrets():
                secret_names = []
                secret_properties = self._client.list_properties_of_secrets()

                for secret_property in secret_properties:
                    # Extract secret name from the ID
                    # Azure Key Vault IDs are like: https://vault-name.vault.azure.net/secrets/secret-name/version
                    secret_name = secret_property.name

                    if prefix is None or secret_name.startswith(prefix):
                        secret_names.append(secret_name)

                return sorted(secret_names)

            all_secrets = await loop.run_in_executor(None, _list_secrets)
            return all_secrets

        except HttpResponseError as e:
            if e.status_code == 403:
                raise SecretManagerException(f"Access denied listing secrets: {e}")
            else:
                raise SecretManagerException(f"Azure error listing secrets: {e}")
        except Exception as e:
            raise SecretManagerException(f"Failed to list secrets: {e}")

    async def health_check(self) -> bool:
        """Check if Azure Key Vault is accessible"""
        try:
            loop = asyncio.get_event_loop()

            # Try to list secret properties with small page size
            def _health_check():
                try:
                    properties = self._client.list_properties_of_secrets(max_page_size=1)
                    # Just try to get the first page
                    next(iter(properties), None)
                    return True
                except StopIteration:
                    # Empty vault is still healthy
                    return True
                except Exception:
                    return False

            result = await loop.run_in_executor(None, _health_check)
            return result

        except Exception as e:
            logger.error(f"Azure Key Vault health check failed: {e}")
            return False

    async def create_secret(self, key: str, value: str, content_type: Optional[str] = None,
                          tags: Optional[Dict[str, str]] = None) -> bool:
        """
        Create a new secret in Azure Key Vault

        Args:
            key: Secret name
            value: Secret value
            content_type: MIME type of the secret value (optional)
            tags: Tags to associate with the secret (optional)

        Returns:
            True if successful
        """
        self._check_write_allowed()
        try:
            loop = asyncio.get_event_loop()

            def _create_secret():
                return self._client.set_secret(
                    name=key,
                    value=value,
                    content_type=content_type,
                    tags=tags
                )

            await loop.run_in_executor(None, _create_secret)

            logger.info(f"Created secret '{key}' in Azure Key Vault")
            return True

        except HttpResponseError as e:
            if e.status_code == 403:
                raise SecretManagerException(f"Access denied creating secret '{key}': {e}")
            elif e.status_code == 409:
                raise SecretManagerException(f"Secret '{key}' already exists (conflict)")
            else:
                raise SecretManagerException(f"Azure error creating secret '{key}': {e}")
        except Exception as e:
            raise SecretManagerException(f"Failed to create secret '{key}': {e}")

    async def update_secret(self, key: str, value: str) -> bool:
        """
        Update an existing secret with a new value

        Args:
            key: Secret name
            value: New secret value

        Returns:
            True if successful
        """
        self._check_write_allowed()
        try:
            loop = asyncio.get_event_loop()

            def _update_secret():
                return self._client.set_secret(name=key, value=value)

            await loop.run_in_executor(None, _update_secret)

            # Clear cache for this key
            if key in self._cache:
                del self._cache[key]

            logger.info(f"Updated secret '{key}' in Azure Key Vault")
            return True

        except ResourceNotFoundError:
            raise SecretNotFoundException(f"Secret '{key}' not found for update")
        except HttpResponseError as e:
            if e.status_code == 403:
                raise SecretManagerException(f"Access denied updating secret '{key}': {e}")
            else:
                raise SecretManagerException(f"Azure error updating secret '{key}': {e}")
        except Exception as e:
            raise SecretManagerException(f"Failed to update secret '{key}': {e}")

    async def delete_secret(self, key: str) -> bool:
        """
        Delete a secret from Azure Key Vault

        Args:
            key: Secret name

        Returns:
            True if successful
        """
        self._check_write_allowed()
        try:
            loop = asyncio.get_event_loop()

            def _delete_secret():
                # Azure Key Vault uses soft delete by default
                return self._client.begin_delete_secret(name=key)

            delete_operation = await loop.run_in_executor(None, _delete_secret)

            # Wait for the delete operation to complete
            def _wait_for_delete():
                return delete_operation.result()

            await loop.run_in_executor(None, _wait_for_delete)

            # Clear cache for this key
            if key in self._cache:
                del self._cache[key]

            logger.info(f"Deleted secret '{key}' from Azure Key Vault")
            return True

        except ResourceNotFoundError:
            raise SecretNotFoundException(f"Secret '{key}' not found for deletion")
        except HttpResponseError as e:
            if e.status_code == 403:
                raise SecretManagerException(f"Access denied deleting secret '{key}': {e}")
            else:
                raise SecretManagerException(f"Azure error deleting secret '{key}': {e}")
        except Exception as e:
            raise SecretManagerException(f"Failed to delete secret '{key}': {e}")

    async def get_secret_versions(self, key: str) -> List[Dict[str, Any]]:
        """
        Get all versions of a secret

        Args:
            key: Secret name

        Returns:
            List of version information dictionaries
        """
        try:
            loop = asyncio.get_event_loop()

            def _get_versions():
                versions = []
                version_properties = self._client.list_properties_of_secret_versions(name=key)

                for version_property in version_properties:
                    versions.append({
                        'version': version_property.version,
                        'enabled': version_property.enabled,
                        'created_on': version_property.created_on.isoformat() if version_property.created_on else None,
                        'updated_on': version_property.updated_on.isoformat() if version_property.updated_on else None,
                        'expires_on': version_property.expires_on.isoformat() if version_property.expires_on else None,
                        'tags': dict(version_property.tags) if version_property.tags else {}
                    })

                return sorted(versions, key=lambda x: x['created_on'] or '', reverse=True)

            versions = await loop.run_in_executor(None, _get_versions)
            return versions

        except ResourceNotFoundError:
            raise SecretNotFoundException(f"Secret '{key}' not found")
        except Exception as e:
            raise SecretManagerException(f"Failed to get versions for secret '{key}': {e}")

    def __repr__(self) -> str:
        vault_name = self.vault_url.split('//')[1].split('.')[0] if self.vault_url else 'unknown'
        return f"AzureSecretManager(vault='{vault_name}')"


