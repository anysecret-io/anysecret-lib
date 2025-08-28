"""
HashiCorp Vault implementation
"""
import asyncio
from typing import Dict, List, Optional, Any
import logging
from urllib.parse import urljoin

try:
    import hvac
    from hvac.exceptions import VaultError, InvalidPath, Forbidden
    HAS_VAULT = True
except ImportError:
    HAS_VAULT = False

from ..secret_manager import (
    BaseSecretManager,
    SecretValue,
    SecretNotFoundException,
    SecretManagerException,
    SecretManagerConnectionException
)

logger = logging.getLogger(__name__)


class VaultSecretManager(BaseSecretManager):
    """HashiCorp Vault implementation"""

    def __init__(self, config: Dict[str, Any]):
        if not HAS_VAULT:
            raise SecretManagerException(
                "HashiCorp Vault requires 'hvac' package. "
                "Install with: pip install hvac"
            )

        super().__init__(config)

        self.vault_url = config.get('vault_url', 'http://localhost:8200')
        self.mount_point = config.get('mount_point', 'secret')
        self.kv_version = config.get('kv_version', 2)  # KV v1 or v2

        # Authentication options
        self.token = config.get('token')
        self.role_id = config.get('role_id')  # AppRole auth
        self.secret_id = config.get('secret_id')  # AppRole auth
        self.username = config.get('username')  # Userpass auth
        self.password = config.get('password')  # Userpass auth
        self.jwt_token = config.get('jwt_token')  # JWT/OIDC auth
        self.role = config.get('role', 'default')  # JWT role

        # TLS options
        self.verify_tls = config.get('verify_tls', True)
        self.ca_cert_path = config.get('ca_cert_path')
        self.client_cert_path = config.get('client_cert_path')
        self.client_key_path = config.get('client_key_path')

        # Initialize client
        self._client = None
        self._initialize_client()

    def _initialize_client(self):
        """Initialize the HashiCorp Vault client"""
        try:
            # Configure TLS
            tls_config = {}
            if not self.verify_tls:
                tls_config['verify'] = False
            if self.ca_cert_path:
                tls_config['verify'] = self.ca_cert_path
            if self.client_cert_path and self.client_key_path:
                tls_config['cert'] = (self.client_cert_path, self.client_key_path)

            # Initialize client
            self._client = hvac.Client(url=self.vault_url, **tls_config)

            # Authenticate based on available credentials
            self._authenticate()

            # Verify authentication
            if not self._client.is_authenticated():
                raise SecretManagerConnectionException("Vault authentication failed")

            logger.info(f"HashiCorp Vault client initialized for: {self.vault_url}")

        except Exception as e:
            raise SecretManagerConnectionException(f"Failed to initialize Vault client: {e}")

    def _authenticate(self):
        """Authenticate with Vault using available credentials"""
        if self.token:
            # Direct token authentication
            self._client.token = self.token
            logger.info("Using Vault token authentication")

        elif self.role_id and self.secret_id:
            # AppRole authentication
            auth_response = self._client.auth.approle.login(
                role_id=self.role_id,
                secret_id=self.secret_id
            )
            self._client.token = auth_response['auth']['client_token']
            logger.info("Using Vault AppRole authentication")

        elif self.username and self.password:
            # Userpass authentication
            auth_response = self._client.auth.userpass.login(
                username=self.username,
                password=self.password
            )
            self._client.token = auth_response['auth']['client_token']
            logger.info("Using Vault userpass authentication")

        elif self.jwt_token:
            # JWT/OIDC authentication
            auth_response = self._client.auth.jwt.login(
                jwt=self.jwt_token,
                role=self.role
            )
            self._client.token = auth_response['auth']['client_token']
            logger.info("Using Vault JWT authentication")

        else:
            # Try to use existing token from environment or file
            if not self._client.token:
                raise SecretManagerException(
                    "No Vault authentication method provided. "
                    "Set token, role_id/secret_id, username/password, or jwt_token"
                )

    def _build_secret_path(self, key: str) -> str:
        """Build the full secret path for Vault KV engine"""
        if self.kv_version == 2:
            # KV v2 uses /data/ prefix for reading secrets
            return f"{self.mount_point}/data/{key}"
        else:
            # KV v1 direct path
            return f"{self.mount_point}/{key}"

    def _build_metadata_path(self, key: str) -> str:
        """Build metadata path for KV v2"""
        if self.kv_version == 2:
            return f"{self.mount_point}/metadata/{key}"
        else:
            # KV v1 doesn't have separate metadata
            return self._build_secret_path(key)

    async def get_secret_with_metadata(self, key: str) -> SecretValue:
        """Get secret with metadata from Vault"""
        try:
            loop = asyncio.get_event_loop()
            secret_path = self._build_secret_path(key)

            # Get secret data
            response = await loop.run_in_executor(
                None,
                self._client.secrets.kv.v2.read_secret_version if self.kv_version == 2
                else self._client.secrets.kv.v1.read_secret,
                key,
                self.mount_point
            )

            if not response:
                raise SecretNotFoundException(f"Secret '{key}' not found in Vault")

            # Extract data based on KV version
            if self.kv_version == 2:
                secret_data = response.get('data', {}).get('data', {})
                metadata = response.get('data', {}).get('metadata', {})
                version = metadata.get('version')
                created_time = metadata.get('created_time')
            else:
                secret_data = response.get('data', {})
                metadata = {}
                version = None
                created_time = None

            # For single-value secrets, return the first value
            # For multi-value secrets, return JSON representation
            if len(secret_data) == 1:
                secret_value = list(secret_data.values())[0]
            else:
                import json
                secret_value = json.dumps(secret_data)

            return SecretValue(
                value=str(secret_value),
                key=key,
                version=str(version) if version else None,
                created_at=created_time,
                metadata={
                    'source': 'hashicorp_vault',
                    'vault_url': self.vault_url,
                    'mount_point': self.mount_point,
                    'kv_version': self.kv_version,
                    'path': secret_path,
                    'is_multi_value': len(secret_data) > 1,
                    'keys': list(secret_data.keys()),
                    **metadata
                }
            )

        except (InvalidPath, KeyError):
            raise SecretNotFoundException(f"Secret '{key}' not found in Vault")
        except Forbidden as e:
            raise SecretManagerException(f"Access denied to secret '{key}': {e}")
        except VaultError as e:
            raise SecretManagerException(f"Vault error retrieving secret '{key}': {e}")
        except Exception as e:
            raise SecretManagerException(f"Failed to retrieve secret '{key}' from Vault: {e}")

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

            if self.kv_version == 2:
                # KV v2 uses metadata endpoint for listing
                list_path = f"{self.mount_point}/metadata"
            else:
                # KV v1 lists directly
                list_path = self.mount_point

            # List secrets recursively
            def _list_secrets_recursive(path: str = "", secrets: List[str] = None) -> List[str]:
                if secrets is None:
                    secrets = []

                current_path = f"{list_path}/{path}".rstrip('/')

                try:
                    response = self._client.secrets.kv.v2.list_secrets(
                        path=path, mount_point=self.mount_point
                    ) if self.kv_version == 2 else self._client.list(current_path)

                    if not response or 'data' not in response:
                        return secrets

                    keys = response['data'].get('keys', [])

                    for key in keys:
                        full_key = f"{path}/{key}".strip('/')

                        if key.endswith('/'):
                            # Directory - recurse
                            _list_secrets_recursive(full_key.rstrip('/'), secrets)
                        else:
                            # Secret
                            if prefix is None or full_key.startswith(prefix):
                                secrets.append(full_key)

                    return secrets

                except (InvalidPath, VaultError):
                    # Path doesn't exist or no permissions
                    return secrets

            all_secrets = await loop.run_in_executor(None, _list_secrets_recursive)
            return sorted(all_secrets)

        except Exception as e:
            raise SecretManagerException(f"Failed to list secrets: {e}")

    async def health_check(self) -> bool:
        """Check if Vault is accessible and authenticated"""
        try:
            loop = asyncio.get_event_loop()

            # Check if client is authenticated
            def _health_check():
                try:
                    return (
                        self._client.sys.is_initialized() and
                        not self._client.sys.is_sealed() and
                        self._client.is_authenticated()
                    )
                except Exception:
                    return False

            result = await loop.run_in_executor(None, _health_check)
            return result

        except Exception as e:
            logger.error(f"Vault health check failed: {e}")
            return False

    async def create_secret(self, key: str, value: Any, **kwargs) -> bool:
        """
        Create or update a secret in Vault

        Args:
            key: Secret path
            value: Secret value (can be string or dict)
            **kwargs: Additional metadata for KV v2

        Returns:
            True if successful
        """
        try:
            loop = asyncio.get_event_loop()

            # Prepare secret data
            if isinstance(value, dict):
                secret_data = value
            else:
                # Single value - use 'value' as key name
                secret_data = {'value': str(value)}

            def _create_secret():
                if self.kv_version == 2:
                    return self._client.secrets.kv.v2.create_or_update_secret(
                        path=key,
                        secret=secret_data,
                        mount_point=self.mount_point,
                        **kwargs
                    )
                else:
                    return self._client.secrets.kv.v1.create_or_update_secret(
                        path=key,
                        secret=secret_data,
                        mount_point=self.mount_point
                    )

            await loop.run_in_executor(None, _create_secret)

            logger.info(f"Created/updated secret '{key}' in Vault")
            return True

        except Forbidden as e:
            raise SecretManagerException(f"Access denied creating secret '{key}': {e}")
        except VaultError as e:
            raise SecretManagerException(f"Vault error creating secret '{key}': {e}")
        except Exception as e:
            raise SecretManagerException(f"Failed to create secret '{key}': {e}")

    async def update_secret(self, key: str, value: Any) -> bool:
        """Update an existing secret"""
        # In Vault, create and update are the same operation
        self._check_write_allowed()
        return await self.create_secret(key, value)

    async def delete_secret(self, key: str, destroy: bool = False) -> bool:
        """
        Delete a secret from Vault

        Args:
            key: Secret path
            destroy: If True, permanently destroy all versions (KV v2 only)

        Returns:
            True if successful
        """
        self._check_write_allowed()
        try:
            loop = asyncio.get_event_loop()

            def _delete_secret():
                if self.kv_version == 2:
                    if destroy:
                        # Permanently destroy all versions
                        return self._client.secrets.kv.v2.destroy_secret_versions(
                            path=key,
                            versions=None,  # All versions
                            mount_point=self.mount_point
                        )
                    else:
                        # Soft delete (can be recovered)
                        return self._client.secrets.kv.v2.delete_metadata_and_all_versions(
                            path=key,
                            mount_point=self.mount_point
                        )
                else:
                    # KV v1 - direct delete
                    return self._client.secrets.kv.v1.delete_secret(
                        path=key,
                        mount_point=self.mount_point
                    )

            await loop.run_in_executor(None, _delete_secret)

            # Clear cache
            if key in self._cache:
                del self._cache[key]

            logger.info(f"Deleted secret '{key}' from Vault (destroy={destroy})")
            return True

        except InvalidPath:
            raise SecretNotFoundException(f"Secret '{key}' not found for deletion")
        except Forbidden as e:
            raise SecretManagerException(f"Access denied deleting secret '{key}': {e}")
        except VaultError as e:
            raise SecretManagerException(f"Vault error deleting secret '{key}': {e}")
        except Exception as e:
            raise SecretManagerException(f"Failed to delete secret '{key}': {e}")

    async def get_secret_versions(self, key: str) -> List[Dict[str, Any]]:
        """
        Get all versions of a secret (KV v2 only)

        Args:
            key: Secret path

        Returns:
            List of version information
        """
        if self.kv_version != 2:
            raise SecretManagerException("Secret versions are only available in KV v2")

        try:
            loop = asyncio.get_event_loop()

            def _get_versions():
                response = self._client.secrets.kv.v2.read_secret_metadata(
                    path=key,
                    mount_point=self.mount_point
                )

                if not response or 'data' not in response:
                    return []

                versions_data = response['data'].get('versions', {})
                versions = []

                for version_num, version_info in versions_data.items():
                    versions.append({
                        'version': int(version_num),
                        'created_time': version_info.get('created_time'),
                        'deletion_time': version_info.get('deletion_time'),
                        'destroyed': version_info.get('destroyed', False)
                    })

                return sorted(versions, key=lambda x: x['version'], reverse=True)

            versions = await loop.run_in_executor(None, _get_versions)
            return versions

        except InvalidPath:
            raise SecretNotFoundException(f"Secret '{key}' not found")
        except Exception as e:
            raise SecretManagerException(f"Failed to get versions for secret '{key}': {e}")

    def __repr__(self) -> str:
        vault_host = self.vault_url.split('://')[1] if '://' in self.vault_url else self.vault_url
        return f"VaultSecretManager(url='{vault_host}', mount='{self.mount_point}')"