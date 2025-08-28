"""
Secret Manager Interface and Base Classes
Provides abstraction for different secret management backends
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
import asyncio
import logging
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class SecretManagerType(Enum):
    """Supported secret manager types"""
    GCP = "gcp"
    AWS = "aws"
    AZURE = "azure"
    VAULT = "vault"
    ENCRYPTED_FILE = "encrypted_file"
    ENV_FILE = "env_file"
    KUBERNETES = "kubernetes"# For development only


@dataclass
class SecretValue:
    """Represents a secret value with metadata"""
    value: str
    key: str
    version: Optional[str] = None
    created_at: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class SecretManagerException(Exception):
    """Base exception for secret manager operations"""
    pass


class SecretNotFoundException(SecretManagerException):
    """Raised when a requested secret is not found"""
    pass


class SecretManagerConnectionException(SecretManagerException):
    """Raised when connection to secret manager fails"""
    pass


class SecretManagerInterface(ABC):
    """Abstract interface for secret managers"""

    @abstractmethod
    async def get_secret(self, key: str) -> str:
        """
        Get a single secret value by key

        Args:
            key: Secret key/name

        Returns:
            Secret value as string

        Raises:
            SecretNotFoundException: If secret doesn't exist
            SecretManagerException: For other errors
        """
        pass

    @abstractmethod
    async def get_secret_with_metadata(self, key: str) -> SecretValue:
        """
        Get a secret with its metadata

        Args:
            key: Secret key/name

        Returns:
            SecretValue object with metadata
        """
        pass

    @abstractmethod
    async def get_secrets_by_prefix(self, prefix: str) -> Dict[str, str]:
        """
        Get all secrets with a given prefix

        Args:
            prefix: Key prefix to search for

        Returns:
            Dictionary of key-value pairs
        """
        pass

    @abstractmethod
    async def list_secrets(self, prefix: Optional[str] = None) -> List[str]:
        """
        List all available secret keys

        Args:
            prefix: Optional prefix to filter by

        Returns:
            List of secret keys
        """
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check if the secret manager is accessible

        Returns:
            True if healthy, False otherwise
        """
        pass

    async def get_secrets_batch(self, keys: List[str]) -> Dict[str, str]:
        """
        Get multiple secrets in a batch (default implementation)

        Args:
            keys: List of secret keys

        Returns:
            Dictionary of key-value pairs
        """
        results = {}
        tasks = []

        for key in keys:
            tasks.append(self._get_secret_safe(key))

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for key, response in zip(keys, responses):
            if isinstance(response, Exception):
                logger.warning(f"Failed to get secret '{key}': {response}")
            else:
                results[key] = response

        return results

    async def _get_secret_safe(self, key: str) -> Optional[str]:
        """Safe secret retrieval that doesn't raise exceptions"""
        try:
            return await self.get_secret(key)
        except Exception as e:
            logger.error(f"Error retrieving secret '{key}': {e}")
            return None

    # Write operations (optional - providers can raise NotImplementedError)
    async def create_secret(self, key: str, value: Any, **kwargs) -> bool:
        """Create a new secret"""
        raise NotImplementedError("Create operation not supported by this provider")

    async def update_secret(self, key: str, value: Any, **kwargs) -> bool:
        """Update an existing secret"""
        raise NotImplementedError("Update operation not supported by this provider")

    async def delete_secret(self, key: str, **kwargs) -> bool:
        """Delete a secret"""
        raise NotImplementedError("Delete operation not supported by this provider")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}()"


class BaseSecretManager(SecretManagerInterface):
    """Base class with common functionality"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._cache: Dict[str, SecretValue] = {}
        self._cache_ttl = self.config.get('cache_ttl', 300)  # 5 minutes default
        self._last_cache_clear = asyncio.get_event_loop().time() if asyncio._get_running_loop() else 0
        self._read_only = self.config.get('read_only', False)

    async def _get_from_cache(self, key: str) -> Optional[str]:
        """Get secret from cache if valid"""
        if not self._is_cache_valid():
            await self._clear_cache()
            return None

        cached = self._cache.get(key)
        if cached:
            logger.debug(f"Secret '{key}' retrieved from cache")
            return cached.value

        return None

    def _check_write_allowed(self):
        """Check if write operations are allowed"""
        if self._read_only:
            raise SecretManagerException("Provider is configured as read-only")

    async def _set_cache(self, key: str, secret_value: SecretValue):
        """Set secret in cache"""
        self._cache[key] = secret_value
        logger.debug(f"Secret '{key}' cached")

    def _is_cache_valid(self) -> bool:
        """Check if cache is still valid"""
        try:
            current_time = asyncio.get_event_loop().time()
            return (current_time - self._last_cache_clear) < self._cache_ttl
        except RuntimeError:
            # No event loop running, assume cache is invalid
            return False

    async def _clear_cache(self):
        """Clear the secret cache"""
        self._cache.clear()
        try:
            self._last_cache_clear = asyncio.get_event_loop().time()
        except RuntimeError:
            self._last_cache_clear = 0
        logger.debug("Secret cache cleared")

    async def get_secret(self, key: str) -> str:
        """Get secret with caching"""
        # Check cache first
        cached_value = await self._get_from_cache(key)
        if cached_value is not None:
            return cached_value

        # Fetch from backend
        secret_value = await self.get_secret_with_metadata(key)

        # Cache the result
        await self._set_cache(key, secret_value)

        return secret_value.value


class SecretManagerFactory:
    """Factory for creating secret manager instances"""

    _managers = {
        SecretManagerType.GCP: 'anysecret.providers.gcp.GcpSecretManager',
        SecretManagerType.AWS: 'anysecret.providers.aws.AwsSecretManager',
        SecretManagerType.AZURE: 'anysecret.providers.azure.AzureSecretManager',
        SecretManagerType.VAULT: 'anysecret.providers.vault.VaultSecretManager',
        SecretManagerType.ENCRYPTED_FILE: 'anysecret.providers.file.EncryptedFileSecretManager',
        SecretManagerType.ENV_FILE: 'anysecret.providers.file.EnvFileSecretManager',
        SecretManagerType.KUBERNETES: 'anysecret.providers.kubernetes.KubernetesSecretManager',

    }

    @classmethod
    def create(cls,
               manager_type: SecretManagerType,
               config: Dict[str, Any]) -> SecretManagerInterface:
        """
        Create a secret manager instance

        Args:
            manager_type: Type of secret manager to create
            config: Configuration for the secret manager

        Returns:
            Secret manager instance
        """
        if manager_type not in cls._managers:
            raise ValueError(f"Unsupported secret manager type: {manager_type}")

        module_path = cls._managers[manager_type]
        module_name, class_name = module_path.rsplit('.', 1)

        try:
            module = __import__(module_name, fromlist=[class_name])
            manager_class = getattr(module, class_name)
            return manager_class(config=config)
        except ImportError as e:
            raise SecretManagerException(f"Failed to import {module_path}: {e}")
        except Exception as e:
            raise SecretManagerException(f"Failed to create {manager_type.value} secret manager: {e}")

    @classmethod
    def detect_available_managers(cls) -> List[SecretManagerType]:
        """Detect which secret managers are available in current environment"""
        available = []

        # Always available
        available.extend([
            SecretManagerType.ENV_FILE,
            SecretManagerType.ENCRYPTED_FILE
        ])

        # Check for cloud SDK availability
        try:
            import google.cloud.secretmanager
            available.append(SecretManagerType.GCP)
        except ImportError:
            pass

        try:
            import boto3
            available.append(SecretManagerType.AWS)
        except ImportError:
            pass

        try:
            import azure.keyvault.secrets
            available.append(SecretManagerType.AZURE)
        except ImportError:
            pass

        try:
            import hvac
            available.append(SecretManagerType.VAULT)
        except ImportError:
            pass

        try:
            import kubernetes  # Add this block
            available.append(SecretManagerType.KUBERNETES)
        except ImportError:
            pass

        return available