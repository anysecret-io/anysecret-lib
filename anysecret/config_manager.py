# File: anysecret/config_manager.py

import re
from typing import Any, Dict, List, Optional, Union
import logging

from .secret_manager import SecretManagerFactory, SecretManagerType
from .parameter_manager import ParameterManagerFactory, ParameterManagerType
from .parameter_manager import ParameterManagerError

logger = logging.getLogger(__name__)


class ConfigValue:
    """Represents a configuration value that could be either a secret or parameter"""

    def __init__(self, key: str, value: Any, is_secret: bool, metadata: Optional[Dict[str, Any]] = None):
        self.key = key
        self.value = value
        self.is_secret = is_secret
        self.metadata = metadata or {}

    def __str__(self) -> str:
        if self.is_secret:
            return "[SECRET]"  # Don't expose secret values in string representation
        return str(self.value)

    def __repr__(self) -> str:
        value_repr = "[SECRET]" if self.is_secret else repr(self.value)
        return f"ConfigValue(key='{self.key}', value={value_repr}, is_secret={self.is_secret})"


class ConfigManager:
    """Unified configuration manager that handles both secrets and parameters"""

    # Default patterns for classifying keys as secrets
    SECRET_PATTERNS = [
        r'.*_secret$',
        r'.*_password$',
        r'.*_key$',
        r'.*_token$',
        r'.*_credential$',
        r'.*_auth$',
        r'.*password.*',
        r'.*secret.*',
        r'.*key.*',
        r'.*token.*',
        r'.*credential.*',
        r'.*auth.*',
    ]

    # Default patterns for classifying keys as parameters
    PARAMETER_PATTERNS = [
        r'.*_config$',
        r'.*_timeout$',
        r'.*_limit$',
        r'.*_host$',
        r'.*_port$',
        r'.*_url$',
        r'.*_endpoint$',
        r'.*_region$',
        r'.*_zone$',
        r'.*config.*',
        r'.*setting.*',
        r'.*option.*',
    ]

    def __init__(self, secret_config: Dict[str, Any], parameter_config: Dict[str, Any]):
        """
        Initialize the unified config manager

        Args:
            secret_config: Configuration for secret manager
            parameter_config: Configuration for parameter manager
        """
        self.secret_factory = SecretManagerFactory()
        self.parameter_factory = ParameterManagerFactory()

        # Initialize managers
        secret_type_str = secret_config.get('type')
        parameter_type_str = parameter_config.get('type')

        if not secret_type_str:
            raise ParameterManagerError("Secret manager type is required")
        if not parameter_type_str:
            raise ParameterManagerError("Parameter manager type is required")

        # Convert strings to enums
        try:
            secret_type = SecretManagerType(secret_type_str)
        except ValueError:
            raise ParameterManagerError(f"Unknown secret manager type: {secret_type_str}")
        
        try:
            parameter_type = ParameterManagerType(parameter_type_str)
        except ValueError:
            raise ParameterManagerError(f"Unknown parameter manager type: {parameter_type_str}")

        self.secret_manager = self.secret_factory.create(secret_type, secret_config)
        self.parameter_manager = self.parameter_factory.create_manager(parameter_type, parameter_config)

        # Custom classification patterns
        self.custom_secret_patterns = secret_config.get('secret_patterns', [])
        self.custom_parameter_patterns = parameter_config.get('parameter_patterns', [])

        # Compile all patterns
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for efficient matching"""
        all_secret_patterns = self.SECRET_PATTERNS + self.custom_secret_patterns
        all_parameter_patterns = self.PARAMETER_PATTERNS + self.custom_parameter_patterns

        self.secret_regexes = [re.compile(pattern, re.IGNORECASE) for pattern in all_secret_patterns]
        self.parameter_regexes = [re.compile(pattern, re.IGNORECASE) for pattern in all_parameter_patterns]

    def classify_key(self, key: str, hint: Optional[str] = None) -> bool:
        """
        Classify a key as secret (True) or parameter (False)

        Args:
            key: The configuration key to classify
            hint: Optional hint ('secret' or 'parameter') to override classification

        Returns:
            True if key should be treated as secret, False for parameter
        """
        # Manual override via hint
        if hint:
            return hint.lower() in ('secret', 'secrets', 'true')

        # Check secret patterns first (more restrictive)
        for regex in self.secret_regexes:
            if regex.search(key):
                return True

        # Check parameter patterns
        for regex in self.parameter_regexes:
            if regex.search(key):
                return False

        # Default: assume parameter (less sensitive default)
        logger.debug(f"Key '{key}' didn't match any pattern, defaulting to parameter")
        return False

    async def get(self, key: str, hint: Optional[str] = None) -> Any:
        """
        Get a configuration value, automatically routing to secrets or parameters

        Args:
            key: Configuration key to retrieve
            hint: Optional hint to override automatic classification

        Returns:
            The configuration value
        """
        is_secret = self.classify_key(key, hint)

        if is_secret:
            return await self.get_secret(key)
        else:
            return await self.get_parameter(key)

    async def get_with_metadata(self, key: str, hint: Optional[str] = None) -> ConfigValue:
        """
        Get a configuration value with metadata and classification info

        Args:
            key: Configuration key to retrieve
            hint: Optional hint to override automatic classification

        Returns:
            ConfigValue with metadata
        """
        is_secret = self.classify_key(key, hint)

        if is_secret:
            secret_value = await self.secret_manager.get_secret_with_metadata(key)
            return ConfigValue(key, secret_value.value, True, secret_value.metadata)
        else:
            param_value = await self.parameter_manager.get_parameter_with_metadata(key)
            return ConfigValue(key, param_value.value, False, param_value.metadata)

    async def get_secret(self, key: str) -> Any:
        """Explicitly get a value from secret storage"""
        secret_value = await self.secret_manager.get_secret_with_metadata(key)
        return secret_value.value

    async def get_parameter(self, key: str) -> Any:
        """Explicitly get a value from parameter storage"""
        param_value = await self.parameter_manager.get_parameter_with_metadata(key)
        return param_value.value

    async def get_config_by_prefix(self, prefix: str) -> Dict[str, Any]:
        """
        Get all configuration values with a given prefix from both stores

        Args:
            prefix: Prefix to search for

        Returns:
            Dictionary of key-value pairs
        """
        config = {}

        # Get secrets with prefix
        try:
            secret_keys = await self.secret_manager.list_secrets(prefix)
            for key in secret_keys:
                try:
                    value = await self.secret_manager.get_secret_with_metadata(key)
                    config[key] = value.value
                except Exception as e:
                    logger.warning(f"Failed to get secret {key}: {e}")
        except Exception as e:
            logger.debug(f"Failed to list secrets with prefix {prefix}: {e}")

        # Get parameters with prefix
        try:
            param_keys = await self.parameter_manager.list_parameters(prefix)
            for key in param_keys:
                try:
                    value = await self.parameter_manager.get_parameter_with_metadata(key)
                    config[key] = value.value
                except Exception as e:
                    logger.warning(f"Failed to get parameter {key}: {e}")
        except Exception as e:
            logger.debug(f"Failed to list parameters with prefix {prefix}: {e}")

        return config

    async def set(self, key: str, value: Any, hint: Optional[str] = None,
                  metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Set a configuration value, automatically routing to secrets or parameters

        Args:
            key: Configuration key
            value: Value to set
            hint: Optional hint to override automatic classification
            metadata: Optional metadata

        Returns:
            True if successful
        """
        is_secret = self.classify_key(key, hint)

        if is_secret:
            return await self.set_secret(key, value, metadata)
        else:
            return await self.set_parameter(key, value, metadata)

    async def set_secret(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Explicitly set a value in secret storage"""
        try:
            # Try update first, fall back to create
            return await self.secret_manager.update_secret(key, value, metadata)
        except Exception:
            return await self.secret_manager.create_secret(key, value, metadata)

    async def set_parameter(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Explicitly set a value in parameter storage"""
        try:
            # Try update first, fall back to create
            return await self.parameter_manager.update_parameter(key, value, metadata)
        except Exception:
            return await self.parameter_manager.create_parameter(key, value, metadata)

    async def delete(self, key: str, hint: Optional[str] = None) -> bool:
        """
        Delete a configuration value, automatically routing to secrets or parameters

        Args:
            key: Configuration key to delete
            hint: Optional hint to override automatic classification

        Returns:
            True if successful
        """
        is_secret = self.classify_key(key, hint)

        if is_secret:
            return await self.delete_secret(key)
        else:
            return await self.delete_parameter(key)

    async def delete_secret(self, key: str) -> bool:
        """Explicitly delete a value from secret storage"""
        return await self.secret_manager.delete_secret(key)

    async def delete_parameter(self, key: str) -> bool:
        """Explicitly delete a value from parameter storage"""
        return await self.parameter_manager.delete_parameter(key)

    async def list_all_keys(self, prefix: Optional[str] = None) -> Dict[str, List[str]]:
        """
        List all configuration keys from both stores

        Args:
            prefix: Optional prefix to filter by

        Returns:
            Dictionary with 'secrets' and 'parameters' keys containing lists of keys
        """
        result = {'secrets': [], 'parameters': []}

        try:
            result['secrets'] = await self.secret_manager.list_secrets(prefix)
        except Exception as e:
            logger.debug(f"Failed to list secrets: {e}")

        try:
            result['parameters'] = await self.parameter_manager.list_parameters(prefix)
        except Exception as e:
            logger.debug(f"Failed to list parameters: {e}")

        return result

    async def health_check(self) -> Dict[str, bool]:
        """
        Check health of both managers

        Returns:
            Dictionary with health status of each manager
        """
        secret_health = await self.secret_manager.health_check()
        parameter_health = await self.parameter_manager.health_check()

        return {
            'secrets': secret_health,
            'parameters': parameter_health,
            'overall': secret_health and parameter_health
        }

    def get_classification_info(self) -> Dict[str, List[str]]:
        """Get information about classification patterns"""
        return {
            'secret_patterns': self.SECRET_PATTERNS + self.custom_secret_patterns,
            'parameter_patterns': self.PARAMETER_PATTERNS + self.custom_parameter_patterns
        }