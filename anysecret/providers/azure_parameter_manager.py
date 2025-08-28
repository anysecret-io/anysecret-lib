# File: anysecret/providers/azure_parameter_manager.py

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


class AzureAppConfigurationManager(BaseParameterManager):
    """Parameter manager using Azure App Configuration"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

        try:
            from azure.appconfiguration import AzureAppConfigurationClient
            from azure.identity import DefaultAzureCredential
            from azure.core.exceptions import ResourceNotFoundError, HttpResponseError

            self.AzureAppConfigurationClient = AzureAppConfigurationClient
            self.DefaultAzureCredential = DefaultAzureCredential
            self.ResourceNotFoundError = ResourceNotFoundError
            self.HttpResponseError = HttpResponseError
        except ImportError:
            raise ParameterManagerError(
                "azure-appconfiguration and azure-identity are required. "
                "Install with: pip install azure-appconfiguration azure-identity"
            )

        # Configuration options
        self.connection_string = config.get('connection_string')
        self.endpoint = config.get('endpoint')

        if not self.connection_string and not self.endpoint:
            raise ParameterManagerError(
                "Either 'connection_string' or 'endpoint' is required for Azure App Configuration"
            )

        self.label = config.get('label', 'Production')
        self.prefix = config.get('prefix', '')

        try:
            if self.connection_string:
                self.client = self.AzureAppConfigurationClient.from_connection_string(
                    self.connection_string
                )
            else:
                credential = self.DefaultAzureCredential()
                self.client = self.AzureAppConfigurationClient(
                    base_url=self.endpoint,
                    credential=credential
                )
        except Exception as e:
            raise ParameterManagerError(f"Failed to initialize Azure App Configuration client: {e}")

    def _get_full_key(self, key: str) -> str:
        """Get the full configuration key with prefix"""
        if self.prefix:
            return f"{self.prefix.rstrip('/')}/{key.lstrip('/')}"
        return key

    def _strip_prefix(self, full_key: str) -> str:
        """Remove prefix from configuration key"""
        if self.prefix and full_key.startswith(self.prefix):
            stripped = full_key[len(self.prefix):].lstrip('/')
            return stripped
        return full_key

    async def get_parameter_with_metadata(self, key: str) -> ParameterValue:
        """Get a parameter from Azure App Configuration"""
        full_key = self._get_full_key(key)

        try:
            loop = asyncio.get_event_loop()

            # Get the configuration setting
            setting = await loop.run_in_executor(
                None,
                lambda: self.client.get_configuration_setting(
                    key=full_key,
                    label=self.label
                )
            )

            # Parse value based on content type
            value = setting.value

            # Try to parse as JSON if it looks like JSON
            if (isinstance(value, str) and
                    (value.startswith('{') or value.startswith('[')) and
                    setting.content_type == 'application/json'):
                try:
                    value = json.loads(value)
                except json.JSONDecodeError:
                    pass  # Keep as string if not valid JSON

            metadata = {
                'source': 'azure_app_configuration',
                'key': full_key,
                'label': setting.label,
                'content_type': setting.content_type,
                'etag': setting.etag,
                'last_modified': setting.last_modified.isoformat() if setting.last_modified else None,
                'tags': dict(setting.tags) if setting.tags else {},
                'locked': setting.read_only
            }

            return ParameterValue(key, value, metadata)

        except self.ResourceNotFoundError:
            raise ParameterNotFoundError(f"Parameter '{key}' not found in Azure App Configuration")
        except Exception as e:
            if "not found" in str(e).lower() or "404" in str(e):
                raise ParameterNotFoundError(f"Parameter '{key}' not found")
            raise ParameterAccessError(f"Failed to get parameter '{key}': {e}")

    async def list_parameters(self, prefix: Optional[str] = None) -> List[str]:
        """List parameters from Azure App Configuration"""
        try:
            loop = asyncio.get_event_loop()

            # Build key filter
            key_filter = None
            if prefix:
                search_prefix = self._get_full_key(prefix)
                key_filter = f"{search_prefix}*"
            elif self.prefix:
                key_filter = f"{self.prefix}*"

            # List configuration settings
            settings = await loop.run_in_executor(
                None,
                lambda: list(self.client.list_configuration_settings(
                    key_filter=key_filter,
                    label_filter=self.label
                ))
            )

            keys = []
            for setting in settings:
                key = self._strip_prefix(setting.key)
                if prefix and not key.startswith(prefix):
                    continue
                keys.append(key)

            return sorted(keys)

        except Exception as e:
            raise ParameterAccessError(f"Failed to list parameters: {e}")

    async def health_check(self) -> bool:
        """Check if Azure App Configuration is accessible"""
        try:
            loop = asyncio.get_event_loop()

            # Try to list configuration settings (lightweight operation)
            await loop.run_in_executor(
                None,
                lambda: list(self.client.list_configuration_settings(
                    label_filter=self.label,
                    top=1
                ))
            )
            return True
        except Exception as e:
            logger.error(f"Azure App Configuration health check failed: {e}")
            return False

    async def create_parameter(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Create a parameter in Azure App Configuration"""
        self._check_write_allowed()

        full_key = self._get_full_key(key)
        metadata = metadata or {}

        try:
            loop = asyncio.get_event_loop()

            # Check if parameter already exists
            try:
                await loop.run_in_executor(
                    None,
                    lambda: self.client.get_configuration_setting(
                        key=full_key,
                        label=self.label
                    )
                )
                raise ParameterManagerError(f"Parameter '{key}' already exists")
            except self.ResourceNotFoundError:
                pass  # Parameter doesn't exist, good to create

            # Prepare value and content type
            if isinstance(value, (dict, list)):
                value_str = json.dumps(value)
                content_type = 'application/json'
            else:
                value_str = str(value)
                content_type = metadata.get('content_type', 'text/plain')

            # Create configuration setting
            from azure.appconfiguration import ConfigurationSetting
            setting = ConfigurationSetting(
                key=full_key,
                label=self.label,
                value=value_str,
                content_type=content_type,
                tags=metadata.get('tags', {})
            )

            await loop.run_in_executor(
                None,
                lambda: self.client.set_configuration_setting(setting)
            )

            return True

        except Exception as e:
            if "already exists" in str(e).lower():
                raise ParameterManagerError(f"Parameter '{key}' already exists")
            raise ParameterAccessError(f"Failed to create parameter '{key}': {e}")

    async def update_parameter(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Update an existing parameter"""
        self._check_write_allowed()

        full_key = self._get_full_key(key)
        metadata = metadata or {}

        try:
            loop = asyncio.get_event_loop()

            # Prepare value and content type
            if isinstance(value, (dict, list)):
                value_str = json.dumps(value)
                content_type = 'application/json'
            else:
                value_str = str(value)
                content_type = metadata.get('content_type', 'text/plain')

            # Create/update configuration setting
            from azure.appconfiguration import ConfigurationSetting
            setting = ConfigurationSetting(
                key=full_key,
                label=self.label,
                value=value_str,
                content_type=content_type,
                tags=metadata.get('tags', {})
            )

            await loop.run_in_executor(
                None,
                lambda: self.client.set_configuration_setting(setting)
            )

            return True

        except Exception as e:
            raise ParameterAccessError(f"Failed to update parameter '{key}': {e}")

    async def delete_parameter(self, key: str) -> bool:
        """Delete a parameter from Azure App Configuration"""
        self._check_write_allowed()

        full_key = self._get_full_key(key)

        try:
            loop = asyncio.get_event_loop()

            await loop.run_in_executor(
                None,
                lambda: self.client.delete_configuration_setting(
                    key=full_key,
                    label=self.label
                )
            )

            return True

        except self.ResourceNotFoundError:
            raise ParameterNotFoundError(f"Parameter '{key}' not found")
        except Exception as e:
            if "not found" in str(e).lower() or "404" in str(e):
                raise ParameterNotFoundError(f"Parameter '{key}' not found")
            raise ParameterAccessError(f"Failed to delete parameter '{key}': {e}")