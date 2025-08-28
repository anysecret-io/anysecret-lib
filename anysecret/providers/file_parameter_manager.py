# File: anysecret/providers/file_parameter_manager.py

import json
import os
import aiofiles
from pathlib import Path
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


class FileJsonParameterManager(BaseParameterManager):
    """Parameter manager for JSON configuration files"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.file_path = Path(config.get('file_path', 'parameters.json'))
        self.encoding = config.get('encoding', 'utf-8')
        self._cache = None
        self._cache_timestamp = None

    async def _load_parameters(self, force_reload: bool = False) -> Dict[str, Any]:
        """Load parameters from JSON file with caching"""
        try:
            if not self.file_path.exists():
                return {}

            file_mtime = self.file_path.stat().st_mtime

            # Use cache if valid and not forcing reload
            if (not force_reload and
                    self._cache is not None and
                    self._cache_timestamp == file_mtime):
                return self._cache

            async with aiofiles.open(self.file_path, 'r', encoding=self.encoding) as f:
                content = await f.read()
                parameters = json.loads(content)

            # Update cache
            self._cache = parameters
            self._cache_timestamp = file_mtime

            return parameters

        except FileNotFoundError:
            return {}
        except json.JSONDecodeError as e:
            raise ParameterAccessError(f"Invalid JSON in {self.file_path}: {e}")
        except Exception as e:
            raise ParameterAccessError(f"Failed to load parameters from {self.file_path}: {e}")

    async def _save_parameters(self, parameters: Dict[str, Any]):
        """Save parameters to JSON file"""
        try:
            # Ensure directory exists
            self.file_path.parent.mkdir(parents=True, exist_ok=True)

            async with aiofiles.open(self.file_path, 'w', encoding=self.encoding) as f:
                await f.write(json.dumps(parameters, indent=2, sort_keys=True))

            # Clear cache to force reload next time
            self._cache = None
            self._cache_timestamp = None

        except Exception as e:
            raise ParameterAccessError(f"Failed to save parameters to {self.file_path}: {e}")

    def _get_nested_value(self, data: Dict[str, Any], key: str) -> Any:
        """Get value from nested dictionary using dot notation"""
        if '.' not in key:
            if key not in data:
                raise KeyError(f"Key '{key}' not found")
            return data[key]

        keys = key.split('.')
        current = data

        for k in keys:
            if not isinstance(current, dict) or k not in current:
                raise KeyError(f"Key '{key}' not found")
            current = current[k]

        return current

    def _set_nested_value(self, data: Dict[str, Any], key: str, value: Any):
        """Set value in nested dictionary using dot notation"""
        if '.' not in key:
            data[key] = value
            return

        keys = key.split('.')
        current = data

        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            elif not isinstance(current[k], dict):
                current[k] = {}
            current = current[k]

        current[keys[-1]] = value

    def _delete_nested_value(self, data: Dict[str, Any], key: str):
        """Delete value from nested dictionary using dot notation"""
        if '.' not in key:
            if key in data:
                del data[key]
            return

        keys = key.split('.')
        current = data

        for k in keys[:-1]:
            if not isinstance(current, dict) or k not in current:
                return  # Key doesn't exist, nothing to delete
            current = current[k]

        if isinstance(current, dict) and keys[-1] in current:
            del current[keys[-1]]

    async def get_parameter_with_metadata(self, key: str) -> ParameterValue:
        """Get a parameter with metadata"""
        parameters = await self._load_parameters()

        try:
            value = self._get_nested_value(parameters, key)
            metadata = {
                'source': str(self.file_path),
                'type': 'json_file',
                'key': key
            }
            return ParameterValue(key, value, metadata)
        except KeyError:
            raise ParameterNotFoundError(f"Parameter '{key}' not found in {self.file_path}")


    async def list_parameters(self, prefix: Optional[str] = None) -> List[str]:
        """List available parameter keys"""
        parameters = await self._load_parameters()

        def _extract_keys(data: Dict[str, Any], parent_key: str = '') -> List[str]:
            keys = []
            for k, v in data.items():
                full_key = f"{parent_key}.{k}" if parent_key else k

                if isinstance(v, dict):
                    # Recursively get nested keys
                    keys.extend(_extract_keys(v, full_key))
                else:
                    keys.append(full_key)

            return keys

        all_keys = _extract_keys(parameters)

        if prefix:
            return [key for key in all_keys if key.startswith(prefix)]
        return all_keys

    async def health_check(self) -> bool:
        """Check if the parameter manager is healthy"""
        try:
            # Try to load parameters (will create empty file if needed)
            await self._load_parameters()
            return True
        except Exception as e:
            logger.error(f"File parameter manager health check failed: {e}")
            return False

    async def create_parameter(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Create a new parameter"""
        self._check_write_allowed()

        parameters = await self._load_parameters()

        # Check if key already exists
        try:
            self._get_nested_value(parameters, key)
            raise ParameterManagerError(f"Parameter '{key}' already exists")
        except KeyError:
            pass  # Key doesn't exist, good to create

        self._set_nested_value(parameters, key, value)
        await self._save_parameters(parameters)
        return True

    async def update_parameter(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Update an existing parameter"""
        self._check_write_allowed()

        parameters = await self._load_parameters()
        self._set_nested_value(parameters, key, value)
        await self._save_parameters(parameters)
        return True

    async def delete_parameter(self, key: str) -> bool:
        """Delete a parameter"""
        self._check_write_allowed()

        parameters = await self._load_parameters()

        # Check if key exists
        try:
            self._get_nested_value(parameters, key)
        except KeyError:
            raise ParameterNotFoundError(f"Parameter '{key}' not found")

        self._delete_nested_value(parameters, key)
        await self._save_parameters(parameters)
        return True


class FileYamlParameterManager(FileJsonParameterManager):
    """Parameter manager for YAML configuration files"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.file_path = Path(config.get('file_path', 'parameters.yaml'))

        # Check for YAML dependency
        try:
            import yaml
            self.yaml = yaml
        except ImportError:
            raise ParameterManagerError(
                "PyYAML is required for YAML parameter manager. Install with: pip install PyYAML")

    async def _load_parameters(self, force_reload: bool = False) -> Dict[str, Any]:
        """Load parameters from YAML file with caching"""
        try:
            if not self.file_path.exists():
                return {}

            file_mtime = self.file_path.stat().st_mtime

            # Use cache if valid and not forcing reload
            if (not force_reload and
                    self._cache is not None and
                    self._cache_timestamp == file_mtime):
                return self._cache

            async with aiofiles.open(self.file_path, 'r', encoding=self.encoding) as f:
                content = await f.read()
                parameters = self.yaml.safe_load(content) or {}

            # Update cache
            self._cache = parameters
            self._cache_timestamp = file_mtime

            return parameters

        except FileNotFoundError:
            return {}
        except self.yaml.YAMLError as e:
            raise ParameterAccessError(f"Invalid YAML in {self.file_path}: {e}")
        except Exception as e:
            raise ParameterAccessError(f"Failed to load parameters from {self.file_path}: {e}")

    async def _save_parameters(self, parameters: Dict[str, Any]):
        """Save parameters to YAML file"""
        try:
            # Ensure directory exists
            self.file_path.parent.mkdir(parents=True, exist_ok=True)

            async with aiofiles.open(self.file_path, 'w', encoding=self.encoding) as f:
                yaml_content = self.yaml.dump(parameters, default_flow_style=False, sort_keys=True)
                await f.write(yaml_content)

            # Clear cache to force reload next time
            self._cache = None
            self._cache_timestamp = None

        except Exception as e:
            raise ParameterAccessError(f"Failed to save parameters to {self.file_path}: {e}")

    async def get_parameter_with_metadata(self, key: str) -> ParameterValue:
        """Get a parameter with metadata"""
        parameters = await self._load_parameters()

        try:
            value = self._get_nested_value(parameters, key)
            metadata = {
                'source': str(self.file_path),
                'type': 'yaml_file',
                'key': key
            }
            return ParameterValue(key, value, metadata)
        except KeyError:
            raise ParameterNotFoundError(f"Parameter '{key}' not found in {self.file_path}")