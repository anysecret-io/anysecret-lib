# File: anysecret/providers/azure_blob_parameter_manager.py

"""
Azure Blob Storage-based parameter managers.
Extends file-based providers to use Azure Blob as storage backend.
"""

import asyncio
import json
from typing import Any, Dict, List, Optional, Tuple
import logging

from ..parameter_manager import (
    BaseParameterManager,
    ParameterValue,
    ParameterNotFoundError,
    ParameterAccessError,
    ParameterManagerError
)
from .cloud_storage_base import CloudStorageParameterManager

logger = logging.getLogger(__name__)


class AzureBlobStorageBackend(CloudStorageParameterManager):
    """Azure Blob Storage backend for parameter managers"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        try:
            from azure.storage.blob import BlobServiceClient
            from azure.core.exceptions import ResourceNotFoundError, ResourceExistsError
            self.BlobServiceClient = BlobServiceClient
            self.ResourceNotFoundError = ResourceNotFoundError
            self.ResourceExistsError = ResourceExistsError
        except ImportError:
            raise ParameterManagerError(
                "azure-storage-blob is required. Install with: pip install azure-storage-blob"
            )
        
        self.account_name = config.get('account_name')
        self.account_key = config.get('account_key')
        self.connection_string = config.get('connection_string')
        
        if not any([self.connection_string, self.account_name]):
            raise ParameterManagerError(
                "Either connection_string or account_name is required for Azure Blob parameter manager"
            )
        
        self.container_name = config.get('container_name', 'anysecret-parameters')
        self.blob_name = config.get('blob_name', 'parameters/config.json')
        
        # Initialize Azure Blob client
        if self.connection_string:
            self.blob_service_client = self.BlobServiceClient.from_connection_string(
                self.connection_string
            )
        else:
            account_url = f"https://{self.account_name}.blob.core.windows.net"
            self.blob_service_client = self.BlobServiceClient(
                account_url=account_url,
                credential=self.account_key
            )
        
        self.blob_client = self.blob_service_client.get_blob_client(
            container=self.container_name,
            blob=self.blob_name
        )
        
    async def _download_content(self) -> Tuple[str, Optional[str]]:
        """Download content from Azure Blob with ETag"""
        loop = asyncio.get_event_loop()
        
        try:
            # Download blob properties and content
            blob_data = await loop.run_in_executor(
                None,
                lambda: self.blob_client.download_blob()
            )
            
            content = blob_data.readall().decode('utf-8')
            etag = blob_data.properties.etag.strip('"') if blob_data.properties.etag else None
            
            return content, etag
            
        except self.ResourceNotFoundError:
            raise FileNotFoundError(f"Azure blob {self.blob_name} not found")
        except Exception as e:
            raise ParameterAccessError(f"Failed to download from Azure Blob: {e}")
    
    async def _upload_content(self, content: str, etag: Optional[str] = None) -> bool:
        """Upload content to Azure Blob with optional ETag for optimistic locking"""
        loop = asyncio.get_event_loop()
        
        try:
            upload_kwargs = {
                'data': content.encode('utf-8'),
                'content_type': 'application/json',
                'overwrite': True
            }
            
            # Add ETag condition if provided (for optimistic locking)
            if etag:
                upload_kwargs['etag'] = f'"{etag}"'  # Azure expects quoted ETags
                upload_kwargs['match_condition'] = 'IfMatch'
                upload_kwargs['overwrite'] = False
            
            # Upload the content
            await loop.run_in_executor(
                None,
                lambda: self.blob_client.upload_blob(**upload_kwargs)
            )
            
            return True
            
        except self.ResourceExistsError:
            # ETag mismatch or conflict
            return False
        except Exception as e:
            if "precondition" in str(e).lower() or "etag" in str(e).lower():
                return False  # Conflict
            raise ParameterAccessError(f"Failed to upload to Azure Blob: {e}")
    
    async def _exists(self) -> bool:
        """Check if Azure Blob exists"""
        loop = asyncio.get_event_loop()
        
        try:
            await loop.run_in_executor(
                None,
                lambda: self.blob_client.get_blob_properties()
            )
            return True
        except self.ResourceNotFoundError:
            return False
        except Exception:
            return False
    
    async def ensure_container_exists(self) -> bool:
        """Ensure Azure Blob container exists, create if not"""
        loop = asyncio.get_event_loop()
        
        try:
            container_client = self.blob_service_client.get_container_client(
                self.container_name
            )
            
            await loop.run_in_executor(
                None,
                lambda: container_client.create_container()
            )
            
            logger.info(f"Created Azure container '{self.container_name}'")
            return True
            
        except self.ResourceExistsError:
            # Container already exists
            return True
        except Exception as e:
            logger.error(f"Failed to ensure container exists: {e}")
            return False


class AzureBlobJsonParameterManager(BaseParameterManager):
    """JSON parameter manager using Azure Blob Storage"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # Update config with appropriate blob name
        config['blob_name'] = config.get('blob_name', 'parameters/config.json')
        self.storage = AzureBlobStorageBackend(config)
    
    async def get_parameter_with_metadata(self, key: str) -> ParameterValue:
        """Get a parameter from Azure Blob-stored JSON"""
        try:
            # Read all parameters from Azure Blob
            parameters = await self.storage.read_content()
            
            if key not in parameters:
                raise ParameterNotFoundError(f"Parameter '{key}' not found")
            
            value = parameters[key]
            
            metadata = {
                'source': 'azure_blob_json_parameter_manager',
                'account_name': self.storage.account_name,
                'container_name': self.storage.container_name,
                'blob_name': self.storage.blob_name
            }
            
            return ParameterValue(key, value, metadata)
            
        except FileNotFoundError:
            raise ParameterNotFoundError(f"Parameter '{key}' not found")
        except Exception as e:
            raise ParameterAccessError(f"Failed to get parameter '{key}': {e}")
    
    async def list_parameters(self, prefix: Optional[str] = None) -> List[str]:
        """List all parameters from Azure Blob-stored JSON"""
        try:
            parameters = await self.storage.read_content()
            
            keys = list(parameters.keys())
            
            if prefix:
                keys = [k for k in keys if k.startswith(prefix)]
            
            return sorted(keys)
            
        except FileNotFoundError:
            return []
        except Exception as e:
            raise ParameterAccessError(f"Failed to list parameters: {e}")
    
    async def create_parameter(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Create a parameter in Azure Blob-stored JSON"""
        self._check_write_allowed()
        
        try:
            # Read current parameters
            parameters = await self.storage.read_content()
            
            if key in parameters:
                raise ParameterManagerError(f"Parameter '{key}' already exists")
            
            # Add new parameter
            parameters[key] = value
            
            # Write back to Azure Blob
            success = await self.storage.write_content(parameters)
            
            if not success:
                raise ParameterManagerError("Failed to write due to conflict")
            
            return True
            
        except FileNotFoundError:
            # First parameter - create new file
            parameters = {key: value}
            return await self.storage.write_content(parameters)
        except ParameterManagerError:
            raise
        except Exception as e:
            raise ParameterAccessError(f"Failed to create parameter '{key}': {e}")
    
    async def update_parameter(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Update a parameter in Azure Blob-stored JSON"""
        self._check_write_allowed()
        
        try:
            # Read current parameters
            parameters = await self.storage.read_content()
            
            if key not in parameters:
                raise ParameterNotFoundError(f"Parameter '{key}' not found")
            
            # Update parameter
            parameters[key] = value
            
            # Write back to Azure Blob
            success = await self.storage.write_content(parameters)
            
            if not success:
                raise ParameterManagerError("Failed to write due to conflict")
            
            return True
            
        except ParameterNotFoundError:
            raise
        except Exception as e:
            raise ParameterAccessError(f"Failed to update parameter '{key}': {e}")
    
    async def delete_parameter(self, key: str) -> bool:
        """Delete a parameter from Azure Blob-stored JSON"""
        self._check_write_allowed()
        
        try:
            # Read current parameters
            parameters = await self.storage.read_content()
            
            if key not in parameters:
                raise ParameterNotFoundError(f"Parameter '{key}' not found")
            
            # Remove parameter
            del parameters[key]
            
            # Write back to Azure Blob
            success = await self.storage.write_content(parameters)
            
            if not success:
                raise ParameterManagerError("Failed to write due to conflict")
            
            return True
            
        except ParameterNotFoundError:
            raise
        except Exception as e:
            raise ParameterAccessError(f"Failed to delete parameter '{key}': {e}")
    
    async def health_check(self) -> bool:
        """Check if Azure Blob is accessible and ensure container exists"""
        try:
            # Ensure container exists (auto-create if needed)
            return await self.storage.ensure_container_exists()
        except Exception as e:
            logger.error(f"Azure Blob health check failed: {e}")
            return False


# Aliases for different formats
class AzureBlobEnvParameterManager(AzureBlobJsonParameterManager):
    """ENV format parameter manager using Azure Blob Storage"""
    
    def __init__(self, config: Dict[str, Any]):
        config['blob_name'] = config.get('blob_name', 'parameters/config.env')
        super().__init__(config)
        # TODO: Override parse/serialize for .env format


class AzureBlobYamlParameterManager(AzureBlobJsonParameterManager):
    """YAML format parameter manager using Azure Blob Storage"""
    
    def __init__(self, config: Dict[str, Any]):
        config['blob_name'] = config.get('blob_name', 'parameters/config.yaml')
        super().__init__(config)
        # TODO: Override parse/serialize for YAML format