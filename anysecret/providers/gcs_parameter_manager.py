# File: anysecret/providers/gcs_parameter_manager.py

"""
Google Cloud Storage-based parameter managers.
Extends file-based providers to use GCS as storage backend.
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


class GCSStorageBackend(CloudStorageParameterManager):
    """GCS storage backend for parameter managers"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        try:
            from google.cloud import storage
            from google.api_core import exceptions as gcp_exceptions
            self.storage = storage
            self.gcp_exceptions = gcp_exceptions
        except ImportError:
            raise ParameterManagerError(
                "google-cloud-storage is required. Install with: pip install google-cloud-storage"
            )
        
        self.project_id = config.get('project_id')
        if not self.project_id:
            raise ParameterManagerError("project_id is required for GCS parameter manager")
        
        self.bucket_name = config.get('bucket_name', f"{self.project_id}-anysecret-parameters")
        self.object_name = config.get('object_name', 'parameters/config.json')
        
        # Initialize GCS client
        self.client = self.storage.Client(project=self.project_id)
        self.bucket = self.client.bucket(self.bucket_name)
        
    async def _download_content(self) -> Tuple[str, Optional[str]]:
        """Download content from GCS with generation number for optimistic locking"""
        loop = asyncio.get_event_loop()
        
        try:
            blob = self.bucket.blob(self.object_name)
            
            # Download content
            content = await loop.run_in_executor(
                None,
                lambda: blob.download_as_text()
            )
            
            # Get generation number (GCS's version of ETag)
            generation = str(blob.generation) if blob.generation else None
            
            return content, generation
            
        except self.gcp_exceptions.NotFound:
            raise FileNotFoundError(f"GCS object {self.object_name} not found")
        except Exception as e:
            raise ParameterAccessError(f"Failed to download from GCS: {e}")
    
    async def _upload_content(self, content: str, etag: Optional[str] = None) -> bool:
        """Upload content to GCS with optional generation number for optimistic locking"""
        loop = asyncio.get_event_loop()
        
        try:
            blob = self.bucket.blob(self.object_name)
            
            # Check for conflicts using generation number
            if etag:
                # Convert etag (generation number) back to int
                try:
                    if_generation_match = int(etag)
                except (ValueError, TypeError):
                    if_generation_match = None
            else:
                if_generation_match = None
            
            # Upload with generation match for optimistic locking
            await loop.run_in_executor(
                None,
                lambda: blob.upload_from_string(
                    content,
                    content_type='application/json',
                    if_generation_match=if_generation_match
                )
            )
            
            return True
            
        except self.gcp_exceptions.PreconditionFailed:
            # Generation number mismatch - conflict
            return False
        except Exception as e:
            if "precondition" in str(e).lower():
                return False  # Conflict
            raise ParameterAccessError(f"Failed to upload to GCS: {e}")
    
    async def _exists(self) -> bool:
        """Check if GCS object exists"""
        loop = asyncio.get_event_loop()
        
        try:
            blob = self.bucket.blob(self.object_name)
            exists = await loop.run_in_executor(None, lambda: blob.exists())
            return exists
        except Exception:
            return False
    
    async def ensure_bucket_exists(self) -> bool:
        """Ensure GCS bucket exists, create if not"""
        loop = asyncio.get_event_loop()
        
        try:
            bucket_exists = await loop.run_in_executor(
                None,
                lambda: self.bucket.exists()
            )
            
            if not bucket_exists:
                logger.info(f"Creating GCS bucket '{self.bucket_name}'...")
                await loop.run_in_executor(
                    None,
                    lambda: self.client.create_bucket(self.bucket_name, location='US')
                )
                logger.info(f"Created GCS bucket '{self.bucket_name}'")
            
            return True
        except Exception as e:
            if "already exists" in str(e).lower():
                return True
            logger.error(f"Failed to ensure bucket exists: {e}")
            return False


class GCSJsonParameterManager(BaseParameterManager):
    """JSON parameter manager using GCS storage"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # Update config with appropriate object name
        config['object_name'] = config.get('object_name', 'parameters/config.json')
        self.storage = GCSStorageBackend(config)
    
    async def get_parameter_with_metadata(self, key: str) -> ParameterValue:
        """Get a parameter from GCS-stored JSON"""
        try:
            # Read all parameters from GCS
            parameters = await self.storage.read_content()
            
            if key not in parameters:
                raise ParameterNotFoundError(f"Parameter '{key}' not found")
            
            value = parameters[key]
            
            metadata = {
                'source': 'gcs_json_parameter_manager',
                'bucket': self.storage.bucket_name,
                'object_name': self.storage.object_name,
                'project_id': self.storage.project_id
            }
            
            return ParameterValue(key, value, metadata)
            
        except FileNotFoundError:
            raise ParameterNotFoundError(f"Parameter '{key}' not found")
        except Exception as e:
            raise ParameterAccessError(f"Failed to get parameter '{key}': {e}")
    
    async def list_parameters(self, prefix: Optional[str] = None) -> List[str]:
        """List all parameters from GCS-stored JSON"""
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
        """Create a parameter in GCS-stored JSON"""
        self._check_write_allowed()
        
        try:
            # Read current parameters
            parameters = await self.storage.read_content()
            
            if key in parameters:
                raise ParameterManagerError(f"Parameter '{key}' already exists")
            
            # Add new parameter
            parameters[key] = value
            
            # Write back to GCS
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
        """Update a parameter in GCS-stored JSON"""
        self._check_write_allowed()
        
        try:
            # Read current parameters
            parameters = await self.storage.read_content()
            
            if key not in parameters:
                raise ParameterNotFoundError(f"Parameter '{key}' not found")
            
            # Update parameter
            parameters[key] = value
            
            # Write back to GCS
            success = await self.storage.write_content(parameters)
            
            if not success:
                raise ParameterManagerError("Failed to write due to conflict")
            
            return True
            
        except ParameterNotFoundError:
            raise
        except Exception as e:
            raise ParameterAccessError(f"Failed to update parameter '{key}': {e}")
    
    async def delete_parameter(self, key: str) -> bool:
        """Delete a parameter from GCS-stored JSON"""
        self._check_write_allowed()
        
        try:
            # Read current parameters
            parameters = await self.storage.read_content()
            
            if key not in parameters:
                raise ParameterNotFoundError(f"Parameter '{key}' not found")
            
            # Remove parameter
            del parameters[key]
            
            # Write back to GCS
            success = await self.storage.write_content(parameters)
            
            if not success:
                raise ParameterManagerError("Failed to write due to conflict")
            
            return True
            
        except ParameterNotFoundError:
            raise
        except Exception as e:
            raise ParameterAccessError(f"Failed to delete parameter '{key}': {e}")
    
    async def health_check(self) -> bool:
        """Check if GCS is accessible and ensure bucket exists"""
        try:
            # Ensure bucket exists (auto-create if needed)
            return await self.storage.ensure_bucket_exists()
        except Exception as e:
            logger.error(f"GCS health check failed: {e}")
            return False


# Aliases for different formats
class GCSEnvParameterManager(GCSJsonParameterManager):
    """ENV format parameter manager using GCS storage"""
    
    def __init__(self, config: Dict[str, Any]):
        config['object_name'] = config.get('object_name', 'parameters/config.env')
        super().__init__(config)
        # TODO: Override parse/serialize for .env format


class GCSYamlParameterManager(GCSJsonParameterManager):
    """YAML format parameter manager using GCS storage"""
    
    def __init__(self, config: Dict[str, Any]):
        config['object_name'] = config.get('object_name', 'parameters/config.yaml')
        super().__init__(config)
        # TODO: Override parse/serialize for YAML format


# Keep the old individual parameter storage for backward compatibility
GcpParameterManagerClient = GCSJsonParameterManager
GcpConfigConnectorManager = GCSJsonParameterManager