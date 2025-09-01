# File: anysecret/providers/aws_s3_parameter_manager.py

"""
AWS S3-based parameter managers.
Extends file-based providers to use S3 as storage backend.
"""

import asyncio
import json
import os
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


class S3StorageBackend(CloudStorageParameterManager):
    """S3 storage backend for parameter managers"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
            self.boto3 = boto3
            self.ClientError = ClientError
            self.NoCredentialsError = NoCredentialsError
        except ImportError:
            raise ParameterManagerError(
                "boto3 is required for S3 parameter manager. Install with: pip install boto3"
            )
        
        self.bucket_name = config.get('bucket_name')
        if not self.bucket_name:
            raise ParameterManagerError("bucket_name is required for S3 parameter manager")
        
        self.object_key = config.get('object_key', 'parameters/config.json')
        self.region = config.get('region', 'us-east-1')
        
        # Initialize S3 client
        self.s3_client = self.boto3.client('s3', region_name=self.region)
        
    async def _download_content(self) -> Tuple[str, Optional[str]]:
        """Download content from S3 with ETag"""
        loop = asyncio.get_event_loop()
        
        try:
            response = await loop.run_in_executor(
                None,
                lambda: self.s3_client.get_object(
                    Bucket=self.bucket_name,
                    Key=self.object_key
                )
            )
            
            content = response['Body'].read().decode('utf-8')
            etag = response.get('ETag', '').strip('"')  # Remove quotes from ETag
            
            return content, etag
            
        except self.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                raise FileNotFoundError(f"S3 object {self.object_key} not found")
            raise ParameterAccessError(f"Failed to download from S3: {e}")
    
    async def _upload_content(self, content: str, etag: Optional[str] = None) -> bool:
        """Upload content to S3 with optional ETag for optimistic locking"""
        loop = asyncio.get_event_loop()
        
        try:
            # Prepare put arguments
            put_args = {
                'Bucket': self.bucket_name,
                'Key': self.object_key,
                'Body': content.encode('utf-8'),
                'ContentType': 'application/json'
            }
            
            # Add ETag condition if provided (for optimistic locking)
            if etag:
                # Use If-Match for update (object must exist with this ETag)
                put_args['Metadata'] = {'previous-etag': etag}
                
                # First check if object exists and matches ETag
                try:
                    head_response = await loop.run_in_executor(
                        None,
                        lambda: self.s3_client.head_object(
                            Bucket=self.bucket_name,
                            Key=self.object_key,
                            IfMatch=etag
                        )
                    )
                except self.ClientError as e:
                    if e.response['Error']['Code'] in ['PreconditionFailed', '412']:
                        # ETag mismatch - conflict
                        return False
                    elif e.response['Error']['Code'] == '404':
                        # Object doesn't exist, remove ETag condition
                        pass
                    else:
                        raise
            
            # Upload the content
            await loop.run_in_executor(
                None,
                lambda: self.s3_client.put_object(**put_args)
            )
            
            return True
            
        except self.ClientError as e:
            if e.response['Error']['Code'] in ['PreconditionFailed', '412']:
                return False  # Conflict
            raise ParameterAccessError(f"Failed to upload to S3: {e}")
    
    async def _exists(self) -> bool:
        """Check if S3 object exists"""
        loop = asyncio.get_event_loop()
        
        try:
            await loop.run_in_executor(
                None,
                lambda: self.s3_client.head_object(
                    Bucket=self.bucket_name,
                    Key=self.object_key
                )
            )
            return True
        except self.ClientError:
            return False


class S3JsonParameterManager(BaseParameterManager):
    """JSON parameter manager using S3 storage"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # Update config with appropriate object key
        config['object_key'] = config.get('object_key', 'parameters/config.json')
        self.storage = S3StorageBackend(config)
        self._parameters_cache = {}
    
    async def get_parameter_with_metadata(self, key: str) -> ParameterValue:
        """Get a parameter from S3-stored JSON"""
        try:
            # Read all parameters from S3
            parameters = await self.storage.read_content()
            
            if key not in parameters:
                raise ParameterNotFoundError(f"Parameter '{key}' not found")
            
            value = parameters[key]
            
            metadata = {
                'source': 's3_json_parameter_manager',
                'bucket': self.storage.bucket_name,
                'object_key': self.storage.object_key,
                'region': self.storage.region
            }
            
            return ParameterValue(key, value, metadata)
            
        except FileNotFoundError:
            raise ParameterNotFoundError(f"Parameter '{key}' not found")
        except Exception as e:
            raise ParameterAccessError(f"Failed to get parameter '{key}': {e}")
    
    async def list_parameters(self, prefix: Optional[str] = None) -> List[str]:
        """List all parameters from S3-stored JSON"""
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
        """Create a parameter in S3-stored JSON"""
        self._check_write_allowed()
        
        try:
            # Read current parameters
            parameters = await self.storage.read_content()
            
            if key in parameters:
                raise ParameterManagerError(f"Parameter '{key}' already exists")
            
            # Add new parameter
            parameters[key] = value
            
            # Write back to S3
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
        """Update a parameter in S3-stored JSON"""
        self._check_write_allowed()
        
        try:
            # Read current parameters
            parameters = await self.storage.read_content()
            
            if key not in parameters:
                raise ParameterNotFoundError(f"Parameter '{key}' not found")
            
            # Update parameter
            parameters[key] = value
            
            # Write back to S3
            success = await self.storage.write_content(parameters)
            
            if not success:
                raise ParameterManagerError("Failed to write due to conflict")
            
            return True
            
        except ParameterNotFoundError:
            raise
        except Exception as e:
            raise ParameterAccessError(f"Failed to update parameter '{key}': {e}")
    
    async def delete_parameter(self, key: str) -> bool:
        """Delete a parameter from S3-stored JSON"""
        self._check_write_allowed()
        
        try:
            # Read current parameters
            parameters = await self.storage.read_content()
            
            if key not in parameters:
                raise ParameterNotFoundError(f"Parameter '{key}' not found")
            
            # Remove parameter
            del parameters[key]
            
            # Write back to S3
            success = await self.storage.write_content(parameters)
            
            if not success:
                raise ParameterManagerError("Failed to write due to conflict")
            
            return True
            
        except ParameterNotFoundError:
            raise
        except Exception as e:
            raise ParameterAccessError(f"Failed to delete parameter '{key}': {e}")
    
    async def health_check(self) -> bool:
        """Check if S3 is accessible"""
        try:
            # Try to check if bucket is accessible
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.storage.s3_client.head_bucket(Bucket=self.storage.bucket_name)
            )
            return True
        except Exception as e:
            logger.error(f"S3 health check failed: {e}")
            return False


# Aliases for different formats (can extend later for .env, .yaml, encrypted)
class S3EnvParameterManager(S3JsonParameterManager):
    """ENV format parameter manager using S3 storage"""
    
    def __init__(self, config: Dict[str, Any]):
        config['object_key'] = config.get('object_key', 'parameters/config.env')
        super().__init__(config)
        # TODO: Override parse/serialize for .env format


class S3YamlParameterManager(S3JsonParameterManager):
    """YAML format parameter manager using S3 storage"""
    
    def __init__(self, config: Dict[str, Any]):
        config['object_key'] = config.get('object_key', 'parameters/config.yaml')
        super().__init__(config)
        # TODO: Override parse/serialize for YAML format