# File: anysecret/providers/aws_parameter_manager.py

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


class AwsParameterStoreManager(BaseParameterManager):
    """Parameter manager for AWS Systems Manager Parameter Store"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

        # Check for boto3 dependency
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
            self.boto3 = boto3
            self.ClientError = ClientError
            self.NoCredentialsError = NoCredentialsError
        except ImportError:
            raise ParameterManagerError("boto3 is required for AWS Parameter Store. Install with: pip install boto3")

        self.region = config.get('region', 'us-east-1')
        self.prefix = config.get('prefix', '')  # Optional prefix for all parameters
        self.kms_key_id = config.get('kms_key_id')  # For SecureString parameters

        # Initialize SSM client
        try:
            session_config = {}
            if 'aws_access_key_id' in config:
                session_config['aws_access_key_id'] = config['aws_access_key_id']
            if 'aws_secret_access_key' in config:
                session_config['aws_secret_access_key'] = config['aws_secret_access_key']
            if 'aws_session_token' in config:
                session_config['aws_session_token'] = config['aws_session_token']

            self.session = self.boto3.Session(**session_config)
            self.ssm_client = self.session.client('ssm', region_name=self.region)

        except Exception as e:
            raise ParameterManagerError(f"Failed to initialize AWS SSM client: {e}")

    def _get_full_key(self, key: str) -> str:
        """Get the full parameter name with prefix"""
        if self.prefix:
            return f"{self.prefix.rstrip('/')}/{key.lstrip('/')}"
        return key

    def _strip_prefix(self, full_key: str) -> str:
        """Remove prefix from parameter name"""
        if self.prefix and full_key.startswith(self.prefix):
            stripped = full_key[len(self.prefix):].lstrip('/')
            return stripped
        return full_key

    async def get_parameter_with_metadata(self, key: str) -> ParameterValue:
        """Get a parameter with metadata from Parameter Store"""
        full_key = self._get_full_key(key)

        try:
            # Run boto3 call in thread pool since it's not async
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.ssm_client.get_parameter(
                    Name=full_key,
                    WithDecryption=True  # Decrypt SecureString parameters
                )
            )

            parameter = response['Parameter']

            # Parse value based on type
            value = parameter['Value']
            param_type = parameter.get('Type', 'String')

            # Try to parse JSON for structured data
            if param_type == 'StringList':
                value = value.split(',')
            elif value.startswith('{') or value.startswith('['):
                try:
                    value = json.loads(value)
                except json.JSONDecodeError:
                    pass  # Keep as string if not valid JSON

            metadata = {
                'source': 'aws_parameter_store',
                'region': self.region,
                'type': param_type,
                'version': parameter.get('Version'),
                'last_modified': parameter.get('LastModifiedDate').isoformat() if parameter.get(
                    'LastModifiedDate') else None,
                'arn': parameter.get('ARN'),
                'data_type': parameter.get('DataType', 'text')
            }

            return ParameterValue(key, value, metadata)

        except self.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ParameterNotFound':
                raise ParameterNotFoundError(f"Parameter '{key}' not found in AWS Parameter Store")
            else:
                raise ParameterAccessError(f"AWS Parameter Store error: {e.response['Error']['Message']}")
        except Exception as e:
            raise ParameterAccessError(f"Failed to get parameter '{key}': {e}")

    async def list_parameters(self, prefix: Optional[str] = None) -> List[str]:
        """List available parameter keys"""
        try:
            loop = asyncio.get_event_loop()
            paginator = self.ssm_client.get_paginator('describe_parameters')

            # Build filters
            filters = []
            search_prefix = self._get_full_key(prefix) if prefix else self.prefix

            if search_prefix:
                filters.append({
                    'Key': 'Name',
                    'Option': 'BeginsWith',
                    'Values': [search_prefix]
                })

            parameters = []
            page_iterator = paginator.paginate(
                Filters=filters,
                MaxItems=1000  # Reasonable limit
            )

            for page in page_iterator:
                for param in page.get('Parameters', []):
                    param_name = self._strip_prefix(param['Name'])
                    parameters.append(param_name)

            return sorted(parameters)

        except Exception as e:
            raise ParameterAccessError(f"Failed to list parameters: {e}")

    async def health_check(self) -> bool:
        """Check if the parameter manager is healthy"""
        try:
            loop = asyncio.get_event_loop()
            # Try to describe parameters (lightweight operation)
            await loop.run_in_executor(
                None,
                lambda: self.ssm_client.describe_parameters(MaxResults=1)
            )
            return True
        except Exception as e:
            logger.error(f"AWS Parameter Store health check failed: {e}")
            return False

    async def create_parameter(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Create a new parameter in Parameter Store"""
        self._check_write_allowed()

        full_key = self._get_full_key(key)
        metadata = metadata or {}

        # Determine parameter type and value
        param_value = value
        param_type = metadata.get('type', 'String')

        if isinstance(value, (list, dict)):
            param_value = json.dumps(value)
            param_type = 'String'  # Store complex types as JSON strings
        elif isinstance(value, list) and all(isinstance(x, str) for x in value):
            param_value = ','.join(value)
            param_type = 'StringList'
        elif isinstance(value, str):
            # Check if this should be a SecureString (for sensitive non-secret data)
            if metadata.get('secure', False) or any(keyword in key.lower()
                                                    for keyword in ['password', 'key', 'token']):
                param_type = 'SecureString'

        try:
            loop = asyncio.get_event_loop()

            put_params = {
                'Name': full_key,
                'Value': str(param_value),
                'Type': param_type,
                'Overwrite': False,  # Fail if parameter already exists
                'Tags': [
                    {'Key': 'ManagedBy', 'Value': 'anysecret'},
                    {'Key': 'CreatedAt', 'Value': str(asyncio.get_event_loop().time())}
                ]
            }

            # Add KMS key for SecureString parameters
            if param_type == 'SecureString' and self.kms_key_id:
                put_params['KeyId'] = self.kms_key_id

            # Add description from metadata
            if 'description' in metadata:
                put_params['Description'] = metadata['description']

            await loop.run_in_executor(
                None,
                lambda: self.ssm_client.put_parameter(**put_params)
            )

            return True

        except self.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ParameterAlreadyExists':
                raise ParameterManagerError(f"Parameter '{key}' already exists")
            else:
                raise ParameterAccessError(f"Failed to create parameter: {e.response['Error']['Message']}")
        except Exception as e:
            raise ParameterAccessError(f"Failed to create parameter '{key}': {e}")

    async def update_parameter(self, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Update an existing parameter"""
        self._check_write_allowed()

        full_key = self._get_full_key(key)
        metadata = metadata or {}

        # Get current parameter to determine type
        try:
            current_param = await self.get_parameter_with_metadata(key)
            param_type = current_param.metadata.get('type', 'String')
        except ParameterNotFoundError:
            # Parameter doesn't exist, create it
            return await self.create_parameter(key, value, metadata)

        # Prepare value
        param_value = value
        if isinstance(value, (list, dict)):
            param_value = json.dumps(value)
        elif isinstance(value, list) and all(isinstance(x, str) for x in value):
            param_value = ','.join(value)

        try:
            loop = asyncio.get_event_loop()

            put_params = {
                'Name': full_key,
                'Value': str(param_value),
                'Type': param_type,
                'Overwrite': True
            }

            # Add KMS key for SecureString parameters
            if param_type == 'SecureString' and self.kms_key_id:
                put_params['KeyId'] = self.kms_key_id

            # Add description from metadata
            if 'description' in metadata:
                put_params['Description'] = metadata['description']

            await loop.run_in_executor(
                None,
                lambda: self.ssm_client.put_parameter(**put_params)
            )

            return True

        except self.ClientError as e:
            raise ParameterAccessError(f"Failed to update parameter: {e.response['Error']['Message']}")
        except Exception as e:
            raise ParameterAccessError(f"Failed to update parameter '{key}': {e}")

    async def delete_parameter(self, key: str) -> bool:
        """Delete a parameter"""
        self._check_write_allowed()

        full_key = self._get_full_key(key)

        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.ssm_client.delete_parameter(Name=full_key)
            )
            return True

        except self.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ParameterNotFound':
                raise ParameterNotFoundError(f"Parameter '{key}' not found")
            else:
                raise ParameterAccessError(f"Failed to delete parameter: {e.response['Error']['Message']}")
        except Exception as e:
            raise ParameterAccessError(f"Failed to delete parameter '{key}': {e}")