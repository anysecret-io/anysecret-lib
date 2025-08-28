"""
AWS Secrets Manager implementation
"""
import asyncio
import json
from typing import Dict, List, Optional, Any
import logging
from datetime import datetime

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
    HAS_AWS = True
except ImportError:
    HAS_AWS = False

from ..secret_manager import (
    BaseSecretManager,
    SecretValue,
    SecretNotFoundException,
    SecretManagerException,
    SecretManagerConnectionException
)

logger = logging.getLogger(__name__)


class AwsSecretManager(BaseSecretManager):
    """AWS Secrets Manager implementation"""

    def __init__(self, config: Dict[str, Any]):
        if not HAS_AWS:
            raise SecretManagerException(
                "AWS Secrets Manager requires 'boto3' package. "
                "Install with: pip install boto3"
            )

        super().__init__(config)

        self.region_name = config.get('region_name', 'us-east-1')
        self.aws_access_key_id = config.get('aws_access_key_id')
        self.aws_secret_access_key = config.get('aws_secret_access_key')
        self.aws_session_token = config.get('aws_session_token')
        self.endpoint_url = config.get('endpoint_url')  # For testing with localstack

        # Initialize client
        self._client = None
        self._initialize_client()

    def _initialize_client(self):
        """Initialize the AWS Secrets Manager client"""
        try:
            session_config = {
                'region_name': self.region_name
            }

            # Add credentials if provided explicitly
            if self.aws_access_key_id and self.aws_secret_access_key:
                session_config.update({
                    'aws_access_key_id': self.aws_access_key_id,
                    'aws_secret_access_key': self.aws_secret_access_key
                })
                if self.aws_session_token:
                    session_config['aws_session_token'] = self.aws_session_token

            # Create session and client
            session = boto3.Session(**session_config)

            client_config = {}
            if self.endpoint_url:
                client_config['endpoint_url'] = self.endpoint_url

            self._client = session.client('secretsmanager', **client_config)

            logger.info(f"AWS Secrets Manager client initialized for region: {self.region_name}")

        except (NoCredentialsError, PartialCredentialsError) as e:
            raise SecretManagerConnectionException(
                f"AWS credentials not found or incomplete: {e}. "
                "Configure credentials via AWS CLI, environment variables, or IAM roles."
            )
        except Exception as e:
            raise SecretManagerConnectionException(f"Failed to initialize AWS client: {e}")

    async def get_secret_with_metadata(self, key: str) -> SecretValue:
        """Get secret with metadata from AWS"""
        try:
            loop = asyncio.get_event_loop()

            # Get secret value
            response = await loop.run_in_executor(
                None,
                self._client.get_secret_value,
                {'SecretId': key}
            )

            # Extract secret value (can be string or binary)
            if 'SecretString' in response:
                secret_value = response['SecretString']
            elif 'SecretBinary' in response:
                secret_value = response['SecretBinary'].decode('utf-8')
            else:
                raise SecretManagerException(f"Secret '{key}' has no value")

            # Parse JSON secrets if they look like JSON
            metadata = {'source': 'aws_secrets_manager', 'region': self.region_name}

            try:
                # Check if it's a JSON secret (common AWS pattern)
                json_data = json.loads(secret_value)
                if isinstance(json_data, dict):
                    metadata['is_json'] = True
                    metadata['json_keys'] = list(json_data.keys())
            except (json.JSONDecodeError, TypeError):
                metadata['is_json'] = False

            return SecretValue(
                value=secret_value,
                key=key,
                version=response.get('VersionId'),
                created_at=response.get('CreatedDate').isoformat() if response.get('CreatedDate') else None,
                metadata=metadata
            )

        except ClientError as e:
            error_code = e.response['Error']['Code']

            if error_code == 'ResourceNotFoundException':
                raise SecretNotFoundException(f"Secret '{key}' not found in AWS Secrets Manager")
            elif error_code == 'AccessDeniedException':
                raise SecretManagerException(f"Access denied to secret '{key}': {e}")
            elif error_code == 'InvalidRequestException':
                raise SecretManagerException(f"Invalid request for secret '{key}': {e}")
            elif error_code == 'DecryptionFailureException':
                raise SecretManagerException(f"Failed to decrypt secret '{key}': {e}")
            else:
                raise SecretManagerException(f"AWS error retrieving secret '{key}': {e}")

        except Exception as e:
            raise SecretManagerException(f"Failed to retrieve secret '{key}' from AWS: {e}")

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
            all_secrets = []

            # AWS API returns paginated results
            paginator = self._client.get_paginator('list_secrets')

            async def _get_page(page_iterator):
                for page in page_iterator:
                    secrets = page.get('SecretList', [])
                    for secret in secrets:
                        secret_name = secret['Name']
                        if prefix is None or secret_name.startswith(prefix):
                            all_secrets.append(secret_name)

            # Run pagination in executor
            page_iterator = paginator.paginate()
            await loop.run_in_executor(None, lambda: list(page_iterator))

            # Process all pages
            for page in paginator.paginate():
                secrets = page.get('SecretList', [])
                for secret in secrets:
                    secret_name = secret['Name']
                    if prefix is None or secret_name.startswith(prefix):
                        all_secrets.append(secret_name)

            return sorted(all_secrets)

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDeniedException':
                raise SecretManagerException(f"Access denied listing secrets: {e}")
            else:
                raise SecretManagerException(f"AWS error listing secrets: {e}")
        except Exception as e:
            raise SecretManagerException(f"Failed to list secrets: {e}")

    async def health_check(self) -> bool:
        """Check if AWS Secrets Manager is accessible"""
        try:
            loop = asyncio.get_event_loop()

            # Try to list secrets with limit to minimize response
            await loop.run_in_executor(
                None,
                self._client.list_secrets,
                {'MaxResults': 1}
            )

            return True

        except Exception as e:
            logger.error(f"AWS Secrets Manager health check failed: {e}")
            return False

    async def create_secret(self, key: str, value: str, description: Optional[str] = None) -> bool:
        """
        Create a new secret in AWS Secrets Manager

        Args:
            key: Secret name
            value: Secret value
            description: Optional description

        Returns:
            True if successful
        """
        self._check_write_allowed()
        try:
            loop = asyncio.get_event_loop()

            request = {
                'Name': key,
                'SecretString': value
            }

            if description:
                request['Description'] = description

            await loop.run_in_executor(
                None,
                self._client.create_secret,
                request
            )

            logger.info(f"Created secret '{key}' in AWS Secrets Manager")
            return True

        except ClientError as e:
            error_code = e.response['Error']['Code']

            if error_code == 'ResourceExistsException':
                raise SecretManagerException(f"Secret '{key}' already exists")
            elif error_code == 'AccessDeniedException':
                raise SecretManagerException(f"Access denied creating secret '{key}': {e}")
            else:
                raise SecretManagerException(f"AWS error creating secret '{key}': {e}")

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

            await loop.run_in_executor(
                None,
                self._client.update_secret,
                {
                    'SecretId': key,
                    'SecretString': value
                }
            )

            # Clear cache for this key
            if key in self._cache:
                del self._cache[key]

            logger.info(f"Updated secret '{key}' in AWS Secrets Manager")
            return True

        except ClientError as e:
            error_code = e.response['Error']['Code']

            if error_code == 'ResourceNotFoundException':
                raise SecretNotFoundException(f"Secret '{key}' not found for update")
            elif error_code == 'AccessDeniedException':
                raise SecretManagerException(f"Access denied updating secret '{key}': {e}")
            else:
                raise SecretManagerException(f"AWS error updating secret '{key}': {e}")

        except Exception as e:
            raise SecretManagerException(f"Failed to update secret '{key}': {e}")

    def __repr__(self) -> str:
        return f"AwsSecretManager(region='{self.region_name}')"

    async def delete_secret(self, key: str, force_delete: bool = False) -> bool:
        """
        Delete a secret from AWS Secrets Manager

        Args:
            key: Secret name
            force_delete: If True, immediately delete without recovery period

        Returns:
            True if successful
        """
        self._check_write_allowed()

        try:
            loop = asyncio.get_event_loop()

            delete_params = {'SecretId': key}
            if force_delete:
                delete_params['ForceDeleteWithoutRecovery'] = True

            await loop.run_in_executor(
                None,
                self._client.delete_secret,
                delete_params
            )

            # Clear cache for this key
            if key in self._cache:
                del self._cache[key]

            logger.info(f"Deleted secret '{key}' from AWS Secrets Manager (force={force_delete})")
            return True

        except ClientError as e:
            error_code = e.response['Error']['Code']

            if error_code == 'ResourceNotFoundException':
                raise SecretNotFoundException(f"Secret '{key}' not found for deletion")
            elif error_code == 'AccessDeniedException':
                raise SecretManagerException(f"Access denied deleting secret '{key}': {e}")
            else:
                raise SecretManagerException(f"AWS error deleting secret '{key}': {e}")

        except Exception as e:
            raise SecretManagerException(f"Failed to delete secret '{key}': {e}")