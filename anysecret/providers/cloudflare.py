"""
Cloudflare Secrets Store implementation
"""
import asyncio
import json
import subprocess
from typing import Dict, List, Optional, Any
import logging
from datetime import datetime

from ..secret_manager import (
    BaseSecretManager,
    SecretValue,
    SecretNotFoundException,
    SecretManagerException,
    SecretManagerConnectionException
)

logger = logging.getLogger(__name__)


class CloudflareSecretManager(BaseSecretManager):
    """
    Cloudflare Secrets Store implementation using Wrangler CLI
    
    Requirements:
        - Wrangler CLI must be installed separately: npm install -g wrangler
        - Authenticate with: wrangler auth login
        - Or provide api_token in config
    
    Configuration:
        account_id (required): Your Cloudflare account ID
        api_token (optional): API token for authentication
        wrangler_path (optional): Path to wrangler binary, defaults to 'wrangler'
    
    Note: Cloudflare Secrets Store is write-only by design.
    Secrets cannot be retrieved after being stored for security reasons.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        self.account_id = config.get('account_id')
        self.api_token = config.get('api_token')
        self.wrangler_path = config.get('wrangler_path', 'wrangler')
        
        if not self.account_id:
            raise SecretManagerException("Cloudflare account_id is required")
        
        # Initialize CLI environment
        self._env = self._prepare_environment()
        
        # Verify wrangler is available
        self._verify_wrangler()

    def _prepare_environment(self) -> Dict[str, str]:
        """Prepare environment variables for Wrangler CLI"""
        env = {}
        
        if self.api_token:
            env['CLOUDFLARE_API_TOKEN'] = self.api_token
        
        return env

    def _verify_wrangler(self):
        """Verify Wrangler CLI is available and authenticated"""
        try:
            result = subprocess.run(
                [self.wrangler_path, '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                raise SecretManagerConnectionException(
                    self._get_installation_message()
                )
                
            logger.info(f"Found Wrangler CLI: {result.stdout.strip()}")
            
        except FileNotFoundError:
            raise SecretManagerConnectionException(
                self._get_installation_message()
            )
        except subprocess.TimeoutExpired:
            raise SecretManagerConnectionException("Wrangler CLI verification timed out")
        except Exception as e:
            raise SecretManagerConnectionException(f"Failed to verify Wrangler CLI: {e}")
    
    def _get_installation_message(self) -> str:
        """Get detailed installation instructions for Wrangler CLI"""
        return """
Cloudflare Wrangler CLI is required but not found.

Installation options:
1. Using npm (recommended): npm install -g wrangler
2. Using yarn: yarn global add wrangler
3. Using pnpm: pnpm add -g wrangler
4. Download binary: https://github.com/cloudflare/workers-sdk/releases

After installation, authenticate with: wrangler auth login

Note: Wrangler is a Node.js tool and cannot be installed via pip.
        """.strip()

    async def _run_wrangler_command(self, args: List[str], input_data: Optional[str] = None) -> str:
        """Run a wrangler command asynchronously"""
        try:
            cmd = [self.wrangler_path] + args
            
            # Add environment variables
            env = dict(self._env)
            
            loop = asyncio.get_event_loop()
            
            def run_command():
                return subprocess.run(
                    cmd,
                    input=input_data,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env=env
                )
            
            result = await loop.run_in_executor(None, run_command)
            
            if result.returncode != 0:
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                raise SecretManagerException(f"Wrangler command failed: {error_msg}")
            
            return result.stdout.strip()
            
        except subprocess.TimeoutExpired:
            raise SecretManagerException("Wrangler command timed out")
        except Exception as e:
            raise SecretManagerException(f"Failed to execute wrangler command: {e}")

    async def get_secret_with_metadata(self, key: str) -> SecretValue:
        """
        Get secret from Cloudflare Secrets Store
        
        Note: Cloudflare secrets are only accessible at runtime within CF Workers
        via env.SECRET_NAME. This method tries to read from environment variables
        if running inside a CF Worker, otherwise raises an exception.
        """
        import os
        
        # Check if we're running in a Cloudflare Worker environment
        # CF Workers expose secrets via environment variables
        if key in os.environ:
            secret_value = os.environ[key]
            return SecretValue(
                value=secret_value,
                key=key,
                version="runtime",
                metadata={
                    'source': 'cloudflare_worker_env',
                    'account_id': self.account_id,
                    'secret_name': key,
                    'access_method': 'environment_variable'
                }
            )
        
        # Not in CF Worker environment or secret not available
        raise SecretManagerException(
            f"Secret '{key}' not accessible. "
            f"Cloudflare secrets are only available at runtime within CF Workers via env.{key}. "
            f"Use 'anysecret set' to store secrets, then access them in your Worker code."
        )

    async def get_secrets_by_prefix(self, prefix: str) -> Dict[str, str]:
        """Get all secrets with given prefix from environment (CF Worker runtime only)"""
        import os
        
        # Look for environment variables matching the prefix
        matching_secrets = {}
        for key, value in os.environ.items():
            if key.startswith(prefix):
                matching_secrets[key] = value
        
        if not matching_secrets:
            raise SecretManagerException(
                f"No secrets found with prefix '{prefix}'. "
                f"Cloudflare secrets are only accessible at runtime within CF Workers."
            )
        
        return matching_secrets

    async def list_secrets(self, prefix: Optional[str] = None) -> List[str]:
        """List secret names (metadata only)"""
        try:
            # Use wrangler to list secrets
            args = ['secret', 'list', '--account-id', self.account_id, '--format', 'json']
            
            output = await self._run_wrangler_command(args)
            
            if not output:
                return []
            
            try:
                secrets_data = json.loads(output)
            except json.JSONDecodeError:
                # Fallback: parse simple text output
                lines = output.strip().split('\n')
                secret_names = [line.strip() for line in lines if line.strip()]
                if prefix:
                    secret_names = [name for name in secret_names if name.startswith(prefix)]
                return sorted(secret_names)
            
            # Extract secret names from JSON response
            secret_names = []
            if isinstance(secrets_data, list):
                for secret in secrets_data:
                    if isinstance(secret, dict) and 'name' in secret:
                        name = secret['name']
                        if prefix is None or name.startswith(prefix):
                            secret_names.append(name)
            
            return sorted(secret_names)
            
        except Exception as e:
            if "not found" in str(e).lower():
                return []
            raise SecretManagerException(f"Failed to list Cloudflare secrets: {e}")

    async def health_check(self) -> bool:
        """Check if Cloudflare Secrets Store is accessible"""
        try:
            logger.info(f"Starting Cloudflare health check for account {self.account_id}")
            
            # Verify wrangler is available
            if not hasattr(self, '_env'):
                return False
            
            # Try to list secrets (this should work even if empty)
            await self.list_secrets()
            
            logger.info(f"Cloudflare health check passed for account {self.account_id}")
            return True
            
        except Exception as e:
            logger.error(f"Cloudflare Secrets Store health check failed: {e}")
            return False

    async def create_secret(self, key: str, value: str, **kwargs) -> bool:
        """
        Create a new secret in Cloudflare Secrets Store
        
        Args:
            key: Secret name
            value: Secret value
            
        Returns:
            True if successful
        """
        self._check_write_allowed()
        
        try:
            args = [
                'secret', 'put', key,
                '--account-id', self.account_id
            ]
            
            # Pass the secret value via stdin for security
            await self._run_wrangler_command(args, input_data=value)
            
            logger.info(f"Created secret '{key}' in Cloudflare Secrets Store")
            return True
            
        except Exception as e:
            if "already exists" in str(e).lower():
                raise SecretManagerException(f"Secret '{key}' already exists")
            raise SecretManagerException(f"Failed to create secret '{key}': {e}")

    async def update_secret(self, key: str, value: str, **kwargs) -> bool:
        """
        Update an existing secret
        
        Args:
            key: Secret name
            value: New secret value
            
        Returns:
            True if successful
        """
        self._check_write_allowed()
        
        try:
            args = [
                'secret', 'put', key,
                '--account-id', self.account_id
            ]
            
            # Pass the secret value via stdin for security
            await self._run_wrangler_command(args, input_data=value)
            
            logger.info(f"Updated secret '{key}' in Cloudflare Secrets Store")
            return True
            
        except Exception as e:
            raise SecretManagerException(f"Failed to update secret '{key}': {e}")

    async def delete_secret(self, key: str, **kwargs) -> bool:
        """
        Delete a secret from Cloudflare Secrets Store
        
        Args:
            key: Secret name
            
        Returns:
            True if successful
        """
        self._check_write_allowed()
        
        try:
            args = [
                'secret', 'delete', key,
                '--account-id', self.account_id
            ]
            
            await self._run_wrangler_command(args)
            
            logger.info(f"Deleted secret '{key}' from Cloudflare Secrets Store")
            return True
            
        except Exception as e:
            if "not found" in str(e).lower():
                raise SecretNotFoundException(f"Secret '{key}' not found for deletion")
            raise SecretManagerException(f"Failed to delete secret '{key}': {e}")

    def __repr__(self) -> str:
        return f"CloudflareSecretManager(account_id='{self.account_id}')"