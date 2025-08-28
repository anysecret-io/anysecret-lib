"""
File-based secret managers for encrypted and plain text secrets
"""
import os
import json
import base64
from typing import Dict, List, Optional, Any
from pathlib import Path
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import asyncio

from ..secret_manager import (
    BaseSecretManager,
    SecretValue,
    SecretNotFoundException,
    SecretManagerException
)

logger = logging.getLogger(__name__)


class EnvFileSecretManager(BaseSecretManager):
    """Simple .env file secret manager (for development only)"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.file_path = Path(config.get('file_path', '.env'))
        self.secrets: Dict[str, str] = {}
        self._load_secrets()

    def _load_secrets(self):
        """Load secrets from .env file"""
        try:
            if not self.file_path.exists():
                logger.warning(f"Env file not found: {self.file_path}")
                return

            with open(self.file_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()

                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue

                    # Parse key=value
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"\'')  # Remove quotes
                        self.secrets[key] = value
                    else:
                        logger.warning(f"Invalid line {line_num} in {self.file_path}: {line}")

            logger.info(f"Loaded {len(self.secrets)} secrets from {self.file_path}")

        except Exception as e:
            raise SecretManagerException(f"Failed to load env file {self.file_path}: {e}")

    async def get_secret_with_metadata(self, key: str) -> SecretValue:
        """Get secret with metadata"""
        if key not in self.secrets:
            raise SecretNotFoundException(f"Secret '{key}' not found in env file")

        return SecretValue(
            value=self.secrets[key],
            key=key,
            metadata={'source': 'env_file', 'file_path': str(self.file_path)}
        )

    async def get_secrets_by_prefix(self, prefix: str) -> Dict[str, str]:
        """Get all secrets with given prefix"""
        return {
            key: value for key, value in self.secrets.items()
            if key.startswith(prefix)
        }

    async def list_secrets(self, prefix: Optional[str] = None) -> List[str]:
        """List all secret keys"""
        if prefix:
            return [key for key in self.secrets.keys() if key.startswith(prefix)]
        return list(self.secrets.keys())

    async def health_check(self) -> bool:
        """Check if env file is accessible"""
        return self.file_path.exists() and self.file_path.is_file()


class EncryptedFileSecretManager(BaseSecretManager):
    """Encrypted file secret manager for production deployments"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.file_path = Path(config.get('file_path', 'secrets.json.enc'))
        self.encryption_key = config.get('encryption_key')
        self.password = config.get('password')
        self.salt = config.get('salt', b'anysecret_salt_2024')  # Should be unique per deployment

        if not self.encryption_key and not self.password:
            raise SecretManagerException(
                "Either 'encryption_key' or 'password' must be provided"
            )

        self.secrets: Dict[str, str] = {}
        self._fernet = self._get_fernet()
        self._load_secrets()

    def _get_fernet(self) -> Fernet:
        """Get Fernet encryption instance"""
        if self.encryption_key:
            # Use provided key directly
            return Fernet(self.encryption_key.encode() if isinstance(self.encryption_key, str) else self.encryption_key)
        else:
            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt if isinstance(self.salt, bytes) else self.salt.encode(),
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.password.encode()))
            return Fernet(key)

    def _load_secrets(self):
        """Load and decrypt secrets from file"""
        try:
            if not self.file_path.exists():
                logger.warning(f"Encrypted secrets file not found: {self.file_path}")
                return

            # Read encrypted data
            with open(self.file_path, 'rb') as f:
                encrypted_data = f.read()

            if not encrypted_data:
                raise ValueError("Encrypted file is empty")

            # Decrypt
            try:
                decrypted_data = self._fernet.decrypt(encrypted_data)
                decrypted_str = decrypted_data.decode('utf-8')
                secrets_data = json.loads(decrypted_str)

                if isinstance(secrets_data, dict):
                    self.secrets = secrets_data
                else:
                    raise ValueError("Decrypted data is not a JSON object")

            except json.JSONDecodeError as e:
                raise SecretManagerException(f"Failed to parse decrypted JSON: {e}")
            except Exception as e:
                raise SecretManagerException(f"Failed to decrypt secrets file (wrong password?): {e}")

            logger.info(f"Loaded {len(self.secrets)} secrets from encrypted file")

        except FileNotFoundError:
            logger.warning(f"Encrypted secrets file not found: {self.file_path}")
        except SecretManagerException:
            # Re-raise our custom exceptions
            raise
        except Exception as e:
            raise SecretManagerException(f"Failed to load encrypted secrets: {e}")

    async def get_secret_with_metadata(self, key: str) -> SecretValue:
        """Get secret with metadata"""
        if key not in self.secrets:
            raise SecretNotFoundException(f"Secret '{key}' not found in encrypted file")

        return SecretValue(
            value=self.secrets[key],
            key=key,
            metadata={
                'source': 'encrypted_file',
                'file_path': str(self.file_path),
                'encrypted': True
            }
        )

    async def get_secrets_by_prefix(self, prefix: str) -> Dict[str, str]:
        """Get all secrets with given prefix"""
        return {
            key: value for key, value in self.secrets.items()
            if key.startswith(prefix)
        }

    async def list_secrets(self, prefix: Optional[str] = None) -> List[str]:
        """List all secret keys"""
        if prefix:
            return [key for key in self.secrets.keys() if key.startswith(prefix)]
        return list(self.secrets.keys())

    async def health_check(self) -> bool:
        """Check if encrypted file is accessible and decryptable"""
        try:
            return (
                self.file_path.exists() and
                self.file_path.is_file() and
                len(self.secrets) > 0
            )
        except Exception:
            return False

    def encrypt_secrets_file(self, secrets_dict: Dict[str, str], output_path: Optional[Path] = None):
        """
        Helper method to create encrypted secrets file

        Args:
            secrets_dict: Dictionary of secrets to encrypt
            output_path: Output file path (defaults to configured file_path)
        """
        output_path = output_path or self.file_path

        try:
            # Convert secrets to JSON
            json_data = json.dumps(secrets_dict, indent=2)

            # Encrypt
            encrypted_data = self._fernet.encrypt(json_data.encode())

            # Write to file
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)

            logger.info(f"Encrypted {len(secrets_dict)} secrets to {output_path}")

        except Exception as e:
            raise SecretManagerException(f"Failed to encrypt secrets file: {e}")

    @classmethod
    def create_encrypted_file(cls,
                              secrets_dict: Dict[str, str],
                              file_path: Path,
                              password: str,
                              salt: Optional[bytes] = None) -> 'EncryptedFileSecretManager':
        """
        Class method to create a new encrypted secrets file
        """
        config = {
            'file_path': str(file_path),
            'password': password,
            'salt': salt or b'anysecret_salt_2024'
        }

        # Create manager WITHOUT loading (file doesn't exist yet)
        manager = cls.__new__(cls)  # Create instance without calling __init__
        BaseSecretManager.__init__(manager, config)

        manager.file_path = Path(config.get('file_path', 'secrets.json.enc'))
        manager.encryption_key = config.get('encryption_key')
        manager.password = config.get('password')
        manager.salt = config.get('salt', b'anysecret_salt_2024')
        manager.secrets = {}
        manager._fernet = manager._get_fernet()

        # Now encrypt the secrets
        manager.encrypt_secrets_file(secrets_dict, file_path)

        return manager


# Utility functions for CLI tools
def create_encrypted_secrets_file(
    input_file: Path,
    output_file: Path,
    password: str,
    salt: Optional[str] = None
):
    """
    CLI utility to create encrypted secrets file from plain text

    Usage:
        create_encrypted_secrets_file(
            Path("secrets.env"),
            Path("secrets.json.enc"),
            "my-secure-password"
        )
    """
    # Load secrets from input file
    secrets = {}

    if input_file.suffix == '.json':
        # JSON input
        with open(input_file, 'r') as f:
            secrets = json.load(f)
    else:
        # .env format input
        with open(input_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    secrets[key.strip()] = value.strip().strip('"\'')

    # Create encrypted file
    salt_bytes = salt.encode() if salt else b'anysecret_salt_2024'

    manager = EncryptedFileSecretManager.create_encrypted_file(
        secrets, output_file, password, salt_bytes
    )

    print(f"Created encrypted secrets file: {output_file}")
    print(f"Secrets encrypted: {len(secrets)}")

    return manager