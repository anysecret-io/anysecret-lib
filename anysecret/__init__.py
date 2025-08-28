# anysecret/__init__.py
from .config import get_secret_manager
from .secret_manager import SecretManagerType, SecretManagerFactory

__version__ = "0.1.0"

__all__ = [
    "get_secret_manager",
    "SecretManagerType",
    "SecretManagerFactory"
]