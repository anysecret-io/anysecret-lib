# anysecret/__init__.py
from .config import get_secret_manager
from .secret_manager import SecretManagerType, SecretManagerFactory

# Version is automatically managed by setuptools_scm from git tags
try:
    from importlib.metadata import version
    __version__ = version("anysecret-io")
except ImportError:
    # Fallback for Python < 3.8
    try:
        from importlib_metadata import version
        __version__ = version("anysecret-io")
    except ImportError:
        # Final fallback for development
        __version__ = "0.1.0-dev"

__all__ = [
    "get_secret_manager", 
    "SecretManagerType",
    "SecretManagerFactory"
]