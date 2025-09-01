# File: anysecret/providers/gcp_parameter_manager.py

# Backward compatibility - import from the new implementation
from .gcs_parameter_manager import GCSJsonParameterManager, GcpParameterManagerClient, GcpConfigConnectorManager

# Keep backward compatibility aliases
__all__ = ['GcpParameterManagerClient', 'GcpConfigConnectorManager']