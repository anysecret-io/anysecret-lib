"""
Configuration Loader Bridge

Bridges the new CLI config system (~/.anysecret/config.json) 
with the existing provider infrastructure
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional
import logging

from .config import (
    UnifiedConfig, 
    SecretManagerConfig,
    ParameterManagerConfig,
    SecretManagerType,
    ParameterManagerType,
    set_unified_config,
    ConfigAutoDetect
)

logger = logging.getLogger(__name__)


def load_from_cli_config() -> Optional[UnifiedConfig]:
    """
    Load configuration from CLI config file (~/.anysecret/config.json)
    """
    try:
        from .cli.core.config import get_config_manager
        
        config_mgr = get_config_manager()
        
        # Check if config exists
        if not config_mgr.config_file.exists():
            return None
        
        # Load current profile
        profile = config_mgr.get_profile_config()
        
        # Convert CLI config to UnifiedConfig format
        secret_config = profile.secret_manager
        param_config = profile.parameter_manager
        
        # Map string types to enums
        secret_type = SecretManagerType(secret_config["type"])
        param_type = ParameterManagerType(param_config["type"])
        
        # Build configs
        secret_manager_config = SecretManagerConfig(
            manager_type=secret_type,
            config=secret_config.get("config", {}),
            fallback_type=SecretManagerType(secret_config["fallback"]["type"]) if "fallback" in secret_config else None,
            fallback_config=secret_config["fallback"].get("config", {}) if "fallback" in secret_config else {},
            enable_caching=secret_config.get("config", {}).get("cache_ttl", 300) > 0,
            cache_ttl=secret_config.get("config", {}).get("cache_ttl", 300)
        )
        
        parameter_manager_config = ParameterManagerConfig(
            manager_type=param_type,
            config=param_config.get("config", {}),
            fallback_type=ParameterManagerType(param_config["fallback"]["type"]) if "fallback" in param_config else None,
            fallback_config=param_config["fallback"].get("config", {}) if "fallback" in param_config else {},
            enable_caching=param_config.get("config", {}).get("cache_ttl", 300) > 0,
            cache_ttl=param_config.get("config", {}).get("cache_ttl", 300)
        )
        
        # Get global settings if available
        config = config_mgr.load_config()
        global_settings = config.get("global_settings", {})
        classification = global_settings.get("classification", {})
        
        unified_config = UnifiedConfig(
            secret_config=secret_manager_config,
            parameter_config=parameter_manager_config,
            custom_secret_patterns=classification.get("custom_secret_patterns", []),
            custom_parameter_patterns=classification.get("custom_parameter_patterns", [])
        )
        
        logger.info(f"Loaded configuration from CLI config: {config_mgr.config_file}")
        return unified_config
        
    except Exception as e:
        logger.debug(f"Could not load CLI config: {e}")
        return None


def load_from_profile_data(profile_data: Dict[str, Any]) -> Optional[UnifiedConfig]:
    """
    Load configuration from processed profile data (from --profile-data)
    """
    try:
        # Extract profile configuration
        secret_config = profile_data["secret_manager"]
        param_config = profile_data["parameter_manager"]
        
        # Map string types to enums
        secret_type = SecretManagerType(secret_config["type"])
        param_type = ParameterManagerType(param_config["type"])
        
        # Build configs
        secret_manager_config = SecretManagerConfig(
            manager_type=secret_type,
            config=secret_config.get("config", {}),
            fallback_type=SecretManagerType(secret_config["fallback"]["type"]) if "fallback" in secret_config else None,
            fallback_config=secret_config["fallback"].get("config", {}) if "fallback" in secret_config else {},
            enable_caching=secret_config.get("config", {}).get("cache_ttl", 300) > 0,
            cache_ttl=secret_config.get("config", {}).get("cache_ttl", 300)
        )
        
        parameter_manager_config = ParameterManagerConfig(
            manager_type=param_type,
            config=param_config.get("config", {}),
            fallback_type=ParameterManagerType(param_config["fallback"]["type"]) if "fallback" in param_config else None,
            fallback_config=param_config["fallback"].get("config", {}) if "fallback" in param_config else {},
            enable_caching=param_config.get("config", {}).get("cache_ttl", 300) > 0,
            cache_ttl=param_config.get("config", {}).get("cache_ttl", 300)
        )
        
        unified_config = UnifiedConfig(
            secret_config=secret_manager_config,
            parameter_config=parameter_manager_config,
            custom_secret_patterns=[],  # Profile data doesn't include these currently
            custom_parameter_patterns=[]
        )
        
        logger.info(f"Loaded configuration from profile data: {profile_data['profile_name']}")
        return unified_config
        
    except Exception as e:
        logger.error(f"Could not load profile data: {e}")
        return None


def load_from_environment() -> Optional[UnifiedConfig]:
    """
    Load configuration from environment variables (backward compatibility)
    """
    secret_type = os.getenv('SECRET_MANAGER_TYPE')
    param_type = os.getenv('PARAMETER_MANAGER_TYPE')
    
    if not secret_type and not param_type:
        return None
    
    # Auto-detect if not specified
    if not secret_type:
        cloud = ConfigAutoDetect.detect_cloud_provider()
        secret_type = cloud or 'env_file'
    
    if not param_type:
        cloud = ConfigAutoDetect.detect_cloud_provider()
        param_type = cloud or 'file_json'
    
    # Map to enum types
    secret_mapping = {
        'aws': SecretManagerType.AWS,
        'gcp': SecretManagerType.GCP,
        'azure': SecretManagerType.AZURE,
        'vault': SecretManagerType.VAULT,
        'kubernetes': SecretManagerType.KUBERNETES,
        'encrypted_file': SecretManagerType.ENCRYPTED_FILE,
        'env_file': SecretManagerType.ENV_FILE
    }
    
    param_mapping = {
        'aws': ParameterManagerType.AWS_PARAMETER_STORE,
        'aws_parameter_store': ParameterManagerType.AWS_PARAMETER_STORE,
        'gcp': ParameterManagerType.GCP_CONFIG_CONNECTOR,
        'gcp_config_connector': ParameterManagerType.GCP_CONFIG_CONNECTOR,
        'azure': ParameterManagerType.AZURE_APP_CONFIGURATION,
        'azure_app_configuration': ParameterManagerType.AZURE_APP_CONFIGURATION,
        'kubernetes': ParameterManagerType.KUBERNETES_CONFIGMAP,
        'kubernetes_configmap': ParameterManagerType.KUBERNETES_CONFIGMAP,
        'file_json': ParameterManagerType.FILE_JSON,
        'file_yaml': ParameterManagerType.FILE_YAML
    }
    
    secret_manager_type = secret_mapping.get(secret_type.lower(), SecretManagerType.ENV_FILE)
    param_manager_type = param_mapping.get(param_type.lower(), ParameterManagerType.FILE_JSON)
    
    # Build config from environment
    secret_config = _build_secret_config_from_env(secret_manager_type)
    param_config = _build_parameter_config_from_env(param_manager_type)
    
    unified_config = UnifiedConfig(
        secret_config=secret_config,
        parameter_config=param_config
    )
    
    logger.info("Loaded configuration from environment variables")
    return unified_config


def _build_secret_config_from_env(manager_type: SecretManagerType) -> SecretManagerConfig:
    """Build secret manager config from environment"""
    config = {}
    
    if manager_type == SecretManagerType.AWS:
        config = {
            'region_name': os.getenv('AWS_DEFAULT_REGION', 'us-east-1'),
            'cache_ttl': int(os.getenv('SECRET_CACHE_TTL', '300'))
        }
    elif manager_type == SecretManagerType.GCP:
        config = {
            'project_id': os.getenv('GCP_PROJECT_ID'),
            'cache_ttl': int(os.getenv('SECRET_CACHE_TTL', '300'))
        }
    elif manager_type == SecretManagerType.ENV_FILE:
        config = {
            'file_path': os.getenv('ENV_FILE', '.env')
        }
    # Add other providers as needed
    
    return SecretManagerConfig(
        manager_type=manager_type,
        config=config
    )


def _build_parameter_config_from_env(manager_type: ParameterManagerType) -> ParameterManagerConfig:
    """Build parameter manager config from environment"""
    config = {}
    
    if manager_type == ParameterManagerType.AWS_PARAMETER_STORE:
        config = {
            'region': os.getenv('AWS_DEFAULT_REGION', 'us-east-1'),
            'prefix': os.getenv('AWS_PARAMETER_PREFIX', '/anysecret/')
        }
    elif manager_type == ParameterManagerType.GCP_CONFIG_CONNECTOR:
        config = {
            'project_id': os.getenv('GCP_PROJECT_ID'),
            'prefix': os.getenv('GCP_PARAMETER_PREFIX', 'anysecret')
        }
    elif manager_type == ParameterManagerType.FILE_JSON:
        config = {
            'file_path': os.getenv('PARAMETERS_JSON', 'parameters.json')
        }
    # Add other providers as needed
    
    return ParameterManagerConfig(
        manager_type=manager_type,
        config=config
    )


def initialize_config(profile_data: Optional[Dict[str, Any]] = None):
    """
    Initialize the configuration system with priority:
    1. Profile data (from --profile-data parameter)
    2. CLI config file (~/.anysecret/config.json)
    3. Environment variables (backward compatibility)
    4. Auto-detection
    """
    
    # Try profile data first if provided
    config = None
    if profile_data:
        config = load_from_profile_data(profile_data)
    
    # Try CLI config if no profile data
    if not config:
        config = load_from_cli_config()
    
    # Fall back to environment variables
    if not config:
        config = load_from_environment()
    
    # Fall back to auto-detection
    if not config:
        logger.info("No configuration found, using auto-detection")
        config = ConfigAutoDetect.get_recommended_config()
    
    # Set the global configuration
    set_unified_config(config)
    
    return config


# Initialize on import (can be called explicitly too)
_initialized = False

def ensure_initialized():
    """Ensure configuration is initialized"""
    global _initialized
    if not _initialized:
        initialize_config()
        _initialized = True