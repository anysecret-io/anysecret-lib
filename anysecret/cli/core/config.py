"""
CLI Configuration Management

Handles ~/.anysecret/ directory and configuration files
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class ProfileConfig:
    """Configuration for a specific profile"""
    name: str
    secret_manager: Dict[str, Any]
    parameter_manager: Dict[str, Any]
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class ConfigManager:
    """Manages AnySecret CLI configuration"""
    
    def __init__(self):
        self.config_dir = Path.home() / ".anysecret"
        self.config_file = self.config_dir / "config.json"
        self.profiles_dir = self.config_dir / "profiles"
        self.credentials_dir = self.config_dir / "credentials"
        self.data_dir = self.config_dir / "data"
        self.cache_dir = self.config_dir / "cache"
        self.logs_dir = self.config_dir / "logs"
        
    def ensure_directories(self):
        """Create ~/.anysecret/ directory structure"""
        for directory in [
            self.config_dir, 
            self.profiles_dir, 
            self.credentials_dir,
            self.data_dir,
            self.cache_dir,
            self.logs_dir
        ]:
            directory.mkdir(mode=0o700, exist_ok=True)
            
    def init_config(self, interactive: bool = True) -> bool:
        """Initialize configuration with defaults or interactively"""
        self.ensure_directories()
        
        if self.config_file.exists() and interactive:
            response = input(f"Configuration already exists at {self.config_file}. Overwrite? (y/N): ")
            if response.lower() != 'y':
                return False
        
        # Create default configuration
        default_config = {
            "version": "1.0",
            "current_profile": "default",
            "profiles": {
                "default": {
                    "secret_manager": {
                        "type": "env_file",
                        "config": {
                            "file_path": str(self.data_dir / "secrets.env"),
                            "cache_ttl": 300
                        }
                    },
                    "parameter_manager": {
                        "type": "file_json", 
                        "config": {
                            "file_path": str(self.data_dir / "parameters.json")
                        }
                    }
                }
            },
            "global_settings": {
                "classification": {
                    "custom_secret_patterns": [],
                    "custom_parameter_patterns": []
                },
                "security": {
                    "enable_audit_log": True,
                    "audit_log_path": str(self.logs_dir / "audit.log"),
                    "encrypt_local_cache": True
                },
                "ui": {
                    "default_output_format": "table",
                    "colors": True,
                    "pager": "auto"
                }
            }
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
        
        # Create default data files
        self._create_default_data_files()
        
        return True
    
    def _create_default_data_files(self):
        """Create default secrets and parameters files"""
        secrets_file = self.data_dir / "secrets.env"
        params_file = self.data_dir / "parameters.json"
        
        if not secrets_file.exists():
            secrets_file.write_text("""# Default secrets file
# Add your secrets here, one per line
# Example:
# DB_PASSWORD=your-secret-password
# API_KEY=your-api-key
""")
            secrets_file.chmod(0o600)  # Read/write for user only
        
        if not params_file.exists():
            default_params = {
                "app_name": "my-application",
                "environment": "development",
                "debug": True
            }
            with open(params_file, 'w') as f:
                json.dump(default_params, f, indent=2)
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        if not self.config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_file}")
        
        with open(self.config_file) as f:
            return json.load(f)
    
    def save_config(self, config: Dict[str, Any]):
        """Save configuration to file"""
        self.ensure_directories()
        
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
    
    def get_current_profile(self) -> str:
        """Get current active profile name"""
        try:
            config = self.load_config()
            return config.get("current_profile", "default")
        except FileNotFoundError:
            return "default"
    
    def set_current_profile(self, profile_name: str):
        """Set current active profile"""
        config = self.load_config()
        
        if profile_name not in config.get("profiles", {}):
            raise ValueError(f"Profile '{profile_name}' not found")
        
        config["current_profile"] = profile_name
        self.save_config(config)
    
    def list_profiles(self) -> List[str]:
        """List available profiles"""
        try:
            config = self.load_config()
            return list(config.get("profiles", {}).keys())
        except FileNotFoundError:
            return ["default"]
    
    def get_profile_config(self, profile_name: Optional[str] = None) -> ProfileConfig:
        """Get configuration for a specific profile"""
        if profile_name is None:
            profile_name = self.get_current_profile()
        
        config = self.load_config()
        profiles = config.get("profiles", {})
        
        if profile_name not in profiles:
            raise ValueError(f"Profile '{profile_name}' not found")
        
        profile_data = profiles[profile_name]
        return ProfileConfig(
            name=profile_name,
            secret_manager=profile_data.get("secret_manager", {}),
            parameter_manager=profile_data.get("parameter_manager", {}),
            metadata=profile_data.get("metadata", {})
        )
    
    def create_profile(self, name: str, secret_config: Dict[str, Any], 
                      parameter_config: Dict[str, Any], metadata: Dict[str, Any] = None):
        """Create a new profile"""
        config = self.load_config()
        
        if "profiles" not in config:
            config["profiles"] = {}
        
        config["profiles"][name] = {
            "secret_manager": secret_config,
            "parameter_manager": parameter_config,
            "metadata": metadata or {}
        }
        
        self.save_config(config)
    
    def delete_profile(self, name: str):
        """Delete a profile"""
        if name == "default":
            raise ValueError("Cannot delete default profile")
        
        config = self.load_config()
        
        if name not in config.get("profiles", {}):
            raise ValueError(f"Profile '{name}' not found")
        
        del config["profiles"][name]
        
        # Switch to default if we deleted the current profile
        if config.get("current_profile") == name:
            config["current_profile"] = "default"
        
        self.save_config(config)
    
    def get_global_settings(self) -> Dict[str, Any]:
        """Get global settings"""
        try:
            config = self.load_config()
            return config.get("global_settings", {})
        except FileNotFoundError:
            return {}
    
    def update_global_settings(self, settings: Dict[str, Any]):
        """Update global settings"""
        config = self.load_config()
        
        if "global_settings" not in config:
            config["global_settings"] = {}
        
        config["global_settings"].update(settings)
        self.save_config(config)
    
    def is_write_enabled(self, profile_name: str = None) -> bool:
        """Check if write operations are enabled for a profile"""
        try:
            if profile_name is None:
                profile_name = self.get_current_profile()
            
            # Get raw config data instead of ProfileConfig object
            config = self.load_config()
            profiles = config.get("profiles", {})
            
            if profile_name not in profiles:
                return False
                
            profile_data = profiles[profile_name]
            
            # Check profile-specific write permission
            permissions = profile_data.get("permissions", {})
            if "write_enabled" in permissions:
                return permissions["write_enabled"]
            
            # Check global default (default is False - read-only by default)
            global_settings = self.get_global_settings()
            security = global_settings.get("security", {})
            return security.get("default_write_enabled", False)
            
        except Exception:
            # If there's any error, default to read-only for safety
            return False
    
    def enable_writes(self, profile_name: str = None, enabled: bool = True):
        """Enable or disable write operations for a profile"""
        if profile_name is None:
            profile_name = self.get_current_profile()
        
        config = self.load_config()
        
        if profile_name not in config.get("profiles", {}):
            raise ValueError(f"Profile '{profile_name}' not found")
        
        # Ensure permissions section exists
        if "permissions" not in config["profiles"][profile_name]:
            config["profiles"][profile_name]["permissions"] = {}
        
        config["profiles"][profile_name]["permissions"]["write_enabled"] = enabled
        
        # Add metadata about the change
        if "metadata" not in config["profiles"][profile_name]:
            config["profiles"][profile_name]["metadata"] = {}
        
        import datetime
        config["profiles"][profile_name]["metadata"]["write_permission_updated"] = {
            "timestamp": datetime.datetime.now().isoformat(),
            "enabled": enabled,
            "method": "cli"
        }
        
        self.save_config(config)
    
    def get_config_info(self) -> Dict[str, Any]:
        """Get information about current configuration"""
        return {
            "config_dir": str(self.config_dir),
            "config_file": str(self.config_file),
            "config_exists": self.config_file.exists(),
            "current_profile": self.get_current_profile(),
            "available_profiles": self.list_profiles(),
            "directories": {
                "profiles": str(self.profiles_dir),
                "credentials": str(self.credentials_dir), 
                "data": str(self.data_dir),
                "cache": str(self.cache_dir),
                "logs": str(self.logs_dir)
            }
        }


# Global instance
_config_manager: Optional[ConfigManager] = None


def get_config_manager() -> ConfigManager:
    """Get global config manager instance"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager


def expand_path(path: str) -> str:
    """Expand ~ and environment variables in paths"""
    return str(Path(path).expanduser().resolve())