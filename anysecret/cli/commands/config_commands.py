"""
Configuration and Metadata Commands
"""

from typing import Optional, List
from pathlib import Path
import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
import json
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass

from ..core import print_not_implemented, handle_errors, async_command
from ..core.config import get_config_manager

app = typer.Typer(help="Configuration management commands")
console = Console()


@app.command(name="init")
@handle_errors
def init_config():
    """Initialize configuration with interactive wizard"""
    config_mgr = get_config_manager()
    
    # Show welcome message
    console.print(Panel.fit(
        "[bold green]🚀 AnySecret Configuration Wizard[/bold green]\n"
        "This will create configuration in ~/.anysecret/",
        border_style="green"
    ))
    
    # Check if config exists
    if config_mgr.config_file.exists():
        if not Confirm.ask(f"\n[yellow]Configuration already exists at {config_mgr.config_file}[/yellow]\nOverwrite?", default=False):
            console.print("[dim]Configuration unchanged.[/dim]")
            raise typer.Exit(0)
    
    # Interactive setup
    console.print("\n[bold cyan]Step 1: Choose your primary provider[/bold cyan]")
    console.print("[dim]This will be used for storing your secrets and configuration[/dim]\n")
    
    providers = [
        "file-based (Local files - good for development)",
        "aws (AWS Secrets Manager + Parameter Store)",
        "gcp (GCP Secret Manager + Config Connector)",
        "azure (Azure Key Vault + App Configuration)",
        "kubernetes (Kubernetes Secrets + ConfigMaps)",
        "vault (HashiCorp Vault)",
        "custom (Configure manually)"
    ]
    
    for i, provider in enumerate(providers, 1):
        console.print(f"  {i}. {provider}")
    
    choice = Prompt.ask("\nSelect provider", choices=[str(i) for i in range(1, len(providers) + 1)], default="1")
    
    # Map choice to provider type
    provider_map = {
        "1": ("env_file", "file_json"),
        "2": ("aws", "aws_parameter_store"),
        "3": ("gcp", "gcp_config_connector"),
        "4": ("azure", "azure_app_configuration"),
        "5": ("kubernetes", "kubernetes_configmap"),
        "6": ("vault", "file_json"),  # Vault doesn't support parameters
        "7": (None, None)
    }
    
    secret_type, param_type = provider_map[choice]
    
    # Build configuration based on choice
    if choice == "1":  # File-based
        config_mgr.ensure_directories()
        profile_config = {
            "secret_manager": {
                "type": "env_file",
                "config": {
                    "file_path": str(config_mgr.data_dir / "secrets.env"),
                    "cache_ttl": 300
                }
            },
            "parameter_manager": {
                "type": "file_json",
                "config": {
                    "file_path": str(config_mgr.data_dir / "parameters.json")
                }
            }
        }
        console.print("\n[green]✅ File-based configuration selected[/green]")
        console.print(f"[dim]Secrets will be stored in: {config_mgr.data_dir / 'secrets.env'}[/dim]")
        console.print(f"[dim]Parameters will be stored in: {config_mgr.data_dir / 'parameters.json'}[/dim]")
        
    elif choice == "2":  # AWS
        console.print("\n[bold cyan]AWS Configuration[/bold cyan]")
        region = Prompt.ask("AWS Region", default="us-east-1")
        profile = Prompt.ask("AWS Profile (leave empty for default)", default="")
        
        profile_config = {
            "secret_manager": {
                "type": "aws",
                "config": {
                    "region_name": region,
                    "cache_ttl": 300
                }
            },
            "parameter_manager": {
                "type": "aws_parameter_store",
                "config": {
                    "region": region,
                    "prefix": "/anysecret/"
                }
            }
        }
        
        if profile:
            profile_config["secret_manager"]["config"]["profile_name"] = profile
            profile_config["parameter_manager"]["config"]["profile_name"] = profile
        
        console.print("\n[green]✅ AWS configuration complete[/green]")
        
    elif choice == "3":  # GCP
        console.print("\n[bold cyan]GCP Configuration[/bold cyan]")
        project_id = Prompt.ask("GCP Project ID")
        creds_path = Prompt.ask("Service Account JSON path (leave empty for default)", default="")
        
        profile_config = {
            "secret_manager": {
                "type": "gcp",
                "config": {
                    "project_id": project_id,
                    "cache_ttl": 300
                }
            },
            "parameter_manager": {
                "type": "gcp_config_connector",
                "config": {
                    "project_id": project_id,
                    "prefix": "anysecret"
                }
            }
        }
        
        if creds_path:
            profile_config["secret_manager"]["config"]["credentials_path"] = creds_path
            profile_config["parameter_manager"]["config"]["credentials_path"] = creds_path
        
        console.print("\n[green]✅ GCP configuration complete[/green]")
        
    elif choice == "4":  # Azure
        console.print("\n[bold cyan]Azure Configuration[/bold cyan]")
        vault_url = Prompt.ask("Key Vault URL (https://your-vault.vault.azure.net/)")
        tenant_id = Prompt.ask("Tenant ID")
        
        profile_config = {
            "secret_manager": {
                "type": "azure",
                "config": {
                    "vault_url": vault_url,
                    "tenant_id": tenant_id,
                    "cache_ttl": 300
                }
            },
            "parameter_manager": {
                "type": "azure_app_configuration",
                "config": {
                    "endpoint": Prompt.ask("App Configuration Endpoint"),
                    "label": "Production"
                }
            }
        }
        
        console.print("\n[green]✅ Azure configuration complete[/green]")
        
    elif choice == "5":  # Kubernetes
        console.print("\n[bold cyan]Kubernetes Configuration[/bold cyan]")
        namespace = Prompt.ask("Namespace", default="default")
        
        profile_config = {
            "secret_manager": {
                "type": "kubernetes",
                "config": {
                    "namespace": namespace,
                    "secret_name": "anysecret-secrets"
                }
            },
            "parameter_manager": {
                "type": "kubernetes_configmap",
                "config": {
                    "namespace": namespace,
                    "configmap_name": "anysecret-config"
                }
            }
        }
        
        console.print("\n[green]✅ Kubernetes configuration complete[/green]")
        
    elif choice == "6":  # Vault
        console.print("\n[bold cyan]Vault Configuration[/bold cyan]")
        vault_url = Prompt.ask("Vault URL", default="http://localhost:8200")
        
        profile_config = {
            "secret_manager": {
                "type": "vault",
                "config": {
                    "url": vault_url,
                    "mount_point": "secret",
                    "cache_ttl": 300
                }
            },
            "parameter_manager": {
                "type": "file_json",
                "config": {
                    "file_path": str(config_mgr.data_dir / "parameters.json")
                }
            }
        }
        
        console.print("\n[green]✅ Vault configuration complete[/green]")
        console.print("[yellow]Note: Vault doesn't support parameters, using local file fallback[/yellow]")
        
    else:  # Custom
        console.print("\n[yellow]Manual configuration selected[/yellow]")
        console.print(f"Edit configuration file: {config_mgr.config_file}")
        profile_config = {
            "secret_manager": {"type": "env_file", "config": {}},
            "parameter_manager": {"type": "file_json", "config": {}}
        }
    
    # Security Configuration - Write permissions
    console.print("\n[bold cyan]Step 2: Security Settings[/bold cyan]")
    console.print("[dim]AnySecret is read-only by default for security[/dim]\n")
    
    console.print(Panel.fit(
        "[bold yellow]⚠️  Write Permissions[/bold yellow]\n\n"
        "Write operations include:\n"
        "• Creating new secrets and parameters\n"
        "• Updating existing values\n"
        "• Deleting configuration data\n\n"
        "[bold]Recommendation:[/bold] Keep disabled for production profiles",
        border_style="yellow"
    ))
    
    enable_writes = Confirm.ask("\nEnable write operations for the default profile?", default=False)
    
    # Create the configuration
    config_mgr.ensure_directories()
    
    # Add write permissions to profile config
    if enable_writes:
        profile_config["permissions"] = {"write_enabled": True}
        import datetime
        profile_config["metadata"] = {
            "created": json.dumps({"timestamp": "now", "method": "cli"}),
            "write_permission_updated": {
                "timestamp": datetime.datetime.now().isoformat(),
                "enabled": True,
                "method": "cli"
            }
        }
        console.print("\n[yellow]⚠️  Write operations enabled for default profile[/yellow]")
    else:
        profile_config["permissions"] = {"write_enabled": False}
        profile_config["metadata"] = {
            "created": json.dumps({"timestamp": "now", "method": "cli"}),
        }
        console.print("\n[green]✅ Profile will be read-only (secure default)[/green]")
    
    config = {
        "version": "1.0",
        "current_profile": "default",
        "profiles": {
            "default": profile_config
        },
        "global_settings": {
            "classification": {
                "custom_secret_patterns": [],
                "custom_parameter_patterns": []
            },
            "security": {
                "enable_audit_log": True,
                "audit_log_path": str(config_mgr.logs_dir / "audit.log"),
                "encrypt_local_cache": False
            },
            "ui": {
                "default_output_format": "table",
                "colors": True,
                "pager": "auto"
            }
        }
    }
    
    config_mgr.save_config(config)
    
    # Create default data files if file-based
    if choice == "1":
        secrets_file = config_mgr.data_dir / "secrets.env"
        params_file = config_mgr.data_dir / "parameters.json"
        
        if not secrets_file.exists():
            secrets_file.write_text("# Add your secrets here\n# Example:\n# DB_PASSWORD=secret123\n# API_KEY=your-api-key\n")
            secrets_file.chmod(0o600)
            
        if not params_file.exists():
            with open(params_file, 'w') as f:
                json.dump({"app_name": "my-app", "environment": "development"}, f, indent=2)
    
    # Success message
    console.print("\n" + "=" * 60)
    write_status = "ENABLED" if enable_writes else "DISABLED (secure default)"
    next_steps = [
        "• Test your configuration: [cyan]anysecret info[/cyan]",
        "• Check status: [cyan]anysecret status[/cyan]",
        "• Create additional profiles: [cyan]anysecret config profile-create[/cyan]"
    ]
    
    if enable_writes:
        next_steps.append("• Set a value: [cyan]anysecret set my-key my-value[/cyan]")
    else:
        next_steps.append("• Enable writes when needed: [cyan]anysecret config enable-writes[/cyan]")
    
    console.print(Panel.fit(
        "[bold green]✅ Configuration initialized successfully![/bold green]\n\n"
        f"Configuration saved to: [cyan]{config_mgr.config_file}[/cyan]\n"
        f"Profile: [cyan]default[/cyan]\n"
        f"Write operations: [cyan]{write_status}[/cyan]\n\n"
        "[dim]Next steps:[/dim]\n" + "\n".join(next_steps),
        border_style="green"
    ))


@app.command(name="validate")
@handle_errors
def validate_config():
    """Validate configuration files and provider connectivity"""
    import asyncio
    import logging
    from pathlib import Path
    from rich.table import Table
    
    try:
        config_mgr = get_config_manager()
        
        # Header
        console.print(Panel.fit(
            "[bold green]✅ Configuration Validation[/bold green]\n"
            "Comprehensive configuration and connectivity checks",
            border_style="green"
        ))
        
        # Suppress noisy logging
        logging.getLogger().setLevel(logging.ERROR)
        
        validation_results = []
        overall_valid = True
        
        # 1. Check if configuration exists
        console.print("\n[bold cyan]🔍 Configuration File Checks[/bold cyan]")
        
        if not config_mgr.config_file.exists():
            console.print("[red]❌ Configuration file missing![/red]")
            console.print(f"[dim]Expected at: {config_mgr.config_file}[/dim]")
            console.print("[yellow]Run 'anysecret config init' to create configuration[/yellow]")
            return
        else:
            console.print(f"[green]✅ Configuration file exists: {config_mgr.config_file}[/green]")
        
        # 2. Validate JSON structure
        try:
            config = config_mgr.load_config()
            console.print("[green]✅ Configuration file is valid JSON[/green]")
        except Exception as e:
            console.print(f"[red]❌ Invalid JSON structure: {e}[/red]")
            overall_valid = False
            return
        
        # 3. Check directory structure
        console.print(f"[green]✅ Configuration directory: {config_mgr.config_dir}[/green]")
        
        for dir_name, dir_path in [
            ("profiles", config_mgr.profiles_dir),
            ("credentials", config_mgr.credentials_dir),
            ("data", config_mgr.data_dir),
            ("cache", config_mgr.cache_dir),
            ("logs", config_mgr.logs_dir)
        ]:
            if dir_path.exists():
                console.print(f"[green]✅ {dir_name.title()} directory exists[/green]")
            else:
                console.print(f"[yellow]⚠️  {dir_name.title()} directory missing (will be created)[/yellow]")
        
        # 4. Validate configuration schema
        console.print("\n[bold cyan]📋 Configuration Schema Validation[/bold cyan]")
        
        # Check required fields
        required_fields = ["version", "current_profile", "profiles"]
        for field in required_fields:
            if field in config:
                console.print(f"[green]✅ Required field '{field}' present[/green]")
            else:
                console.print(f"[red]❌ Missing required field '{field}'[/red]")
                overall_valid = False
        
        # Check current profile exists
        current_profile = config.get("current_profile", "default")
        profiles = config.get("profiles", {})
        
        if current_profile in profiles:
            console.print(f"[green]✅ Current profile '{current_profile}' exists[/green]")
        else:
            console.print(f"[red]❌ Current profile '{current_profile}' not found in profiles[/red]")
            overall_valid = False
        
        # 5. Validate each profile
        console.print("\n[bold cyan]👤 Profile Validation[/bold cyan]")
        
        profile_table = Table()
        profile_table.add_column("Profile", style="cyan")
        profile_table.add_column("Secret Manager", style="yellow") 
        profile_table.add_column("Parameter Manager", style="yellow")
        profile_table.add_column("Config Valid", style="green")
        profile_table.add_column("Connectivity", style="")
        
        for profile_name, profile_config in profiles.items():
            # Validate profile structure
            secret_mgr = profile_config.get("secret_manager", {})
            param_mgr = profile_config.get("parameter_manager", {})
            
            secret_type = secret_mgr.get("type", "unknown")
            param_type = param_mgr.get("type", "unknown") 
            
            # Check if types are valid
            valid_secret_types = ["aws", "gcp", "azure", "vault", "kubernetes", "env_file", "encrypted_file"]
            valid_param_types = ["aws_parameter_store", "gcp_config_connector", "azure_app_configuration", 
                                "kubernetes_configmap", "file_json", "file_yaml"]
            
            config_valid = "✅"
            if secret_type not in valid_secret_types:
                config_valid = "❌"
                overall_valid = False
            if param_type not in valid_param_types:
                config_valid = "❌" 
                overall_valid = False
            
            # Test connectivity
            connectivity = "❌"
            original_profile = config_mgr.get_current_profile()
            
            try:
                # Switch to this profile for testing
                if profile_name != original_profile:
                    config_mgr.set_current_profile(profile_name)
                
                # Initialize and test providers
                from ...config_loader import initialize_config
                from ...config import get_secret_manager, get_parameter_manager
                
                initialize_config()
                
                # Test both managers
                secret_ok = False
                param_ok = False
                
                try:
                    secret_mgr_instance = asyncio.run(get_secret_manager())
                    asyncio.run(secret_mgr_instance.list_secrets())
                    secret_ok = True
                except Exception:
                    pass
                
                try:
                    param_mgr_instance = asyncio.run(get_parameter_manager())
                    asyncio.run(param_mgr_instance.list_parameters())
                    param_ok = True
                except Exception:
                    pass
                
                if secret_ok and param_ok:
                    connectivity = "✅"
                elif secret_ok or param_ok:
                    connectivity = "⚠️"
                else:
                    connectivity = "❌"
                    
            except Exception:
                connectivity = "❌"
                overall_valid = False
                
            finally:
                # Restore original profile
                if original_profile != profile_name:
                    try:
                        config_mgr.set_current_profile(original_profile)
                    except:
                        pass
            
            profile_table.add_row(
                profile_name,
                secret_type,
                param_type,
                config_valid,
                connectivity
            )
        
        console.print(profile_table)
        
        # 6. Validate file-based provider files
        console.print("\n[bold cyan]📁 File-based Provider Validation[/bold cyan]")
        
        file_issues = []
        for profile_name, profile_config in profiles.items():
            secret_mgr = profile_config.get("secret_manager", {})
            param_mgr = profile_config.get("parameter_manager", {})
            
            # Check env files
            if secret_mgr.get("type") == "env_file":
                file_path = secret_mgr.get("config", {}).get("file_path")
                if file_path:
                    file_path = Path(file_path)
                    if file_path.exists():
                        # Check permissions
                        stat = file_path.stat()
                        if stat.st_mode & 0o077:  # Check if readable by group/others
                            console.print(f"[yellow]⚠️  {profile_name}: {file_path} has loose permissions[/yellow]")
                            file_issues.append(f"Fix permissions: chmod 600 {file_path}")
                        else:
                            console.print(f"[green]✅ {profile_name}: Secret file permissions OK[/green]")
                    else:
                        console.print(f"[red]❌ {profile_name}: Secret file missing: {file_path}[/red]")
                        file_issues.append(f"Create missing secret file: {file_path}")
                        overall_valid = False
            
            # Check JSON/YAML parameter files
            if param_mgr.get("type") in ["file_json", "file_yaml"]:
                file_path = param_mgr.get("config", {}).get("file_path")
                if file_path:
                    file_path = Path(file_path)
                    if file_path.exists():
                        try:
                            # Try to parse the file
                            if file_path.suffix == ".json":
                                import json
                                with open(file_path) as f:
                                    json.load(f)
                                console.print(f"[green]✅ {profile_name}: Parameter file is valid JSON[/green]")
                            elif file_path.suffix == ".yaml":
                                try:
                                    import yaml
                                    with open(file_path) as f:
                                        yaml.safe_load(f)
                                    console.print(f"[green]✅ {profile_name}: Parameter file is valid YAML[/green]")
                                except ImportError:
                                    console.print(f"[yellow]⚠️  {profile_name}: YAML support not installed[/yellow]")
                        except Exception as e:
                            console.print(f"[red]❌ {profile_name}: Invalid parameter file: {e}[/red]")
                            overall_valid = False
                    else:
                        console.print(f"[red]❌ {profile_name}: Parameter file missing: {file_path}[/red]")
                        file_issues.append(f"Create missing parameter file: {file_path}")
                        overall_valid = False
        
        # 7. Final validation summary
        console.print("\n[bold]Validation Summary:[/bold]")
        
        if overall_valid:
            console.print("[green]✅ Configuration is valid and ready to use![/green]")
        else:
            console.print("[red]❌ Configuration has issues that need attention[/red]")
        
        # Show action items
        if file_issues:
            console.print("\n[bold]Action Items:[/bold]")
            for issue in file_issues:
                console.print(f"• [yellow]{issue}[/yellow]")
        
        # Quick fixes
        console.print("\n[bold]Quick Actions:[/bold]")
        console.print("• Fix permissions: [cyan]chmod 600 ~/.anysecret/data/*.env[/cyan]")
        console.print("• Create missing directories: [cyan]anysecret config init[/cyan]")
        console.print("• Test connectivity: [cyan]anysecret providers health[/cyan]")
        console.print("• View profiles: [cyan]anysecret config profile-list[/cyan]")
        
    except Exception as e:
        console.print(f"[red]❌ Validation failed with error: {e}[/red]")
        import traceback
        traceback.print_exc()


@app.command(name="show")
@handle_errors
def show_config():
    """Display current configuration"""
    config_mgr = get_config_manager()
    
    if not config_mgr.config_file.exists():
        console.print("[red]❌ No configuration found![/red]")
        console.print("[dim]Run 'anysecret config init' to create configuration[/dim]")
        raise typer.Exit(1)
    
    try:
        config = config_mgr.load_config()
        info = config_mgr.get_config_info()
        
        # Display configuration info
        console.print(Panel.fit(
            "[bold cyan]AnySecret Configuration[/bold cyan]",
            border_style="cyan"
        ))
        
        # Configuration paths
        table = Table(show_header=False)
        table.add_column("Key", style="dim")
        table.add_column("Value", style="cyan")
        
        table.add_row("Config File", str(info["config_file"]))
        table.add_row("Config Directory", str(info["config_dir"]))
        table.add_row("Current Profile", info["current_profile"])
        table.add_row("Available Profiles", ", ".join(info["available_profiles"]))
        
        console.print(table)
        
        # Current profile details
        current_profile = config_mgr.get_profile_config()
        
        console.print("\n[bold]Current Profile Configuration:[/bold]")
        
        profile_table = Table()
        profile_table.add_column("Component", style="cyan")
        profile_table.add_column("Type", style="green")
        profile_table.add_column("Configuration", style="dim")
        
        # Secret manager
        sm_config = current_profile.secret_manager
        sm_type = sm_config.get("type", "unknown")
        sm_details = json.dumps(sm_config.get("config", {}), indent=2)
        profile_table.add_row("Secret Manager", sm_type, sm_details)
        
        # Parameter manager
        pm_config = current_profile.parameter_manager
        pm_type = pm_config.get("type", "unknown")
        pm_details = json.dumps(pm_config.get("config", {}), indent=2)
        profile_table.add_row("Parameter Manager", pm_type, pm_details)
        
        console.print(profile_table)
        
        # Global settings
        if "global_settings" in config:
            console.print("\n[bold]Global Settings:[/bold]")
            console.print(json.dumps(config["global_settings"], indent=2))
            
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="reset")
@handle_errors  
def reset_config():
    """Reset configuration to defaults"""
    print_not_implemented(
        "anysecret config reset",
        "Will reset configuration to default values"
    )


@app.command(name="backup")
@handle_errors
def backup_config(
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Backup file path")
):
    """Backup current configuration"""
    print_not_implemented(
        "anysecret config backup",
        f"Will backup configuration to {output or 'default location'}"
    )


@app.command(name="restore")
@handle_errors
def restore_config(backup_file: Path):
    """Restore configuration from backup"""
    print_not_implemented(
        "anysecret config restore",
        f"Will restore configuration from {backup_file}"
    )


# Profile management
@app.command(name="profile-create")
@handle_errors
def create_profile(name: str):
    """Create a new configuration profile"""
    config_mgr = get_config_manager()
    
    if not config_mgr.config_file.exists():
        console.print("[red]❌ No configuration found![/red]")
        console.print("[dim]Run 'anysecret config init' first to initialize configuration[/dim]")
        raise typer.Exit(1)
    
    try:
        # Check if profile already exists
        existing_profiles = config_mgr.list_profiles()
        if name in existing_profiles:
            console.print(f"[red]❌ Profile '{name}' already exists![/red]")
            console.print("[dim]Use 'anysecret config profile-list' to see existing profiles[/dim]")
            raise typer.Exit(1)
        
        # Show header
        console.print(Panel.fit(
            f"[bold green]🔧 Creating Profile: {name}[/bold green]\n"
            "Configure providers for this profile",
            border_style="green"
        ))
        
        # Interactive provider selection
        console.print("\n[bold cyan]Choose providers for this profile[/bold cyan]")
        console.print("[dim]This will configure both secret and parameter management[/dim]\n")
        
        providers = [
            "file-based (Local files - good for development/testing)",
            "aws (AWS Secrets Manager + Parameter Store)",
            "gcp (GCP Secret Manager + Config Connector)", 
            "azure (Azure Key Vault + App Configuration)",
            "kubernetes (Kubernetes Secrets + ConfigMaps)",
            "vault (HashiCorp Vault + local file for parameters)",
            "custom (Manual configuration)"
        ]
        
        for i, provider in enumerate(providers, 1):
            console.print(f"  {i}. {provider}")
        
        choice = Prompt.ask(f"\nSelect provider for profile '{name}'", 
                           choices=[str(i) for i in range(1, len(providers) + 1)], 
                           default="1")
        
        # Build profile configuration based on choice
        if choice == "1":  # File-based
            console.print(f"\n[bold cyan]File-based Configuration for '{name}'[/bold cyan]")
            use_default_location = Confirm.ask("Use default location (~/.anysecret/data)?", default=True)
            
            if use_default_location:
                secrets_path = str(config_mgr.data_dir / f"secrets-{name}.env")
                params_path = str(config_mgr.data_dir / f"parameters-{name}.json")
            else:
                secrets_path = Prompt.ask("Secrets file path", default=f"./secrets-{name}.env")
                params_path = Prompt.ask("Parameters file path", default=f"./parameters-{name}.json")
            
            profile_config = {
                "secret_manager": {
                    "type": "env_file",
                    "config": {
                        "file_path": secrets_path,
                        "cache_ttl": 300
                    }
                },
                "parameter_manager": {
                    "type": "file_json", 
                    "config": {
                        "file_path": params_path
                    }
                }
            }
            
            # Create files if using default location
            if use_default_location:
                Path(secrets_path).write_text(f"# Secrets for {name} profile\n# Add your secrets here\n")
                Path(secrets_path).chmod(0o600)
                
                Path(params_path).write_text(json.dumps({
                    "profile": name,
                    "environment": "development" if "dev" in name.lower() else "production"
                }, indent=2))
                
                console.print(f"\n[green]✅ Created files:[/green]")
                console.print(f"[dim]  Secrets: {secrets_path}[/dim]")
                console.print(f"[dim]  Parameters: {params_path}[/dim]")
        
        elif choice == "2":  # AWS
            console.print(f"\n[bold cyan]AWS Configuration for '{name}'[/bold cyan]")
            region = Prompt.ask("AWS Region", default="us-east-1")
            aws_profile = Prompt.ask("AWS Profile (leave empty for default)", default="")
            prefix = Prompt.ask("Parameter Store prefix", default=f"/anysecret/{name}/")
            
            profile_config = {
                "secret_manager": {
                    "type": "aws",
                    "config": {
                        "region_name": region,
                        "cache_ttl": 300
                    }
                },
                "parameter_manager": {
                    "type": "aws_parameter_store",
                    "config": {
                        "region": region,
                        "prefix": prefix
                    }
                }
            }
            
            if aws_profile:
                profile_config["secret_manager"]["config"]["profile_name"] = aws_profile
                profile_config["parameter_manager"]["config"]["profile_name"] = aws_profile
        
        elif choice == "3":  # GCP
            console.print(f"\n[bold cyan]GCP Configuration for '{name}'[/bold cyan]")
            project_id = Prompt.ask("GCP Project ID")
            creds_path = Prompt.ask("Service Account JSON path (leave empty for default)", default="")
            prefix = Prompt.ask("Config prefix", default=f"anysecret-{name}")
            
            profile_config = {
                "secret_manager": {
                    "type": "gcp",
                    "config": {
                        "project_id": project_id,
                        "cache_ttl": 300
                    }
                },
                "parameter_manager": {
                    "type": "gcp_config_connector",
                    "config": {
                        "project_id": project_id,
                        "prefix": prefix
                    }
                }
            }
            
            if creds_path:
                profile_config["secret_manager"]["config"]["credentials_path"] = creds_path
                profile_config["parameter_manager"]["config"]["credentials_path"] = creds_path
        
        elif choice == "4":  # Azure
            console.print(f"\n[bold cyan]Azure Configuration for '{name}'[/bold cyan]")
            vault_url = Prompt.ask("Key Vault URL")
            tenant_id = Prompt.ask("Tenant ID")
            app_config_endpoint = Prompt.ask("App Configuration Endpoint")
            
            profile_config = {
                "secret_manager": {
                    "type": "azure",
                    "config": {
                        "vault_url": vault_url,
                        "tenant_id": tenant_id,
                        "cache_ttl": 300
                    }
                },
                "parameter_manager": {
                    "type": "azure_app_configuration",
                    "config": {
                        "endpoint": app_config_endpoint,
                        "label": name
                    }
                }
            }
        
        elif choice == "5":  # Kubernetes
            console.print(f"\n[bold cyan]Kubernetes Configuration for '{name}'[/bold cyan]")
            namespace = Prompt.ask("Namespace", default="default")
            
            profile_config = {
                "secret_manager": {
                    "type": "kubernetes",
                    "config": {
                        "namespace": namespace,
                        "secret_name": f"anysecret-{name}-secrets"
                    }
                },
                "parameter_manager": {
                    "type": "kubernetes_configmap",
                    "config": {
                        "namespace": namespace,
                        "configmap_name": f"anysecret-{name}-config"
                    }
                }
            }
        
        elif choice == "6":  # Vault
            console.print(f"\n[bold cyan]Vault Configuration for '{name}'[/bold cyan]")
            vault_url = Prompt.ask("Vault URL", default="http://localhost:8200")
            mount_point = Prompt.ask("Mount point", default="secret")
            
            # Vault doesn't support parameters, so use local file
            params_path = str(config_mgr.data_dir / f"parameters-{name}.json")
            
            profile_config = {
                "secret_manager": {
                    "type": "vault",
                    "config": {
                        "url": vault_url,
                        "mount_point": mount_point,
                        "cache_ttl": 300
                    }
                },
                "parameter_manager": {
                    "type": "file_json",
                    "config": {
                        "file_path": params_path
                    }
                }
            }
            
            # Create parameter file
            Path(params_path).write_text(json.dumps({
                "profile": name,
                "vault_url": vault_url
            }, indent=2))
            
            console.print("\n[yellow]Note: Vault doesn't support parameters, using local file[/yellow]")
        
        else:  # Custom
            console.print(f"\n[yellow]Manual configuration for '{name}'[/yellow]")
            profile_config = {
                "secret_manager": {"type": "env_file", "config": {}},
                "parameter_manager": {"type": "file_json", "config": {}}
            }
            console.print(f"[dim]You'll need to edit the config file manually after creation[/dim]")
        
        # Security Configuration - Write permissions
        console.print("\n[bold cyan]Security Settings[/bold cyan]")
        console.print("[dim]Configure write permissions for this profile[/dim]\n")
        
        console.print(Panel.fit(
            "[bold yellow]⚠️  Write Permissions[/bold yellow]\n\n"
            "Write operations include:\n"
            "• Creating new secrets and parameters\n"
            "• Updating existing values\n"
            "• Deleting configuration data\n\n"
            "[bold]Recommendation:[/bold] Keep disabled for production profiles",
            border_style="yellow"
        ))
        
        enable_writes = Confirm.ask(f"\nEnable write operations for profile '{name}'?", default=False)
        
        # Add metadata and permissions
        import datetime
        metadata = {
            "created": json.dumps({"timestamp": "now", "method": "cli"}),
            "description": Prompt.ask(f"Description for '{name}' profile (optional)", default="")
        }
        
        # Add write permissions
        if enable_writes:
            profile_config["permissions"] = {"write_enabled": True}
            metadata["write_permission_updated"] = {
                "timestamp": datetime.datetime.now().isoformat(),
                "enabled": True,
                "method": "cli"
            }
            console.print(f"\n[yellow]⚠️  Write operations enabled for profile '{name}'[/yellow]")
        else:
            profile_config["permissions"] = {"write_enabled": False}
            console.print(f"\n[green]✅ Profile '{name}' will be read-only (secure default)[/green]")
        
        # Create the profile
        config_mgr.create_profile(name, profile_config["secret_manager"], 
                                 profile_config["parameter_manager"], metadata)
        
        # Success message
        write_status = "ENABLED" if enable_writes else "DISABLED (secure default)"
        next_steps = [
            f"• Switch to profile: [cyan]anysecret config profile-use {name}[/cyan]",
            f"• Test configuration: [cyan]anysecret info[/cyan]",
            f"• View all profiles: [cyan]anysecret config profile-list[/cyan]"
        ]
        
        if enable_writes:
            next_steps.append(f"• Set a value: [cyan]anysecret set my-key my-value[/cyan]")
        else:
            next_steps.append(f"• Enable writes when needed: [cyan]anysecret config enable-writes --profile {name}[/cyan]")
        
        console.print(Panel.fit(
            f"[bold green]✅ Profile '{name}' created successfully![/bold green]\n\n"
            f"Write operations: [cyan]{write_status}[/cyan]\n\n"
            f"[dim]Next steps:[/dim]\n" + "\n".join(next_steps),
            border_style="green"
        ))
        
    except Exception as e:
        console.print(f"[red]❌ Error creating profile: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="profile-list")
@handle_errors
def list_profiles():
    """List available configuration profiles"""
    config_mgr = get_config_manager()
    
    if not config_mgr.config_file.exists():
        console.print("[red]❌ No configuration found![/red]")
        console.print("[dim]Run 'anysecret config init' to create configuration[/dim]")
        raise typer.Exit(1)
    
    try:
        profiles = config_mgr.list_profiles()
        current = config_mgr.get_current_profile()
        
        console.print(Panel.fit(
            "[bold cyan]Configuration Profiles[/bold cyan]",
            border_style="cyan"
        ))
        
        table = Table()
        table.add_column("Profile", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Secret Manager", style="yellow")
        table.add_column("Parameter Manager", style="yellow")
        
        for profile_name in profiles:
            try:
                profile = config_mgr.get_profile_config(profile_name)
                status = "✓ Active" if profile_name == current else ""
                sm_type = profile.secret_manager.get("type", "unknown")
                pm_type = profile.parameter_manager.get("type", "unknown")
                table.add_row(profile_name, status, sm_type, pm_type)
            except:
                table.add_row(profile_name, "Error", "-", "-")
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Error listing profiles: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="profile-use")
@handle_errors
def use_profile(name: str):
    """Switch to a different profile"""
    config_mgr = get_config_manager()
    
    try:
        config_mgr.set_current_profile(name)
        console.print(f"[green]✅ Switched to profile: [cyan]{name}[/cyan][/green]")
        
        # Show profile details
        profile = config_mgr.get_profile_config(name)
        console.print(f"[dim]Secret Manager: {profile.secret_manager.get('type')}[/dim]")
        console.print(f"[dim]Parameter Manager: {profile.parameter_manager.get('type')}[/dim]")
        
    except ValueError as e:
        console.print(f"[red]❌ {e}[/red]")
        console.print("[dim]Run 'anysecret config profile-list' to see available profiles[/dim]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error switching profile: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="profile-delete")
@handle_errors
def delete_profile(name: str):
    """Delete a configuration profile"""
    print_not_implemented(
        "anysecret config profile-delete",
        f"Will delete profile '{name}'"
    )


@app.command(name="profile-show")
@handle_errors
def show_profile(name: str):
    """Show details of a specific profile"""
    print_not_implemented(
        "anysecret config profile-show",
        f"Will show details for profile '{name}'"
    )


@app.command(name="profile-export")
@handle_errors
def export_profile(
    profile_name: Optional[str] = typer.Argument(None, help="Profile name to export (default: current profile)"),
    base64_encode: bool = typer.Option(True, "--base64/--no-base64", help="Encode output as base64"),
    encrypt: bool = typer.Option(False, "--encrypt", help="Encrypt the profile data"),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Write to file instead of stdout")
):
    """Export profile configuration for CI/CD use"""
    config_mgr = get_config_manager()
    
    try:
        # Get profile configuration
        if profile_name is None:
            profile_name = config_mgr.get_current_profile()
            
        profile_config = config_mgr.get_profile_config(profile_name)
        
        # Create exportable profile data
        export_data = {
            "version": "1.0",
            "profile_name": profile_name,
            "secret_manager": profile_config.secret_manager,
            "parameter_manager": profile_config.parameter_manager,
            "metadata": profile_config.metadata or {},
            "exported_at": json.dumps({"timestamp": "now", "method": "cli"}),
        }
        
        # Convert to JSON string
        json_data = json.dumps(export_data, indent=2)
        
        # Handle encryption if requested
        if encrypt:
            console.print("[yellow]🔒 Encryption enabled - you will be prompted for a passphrase[/yellow]")
            passphrase = getpass.getpass("Enter passphrase for encryption: ")
            confirm_passphrase = getpass.getpass("Confirm passphrase: ")
            
            if passphrase != confirm_passphrase:
                console.print("[red]❌ Passphrases don't match[/red]")
                raise typer.Exit(1)
                
            if len(passphrase) < 8:
                console.print("[red]❌ Passphrase must be at least 8 characters[/red]")
                raise typer.Exit(1)
            
            # Encrypt the data
            encrypted_data = _encrypt_data(json_data, passphrase)
            output_data = encrypted_data
            console.print("[green]✅ Profile data encrypted[/green]")
        else:
            output_data = json_data
        
        # Handle base64 encoding
        if base64_encode:
            encoded_data = base64.b64encode(output_data.encode('utf-8')).decode('utf-8')
            output_data = encoded_data
            console.print("[dim]✅ Profile data base64 encoded[/dim]")
        
        # Output the result
        if output_file:
            output_file.write_text(output_data)
            console.print(f"[green]✅ Profile '{profile_name}' exported to {output_file}[/green]")
        else:
            console.print(f"\n[bold cyan]📤 Exported Profile: {profile_name}[/bold cyan]")
            if encrypt:
                console.print("[yellow]🔒 Encrypted with passphrase[/yellow]")
            if base64_encode:
                console.print("[dim]📝 Base64 encoded[/dim]")
            console.print("\n[bold]Profile Data:[/bold]")
            print(output_data)
            
        # Show usage instructions
        console.print(f"\n[bold cyan]💡 Usage in CI/CD:[/bold cyan]")
        if encrypt:
            console.print("Set as environment variable and use with passphrase:")
            console.print(f"[dim]export ANYSECRET_PROFILE_DATA='{output_data[:50]}...'[/dim]")
            console.print("[dim]export ANYSECRET_PROFILE_PASSPHRASE='your_passphrase'[/dim]")
            console.print("[cyan]anysecret --profile-data \"$ANYSECRET_PROFILE_DATA\" --decrypt list[/cyan]")
        else:
            console.print("Set as environment variable and use:")
            console.print(f"[dim]export ANYSECRET_PROFILE_DATA='{output_data[:50]}...'[/dim]")
            console.print("[cyan]anysecret --profile-data \"$ANYSECRET_PROFILE_DATA\" list[/cyan]")
            
    except Exception as e:
        console.print(f"[red]❌ Export failed: {e}[/red]")
        raise typer.Exit(1)


def _encrypt_data(data: str, passphrase: str) -> str:
    """Encrypt data using a passphrase"""
    # Generate a key from the passphrase
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    
    # Encrypt the data
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data.encode())
    
    # Combine salt and encrypted data
    combined = base64.b64encode(salt + encrypted).decode('utf-8')
    return combined


def _decrypt_data(encrypted_data: str, passphrase: str) -> str:
    """Decrypt data using a passphrase"""
    try:
        # Decode the combined data
        combined = base64.b64decode(encrypted_data.encode())
        
        # Split salt and encrypted data
        salt = combined[:16]
        encrypted = combined[16:]
        
        # Generate key from passphrase
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
        
        # Decrypt
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted)
        return decrypted.decode()
        
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")


# Provider configuration
@app.command(name="provider-configure")
@handle_errors
def configure_provider(provider: str):
    """Configure a specific provider"""
    print_not_implemented(
        "anysecret config provider-configure",
        f"Will configure {provider} provider settings"
    )


@app.command(name="provider-test")
@handle_errors
def test_provider(provider: str):
    """Test provider connectivity"""
    print_not_implemented(
        "anysecret config provider-test",
        f"Will test connectivity to {provider} provider"
    )


# Pattern management
@app.command(name="patterns-show")
@handle_errors
def show_patterns():
    """Show classification patterns"""
    print_not_implemented(
        "anysecret config patterns-show",
        "Will show current secret/parameter classification patterns"
    )


@app.command(name="patterns-add-secret")
@handle_errors
def add_secret_pattern(pattern: str):
    """Add a secret classification pattern"""
    import re
    
    try:
        config_mgr = get_config_manager()
        
        # Validate the configuration exists
        if not config_mgr.config_file.exists():
            console.print("[red]❌ No configuration found![/red]")
            console.print("[dim]Run 'anysecret config init' to create configuration[/dim]")
            raise typer.Exit(1)
        
        # Validate the regex pattern
        try:
            re.compile(pattern)
        except re.error as e:
            console.print(f"[red]❌ Invalid regex pattern: {e}[/red]")
            console.print(f"[dim]Pattern: {pattern}[/dim]")
            raise typer.Exit(1)
        
        # Load current configuration
        config = config_mgr.load_config()
        
        # Ensure global_settings structure exists
        if "global_settings" not in config:
            config["global_settings"] = {}
        if "classification" not in config["global_settings"]:
            config["global_settings"]["classification"] = {}
        if "custom_secret_patterns" not in config["global_settings"]["classification"]:
            config["global_settings"]["classification"]["custom_secret_patterns"] = []
        
        # Check if pattern already exists
        existing_patterns = config["global_settings"]["classification"]["custom_secret_patterns"]
        if pattern in existing_patterns:
            console.print(f"[yellow]⚠️  Pattern already exists: [cyan]{pattern}[/cyan][/yellow]")
            console.print("[dim]Pattern was not added again[/dim]")
            return
        
        # Add the pattern
        existing_patterns.append(pattern)
        
        # Save configuration
        config_mgr.save_config(config)
        
        # Success message
        console.print(Panel.fit(
            f"[bold green]✅ Secret pattern added successfully![/bold green]\n\n"
            f"Pattern: [cyan]{pattern}[/cyan]\n"
            f"Total custom secret patterns: [yellow]{len(existing_patterns)}[/yellow]\n\n"
            "[dim]This pattern will now route matching keys to secret storage[/dim]",
            border_style="green"
        ))
        
        # Show examples of what would match
        console.print("\n[bold]Example keys that would match this pattern:[/bold]")
        
        # Generate some example matches based on common patterns
        examples = []
        if pattern.endswith("$"):
            # Suffix pattern
            suffix = pattern.replace(".*", "").replace("$", "")
            examples = [f"API{suffix}", f"DB{suffix}", f"USER{suffix}"]
        elif pattern.startswith(".*") and pattern.endswith(".*"):
            # Contains pattern
            middle = pattern.replace(".*", "")
            examples = [f"MY_{middle.upper()}_KEY", f"{middle.upper()}_CONFIG", f"APP_{middle.upper()}"]
        elif ".*" in pattern:
            # Complex pattern - show the pattern itself as guidance
            examples = [f"(matches pattern: {pattern})"]
        else:
            examples = [pattern]  # Literal match
        
        for example in examples[:3]:  # Show first 3 examples
            console.print(f"• [yellow]{example}[/yellow]")
        
        console.print(f"\n[bold]Next steps:[/bold]")
        console.print(f"• Test pattern: [cyan]anysecret config patterns-test YOUR_KEY[/cyan]")
        console.print(f"• View all patterns: [cyan]anysecret patterns show[/cyan]")
        console.print(f"• Set a secret: [cyan]anysecret set API{pattern.replace('.*', '').replace('$', '')} your-secret[/cyan]")
        
    except Exception as e:
        console.print(f"[red]❌ Error adding secret pattern: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="patterns-add-param")
@handle_errors
def add_parameter_pattern(pattern: str):
    """Add a parameter classification pattern"""
    import re
    
    try:
        config_mgr = get_config_manager()
        
        # Header
        console.print(Panel.fit(
            f"[bold cyan]🏷️  Adding Parameter Pattern[/bold cyan]\n"
            f"Pattern: [yellow]{pattern}[/yellow]",
            border_style="cyan"
        ))
        
        # Validate the configuration exists
        if not config_mgr.config_file.exists():
            console.print("[red]❌ No configuration found![/red]")
            console.print("[dim]Run 'anysecret config init' to create configuration[/dim]")
            raise typer.Exit(1)
        
        # Validate the regex pattern
        try:
            compiled_pattern = re.compile(pattern)
        except re.error as e:
            console.print(f"[red]❌ Invalid regex pattern: {e}[/red]")
            console.print(f"[dim]Pattern: {pattern}[/dim]")
            
            # Provide helpful examples
            console.print(f"\n[yellow]💡 Example parameter patterns:[/yellow]")
            console.print("• [cyan].*_config$[/cyan]     - Matches keys ending with '_config'")
            console.print("• [cyan]^app_.*[/cyan]       - Matches keys starting with 'app_'") 
            console.print("• [cyan].*setting.*[/cyan]   - Matches keys containing 'setting'")
            console.print("• [cyan]timeout|limit[/cyan] - Matches 'timeout' or 'limit'")
            
            raise typer.Exit(1)
        
        # Load current configuration
        config = config_mgr.load_config()
        
        # Ensure global_settings structure exists
        if "global_settings" not in config:
            config["global_settings"] = {}
        if "classification" not in config["global_settings"]:
            config["global_settings"]["classification"] = {}
        if "custom_parameter_patterns" not in config["global_settings"]["classification"]:
            config["global_settings"]["classification"]["custom_parameter_patterns"] = []
        
        # Check if pattern already exists
        existing_patterns = config["global_settings"]["classification"]["custom_parameter_patterns"]
        if pattern in existing_patterns:
            console.print(f"[yellow]⚠️  Pattern already exists: [cyan]{pattern}[/cyan][/yellow]")
            console.print("[dim]Pattern was not added again[/dim]")
            return
        
        # Add the pattern
        existing_patterns.append(pattern)
        
        # Save configuration
        config_mgr.save_config(config)
        
        # Success message
        console.print(Panel.fit(
            f"[bold green]✅ Parameter pattern added successfully![/bold green]\n\n"
            f"Pattern: [cyan]{pattern}[/cyan]\n"
            f"Total custom parameter patterns: [yellow]{len(existing_patterns)}[/yellow]\n\n"
            "[dim]This pattern will now route matching keys to parameter storage[/dim]",
            border_style="green"
        ))
        
        # Show examples of what would match
        console.print("\n[bold]Example keys that would match this pattern:[/bold]")
        
        # Generate some example matches based on common patterns
        examples = []
        if pattern.endswith("$"):
            # Suffix pattern
            base = pattern.replace(".*_", "").replace("$", "")
            examples.extend([f"app_{base}", f"user_{base}", f"system_{base}"])
        elif pattern.startswith("^"):
            # Prefix pattern  
            base = pattern.replace("^", "").replace(".*", "")
            examples.extend([f"{base}config", f"{base}setting", f"{base}value"])
        elif "config" in pattern.lower():
            examples.extend(["database_config", "server_config", "app_config"])
        elif "setting" in pattern.lower():
            examples.extend(["user_setting", "display_setting", "cache_setting"])
        elif "timeout" in pattern.lower() or "limit" in pattern.lower():
            examples.extend(["request_timeout", "connection_limit", "retry_timeout"])
        else:
            # Generic parameter examples
            examples.extend(["max_connections", "default_timeout", "buffer_size"])
        
        # Test examples against the pattern and show matches
        matched_examples = []
        for example in examples:
            if compiled_pattern.match(example):
                matched_examples.append(example)
        
        if matched_examples:
            for example in matched_examples[:3]:  # Show first 3 matches
                console.print(f"  • [yellow]{example}[/yellow]")
            if len(matched_examples) > 3:
                console.print(f"  [dim]... and {len(matched_examples) - 3} more[/dim]")
        else:
            console.print("  [dim]No standard examples match this pattern[/dim]")
            console.print(f"  [dim]Test with: anysecret config patterns-test <key_name>[/dim]")
        
        # Usage guidance
        console.print(f"\n[bold]Next Steps:[/bold]")
        console.print("• [cyan]anysecret config patterns show[/cyan] - View all patterns")
        console.print("• [cyan]anysecret get <key>[/cyan] - Test pattern classification")
        console.print("• [cyan]anysecret status[/cyan] - Check current configuration")
        
    except Exception as e:
        console.print(f"[red]❌ Error adding parameter pattern: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="enable-writes")
@handle_errors
def enable_writes_command(
    profile: Optional[str] = typer.Option(None, "--profile", "-p", help="Profile name (default: current)"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt")
):
    """Enable write operations for a profile"""
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm
    
    console = Console()
    
    try:
        config_mgr = get_config_manager()
        
        # Validate the configuration exists
        if not config_mgr.config_file.exists():
            console.print("[red]❌ No configuration found![/red]")
            console.print("[dim]Run 'anysecret config init' to create configuration[/dim]")
            raise typer.Exit(1)
        
        profile_name = profile if profile else config_mgr.get_current_profile()
        
        # Check if already enabled
        if config_mgr.is_write_enabled(profile_name):
            console.print(f"[yellow]⚠️  Write operations already enabled for profile '[cyan]{profile_name}[/cyan]'[/yellow]")
            return
        
        # Warning panel
        console.print(Panel.fit(
            "[bold yellow]⚠️  SECURITY WARNING[/bold yellow]\n\n"
            f"You are about to enable write operations for profile: [cyan]{profile_name}[/cyan]\n\n"
            "This will allow:\n"
            "• Creating new secrets and parameters\n"
            "• Updating existing values\n"
            "• Deleting configuration data\n\n"
            "[bold red]Only enable writes in trusted environments![/bold red]",
            border_style="yellow"
        ))
        
        # Confirm the action (unless --yes flag is used)
        if not yes and not Confirm.ask(f"\nEnable write operations for profile '{profile_name}'?", default=False):
            console.print("[dim]Write operations remain disabled[/dim]")
            return
        
        # Enable writes
        config_mgr.enable_writes(profile_name, True)
        
        # Success message
        console.print(Panel.fit(
            f"[bold green]✅ Write operations enabled![/bold green]\n\n"
            f"Profile: [cyan]{profile_name}[/cyan]\n"
            f"Write operations: [green]ENABLED[/green]\n\n"
            "[dim]You can now use set, delete, and other write commands[/dim]",
            border_style="green"
        ))
        
        console.print(f"\n[bold]Next steps:[/bold]")
        console.print("• [cyan]anysecret set <key> <value>[/cyan] - Create/update configuration")
        console.print("• [cyan]anysecret config disable-writes[/cyan] - Disable writes when done")
        console.print("• [cyan]anysecret status[/cyan] - Check current permissions")
        
    except Exception as e:
        console.print(f"[red]❌ Error enabling writes: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="disable-writes")
@handle_errors
def disable_writes_command(
    profile: Optional[str] = typer.Option(None, "--profile", "-p", help="Profile name (default: current)")
):
    """Disable write operations for a profile (default security setting)"""
    from rich.console import Console
    from rich.panel import Panel
    
    console = Console()
    
    try:
        config_mgr = get_config_manager()
        
        # Validate the configuration exists
        if not config_mgr.config_file.exists():
            console.print("[red]❌ No configuration found![/red]")
            console.print("[dim]Run 'anysecret config init' to create configuration[/dim]")
            raise typer.Exit(1)
        
        profile_name = profile if profile else config_mgr.get_current_profile()
        
        # Check if already disabled
        if not config_mgr.is_write_enabled(profile_name):
            console.print(f"[green]✅ Write operations already disabled for profile '[cyan]{profile_name}[/cyan]'[/green]")
            return
        
        # Disable writes
        config_mgr.enable_writes(profile_name, False)
        
        # Success message
        console.print(Panel.fit(
            f"[bold green]✅ Write operations disabled![/bold green]\n\n"
            f"Profile: [cyan]{profile_name}[/cyan]\n"
            f"Write operations: [red]DISABLED[/red]\n\n"
            "[dim]Profile is now read-only for security[/dim]",
            border_style="green"
        ))
        
        console.print(f"\n[bold]Read-only operations available:[/bold]")
        console.print("• [cyan]anysecret list[/cyan] - List all configuration")
        console.print("• [cyan]anysecret get <key>[/cyan] - Retrieve values")
        console.print("• [cyan]anysecret config enable-writes[/cyan] - Re-enable when needed")
        
    except Exception as e:
        console.print(f"[red]❌ Error disabling writes: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="check-permissions")
@handle_errors
def check_permissions_command(
    profile: Optional[str] = typer.Option(None, "--profile", "-p", help="Profile name (default: current)")
):
    """Check write permissions for a profile"""
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    
    console = Console()
    
    try:
        config_mgr = get_config_manager()
        
        # Validate the configuration exists
        if not config_mgr.config_file.exists():
            console.print("[red]❌ No configuration found![/red]")
            console.print("[dim]Run 'anysecret config init' to create configuration[/dim]")
            raise typer.Exit(1)
        
        if profile:
            profiles_to_check = [profile]
        else:
            # Check all profiles
            profiles_to_check = config_mgr.list_profiles()
            current_profile = config_mgr.get_current_profile()
        
        # Header
        console.print(Panel.fit(
            "[bold cyan]🔒 Write Permissions Status[/bold cyan]\n"
            "AnySecret is read-only by default for security",
            border_style="cyan"
        ))
        
        # Create table
        table = Table()
        table.add_column("Profile", style="cyan", width=15)
        table.add_column("Status", style="", width=12)
        table.add_column("Write Operations", style="", width=18)
        table.add_column("Last Updated", style="dim", width=20)
        
        for profile_name in profiles_to_check:
            try:
                is_enabled = config_mgr.is_write_enabled(profile_name)
                # Get raw config data
                config_data = config_mgr.load_config()
                profile_config = config_data.get("profiles", {}).get(profile_name, {})
                
                # Status indicators
                if profile_name == (current_profile if not profile else profile_name):
                    profile_display = f"{profile_name} [dim](current)[/dim]"
                else:
                    profile_display = profile_name
                
                if is_enabled:
                    status = "[red]⚠️  ENABLED[/red]"
                    operations = "[yellow]set, delete, update[/yellow]"
                else:
                    status = "[green]✅ DISABLED[/green]"
                    operations = "[dim]read-only[/dim]"
                
                # Get last updated info
                last_updated = "Never"
                if ("metadata" in profile_config and 
                    "write_permission_updated" in profile_config["metadata"]):
                    update_info = profile_config["metadata"]["write_permission_updated"]
                    timestamp = update_info.get("timestamp", "Unknown")
                    if timestamp != "Unknown":
                        # Format timestamp nicely
                        from datetime import datetime
                        try:
                            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                            last_updated = dt.strftime("%Y-%m-%d %H:%M")
                        except:
                            last_updated = timestamp[:16]  # Fallback
                
                table.add_row(profile_display, status, operations, last_updated)
                
            except Exception as e:
                table.add_row(profile_name, "[red]ERROR[/red]", f"[red]{str(e)[:15]}...[/red]", "Error")
        
        console.print(table)
        
        # Security recommendations
        console.print(f"\n[bold]Security Recommendations:[/bold]")
        console.print("• Keep profiles read-only in production environments")
        console.print("• Only enable writes temporarily when needed")
        console.print("• Disable writes immediately after bulk operations")
        console.print("• Use separate development profiles for testing")
        
        console.print(f"\n[bold]Commands:[/bold]")
        console.print("• [cyan]anysecret config enable-writes[/cyan] - Enable writes for current profile")
        console.print("• [cyan]anysecret config disable-writes[/cyan] - Disable writes (secure default)")
        console.print("• [cyan]anysecret config enable-writes --profile <name>[/cyan] - Enable for specific profile")
        
    except Exception as e:
        console.print(f"[red]❌ Error checking permissions: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="patterns-remove")
@handle_errors
def remove_pattern(pattern: str):
    """Remove a classification pattern"""
    print_not_implemented(
        "anysecret config patterns-remove",
        f"Will remove pattern: {pattern}"
    )


@app.command(name="patterns-test")
@handle_errors
def test_pattern(key: str):
    """Test key classification"""
    print_not_implemented(
        "anysecret config patterns-test",
        f"Will test classification for key: {key}"
    )


@app.command(name="patterns-export")
@handle_errors
def export_patterns(
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file")
):
    """Export patterns to file"""
    print_not_implemented(
        "anysecret config patterns-export",
        f"Will export patterns to {output or 'default file'}"
    )


@app.command(name="patterns-import")
@handle_errors
def import_patterns(file: Path):
    """Import patterns from file"""
    print_not_implemented(
        "anysecret config patterns-import",
        f"Will import patterns from {file}"
    )


# Legacy compatibility commands (called from main CLI)
def info():
    """Show system information and current configuration"""
    import platform
    import sys
    from pathlib import Path
    
    try:
        config_mgr = get_config_manager()
        
        # Header
        console.print("╭─ AnySecret System Information ─────────────────────────────────────────╮")
        
        # System Information
        console.print(f"│ System: {platform.system()} {platform.release()} ({platform.machine()})")
        console.print(f"│ Python: {sys.version.split()[0]} ({sys.executable})")
        console.print(f"│ AnySecret: {Path(__file__).parent.parent.parent.parent}")
        console.print("│")
        
        # Configuration Status
        config_info = config_mgr.get_config_info()
        console.print(f"│ Config Directory: {config_info['config_dir']}")
        console.print(f"│ Config File: {'✅ Found' if config_info['config_exists'] else '❌ Missing'}")
        console.print(f"│ Current Profile: {config_info['current_profile']}")
        console.print(f"│ Available Profiles: {', '.join(config_info['available_profiles'])}")
        console.print("│")
        
        if config_info['config_exists']:
            # Current Profile Details
            try:
                profile = config_mgr.get_profile_config()
                console.print("│ Active Configuration:")
                console.print(f"│   Secret Manager: {profile.secret_manager['type']}")
                secret_config = {k: v for k, v in profile.secret_manager.get('config', {}).items() if k != 'cache_ttl'}
                if secret_config:
                    for key, value in secret_config.items():
                        # Mask sensitive values
                        display_value = "***" if any(sensitive in key.lower() for sensitive in ['key', 'secret', 'token', 'password']) else str(value)
                        console.print(f"│     {key}: {display_value}")
                
                console.print(f"│   Parameter Manager: {profile.parameter_manager['type']}")
                param_config = profile.parameter_manager.get('config', {})
                if param_config:
                    for key, value in param_config.items():
                        display_value = "***" if any(sensitive in key.lower() for sensitive in ['key', 'secret', 'token', 'password']) else str(value)
                        console.print(f"│     {key}: {display_value}")
                        
            except Exception as e:
                console.print(f"│ ⚠️  Profile Error: {e}")
                
            console.print("│")
            
            # Provider Health Check
            console.print("│ Provider Status:")
            try:
                from ...config_loader import load_from_cli_config, initialize_config
                from ...config import get_secret_manager, get_parameter_manager
                import asyncio
                import logging
                
                # Suppress noisy log messages during info check
                logging.getLogger().setLevel(logging.ERROR)
                
                # Initialize config to ensure providers are set up
                initialize_config()
                
                # Test secret manager
                try:
                    secret_mgr = asyncio.run(get_secret_manager())
                    console.print("│   Secret Manager: ✅ Connected")
                    
                    # Test basic operation quietly
                    try:
                        secrets = asyncio.run(secret_mgr.list_secrets())
                        console.print(f"│     Available secrets: {len(secrets)}")
                        if secrets:
                            sample_secrets = secrets[:3]  # Show first 3
                            console.print(f"│     Examples: {', '.join(sample_secrets)}")
                    except Exception:
                        console.print("│     Available secrets: Unable to list")
                        
                except Exception as e:
                    error_msg = str(e).replace("Secret manager health check failed", "Connection failed")
                    console.print(f"│   Secret Manager: ❌ {error_msg[:40]}...")
                
                # Test parameter manager
                try:
                    param_mgr = asyncio.run(get_parameter_manager())
                    console.print("│   Parameter Manager: ✅ Connected")
                    
                    # Test basic operation quietly
                    try:
                        params = asyncio.run(param_mgr.list_parameters())
                        console.print(f"│     Available parameters: {len(params)}")
                        if params:
                            sample_params = params[:3]  # Show first 3
                            console.print(f"│     Examples: {', '.join(sample_params)}")
                    except Exception:
                        console.print("│     Available parameters: Unable to list")
                        
                except Exception as e:
                    error_msg = str(e).replace("Secret manager health check failed", "Connection failed")
                    console.print(f"│   Parameter Manager: ❌ {error_msg[:40]}...")
                        
            except Exception as e:
                console.print(f"│   Provider initialization failed: {str(e)[:40]}...")
        
        else:
            console.print("│ ⚠️  No configuration found. Run 'anysecret config init' to get started.")
            
        console.print("╰─────────────────────────────────────────────────────────────────────────╯")
        
    except Exception as e:
        console.print(f"[red]❌ Error retrieving system information: {e}[/red]")
        import traceback
        traceback.print_exc()


def status():
    """Show provider status across all profiles"""
    import asyncio
    import logging
    from rich.table import Table
    
    try:
        config_mgr = get_config_manager()
        
        # Header
        console.print(Panel.fit(
            "[bold cyan]🔍 Provider Status Overview[/bold cyan]\n"
            "Health check across all profiles and providers",
            border_style="cyan"
        ))
        
        if not config_mgr.config_file.exists():
            console.print("[red]❌ No configuration found![/red]")
            console.print("[dim]Run 'anysecret config init' to create configuration[/dim]")
            return
        
        # Suppress noisy logging
        logging.getLogger().setLevel(logging.ERROR)
        
        # Create status table
        table = Table()
        table.add_column("Profile", style="cyan")
        table.add_column("Current", style="green") 
        table.add_column("Write Access", style="")
        table.add_column("Secret Manager", style="yellow")
        table.add_column("Secret Status", style="")
        table.add_column("Parameter Manager", style="yellow")
        table.add_column("Parameter Status", style="")
        table.add_column("Data Count", style="dim")
        
        profiles = config_mgr.list_profiles()
        current_profile = config_mgr.get_current_profile()
        
        for profile_name in profiles:
            try:
                # Get profile configuration
                profile = config_mgr.get_profile_config(profile_name)
                is_current = "✓" if profile_name == current_profile else ""
                
                secret_type = profile.secret_manager.get('type', 'unknown')
                param_type = profile.parameter_manager.get('type', 'unknown')
                
                # Test providers by temporarily switching if needed
                original_profile = current_profile
                secret_status = "❌"
                param_status = "❌"
                data_info = "0/0"
                
                try:
                    # Switch to this profile temporarily for testing
                    if profile_name != current_profile:
                        config_mgr.set_current_profile(profile_name)
                    
                    # Initialize config for this profile
                    from ...config_loader import initialize_config
                    from ...config import get_secret_manager, get_parameter_manager
                    
                    initialize_config()
                    
                    # Test secret manager
                    secret_count = 0
                    try:
                        secret_mgr = asyncio.run(get_secret_manager())
                        secrets = asyncio.run(secret_mgr.list_secrets())
                        secret_count = len(secrets)
                        secret_status = "✅"
                    except Exception as e:
                        secret_status = f"❌ {str(e)[:20]}..."
                    
                    # Test parameter manager
                    param_count = 0
                    try:
                        param_mgr = asyncio.run(get_parameter_manager())
                        params = asyncio.run(param_mgr.list_parameters())
                        param_count = len(params)
                        param_status = "✅"
                    except Exception as e:
                        param_status = f"❌ {str(e)[:20]}..."
                    
                    data_info = f"{secret_count}/{param_count}"
                    
                except Exception as e:
                    secret_status = f"❌ Config error"
                    param_status = f"❌ Config error"
                    data_info = "?/?"
                
                finally:
                    # Restore original profile
                    if original_profile != profile_name:
                        try:
                            config_mgr.set_current_profile(original_profile)
                        except:
                            pass
                
                # Check write permissions
                write_enabled = config_mgr.is_write_enabled(profile_name)
                write_status = "[red]🔒 Disabled[/red]" if not write_enabled else "[yellow]⚠️  Enabled[/yellow]"
                
                # Add row to table
                table.add_row(
                    profile_name,
                    is_current,
                    write_status,
                    secret_type,
                    secret_status,
                    param_type, 
                    param_status,
                    data_info
                )
                
            except Exception as e:
                # Add error row
                table.add_row(
                    profile_name,
                    is_current,
                    "[red]ERROR[/red]",
                    "error",
                    f"❌ {str(e)[:20]}...",
                    "error",
                    f"❌ {str(e)[:20]}...",
                    "?/?"
                )
        
        console.print(table)
        
        # Summary
        console.print(f"\n[dim]Legend: Data Count shows secrets/parameters available[/dim]")
        console.print(f"[dim]Current profile: [cyan]{current_profile}[/cyan][/dim]")
        console.print(f"[dim]Write Access: [red]🔒 Disabled[/red] (secure default), [yellow]⚠️  Enabled[/yellow] (use with caution)[/dim]")
        
        # Quick actions
        console.print(f"\n[bold]Quick Actions:[/bold]")
        console.print(f"• Switch profile: [cyan]anysecret config profile-use <name>[/cyan]")
        console.print(f"• Enable writes: [cyan]anysecret config enable-writes[/cyan]")
        console.print(f"• Check permissions: [cyan]anysecret config check-permissions[/cyan]")
        console.print(f"• Detailed info: [cyan]anysecret info[/cyan]")
        
    except Exception as e:
        console.print(f"[red]❌ Error retrieving status: {e}[/red]")
        import traceback
        traceback.print_exc()


def show_patterns():
    """Show classification patterns (legacy compatibility)"""
    from rich.table import Table
    from ...config_manager import ConfigManager as LegacyConfigManager
    
    try:
        config_mgr = get_config_manager()
        
        # Header
        console.print(Panel.fit(
            "[bold green]🔍 Classification Patterns[/bold green]\n"
            "Patterns used to route keys to secrets vs parameters",
            border_style="green"
        ))
        
        # Get current configuration to load custom patterns
        try:
            config = config_mgr.load_config()
            global_settings = config.get("global_settings", {})
            classification = global_settings.get("classification", {})
            custom_secret_patterns = classification.get("custom_secret_patterns", [])
            custom_parameter_patterns = classification.get("custom_parameter_patterns", [])
        except:
            custom_secret_patterns = []
            custom_parameter_patterns = []
        
        # Create a temporary ConfigManager instance to get default patterns
        temp_secret_config = {"type": "env_file", "file_path": ".env"}
        temp_param_config = {"type": "file_json", "file_path": "config.json"}
        legacy_mgr = LegacyConfigManager(temp_secret_config, temp_param_config)
        
        # Get all patterns (built-in + custom)
        all_secret_patterns = legacy_mgr.SECRET_PATTERNS + custom_secret_patterns
        all_param_patterns = legacy_mgr.PARAMETER_PATTERNS + custom_parameter_patterns
        
        console.print("\n[bold cyan]🔐 Secret Patterns[/bold cyan]")
        console.print("[dim]Keys matching these patterns are stored as secrets (encrypted)[/dim]")
        
        secret_table = Table()
        secret_table.add_column("Pattern", style="yellow", width=25)
        secret_table.add_column("Type", style="green", width=10)
        secret_table.add_column("Example Matches", style="dim", width=40)
        
        # Built-in secret patterns
        for pattern in legacy_mgr.SECRET_PATTERNS:
            examples = []
            # Generate some example matches for common patterns
            if pattern == r'.*_secret$':
                examples = ["API_SECRET", "DB_SECRET"]
            elif pattern == r'.*_password$':
                examples = ["DB_PASSWORD", "USER_PASSWORD"]
            elif pattern == r'.*_key$':
                examples = ["API_KEY", "ENCRYPTION_KEY"]
            elif pattern == r'.*_token$':
                examples = ["AUTH_TOKEN", "ACCESS_TOKEN"]
            elif pattern == r'.*password.*':
                examples = ["PASSWORD", "ADMIN_PASSWORD"]
            elif pattern == r'.*secret.*':
                examples = ["SECRET_CONFIG", "CLIENT_SECRET"]
            elif pattern == r'.*key.*':
                examples = ["PRIVATE_KEY", "MASTER_KEY"]
            elif pattern == r'.*token.*':
                examples = ["JWT_TOKEN", "REFRESH_TOKEN"]
            else:
                examples = ["(pattern-based)"]
            
            secret_table.add_row(
                f"`{pattern}`",
                "Built-in",
                ", ".join(examples)
            )
        
        # Custom secret patterns
        for pattern in custom_secret_patterns:
            secret_table.add_row(
                f"`{pattern}`",
                "Custom",
                "(user-defined)"
            )
        
        console.print(secret_table)
        
        console.print("\n[bold cyan]⚙️  Parameter Patterns[/bold cyan]")
        console.print("[dim]Keys matching these patterns are stored as parameters (configuration)[/dim]")
        
        param_table = Table()
        param_table.add_column("Pattern", style="yellow", width=25)
        param_table.add_column("Type", style="green", width=10)
        param_table.add_column("Example Matches", style="dim", width=40)
        
        # Built-in parameter patterns
        for pattern in legacy_mgr.PARAMETER_PATTERNS:
            examples = []
            # Generate example matches
            if pattern == r'.*_config$':
                examples = ["DB_CONFIG", "API_CONFIG"]
            elif pattern == r'.*_timeout$':
                examples = ["REQUEST_TIMEOUT", "DB_TIMEOUT"]
            elif pattern == r'.*_host$':
                examples = ["DB_HOST", "REDIS_HOST"]
            elif pattern == r'.*_port$':
                examples = ["DB_PORT", "SERVICE_PORT"]
            elif pattern == r'.*_url$':
                examples = ["API_URL", "WEBHOOK_URL"]
            elif pattern == r'.*config.*':
                examples = ["CONFIG_FILE", "APP_CONFIG"]
            elif pattern == r'.*setting.*':
                examples = ["DEBUG_SETTING", "LOG_SETTING"]
            else:
                examples = ["(pattern-based)"]
            
            param_table.add_row(
                f"`{pattern}`",
                "Built-in",
                ", ".join(examples)
            )
        
        # Custom parameter patterns
        for pattern in custom_parameter_patterns:
            param_table.add_row(
                f"`{pattern}`",
                "Custom", 
                "(user-defined)"
            )
        
        console.print(param_table)
        
        # Summary and examples
        console.print(f"\n[bold]Pattern Summary:[/bold]")
        console.print(f"• Secret patterns: {len(all_secret_patterns)} total ({len(legacy_mgr.SECRET_PATTERNS)} built-in + {len(custom_secret_patterns)} custom)")
        console.print(f"• Parameter patterns: {len(all_param_patterns)} total ({len(legacy_mgr.PARAMETER_PATTERNS)} built-in + {len(custom_parameter_patterns)} custom)")
        
        console.print(f"\n[bold]Classification Logic:[/bold]")
        console.print("1. Check explicit hint if provided")
        console.print("2. Match against secret patterns → Store as secret")
        console.print("3. Match against parameter patterns → Store as parameter")
        console.print("4. No match → Default to parameter")
        
        console.print(f"\n[bold]Usage Examples:[/bold]")
        console.print("• Test classification: [cyan]anysecret classify MY_API_KEY[/cyan]")
        console.print("• Add custom secret pattern: [cyan]anysecret config patterns-add-secret '.*_credentials$'[/cyan]")
        console.print("• Add custom param pattern: [cyan]anysecret config patterns-add-param '.*_setting$'[/cyan]")
        
    except Exception as e:
        console.print(f"[red]❌ Error showing patterns: {e}[/red]")
        import traceback
        traceback.print_exc()