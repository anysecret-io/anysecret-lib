"""
Modern AnySecret CLI Entrypoint
Built with Typer and modern CLI patterns
"""

import asyncio
import os
from pathlib import Path
from typing import Optional, Dict, Any
import json
import base64
import getpass

import typer
from rich.console import Console
from rich.panel import Panel
from rich import print as rprint

# Import command modules
from .commands import (
    config_commands,
    read_commands, 
    write_commands,
    sync_commands,
    bulk_commands,
    env_commands,
    security_commands,
    debug_commands,
    cicd_commands,
    multicloud_commands,
    providers_commands
)

# Import core decorators
from .core import requires_write_permission

# Create the main CLI app
app = typer.Typer(
    name="anysecret",
    help="🔐 AnySecret.io - Universal Configuration & Secret Manager",
    epilog="Visit https://anysecret.io for documentation and examples",
    no_args_is_help=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
    invoke_without_command=True
)

console = Console()


# Global options that apply to all commands
@app.callback()
def main(
    ctx: typer.Context,
    config: Optional[Path] = typer.Option(
        None,
        "--config", "-c",
        help="Configuration file path",
        envvar="ANYSECRET_CONFIG_FILE"
    ),
    profile: Optional[str] = typer.Option(
        None,
        "--profile", "-p", 
        help="Configuration profile to use",
        envvar="ANYSECRET_PROFILE"
    ),
    profile_data: Optional[str] = typer.Option(
        None,
        "--profile-data",
        help="Base64-encoded profile configuration for CI/CD",
        envvar="ANYSECRET_PROFILE_DATA"
    ),
    decrypt: bool = typer.Option(
        False,
        "--decrypt",
        help="Decrypt profile data (requires passphrase via ANYSECRET_PROFILE_PASSPHRASE)"
    ),
    provider: Optional[str] = typer.Option(
        None,
        "--provider",
        help="Override default provider",
        envvar="ANYSECRET_PROVIDER"
    ),
    region: Optional[str] = typer.Option(
        None,
        "--region",
        help="Override default region",
        envvar="ANYSECRET_REGION"
    ),
    output_format: Optional[str] = typer.Option(
        "table",
        "--format", "-f",
        help="Output format",
        envvar="ANYSECRET_OUTPUT_FORMAT"
    ),
    verbose: int = typer.Option(
        0,
        "--verbose", "-v",
        help="Verbose output (use multiple times for more verbosity)",
        count=True
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet", "-q",
        help="Suppress output"
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        help="Debug mode",
        envvar="ANYSECRET_DEBUG"
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show what would be done without executing"
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Disable caching"
    ),
    timeout: Optional[int] = typer.Option(
        None,
        "--timeout",
        help="Operation timeout in seconds",
        envvar="ANYSECRET_TIMEOUT"
    ),
    version: bool = typer.Option(
        False,
        "--version",
        help="Show version information and exit"
    ),
):
    """
    AnySecret CLI - Universal configuration and secret management
    
    Intelligently routes between secrets and parameters across multiple cloud providers
    with cost optimization and enterprise-grade security.
    """
    # Handle --version option
    if version:
        show_version()
        raise typer.Exit()
    
    # If no command provided and not just showing help, show help  
    if ctx.invoked_subcommand is None and not version:
        console.print(ctx.get_help())
        raise typer.Exit()
    
    # Process profile data if provided
    processed_profile_data = None
    if profile_data:
        processed_profile_data = _process_profile_data(profile_data, decrypt)
    
    # Store global options in context for commands to access
    ctx.obj = {
        'config': config,
        'profile': profile,
        'profile_data': processed_profile_data,
        'provider': provider,
        'region': region,
        'output_format': output_format,
        'verbose': verbose,
        'quiet': quiet,
        'debug': debug,
        'dry_run': dry_run,
        'no_cache': no_cache,
        'timeout': timeout,
    }


def _process_profile_data(profile_data: str, decrypt: bool = False) -> Dict[str, Any]:
    """Process base64-encoded profile data, with optional decryption"""
    try:
        # First decode from base64
        decoded_data = base64.b64decode(profile_data.encode()).decode('utf-8')
        
        # If decryption is requested, decrypt the data
        if decrypt:
            passphrase = os.getenv('ANYSECRET_PROFILE_PASSPHRASE')
            if not passphrase:
                console.print("[red]❌ Decryption requested but ANYSECRET_PROFILE_PASSPHRASE not set[/red]")
                raise typer.Exit(1)
            
            # Import the decrypt function (we'll need to make it accessible)
            from .commands.config_commands import _decrypt_data
            decoded_data = _decrypt_data(decoded_data, passphrase)
        
        # Parse as JSON
        profile_config = json.loads(decoded_data)
        
        # Validate profile structure
        required_fields = ['profile_name', 'secret_manager', 'parameter_manager']
        for field in required_fields:
            if field not in profile_config:
                raise ValueError(f"Missing required field: {field}")
        
        return profile_config
        
    except Exception as e:
        console.print(f"[red]❌ Failed to process profile data: {e}[/red]")
        console.print("[dim]Profile data should be base64-encoded JSON from 'anysecret config profile-export'[/dim]")
        raise typer.Exit(1)


# Add all command modules
app.add_typer(config_commands.app, name="config", help="🔧 Configuration management")
app.add_typer(read_commands.app, name="read", help="📖 Read operations") 
app.add_typer(write_commands.app, name="write", help="✏️  Write operations")
app.add_typer(sync_commands.app, name="sync", help="🔄 Sync and migration")
app.add_typer(bulk_commands.app, name="bulk", help="📦 Bulk operations")
app.add_typer(env_commands.app, name="env", help="🌍 Environment management")
app.add_typer(security_commands.app, name="security", help="🔐 Security operations")
app.add_typer(debug_commands.app, name="debug", help="🐛 Debug and monitoring") 
app.add_typer(cicd_commands.app, name="ci", help="🚀 CI/CD integration")
app.add_typer(multicloud_commands.app, name="cloud", help="☁️  Multi-cloud operations")
app.add_typer(providers_commands.app, name="providers", help="🏪 Provider management")

# Legacy compatibility - expose common commands at root level
@app.command(name="info")
def info():
    """Show system information and current configuration"""
    return config_commands.info()

@app.command(name="status")  
def status():
    """Show status of all providers"""
    return config_commands.status()

@app.command(name="list")
def list_configs(
    prefix: Optional[str] = typer.Option(None, "--prefix", "-p", help="Filter by prefix"),
    secrets_only: bool = typer.Option(False, "--secrets-only", help="Show only secrets"),
    parameters_only: bool = typer.Option(False, "--parameters-only", help="Show only parameters"),
    show_values: bool = typer.Option(False, "--values", "-v", help="Show parameter values"),
    format_output: Optional[str] = typer.Option(None, "--format", help="Output format: table|json|yaml"),
    pattern: Optional[str] = typer.Option(None, "--pattern", help="Filter by regex pattern")
):
    """List all configuration keys"""
    # Call the async implementation directly
    import asyncio
    try:
        result = asyncio.run(read_commands.list_configs_async(
            prefix=prefix,
            secrets_only=secrets_only, 
            parameters_only=parameters_only, 
            show_values=show_values,
            pattern=pattern,
            format_output=format_output,
            modified_since=None,
            tags=None
        ))
        return result
    except Exception:
        # Handle any async wrapper errors gracefully
        return

@app.command(name="get")
def get_value(
    key: str,
    hint: Optional[str] = typer.Option(None, "--hint", "-h", help="Classification hint: secret|parameter"),
    metadata: bool = typer.Option(False, "--metadata", "-m", help="Show metadata"),
    raw: bool = typer.Option(False, "--raw", help="Raw output without formatting"),
    format_output: Optional[str] = typer.Option(None, "--format", help="Output format: table|json|yaml")
):
    """Get a configuration value with intelligent routing"""
    # Call the async implementation directly
    import asyncio
    try:
        result = asyncio.run(read_commands.get_value_async(
            key=key,
            hint=hint,
            metadata=metadata,
            raw=raw,
            format_output=format_output
        ))
        return result
    except Exception:
        # Handle any async wrapper errors gracefully
        return

@app.command(name="set") 
def set_value(
    key: str,
    value: str,
    hint: Optional[str] = typer.Option(None, "--hint", "-h", help="Classification hint: secret|parameter"),
    json_value: bool = typer.Option(False, "--json", help="Parse value as JSON"),
    base64: bool = typer.Option(False, "--base64", help="Decode base64 value"),
    if_not_exists: bool = typer.Option(False, "--if-not-exists", help="Only set if key doesn't exist")
):
    """Set a configuration value with intelligent routing"""
    # Import and run the write logic directly
    import asyncio
    from ..config_loader import initialize_config
    from ..config import get_secret_manager, get_parameter_manager
    from ..config_manager import ConfigManager
    from rich.console import Console
    from rich.panel import Panel
    import json as json_lib
    import base64 as b64_lib
    
    console = Console()
    
    async def _set_value():
        # Initialize configuration
        initialize_config()
        
        # Get managers
        secret_mgr = await get_secret_manager()
        param_mgr = await get_parameter_manager()
        
        # Process value transformations
        processed_value = value
        
        # Handle base64 decoding
        if base64:
            try:
                processed_value = b64_lib.b64decode(value).decode('utf-8')
            except Exception:
                console.print("[red]❌ Invalid base64 value[/red]")
                raise typer.Exit(1)
        
        # Handle JSON parsing
        if json_value:
            try:
                json_lib.loads(processed_value)  # Validate JSON
            except json_lib.JSONDecodeError:
                console.print("[red]❌ Invalid JSON value[/red]")
                raise typer.Exit(1)
        
        # Check if_not_exists
        if if_not_exists:
            try:
                existing = await secret_mgr.get_secret(key)
                if existing:
                    console.print(f"[yellow]Key '{key}' already exists (skipped)[/yellow]")
                    return
            except:
                pass
            try:
                existing = await param_mgr.get_parameter(key)
                if existing:
                    console.print(f"[yellow]Key '{key}' already exists (skipped)[/yellow]")
                    return
            except:
                pass
        
        # Determine classification
        classification = hint
        if not classification:
            # Use pattern matching directly
            if any(pattern in key.lower() for pattern in ['secret', 'password', 'key', 'token', 'api', 'credential']):
                classification = 'secret'
            else:
                classification = 'parameter'
        
        # Set value
        success = False
        storage_type = None
        
        if classification == 'secret':
            try:
                try:
                    await secret_mgr.create_secret(key, processed_value)
                    success = True
                except Exception as e:
                    if "already exists" in str(e).lower():
                        await secret_mgr.update_secret(key, processed_value)
                        success = True
                    else:
                        raise
                storage_type = secret_mgr.__class__.__name__.replace('SecretManager', '').replace('Manager', '')
            except Exception as e:
                if "already exists" not in str(e).lower():
                    try:
                        await param_mgr.create_parameter(key, processed_value)
                        success = True
                        classification = 'parameter'
                        storage_type = param_mgr.__class__.__name__.replace('ParameterManager', '').replace('Manager', '')
                    except Exception as pe:
                        console.print(f"[red]❌ Failed to set: {e}[/red]")
                        raise typer.Exit(1)
                else:
                    console.print(f"[red]❌ Failed to set: {e}[/red]")
                    raise typer.Exit(1)
        else:
            try:
                try:
                    await param_mgr.create_parameter(key, processed_value)
                    success = True
                except Exception as e:
                    print(f"DEBUG: create_parameter failed with: {e}")
                    if "already exists" in str(e).lower():
                        await param_mgr.update_parameter(key, processed_value)
                        success = True
                    else:
                        raise
                storage_type = param_mgr.__class__.__name__.replace('ParameterManagerClient', '').replace('ParameterManager', '').replace('Manager', '')
            except Exception as e:
                if "already exists" not in str(e).lower():
                    try:
                        await secret_mgr.create_secret(key, processed_value)
                        success = True
                        classification = 'secret'
                        storage_type = secret_mgr.__class__.__name__.replace('SecretManager', '').replace('Manager', '')
                    except Exception as se:
                        console.print(f"[red]❌ Failed to set: {e}[/red]")
                        raise typer.Exit(1)
                else:
                    console.print(f"[red]❌ Failed to set: {e}[/red]")
                    raise typer.Exit(1)
        
        if success:
            icon = '🔐' if classification == 'secret' else '⚙️'
            console.print(Panel.fit(
                f"[bold green]✅ Value Set Successfully[/bold green]\n\n"
                f"Key: {key}\n"
                f"Type: {icon} {'Secret' if classification == 'secret' else 'Parameter'}\n"
                f"Storage: {storage_type}\n"
                f"Value Length: {len(processed_value)} characters",
                border_style="green"
            ))
            console.print(f"\nNext steps:\n• Retrieve value: anysecret get {key}")
            if classification == 'secret':
                console.print(f"• Show value: anysecret get {key} --raw")
    
    asyncio.run(_set_value())

@app.command(name="delete")
@requires_write_permission
def delete_value(
    key: str,
    hint: Optional[str] = typer.Option(None, "--hint", "-h", help="Classification hint: secret|parameter"),
    force: bool = typer.Option(False, "--force", help="Skip confirmation"),
    backup: bool = typer.Option(True, "--backup/--no-backup", help="Create backup before deletion")
):
    """Delete a configuration value"""
    import asyncio
    try:
        return asyncio.run(write_commands.delete_value(
            key=key,
            hint=hint,
            force=force,
            backup=backup
        ))
    except Exception:
        return

@app.command(name="health")
def health_check():
    """Check health of all providers"""
    return debug_commands.health_check()

@app.command(name="patterns")
def show_patterns():
    """Show classification patterns"""
    return config_commands.show_patterns()

@app.command(name="classify")
def classify_key(key: str):
    """Test how a key would be classified"""
    return read_commands.classify_key(key)


# Version command
@app.command(name="version")
def show_version():
    """Show version information"""
    try:
        from anysecret import __version__
        version = __version__
    except ImportError:
        version = "development"
    
    rprint(Panel.fit(
        f"[bold green]AnySecret CLI[/bold green]\n"
        f"Version: [cyan]{version}[/cyan]\n"
        f"Universal Configuration Manager",
        border_style="green"
    ))


def run_cli():
    """Entry point for the CLI"""
    try:
        app()
    except KeyboardInterrupt:
        rprint("\n[yellow]Interrupted by user[/yellow]")
        raise typer.Exit(130)
    except Exception as e:
        if os.getenv('ANYSECRET_DEBUG'):
            raise
        rprint(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    run_cli()