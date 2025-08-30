"""
Modern AnySecret CLI Entrypoint
Built with Typer and modern CLI patterns
"""

import asyncio
import os
from pathlib import Path
from typing import Optional

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
    context_settings={"help_option_names": ["-h", "--help"]}
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
):
    """
    AnySecret CLI - Universal configuration and secret management
    
    Intelligently routes between secrets and parameters across multiple cloud providers
    with cost optimization and enterprise-grade security.
    """
    # Store global options in context for commands to access
    ctx.obj = {
        'config': config,
        'profile': profile,
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
@requires_write_permission
def set_value(
    key: str,
    value: str,
    hint: Optional[str] = typer.Option(None, "--hint", "-h", help="Classification hint: secret|parameter"),
    json_value: bool = typer.Option(False, "--json", help="Parse value as JSON")
):
    """Set a configuration value with intelligent routing"""  
    return write_commands.set_value(key, value, hint, json_value)

@app.command(name="delete")
@requires_write_permission
def delete_value(
    key: str,
    hint: Optional[str] = typer.Option(None, "--hint", "-h", help="Classification hint: secret|parameter"),
    force: bool = typer.Option(False, "--force", help="Skip confirmation")
):
    """Delete a configuration value"""
    return write_commands.delete_value(key, hint, force)

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