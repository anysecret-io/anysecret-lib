# File: anysecret/cli/main.py (Enhanced)

import asyncio
import json
import os
from pathlib import Path
from typing import Optional, Dict, Any
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

from ..config import get_config_manager, get_unified_provider
from ..parameter_manager import ParameterManagerError
from ..secret_manager import SecretNotFoundException, SecretManagerException

app = typer.Typer(
    name="anysecret",
    help="Universal configuration and secret manager with intelligent routing across clouds",
    epilog="Visit https://anysecret.io for documentation and examples",
    no_args_is_help=True
)
console = Console()


@app.command()
def info():
    """Show system information, available providers, and current configuration"""
    try:
        provider = get_unified_provider()
        config = provider.config

        # Header
        rprint(Panel.fit(
            "[bold green]AnySecret.io[/bold green]\n"
            "Universal Configuration Manager with Intelligent Routing",
            border_style="green"
        ))

        # Current Configuration
        table = Table(title="Current Configuration", show_header=True)
        table.add_column("Component", style="cyan", width=20)
        table.add_column("Type", style="green", width=25)
        table.add_column("Status", style="yellow", width=15)

        secret_type = config.secret_config.manager_type.value
        param_type = config.parameter_config.manager_type.value

        table.add_row("Secret Manager", secret_type, "Configured")
        table.add_row("Parameter Manager", param_type, "Configured")

        # Show fallbacks if configured
        if config.secret_config.fallback_type:
            table.add_row("Secret Fallback", config.secret_config.fallback_type.value, "Available")
        if config.parameter_config.fallback_type:
            table.add_row("Parameter Fallback", config.parameter_config.fallback_type.value, "Available")

        console.print(table)

        # Environment Detection
        rprint("\n[bold blue]Environment Detection:[/bold blue]")
        from ..config import ConfigAutoDetect

        cloud = ConfigAutoDetect.detect_cloud_provider()
        k8s = ConfigAutoDetect.detect_kubernetes()

        if cloud:
            rprint(f"  Cloud Provider: [green]{cloud.upper()}[/green]")
        if k8s:
            rprint(f"  Kubernetes: [green]Detected[/green]")
        if not cloud and not k8s:
            rprint("  Environment: [yellow]Local Development[/yellow]")

        # Read-only mode
        read_only = os.getenv('ANYSECRET_READ_ONLY', '').lower() == 'true'
        status_color = "red" if read_only else "green"
        mode = "ENABLED" if read_only else "Disabled"
        rprint(f"  Read-Only Mode: [{status_color}]{mode}[/{status_color}]")

    except Exception as e:
        rprint(f"[red]Configuration error: {e}[/red]")
        rprint("[yellow]Run with DEBUG=true for more details[/yellow]")


@app.command()
def get(
        key: str,
        hint: Optional[str] = typer.Option(
            None,
            "--hint", "-h",
            help="Override classification: 'secret' or 'parameter'"
        ),
        show_metadata: bool = typer.Option(
            False,
            "--metadata", "-m",
            help="Show metadata information"
        )
):
    """
    Get a configuration value with intelligent routing

    Automatically routes to secrets or parameters based on naming patterns.
    Use --hint to override automatic classification.
    """
    asyncio.run(_get_unified(key, hint, show_metadata))


async def _get_unified(key: str, hint: Optional[str] = None, show_metadata: bool = False):
    """Get a configuration value using unified interface"""
    try:
        config_manager = await get_config_manager()
        config_value = await config_manager.get_with_metadata(key, hint)

        # Show classification
        classification = "Secret" if config_value.is_secret else "Parameter"
        class_color = "red" if config_value.is_secret else "blue"
        rprint(f"[{class_color}]{classification}:[/{class_color}] {key}")

        # Show value (secrets are masked)
        if config_value.is_secret:
            rprint("[green]Value: [red][HIDDEN][/red][/green]")
            rprint("[dim]Use 'anysecret get-secret {key}' to reveal the value[/dim]")
        else:
            if isinstance(config_value.value, (dict, list)):
                rprint("[green]Value:[/green]")
                rprint(json.dumps(config_value.value, indent=2))
            else:
                rprint(f"[green]Value: {config_value.value}[/green]")

        # Show metadata if requested
        if show_metadata and config_value.metadata:
            rprint("\n[bold blue]Metadata:[/bold blue]")
            for k, v in config_value.metadata.items():
                rprint(f"  {k}: {v}")

    except (SecretNotFoundException, ParameterManagerError) as e:
        rprint(f"[red]Not found: {e}[/red]")
        rprint(f"[yellow]Tip: Use 'anysecret list-config' to see available keys[/yellow]")
        raise typer.Exit(1)
    except Exception as e:
        rprint(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def get_secret(
        key: str,
        show_metadata: bool = typer.Option(
            False,
            "--metadata", "-m",
            help="Show metadata information"
        )
):
    """Explicitly get a value from secret storage"""
    asyncio.run(_get_secret(key, show_metadata))


async def _get_secret(key: str, show_metadata: bool = False):
    """Get a secret value"""
    try:
        config_manager = await get_config_manager()

        if show_metadata:
            secret_value = await config_manager.secret_manager.get_secret_with_metadata(key)
            rprint(f"[red]Secret:[/red] {key}")
            rprint(f"[green]Value: {secret_value.value}[/green]")

            if secret_value.metadata:
                rprint("\n[bold blue]Metadata:[/bold blue]")
                for k, v in secret_value.metadata.items():
                    rprint(f"  {k}: {v}")
        else:
            value = await config_manager.get_secret(key)
            rprint(f"[green]{value}[/green]")

    except SecretNotFoundException as e:
        rprint(f"[red]Secret not found: {e}[/red]")
        rprint("[yellow]Tip: Use 'anysecret list-config' to see available secrets[/yellow]")
        raise typer.Exit(1)
    except Exception as e:
        rprint(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def get_parameter(
        key: str,
        show_metadata: bool = typer.Option(
            False,
            "--metadata", "-m",
            help="Show metadata information"
        )
):
    """Explicitly get a value from parameter storage"""
    asyncio.run(_get_parameter(key, show_metadata))


async def _get_parameter(key: str, show_metadata: bool = False):
    """Get a parameter value"""
    try:
        config_manager = await get_config_manager()

        if show_metadata:
            param_value = await config_manager.parameter_manager.get_parameter_with_metadata(key)
            rprint(f"[blue]Parameter:[/blue] {key}")

            if isinstance(param_value.value, (dict, list)):
                rprint("[green]Value:[/green]")
                rprint(json.dumps(param_value.value, indent=2))
            else:
                rprint(f"[green]Value: {param_value.value}[/green]")

            if param_value.metadata:
                rprint("\n[bold blue]Metadata:[/bold blue]")
                for k, v in param_value.metadata.items():
                    rprint(f"  {k}: {v}")
        else:
            value = await config_manager.get_parameter(key)
            if isinstance(value, (dict, list)):
                rprint(json.dumps(value, indent=2))
            else:
                rprint(f"{value}")

    except ParameterManagerError as e:
        rprint(f"[red]Parameter not found: {e}[/red]")
        rprint("[yellow]Tip: Use 'anysecret list-config' to see available parameters[/yellow]")
        raise typer.Exit(1)
    except Exception as e:
        rprint(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def set_config(
        key: str,
        value: str,
        hint: Optional[str] = typer.Option(
            None,
            "--hint", "-h",
            help="Override classification: 'secret' or 'parameter'"
        ),
        json_value: bool = typer.Option(
            False,
            "--json",
            help="Parse value as JSON"
        )
):
    """
    Set a configuration value with intelligent routing

    Automatically routes to secrets or parameters based on naming patterns.
    Use --hint to override automatic classification.
    Use --json to parse complex values.
    """
    asyncio.run(_set_config(key, value, hint, json_value))


async def _set_config(key: str, value: str, hint: Optional[str] = None, json_value: bool = False):
    """Set a configuration value"""
    try:
        config_manager = await get_config_manager()

        # Parse value
        if json_value:
            try:
                parsed_value = json.loads(value)
            except json.JSONDecodeError as e:
                rprint(f"[red]Invalid JSON: {e}[/red]")
                raise typer.Exit(1)
        else:
            # Try auto-parsing JSON if it looks like JSON
            if value.startswith(('{', '[')) and value.endswith(('}', ']')):
                try:
                    parsed_value = json.loads(value)
                    rprint("[dim]Auto-detected JSON format[/dim]")
                except json.JSONDecodeError:
                    parsed_value = value
            else:
                parsed_value = value

        # Show what will happen
        classification = "secret" if config_manager.classify_key(key, hint) else "parameter"
        rprint(f"[dim]Will store as {classification}: {key}[/dim]")

        success = await config_manager.set(key, parsed_value, hint)
        if success:
            rprint(f"[green]Successfully set {classification}: {key}[/green]")
        else:
            rprint(f"[red]Failed to set {classification}: {key}[/red]")

    except Exception as e:
        rprint(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def list_config(
        prefix: Optional[str] = typer.Option(
            None,
            "--prefix", "-p",
            help="Filter by key prefix"
        ),
        secrets_only: bool = typer.Option(
            False,
            "--secrets-only",
            help="Show only secrets"
        ),
        parameters_only: bool = typer.Option(
            False,
            "--parameters-only",
            help="Show only parameters"
        ),
        show_values: bool = typer.Option(
            False,
            "--values", "-v",
            help="Show parameter values (secrets always hidden)"
        )
):
    """List all configuration keys with classification info"""
    asyncio.run(_list_config(prefix, secrets_only, parameters_only, show_values))


async def _list_config(
        prefix: Optional[str] = None,
        secrets_only: bool = False,
        parameters_only: bool = False,
        show_values: bool = False
):
    """List configuration keys"""
    try:
        config_manager = await get_config_manager()
        keys = await config_manager.list_all_keys(prefix)

        # Filter by type if requested
        if secrets_only:
            keys['parameters'] = []
        elif parameters_only:
            keys['secrets'] = []

        if not keys['secrets'] and not keys['parameters']:
            rprint("[yellow]No configuration found[/yellow]")
            if prefix:
                rprint(f"[dim]No keys found with prefix: {prefix}[/dim]")
            return

        # Create table
        table = Table(title=f"Configuration Keys{f' (prefix: {prefix})' if prefix else ''}")
        table.add_column("Type", style="cyan", width=12)
        table.add_column("Key", style="green", width=40)
        if show_values:
            table.add_column("Value", style="yellow", width=30)
        table.add_column("Classification", style="dim", width=15)

        # Add secret keys
        for key in sorted(keys['secrets']):
            classification = "Auto" if config_manager.classify_key(key) else "Manual"
            if show_values:
                table.add_row("Secret", key, "[red][HIDDEN][/red]", classification)
            else:
                table.add_row("Secret", key, classification)

        # Add parameter keys
        for key in sorted(keys['parameters']):
            classification = "Auto" if not config_manager.classify_key(key) else "Manual"
            if show_values:
                try:
                    value = await config_manager.get_parameter(key)
                    if isinstance(value, (dict, list)):
                        value_str = json.dumps(value)[:25] + "..." if len(json.dumps(value)) > 25 else json.dumps(value)
                    else:
                        value_str = str(value)[:25] + "..." if len(str(value)) > 25 else str(value)
                    table.add_row("Parameter", key, value_str, classification)
                except:
                    table.add_row("Parameter", key, "[red]Error[/red]", classification)
            else:
                table.add_row("Parameter", key, classification)

        console.print(table)

        # Summary
        total_secrets = len(keys['secrets'])
        total_params = len(keys['parameters'])
        rprint(f"\n[dim]Total: {total_secrets} secrets, {total_params} parameters[/dim]")

        if total_secrets > 0 and total_params > 0:
            # Rough cost estimate (AWS pricing)
            estimated_cost = total_secrets * 0.40 + total_params * 0.05
            naive_cost = (total_secrets + total_params) * 0.40
            savings = naive_cost - estimated_cost
            rprint(f"[dim]Estimated monthly cost: ${estimated_cost:.2f} (saves ${savings:.2f} vs all-secrets)[/dim]")

    except Exception as e:
        rprint(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def classify(key: str):
    """Test how a key would be classified and show matching patterns"""
    asyncio.run(_classify(key))


async def _classify(key: str):
    """Test key classification"""
    try:
        config_manager = await get_config_manager()

        is_secret = config_manager.classify_key(key)
        classification = "Secret" if is_secret else "Parameter"
        class_color = "red" if is_secret else "blue"

        rprint(f"[bold]Key:[/bold] {key}")
        rprint(f"[bold]Classification:[/bold] [{class_color}]{classification}[/{class_color}]")

        # Show cost implications
        cost = "$0.40/month" if is_secret else "$0.05/month"
        storage = "Secrets Manager" if is_secret else "Parameter Store"
        rprint(f"[dim]Storage: {storage} (~{cost} on AWS)[/dim]")

        # Show matching patterns
        patterns = config_manager.get_classification_info()

        rprint(f"\n[bold blue]Pattern Analysis:[/bold blue]")
        if is_secret:
            matched = []
            for pattern in patterns['secret_patterns']:
                for regex in config_manager.secret_regexes:
                    if regex.pattern == pattern and regex.search(key):
                        matched.append(pattern)
                        break

            if matched:
                rprint("[green]Matched secret patterns:[/green]")
                for pattern in matched:
                    rprint(f"  • {pattern}")
            else:
                rprint("[yellow]No patterns matched - classified by manual hint[/yellow]")
        else:
            matched = []
            for pattern in patterns['parameter_patterns']:
                for regex in config_manager.parameter_regexes:
                    if regex.pattern == pattern and regex.search(key):
                        matched.append(pattern)
                        break

            if matched:
                rprint("[green]Matched parameter patterns:[/green]")
                for pattern in matched:
                    rprint(f"  • {pattern}")
            else:
                rprint("[blue]Default classification (no secret patterns matched)[/blue]")

    except Exception as e:
        rprint(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def get_prefix(
        prefix: str,
        show_classification: bool = typer.Option(
            True,
            "--no-classification",
            help="Hide classification column"
        )
):
    """Get all configuration values with a given prefix from both stores"""
    asyncio.run(_get_prefix(prefix, show_classification))


async def _get_prefix(prefix: str, show_classification: bool = True):
    """Get all config with prefix"""
    try:
        config_manager = await get_config_manager()
        config = await config_manager.get_config_by_prefix(prefix)

        if not config:
            rprint(f"[yellow]No configuration found with prefix: {prefix}[/yellow]")
            rprint("[dim]Tip: Check your prefix spelling or use 'anysecret list-config' to browse[/dim]")
            return

        # Create table
        table = Table(title=f"Configuration: {prefix}*")
        table.add_column("Key", style="cyan", width=35)
        table.add_column("Value", style="green", width=40)
        if show_classification:
            table.add_column("Type", style="yellow", width=12)

        for key, value in sorted(config.items()):
            is_secret = config_manager.classify_key(key)

            # Format value
            if is_secret:
                value_display = "[red][HIDDEN][/red]"
            elif isinstance(value, (dict, list)):
                value_str = json.dumps(value)
                value_display = value_str[:35] + "..." if len(value_str) > 35 else value_str
            else:
                value_str = str(value)
                value_display = value_str[:35] + "..." if len(value_str) > 35 else value_str

            type_display = "Secret" if is_secret else "Parameter"

            if show_classification:
                table.add_row(key, value_display, type_display)
            else:
                table.add_row(key, value_display)

        console.print(table)

        # Summary
        total = len(config)
        secrets = sum(1 for k in config.keys() if config_manager.classify_key(k))
        rprint(f"\n[dim]Found {total} items ({secrets} secrets, {total - secrets} parameters)[/dim]")

    except Exception as e:
        rprint(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def health():
    """Check health of both secret and parameter managers"""
    asyncio.run(_health_check())


async def _health_check():
    """Check health of managers"""
    try:
        config_manager = await get_config_manager()
        health = await config_manager.health_check()

        rprint("[bold]Health Check Results:[/bold]")

        # Create status table
        table = Table()
        table.add_column("Component", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Details", style="dim")

        secret_status = "[green]Healthy[/green]" if health['secrets'] else "[red]Unhealthy[/red]"
        param_status = "[green]Healthy[/green]" if health['parameters'] else "[red]Unhealthy[/red]"
        overall_status = "[green]Healthy[/green]" if health['overall'] else "[red]Unhealthy[/red]"

        provider = get_unified_provider()
        secret_type = provider.config.secret_config.manager_type.value
        param_type = provider.config.parameter_config.manager_type.value

        table.add_row("Secret Manager", secret_status, secret_type)
        table.add_row("Parameter Manager", param_status, param_type)
        table.add_row("Overall System", overall_status, "Both components")

        console.print(table)

        if not health['overall']:
            rprint("\n[red]System unhealthy - check your configuration and network connectivity[/red]")
            raise typer.Exit(1)
        else:
            rprint("\n[green]All systems operational[/green]")

    except Exception as e:
        rprint(f"[red]Health check failed: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def patterns():
    """Show classification patterns for secrets and parameters"""
    asyncio.run(_show_patterns())


async def _show_patterns():
    """Show classification patterns"""
    try:
        config_manager = await get_config_manager()
        info = config_manager.get_classification_info()

        # Secret patterns
        rprint("[bold red]Secret Patterns (sensitive data):[/bold red]")
        for pattern in info['secret_patterns']:
            rprint(f"  • {pattern}")

        rprint()

        # Parameter patterns
        rprint("[bold blue]Parameter Patterns (configuration data):[/bold blue]")
        for pattern in info['parameter_patterns']:
            rprint(f"  • {pattern}")

        rprint()
        rprint("[dim]Default: Keys not matching secret patterns are classified as parameters[/dim]")
        rprint("[dim]Use --hint to override classification for any key[/dim]")

    except Exception as e:
        rprint(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()