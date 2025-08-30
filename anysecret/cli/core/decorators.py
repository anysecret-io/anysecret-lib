"""
CLI Decorators for common patterns
"""

import asyncio
import functools
from typing import Callable, Any
import typer
from rich import print as rprint
from rich.panel import Panel

from .context import get_cli_context


def async_command(func: Callable) -> Callable:
    """
    Decorator to run async functions in Typer commands
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return asyncio.run(func(*args, **kwargs))
    return wrapper


def handle_errors(func: Callable) -> Callable:
    """
    Decorator to handle common CLI errors gracefully
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        ctx = get_cli_context()
        try:
            return func(*args, **kwargs)
        except KeyboardInterrupt:
            if not ctx.quiet:
                rprint("\n[yellow]Operation cancelled by user[/yellow]")
            raise typer.Exit(130)
        except Exception as e:
            if ctx.is_debug():
                # In debug mode, show full traceback
                raise
            else:
                # In normal mode, show clean error message
                if not ctx.quiet:
                    rprint(f"[red]Error: {e}[/red]")
                raise typer.Exit(1)
    return wrapper


def requires_provider(*supported_providers):
    """
    Decorator to check if command is supported by current provider
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            ctx = get_cli_context()
            if ctx.provider and ctx.provider not in supported_providers:
                rprint(f"[red]Command not supported by provider: {ctx.provider}[/red]")
                rprint(f"[dim]Supported providers: {', '.join(supported_providers)}[/dim]")
                raise typer.Exit(1)
            return func(*args, **kwargs)
        return wrapper
    return decorator


def log_operation(operation_name: str):
    """
    Decorator to log CLI operations
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            ctx = get_cli_context()
            if ctx.is_verbose():
                rprint(f"[dim]Starting {operation_name}...[/dim]")
            result = func(*args, **kwargs)
            if ctx.is_verbose():
                rprint(f"[dim]Completed {operation_name}[/dim]")
            return result
        return wrapper
    return decorator


def requires_write_permission(func: Callable) -> Callable:
    """
    Decorator to check write permissions before executing write operations.
    Shows clear error message and guidance if writes are disabled.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            from ..core.config import get_config_manager
            
            config_mgr = get_config_manager()
            
            # Check if configuration exists
            if not config_mgr.config_file.exists():
                rprint(Panel.fit(
                    "[red]❌ No Configuration Found[/red]\n\n"
                    "AnySecret configuration is required for write operations.\n\n"
                    "[bold]Next steps:[/bold]\n"
                    "• Initialize configuration: [cyan]anysecret config init[/cyan]",
                    border_style="red"
                ))
                raise typer.Exit(1)
            
            # Check write permissions for current profile
            current_profile = config_mgr.get_current_profile()
            
            if not config_mgr.is_write_enabled(current_profile):
                rprint(Panel.fit(
                    "[red]🔒 Write Operations Disabled[/red]\n\n"
                    f"Profile '[cyan]{current_profile}[/cyan]' is read-only for security.\n"
                    "Write operations include creating, updating, and deleting configuration.\n\n"
                    "[bold]To enable writes:[/bold]\n"
                    f"• Enable writes: [cyan]anysecret config enable-writes[/cyan]\n"
                    f"• Check permissions: [cyan]anysecret config check-permissions[/cyan]\n"
                    f"• Switch profile: [cyan]anysecret config profile-list[/cyan]\n\n"
                    "[dim]AnySecret is read-only by default to prevent accidental modifications.[/dim]",
                    border_style="red"
                ))
                raise typer.Exit(1)
            
            # Write permissions are enabled - proceed with operation
            return func(*args, **kwargs)
            
        except typer.Exit:
            # Re-raise typer exits (these are intentional)
            raise
        except Exception as e:
            # Handle any other errors gracefully
            rprint(f"[red]❌ Error checking write permissions: {e}[/red]")
            rprint("[dim]Run 'anysecret config validate' to check configuration health[/dim]")
            raise typer.Exit(1)
    
    return wrapper