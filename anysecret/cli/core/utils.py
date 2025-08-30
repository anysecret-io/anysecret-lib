"""
CLI Utilities
"""

import json
from typing import Any, Dict, List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint
import typer

try:
    import yaml
except ImportError:
    yaml = None

from .context import get_cli_context

console = Console()


def print_not_implemented(command_name: str, additional_info: Optional[str] = None):
    """
    Print a consistent 'not implemented' message
    """
    try:
        ctx = get_cli_context()
        provider_info = f"\n[dim]Provider: {ctx.provider}[/dim]" if ctx.provider else ""
        quiet = ctx.quiet
    except:
        # Fallback if context is not available
        provider_info = ""
        quiet = False
    
    if quiet:
        return
        
    message = f"[yellow]⚠️  Command '[bold]{command_name}[/bold]' not yet implemented[/yellow]"
    
    if additional_info:
        message += f"\n[dim]{additional_info}[/dim]"
    
    message += provider_info
    
    rprint(Panel(message, border_style="yellow"))


def format_output(data: Any, format_type: Optional[str] = None) -> None:
    """
    Format and display output based on context format preference
    """
    ctx = get_cli_context()
    output_format = format_type or ctx.output_format
    
    if ctx.quiet:
        return
    
    if output_format == "json":
        print(json.dumps(data, indent=2, default=str))
    elif output_format == "yaml":
        if yaml:
            print(yaml.safe_dump(data, default_flow_style=False))
        else:
            rprint("[red]YAML support not available. Install PyYAML: pip install pyyaml[/red]")
            print(json.dumps(data, indent=2, default=str))
    elif output_format == "raw":
        print(data)
    else:  # table or default
        _format_as_table(data)


def _format_as_table(data: Any) -> None:
    """Format data as a rich table"""
    if isinstance(data, dict):
        _dict_to_table(data)
    elif isinstance(data, list):
        _list_to_table(data)
    else:
        rprint(str(data))


def _dict_to_table(data: Dict[str, Any], title: Optional[str] = None) -> None:
    """Convert dictionary to table"""
    table = Table(title=title)
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="green")
    
    for key, value in data.items():
        if isinstance(value, (dict, list)):
            value_str = json.dumps(value, default=str)[:50] + "..." if len(json.dumps(value, default=str)) > 50 else json.dumps(value, default=str)
        else:
            value_str = str(value)[:50] + "..." if len(str(value)) > 50 else str(value)
        table.add_row(key, value_str)
    
    console.print(table)


def _list_to_table(data: List[Any], title: Optional[str] = None) -> None:
    """Convert list to table"""
    if not data:
        rprint("[dim]No items found[/dim]")
        return
    
    if isinstance(data[0], dict):
        # Table from list of dicts
        table = Table(title=title)
        if data:
            for key in data[0].keys():
                table.add_column(key.title(), style="cyan")
            
            for item in data:
                row = []
                for value in item.values():
                    if isinstance(value, (dict, list)):
                        value_str = json.dumps(value, default=str)[:30] + "..." if len(json.dumps(value, default=str)) > 30 else json.dumps(value, default=str)
                    else:
                        value_str = str(value)[:30] + "..." if len(str(value)) > 30 else str(value)
                    row.append(value_str)
                table.add_row(*row)
        console.print(table)
    else:
        # Simple list
        for item in data:
            rprint(f"• {item}")


def confirm_operation(message: str, default: bool = False) -> bool:
    """
    Ask for user confirmation
    """
    ctx = get_cli_context()
    
    if ctx.dry_run:
        rprint(f"[dim]DRY RUN: Would ask: {message}[/dim]")
        return True
    
    return typer.confirm(message, default=default)


def show_progress(message: str):
    """
    Show a progress message if not in quiet mode
    """
    ctx = get_cli_context()
    if not ctx.quiet:
        rprint(f"[dim]{message}...[/dim]")


def show_success(message: str):
    """
    Show a success message if not in quiet mode
    """
    ctx = get_cli_context()
    if not ctx.quiet:
        rprint(f"[green]✅ {message}[/green]")


def show_warning(message: str):
    """
    Show a warning message
    """
    ctx = get_cli_context()
    if not ctx.quiet:
        rprint(f"[yellow]⚠️  {message}[/yellow]")


def show_error(message: str):
    """
    Show an error message
    """
    ctx = get_cli_context()
    if not ctx.quiet:
        rprint(f"[red]❌ {message}[/red]")


def debug_print(message: str, data: Any = None):
    """
    Print debug information if in debug mode
    """
    ctx = get_cli_context()
    if ctx.is_debug():
        rprint(f"[dim]DEBUG: {message}[/dim]")
        if data is not None:
            rprint(f"[dim]  Data: {data}[/dim]")