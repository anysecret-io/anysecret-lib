"""
Read Operation Commands
"""

from typing import Optional
import typer
from rich import print as rprint

from ..core import print_not_implemented, handle_errors, async_command

app = typer.Typer(help="Read operation commands")


@app.command(name="list")
@handle_errors
@async_command
async def list_configs_async(
    prefix: Optional[str] = typer.Option(None, "--prefix", "-p", help="Filter by prefix"),
    secrets_only: bool = typer.Option(False, "--secrets-only", help="Show only secrets"),
    parameters_only: bool = typer.Option(False, "--parameters-only", help="Show only parameters"),
    show_values: bool = typer.Option(False, "--values", "-v", help="Show parameter values"),
    pattern: Optional[str] = typer.Option(None, "--pattern", help="Filter by regex pattern"),
    format_output: Optional[str] = typer.Option(None, "--format", help="Output format: table|json|yaml"),
    modified_since: Optional[str] = typer.Option(None, "--modified-since", help="Filter by modification date"),
    tags: Optional[str] = typer.Option(None, "--tags", help="Filter by tags (key=value)")
):
    """List all configuration keys with classification"""
    import re
    import json
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    
    console = Console()
    
    # Validate format option
    if format_output and format_output.lower() not in ['table', 'json', 'yaml']:
        console.print(f"[red]❌ Invalid format: {format_output}[/red]")
        console.print("[dim]Valid formats: table, json, yaml[/dim]")
        raise typer.Exit(1)
    
    try:
        # Import configuration managers
        from ...config_loader import initialize_config
        from ...config import get_secret_manager, get_parameter_manager
        
        # Initialize configuration
        initialize_config()
        
        # Get managers
        secret_mgr = await get_secret_manager()
        param_mgr = await get_parameter_manager()
        
        # Header
        filter_desc = []
        if prefix:
            filter_desc.append(f"prefix: {prefix}")
        if secrets_only:
            filter_desc.append("secrets only")
        if parameters_only:
            filter_desc.append("parameters only")
        if pattern:
            filter_desc.append(f"pattern: {pattern}")
        
        header_text = "[bold green]📋 Configuration Listing[/bold green]"
        if filter_desc:
            header_text += f"\nFilters: {', '.join(filter_desc)}"
        
        console.print(Panel.fit(header_text, border_style="green"))
        
        # Collect all keys
        all_items = []
        
        # Get secrets if not parameters_only
        if not parameters_only:
            try:
                secrets = await secret_mgr.list_secrets()
                for key in secrets:
                    # Apply prefix filter
                    if prefix and not key.startswith(prefix):
                        continue
                    
                    # Apply pattern filter
                    if pattern:
                        try:
                            if not re.search(pattern, key):
                                continue
                        except re.error as e:
                            console.print(f"[red]❌ Invalid regex pattern: {e}[/red]")
                            raise typer.Exit(1)
                    
                    all_items.append({
                        'key': key,
                        'type': 'Secret',
                        'icon': '🔐',
                        'value': '[HIDDEN]' if not show_values else '[HIDDEN]',
                        'storage': secret_mgr.__class__.__name__.replace('Manager', '').replace('Secret', '')
                    })
            except Exception as e:
                console.print(f"[yellow]⚠️  Could not list secrets: {e}[/yellow]")
        
        # Get parameters if not secrets_only
        if not secrets_only:
            try:
                parameters = await param_mgr.list_parameters()
                for key in parameters:
                    # Apply prefix filter
                    if prefix and not key.startswith(prefix):
                        continue
                    
                    # Apply pattern filter
                    if pattern:
                        try:
                            if not re.search(pattern, key):
                                continue
                        except re.error as e:
                            console.print(f"[red]❌ Invalid regex pattern: {e}[/red]")
                            raise typer.Exit(1)
                    
                    value_display = '[NOT SHOWN]'
                    if show_values:
                        try:
                            value = await param_mgr.get_parameter(key)
                            value_display = str(value)[:50] + ('...' if len(str(value)) > 50 else '')
                        except:
                            value_display = '[ERROR]'
                    
                    all_items.append({
                        'key': key,
                        'type': 'Parameter',
                        'icon': '⚙️',
                        'value': value_display,
                        'storage': param_mgr.__class__.__name__.replace('Manager', '').replace('Parameter', '')
                    })
            except Exception as e:
                console.print(f"[yellow]⚠️  Could not list parameters: {e}[/yellow]")
        
        if not all_items:
            console.print("[yellow]No configuration items found matching the criteria[/yellow]")
            console.print("[dim]Try adjusting your filters or check provider connectivity[/dim]")
            return
        
        # Sort items by key
        all_items.sort(key=lambda x: x['key'])
        
        # Handle different output formats
        if format_output and format_output.lower() == 'json':
            # JSON output
            output_data = {
                "items": [],
                "summary": {
                    "total": len(all_items),
                    "secrets": len([item for item in all_items if item['type'] == 'Secret']),
                    "parameters": len([item for item in all_items if item['type'] == 'Parameter'])
                },
                "filters": {}
            }
            
            # Add filter info
            if prefix:
                output_data["filters"]["prefix"] = prefix
            if secrets_only:
                output_data["filters"]["secrets_only"] = True
            if parameters_only:
                output_data["filters"]["parameters_only"] = True
            if pattern:
                output_data["filters"]["pattern"] = pattern
            
            # Add items
            for item in all_items:
                item_data = {
                    "key": item['key'],
                    "type": item['type'].lower(),
                    "storage": item['storage']
                }
                if show_values and item['type'] == 'Parameter':
                    item_data["value"] = item['value']
                elif show_values and item['type'] == 'Secret':
                    item_data["value"] = "[HIDDEN]"
                
                output_data["items"].append(item_data)
            
            print(json.dumps(output_data, indent=2))
            
        elif format_output and format_output.lower() == 'yaml':
            # YAML output
            try:
                import yaml
            except ImportError:
                console.print("[red]❌ YAML output requires PyYAML: pip install PyYAML[/red]")
                raise typer.Exit(1)
            
            output_data = {
                "items": [],
                "summary": {
                    "total": len(all_items),
                    "secrets": len([item for item in all_items if item['type'] == 'Secret']),
                    "parameters": len([item for item in all_items if item['type'] == 'Parameter'])
                },
                "filters": {}
            }
            
            # Add filter info
            if prefix:
                output_data["filters"]["prefix"] = prefix
            if secrets_only:
                output_data["filters"]["secrets_only"] = True
            if parameters_only:
                output_data["filters"]["parameters_only"] = True
            if pattern:
                output_data["filters"]["pattern"] = pattern
            
            # Add items
            for item in all_items:
                item_data = {
                    "key": item['key'],
                    "type": item['type'].lower(),
                    "storage": item['storage']
                }
                if show_values and item['type'] == 'Parameter':
                    item_data["value"] = item['value']
                elif show_values and item['type'] == 'Secret':
                    item_data["value"] = "[HIDDEN]"
                
                output_data["items"].append(item_data)
            
            print(yaml.dump(output_data, default_flow_style=False, sort_keys=False))
            
        else:
            # Default table output
            # Create table
            table = Table()
            table.add_column("", style="", width=3)  # Icon
            table.add_column("Key", style="cyan", min_width=20)
            table.add_column("Type", style="", width=10)
            table.add_column("Storage", style="dim", width=12)
            if show_values:
                table.add_column("Value", style="yellow", min_width=20, max_width=50)
            
            # Add rows
            for item in all_items:
                if show_values:
                    table.add_row(
                        item['icon'],
                        item['key'],
                        f"[green]{item['type']}[/green]" if item['type'] == 'Parameter' else f"[red]{item['type']}[/red]",
                        item['storage'],
                        item['value']
                    )
                else:
                    table.add_row(
                        item['icon'],
                        item['key'],
                        f"[green]{item['type']}[/green]" if item['type'] == 'Parameter' else f"[red]{item['type']}[/red]",
                        item['storage']
                    )
            
            console.print(table)
        
        # Only show summary and tips for table format
        if not format_output or format_output.lower() == 'table':
            # Summary
            secret_count = len([item for item in all_items if item['type'] == 'Secret'])
            param_count = len([item for item in all_items if item['type'] == 'Parameter'])
            
            console.print(f"\n[bold]Summary:[/bold] {len(all_items)} items total")
            if secret_count > 0:
                console.print(f"• [red]Secrets:[/red] {secret_count}")
            if param_count > 0:
                console.print(f"• [green]Parameters:[/green] {param_count}")
            
            # Usage tips
            if not show_values:
                console.print(f"\n[dim]💡 Use [cyan]--values[/cyan] to show parameter values[/dim]")
            console.print(f"[dim]💡 Use [cyan]anysecret get <key>[/cyan] to retrieve specific values[/dim]")
            console.print(f"[dim]💡 Use [cyan]--prefix <prefix>[/cyan] or [cyan]--pattern <regex>[/cyan] to filter results[/dim]")
            console.print(f"[dim]💡 Use [cyan]--format json|yaml[/cyan] for structured output[/dim]")
        
        return len(all_items)  # Return count for success
        
    except Exception as e:
        console.print(f"[red]❌ Error listing configuration: {e}[/red]")
        import traceback
        traceback.print_exc()
        raise typer.Exit(1)


@app.command(name="tree")
@handle_errors
def tree_view(
    prefix: Optional[str] = typer.Option(None, "--prefix", "-p", help="Root prefix"),
    depth: Optional[int] = typer.Option(None, "--depth", "-d", help="Maximum depth")
):
    """Show hierarchical tree view of configuration"""
    print_not_implemented(
        "anysecret read tree",
        f"Will show tree view - prefix: {prefix}, depth: {depth}"
    )


@app.command(name="search")
@handle_errors
def search_configs(
    query: str,
    content: bool = typer.Option(False, "--content", help="Search in values"),
    metadata: bool = typer.Option(False, "--metadata", help="Search in metadata")
):
    """Search configuration keys and values"""
    print_not_implemented(
        "anysecret read search",
        f"Will search for '{query}' in {'content and metadata' if content and metadata else 'content' if content else 'metadata' if metadata else 'keys'}"
    )


@app.command(name="grep")
@handle_errors 
def grep_configs(pattern: str):
    """Regex search across keys and values"""
    print_not_implemented(
        "anysecret read grep",
        f"Will grep for pattern: {pattern}"
    )


@app.command(name="get")
@handle_errors
@async_command
async def get_value_async(
    key: str,
    hint: Optional[str] = typer.Option(None, "--hint", "-h", help="Classification hint: secret|parameter"),
    metadata: bool = typer.Option(False, "--metadata", "-m", help="Show metadata"),
    raw: bool = typer.Option(False, "--raw", help="Raw output without formatting"),
    format_output: Optional[str] = typer.Option(None, "--format", help="Output format: table|json|yaml")
):
    """Get a configuration value with intelligent routing"""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    import json
    
    console = Console()
    
    # Validate format option
    if format_output and format_output.lower() not in ['table', 'json', 'yaml']:
        console.print(f"[red]❌ Invalid format: {format_output}[/red]")
        console.print("[dim]Valid formats: table, json, yaml[/dim]")
        raise typer.Exit(1)
    
    try:
        # Import configuration managers
        from ...config_loader import initialize_config
        from ...config import get_secret_manager, get_parameter_manager
        from ..core.config import get_config_manager as get_cli_config_manager
        
        # Initialize configuration
        initialize_config()
        
        # Get managers
        secret_mgr = await get_secret_manager()
        param_mgr = await get_parameter_manager()
        cli_config_mgr = get_cli_config_manager()
        
        # Use built-in classification to determine if secret or parameter
        is_secret = False
        value = None
        found = False
        error_msg = None
        storage_type = None
        
        # If hint provided, try that first
        if hint and hint.lower() == 'secret':
            try:
                value = await secret_mgr.get_secret(key)
                is_secret = True
                found = True
                storage_type = secret_mgr.__class__.__name__.replace('Manager', '').replace('Secret', '')
            except Exception as e:
                error_msg = f"Secret not found: {e}"
        elif hint and hint.lower() == 'parameter':
            try:
                value = await param_mgr.get_parameter(key)
                is_secret = False
                found = True
                storage_type = param_mgr.__class__.__name__.replace('Manager', '').replace('Parameter', '')
            except Exception as e:
                error_msg = f"Parameter not found: {e}"
        else:
            # Use intelligent classification
            # Check if it matches secret patterns
            config = cli_config_mgr.load_config()
            
            # Get built-in and custom patterns
            secret_patterns = [
                r'.*password.*', r'.*secret.*', r'.*key.*', r'.*token.*', 
                r'.*credential.*', r'.*auth.*', r'.*api.*key.*'
            ]
            param_patterns = [
                r'.*config.*', r'.*setting.*', r'.*timeout.*', r'.*limit.*',
                r'.*url.*', r'.*host.*', r'.*port.*', r'.*size.*'
            ]
            
            # Add custom patterns from config
            if 'global_settings' in config and 'classification' in config['global_settings']:
                classification = config['global_settings']['classification']
                if 'custom_secret_patterns' in classification:
                    secret_patterns.extend(classification['custom_secret_patterns'])
                if 'custom_parameter_patterns' in classification:
                    param_patterns.extend(classification['custom_parameter_patterns'])
            
            # Check patterns to determine type
            import re
            key_lower = key.lower()
            
            is_likely_secret = any(re.search(pattern.lower(), key_lower) for pattern in secret_patterns)
            is_likely_param = any(re.search(pattern.lower(), key_lower) for pattern in param_patterns)
            
            # Try secret first if it looks like a secret, otherwise try parameter first
            if is_likely_secret and not is_likely_param:
                # Try secret first
                try:
                    value = await secret_mgr.get_secret(key)
                    is_secret = True
                    found = True
                    storage_type = secret_mgr.__class__.__name__.replace('Manager', '').replace('Secret', '')
                except Exception:
                    try:
                        value = await param_mgr.get_parameter(key)
                        is_secret = False
                        found = True
                        storage_type = param_mgr.__class__.__name__.replace('Manager', '').replace('Parameter', '')
                    except Exception as e:
                        error_msg = f"Key not found in secrets or parameters: {e}"
            else:
                # Try parameter first
                try:
                    value = await param_mgr.get_parameter(key)
                    is_secret = False
                    found = True
                    storage_type = param_mgr.__class__.__name__.replace('Manager', '').replace('Parameter', '')
                except Exception:
                    try:
                        value = await secret_mgr.get_secret(key)
                        is_secret = True
                        found = True
                        storage_type = secret_mgr.__class__.__name__.replace('Manager', '').replace('Secret', '')
                    except Exception as e:
                        error_msg = f"Key not found in parameters or secrets: {e}"
        
        if not found:
            console.print(f"[red]❌ Key '{key}' not found[/red]")
            if error_msg:
                console.print(f"[dim]{error_msg}[/dim]")
            console.print(f"\n[dim]💡 Use [cyan]anysecret list[/cyan] to see available keys[/dim]")
            console.print(f"[dim]💡 Use [cyan]--hint secret[/cyan] or [cyan]--hint parameter[/cyan] to specify type[/dim]")
            raise typer.Exit(1)
        
        # Prepare output data
        output_data = {
            'key': key,
            'type': 'secret' if is_secret else 'parameter',
            'storage': storage_type,
            'found': True
        }
        
        # Handle value display based on type and format
        if is_secret:
            if raw:
                # Raw output shows actual secret value
                output_data['value'] = str(value)
            else:
                # Normal output hides secret value
                output_data['value'] = '[HIDDEN]'
        else:
            output_data['value'] = str(value)
        
        # Add metadata if requested
        if metadata:
            output_data['metadata'] = {
                'classification': 'automatic' if not hint else f'manual ({hint})',
                'storage_backend': storage_type,
                'value_type': type(value).__name__
            }
        
        # Output based on format
        if format_output and format_output.lower() == 'json':
            if raw and is_secret:
                # For JSON raw output of secrets, show the actual value
                output_data['value'] = str(value)
            print(json.dumps(output_data, indent=2))
            
        elif format_output and format_output.lower() == 'yaml':
            try:
                import yaml
            except ImportError:
                console.print("[red]❌ YAML output requires PyYAML: pip install PyYAML[/red]")
                raise typer.Exit(1)
            
            if raw and is_secret:
                # For YAML raw output of secrets, show the actual value
                output_data['value'] = str(value)
            print(yaml.dump(output_data, default_flow_style=False, sort_keys=False))
            
        elif raw:
            # Raw format just prints the value
            print(value)
            
        else:
            # Default table/formatted output
            if is_secret:
                console.print(Panel.fit(
                    f"[bold red]🔐 Secret: {key}[/bold red]\n"
                    f"Storage: [cyan]{storage_type}[/cyan]\n"
                    f"Value: [red][HIDDEN][/red]\n\n"
                    "[dim]Use [cyan]--raw[/cyan] to reveal the actual value[/dim]",
                    border_style="red"
                ))
            else:
                console.print(Panel.fit(
                    f"[bold green]⚙️  Parameter: {key}[/bold green]\n"
                    f"Storage: [cyan]{storage_type}[/cyan]\n"
                    f"Value: [yellow]{value}[/yellow]",
                    border_style="green"  
                ))
            
            if metadata:
                console.print(f"\n[bold]Metadata:[/bold]")
                console.print(f"• Classification: [cyan]{output_data['metadata']['classification']}[/cyan]")
                console.print(f"• Storage Backend: [cyan]{output_data['metadata']['storage_backend']}[/cyan]")
                console.print(f"• Value Type: [cyan]{output_data['metadata']['value_type']}[/cyan]")
            
            # Usage tips
            if is_secret and not raw:
                console.print(f"\n[dim]💡 Use [cyan]anysecret get {key} --raw[/cyan] to reveal the secret value[/dim]")
            console.print(f"[dim]💡 Use [cyan]--format json|yaml[/cyan] for structured output[/dim]")
            console.print(f"[dim]💡 Use [cyan]--metadata[/cyan] to see additional information[/dim]")
        
        return value if raw else output_data
                
    except Exception as e:
        console.print(f"[red]❌ Error getting '{key}': {e}[/red]")
        import traceback
        traceback.print_exc()
        raise typer.Exit(1)


@app.command(name="get-secret")
@handle_errors
def get_secret(
    key: str,
    metadata: bool = typer.Option(False, "--metadata", "-m", help="Show metadata"),
    version: Optional[str] = typer.Option(None, "--version", help="Specific version"),
    decrypt: bool = typer.Option(False, "--decrypt", help="Decrypt and show value")
):
    """Explicitly get a value from secret storage"""
    print_not_implemented(
        "anysecret read get-secret",
        f"Will get secret '{key}' version: {version}, decrypt: {decrypt}"
    )


@app.command(name="get-parameter")
@handle_errors
def get_parameter(
    key: str,
    metadata: bool = typer.Option(False, "--metadata", "-m", help="Show metadata")
):
    """Explicitly get a value from parameter storage"""
    print_not_implemented(
        "anysecret read get-parameter",
        f"Will get parameter '{key}' with metadata: {metadata}"
    )


@app.command(name="get-prefix")
@handle_errors
def get_prefix(
    prefix: str,
    classification: bool = typer.Option(True, "--no-classification", help="Hide classification")
):
    """Get all configuration values with a given prefix"""
    print_not_implemented(
        "anysecret read get-prefix",
        f"Will get all values with prefix '{prefix}'"
    )


@app.command(name="get-batch")
@handle_errors
def get_batch(
    keys: str,
    file: Optional[str] = typer.Option(None, "--file", help="Keys from file")
):
    """Get multiple keys in batch"""
    print_not_implemented(
        "anysecret read get-batch",
        f"Will get batch keys: {keys if not file else f'from file {file}'}"
    )


@app.command(name="get-env")
@handle_errors
def get_env(
    prefix: Optional[str] = typer.Option(None, "--prefix", "-p", help="Filter by prefix")
):
    """Output configuration as environment variables"""
    print_not_implemented(
        "anysecret read get-env",
        f"Will output env vars with prefix: {prefix}"
    )


@app.command(name="get-json")
@handle_errors
def get_json(
    prefix: Optional[str] = typer.Option(None, "--prefix", "-p", help="Filter by prefix")
):
    """Output configuration as JSON object"""
    print_not_implemented(
        "anysecret read get-json",
        f"Will output JSON with prefix: {prefix}"
    )


@app.command(name="get-yaml")
@handle_errors
def get_yaml(
    prefix: Optional[str] = typer.Option(None, "--prefix", "-p", help="Filter by prefix")
):
    """Output configuration as YAML object"""
    print_not_implemented(
        "anysecret read get-yaml",
        f"Will output YAML with prefix: {prefix}"
    )


@app.command(name="history")
@handle_errors
def show_history(key: str):
    """Show version history for a key"""
    print_not_implemented(
        "anysecret read history",
        f"Will show version history for '{key}'"
    )


@app.command(name="versions")
@handle_errors
def list_versions(key: str):
    """List all versions of a key"""
    print_not_implemented(
        "anysecret read versions",
        f"Will list versions for '{key}'"
    )


@app.command(name="get-version")
@handle_errors
def get_version(key: str, version: str):
    """Get a specific version of a key"""
    print_not_implemented(
        "anysecret read get-version",
        f"Will get '{key}' version '{version}'"
    )


@app.command(name="diff-versions")
@handle_errors
def diff_versions(key: str, version1: str, version2: str):
    """Compare two versions of a key"""
    print_not_implemented(
        "anysecret read diff-versions",
        f"Will compare '{key}' versions '{version1}' vs '{version2}'"
    )


@app.command(name="describe")
@handle_errors
def describe_key(key: str):
    """Show detailed metadata for a key"""
    print_not_implemented(
        "anysecret read describe",
        f"Will describe key '{key}' with full metadata"
    )


@app.command(name="tags")
@handle_errors
def show_tags(key: str):
    """Show tags for a key"""
    print_not_implemented(
        "anysecret read tags",
        f"Will show tags for '{key}'"
    )


@app.command(name="references")
@handle_errors
def show_references(key: str):
    """Show what references this key"""
    print_not_implemented(
        "anysecret read references",
        f"Will show references to '{key}'"
    )


@app.command(name="dependencies")
@handle_errors
def show_dependencies(key: str):
    """Show key dependencies"""
    print_not_implemented(
        "anysecret read dependencies",
        f"Will show dependencies for '{key}'"
    )


@app.command(name="validate")
@handle_errors
def validate_key(key: str):
    """Validate that key exists and is accessible"""
    print_not_implemented(
        "anysecret read validate",
        f"Will validate access to '{key}'"
    )


@app.command(name="test")
@handle_errors
def test_key(key: str):
    """Test key retrieval"""
    print_not_implemented(
        "anysecret read test",
        f"Will test retrieval of '{key}'"
    )


@app.command(name="check-access")
@handle_errors
def check_access(key: str):
    """Check access permissions for a key"""
    print_not_implemented(
        "anysecret read check-access",
        f"Will check access permissions for '{key}'"
    )


@app.command(name="classify")
@handle_errors
def classify_key(key: str):
    """Test how a key would be classified"""
    print_not_implemented(
        "anysecret read classify",
        f"Will classify key '{key}' and show matching patterns"
    )


@app.command(name="why-secret")
@handle_errors
def why_secret(key: str):
    """Explain why key is classified as secret"""
    print_not_implemented(
        "anysecret read why-secret",
        f"Will explain secret classification for '{key}'"
    )


@app.command(name="why-parameter")
@handle_errors
def why_parameter(key: str):
    """Explain why key is classified as parameter"""
    print_not_implemented(
        "anysecret read why-parameter",
        f"Will explain parameter classification for '{key}'"
    )


@app.command(name="diff")
@handle_errors
def diff_environments(env1: str, env2: str):
    """Compare two environments"""
    print_not_implemented(
        "anysecret read diff",
        f"Will compare environments '{env1}' and '{env2}'"
    )


@app.command(name="validate-refs")
@handle_errors
def validate_refs(file: str):
    """Validate references in a file"""
    print_not_implemented(
        "anysecret read validate-refs",
        f"Will validate references in file '{file}'"
    )


# Legacy compatibility functions (called from main CLI)
def list_configs(prefix, secrets_only, parameters_only, show_values):
    """List configs (legacy compatibility)"""
    import asyncio
    # Call the actual async implementation with default values for missing params
    try:
        return asyncio.run(list_configs_async(
            prefix=prefix, 
            secrets_only=secrets_only, 
            parameters_only=parameters_only, 
            show_values=show_values,
            pattern=None,  # Default values for params not in legacy function
            format_output=None,  # Default to table format
            modified_since=None,
            tags=None
        ))
    except Exception:
        # If async fails, don't propagate the exception through asyncio wrapper
        return


def get_value(key, hint, metadata):
    """Get value (legacy compatibility)"""
    import asyncio
    # Call the actual async implementation
    try:
        return asyncio.run(get_value_async(
            key=key,
            hint=hint,
            metadata=metadata,
            raw=False,
            format_output=None
        ))
    except Exception:
        # If async fails, don't propagate the exception through asyncio wrapper
        return


def classify_key(key):
    """Classify key (legacy compatibility)"""
    print_not_implemented(
        "anysecret classify",
        f"Will classify key '{key}'"
    )