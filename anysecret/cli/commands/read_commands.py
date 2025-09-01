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
@async_command
async def tree_view(
    prefix: Optional[str] = typer.Option(None, "--prefix", "-p", help="Root prefix"),
    depth: Optional[int] = typer.Option(None, "--depth", "-d", help="Maximum depth"),
    secrets_only: bool = typer.Option(False, "--secrets-only", help="Show only secrets"),
    parameters_only: bool = typer.Option(False, "--parameters-only", help="Show only parameters")
):
    """Show hierarchical tree view of configuration"""
    from rich.console import Console
    from rich.panel import Panel
    from rich.tree import Tree
    from collections import defaultdict
    
    console = Console()
    
    try:
        # Import configuration managers
        from ...config_loader import initialize_config
        from ...config import get_secret_manager, get_parameter_manager
        
        # Initialize configuration
        initialize_config()
        
        # Get managers
        secret_mgr = await get_secret_manager()
        param_mgr = await get_parameter_manager()
        
        # Collect all keys
        all_keys = []
        
        # Get secrets if not parameters_only
        if not parameters_only:
            try:
                secrets = await secret_mgr.list_secrets()
                for key in secrets:
                    all_keys.append((key, 'secret', '🔐'))
            except Exception as e:
                console.print(f"[yellow]⚠️  Could not list secrets: {e}[/yellow]")
        
        # Get parameters if not secrets_only
        if not secrets_only:
            try:
                parameters = await param_mgr.list_parameters()
                for key in parameters:
                    all_keys.append((key, 'parameter', '⚙️'))
            except Exception as e:
                console.print(f"[yellow]⚠️  Could not list parameters: {e}[/yellow]")
        
        # Filter by prefix
        if prefix:
            all_keys = [(k, t, i) for k, t, i in all_keys if k.startswith(prefix)]
        
        if not all_keys:
            console.print(f"[yellow]No configuration found{' with prefix ' + prefix if prefix else ''}[/yellow]")
            return
        
        # Build tree structure
        tree_data = defaultdict(lambda: defaultdict(list))
        
        for key, key_type, icon in all_keys:
            # Remove prefix if specified
            display_key = key[len(prefix):] if prefix else key
            
            # Split by separator (/ or _)
            if '/' in display_key:
                parts = display_key.split('/')
            elif '_' in display_key:
                parts = display_key.split('_')
            else:
                parts = [display_key]
            
            # Apply depth limit
            if depth and len(parts) > depth:
                parts = parts[:depth]
                parts[-1] = parts[-1] + "..."
            
            # Build nested structure
            current = tree_data
            for i, part in enumerate(parts[:-1]):
                if part not in current:
                    current[part] = defaultdict(list)
                current = current[part]
            
            # Add final item
            final_part = parts[-1] if parts else key
            current['__items__'].append((final_part, key_type, icon, key))
        
        # Display tree
        root_title = f"Configuration Tree"
        if prefix:
            root_title += f" (prefix: {prefix})"
        if depth:
            root_title += f" (depth: {depth})"
        
        console.print(Panel.fit(f"[bold green]🌳 {root_title}[/bold green]", border_style="green"))
        
        # Create Rich tree
        tree = Tree("📁 Configuration")
        
        def build_tree_node(node_data, parent_tree, current_depth=0):
            # Add items at this level
            if '__items__' in node_data:
                for item_name, item_type, icon, full_key in sorted(node_data['__items__']):
                    label = f"{icon} [cyan]{item_name}[/cyan] [dim]({item_type})[/dim]"
                    parent_tree.add(label)
            
            # Add subdirectories
            for key, subdata in sorted(node_data.items()):
                if key != '__items__':
                    subtree = parent_tree.add(f"📁 [yellow]{key}/[/yellow]")
                    build_tree_node(subdata, subtree, current_depth + 1)
        
        build_tree_node(tree_data, tree)
        console.print(tree)
        
        # Summary
        total_items = len(all_keys)
        secrets_count = len([k for k, t, i in all_keys if t == 'secret'])
        params_count = len([k for k, t, i in all_keys if t == 'parameter'])
        
        console.print(f"\n[bold]Summary:[/bold] {total_items} items ({secrets_count} secrets, {params_count} parameters)")
        
    except Exception as e:
        console.print(f"[red]❌ Error building tree view: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="search")
@handle_errors
@async_command
async def search_configs(
    query: str,
    content: bool = typer.Option(False, "--content", help="Search in values"),
    metadata: bool = typer.Option(False, "--metadata", help="Search in metadata"),
    secrets_only: bool = typer.Option(False, "--secrets-only", help="Search only secrets"),
    parameters_only: bool = typer.Option(False, "--parameters-only", help="Search only parameters"),
    case_sensitive: bool = typer.Option(False, "--case-sensitive", help="Case sensitive search"),
    regex: bool = typer.Option(False, "--regex", help="Use regex pattern matching"),
    format_output: Optional[str] = typer.Option(None, "--format", help="Output format: table|json|yaml")
):
    """Search configuration keys and values"""
    import re
    import json
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    
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
        
        # Prepare search pattern
        if regex:
            try:
                pattern = re.compile(query if case_sensitive else query, re.IGNORECASE if not case_sensitive else 0)
            except re.error as e:
                console.print(f"[red]❌ Invalid regex pattern: {e}[/red]")
                raise typer.Exit(1)
        else:
            pattern = None
        
        def matches_query(text):
            if not text:
                return False
            if regex:
                return bool(pattern.search(text))
            else:
                return query.lower() in text.lower() if not case_sensitive else query in text
        
        # Search results
        results = []
        
        # Search secrets if not parameters_only
        if not parameters_only:
            try:
                secrets = await secret_mgr.list_secrets()
                for key in secrets:
                    match_info = {}
                    
                    # Search in key name
                    if matches_query(key):
                        match_info['key'] = True
                    
                    # Search in content if requested
                    if content:
                        try:
                            value = await secret_mgr.get_secret(key)
                            if isinstance(value, str) and matches_query(value):
                                match_info['content'] = True
                        except:
                            pass  # Skip if can't retrieve value
                    
                    # Search in metadata if requested (and supported)
                    if metadata:
                        try:
                            # Try to get metadata (not all providers support this)
                            meta = getattr(secret_mgr, 'get_metadata', None)
                            if meta:
                                meta_data = await meta(key)
                                if meta_data and matches_query(str(meta_data)):
                                    match_info['metadata'] = True
                        except:
                            pass  # Skip if metadata not supported
                    
                    # If any matches found, add to results
                    if match_info:
                        results.append({
                            'key': key,
                            'type': 'Secret',
                            'icon': '🔐',
                            'matches': match_info,
                            'storage': secret_mgr.__class__.__name__.replace('Manager', '').replace('Secret', '')
                        })
            except Exception as e:
                console.print(f"[yellow]⚠️  Could not search secrets: {e}[/yellow]")
        
        # Search parameters if not secrets_only
        if not secrets_only:
            try:
                parameters = await param_mgr.list_parameters()
                for key in parameters:
                    match_info = {}
                    
                    # Search in key name
                    if matches_query(key):
                        match_info['key'] = True
                    
                    # Search in content if requested
                    if content:
                        try:
                            value = await param_mgr.get_parameter(key)
                            if isinstance(value, str) and matches_query(value):
                                match_info['content'] = True
                        except:
                            pass  # Skip if can't retrieve value
                    
                    # Search in metadata if requested (and supported)
                    if metadata:
                        try:
                            # Try to get metadata (not all providers support this)
                            meta = getattr(param_mgr, 'get_metadata', None)
                            if meta:
                                meta_data = await meta(key)
                                if meta_data and matches_query(str(meta_data)):
                                    match_info['metadata'] = True
                        except:
                            pass  # Skip if metadata not supported
                    
                    # If any matches found, add to results
                    if match_info:
                        results.append({
                            'key': key,
                            'type': 'Parameter',
                            'icon': '⚙️',
                            'matches': match_info,
                            'storage': param_mgr.__class__.__name__.replace('Manager', '').replace('Parameter', '')
                        })
            except Exception as e:
                console.print(f"[yellow]⚠️  Could not search parameters: {e}[/yellow]")
        
        # Display results
        search_scope = []
        if content:
            search_scope.append("content")
        if metadata:
            search_scope.append("metadata")
        if not content and not metadata:
            search_scope.append("keys")
        
        header_text = f"[bold green]🔍 Search Results[/bold green]\n"
        header_text += f"Query: [cyan]{query}[/cyan] | Scope: {', '.join(search_scope)}"
        if regex:
            header_text += " | [yellow]regex[/yellow]"
        if not case_sensitive:
            header_text += " | [dim]case-insensitive[/dim]"
        
        console.print(Panel.fit(header_text, border_style="green"))
        
        if not results:
            console.print("[yellow]No matches found[/yellow]")
            return
        
        # Format output
        if format_output and format_output.lower() == 'json':
            output_data = []
            for result in results:
                match_types = list(result['matches'].keys())
                output_data.append({
                    'key': result['key'],
                    'type': result['type'].lower(),
                    'storage': result['storage'],
                    'matches_in': match_types
                })
            console.print(json.dumps(output_data, indent=2))
        elif format_output and format_output.lower() == 'yaml':
            import yaml
            output_data = []
            for result in results:
                match_types = list(result['matches'].keys())
                output_data.append({
                    'key': result['key'],
                    'type': result['type'].lower(),
                    'storage': result['storage'],
                    'matches_in': match_types
                })
            console.print(yaml.dump(output_data, default_flow_style=False))
        else:
            # Table format
            table = Table()
            table.add_column("Key", style="cyan", width=30)
            table.add_column("Type", style="green", width=10)
            table.add_column("Matches In", style="yellow", width=15)
            table.add_column("Storage", style="dim", width=12)
            
            for result in sorted(results, key=lambda x: (x['type'], x['key'])):
                match_types = []
                if result['matches'].get('key'):
                    match_types.append("key")
                if result['matches'].get('content'):
                    match_types.append("content")
                if result['matches'].get('metadata'):
                    match_types.append("metadata")
                
                table.add_row(
                    f"{result['icon']} {result['key']}",
                    result['type'],
                    ", ".join(match_types),
                    result['storage']
                )
            
            console.print(table)
        
        # Summary
        secrets_count = len([r for r in results if r['type'] == 'Secret'])
        params_count = len([r for r in results if r['type'] == 'Parameter'])
        console.print(f"\n[bold]Summary:[/bold] {len(results)} matches ({secrets_count} secrets, {params_count} parameters)")
        
    except Exception as e:
        console.print(f"[red]❌ Error during search: {e}[/red]")
        raise typer.Exit(1)


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
@async_command
async def get_batch(
    keys: Optional[str] = typer.Argument(None, help="Comma-separated list of keys"),
    file: Optional[str] = typer.Option(None, "--file", "-f", help="Keys from file (one per line)"),
    format_output: Optional[str] = typer.Option(None, "--format", help="Output format: table|json|yaml|env"),
    fail_fast: bool = typer.Option(False, "--fail-fast", help="Stop on first error"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only show values, no formatting"),
    prefix: Optional[str] = typer.Option(None, "--prefix", help="Add prefix to keys")
):
    """Get multiple keys in batch"""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from pathlib import Path
    import json
    
    console = Console()
    
    if not keys and not file:
        console.print("[red]❌ Must provide either keys or --file option[/red]")
        console.print("[dim]Examples:[/dim]")
        console.print("[dim]  anysecret get-batch API_KEY,DB_HOST,SECRET_TOKEN[/dim]")
        console.print("[dim]  anysecret get-batch --file keys.txt[/dim]")
        raise typer.Exit(1)
    
    # Validate format option
    if format_output and format_output.lower() not in ['table', 'json', 'yaml', 'env']:
        console.print(f"[red]❌ Invalid format: {format_output}[/red]")
        console.print("[dim]Valid formats: table, json, yaml, env[/dim]")
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
        
        # Parse keys list
        key_list = []
        if file:
            try:
                file_path = Path(file)
                if not file_path.exists():
                    console.print(f"[red]❌ File not found: {file}[/red]")
                    raise typer.Exit(1)
                
                with open(file_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):  # Skip comments and empty lines
                            key_list.append(line)
            except Exception as e:
                console.print(f"[red]❌ Error reading file: {e}[/red]")
                raise typer.Exit(1)
        else:
            key_list = [k.strip() for k in keys.split(',') if k.strip()]
        
        if not key_list:
            console.print("[yellow]⚠️  No keys to retrieve[/yellow]")
            return
        
        if not quiet:
            header_text = f"[bold green]📦 Batch Retrieval[/bold green]\n"
            header_text += f"Keys: {len(key_list)}"
            if file:
                header_text += f" | Source: {file}"
            console.print(Panel.fit(header_text, border_style="green"))
        
        # Retrieve all keys
        results = []
        errors = []
        
        for key in key_list:
            actual_key = f"{prefix}{key}" if prefix else key
            
            try:
                value = None
                is_secret = False
                storage_type = None
                
                # Try to classify key first
                from ...config_manager import ConfigManager
                
                # Create temporary config for classification
                temp_config = ConfigManager({}, {})
                classification = temp_config.classify_key(actual_key)
                
                if classification == 'secret':
                    try:
                        value = await secret_mgr.get_secret(actual_key)
                        is_secret = True
                        storage_type = secret_mgr.__class__.__name__.replace('Manager', '').replace('Secret', '')
                    except Exception:
                        # Fallback to parameter if secret retrieval fails
                        value = await param_mgr.get_parameter(actual_key)
                        is_secret = False
                        storage_type = param_mgr.__class__.__name__.replace('Manager', '').replace('Parameter', '')
                else:
                    try:
                        value = await param_mgr.get_parameter(actual_key)
                        is_secret = False
                        storage_type = param_mgr.__class__.__name__.replace('Manager', '').replace('Parameter', '')
                    except Exception:
                        # Fallback to secret if parameter retrieval fails
                        value = await secret_mgr.get_secret(actual_key)
                        is_secret = True
                        storage_type = secret_mgr.__class__.__name__.replace('Manager', '').replace('Secret', '')
                
                results.append({
                    'original_key': key,
                    'actual_key': actual_key,
                    'value': value,
                    'type': 'Secret' if is_secret else 'Parameter',
                    'icon': '🔐' if is_secret else '⚙️',
                    'storage': storage_type,
                    'success': True
                })
                
            except Exception as e:
                error_info = {
                    'original_key': key,
                    'actual_key': actual_key,
                    'error': str(e),
                    'success': False
                }
                errors.append(error_info)
                results.append(error_info)
                
                if fail_fast:
                    console.print(f"[red]❌ Failed to retrieve '{actual_key}': {e}[/red]")
                    raise typer.Exit(1)
        
        # Format and display results
        successful_results = [r for r in results if r['success']]
        
        if format_output and format_output.lower() == 'json':
            output_data = {}
            for result in successful_results:
                output_data[result['actual_key']] = result['value']
            console.print(json.dumps(output_data, indent=2))
        
        elif format_output and format_output.lower() == 'yaml':
            import yaml
            output_data = {}
            for result in successful_results:
                output_data[result['actual_key']] = result['value']
            console.print(yaml.dump(output_data, default_flow_style=False))
        
        elif format_output and format_output.lower() == 'env':
            for result in successful_results:
                # Export format: KEY=value
                value_str = str(result['value']).replace('\n', '\\n').replace('"', '\\"')
                console.print(f"export {result['actual_key']}=\"{value_str}\"")
        
        elif quiet:
            # Just output values
            for result in successful_results:
                console.print(f"{result['actual_key']}={result['value']}")
        
        else:
            # Table format
            table = Table()
            table.add_column("Key", style="cyan", width=25)
            table.add_column("Type", style="green", width=10)
            table.add_column("Value", style="", width=30)
            table.add_column("Storage", style="dim", width=12)
            table.add_column("Status", style="", width=10)
            
            for result in results:
                if result['success']:
                    # Show truncated value for display
                    display_value = str(result['value'])
                    if len(display_value) > 28:
                        display_value = display_value[:25] + "..."
                    
                    table.add_row(
                        f"{result['icon']} {result['actual_key']}",
                        result['type'],
                        display_value,
                        result['storage'],
                        "[green]✅[/green]"
                    )
                else:
                    table.add_row(
                        f"❌ {result['actual_key']}",
                        "-",
                        f"[red]{result['error'][:25]}...[/red]",
                        "-",
                        "[red]FAILED[/red]"
                    )
            
            console.print(table)
        
        # Summary
        if not quiet:
            success_count = len(successful_results)
            error_count = len(errors)
            console.print(f"\n[bold]Summary:[/bold] {success_count}/{len(key_list)} successful")
            
            if errors:
                console.print(f"\n[red]❌ Errors ({error_count}):[/red]")
                for error in errors[:5]:  # Show first 5 errors
                    console.print(f"  • {error['actual_key']}: {error['error']}")
                if len(errors) > 5:
                    console.print(f"  • ... and {len(errors) - 5} more errors")
                
                if not fail_fast:
                    console.print(f"\n[dim]💡 Use --fail-fast to stop on first error[/dim]")
        
    except Exception as e:
        console.print(f"[red]❌ Error during batch retrieval: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="get-env")
@handle_errors
@async_command
async def get_env(
    prefix: Optional[str] = typer.Option(None, "--prefix", "-p", help="Filter by prefix"),
    secrets_only: bool = typer.Option(False, "--secrets-only", help="Include only secrets"),
    parameters_only: bool = typer.Option(False, "--parameters-only", help="Include only parameters"),
    export_format: bool = typer.Option(True, "--export/--no-export", help="Include 'export' keyword"),
    quote_values: bool = typer.Option(True, "--quote/--no-quote", help="Quote values"),
    uppercase: bool = typer.Option(False, "--uppercase", help="Convert keys to uppercase"),
    file_output: Optional[str] = typer.Option(None, "--output", "-o", help="Write to file instead of stdout")
):
    """Output configuration as environment variables"""
    from rich.console import Console
    from rich.panel import Panel
    from pathlib import Path
    import sys
    
    console = Console()
    
    try:
        # Import configuration managers
        from ...config_loader import initialize_config
        from ...config import get_secret_manager, get_parameter_manager
        
        # Initialize configuration
        initialize_config()
        
        # Get managers
        secret_mgr = await get_secret_manager()
        param_mgr = await get_parameter_manager()
        
        # Collect all items
        all_items = []
        
        # Get secrets if not parameters_only
        if not parameters_only:
            try:
                secrets = await secret_mgr.list_secrets()
                for key in secrets:
                    # Apply prefix filter
                    if prefix and not key.startswith(prefix):
                        continue
                    
                    try:
                        value = await secret_mgr.get_secret(key)
                        all_items.append({
                            'key': key,
                            'value': value,
                            'type': 'secret'
                        })
                    except Exception as e:
                        console.print(f"[yellow]⚠️  Could not retrieve secret '{key}': {e}[/yellow]", file=sys.stderr)
            except Exception as e:
                console.print(f"[yellow]⚠️  Could not list secrets: {e}[/yellow]", file=sys.stderr)
        
        # Get parameters if not secrets_only
        if not secrets_only:
            try:
                parameters = await param_mgr.list_parameters()
                for key in parameters:
                    # Apply prefix filter
                    if prefix and not key.startswith(prefix):
                        continue
                    
                    try:
                        value = await param_mgr.get_parameter(key)
                        all_items.append({
                            'key': key,
                            'value': value,
                            'type': 'parameter'
                        })
                    except Exception as e:
                        console.print(f"[yellow]⚠️  Could not retrieve parameter '{key}': {e}[/yellow]", file=sys.stderr)
            except Exception as e:
                console.print(f"[yellow]⚠️  Could not list parameters: {e}[/yellow]", file=sys.stderr)
        
        if not all_items:
            console.print(f"[yellow]No configuration found{' with prefix ' + prefix if prefix else ''}[/yellow]", file=sys.stderr)
            return
        
        # Prepare output
        env_lines = []
        
        # Add header comment if writing to file
        if file_output:
            env_lines.append("# Environment variables exported by AnySecret")
            env_lines.append(f"# Generated: {__import__('datetime').datetime.now().isoformat()}")
            if prefix:
                env_lines.append(f"# Prefix filter: {prefix}")
            env_lines.append("")
        
        # Sort items for consistent output
        all_items.sort(key=lambda x: (x['type'], x['key']))
        
        # Generate environment variable lines
        for item in all_items:
            key = item['key']
            value = item['value']
            
            # Transform key if needed
            if uppercase:
                key = key.upper()
            
            # Clean and escape value
            if value is None:
                value = ""
            else:
                value_str = str(value)
                
                # Escape special characters for shell
                if quote_values:
                    # Escape quotes and backslashes
                    value_str = value_str.replace('\\', '\\\\').replace('"', '\\"')
                    # Handle newlines
                    value_str = value_str.replace('\n', '\\n').replace('\r', '\\r')
                
                value = value_str
            
            # Format the export line
            if quote_values:
                env_line = f'{key}="{value}"'
            else:
                env_line = f'{key}={value}'
            
            if export_format:
                env_line = f"export {env_line}"
            
            env_lines.append(env_line)
        
        # Output results
        output_content = '\n'.join(env_lines)
        
        if file_output:
            try:
                output_path = Path(file_output)
                with open(output_path, 'w') as f:
                    f.write(output_content)
                    if not output_content.endswith('\n'):
                        f.write('\n')
                
                console.print(f"[green]✅ Environment variables written to: {output_path}[/green]", file=sys.stderr)
                console.print(f"[dim]Source with: source {output_path}[/dim]", file=sys.stderr)
                
                # Show summary
                secrets_count = len([i for i in all_items if i['type'] == 'secret'])
                params_count = len([i for i in all_items if i['type'] == 'parameter'])
                console.print(f"[bold]Summary:[/bold] {len(all_items)} variables ({secrets_count} secrets, {params_count} parameters)", file=sys.stderr)
                
            except Exception as e:
                console.print(f"[red]❌ Error writing to file: {e}[/red]", file=sys.stderr)
                raise typer.Exit(1)
        else:
            # Output to stdout (can be sourced directly)
            print(output_content)
            
            # Show summary to stderr so it doesn't interfere with sourcing
            if not file_output:
                secrets_count = len([i for i in all_items if i['type'] == 'secret'])
                params_count = len([i for i in all_items if i['type'] == 'parameter'])
                console.print(f"[dim]# Generated {len(all_items)} variables ({secrets_count} secrets, {params_count} parameters)[/dim]", file=sys.stderr)
        
    except Exception as e:
        console.print(f"[red]❌ Error generating environment variables: {e}[/red]", file=sys.stderr)
        raise typer.Exit(1)


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
@async_command
async def describe_key(
    key: str,
    format_output: Optional[str] = typer.Option(None, "--format", help="Output format: table|json|yaml"),
    show_value: bool = typer.Option(False, "--show-value", help="Include the actual value (secrets will be masked)"),
    include_history: bool = typer.Option(False, "--history", help="Include version history if available"),
    raw: bool = typer.Option(False, "--raw", help="Raw output without formatting")
):
    """Show detailed metadata for a key"""
    import json
    from datetime import datetime
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    
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
        from ...config_manager import ConfigManager
        
        # Initialize configuration
        initialize_config()
        
        # Get managers
        secret_mgr = await get_secret_manager()
        param_mgr = await get_parameter_manager()
        
        # Try to find the key and determine its type
        key_info = {
            'key': key,
            'found': False,
            'type': None,
            'value': None,
            'storage': None,
            'metadata': {},
            'classification': None,
            'history': [],
            'error': None
        }
        
        # Classify the key
        temp_config = ConfigManager({}, {})
        classification = temp_config.classify_key(key)
        key_info['classification'] = classification
        
        # Try to retrieve as the classified type first
        if classification == 'secret':
            try:
                value = await secret_mgr.get_secret(key)
                key_info['found'] = True
                key_info['type'] = 'Secret'
                key_info['value'] = value
                key_info['storage'] = secret_mgr.__class__.__name__.replace('Manager', '').replace('Secret', '')
                
                # Try to get metadata if supported
                if hasattr(secret_mgr, 'get_metadata'):
                    try:
                        metadata = await secret_mgr.get_metadata(key)
                        if metadata:
                            key_info['metadata'] = metadata
                    except:
                        pass  # Metadata not supported or available
                
                # Try to get version history if requested and supported
                if include_history and hasattr(secret_mgr, 'get_versions'):
                    try:
                        versions = await secret_mgr.get_versions(key)
                        if versions:
                            key_info['history'] = versions
                    except:
                        pass  # Version history not supported
                        
            except Exception as e:
                # Fallback to parameter
                try:
                    value = await param_mgr.get_parameter(key)
                    key_info['found'] = True
                    key_info['type'] = 'Parameter'
                    key_info['value'] = value
                    key_info['storage'] = param_mgr.__class__.__name__.replace('Manager', '').replace('Parameter', '')
                    
                    # Try to get metadata if supported
                    if hasattr(param_mgr, 'get_metadata'):
                        try:
                            metadata = await param_mgr.get_metadata(key)
                            if metadata:
                                key_info['metadata'] = metadata
                        except:
                            pass
                except Exception as param_error:
                    key_info['error'] = f"Secret error: {e}, Parameter error: {param_error}"
        else:
            # Try parameter first
            try:
                value = await param_mgr.get_parameter(key)
                key_info['found'] = True
                key_info['type'] = 'Parameter'
                key_info['value'] = value
                key_info['storage'] = param_mgr.__class__.__name__.replace('Manager', '').replace('Parameter', '')
                
                # Try to get metadata if supported
                if hasattr(param_mgr, 'get_metadata'):
                    try:
                        metadata = await param_mgr.get_metadata(key)
                        if metadata:
                            key_info['metadata'] = metadata
                    except:
                        pass
                        
                # Try to get version history if requested and supported
                if include_history and hasattr(param_mgr, 'get_versions'):
                    try:
                        versions = await param_mgr.get_versions(key)
                        if versions:
                            key_info['history'] = versions
                    except:
                        pass
                        
            except Exception as e:
                # Fallback to secret
                try:
                    value = await secret_mgr.get_secret(key)
                    key_info['found'] = True
                    key_info['type'] = 'Secret'
                    key_info['value'] = value
                    key_info['storage'] = secret_mgr.__class__.__name__.replace('Manager', '').replace('Secret', '')
                    
                    # Try to get metadata if supported
                    if hasattr(secret_mgr, 'get_metadata'):
                        try:
                            metadata = await secret_mgr.get_metadata(key)
                            if metadata:
                                key_info['metadata'] = metadata
                        except:
                            pass
                except Exception as secret_error:
                    key_info['error'] = f"Parameter error: {e}, Secret error: {secret_error}"
        
        # Check if key was found
        if not key_info['found']:
            console.print(f"[red]❌ Key '{key}' not found[/red]")
            if key_info['error']:
                console.print(f"[dim]{key_info['error']}[/dim]")
            console.print(f"\n[dim]💡 Use [cyan]anysecret list[/cyan] to see available keys[/dim]")
            raise typer.Exit(1)
        
        # Prepare display data
        display_value = key_info['value']
        if key_info['type'] == 'Secret' and not show_value:
            display_value = "[HIDDEN - use --show-value to reveal]"
        elif show_value and isinstance(display_value, str) and len(display_value) > 100:
            display_value = display_value[:97] + "..."
        
        # Format output
        if format_output and format_output.lower() == 'json':
            output_data = {
                'key': key_info['key'],
                'type': key_info['type'].lower(),
                'classification': key_info['classification'],
                'storage': key_info['storage'],
                'metadata': key_info['metadata'],
                'has_value': key_info['value'] is not None,
                'value_length': len(str(key_info['value'])) if key_info['value'] else 0
            }
            if show_value:
                output_data['value'] = key_info['value']
            if key_info['history']:
                output_data['version_count'] = len(key_info['history'])
            console.print(json.dumps(output_data, indent=2, default=str))
            
        elif format_output and format_output.lower() == 'yaml':
            import yaml
            output_data = {
                'key': key_info['key'],
                'type': key_info['type'].lower(),
                'classification': key_info['classification'],
                'storage': key_info['storage'],
                'metadata': key_info['metadata'],
                'has_value': key_info['value'] is not None,
                'value_length': len(str(key_info['value'])) if key_info['value'] else 0
            }
            if show_value:
                output_data['value'] = key_info['value']
            if key_info['history']:
                output_data['version_count'] = len(key_info['history'])
            console.print(yaml.dump(output_data, default_flow_style=False))
            
        elif raw:
            # Raw output - just the value
            if show_value:
                print(key_info['value'] or "")
            else:
                print("[HIDDEN]" if key_info['type'] == 'Secret' else (key_info['value'] or ""))
        else:
            # Rich table format
            icon = '🔐' if key_info['type'] == 'Secret' else '⚙️'
            console.print(Panel.fit(
                f"[bold green]{icon} Key Description[/bold green]\n"
                f"Key: [cyan]{key}[/cyan] | Type: [yellow]{key_info['type']}[/yellow] | Storage: [dim]{key_info['storage']}[/dim]",
                border_style="green"
            ))
            
            # Main information table
            info_table = Table()
            info_table.add_column("Property", style="cyan", width=20)
            info_table.add_column("Value", style="", width=50)
            
            info_table.add_row("Key Name", key_info['key'])
            info_table.add_row("Type", f"{icon} {key_info['type']}")
            info_table.add_row("Classification", key_info['classification'])
            info_table.add_row("Storage Backend", key_info['storage'])
            
            if key_info['value'] is not None:
                value_len = len(str(key_info['value']))
                info_table.add_row("Value Length", f"{value_len} characters")
                
                if show_value:
                    # Show actual value
                    value_display = str(display_value)
                    if '\n' in value_display:
                        value_display = value_display.replace('\n', '\\n')
                    info_table.add_row("Value", value_display)
                else:
                    info_table.add_row("Value", "[HIDDEN - use --show-value to reveal]" if key_info['type'] == 'Secret' else str(display_value))
            
            console.print(info_table)
            
            # Metadata table if available
            if key_info['metadata']:
                console.print("\n[bold]Metadata:[/bold]")
                meta_table = Table()
                meta_table.add_column("Key", style="yellow", width=25)
                meta_table.add_column("Value", style="", width=45)
                
                for meta_key, meta_value in key_info['metadata'].items():
                    # Format dates if they look like ISO timestamps
                    display_meta = str(meta_value)
                    if isinstance(meta_value, str) and 'T' in meta_value and ('Z' in meta_value or '+' in meta_value):
                        try:
                            dt = datetime.fromisoformat(meta_value.replace('Z', '+00:00'))
                            display_meta = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                        except:
                            pass  # Keep original if parsing fails
                    
                    meta_table.add_row(meta_key, display_meta)
                
                console.print(meta_table)
            
            # Version history if available
            if key_info['history']:
                console.print(f"\n[bold]Version History:[/bold] ({len(key_info['history'])} versions)")
                history_table = Table()
                history_table.add_column("Version", style="green", width=10)
                history_table.add_column("Created", style="yellow", width=20)
                history_table.add_column("Description", style="", width=35)
                
                for i, version in enumerate(key_info['history'][:10]):  # Show last 10 versions
                    version_num = str(version.get('version', i + 1))
                    created = version.get('created_date', 'Unknown')
                    description = version.get('description', 'No description')
                    
                    if isinstance(created, str) and 'T' in created:
                        try:
                            dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
                            created = dt.strftime("%Y-%m-%d %H:%M")
                        except:
                            pass
                    
                    history_table.add_row(version_num, str(created), str(description)[:32] + "..." if len(str(description)) > 32 else str(description))
                
                console.print(history_table)
                
                if len(key_info['history']) > 10:
                    console.print(f"[dim]... and {len(key_info['history']) - 10} more versions[/dim]")
            
            # Usage recommendations
            console.print(f"\n[bold]Usage:[/bold]")
            console.print(f"• Get value: [cyan]anysecret get {key}[/cyan]")
            console.print(f"• Get with hint: [cyan]anysecret get {key} --hint {key_info['type'].lower()}[/cyan]")
            if key_info['type'] == 'Secret':
                console.print(f"• Show value: [cyan]anysecret describe {key} --show-value[/cyan]")
            if key_info['history']:
                console.print(f"• Version history: [cyan]anysecret versions {key}[/cyan]")
        
    except Exception as e:
        console.print(f"[red]❌ Error describing key: {e}[/red]")
        raise typer.Exit(1)


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