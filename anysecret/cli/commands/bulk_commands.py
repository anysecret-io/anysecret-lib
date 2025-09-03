"""
Bulk Operation Commands
"""

from typing import Optional
from pathlib import Path
import os
import typer
from rich import print as rprint

from ..core import print_not_implemented, handle_errors, async_command, requires_write_permission

app = typer.Typer(help="Bulk operation commands")


@app.command(name="import")
@handle_errors
@async_command
@requires_write_permission
async def import_config(
    file: Path,
    format: Optional[str] = typer.Option(None, "--format", help="Input format: json|yaml|env|csv"),
    prefix: Optional[str] = typer.Option(None, "--prefix", help="Add prefix to imported keys"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be imported"),
    overwrite: bool = typer.Option(False, "--overwrite", help="Overwrite existing keys"),
    skip_existing: bool = typer.Option(False, "--skip-existing", help="Skip existing keys"),
    transform_script: Optional[Path] = typer.Option(None, "--transform", help="Transform script to apply")
):
    """Import configuration from file"""
    import json
    from pathlib import Path
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    
    console = Console()
    
    # Check if file exists
    if not file.exists():
        console.print(f"[red]❌ File not found: {file}[/red]")
        raise typer.Exit(1)
    
    # Detect format if not specified
    if not format:
        suffix = file.suffix.lower()
        format_map = {
            '.env': 'env',
            '.json': 'json',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.csv': 'csv'
        }
        format = format_map.get(suffix, 'env')
        console.print(f"[dim]Auto-detected format: {format}[/dim]")
    
    # Import necessary modules
    try:
        from ...config_loader import initialize_config
        from ...config import get_secret_manager, get_parameter_manager
        from ...config_manager import ConfigManager
        
        # Initialize configuration
        console.print("[dim]Initializing configuration...[/dim]")
        
        # Check if profile data is available from global context
        profile_data = None
        try:
            import typer
            if typer.current_ctx and typer.current_ctx.obj:
                profile_data = typer.current_ctx.obj.get('profile_data')
        except:
            pass  # No context available
            
        config = initialize_config(profile_data)
        console.print(f"[dim]Configuration initialized: {config is not None}[/dim]")
        
        # Get managers
        console.print("[dim]Getting secret manager...[/dim]")
        secret_mgr = await get_secret_manager()
        console.print("[dim]Getting parameter manager...[/dim]")
        param_mgr = await get_parameter_manager()
        
        # Simple classification function (avoiding ConfigManager for now)
        def classify_key(key):
            """Classify key as secret or parameter based on patterns"""
            key_upper = key.upper()
            secret_patterns = [
                'PASSWORD', 'SECRET', 'TOKEN', 'KEY', 'CREDENTIALS', 
                'PRIVATE', 'CERT', 'CERTIFICATE'
            ]
            
            # Check if it matches secret patterns
            for pattern in secret_patterns:
                if pattern in key_upper:
                    return 'secret'
            
            # Default to parameter
            return 'parameter'
        
    except Exception as e:
        console.print(f"[red]❌ Failed to initialize configuration: {e}[/red]")
        console.print(f"[dim]Exception details: {type(e).__name__}[/dim]")
        if hasattr(e, '__traceback__'):
            import traceback
            console.print(f"[dim]Traceback: {traceback.format_exc()}[/dim]")
        raise typer.Exit(1)
    
    # Parse file based on format
    data = {}
    
    try:
        with open(file, 'r') as f:
            if format == 'env':
                # Parse .env file
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    # Parse KEY=VALUE format
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        # Remove quotes from value
                        value = value.strip()
                        if value.startswith('"') and value.endswith('"'):
                            value = value[1:-1]
                        elif value.startswith("'") and value.endswith("'"):
                            value = value[1:-1]
                        # Apply prefix if specified
                        if prefix:
                            key = f"{prefix}{key}"
                        data[key] = value
            
            elif format == 'json':
                # Parse JSON file
                json_data = json.load(f)
                if isinstance(json_data, dict):
                    for key, value in json_data.items():
                        if prefix:
                            key = f"{prefix}{key}"
                        # Convert non-string values to strings
                        data[key] = str(value) if not isinstance(value, str) else value
                else:
                    console.print("[red]❌ JSON file must contain an object/dictionary[/red]")
                    raise typer.Exit(1)
            
            elif format == 'yaml':
                try:
                    import yaml
                    yaml_data = yaml.safe_load(f)
                    if isinstance(yaml_data, dict):
                        # Flatten nested YAML structure
                        def flatten_dict(d, parent_key=''):
                            items = []
                            for k, v in d.items():
                                new_key = f"{parent_key}.{k}" if parent_key else k
                                if isinstance(v, dict):
                                    items.extend(flatten_dict(v, new_key).items())
                                else:
                                    items.append((new_key, str(v)))
                            return dict(items)
                        
                        flat_data = flatten_dict(yaml_data)
                        for key, value in flat_data.items():
                            if prefix:
                                key = f"{prefix}{key}"
                            data[key] = value
                    else:
                        console.print("[red]❌ YAML file must contain a dictionary[/red]")
                        raise typer.Exit(1)
                except ImportError:
                    console.print("[red]❌ PyYAML not installed. Install with: pip install pyyaml[/red]")
                    raise typer.Exit(1)
            
            elif format == 'csv':
                import csv
                reader = csv.DictReader(f)
                for row in reader:
                    # Assume first column is key, second is value
                    if len(row) >= 2:
                        items = list(row.items())
                        key = items[0][1]  # Value of first column
                        value = items[1][1] if len(items) > 1 else ""  # Value of second column
                        if prefix:
                            key = f"{prefix}{key}"
                        data[key] = value
            
            else:
                console.print(f"[red]❌ Unsupported format: {format}[/red]")
                raise typer.Exit(1)
                
    except Exception as e:
        console.print(f"[red]❌ Error parsing file: {e}[/red]")
        raise typer.Exit(1)
    
    if not data:
        console.print("[yellow]⚠️  No data found in file[/yellow]")
        return
    
    # Show what will be imported
    table = Table(title=f"Import Preview ({len(data)} items)")
    table.add_column("Key", style="cyan")
    table.add_column("Classification", style="yellow")
    table.add_column("Action", style="green")
    
    import_plan = []
    for key, value in data.items():
        classification = classify_key(key)
        
        # Check if key exists
        action = "Create"
        if not dry_run:
            try:
                existing = None
                if classification == "secret":
                    try:
                        existing = await secret_mgr.get_secret(key)
                    except:
                        pass  # Key doesn't exist
                else:
                    try:
                        existing = await param_mgr.get_parameter(key)
                    except:
                        pass  # Key doesn't exist
                
                if existing is not None:
                    if skip_existing:
                        action = "Skip (exists)"
                    elif overwrite:
                        action = "Overwrite"
                    else:
                        action = "Skip (use --overwrite)"
            except:
                pass  # Key doesn't exist
        
        import_plan.append((key, value, classification, action))
        
        # Show value preview (truncated for security)
        value_preview = "***" if classification == "secret" else (value[:20] + "..." if len(value) > 20 else value)
        table.add_row(key, classification, action)
    
    console.print(table)
    
    if dry_run:
        console.print("\n[yellow]DRY RUN - No changes made[/yellow]")
        return
    
    # Confirm import
    if not typer.confirm(f"\nImport {len(import_plan)} configuration items?"):
        console.print("[yellow]Import cancelled[/yellow]")
        return
    
    # Perform import
    success_count = 0
    skip_count = 0
    error_count = 0
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console
    ) as progress:
        task = progress.add_task("Importing configuration...", total=len(import_plan))
        
        for key, value, classification, action in import_plan:
            if action.startswith("Skip"):
                skip_count += 1
                progress.advance(task)
                continue
            
            try:
                if classification == "secret":
                    # Try create first, then update if it exists
                    try:
                        await secret_mgr.create_secret(key, value)
                    except Exception as create_error:
                        if "already exists" in str(create_error).lower():
                            await secret_mgr.update_secret(key, value)
                        else:
                            raise create_error
                else:
                    # Try create first, then update if it exists
                    try:
                        await param_mgr.create_parameter(key, value)
                    except Exception as create_error:
                        if "already exists" in str(create_error).lower():
                            await param_mgr.update_parameter(key, value)
                        else:
                            raise create_error
                success_count += 1
            except Exception as e:
                console.print(f"[red]❌ Failed to import {key}: {e}[/red]")
                error_count += 1
            
            progress.advance(task)
    
    # Show summary
    console.print(f"\n[green]✅ Import complete:[/green]")
    console.print(f"  • Imported: {success_count}")
    if skip_count > 0:
        console.print(f"  • Skipped: {skip_count}")
    if error_count > 0:
        console.print(f"  • Errors: {error_count}")


@app.command(name="export")
@handle_errors
@async_command
async def export_config(
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file (required for secrets)"),
    format: Optional[str] = typer.Option("env", "--format", "-f", help="Output format: env|json|yaml|csv"),
    prefix: Optional[str] = typer.Option(None, "--prefix", help="Filter keys by prefix"),
    pattern: Optional[str] = typer.Option(None, "--pattern", help="Filter keys by regex pattern"),
    secrets_only: bool = typer.Option(False, "--secrets-only", help="Export only secrets"),
    parameters_only: bool = typer.Option(False, "--parameters-only", help="Export only parameters"),
    show_secrets: bool = typer.Option(False, "--show-secrets", help="Show actual secret values in terminal (USE WITH CAUTION)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview what would be exported"),
    no_comments: bool = typer.Option(False, "--no-comments", help="Exclude comments from output"),
    sort_keys: bool = typer.Option(True, "--sort/--no-sort", help="Sort keys alphabetically"),
    include_metadata: bool = typer.Option(False, "--include-metadata", help="Include metadata as comments")
):
    """Export configuration from cloud providers to file
    
    Examples:
        anysecret bulk export --output .env.production
        anysecret bulk export --format json --output config.json
        anysecret bulk export --parameters-only --output params.env
    """
    import json
    import yaml
    import re
    from datetime import datetime
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.prompt import Confirm
    
    console = Console()
    
    try:
        # Import necessary modules
        from ...config_loader import initialize_config
        from ...config import get_secret_manager, get_parameter_manager
        
        # Initialize configuration
        console.print("[dim]Initializing configuration...[/dim]")
        
        # Check if profile data is available from global context
        profile_data = None
        try:
            import typer
            if typer.current_ctx and typer.current_ctx.obj:
                profile_data = typer.current_ctx.obj.get('profile_data')
        except:
            pass  # No context available
            
        config = initialize_config(profile_data)
        
        # Get managers
        secret_mgr = await get_secret_manager()
        param_mgr = await get_parameter_manager()
        
        # Collect all configuration items
        items = {}
        secret_keys = set()
        param_keys = set()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=console
        ) as progress:
            task = progress.add_task("Fetching configuration...", total=None)
            
            # Get secrets if not parameters_only
            if not parameters_only:
                try:
                    secret_list = await secret_mgr.list_secrets(prefix)
                    for key in secret_list:
                        if pattern and not re.match(pattern, key):
                            continue
                        try:
                            secret_value = await secret_mgr.get_secret(key)
                            items[key] = secret_value
                            secret_keys.add(key)
                        except Exception as e:
                            console.print(f"[yellow]⚠️  Failed to get secret '{key}': {e}[/yellow]")
                except Exception as e:
                    console.print(f"[yellow]⚠️  Failed to list secrets: {e}[/yellow]")
            
            # Get parameters if not secrets_only
            if not secrets_only:
                try:
                    param_list = await param_mgr.list_parameters(prefix)
                    for key in param_list:
                        if pattern and not re.match(pattern, key):
                            continue
                        try:
                            param_value = await param_mgr.get_parameter(key)
                            items[key] = param_value
                            param_keys.add(key)
                        except Exception as e:
                            console.print(f"[yellow]⚠️  Failed to get parameter '{key}': {e}[/yellow]")
                except Exception as e:
                    console.print(f"[yellow]⚠️  Failed to list parameters: {e}[/yellow]")
        
        if not items:
            console.print("[yellow]⚠️  No configuration items found to export[/yellow]")
            return
        
        # Sort keys if requested
        keys = sorted(items.keys()) if sort_keys else items.keys()
        
        # Show preview table
        if dry_run or not output_file:
            table = Table(title=f"Export Preview ({len(items)} items)")
            table.add_column("Key", style="cyan")
            table.add_column("Type", style="yellow")
            table.add_column("Value", style="green")
            
            for key in keys:
                is_secret = key in secret_keys
                value_display = items[key]
                
                # Mask secrets unless explicitly requested to show
                if is_secret and not show_secrets:
                    value_display = "***"
                elif not is_secret and len(str(value_display)) > 50:
                    value_display = str(value_display)[:47] + "..."
                
                table.add_row(
                    key,
                    "🔐 Secret" if is_secret else "⚙️  Parameter",
                    str(value_display)
                )
            
            console.print(table)
            
            if dry_run:
                console.print("\n[yellow]DRY RUN - No file created[/yellow]")
                return
        
        # Check if output file is specified for secrets
        if secret_keys and not output_file and not dry_run:
            console.print("[red]❌ Output file required when exporting secrets[/red]")
            console.print("[dim]Use --output <file> to specify destination[/dim]")
            raise typer.Exit(1)
        
        # Security warning for secrets
        if secret_keys and output_file and not dry_run:
            console.print(f"\n[bold yellow]⚠️  SECURITY WARNING[/bold yellow]")
            console.print(f"Exporting {len(secret_keys)} secrets to {output_file}")
            console.print("[yellow]Secrets will be written in PLAIN TEXT[/yellow]")
            console.print("[dim]File will be created with restricted permissions (600)[/dim]")
            
            if not parameters_only:
                console.print("\n[dim]Consider using --parameters-only to exclude secrets[/dim]")
            
            # In CI mode, auto-confirm but log warning
            ci_mode = os.getenv('CI', '').lower() in ('true', '1', 'yes')
            if ci_mode:
                console.print("[dim]CI mode detected - auto-confirming[/dim]")
            else:
                if not Confirm.ask("\nContinue with export?", default=False):
                    console.print("[yellow]Export cancelled[/yellow]")
                    return
        
        # Format and prepare output
        output_lines = []
        
        if format == "env":
            # .env format
            if not no_comments:
                output_lines.append("# Generated by AnySecret")
                output_lines.append(f"# Exported at: {datetime.now().isoformat()}")
                if prefix:
                    output_lines.append(f"# Prefix filter: {prefix}")
                output_lines.append(f"# Total items: {len(items)} ({len(secret_keys)} secrets, {len(param_keys)} parameters)")
                output_lines.append("")
            
            for key in keys:
                if include_metadata and not no_comments:
                    if key in secret_keys:
                        output_lines.append(f"# [SECRET]")
                    else:
                        output_lines.append(f"# [PARAMETER]")
                
                value = items[key]
                # Escape special characters in env format
                if isinstance(value, str) and (' ' in value or '"' in value or "'" in value):
                    value = f'"{value}"'
                
                output_lines.append(f"{key}={value}")
            
            output_content = "\n".join(output_lines)
        
        elif format == "json":
            # JSON format
            export_data = {}
            
            if include_metadata:
                export_data["_metadata"] = {
                    "exported_at": datetime.now().isoformat(),
                    "total_items": len(items),
                    "secrets": len(secret_keys),
                    "parameters": len(param_keys)
                }
            
            for key in keys:
                export_data[key] = items[key]
            
            output_content = json.dumps(export_data, indent=2, sort_keys=sort_keys)
        
        elif format == "yaml":
            # YAML format
            export_data = {}
            
            if include_metadata:
                export_data["_metadata"] = {
                    "exported_at": datetime.now().isoformat(),
                    "total_items": len(items),
                    "secrets": len(secret_keys),
                    "parameters": len(param_keys)
                }
            
            for key in keys:
                export_data[key] = items[key]
            
            output_content = yaml.dump(export_data, default_flow_style=False, sort_keys=sort_keys)
        
        elif format == "csv":
            # CSV format
            import csv
            import io
            
            string_io = io.StringIO()
            writer = csv.writer(string_io)
            
            # Header
            writer.writerow(["Key", "Value", "Type"])
            
            for key in keys:
                writer.writerow([
                    key,
                    items[key],
                    "secret" if key in secret_keys else "parameter"
                ])
            
            output_content = string_io.getvalue()
        
        else:
            console.print(f"[red]❌ Unsupported format: {format}[/red]")
            raise typer.Exit(1)
        
        # Write to file or output
        if output_file:
            # Create parent directories if needed
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Write file
            output_file.write_text(output_content)
            
            # Set restrictive permissions if contains secrets
            if secret_keys:
                os.chmod(output_file, 0o600)
                console.print(f"[dim]Set file permissions to 600 (owner read/write only)[/dim]")
            
            # Check if file is in .gitignore
            gitignore_path = Path(".gitignore")
            if gitignore_path.exists() and output_file.name not in gitignore_path.read_text():
                console.print(f"[yellow]⚠️  Warning: {output_file} is not in .gitignore[/yellow]")
            
            console.print(f"\n[green]✅ Exported {len(items)} items to {output_file}[/green]")
            console.print(f"  • Secrets: {len(secret_keys)}")
            console.print(f"  • Parameters: {len(param_keys)}")
            
            if secret_keys:
                console.print(f"\n[yellow]⚠️  Remember to:[/yellow]")
                console.print(f"  • Add {output_file} to .gitignore")
                console.print(f"  • Securely handle this file")
                console.print(f"  • Delete after use if possible")
        else:
            # Output to console (masked)
            console.print("\n[bold]Exported Configuration:[/bold]")
            print(output_content)
    
    except Exception as e:
        console.print(f"[red]❌ Export failed: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="batch")
@handle_errors
def batch_operations(
    file: Optional[Path] = typer.Option(None, "--file", help="Batch operations file"),
    stdin: bool = typer.Option(False, "--stdin", help="Read operations from stdin"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what operations would be performed")
):
    """Execute batch operations from file or stdin"""
    source = "stdin" if stdin else file or "interactive"
    print_not_implemented(
        "anysecret bulk batch",
        f"Will execute batch operations from {source} - dry_run: {dry_run}"
    )


@app.command(name="transform")
@handle_errors
def transform_config(
    script: Path,
    dry_run: bool = typer.Option(False, "--dry-run", help="Show transformation preview"),
    backup: bool = typer.Option(True, "--backup", help="Backup before transformation")
):
    """Apply transformation script to configuration"""
    print_not_implemented(
        "anysecret bulk transform",
        f"Will apply transformation script {script} - backup: {backup}, dry_run: {dry_run}"
    )


@app.command(name="populate")
@handle_errors
def populate_from_template(
    template: Path,
    values: Optional[Path] = typer.Option(None, "--values", help="Values file"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be populated")
):
    """Populate configuration from template"""
    print_not_implemented(
        "anysecret bulk populate",
        f"Will populate from template {template} with values {values}"
    )


@app.command(name="seed")
@handle_errors
def seed_environment(
    environment: str,
    template: Optional[Path] = typer.Option(None, "--template", help="Environment template"),
    overwrite: bool = typer.Option(False, "--overwrite", help="Overwrite existing values")
):
    """Seed environment with initial data"""
    print_not_implemented(
        "anysecret bulk seed",
        f"Will seed environment '{environment}' - template: {template}, overwrite: {overwrite}"
    )


@app.command(name="validate")
@handle_errors
def validate_bulk(
    file: Path,
    format: Optional[str] = typer.Option(None, "--format", help="File format"),
    schema: Optional[Path] = typer.Option(None, "--schema", help="Validation schema")
):
    """Validate bulk configuration file"""
    print_not_implemented(
        "anysecret bulk validate",
        f"Will validate {file} against schema {schema}"
    )


@app.command(name="convert")
@handle_errors
def convert_format(
    input_file: Path,
    output_file: Path,
    from_format: str = typer.Option(..., "--from", help="Source format"),
    to_format: str = typer.Option(..., "--to", help="Target format")
):
    """Convert between configuration formats"""
    print_not_implemented(
        "anysecret bulk convert",
        f"Will convert {input_file} from {from_format} to {to_format} -> {output_file}"
    )


@app.command(name="merge")
@handle_errors
def merge_configs(
    files: str = typer.Argument(..., help="Comma-separated list of files to merge"),
    output: Path = typer.Option(..., "--output", help="Output file"),
    strategy: Optional[str] = typer.Option("merge", "--strategy", help="Merge strategy")
):
    """Merge multiple configuration files"""
    print_not_implemented(
        "anysecret bulk merge",
        f"Will merge {files} into {output} using {strategy} strategy"
    )


@app.command(name="split")
@handle_errors
def split_config(
    file: Path,
    output_dir: Path = typer.Option(..., "--output-dir", help="Output directory"),
    by: str = typer.Option("provider", "--by", help="Split by: provider|prefix|type")
):
    """Split configuration file by criteria"""
    print_not_implemented(
        "anysecret bulk split",
        f"Will split {file} by {by} into {output_dir}"
    )


@app.command(name="template")
@handle_errors
def template_operations():
    """Template management operations (subcommands)"""
    print_not_implemented(
        "anysecret bulk template",
        "Template operations - use subcommands: create, render, validate, list"
    )


@app.command(name="template-create")
@handle_errors
def create_template(name: str):
    """Create a new configuration template"""
    print_not_implemented(
        "anysecret bulk template-create",
        f"Will create template '{name}'"
    )


@app.command(name="template-render")
@handle_errors
def render_template(
    template: Path,
    values: Optional[Path] = typer.Option(None, "--values", help="Values file"),
    output: Optional[Path] = typer.Option(None, "--output", help="Output file")
):
    """Render configuration template"""
    print_not_implemented(
        "anysecret bulk template-render",
        f"Will render template {template} with values {values}"
    )


@app.command(name="template-validate")
@handle_errors
def validate_template(template: Path):
    """Validate template syntax"""
    print_not_implemented(
        "anysecret bulk template-validate",
        f"Will validate template {template}"
    )


@app.command(name="template-list")
@handle_errors
def list_templates():
    """List available templates"""
    print_not_implemented(
        "anysecret bulk template-list",
        "Will list all available templates"
    )


@app.command(name="diff")
@handle_errors
def diff_configs(
    file1: Path,
    file2: Path,
    format: Optional[str] = typer.Option(None, "--format", help="File format"),
    ignore_order: bool = typer.Option(False, "--ignore-order", help="Ignore key order")
):
    """Compare two configuration files"""
    print_not_implemented(
        "anysecret bulk diff",
        f"Will compare {file1} vs {file2} - ignore_order: {ignore_order}"
    )


@app.command(name="stats")
@handle_errors
def config_stats(
    file: Optional[Path] = typer.Option(None, "--file", help="Configuration file to analyze")
):
    """Show configuration statistics"""
    source = file or "current configuration"
    print_not_implemented(
        "anysecret bulk stats",
        f"Will show statistics for {source}"
    )