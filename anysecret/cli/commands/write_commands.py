"""
Write Operation Commands
"""

from typing import Optional
from pathlib import Path
import typer
from rich import print as rprint

from ..core import print_not_implemented, handle_errors, async_command, requires_write_permission

app = typer.Typer(help="Write operation commands")


@app.command(name="set")
@handle_errors
@requires_write_permission
@async_command
async def set_value(
    key: str,
    value: str,
    hint: Optional[str] = typer.Option(None, "--hint", "-h", help="Classification hint: secret|parameter"),
    json_value: bool = typer.Option(False, "--json", help="Parse value as JSON"),
    base64: bool = typer.Option(False, "--base64", help="Decode base64 value"),
    description: Optional[str] = typer.Option(None, "--description", help="Add description"),
    tags: Optional[str] = typer.Option(None, "--tags", help="Add tags (key=value,key2=value2)"),
    ttl: Optional[int] = typer.Option(None, "--ttl", help="Set TTL in seconds"),
    encrypt: bool = typer.Option(False, "--encrypt", help="Force encryption"),
    if_not_exists: bool = typer.Option(False, "--if-not-exists", help="Only set if key doesn't exist")
):
    """Set a configuration value with intelligent routing"""
    import json as json_lib
    import base64 as b64_lib
    from rich.console import Console
    from rich.panel import Panel
    
    console = Console()
    
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
        
        # Process value transformations
        processed_value = value
        
        # Handle base64 decoding
        if base64:
            try:
                processed_value = b64_lib.b64decode(value).decode('utf-8')
                console.print("[dim]Base64 decoded value[/dim]")
            except Exception as e:
                console.print(f"[red]❌ Invalid base64 value: {e}[/red]")
                raise typer.Exit(1)
        
        # Handle JSON parsing
        if json_value:
            try:
                # Validate JSON
                json_lib.loads(processed_value)
                console.print("[dim]JSON validated[/dim]")
            except json_lib.JSONDecodeError as e:
                console.print(f"[red]❌ Invalid JSON value: {e}[/red]")
                raise typer.Exit(1)
        
        # Check if key exists (for if_not_exists option)
        if if_not_exists:
            try:
                # Try both managers to see if key exists
                existing_value = None
                try:
                    existing_value = await secret_mgr.get_secret(key)
                except:
                    try:
                        existing_value = await param_mgr.get_parameter(key)
                    except:
                        pass  # Key doesn't exist, which is what we want
                
                if existing_value is not None:
                    console.print(f"[yellow]⚠️  Key '{key}' already exists. Use --force to overwrite.[/yellow]")
                    return
            except Exception:
                pass  # Continue if we can't check existence
        
        # Determine classification
        classification = hint
        if not classification:
            # Use built-in classification
            temp_config = ConfigManager({}, {})
            classification = temp_config.classify_key(key)
        
        # Set value in appropriate manager
        success = False
        storage_type = None
        
        if classification == 'secret':
            try:
                # Try to create the secret first
                try:
                    await secret_mgr.create_secret(key, processed_value)
                    success = True
                except Exception as create_error:
                    # If it exists, try to update it
                    if "already exists" in str(create_error).lower():
                        await secret_mgr.update_secret(key, processed_value)
                        success = True
                    else:
                        raise create_error
                storage_type = secret_mgr.__class__.__name__.replace('Manager', '').replace('Secret', '')
            except Exception as e:
                # Only fallback to parameter if it's not an "already exists" error
                if "already exists" not in str(e).lower():
                    try:
                        await param_mgr.create_parameter(key, processed_value)
                        success = True
                        classification = 'parameter'
                        storage_type = param_mgr.__class__.__name__.replace('Manager', '').replace('Parameter', '')
                    except Exception as param_error:
                        console.print(f"[red]❌ Failed to set as secret: {e}[/red]")
                        console.print(f"[red]❌ Failed to set as parameter: {param_error}[/red]")
                        raise typer.Exit(1)
                else:
                    console.print(f"[red]❌ Failed to set as secret: {e}[/red]")
                    raise typer.Exit(1)
        else:
            try:
                # Try to create the parameter first
                try:
                    await param_mgr.create_parameter(key, processed_value)
                    success = True
                except Exception as create_error:
                    # If it exists, try to update it
                    if "already exists" in str(create_error).lower():
                        await param_mgr.update_parameter(key, processed_value)
                        success = True
                    else:
                        raise create_error
                storage_type = param_mgr.__class__.__name__.replace('Manager', '').replace('Parameter', '')
            except Exception as e:
                # Only fallback to secret if it's not an "already exists" error
                if "already exists" not in str(e).lower():
                    try:
                        await secret_mgr.create_secret(key, processed_value)
                        success = True
                        classification = 'secret'
                        storage_type = secret_mgr.__class__.__name__.replace('Manager', '').replace('Secret', '')
                    except Exception as secret_error:
                        console.print(f"[red]❌ Failed to set as parameter: {e}[/red]")
                        console.print(f"[red]❌ Failed to set as secret: {secret_error}[/red]")
                        raise typer.Exit(1)
                else:
                    console.print(f"[red]❌ Failed to set as parameter: {e}[/red]")
                    raise typer.Exit(1)
        
        if success:
            icon = '🔐' if classification == 'secret' else '⚙️'
            console.print(Panel.fit(
                f"[bold green]✅ Value Set Successfully[/bold green]\n\n"
                f"Key: [cyan]{key}[/cyan]\n"
                f"Type: {icon} [yellow]{classification.title()}[/yellow]\n"
                f"Storage: [dim]{storage_type}[/dim]\n"
                f"Value Length: [dim]{len(str(processed_value))} characters[/dim]",
                border_style="green"
            ))
            
            # Show additional info if provided
            if description:
                console.print(f"[dim]Description: {description}[/dim]")
            if tags:
                console.print(f"[dim]Tags: {tags}[/dim]")
            if ttl:
                console.print(f"[dim]TTL: {ttl} seconds[/dim]")
            
            # Usage tips
            console.print(f"\n[bold]Next steps:[/bold]")
            console.print(f"• Retrieve value: [cyan]anysecret get {key}[/cyan]")
            console.print(f"• View details: [cyan]anysecret describe {key}[/cyan]")
            if classification == 'secret':
                console.print(f"• Show value: [cyan]anysecret get {key} --raw[/cyan]")
        
    except Exception as e:
        console.print(f"[red]❌ Error setting value: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="set-secret")
@handle_errors
@requires_write_permission
@async_command
async def set_secret(
    key: str,
    value: Optional[str] = typer.Argument(None),
    file: Optional[Path] = typer.Option(None, "--file", help="Read value from file"),
    prompt: bool = typer.Option(False, "--prompt", help="Prompt for value (hidden input)"),
    description: Optional[str] = typer.Option(None, "--description", help="Add description"),
    tags: Optional[str] = typer.Option(None, "--tags", help="Add tags"),
    base64: bool = typer.Option(False, "--base64", help="Decode base64 value"),
    if_not_exists: bool = typer.Option(False, "--if-not-exists", help="Only set if key doesn't exist")
):
    """Explicitly set a value as secret"""
    import base64 as b64_lib
    from rich.console import Console
    from rich.panel import Panel
    from pathlib import Path as PathlibPath
    
    console = Console()
    
    try:
        # Import configuration managers
        from ...config_loader import initialize_config
        from ...config import get_secret_manager
        
        # Initialize configuration
        initialize_config()
        
        # Get secret manager
        secret_mgr = await get_secret_manager()
        
        # Determine value source and get value
        actual_value = None
        
        if prompt:
            import getpass
            try:
                actual_value = getpass.getpass(f"Enter secret value for '{key}': ")
                if not actual_value:
                    console.print("[red]❌ No value provided[/red]")
                    raise typer.Exit(1)
            except KeyboardInterrupt:
                console.print("\n[yellow]Operation cancelled[/yellow]")
                raise typer.Exit(130)
        elif file:
            try:
                file_path = PathlibPath(file)
                if not file_path.exists():
                    console.print(f"[red]❌ File not found: {file}[/red]")
                    raise typer.Exit(1)
                
                with open(file_path, 'r') as f:
                    actual_value = f.read()
                    # Remove trailing newline if present
                    if actual_value.endswith('\n'):
                        actual_value = actual_value[:-1]
                
                console.print(f"[dim]Read {len(actual_value)} characters from {file}[/dim]")
            except Exception as e:
                console.print(f"[red]❌ Error reading file: {e}[/red]")
                raise typer.Exit(1)
        elif value:
            actual_value = value
        else:
            console.print("[red]❌ Must provide value via argument, --file, or --prompt[/red]")
            console.print("[dim]Examples:[/dim]")
            console.print("[dim]  anysecret write set-secret API_KEY my-secret-value[/dim]")
            console.print("[dim]  anysecret write set-secret API_KEY --file secret.txt[/dim]")
            console.print("[dim]  anysecret write set-secret API_KEY --prompt[/dim]")
            raise typer.Exit(1)
        
        # Handle base64 decoding
        if base64:
            try:
                actual_value = b64_lib.b64decode(actual_value).decode('utf-8')
                console.print("[dim]Base64 decoded value[/dim]")
            except Exception as e:
                console.print(f"[red]❌ Invalid base64 value: {e}[/red]")
                raise typer.Exit(1)
        
        # Check if key exists (for if_not_exists option)
        if if_not_exists:
            try:
                existing_value = await secret_mgr.get_secret(key)
                if existing_value is not None:
                    console.print(f"[yellow]⚠️  Secret '{key}' already exists. Skipping.[/yellow]")
                    return
            except:
                pass  # Key doesn't exist, which is what we want
        
        # Set secret
        await secret_mgr.create_secret(key, actual_value)
        storage_type = secret_mgr.__class__.__name__.replace('Manager', '').replace('Secret', '')
        
        # Success message
        console.print(Panel.fit(
            f"[bold green]🔐 Secret Set Successfully[/bold green]\n\n"
            f"Key: [cyan]{key}[/cyan]\n"
            f"Type: 🔐 [yellow]Secret[/yellow]\n"
            f"Storage: [dim]{storage_type}[/dim]\n"
            f"Value Length: [dim]{len(str(actual_value))} characters[/dim]",
            border_style="green"
        ))
        
        # Show additional info if provided
        if description:
            console.print(f"[dim]Description: {description}[/dim]")
        if tags:
            console.print(f"[dim]Tags: {tags}[/dim]")
        
        # Usage tips
        console.print(f"\n[bold]Next steps:[/bold]")
        console.print(f"• Retrieve value: [cyan]anysecret get {key}[/cyan]")
        console.print(f"• Show value: [cyan]anysecret get {key} --raw[/cyan]")
        console.print(f"• View details: [cyan]anysecret describe {key}[/cyan]")
        
    except Exception as e:
        console.print(f"[red]❌ Error setting secret: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="set-parameter")
@handle_errors
@requires_write_permission
@async_command
async def set_parameter(
    key: str,
    value: Optional[str] = typer.Argument(None),
    file: Optional[Path] = typer.Option(None, "--file", help="Read value from file"),
    description: Optional[str] = typer.Option(None, "--description", help="Add description"),
    tags: Optional[str] = typer.Option(None, "--tags", help="Add tags"),
    json_value: bool = typer.Option(False, "--json", help="Parse value as JSON"),
    if_not_exists: bool = typer.Option(False, "--if-not-exists", help="Only set if key doesn't exist")
):
    """Explicitly set a value as parameter"""
    import json as json_lib
    from rich.console import Console
    from rich.panel import Panel
    from pathlib import Path as PathlibPath
    
    console = Console()
    
    try:
        # Import configuration managers
        from ...config_loader import initialize_config
        from ...config import get_parameter_manager
        
        # Initialize configuration
        initialize_config()
        
        # Get parameter manager
        param_mgr = await get_parameter_manager()
        
        # Determine value source and get value
        actual_value = None
        
        if file:
            try:
                file_path = PathlibPath(file)
                if not file_path.exists():
                    console.print(f"[red]❌ File not found: {file}[/red]")
                    raise typer.Exit(1)
                
                with open(file_path, 'r') as f:
                    actual_value = f.read()
                    # Remove trailing newline if present
                    if actual_value.endswith('\n'):
                        actual_value = actual_value[:-1]
                
                console.print(f"[dim]Read {len(actual_value)} characters from {file}[/dim]")
            except Exception as e:
                console.print(f"[red]❌ Error reading file: {e}[/red]")
                raise typer.Exit(1)
        elif value:
            actual_value = value
        else:
            console.print("[red]❌ Must provide value via argument or --file[/red]")
            console.print("[dim]Examples:[/dim]")
            console.print("[dim]  anysecret write set-parameter DB_HOST localhost[/dim]")
            console.print("[dim]  anysecret write set-parameter CONFIG --file config.json --json[/dim]")
            raise typer.Exit(1)
        
        # Handle JSON parsing
        if json_value:
            try:
                # Validate JSON
                json_lib.loads(actual_value)
                console.print("[dim]JSON validated[/dim]")
            except json_lib.JSONDecodeError as e:
                console.print(f"[red]❌ Invalid JSON value: {e}[/red]")
                raise typer.Exit(1)
        
        # Check if key exists (for if_not_exists option)
        if if_not_exists:
            try:
                existing_value = await param_mgr.get_parameter(key)
                if existing_value is not None:
                    console.print(f"[yellow]⚠️  Parameter '{key}' already exists. Skipping.[/yellow]")
                    return
            except:
                pass  # Key doesn't exist, which is what we want
        
        # Set parameter
        await param_mgr.create_parameter(key, actual_value)
        storage_type = param_mgr.__class__.__name__.replace('Manager', '').replace('Parameter', '')
        
        # Success message
        console.print(Panel.fit(
            f"[bold green]⚙️  Parameter Set Successfully[/bold green]\n\n"
            f"Key: [cyan]{key}[/cyan]\n"
            f"Type: ⚙️ [yellow]Parameter[/yellow]\n"
            f"Storage: [dim]{storage_type}[/dim]\n"
            f"Value Length: [dim]{len(str(actual_value))} characters[/dim]\n"
            f"Value: [green]{actual_value}[/green]",
            border_style="green"
        ))
        
        # Show additional info if provided
        if description:
            console.print(f"[dim]Description: {description}[/dim]")
        if tags:
            console.print(f"[dim]Tags: {tags}[/dim]")
        if json_value:
            console.print("[dim]JSON format[/dim]")
        
        # Usage tips
        console.print(f"\n[bold]Next steps:[/bold]")
        console.print(f"• Retrieve value: [cyan]anysecret get {key}[/cyan]")
        console.print(f"• View details: [cyan]anysecret describe {key}[/cyan]")
        console.print(f"• List parameters: [cyan]anysecret list --parameters-only[/cyan]")
        
    except Exception as e:
        console.print(f"[red]❌ Error setting parameter: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="update")
@handle_errors
@requires_write_permission
def update_value(
    key: str,
    value: str,
    hint: Optional[str] = typer.Option(None, "--hint", "-h", help="Classification hint"),
    description: Optional[str] = typer.Option(None, "--description", help="Update description"),
    tags: Optional[str] = typer.Option(None, "--tags", help="Update tags")
):
    """Update an existing configuration value"""
    print_not_implemented(
        "anysecret write update",
        f"Will update '{key}' with new value"
    )


@app.command(name="append")
@handle_errors
def append_value(key: str, value: str):
    """Append to an existing value"""
    print_not_implemented(
        "anysecret write append",
        f"Will append '{value}' to '{key}'"
    )


@app.command(name="replace")
@handle_errors
def replace_substring(key: str, old: str, new: str):
    """Replace substring in existing value"""
    print_not_implemented(
        "anysecret write replace",
        f"Will replace '{old}' with '{new}' in '{key}'"
    )


@app.command(name="delete")
@handle_errors
@requires_write_permission
@async_command
async def delete_value(
    key: str,
    hint: Optional[str] = typer.Option(None, "--hint", "-h", help="Classification hint"),
    force: bool = typer.Option(False, "--force", help="Skip confirmation"),
    backup: bool = typer.Option(False, "--backup", help="Backup before delete"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be deleted without doing it")
):
    """Delete a configuration value"""
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm
    import json
    from datetime import datetime
    
    console = Console()
    
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
        
        # Find the key and determine its type
        found_value = None
        found_type = None
        storage_type = None
        
        # Use hint if provided, otherwise try to classify and find
        if hint and hint.lower() == 'secret':
            try:
                found_value = await secret_mgr.get_secret(key)
                found_type = 'secret'
                storage_type = secret_mgr.__class__.__name__.replace('Manager', '').replace('Secret', '')
            except:
                console.print(f"[red]❌ Secret '{key}' not found[/red]")
                raise typer.Exit(1)
        elif hint and hint.lower() == 'parameter':
            try:
                found_value = await param_mgr.get_parameter(key)
                found_type = 'parameter'
                storage_type = param_mgr.__class__.__name__.replace('Manager', '').replace('Parameter', '')
            except:
                console.print(f"[red]❌ Parameter '{key}' not found[/red]")
                raise typer.Exit(1)
        else:
            # Try to classify and find the key
            temp_config = ConfigManager({}, {})
            classification = temp_config.classify_key(key)
            
            if classification == 'secret':
                try:
                    found_value = await secret_mgr.get_secret(key)
                    found_type = 'secret'
                    storage_type = secret_mgr.__class__.__name__.replace('Manager', '').replace('Secret', '')
                except:
                    # Fallback to parameter
                    try:
                        found_value = await param_mgr.get_parameter(key)
                        found_type = 'parameter'
                        storage_type = param_mgr.__class__.__name__.replace('Manager', '').replace('Parameter', '')
                    except:
                        console.print(f"[red]❌ Key '{key}' not found in secrets or parameters[/red]")
                        console.print(f"[dim]💡 Use [cyan]anysecret list[/cyan] to see available keys[/dim]")
                        raise typer.Exit(1)
            else:
                try:
                    found_value = await param_mgr.get_parameter(key)
                    found_type = 'parameter'
                    storage_type = param_mgr.__class__.__name__.replace('Manager', '').replace('Parameter', '')
                except:
                    # Fallback to secret
                    try:
                        found_value = await secret_mgr.get_secret(key)
                        found_type = 'secret'
                        storage_type = secret_mgr.__class__.__name__.replace('Manager', '').replace('Secret', '')
                    except:
                        console.print(f"[red]❌ Key '{key}' not found in parameters or secrets[/red]")
                        console.print(f"[dim]💡 Use [cyan]anysecret list[/cyan] to see available keys[/dim]")
                        raise typer.Exit(1)
        
        # Show what will be deleted
        icon = '🔐' if found_type == 'secret' else '⚙️'
        display_value = "[HIDDEN]" if found_type == 'secret' else str(found_value)
        if found_type != 'secret' and len(display_value) > 50:
            display_value = display_value[:47] + "..."
        
        console.print(Panel.fit(
            f"[bold yellow]🗑️  Delete Operation[/bold yellow]\n\n"
            f"Key: [cyan]{key}[/cyan]\n"
            f"Type: {icon} [yellow]{found_type.title()}[/yellow]\n"
            f"Storage: [dim]{storage_type}[/dim]\n"
            f"Value: [dim]{display_value}[/dim]",
            border_style="yellow"
        ))
        
        # Handle backup if requested
        backup_info = None
        if backup and not dry_run:
            from pathlib import Path
            backup_dir = Path.home() / ".anysecret" / "backups"
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = backup_dir / f"{key.replace('/', '_')}_{timestamp}.json"
            
            backup_data = {
                "key": key,
                "type": found_type,
                "value": found_value,
                "storage": storage_type,
                "deleted_at": datetime.now().isoformat(),
                "backup_version": "1.0"
            }
            
            try:
                with open(backup_file, 'w') as f:
                    json.dump(backup_data, f, indent=2)
                backup_info = str(backup_file)
                console.print(f"[green]💾 Backup created: {backup_file}[/green]")
            except Exception as e:
                console.print(f"[red]❌ Failed to create backup: {e}[/red]")
                if not force:
                    console.print("Use --force to delete without backup")
                    raise typer.Exit(1)
        
        # Dry run - show what would happen
        if dry_run:
            console.print("\n[bold blue]🔍 DRY RUN - No changes will be made[/bold blue]")
            console.print(f"Would delete {found_type}: [cyan]{key}[/cyan]")
            if backup:
                console.print(f"Would create backup in: [dim]~/.anysecret/backups/[/dim]")
            return
        
        # Confirmation prompt (unless force is used)
        if not force:
            console.print("\n[bold red]⚠️  WARNING: This action cannot be undone![/bold red]")
            if not backup_info:
                console.print("[dim]Consider using --backup to create a backup first[/dim]")
            
            confirmed = Confirm.ask(f"Delete {found_type} '{key}'?", default=False)
            if not confirmed:
                console.print("[yellow]Operation cancelled[/yellow]")
                return
        
        # Perform deletion
        if found_type == 'secret':
            await secret_mgr.delete_secret(key)
        else:
            await param_mgr.delete_parameter(key)
        
        # Success message
        console.print(Panel.fit(
            f"[bold green]✅ {found_type.title()} Deleted Successfully[/bold green]\n\n"
            f"Key: [cyan]{key}[/cyan]\n"
            f"Type: {icon} [yellow]{found_type.title()}[/yellow]\n"
            f"Storage: [dim]{storage_type}[/dim]",
            border_style="green"
        ))
        
        if backup_info:
            console.print(f"[green]💾 Backup available at: {backup_info}[/green]")
        
        # Usage tips
        console.print(f"\n[bold]Related commands:[/bold]")
        console.print(f"• List remaining keys: [cyan]anysecret list[/cyan]")
        console.print(f"• Verify deletion: [cyan]anysecret get {key}[/cyan] (should fail)")
        if backup_info:
            console.print(f"• Restore from backup: [cyan]anysecret restore {backup_info}[/cyan]")
        
    except Exception as e:
        console.print(f"[red]❌ Error deleting value: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="rotate")
@handle_errors
@requires_write_permission
def rotate_secret(key: str):
    """Generate new value for secret (rotation)"""
    print_not_implemented(
        "anysecret write rotate",
        f"Will rotate secret '{key}' with new generated value"
    )


@app.command(name="edit")
@handle_errors
def edit_value(
    key: str,
    editor: Optional[str] = typer.Option(None, "--editor", help="Specific editor to use")
):
    """Edit value in default/specified editor"""
    print_not_implemented(
        "anysecret write edit",
        f"Will edit '{key}' using {editor or 'default editor'}"
    )


@app.command(name="create-interactive")
@handle_errors
def create_interactive():
    """Interactive key creation wizard"""
    print_not_implemented(
        "anysecret write create-interactive",
        "Will launch interactive wizard for creating new keys"
    )


@app.command(name="generate")
@handle_errors
@requires_write_permission
def generate_secret(
    key: str,
    length: Optional[int] = typer.Option(32, "--length", "-l", help="Secret length"),
    pattern: Optional[str] = typer.Option(None, "--pattern", help="Generation pattern"),
    charset: Optional[str] = typer.Option(None, "--charset", help="Character set to use")
):
    """Generate a random secret value"""
    print_not_implemented(
        "anysecret write generate",
        f"Will generate secret '{key}' with length {length}, pattern: {pattern}"
    )


@app.command(name="generate-batch")
@handle_errors
def generate_batch(
    count: int,
    prefix: str,
    length: Optional[int] = typer.Option(32, "--length", "-l", help="Secret length")
):
    """Generate multiple random secrets"""
    print_not_implemented(
        "anysecret write generate-batch",
        f"Will generate {count} secrets with prefix '{prefix}'"
    )


@app.command(name="copy")
@handle_errors
def copy_value(source_key: str, target_key: str):
    """Copy value from one key to another"""
    print_not_implemented(
        "anysecret write copy",
        f"Will copy from '{source_key}' to '{target_key}'"
    )


@app.command(name="move")
@handle_errors
def move_value(source_key: str, target_key: str):
    """Move value from one key to another"""
    print_not_implemented(
        "anysecret write move",
        f"Will move from '{source_key}' to '{target_key}'"
    )


@app.command(name="rename")
@handle_errors
def rename_key(old_key: str, new_key: str):
    """Rename a key"""
    print_not_implemented(
        "anysecret write rename",
        f"Will rename '{old_key}' to '{new_key}'"
    )


@app.command(name="tag")
@handle_errors
def tag_key(key: str, tags: str):
    """Add tags to a key"""
    print_not_implemented(
        "anysecret write tag",
        f"Will add tags '{tags}' to '{key}'"
    )


@app.command(name="untag")
@handle_errors
def untag_key(key: str, tag_keys: str):
    """Remove tags from a key"""
    print_not_implemented(
        "anysecret write untag",
        f"Will remove tags '{tag_keys}' from '{key}'"
    )


@app.command(name="update-tags")
@handle_errors
def update_tags(
    pattern: Optional[str] = typer.Option(None, "--pattern", help="Key pattern to match"),
    add: Optional[str] = typer.Option(None, "--add", help="Tags to add"),
    remove: Optional[str] = typer.Option(None, "--remove", help="Tags to remove")
):
    """Bulk update tags on matching keys"""
    print_not_implemented(
        "anysecret write update-tags",
        f"Will update tags on pattern '{pattern}' - add: {add}, remove: {remove}"
    )


@app.command(name="expire")
@handle_errors
def set_expiration(
    pattern: str,
    ttl: int
):
    """Set expiration on keys matching pattern"""
    print_not_implemented(
        "anysecret write expire",
        f"Will set TTL {ttl} on keys matching '{pattern}'"
    )


@app.command(name="touch")
@handle_errors
def touch_key(key: str):
    """Update last modified timestamp"""
    print_not_implemented(
        "anysecret write touch",
        f"Will update timestamp for '{key}'"
    )


# Legacy compatibility functions (called from main CLI)
def set_value(key, value, hint, json_value):
    """Set value (legacy compatibility)"""
    print_not_implemented(
        "anysecret set",
        f"Will set '{key}' = '{value}' with hint: {hint}, JSON: {json_value}"
    )


def delete_value(key, hint, force):
    """Delete value (legacy compatibility)"""
    print_not_implemented(
        "anysecret delete",
        f"Will delete '{key}' with hint: {hint}, force: {force}"
    )