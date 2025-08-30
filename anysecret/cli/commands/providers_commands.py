"""
Provider Management Commands
"""

import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from ..core import print_not_implemented, handle_errors

app = typer.Typer(help="Provider management and information commands")
console = Console()


@app.command(name="list")
@handle_errors
def list_providers():
    """List all available provider types and their capabilities"""
    
    # Header
    console.print(Panel.fit(
        "[bold green]📋 Available Providers[/bold green]\n"
        "Supported secret and parameter management providers",
        border_style="green"
    ))
    
    # Provider information
    providers_info = [
        {
            "name": "AWS", 
            "secret_type": "aws",
            "param_type": "aws_parameter_store",
            "secrets": "Secrets Manager",
            "parameters": "Parameter Store", 
            "status": "✅",
            "notes": "Native cloud integration"
        },
        {
            "name": "GCP",
            "secret_type": "gcp", 
            "param_type": "gcp_config_connector",
            "secrets": "Secret Manager",
            "parameters": "Config Connector",
            "status": "✅",
            "notes": "Native cloud integration"
        },
        {
            "name": "Azure",
            "secret_type": "azure",
            "param_type": "azure_app_configuration", 
            "secrets": "Key Vault",
            "parameters": "App Configuration",
            "status": "✅",
            "notes": "Native cloud integration"
        },
        {
            "name": "Kubernetes",
            "secret_type": "kubernetes",
            "param_type": "kubernetes_configmap",
            "secrets": "Secrets",
            "parameters": "ConfigMaps",
            "status": "✅", 
            "notes": "Container native"
        },
        {
            "name": "Vault",
            "secret_type": "vault",
            "param_type": "file_json",
            "secrets": "HashiCorp Vault",
            "parameters": "Local files",
            "status": "✅",
            "notes": "Secrets only, parameters via files"
        },
        {
            "name": "Environment Files",
            "secret_type": "env_file",
            "param_type": "file_json",
            "secrets": ".env files",
            "parameters": "JSON files",
            "status": "✅",
            "notes": "Local development"
        },
        {
            "name": "Encrypted Files", 
            "secret_type": "encrypted_file",
            "param_type": "file_yaml",
            "secrets": "Encrypted files",
            "parameters": "YAML files", 
            "status": "✅",
            "notes": "Local with encryption"
        },
        {
            "name": "GitHub Actions",
            "secret_type": "github_actions",
            "param_type": "github_actions",
            "secrets": "Repository Secrets",
            "parameters": "Environment Variables",
            "status": "⏳",
            "notes": "CI/CD integration (coming soon)"
        }
    ]
    
    # Create table
    table = Table()
    table.add_column("Provider", style="cyan", width=15)
    table.add_column("Status", style="", width=6)
    table.add_column("Secret Storage", style="yellow", width=18)
    table.add_column("Parameter Storage", style="yellow", width=18)  
    table.add_column("Notes", style="dim", width=25)
    
    for provider in providers_info:
        table.add_row(
            provider["name"],
            provider["status"],
            provider["secrets"],
            provider["parameters"],
            provider["notes"]
        )
    
    console.print(table)
    
    # Usage examples
    console.print(f"\n[bold]Usage Examples:[/bold]")
    console.print(f"• Create AWS profile: [cyan]anysecret config profile-create prod[/cyan]")
    console.print(f"• Create file-based profile: [cyan]anysecret config profile-create dev[/cyan]")
    console.print(f"• Check provider health: [cyan]anysecret providers health[/cyan]")
    console.print(f"• View current status: [cyan]anysecret status[/cyan]")
    
    # Legend
    console.print(f"\n[dim]Legend: ✅ Fully supported  ⏳ In development  ❌ Not supported[/dim]")


@app.command(name="status") 
@handle_errors
def providers_status():
    """Show status of providers in current profile"""
    print_not_implemented(
        "anysecret providers status",
        "Will show detailed status of providers in current profile"
    )


@app.command(name="health")
@handle_errors  
def providers_health():
    """Check health of all configured providers across profiles"""
    import asyncio
    import logging
    from collections import defaultdict
    from rich.table import Table
    
    try:
        from ..core.config import get_config_manager
        
        config_mgr = get_config_manager()
        
        # Header
        console.print(Panel.fit(
            "[bold green]🏥 Provider Health Check[/bold green]\n"
            "Infrastructure health across all profiles",
            border_style="green"
        ))
        
        if not config_mgr.config_file.exists():
            console.print("[red]❌ No configuration found![/red]")
            console.print("[dim]Run 'anysecret config init' to create configuration[/dim]")
            return
        
        # Suppress noisy logging
        logging.getLogger().setLevel(logging.ERROR)
        
        # Group providers by type across all profiles
        provider_profiles = defaultdict(list)  # provider_type -> [profile_names]
        profiles = config_mgr.list_profiles()
        current_profile = config_mgr.get_current_profile()
        
        # Collect all provider configurations
        for profile_name in profiles:
            try:
                profile = config_mgr.get_profile_config(profile_name)
                secret_type = profile.secret_manager.get('type', 'unknown')
                param_type = profile.parameter_manager.get('type', 'unknown')
                
                provider_profiles[secret_type].append(f"{profile_name}:secrets")
                if param_type != secret_type:  # Don't duplicate if same provider
                    provider_profiles[param_type].append(f"{profile_name}:parameters")
                    
            except Exception as e:
                provider_profiles["error"].append(f"{profile_name}:error")
        
        # Create results table
        table = Table()
        table.add_column("Provider Type", style="cyan", width=16)
        table.add_column("Status", style="", width=8)
        table.add_column("Used In", style="yellow", width=30)
        table.add_column("Health Details", style="dim", width=35)
        
        # Test each provider type
        original_profile = current_profile
        provider_health = {}  # Track health status for summary
        
        for provider_type, usage_list in sorted(provider_profiles.items()):
            if provider_type == "error":
                table.add_row(
                    "Configuration Error",
                    "❌",
                    ", ".join(usage_list),
                    "Profile configuration errors"
                )
                provider_health[provider_type] = False
                continue
                
            # Find a profile that uses this provider to test with
            test_profile = None
            test_type = None  # 'secrets' or 'parameters'
            
            for usage in usage_list:
                profile_name, usage_type = usage.split(':')
                test_profile = profile_name
                test_type = usage_type
                break
            
            if not test_profile:
                continue
                
            status = "❌"
            details = "Unable to test"
            
            try:
                # Switch to test profile temporarily
                if test_profile != current_profile:
                    config_mgr.set_current_profile(test_profile)
                
                # Initialize config for this profile
                from ...config_loader import initialize_config
                from ...config import get_secret_manager, get_parameter_manager
                
                initialize_config()
                
                # Test the provider based on type
                if test_type == "secrets":
                    try:
                        mgr = asyncio.run(get_secret_manager())
                        secrets = asyncio.run(mgr.list_secrets())
                        status = "✅"
                        details = f"Connected, {len(secrets)} secrets accessible"
                        provider_health[provider_type] = True
                    except Exception as e:
                        status = "❌" 
                        details = f"Connection failed: {str(e)[:30]}..."
                        provider_health[provider_type] = False
                        
                elif test_type == "parameters":
                    try:
                        mgr = asyncio.run(get_parameter_manager())
                        params = asyncio.run(mgr.list_parameters())
                        status = "✅"
                        details = f"Connected, {len(params)} parameters accessible"
                        provider_health[provider_type] = True
                    except Exception as e:
                        status = "❌"
                        details = f"Connection failed: {str(e)[:30]}..."
                        provider_health[provider_type] = False
                        
            except Exception as e:
                status = "❌"
                details = f"Test failed: {str(e)[:30]}..."
                provider_health[provider_type] = False
                
            finally:
                # Restore original profile
                if original_profile != test_profile:
                    try:
                        config_mgr.set_current_profile(original_profile)
                    except:
                        pass
            
            # Format usage list for display
            usage_display = ", ".join([
                f"[cyan]{usage.split(':')[0]}[/cyan]:{usage.split(':')[1]}" 
                for usage in usage_list[:3]  # Show first 3
            ])
            if len(usage_list) > 3:
                usage_display += f" +{len(usage_list) - 3} more"
            
            table.add_row(
                provider_type,
                status,
                usage_display,
                details
            )
        
        console.print(table)
        
        # Summary and recommendations
        healthy_count = sum(1 for is_healthy in provider_health.values() if is_healthy)
        total_count = len(provider_health)
        
        console.print(f"\n[bold]Health Summary:[/bold] {healthy_count}/{total_count} provider types healthy")
        
        if healthy_count < total_count:
            console.print("[yellow]⚠️  Some providers have health issues. Check:[/yellow]")
            console.print("• Network connectivity to cloud providers")
            console.print("• Authentication credentials and permissions")
            console.print("• Service availability and endpoints")
            
        console.print(f"\n[dim]Current profile: [cyan]{current_profile}[/cyan][/dim]")
        console.print(f"[dim]Use [cyan]anysecret status[/cyan] for profile-specific details[/dim]")
        
    except Exception as e:
        console.print(f"[red]❌ Error performing health checks: {e}[/red]")
        import traceback
        traceback.print_exc()


@app.command(name="capabilities")
@handle_errors
def provider_capabilities(provider: str):
    """Show capabilities of a specific provider"""
    print_not_implemented(
        "anysecret providers capabilities",
        f"Will show detailed capabilities for {provider} provider"
    )


@app.command(name="configure")
@handle_errors
def configure_provider(provider: str):
    """Configure credentials for a specific provider"""
    print_not_implemented(
        "anysecret providers configure",
        f"Will configure credentials and settings for {provider} provider"
    )