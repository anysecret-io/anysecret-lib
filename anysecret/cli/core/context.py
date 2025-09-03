"""
CLI Context Management
"""

from typing import Dict, Any, Optional
from dataclasses import dataclass
from pathlib import Path
import click


@dataclass
class CLIContext:
    """CLI context holds global configuration and state"""
    config: Optional[Path] = None
    profile: Optional[str] = None
    profile_data: Optional[Dict[str, Any]] = None
    provider: Optional[str] = None
    region: Optional[str] = None
    output_format: str = "table"
    verbose: int = 0
    quiet: bool = False
    debug: bool = False
    dry_run: bool = False
    no_cache: bool = False
    timeout: Optional[int] = None

    def is_verbose(self) -> bool:
        """Check if verbose mode is enabled"""
        return self.verbose > 0

    def is_debug(self) -> bool:
        """Check if debug mode is enabled"""
        return self.debug or self.verbose > 1

    def should_use_cache(self) -> bool:
        """Check if caching should be used"""
        return not self.no_cache


def get_cli_context() -> CLIContext:
    """Get the current CLI context from Click"""
    try:
        ctx = click.get_current_context()
        if ctx and hasattr(ctx, 'obj') and ctx.obj:
            return CLIContext(**ctx.obj)
    except RuntimeError:
        # No context available (probably running outside CLI)
        pass
    
    # Return default context if none available
    return CLIContext()