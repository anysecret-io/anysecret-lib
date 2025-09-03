#!/usr/bin/env python3
"""
AnySecret CLI Entry Point

This is the main entry point for the anysecret command-line interface.
It imports and exposes the full CLI application from cli.py.
"""

from .cli import app

if __name__ == "__main__":
    app()