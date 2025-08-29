#!/bin/bash
set -e

echo "Installing Python dependencies..."
pip install -r requirements-docs.txt

echo "Building MkDocs site..."
mkdocs build

echo "Build completed! Site is in the 'site' directory."