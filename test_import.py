#!/usr/bin/env python3
"""
Test the import functionality locally
"""

import asyncio
import json
import os

def test_env_parser():
    """Test .env file parsing logic"""
    env_content = """
# Test environment file
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_PASSWORD="super_secret_password"
API_KEY=sk_test_1234567890
API_ENDPOINT=https://api.example.com
API_TIMEOUT=30
FEATURE_NEW_UI=true
LOG_LEVEL=info
"""
    
    data = {}
    for line in env_content.strip().split('\n'):
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
            data[key] = value
    
    print("Parsed env data:")
    for key, value in data.items():
        print(f"  {key}: {value}")
    
    # Test classification (simplified)
    secret_patterns = ['PASSWORD', 'KEY', 'SECRET', 'TOKEN']
    parameter_patterns = ['HOST', 'PORT', 'URL', 'ENDPOINT', 'TIMEOUT', 'LEVEL', 'FEATURE']
    
    print("\nClassification:")
    for key, value in data.items():
        is_secret = any(pattern in key.upper() for pattern in secret_patterns)
        is_parameter = any(pattern in key.upper() for pattern in parameter_patterns)
        
        if is_secret:
            classification = "secret"
        elif is_parameter:
            classification = "parameter"
        else:
            # Default to parameter for unknown patterns
            classification = "parameter"
        
        print(f"  {key}: {classification}")
    
    return data

if __name__ == "__main__":
    print("Testing .env import parsing...")
    test_env_parser()