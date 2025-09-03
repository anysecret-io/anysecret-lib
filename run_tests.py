#!/usr/bin/env python3
"""
Test runner for AnySecret
Provides easy ways to run different test suites
"""

import subprocess
import sys
from pathlib import Path


def run_command(cmd):
    """Run command and return result"""
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    return result.returncode == 0


def main():
    """Main test runner"""
    if len(sys.argv) < 2:
        print("""
AnySecret Test Runner

Usage:
    python run_tests.py <suite>

Test suites:
    smoke       - Quick smoke tests (basic functionality)
    cli         - CLI command tests  
    unit        - Unit tests for core components
    integration - Integration tests (slower)
    all         - All tests
    file <path> - Run specific test file
    
Examples:
    python run_tests.py smoke
    python run_tests.py cli
    python run_tests.py file tests/test_basic.py
        """)
        return

    suite = sys.argv[1]
    
    base_cmd = [sys.executable, "-m", "pytest", "-x"]  # Stop on first failure
    
    if suite == "smoke":
        cmd = base_cmd + [
            "tests/test_basic.py::TestSmokeBasicComponents",
            "tests/test_basic.py::TestSmokeEnvFileManager", 
            "tests/test_basic.py::TestSmokeCLI",
        ]
        
    elif suite == "cli":
        cmd = base_cmd + [
            "tests/test_cli_commands.py::TestCLIBasics",
            "tests/test_cli_commands.py::TestProviderCommands",
            "tests/test_cli_commands.py::TestConfigCommands",
        ]
        
    elif suite == "unit":
        cmd = base_cmd + [
            "tests/test_basic.py",
            "tests/test_config_manager.py",
            "-m", "not slow"
        ]
        
    elif suite == "integration":
        cmd = base_cmd + [
            "tests/test_basic.py::TestSmokeIntegration",
            "-m", "slow"
        ]
        
    elif suite == "all":
        cmd = base_cmd + ["tests/"]
        
    elif suite == "file" and len(sys.argv) > 2:
        cmd = base_cmd + [sys.argv[2]]
        
    else:
        print(f"Unknown test suite: {suite}")
        return
    
    success = run_command(cmd)
    
    if success:
        print("\n✅ All tests passed!")
    else:
        print("\n❌ Some tests failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()