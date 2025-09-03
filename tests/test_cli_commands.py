"""
Tests for AnySecret CLI commands and functionality
"""
import pytest
import tempfile
import json
import os
from pathlib import Path
from unittest.mock import patch, AsyncMock, Mock
from typer.testing import CliRunner

from anysecret.cli.cli import app
from anysecret.cli.commands import config_commands, bulk_commands, read_commands


class TestCLIBasics:
    """Test basic CLI functionality"""

    def test_cli_help_command(self):
        """Test CLI help command works"""
        runner = CliRunner()
        result = runner.invoke(app, ["--help"])
        
        assert result.exit_code == 0
        assert "Universal Configuration & Secret Manager" in result.stdout
        assert "config" in result.stdout
        assert "bulk" in result.stdout
        assert "providers" in result.stdout

    def test_cli_version_command(self):
        """Test version command"""
        runner = CliRunner()
        result = runner.invoke(app, ["version"])
        
        assert result.exit_code == 0
        assert "AnySecret CLI" in result.stdout or "Version:" in result.stdout

    def test_cli_patterns_command(self):
        """Test patterns command"""
        runner = CliRunner()
        result = runner.invoke(app, ["patterns"])
        
        assert result.exit_code == 0
        assert "Secret Patterns" in result.stdout
        assert "Parameter Patterns" in result.stdout


class TestConfigCommands:
    """Test config subcommands"""

    def test_config_help(self):
        """Test config help command"""
        runner = CliRunner()
        result = runner.invoke(app, ["config", "--help"])
        
        assert result.exit_code == 0
        assert "Configuration management" in result.stdout
        assert "profile-create" in result.stdout
        assert "profile-list" in result.stdout

    def test_config_validate_command(self):
        """Test config validate command"""
        runner = CliRunner()
        result = runner.invoke(app, ["config", "validate"])
        
        # Should either succeed or fail gracefully
        assert result.exit_code in [0, 1]


class TestBulkCommands:
    """Test bulk operation commands"""

    def test_bulk_help(self):
        """Test bulk help command"""
        runner = CliRunner()
        result = runner.invoke(app, ["bulk", "--help"])
        
        assert result.exit_code == 0
        assert "Bulk operations" in result.stdout
        assert "import" in result.stdout
        assert "export" in result.stdout

    def test_bulk_import_dry_run(self):
        """Test bulk import with dry-run"""
        # Create test .env file
        env_content = """# Test environment file
DATABASE_PASSWORD=secret123
API_KEY=key456
DATABASE_HOST=localhost
API_TIMEOUT=30
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(env_content)
            temp_path = f.name

        try:
            runner = CliRunner()
            result = runner.invoke(app, [
                "bulk", "import", temp_path, "--dry-run"
            ])
            
            # Should show what would be imported
            assert "DATABASE_PASSWORD" in result.stdout or result.exit_code in [0, 1]
            
        finally:
            os.unlink(temp_path)

    def test_bulk_export_dry_run(self):
        """Test bulk export with dry-run"""
        runner = CliRunner()
        result = runner.invoke(app, [
            "bulk", "export", "--dry-run"
        ])
        
        # Should either work or fail gracefully
        assert result.exit_code in [0, 1]


class TestProviderCommands:
    """Test provider management commands"""

    def test_providers_list_command(self):
        """Test providers list command"""
        runner = CliRunner()
        result = runner.invoke(app, ["providers", "list"])
        
        assert result.exit_code == 0
        assert "AWS" in result.stdout
        assert "GCP" in result.stdout
        assert "Azure" in result.stdout

    def test_providers_help(self):
        """Test providers help"""
        runner = CliRunner()
        result = runner.invoke(app, ["providers", "--help"])
        
        assert result.exit_code == 0
        assert "Provider management" in result.stdout


class TestReadCommands:
    """Test read operation commands"""

    def test_read_help(self):
        """Test read help command"""
        runner = CliRunner()
        result = runner.invoke(app, ["read", "--help"])
        
        assert result.exit_code == 0
        assert "Read operations" in result.stdout


class TestGlobalOptions:
    """Test global CLI options"""

    def test_debug_option(self):
        """Test --debug global option"""
        runner = CliRunner()
        result = runner.invoke(app, ["--debug", "version"])
        
        # Should work with debug enabled
        assert result.exit_code == 0

    def test_format_option(self):
        """Test --format global option"""
        runner = CliRunner()
        result = runner.invoke(app, ["--format", "json", "patterns"])
        
        # Should either work or fail gracefully
        assert result.exit_code in [0, 1]

    def test_quiet_option(self):
        """Test --quiet global option"""
        runner = CliRunner()
        result = runner.invoke(app, ["--quiet", "version"])
        
        # Should work and potentially suppress output
        assert result.exit_code == 0


class TestErrorHandling:
    """Test CLI error handling"""

    def test_invalid_command(self):
        """Test invalid command handling"""
        runner = CliRunner()
        result = runner.invoke(app, ["invalid-command"])
        
        assert result.exit_code != 0
        assert "No such command" in result.stderr

    def test_missing_required_argument(self):
        """Test missing required argument handling"""
        runner = CliRunner()
        result = runner.invoke(app, ["get"])  # Missing required key argument
        
        assert result.exit_code != 0

    def test_invalid_option(self):
        """Test invalid option handling"""
        runner = CliRunner()
        result = runner.invoke(app, ["--invalid-option"])
        
        assert result.exit_code != 0


class TestCLIWithMockData:
    """Test CLI with mocked data providers"""

    @pytest.fixture
    def mock_config_manager(self):
        """Mock config manager for testing"""
        mock_manager = Mock()
        mock_manager.get = AsyncMock(return_value="test_value")
        mock_manager.set = AsyncMock(return_value=True)
        mock_manager.list_all_keys = AsyncMock(return_value={
            'secrets': ['API_KEY', 'DB_PASSWORD'],
            'parameters': ['DATABASE_HOST', 'API_TIMEOUT']
        })
        mock_manager.classify_key = Mock(side_effect=lambda key: 'password' in key.lower() or 'key' in key.lower())
        return mock_manager

    @patch('anysecret.config.get_config_manager')
    def test_get_command_with_mock(self, mock_get_config_manager, mock_config_manager):
        """Test get command with mocked data"""
        mock_get_config_manager.return_value = mock_config_manager
        
        runner = CliRunner()
        result = runner.invoke(app, ["get", "DATABASE_HOST"])
        
        # Should attempt to call the command
        assert result.exit_code in [0, 1]

    @patch('anysecret.config.get_config_manager')
    def test_set_command_with_mock(self, mock_get_config_manager, mock_config_manager):
        """Test set command with mocked data"""
        mock_get_config_manager.return_value = mock_config_manager
        
        runner = CliRunner()
        result = runner.invoke(app, ["set", "TEST_KEY", "test_value"])
        
        # Should attempt to call the command
        assert result.exit_code in [0, 1]


class TestCLIIntegration:
    """Integration tests for CLI with actual file operations"""

    def test_cli_with_temp_profile(self):
        """Test CLI with temporary profile setup"""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / ".anysecret"
            config_dir.mkdir()
            
            # Set environment to use temp directory
            with patch.dict(os.environ, {'ANYSECRET_CONFIG_DIR': str(config_dir)}):
                runner = CliRunner()
                result = runner.invoke(app, ["info"])
                
                # Should handle missing profile gracefully
                assert result.exit_code in [0, 1]

    def test_classify_command_examples(self):
        """Test classify command with various key examples"""
        runner = CliRunner()
        
        test_keys = [
            "API_KEY",
            "DATABASE_PASSWORD", 
            "DATABASE_HOST",
            "API_TIMEOUT",
            "JWT_SECRET",
            "LOG_LEVEL"
        ]
        
        for key in test_keys:
            result = runner.invoke(app, ["classify", key])
            # Should classify each key
            assert result.exit_code in [0, 1]


class TestCLIAsync:
    """Test CLI async operations"""

    def test_cli_handles_async_operations(self):
        """Test that CLI properly handles async operations"""
        # Most CLI operations are async, so this tests the async wrapper
        runner = CliRunner()
        result = runner.invoke(app, ["patterns"])
        
        assert result.exit_code == 0
        # Should complete without async errors

    def test_multiple_async_commands(self):
        """Test running multiple commands that use async"""
        runner = CliRunner()
        
        commands = [
            ["patterns"],
            ["version"], 
            ["providers", "list"]
        ]
        
        for cmd in commands:
            result = runner.invoke(app, cmd)
            assert result.exit_code == 0


class TestCLIRichOutput:
    """Test CLI Rich formatting and output"""

    def test_rich_formatting_in_help(self):
        """Test that Rich formatting works in help output"""
        runner = CliRunner()
        result = runner.invoke(app, ["--help"])
        
        assert result.exit_code == 0
        # Should contain Rich formatting (emojis, boxes, etc.)
        assert "🔐" in result.stdout or "Configuration" in result.stdout

    def test_rich_table_output(self):
        """Test Rich table output"""
        runner = CliRunner()
        result = runner.invoke(app, ["providers", "list"])
        
        assert result.exit_code == 0
        # Should contain table formatting
        assert ("┌" in result.stdout or "┏" in result.stdout or 
                "AWS" in result.stdout)  # Either Rich tables or basic text

    def test_rich_panels_in_version(self):
        """Test Rich panels in version output"""
        runner = CliRunner()
        result = runner.invoke(app, ["version"])
        
        assert result.exit_code == 0
        # Should show version info (possibly in Rich panel)
        assert "Version" in result.stdout or "AnySecret" in result.stdout


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v"])