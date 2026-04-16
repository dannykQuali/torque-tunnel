"""Tests for croc_manager module."""

import asyncio
import os
import platform
import secrets
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest
import pytest_asyncio

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import croc_manager


# ============================================================================
# Constants
# ============================================================================

class TestConstants:
    def test_croc_version_format(self):
        assert croc_manager.CROC_VERSION.startswith("v")
        parts = croc_manager.CROC_VERSION[1:].split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

    def test_threshold_bytes(self):
        assert croc_manager.CROC_THRESHOLD_BYTES == 300 * 1024

    def test_install_chunks(self):
        assert croc_manager.REMOTE_INSTALL_CHUNKS == 7

    def test_startup_seconds(self):
        assert croc_manager.CROC_SEND_STARTUP_SECONDS > 0


# ============================================================================
# Platform detection
# ============================================================================

class TestPlatformDetection:
    def test_cache_dir_returns_path(self):
        path = croc_manager._get_cache_dir()
        assert isinstance(path, Path)
        assert "torque-tunnel" in str(path)

    def test_binary_name_windows(self):
        with mock.patch("sys.platform", "win32"):
            assert croc_manager._get_croc_binary_name() == "croc.exe"

    def test_binary_name_linux(self):
        with mock.patch("sys.platform", "linux"):
            assert croc_manager._get_croc_binary_name() == "croc"

    def test_binary_name_darwin(self):
        with mock.patch("sys.platform", "darwin"):
            assert croc_manager._get_croc_binary_name() == "croc"

    def test_asset_name_linux_x86(self):
        with mock.patch("platform.system", return_value="Linux"), \
             mock.patch("platform.machine", return_value="x86_64"):
            asset, url = croc_manager._get_croc_asset_name()
            assert "Linux-64bit" in asset
            assert asset.endswith(".tar.gz")
            assert "github.com/schollz/croc" in url

    def test_asset_name_windows_x86(self):
        with mock.patch("platform.system", return_value="Windows"), \
             mock.patch("platform.machine", return_value="AMD64"):
            asset, url = croc_manager._get_croc_asset_name()
            assert "Windows-64bit" in asset
            assert asset.endswith(".zip")

    def test_asset_name_unsupported_platform(self):
        with mock.patch("platform.system", return_value="FreeBSD"), \
             mock.patch("platform.machine", return_value="sparc"):
            with pytest.raises(RuntimeError, match="Unsupported platform"):
                croc_manager._get_croc_asset_name()


# ============================================================================
# Code generation
# ============================================================================

class TestCodeGeneration:
    def test_code_length(self):
        code = croc_manager.generate_croc_code()
        # secrets.token_urlsafe(256) produces ~342 characters
        assert len(code) > 300
        assert len(code) < 400

    def test_code_uniqueness(self):
        codes = {croc_manager.generate_croc_code() for _ in range(10)}
        assert len(codes) == 10

    def test_code_url_safe(self):
        code = croc_manager.generate_croc_code()
        # URL-safe characters only: A-Z, a-z, 0-9, -, _
        import re
        assert re.match(r'^[A-Za-z0-9_-]+$', code)

    def test_code_entropy_bits(self):
        # 256 bytes = 2048 bits of entropy
        code = croc_manager.generate_croc_code()
        # token_urlsafe(256) should be at least 340 chars
        assert len(code) >= 340


# ============================================================================
# Mode validation
# ============================================================================

class TestModeValidation:
    def test_valid_modes(self):
        assert croc_manager._validate_mode("755")
        assert croc_manager._validate_mode("644")
        assert croc_manager._validate_mode("0755")
        assert croc_manager._validate_mode("777")
        assert croc_manager._validate_mode("000")
        assert croc_manager._validate_mode("0000")

    def test_invalid_modes(self):
        assert not croc_manager._validate_mode("foobar")
        assert not croc_manager._validate_mode("888")  # 8 is not octal
        assert not croc_manager._validate_mode("75")   # too short
        assert not croc_manager._validate_mode("75555")  # too long
        assert not croc_manager._validate_mode("755; rm -rf /")
        assert not croc_manager._validate_mode("")
        assert not croc_manager._validate_mode("abc")


# ============================================================================
# Shell escaping
# ============================================================================

class TestShellEscaping:
    def test_simple_string(self):
        assert croc_manager._shell_escape_single("hello") == "hello"

    def test_single_quote_escaping(self):
        result = croc_manager._shell_escape_single("it's a test")
        assert result == "it'\\''s a test"

    def test_double_quotes_unchanged(self):
        assert croc_manager._shell_escape_single('"hello"') == '"hello"'

    def test_spaces_unchanged(self):
        assert croc_manager._shell_escape_single("hello world") == "hello world"


# ============================================================================
# Remote install script generation
# ============================================================================

class TestRemoteInstallScript:
    def test_script_contains_croc_url(self):
        script = croc_manager.generate_remote_croc_install_script()
        assert "github.com/schollz/croc" in script
        assert croc_manager.CROC_VERSION in script

    def test_script_contains_chunk_count(self):
        script = croc_manager.generate_remote_croc_install_script()
        assert str(croc_manager.REMOTE_INSTALL_CHUNKS) in script

    def test_script_has_fallback(self):
        script = croc_manager.generate_remote_croc_install_script()
        assert "Fallback" in script or "fallback" in script.lower()

    def test_script_skips_if_installed(self):
        script = croc_manager.generate_remote_croc_install_script()
        assert "command -v croc" in script

    def test_script_checks_install_success(self):
        script = croc_manager.generate_remote_croc_install_script()
        assert "Failed to install croc" in script


# ============================================================================
# Croc receive commands generation
# ============================================================================

class TestCrocReceiveCommands:
    def test_basic_file_receive(self):
        cmds = croc_manager.generate_croc_receive_commands(
            code="test-code-123",
            file_transfers=[{
                "croc_filename": "_croc_0_data.bin",
                "remote_destination_path": "/tmp/data.bin",
            }],
        )
        assert 'CROC_SECRET="test-code-123"' in cmds
        assert "croc --yes --overwrite" in cmds
        assert "_croc_0_data.bin" in cmds
        assert "/tmp/data.bin" in cmds

    def test_file_with_mode(self):
        cmds = croc_manager.generate_croc_receive_commands(
            code="test-code",
            file_transfers=[{
                "croc_filename": "_croc_0_script.sh",
                "remote_destination_path": "/tmp/script.sh",
                "mode": "755",
            }],
        )
        assert "chmod 755" in cmds

    def test_invalid_mode_ignored(self):
        cmds = croc_manager.generate_croc_receive_commands(
            code="test-code",
            file_transfers=[{
                "croc_filename": "_croc_0_file.txt",
                "remote_destination_path": "/tmp/file.txt",
                "mode": "755; rm -rf /",
            }],
        )
        assert "rm -rf /" not in cmds.split("\n")[-5:]  # Mode injection prevented

    def test_dir_tar_extraction(self):
        cmds = croc_manager.generate_croc_receive_commands(
            code="test-code",
            file_transfers=[{
                "croc_filename": "_croc_0_mydir.tar.gz",
                "remote_destination_path": "/opt/mydir",
                "is_dir_tar": True,
            }],
        )
        assert "tar xzf" in cmds
        assert "mkdir -p" in cmds
        assert "/opt/mydir" in cmds

    def test_multiple_files(self):
        cmds = croc_manager.generate_croc_receive_commands(
            code="test-code",
            file_transfers=[
                {"croc_filename": "_croc_0_a.txt", "remote_destination_path": "/tmp/a.txt"},
                {"croc_filename": "_croc_1_b.txt", "remote_destination_path": "/opt/b.txt"},
            ],
        )
        assert "_croc_0_a.txt" in cmds
        assert "_croc_1_b.txt" in cmds
        assert "/tmp/a.txt" in cmds
        assert "/opt/b.txt" in cmds

    def test_creates_parent_directories(self):
        cmds = croc_manager.generate_croc_receive_commands(
            code="test-code",
            file_transfers=[{
                "croc_filename": "_croc_0_config.yml",
                "remote_destination_path": "/etc/app/config/deep/config.yml",
            }],
        )
        assert "mkdir -p '/etc/app/config/deep'" in cmds

    def test_error_handling_on_receive_failure(self):
        cmds = croc_manager.generate_croc_receive_commands(
            code="code",
            file_transfers=[{"croc_filename": "f", "remote_destination_path": "/f"}],
        )
        assert "exit 1" in cmds
        assert "__CROC_RC" in cmds

    def test_cleanup_temp_dir(self):
        cmds = croc_manager.generate_croc_receive_commands(
            code="code",
            file_transfers=[{"croc_filename": "f", "remote_destination_path": "/f"}],
        )
        assert "rm -rf" in cmds

    def test_special_characters_in_path(self):
        """Paths with single quotes should be escaped."""
        cmds = croc_manager.generate_croc_receive_commands(
            code="test-code",
            file_transfers=[{
                "croc_filename": "_croc_0_file.txt",
                "remote_destination_path": "/tmp/it's a file.txt",
            }],
        )
        assert "'\\''s a file" in cmds  # The shell-escaped version of single quote

    def test_croc_dir_variable_expansion_in_mv(self):
        """$__CROC_DIR must be in double quotes for shell expansion, not single quotes."""
        cmds = croc_manager.generate_croc_receive_commands(
            code="test-code",
            file_transfers=[{
                "croc_filename": "_croc_0_data.bin",
                "remote_destination_path": "/tmp/data.bin",
            }],
        )
        # Must use double quotes for variable expansion
        assert '"$__CROC_DIR/"' in cmds
        # Must NOT have $__CROC_DIR in single quotes (prevents expansion)
        assert "'$__CROC_DIR/'" not in cmds

    def test_croc_dir_variable_expansion_in_tar(self):
        """$__CROC_DIR must be in double quotes for tar extraction too."""
        cmds = croc_manager.generate_croc_receive_commands(
            code="test-code",
            file_transfers=[{
                "croc_filename": "_croc_0_mydir.tar.gz",
                "remote_destination_path": "/opt/mydir",
                "is_dir_tar": True,
            }],
        )
        assert '"$__CROC_DIR/"' in cmds
        assert "'$__CROC_DIR/'" not in cmds


# ============================================================================
# Croc SCP commands generation
# ============================================================================

class TestCrocScpCommands:
    def test_key_auth_scp(self):
        cmds = croc_manager.generate_croc_scp_commands(
            code="test-code",
            file_transfers=[{
                "croc_filename": "_croc_0_data.bin",
                "remote_destination_path": "/tmp/data.bin",
            }],
            target_ip="10.0.0.1",
            ssh_user="root",
            ssh_private_key="-----BEGIN RSA PRIVATE KEY-----\nKEYDATA\n-----END RSA PRIVATE KEY-----",
        )
        assert "CROC_SECRET" in cmds
        assert "scp" in cmds
        assert "StrictHostKeyChecking=no" in cmds
        assert "__SCP_KEY" in cmds
        assert "10.0.0.1" in cmds

    def test_password_auth_scp(self):
        cmds = croc_manager.generate_croc_scp_commands(
            code="test-code",
            file_transfers=[{
                "croc_filename": "_croc_0_data.bin",
                "remote_destination_path": "/tmp/data.bin",
            }],
            target_ip="10.0.0.1",
            ssh_user="root",
            ssh_password="mypassword",
        )
        assert "sshpass" in cmds
        assert "PubkeyAuthentication=no" in cmds

    def test_no_auth_raises(self):
        with pytest.raises(ValueError, match="ssh_private_key or ssh_password"):
            croc_manager.generate_croc_scp_commands(
                code="test-code",
                file_transfers=[],
                target_ip="10.0.0.1",
                ssh_user="root",
            )

    def test_dir_tar_extraction_via_ssh(self):
        cmds = croc_manager.generate_croc_scp_commands(
            code="test-code",
            file_transfers=[{
                "croc_filename": "_croc_0_mydir.tar.gz",
                "remote_destination_path": "/opt/mydir",
                "is_dir_tar": True,
            }],
            target_ip="10.0.0.1",
            ssh_user="root",
            ssh_private_key="KEY",
        )
        assert "tar xzf" in cmds
        assert "mkdir -p" in cmds

    def test_mode_validated(self):
        cmds = croc_manager.generate_croc_scp_commands(
            code="test-code",
            file_transfers=[{
                "croc_filename": "_croc_0_script.sh",
                "remote_destination_path": "/tmp/script.sh",
                "mode": "abc",  # Invalid
            }],
            target_ip="10.0.0.1",
            ssh_user="root",
            ssh_private_key="KEY",
        )
        # Invalid mode should be ignored
        assert "chmod abc" not in cmds

    def test_password_with_special_chars(self):
        """Password with single quotes should be escaped."""
        cmds = croc_manager.generate_croc_scp_commands(
            code="test-code",
            file_transfers=[{
                "croc_filename": "_croc_0_f.txt",
                "remote_destination_path": "/f.txt",
            }],
            target_ip="10.0.0.1",
            ssh_user="root",
            ssh_password="p@ss'word",
        )
        assert "'\\''word" in cmds  # Escaped single quote in password

    def test_croc_dir_variable_expansion_in_scp(self):
        """$__CROC_DIR must be in double quotes for SCP source path."""
        cmds = croc_manager.generate_croc_scp_commands(
            code="test-code",
            file_transfers=[{
                "croc_filename": "_croc_0_data.bin",
                "remote_destination_path": "/tmp/data.bin",
            }],
            target_ip="10.0.0.1",
            ssh_user="root",
            ssh_private_key="KEY",
        )
        assert '"$__CROC_DIR/"' in cmds
        assert "'$__CROC_DIR/'" not in cmds

    def test_croc_dir_variable_expansion_in_tar_pipe(self):
        """$__CROC_DIR must be in double quotes for tar pipe source path."""
        cmds = croc_manager.generate_croc_scp_commands(
            code="test-code",
            file_transfers=[{
                "croc_filename": "_croc_0_dir.tar.gz",
                "remote_destination_path": "/opt/dir",
                "is_dir_tar": True,
            }],
            target_ip="10.0.0.1",
            ssh_user="root",
            ssh_private_key="KEY",
        )
        assert '"$__CROC_DIR/"' in cmds
        assert "'$__CROC_DIR/'" not in cmds


# ============================================================================
# Local croc path detection
# ============================================================================

class TestLocalCrocPath:
    def test_returns_none_when_not_found(self):
        with mock.patch("shutil.which", return_value=None):
            # Also mock the cache dir to not exist
            with mock.patch.object(Path, "exists", return_value=False):
                result = croc_manager.get_local_croc_path()
                assert result is None

    def test_finds_croc_in_cache_first(self):
        """Cache dir is checked before PATH."""
        with mock.patch.object(Path, "exists", return_value=True):
            result = croc_manager.get_local_croc_path()
            # Should return cache path, not bother with PATH
            assert result is not None
            assert str(result).endswith(croc_manager._get_croc_binary_name())

    def test_finds_croc_in_path_with_matching_version(self):
        """PATH croc is used only if version matches."""
        with mock.patch.object(Path, "exists", return_value=False):  # No cache
            with mock.patch("shutil.which", return_value="/usr/bin/croc"):
                with mock.patch("subprocess.run") as mock_run:
                    mock_run.return_value = mock.Mock(
                        stdout=f"croc version {croc_manager.CROC_VERSION}\n",
                        returncode=0,
                    )
                    result = croc_manager.get_local_croc_path()
                    assert result == Path("/usr/bin/croc")

    def test_skips_path_croc_with_wrong_version(self):
        """PATH croc with wrong version should be skipped."""
        with mock.patch.object(Path, "exists", return_value=False):  # No cache
            with mock.patch("shutil.which", return_value="/usr/bin/croc"):
                with mock.patch("subprocess.run") as mock_run:
                    mock_run.return_value = mock.Mock(
                        stdout="croc version v10.3.1\n",
                        returncode=0,
                    )
                    result = croc_manager.get_local_croc_path()
                    assert result is None


# ============================================================================
# Cleanup function
# ============================================================================

class TestCleanup:
    @pytest.mark.asyncio
    async def test_cleanup_none_process(self):
        """Should not raise when process is None."""
        await croc_manager.cleanup_croc_send(None)

    @pytest.mark.asyncio
    async def test_cleanup_already_finished(self):
        """Should not raise when process already terminated."""
        mock_process = mock.AsyncMock()
        mock_process.returncode = 0  # Already terminated
        await croc_manager.cleanup_croc_send(mock_process)
        mock_process.terminate.assert_not_called()

    @pytest.mark.asyncio
    async def test_cleanup_running_process(self):
        """Should terminate a running process."""
        mock_process = mock.AsyncMock()
        mock_process.returncode = None  # Still running
        mock_process.wait = mock.AsyncMock(return_value=0)
        # After terminate, returncode changes
        type(mock_process).returncode = mock.PropertyMock(side_effect=[None, 0])
        
        await croc_manager.cleanup_croc_send(mock_process)
        mock_process.terminate.assert_called_once()


# ============================================================================
# Start croc send
# ============================================================================

class TestStartCrocSend:
    @pytest.mark.asyncio
    async def test_uses_croc_secret_env_var(self):
        """Should pass code via CROC_SECRET env var, not --code flag."""
        with mock.patch("asyncio.create_subprocess_exec") as mock_exec, \
             mock.patch("asyncio.sleep"):
            mock_proc = mock.AsyncMock()
            mock_proc.returncode = None  # Still running
            mock_exec.return_value = mock_proc

            await croc_manager.start_croc_send(
                croc_path=Path("/usr/bin/croc"),
                code="test-secret",
                files=["file1.txt"],
            )

            # Check the command doesn't contain --code
            call_args = mock_exec.call_args
            cmd_args = call_args[0]
            assert "--code" not in cmd_args
            assert "test-secret" not in cmd_args
            
            # Check CROC_SECRET is in env
            env = call_args[1]["env"]
            assert env["CROC_SECRET"] == "test-secret"

    @pytest.mark.asyncio
    async def test_raises_on_immediate_exit(self):
        """Should raise if croc exits during startup."""
        with mock.patch("asyncio.create_subprocess_exec") as mock_exec, \
             mock.patch("asyncio.sleep"):
            mock_proc = mock.AsyncMock()
            mock_proc.returncode = 1  # Exited immediately
            mock_proc.stderr.read = mock.AsyncMock(return_value=b"error message")
            mock_exec.return_value = mock_proc

            with pytest.raises(RuntimeError, match="croc send exited immediately"):
                await croc_manager.start_croc_send(
                    croc_path=Path("/usr/bin/croc"),
                    code="test",
                    files=["file1.txt"],
                )

    @pytest.mark.asyncio
    async def test_no_local_flag(self):
        """Should use --no-local flag."""
        with mock.patch("asyncio.create_subprocess_exec") as mock_exec, \
             mock.patch("asyncio.sleep"):
            mock_proc = mock.AsyncMock()
            mock_proc.returncode = None
            mock_exec.return_value = mock_proc

            await croc_manager.start_croc_send(
                croc_path=Path("/usr/bin/croc"),
                code="test",
                files=["file1.txt"],
            )

            cmd_args = mock_exec.call_args[0]
            assert "--no-local" in cmd_args
            assert "--yes" in cmd_args
            # --yes must come BEFORE "send" (it's a global option)
            yes_idx = cmd_args.index("--yes")
            send_idx = cmd_args.index("send")
            assert yes_idx < send_idx, "--yes must be before 'send' subcommand"
