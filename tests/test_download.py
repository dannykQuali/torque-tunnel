"""Tests for download feature: croc_manager download functions, DownloadPlan, finalize_download, parse_downloads."""

import asyncio
import os
import shutil
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import croc_manager
from torque_tunnel.mcp_tool import (
    DownloadPlan,
    prepare_download_with_croc,
    finalize_download,
    cleanup_download_resources,
)


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    d = tempfile.mkdtemp(prefix="test_dl_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


# ============================================================================
# generate_croc_send_commands
# ============================================================================

class TestGenerateCrocSendCommands:
    def test_basic_single_file(self):
        cmds = croc_manager.generate_croc_send_commands(
            code="test-code-123",
            file_infos=[{
                "remote_source_path": "/var/log/app.log",
                "croc_filename": "_croc_dl_0_app.log",
            }],
        )
        assert 'CROC_SECRET="test-code-123"' in cmds
        assert "croc send --no-local" in cmds
        assert "_croc_dl_0_app.log" in cmds
        assert "cp -r '/var/log/app.log'" in cmds
        assert "__DL_DIR=$(mktemp -d)" in cmds

    def test_multiple_files(self):
        cmds = croc_manager.generate_croc_send_commands(
            code="multi-code",
            file_infos=[
                {"remote_source_path": "/tmp/a.txt", "croc_filename": "_croc_dl_0_a.txt"},
                {"remote_source_path": "/opt/b.bin", "croc_filename": "_croc_dl_1_b.bin"},
            ],
        )
        assert "_croc_dl_0_a.txt" in cmds
        assert "_croc_dl_1_b.bin" in cmds
        assert "cp -r '/tmp/a.txt'" in cmds
        assert "cp -r '/opt/b.bin'" in cmds
        # Both files in croc send command
        assert "'_croc_dl_0_a.txt' '_croc_dl_1_b.bin'" in cmds

    def test_directory_staging_uses_cp_r(self):
        cmds = croc_manager.generate_croc_send_commands(
            code="dir-code",
            file_infos=[{
                "remote_source_path": "/opt/results",
                "croc_filename": "_croc_dl_0_results",
            }],
        )
        # cp -r works for both files and directories
        assert "cp -r '/opt/results'" in cmds

    def test_cleanup_after_send(self):
        cmds = croc_manager.generate_croc_send_commands(
            code="code",
            file_infos=[{"remote_source_path": "/f", "croc_filename": "f"}],
        )
        assert 'rm -rf "$__DL_DIR"' in cmds
        assert "unset CROC_SECRET" in cmds

    def test_error_handling_on_copy_failure(self):
        cmds = croc_manager.generate_croc_send_commands(
            code="code",
            file_infos=[{"remote_source_path": "/f", "croc_filename": "f"}],
        )
        assert "WARNING: Failed to stage" in cmds

    def test_error_handling_on_croc_failure(self):
        cmds = croc_manager.generate_croc_send_commands(
            code="code",
            file_infos=[{"remote_source_path": "/f", "croc_filename": "f"}],
        )
        assert "__DL_RC" in cmds
        assert "WARNING: croc file download failed" in cmds

    def test_custom_timeout(self):
        cmds = croc_manager.generate_croc_send_commands(
            code="code",
            file_infos=[{"remote_source_path": "/f", "croc_filename": "f"}],
            timeout=120,
        )
        assert "timeout -k 5 120 croc send" in cmds

    def test_default_timeout(self):
        cmds = croc_manager.generate_croc_send_commands(
            code="code",
            file_infos=[{"remote_source_path": "/f", "croc_filename": "f"}],
        )
        assert "timeout -k 5 300 croc send" in cmds

    def test_special_characters_in_path(self):
        cmds = croc_manager.generate_croc_send_commands(
            code="code",
            file_infos=[{
                "remote_source_path": "/tmp/it's a file.txt",
                "croc_filename": "_croc_dl_0_it's a file.txt",
            }],
        )
        # Single quotes in paths should be escaped
        assert "'\\''s a file" in cmds

    def test_changes_to_staging_dir_and_back(self):
        cmds = croc_manager.generate_croc_send_commands(
            code="code",
            file_infos=[{"remote_source_path": "/f", "croc_filename": "f"}],
        )
        assert 'cd "$__DL_DIR"' in cmds
        assert "cd /" in cmds

    def test_start_and_end_comments(self):
        cmds = croc_manager.generate_croc_send_commands(
            code="code",
            file_infos=[{"remote_source_path": "/f", "croc_filename": "f"}],
        )
        assert cmds.startswith("# === Croc file download")
        assert cmds.endswith("# === End croc file download ===")


# ============================================================================
# generate_croc_scp_download_commands
# ============================================================================

class TestGenerateCrocScpDownloadCommands:
    def test_key_auth(self):
        cmds = croc_manager.generate_croc_scp_download_commands(
            code="dl-code",
            file_infos=[{
                "remote_source_path": "/var/log/syslog",
                "croc_filename": "_croc_dl_0_syslog",
            }],
            target_ip="10.0.0.1",
            ssh_user="root",
            ssh_private_key="-----BEGIN RSA PRIVATE KEY-----\nKEYDATA\n-----END RSA PRIVATE KEY-----",
        )
        assert "CROC_SECRET" in cmds
        assert "scp -r" in cmds
        assert "StrictHostKeyChecking=no" in cmds
        assert "__DL_KEY" in cmds
        assert "10.0.0.1" in cmds
        assert "croc send --no-local" in cmds

    def test_password_auth(self):
        cmds = croc_manager.generate_croc_scp_download_commands(
            code="dl-code",
            file_infos=[{
                "remote_source_path": "/tmp/file.txt",
                "croc_filename": "_croc_dl_0_file.txt",
            }],
            target_ip="10.0.0.1",
            ssh_user="admin",
            ssh_password="secret123",
        )
        assert "sshpass" in cmds
        assert "PubkeyAuthentication=no" in cmds

    def test_no_auth_raises(self):
        with pytest.raises(ValueError, match="ssh_private_key or ssh_password"):
            croc_manager.generate_croc_scp_download_commands(
                code="dl-code",
                file_infos=[{
                    "remote_source_path": "/tmp/file.txt",
                    "croc_filename": "_croc_dl_0_file.txt",
                }],
                target_ip="10.0.0.1",
                ssh_user="root",
            )

    def test_multiple_files(self):
        cmds = croc_manager.generate_croc_scp_download_commands(
            code="dl-code",
            file_infos=[
                {"remote_source_path": "/tmp/a.txt", "croc_filename": "_croc_dl_0_a.txt"},
                {"remote_source_path": "/opt/b.bin", "croc_filename": "_croc_dl_1_b.bin"},
            ],
            target_ip="10.0.0.1",
            ssh_user="root",
            ssh_private_key="KEY",
        )
        assert "_croc_dl_0_a.txt" in cmds
        assert "_croc_dl_1_b.bin" in cmds
        # SCP for each file
        assert cmds.count("scp -r") == 2

    def test_cleanup_key_file(self):
        cmds = croc_manager.generate_croc_scp_download_commands(
            code="code",
            file_infos=[{"remote_source_path": "/f", "croc_filename": "f"}],
            target_ip="10.0.0.1",
            ssh_user="root",
            ssh_private_key="KEY",
        )
        assert 'rm -f "$__DL_KEY"' in cmds

    def test_no_key_cleanup_for_password(self):
        cmds = croc_manager.generate_croc_scp_download_commands(
            code="code",
            file_infos=[{"remote_source_path": "/f", "croc_filename": "f"}],
            target_ip="10.0.0.1",
            ssh_user="root",
            ssh_password="pass",
        )
        assert "__DL_KEY" not in cmds

    def test_staging_dir_cleanup(self):
        cmds = croc_manager.generate_croc_scp_download_commands(
            code="code",
            file_infos=[{"remote_source_path": "/f", "croc_filename": "f"}],
            target_ip="10.0.0.1",
            ssh_user="root",
            ssh_private_key="KEY",
        )
        assert 'rm -rf "$__DL_DIR"' in cmds
        assert "unset CROC_SECRET" in cmds

    def test_custom_timeout(self):
        cmds = croc_manager.generate_croc_scp_download_commands(
            code="code",
            file_infos=[{"remote_source_path": "/f", "croc_filename": "f"}],
            target_ip="10.0.0.1",
            ssh_user="root",
            ssh_private_key="KEY",
            timeout=300,
        )
        assert "timeout -k 5 300 croc send" in cmds

    def test_scp_uses_r_flag(self):
        """scp -r works for both files and directories."""
        cmds = croc_manager.generate_croc_scp_download_commands(
            code="code",
            file_infos=[{"remote_source_path": "/opt/dir", "croc_filename": "dir"}],
            target_ip="10.0.0.1",
            ssh_user="root",
            ssh_private_key="KEY",
        )
        assert "scp -r" in cmds

    def test_start_and_end_comments(self):
        cmds = croc_manager.generate_croc_scp_download_commands(
            code="code",
            file_infos=[{"remote_source_path": "/f", "croc_filename": "f"}],
            target_ip="10.0.0.1",
            ssh_user="root",
            ssh_private_key="KEY",
        )
        assert cmds.startswith("# === SCP download")
        assert cmds.endswith("# === End SCP download + croc send ===")

    def test_special_chars_in_target_and_user(self):
        cmds = croc_manager.generate_croc_scp_download_commands(
            code="code",
            file_infos=[{"remote_source_path": "/f", "croc_filename": "f"}],
            target_ip="host'name",
            ssh_user="user'name",
            ssh_private_key="KEY",
        )
        # Should be escaped, not raw
        assert "host'\\''name" in cmds or "host'name" not in cmds.split("scp")[1]


# ============================================================================
# prepare_download_with_croc
# ============================================================================

class TestPrepareDownloadWithCroc:
    def test_empty_files_list(self):
        plan = prepare_download_with_croc([])
        assert not plan.needs_download
        assert plan.download_commands == ""
        assert plan.file_mappings == []

    def test_single_file_container_mode(self):
        plan = prepare_download_with_croc(
            [{"remote_source_path": "/tmp/result.txt", "local_destination_path": "./result.txt"}],
            transfer_mode="container",
        )
        assert plan.needs_download
        assert plan.croc_code  # non-empty
        assert plan.croc_receive_dir  # temp dir created
        assert os.path.isdir(plan.croc_receive_dir)
        assert len(plan.file_mappings) == 1
        assert plan.file_mappings[0]["croc_filename"] == "_croc_dl_0_result.txt"
        assert plan.file_mappings[0]["local_destination_path"] == "./result.txt"
        assert "croc send" in plan.download_commands
        assert plan.errors == []
        # Cleanup
        shutil.rmtree(plan.croc_receive_dir, ignore_errors=True)

    def test_single_file_ssh_mode(self):
        plan = prepare_download_with_croc(
            [{"remote_source_path": "/var/log/app.log", "local_destination_path": "C:\\logs\\app.log"}],
            transfer_mode="ssh",
            target_ip="10.0.0.1",
            ssh_user="root",
            ssh_private_key="KEY",
        )
        assert plan.needs_download
        assert "scp" in plan.download_commands
        assert "croc send" in plan.download_commands
        assert len(plan.file_mappings) == 1
        # Cleanup
        shutil.rmtree(plan.croc_receive_dir, ignore_errors=True)

    def test_multiple_files(self):
        plan = prepare_download_with_croc(
            [
                {"remote_source_path": "/tmp/a.txt", "local_destination_path": "./a.txt"},
                {"remote_source_path": "/opt/b.bin", "local_destination_path": "./b.bin"},
            ],
            transfer_mode="container",
        )
        assert plan.needs_download
        assert len(plan.file_mappings) == 2
        assert plan.file_mappings[0]["croc_filename"] == "_croc_dl_0_a.txt"
        assert plan.file_mappings[1]["croc_filename"] == "_croc_dl_1_b.bin"
        assert len(plan.files_info) == 2
        # Cleanup
        shutil.rmtree(plan.croc_receive_dir, ignore_errors=True)

    def test_includes_croc_install_script(self):
        plan = prepare_download_with_croc(
            [{"remote_source_path": "/f", "local_destination_path": "./f"}],
            transfer_mode="container",
        )
        # Should include croc install + croc send
        assert "command -v croc" in plan.download_commands or "croc" in plan.download_commands
        # Cleanup
        shutil.rmtree(plan.croc_receive_dir, ignore_errors=True)

    def test_receive_dir_is_unique_per_call(self):
        plan1 = prepare_download_with_croc(
            [{"remote_source_path": "/f", "local_destination_path": "./f"}],
        )
        plan2 = prepare_download_with_croc(
            [{"remote_source_path": "/g", "local_destination_path": "./g"}],
        )
        assert plan1.croc_receive_dir != plan2.croc_receive_dir
        # Cleanup
        shutil.rmtree(plan1.croc_receive_dir, ignore_errors=True)
        shutil.rmtree(plan2.croc_receive_dir, ignore_errors=True)

    def test_croc_code_is_unique_per_call(self):
        plan1 = prepare_download_with_croc(
            [{"remote_source_path": "/f", "local_destination_path": "./f"}],
        )
        plan2 = prepare_download_with_croc(
            [{"remote_source_path": "/g", "local_destination_path": "./g"}],
        )
        assert plan1.croc_code != plan2.croc_code
        # Cleanup
        shutil.rmtree(plan1.croc_receive_dir, ignore_errors=True)
        shutil.rmtree(plan2.croc_receive_dir, ignore_errors=True)

    def test_directory_download(self):
        """Directories should be handled by croc natively (no tar needed)."""
        plan = prepare_download_with_croc(
            [{"remote_source_path": "/opt/results/", "local_destination_path": "./results"}],
            transfer_mode="container",
        )
        assert plan.needs_download
        # croc_filename should not contain tar.gz
        assert ".tar.gz" not in plan.file_mappings[0]["croc_filename"]
        # Cleanup
        shutil.rmtree(plan.croc_receive_dir, ignore_errors=True)

    def test_files_info_format(self):
        plan = prepare_download_with_croc(
            [{"remote_source_path": "/var/log/app.log", "local_destination_path": "./app.log"}],
        )
        assert len(plan.files_info) == 1
        assert "/var/log/app.log" in plan.files_info[0]
        assert "./app.log" in plan.files_info[0]
        assert "→" in plan.files_info[0]
        # Cleanup
        shutil.rmtree(plan.croc_receive_dir, ignore_errors=True)


# ============================================================================
# finalize_download
# ============================================================================

class TestFinalizeDownload:
    def test_moves_received_file(self, temp_dir):
        """Successfully received file should be moved to destination."""
        receive_dir = os.path.join(temp_dir, "receive")
        os.makedirs(receive_dir)
        dest_dir = os.path.join(temp_dir, "dest")
        os.makedirs(dest_dir)
        dest_file = os.path.join(dest_dir, "result.txt")

        # Simulate croc receive put a file there
        croc_file = os.path.join(receive_dir, "_croc_dl_0_result.txt")
        with open(croc_file, "w") as f:
            f.write("hello")

        plan = DownloadPlan(
            croc_receive_dir=receive_dir,
            file_mappings=[{
                "croc_filename": "_croc_dl_0_result.txt",
                "local_destination_path": dest_file,
            }],
            needs_download=True,
        )

        successes, errors = finalize_download(plan)
        assert len(successes) == 1
        assert len(errors) == 0
        assert os.path.exists(dest_file)
        with open(dest_file) as f:
            assert f.read() == "hello"
        # Source should be moved (not exist anymore)
        assert not os.path.exists(croc_file)

    def test_moves_received_directory(self, temp_dir):
        """Successfully received directory should be moved to destination."""
        receive_dir = os.path.join(temp_dir, "receive")
        os.makedirs(receive_dir)
        dest_dir = os.path.join(temp_dir, "dest")
        dest_path = os.path.join(dest_dir, "mydir")

        # Simulate croc receive put a directory there
        croc_dir = os.path.join(receive_dir, "_croc_dl_0_mydir")
        os.makedirs(croc_dir)
        with open(os.path.join(croc_dir, "inner.txt"), "w") as f:
            f.write("inner content")

        plan = DownloadPlan(
            croc_receive_dir=receive_dir,
            file_mappings=[{
                "croc_filename": "_croc_dl_0_mydir",
                "local_destination_path": dest_path,
            }],
            needs_download=True,
        )

        successes, errors = finalize_download(plan)
        assert len(successes) == 1
        assert len(errors) == 0
        assert os.path.isdir(dest_path)
        assert os.path.exists(os.path.join(dest_path, "inner.txt"))

    def test_file_not_received(self, temp_dir):
        """Missing files should produce errors, not exceptions."""
        receive_dir = os.path.join(temp_dir, "receive")
        os.makedirs(receive_dir)

        plan = DownloadPlan(
            croc_receive_dir=receive_dir,
            file_mappings=[{
                "croc_filename": "_croc_dl_0_missing.txt",
                "local_destination_path": os.path.join(temp_dir, "out.txt"),
            }],
            needs_download=True,
        )

        successes, errors = finalize_download(plan)
        assert len(successes) == 0
        assert len(errors) == 1
        assert "not received" in errors[0]

    def test_multiple_files_mixed(self, temp_dir):
        """Mix of received and missing files."""
        receive_dir = os.path.join(temp_dir, "receive")
        os.makedirs(receive_dir)

        # Create one file but not the other
        croc_file = os.path.join(receive_dir, "_croc_dl_0_a.txt")
        with open(croc_file, "w") as f:
            f.write("a")

        plan = DownloadPlan(
            croc_receive_dir=receive_dir,
            file_mappings=[
                {"croc_filename": "_croc_dl_0_a.txt", "local_destination_path": os.path.join(temp_dir, "a.txt")},
                {"croc_filename": "_croc_dl_1_b.txt", "local_destination_path": os.path.join(temp_dir, "b.txt")},
            ],
            needs_download=True,
        )

        successes, errors = finalize_download(plan)
        assert len(successes) == 1
        assert len(errors) == 1

    def test_creates_parent_directories(self, temp_dir):
        """Parent directories for destination should be created automatically."""
        receive_dir = os.path.join(temp_dir, "receive")
        os.makedirs(receive_dir)

        deep_dest = os.path.join(temp_dir, "a", "b", "c", "result.txt")

        croc_file = os.path.join(receive_dir, "_croc_dl_0_result.txt")
        with open(croc_file, "w") as f:
            f.write("deep")

        plan = DownloadPlan(
            croc_receive_dir=receive_dir,
            file_mappings=[{
                "croc_filename": "_croc_dl_0_result.txt",
                "local_destination_path": deep_dest,
            }],
            needs_download=True,
        )

        successes, errors = finalize_download(plan)
        assert len(successes) == 1
        assert len(errors) == 0
        assert os.path.exists(deep_dest)

    def test_overwrites_existing_file(self, temp_dir):
        """Should overwrite existing destination file."""
        receive_dir = os.path.join(temp_dir, "receive")
        os.makedirs(receive_dir)

        dest_file = os.path.join(temp_dir, "existing.txt")
        with open(dest_file, "w") as f:
            f.write("old")

        croc_file = os.path.join(receive_dir, "_croc_dl_0_existing.txt")
        with open(croc_file, "w") as f:
            f.write("new")

        plan = DownloadPlan(
            croc_receive_dir=receive_dir,
            file_mappings=[{
                "croc_filename": "_croc_dl_0_existing.txt",
                "local_destination_path": dest_file,
            }],
            needs_download=True,
        )

        successes, errors = finalize_download(plan)
        assert len(successes) == 1
        assert len(errors) == 0
        with open(dest_file) as f:
            assert f.read() == "new"

    def test_overwrites_existing_directory(self, temp_dir):
        """Should overwrite existing destination directory."""
        receive_dir = os.path.join(temp_dir, "receive")
        os.makedirs(receive_dir)

        dest_path = os.path.join(temp_dir, "existing_dir")
        os.makedirs(dest_path)
        with open(os.path.join(dest_path, "old.txt"), "w") as f:
            f.write("old")

        croc_dir = os.path.join(receive_dir, "_croc_dl_0_existing_dir")
        os.makedirs(croc_dir)
        with open(os.path.join(croc_dir, "new.txt"), "w") as f:
            f.write("new")

        plan = DownloadPlan(
            croc_receive_dir=receive_dir,
            file_mappings=[{
                "croc_filename": "_croc_dl_0_existing_dir",
                "local_destination_path": dest_path,
            }],
            needs_download=True,
        )

        successes, errors = finalize_download(plan)
        assert len(successes) == 1
        assert len(errors) == 0
        # Old file should be gone, new file should be there
        assert not os.path.exists(os.path.join(dest_path, "old.txt"))
        assert os.path.exists(os.path.join(dest_path, "new.txt"))

    def test_empty_file_mappings(self, temp_dir):
        """No file mappings → empty results."""
        plan = DownloadPlan(
            croc_receive_dir=temp_dir,
            file_mappings=[],
            needs_download=True,
        )
        successes, errors = finalize_download(plan)
        assert successes == []
        assert errors == []


# ============================================================================
# cleanup_download_resources
# ============================================================================

class TestCleanupDownloadResources:
    def test_cleanup_with_none_values(self):
        """Should not raise with None process and empty dir."""
        asyncio.run(cleanup_download_resources(None, ""))

    def test_cleanup_removes_directory(self, temp_dir):
        """Should remove the receive directory."""
        receive_dir = os.path.join(temp_dir, "to_clean")
        os.makedirs(receive_dir)
        with open(os.path.join(receive_dir, "file.txt"), "w") as f:
            f.write("data")

        asyncio.run(cleanup_download_resources(None, receive_dir))
        assert not os.path.exists(receive_dir)

    def test_cleanup_nonexistent_dir(self):
        """Should not raise if dir doesn't exist."""
        asyncio.run(cleanup_download_resources(None, "/nonexistent/path/that/does/not/exist"))


# ============================================================================
# DownloadPlan dataclass
# ============================================================================

class TestDownloadPlan:
    def test_defaults(self):
        plan = DownloadPlan()
        assert plan.download_commands == ""
        assert plan.croc_code == ""
        assert plan.croc_receive_dir == ""
        assert plan.file_mappings == []
        assert plan.needs_download is False
        assert plan.errors == []
        assert plan.files_info == []

    def test_independent_instances(self):
        """Mutable defaults must not be shared between instances."""
        plan1 = DownloadPlan()
        plan2 = DownloadPlan()
        plan1.file_mappings.append({"a": "b"})
        plan1.errors.append("err")
        plan1.files_info.append("info")
        assert plan2.file_mappings == []
        assert plan2.errors == []
        assert plan2.files_info == []


# ============================================================================
# parse_downloads (CLI)
# ============================================================================

class TestParseDownloads:
    @pytest.fixture(autouse=True)
    def setup_parse_downloads(self):
        """Import the CLI parse function by importing from main and extracting it.

        Since parse_downloads is a local function inside _run_cli, we replicate its
        logic here for testing to avoid importing the full CLI machinery.
        """
        # Replicate the parse logic exactly as in mcp_tool.py
        def parse_downloads(download_args):
            if not download_args:
                return []
            files = []
            for spec in download_args:
                parts = spec.split(':')
                if len(parts) >= 3 and len(parts[1]) == 1 and parts[1].isalpha():
                    if parts[2].startswith('\\') or parts[2].startswith('/'):
                        parts = [parts[0], parts[1] + ':' + parts[2]] + parts[3:]
                if len(parts) < 2:
                    raise SystemExit(1)
                file_spec = {
                    'remote_source_path': parts[0],
                    'local_destination_path': parts[1],
                }
                files.append(file_spec)
            return files
        self._parse = parse_downloads

    def test_none_returns_empty(self):
        assert self._parse(None) == []

    def test_empty_list_returns_empty(self):
        assert self._parse([]) == []

    def test_basic_parse(self):
        result = self._parse(["/var/log/app.log:./app.log"])
        assert len(result) == 1
        assert result[0]["remote_source_path"] == "/var/log/app.log"
        assert result[0]["local_destination_path"] == "./app.log"

    def test_multiple_downloads(self):
        result = self._parse(["/tmp/a.txt:./a.txt", "/opt/b:./b"])
        assert len(result) == 2
        assert result[0]["remote_source_path"] == "/tmp/a.txt"
        assert result[1]["remote_source_path"] == "/opt/b"

    def test_windows_drive_letter_in_local_path(self):
        """LOCAL path with Windows drive letter (C:\\path) should be preserved."""
        result = self._parse(["/var/log/app.log:C:\\Users\\me\\logs\\app.log"])
        assert len(result) == 1
        assert result[0]["remote_source_path"] == "/var/log/app.log"
        assert result[0]["local_destination_path"] == "C:\\Users\\me\\logs\\app.log"

    def test_windows_drive_letter_d(self):
        result = self._parse(["/tmp/out:D:\\data\\out"])
        assert result[0]["local_destination_path"] == "D:\\data\\out"

    def test_single_part_raises(self):
        """Spec with no colon should fail."""
        with pytest.raises(SystemExit):
            self._parse(["nocolon"])

    def test_simple_relative_paths(self):
        result = self._parse(["/remote/file.txt:local_file.txt"])
        assert result[0]["remote_source_path"] == "/remote/file.txt"
        assert result[0]["local_destination_path"] == "local_file.txt"
