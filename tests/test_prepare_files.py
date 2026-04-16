"""Tests for prepare_files_with_croc and related helpers in mcp_tool."""

import asyncio
import base64
import gzip
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
    FileDeploymentPlan,
    prepare_files_with_croc,
    execute_with_croc,
    cleanup_croc_resources,
)


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    d = tempfile.mkdtemp(prefix="test_croc_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


def create_file_of_size(path: str, size_bytes: int, compressible: bool = True):
    """Create a test file of approximately the given size."""
    if compressible:
        # Write repetitive data that compresses well
        data = b"A" * size_bytes
    else:
        # Write truly random data that resists compression
        data = os.urandom(size_bytes)
    with open(path, 'wb') as f:
        f.write(data)


# ============================================================================
# FileDeploymentPlan dataclass
# ============================================================================

class TestFileDeploymentPlan:
    def test_default_values(self):
        plan = FileDeploymentPlan()
        assert plan.inline_commands == ""
        assert plan.croc_init_commands == ""
        assert plan.croc_container_pre_commands == ""
        assert plan.croc_code == ""
        assert plan.croc_local_files == []
        assert plan.croc_staging_dir == ""
        assert plan.needs_croc is False
        assert plan.errors == []
        assert plan.files_info == []

    def test_independent_list_instances(self):
        """Ensure mutable default fields are independent across instances."""
        plan1 = FileDeploymentPlan()
        plan2 = FileDeploymentPlan()
        plan1.errors.append("error1")
        assert len(plan2.errors) == 0


# ============================================================================
# prepare_files_with_croc - empty/basic cases
# ============================================================================

class TestPrepareFilesEmpty:
    def test_empty_files_list(self):
        plan = prepare_files_with_croc([])
        assert not plan.needs_croc
        assert plan.inline_commands == ""
        assert plan.errors == []

    def test_missing_remote_path(self):
        plan = prepare_files_with_croc([{"content": "hello"}])
        assert len(plan.errors) == 1
        assert "missing 'remote_destination_path'" in plan.errors[0]

    def test_both_local_and_content(self):
        plan = prepare_files_with_croc([{
            "remote_destination_path": "/tmp/test",
            "local_source_path": "/some/file",
            "content": "hello",
        }])
        assert len(plan.errors) == 1
        assert "either 'local_source_path' OR 'content'" in plan.errors[0]

    def test_neither_local_nor_content(self):
        plan = prepare_files_with_croc([{
            "remote_destination_path": "/tmp/test",
        }])
        assert len(plan.errors) == 1
        assert "must provide either" in plan.errors[0]


# ============================================================================
# prepare_files_with_croc - inline (small) files
# ============================================================================

class TestPrepareFilesInline:
    def test_small_file_goes_inline(self, temp_dir):
        """Files under CROC_THRESHOLD_BYTES compressed go inline."""
        small_file = os.path.join(temp_dir, "small.txt")
        create_file_of_size(small_file, 100)  # 100 bytes, compresses to much less
        
        plan = prepare_files_with_croc([{
            "remote_destination_path": "/tmp/small.txt",
            "local_source_path": small_file,
        }])
        
        assert not plan.needs_croc
        assert plan.inline_commands != ""
        assert "small.txt" in plan.files_info[0]
        assert plan.errors == []

    def test_content_always_inline(self):
        """Content-based files always go inline."""
        plan = prepare_files_with_croc([{
            "remote_destination_path": "/tmp/content.txt",
            "content": "Hello, World!",
        }])
        
        assert not plan.needs_croc
        assert "base64 -d" in plan.inline_commands
        assert plan.errors == []

    def test_inline_file_with_mode(self, temp_dir):
        small_file = os.path.join(temp_dir, "script.sh")
        create_file_of_size(small_file, 50)
        
        plan = prepare_files_with_croc([{
            "remote_destination_path": "/tmp/script.sh",
            "local_source_path": small_file,
            "mode": "755",
        }])
        
        assert "chmod 755" in plan.inline_commands

    def test_small_directory_goes_inline(self, temp_dir):
        """Small directories should be inlined via tar."""
        dir_path = os.path.join(temp_dir, "mydir")
        os.makedirs(dir_path)
        create_file_of_size(os.path.join(dir_path, "file1.txt"), 50)
        create_file_of_size(os.path.join(dir_path, "file2.txt"), 50)
        
        plan = prepare_files_with_croc([{
            "remote_destination_path": "/opt/mydir",
            "local_source_path": dir_path,
        }])
        
        assert not plan.needs_croc
        assert "tar xzf" in plan.inline_commands

    def test_nonexistent_file_error(self):
        plan = prepare_files_with_croc([{
            "remote_destination_path": "/tmp/nope",
            "local_source_path": "/tmp/does_not_exist_8675309",
        }])
        assert len(plan.errors) == 1
        assert "not found" in plan.errors[0]


# ============================================================================
# prepare_files_with_croc - croc (large) files
# ============================================================================

class TestPrepareFilesCroc:
    def test_large_file_triggers_croc(self, temp_dir):
        """Files exceeding CROC_THRESHOLD_BYTES compressed should trigger croc."""
        large_file = os.path.join(temp_dir, "large.bin")
        # Create file that compresses to more than threshold
        create_file_of_size(large_file, 500_000, compressible=False)
        
        # Verify it actually exceeds threshold when compressed
        with open(large_file, 'rb') as f:
            compressed = gzip.compress(f.read())
        assert len(compressed) > croc_manager.CROC_THRESHOLD_BYTES, \
            f"Compressed size {len(compressed)} is not above threshold {croc_manager.CROC_THRESHOLD_BYTES}"
        
        plan = prepare_files_with_croc([{
            "remote_destination_path": "/tmp/large.bin",
            "local_source_path": large_file,
        }])
        
        assert plan.needs_croc
        assert plan.croc_code != ""
        assert len(plan.croc_local_files) == 1
        assert plan.croc_staging_dir != ""
        assert os.path.exists(plan.croc_staging_dir)
        # Cleanup
        shutil.rmtree(plan.croc_staging_dir, ignore_errors=True)

    def test_unique_filenames_in_staging(self, temp_dir):
        """Multiple large files with same basename should get unique staged names."""
        dir_a = os.path.join(temp_dir, "a")
        dir_b = os.path.join(temp_dir, "b")
        os.makedirs(dir_a)
        os.makedirs(dir_b)
        
        file_a = os.path.join(dir_a, "data.bin")
        file_b = os.path.join(dir_b, "data.bin")
        create_file_of_size(file_a, 500_000, compressible=False)
        create_file_of_size(file_b, 500_000, compressible=False)
        
        plan = prepare_files_with_croc([
            {"remote_destination_path": "/tmp/a/data.bin", "local_source_path": file_a},
            {"remote_destination_path": "/tmp/b/data.bin", "local_source_path": file_b},
        ])
        
        assert plan.needs_croc
        assert len(plan.croc_local_files) == 2
        # File names should be unique
        basenames = [os.path.basename(f) for f in plan.croc_local_files]
        assert basenames[0] != basenames[1]
        assert "_croc_0_" in basenames[0]
        assert "_croc_1_" in basenames[1]
        # Cleanup
        shutil.rmtree(plan.croc_staging_dir, ignore_errors=True)

    def test_large_directory_triggers_croc_and_tars(self, temp_dir):
        """Large directories should be tarred and sent via croc."""
        dir_path = os.path.join(temp_dir, "bigdir")
        os.makedirs(dir_path)
        # Create enough truly incompressible data to exceed threshold
        for i in range(40):
            create_file_of_size(
                os.path.join(dir_path, f"file_{i}.bin"),
                30_000,
                compressible=False,
            )
        
        plan = prepare_files_with_croc([{
            "remote_destination_path": "/opt/bigdir",
            "local_source_path": dir_path,
        }])
        
        assert plan.needs_croc
        assert len(plan.croc_local_files) == 1
        # Should be a .tar.gz in staging
        staged_file = plan.croc_local_files[0]
        assert staged_file.endswith(".tar.gz")
        assert os.path.exists(staged_file)
        # Cleanup
        shutil.rmtree(plan.croc_staging_dir, ignore_errors=True)

    def test_container_mode_croc_commands_in_init(self, temp_dir):
        """In container mode, croc commands go in croc_init_commands."""
        large_file = os.path.join(temp_dir, "large.bin")
        create_file_of_size(large_file, 500_000, compressible=False)
        
        plan = prepare_files_with_croc(
            [{"remote_destination_path": "/tmp/large.bin", "local_source_path": large_file}],
            transfer_mode="container",
        )
        
        assert plan.needs_croc
        assert plan.croc_init_commands != ""
        assert plan.croc_container_pre_commands == ""
        assert "croc" in plan.croc_init_commands
        # Cleanup
        shutil.rmtree(plan.croc_staging_dir, ignore_errors=True)

    def test_ssh_mode_croc_commands_in_pre(self, temp_dir):
        """In SSH mode, croc commands go in croc_container_pre_commands."""
        large_file = os.path.join(temp_dir, "large.bin")
        create_file_of_size(large_file, 500_000, compressible=False)
        
        plan = prepare_files_with_croc(
            [{"remote_destination_path": "/tmp/large.bin", "local_source_path": large_file}],
            transfer_mode="ssh",
            target_ip="10.0.0.1",
            ssh_user="root",
            ssh_private_key="KEY",
        )
        
        assert plan.needs_croc
        assert plan.croc_container_pre_commands != ""
        assert plan.croc_init_commands == ""
        assert "scp" in plan.croc_container_pre_commands
        # Cleanup
        shutil.rmtree(plan.croc_staging_dir, ignore_errors=True)


# ============================================================================
# prepare_files_with_croc - mixed files
# ============================================================================

class TestPrepareFilesMixed:
    def test_mixed_small_and_large(self, temp_dir):
        """Should split files: small inline, large via croc."""
        small_file = os.path.join(temp_dir, "small.txt")
        large_file = os.path.join(temp_dir, "large.bin")
        create_file_of_size(small_file, 100)
        create_file_of_size(large_file, 500_000, compressible=False)
        
        plan = prepare_files_with_croc([
            {"remote_destination_path": "/tmp/small.txt", "local_source_path": small_file},
            {"remote_destination_path": "/tmp/large.bin", "local_source_path": large_file},
        ], transfer_mode="container")
        
        assert plan.needs_croc
        assert plan.inline_commands != ""
        assert plan.croc_init_commands != ""
        assert len(plan.files_info) == 2
        # Cleanup
        shutil.rmtree(plan.croc_staging_dir, ignore_errors=True)


# ============================================================================
# cleanup_croc_resources
# ============================================================================

class TestCleanupCrocResources:
    @pytest.mark.asyncio
    async def test_cleanup_with_none(self):
        """Should not raise with None process and empty staging."""
        await cleanup_croc_resources(None, "")

    @pytest.mark.asyncio
    async def test_cleanup_removes_staging_dir(self):
        """Should remove the staging directory."""
        staging = tempfile.mkdtemp(prefix="test_staging_")
        # Create a file in it
        with open(os.path.join(staging, "test.txt"), 'w') as f:
            f.write("test")
        
        await cleanup_croc_resources(None, staging)
        assert not os.path.exists(staging)

    @pytest.mark.asyncio
    async def test_cleanup_nonexistent_staging_dir(self):
        """Should not raise when staging dir doesn't exist."""
        await cleanup_croc_resources(None, "/tmp/nonexistent_dir_8675309")


# ============================================================================
# execute_with_croc
# ============================================================================

class TestExecuteWithCroc:
    @pytest.mark.asyncio
    async def test_calls_ensure_and_start(self):
        """Should call ensure_local_croc then start_croc_send."""
        plan = FileDeploymentPlan(
            needs_croc=True,
            croc_code="test-code",
            croc_local_files=["file1.txt"],
        )
        mock_path = Path("/usr/bin/croc")
        mock_process = mock.AsyncMock()
        
        with mock.patch.object(croc_manager, "ensure_local_croc",
                              new_callable=mock.AsyncMock, return_value=mock_path) as mock_ensure, \
             mock.patch.object(croc_manager, "start_croc_send",
                              new_callable=mock.AsyncMock, return_value=mock_process) as mock_start:
            result = await execute_with_croc(plan)
            
            mock_ensure.assert_called_once()
            mock_start.assert_called_once_with(
                croc_path=mock_path,
                code="test-code",
                files=["file1.txt"],
            )
            assert result is mock_process
