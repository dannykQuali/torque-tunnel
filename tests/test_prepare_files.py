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
from torque_tunnel import mcp_tool
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

    def _staged_tar_members(self, plan):
        import tarfile
        assert len(plan.croc_local_files) == 1, plan.croc_local_files
        with tarfile.open(plan.croc_local_files[0]) as tar:
            return {m.name.lstrip("./"): ("link" if m.issym() else "dir" if m.isdir() else "file")
                    for m in tar.getmembers()}

    def _real_dir_and_link(self, temp_dir):
        """A directory big enough for croc, holding an inner link, and a symlink to it."""
        real = os.path.join(temp_dir, "real")
        os.makedirs(real)
        create_file_of_size(os.path.join(real, "big.bin"), 500_000, compressible=False)
        try:
            os.symlink("big.bin", os.path.join(real, "inner-link"))
            os.symlink(real, os.path.join(temp_dir, "link"), target_is_directory=True)
        except OSError as e:  # Windows without the symlink privilege
            pytest.skip(f"cannot create symlinks here: {e}")
        return real, os.path.join(temp_dir, "link")

    def test_a_symlink_to_a_large_directory_uploads_the_directory(self, temp_dir):
        """2026-11-11: the croc path tarred a symlinked directory with
        tar.add(path, arcname='.'), which does not follow the link: the archive held
        one entry, '.' -> the target, instead of the directory."""
        _, link = self._real_dir_and_link(temp_dir)
        plan = prepare_files_with_croc([{"remote_destination_path": "/tmp/dest", "local_source_path": link}])
        try:
            assert plan.needs_croc, "the test needs the croc path"
            members = self._staged_tar_members(plan)
            assert members.get("big.bin") == "file", members
            assert members.get("") != "link", members
        finally:
            shutil.rmtree(plan.croc_staging_dir, ignore_errors=True)

    def test_links_inside_an_uploaded_directory_stay_links(self, temp_dir):
        """Only the path that was named is followed, as for the small (inline) path."""
        _, link = self._real_dir_and_link(temp_dir)
        plan = prepare_files_with_croc([{"remote_destination_path": "/tmp/dest", "local_source_path": link}])
        try:
            assert self._staged_tar_members(plan).get("inner-link") == "link"
        finally:
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
            mock_start.assert_called_once()
            kwargs = mock_start.call_args.kwargs
            assert kwargs["croc_path"] == mock_path
            assert kwargs["code"] == "test-code"
            assert kwargs["files"] == ["file1.txt"]
            assert result is mock_process

    @pytest.mark.asyncio
    async def test_sends_on_the_relay_pinned_by_the_plan(self):
        plan = FileDeploymentPlan(
            needs_croc=True,
            croc_code="test-code",
            croc_local_files=["file1.txt"],
            croc_relay="relay.internal:9009",
            croc_relay_password="s3kr1t",
            croc_transfers=1,
        )
        with mock.patch.object(croc_manager, "ensure_local_croc",
                               new_callable=mock.AsyncMock, return_value=Path("/usr/bin/croc")), \
             mock.patch.object(croc_manager, "start_croc_send",
                               new_callable=mock.AsyncMock) as mock_start:
            await execute_with_croc(plan)

        kwargs = mock_start.call_args.kwargs
        assert kwargs["relay"] == "relay.internal:9009"
        assert kwargs["relay_password"] == "s3kr1t"
        assert kwargs["transfers"] == 1


class TestRelayConfigReachesBothSides:
    """Sender and receiver must agree on the relay, or the transfer silently hangs."""

    def _big_file(self, temp_dir):
        path = os.path.join(temp_dir, "big.bin")
        create_file_of_size(path, 500_000, compressible=False)
        return path

    def test_configured_relay_lands_in_the_receive_commands(self, temp_dir):
        overrides = {
            "croc_relay": "relay.internal:9009",
            "croc_relay_password": "s3kr1t",
            "croc_transfers": 1,
        }
        with mock.patch.dict(mcp_tool._config, overrides):
            plan = prepare_files_with_croc([{
                "remote_destination_path": "/tmp/big.bin",
                "local_source_path": self._big_file(temp_dir),
            }])
        try:
            assert plan.needs_croc
            assert plan.croc_relay == "relay.internal:9009"
            assert plan.croc_relay_password == "s3kr1t"
            assert plan.croc_transfers == 1
            assert "--relay relay.internal:9009" in plan.croc_init_commands
            assert "CROC_PASS=" in plan.croc_init_commands
            # ...from the environment: the password itself never goes into a command
            assert "s3kr1t" not in plan.croc_init_commands
        finally:
            shutil.rmtree(plan.croc_staging_dir, ignore_errors=True)

    def test_unset_relay_means_crocs_public_one(self, temp_dir):
        with mock.patch.dict(mcp_tool._config,
                             {"croc_relay": None, "croc_relay_password": None,
                              "croc_transfers": None}):
            plan = prepare_files_with_croc([{
                "remote_destination_path": "/tmp/big.bin",
                "local_source_path": self._big_file(temp_dir),
            }])
        try:
            assert plan.croc_relay == ""
            assert plan.croc_transfers is None
            # Named explicitly even when unconfigured: croc's built-in default is
            # resolved in a 500 ms window and silently blanked when that's missed.
            assert f"--relay {croc_manager.DEFAULT_CROC_RELAY}" in plan.croc_init_commands
            # No password to hand the environment (the commands only ever name the
            # variable; an empty one exports no CROC_PASS).
            assert plan.croc_relay_password == ""
        finally:
            shutil.rmtree(plan.croc_staging_dir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_a_config_reload_mid_transfer_cannot_split_the_two_sides(self, temp_dir):
        """The config is hot-reloaded every 2s; the local send starts after the
        receive commands are already generated. Re-reading the config there would
        put the two ends on different relays and hang the transfer."""
        with mock.patch.dict(mcp_tool._config, {"croc_relay": "relay-a:9009"}):
            plan = prepare_files_with_croc([{
                "remote_destination_path": "/tmp/big.bin",
                "local_source_path": self._big_file(temp_dir),
            }])

        try:
            assert "--relay relay-a:9009" in plan.croc_init_commands

            # Config changes before the local sender starts.
            with mock.patch.dict(mcp_tool._config, {"croc_relay": "relay-b:9009"}), \
                 mock.patch.object(croc_manager, "ensure_local_croc",
                                   new_callable=mock.AsyncMock,
                                   return_value=Path("/usr/bin/croc")), \
                 mock.patch.object(croc_manager, "start_croc_send",
                                   new_callable=mock.AsyncMock) as mock_start:
                await execute_with_croc(plan)

            assert mock_start.call_args.kwargs["relay"] == "relay-a:9009"
        finally:
            shutil.rmtree(plan.croc_staging_dir, ignore_errors=True)


# ============================================================================
# Inline-vs-croc decision must not load the file into memory
# ============================================================================

class TestThresholdDecisionIsStreamed:
    """The decision used to be made by ``gzip.compress(open(p,'rb').read())``.

    That held the whole file plus its compressed copy in RAM just to compare the
    result against 300 KB: ~2.5 GB for a 1.27 GB upload and ~31 GB (i.e.
    MemoryError) for the 15.7 GB images this tool is meant to move.
    """

    def _peak_mb(self, fn):
        import tracemalloc
        tracemalloc.start()
        try:
            result = fn()
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        return result, peak / (1024 * 1024)

    def test_large_incompressible_file_decided_without_loading_it(self, temp_dir):
        path = os.path.join(temp_dir, "big.bin")
        create_file_of_size(path, 40 * 1024 * 1024, compressible=False)

        plan, peak_mb = self._peak_mb(lambda: prepare_files_with_croc([
            {"local_source_path": path, "remote_destination_path": "/tmp/big.bin"}
        ]))
        try:
            assert plan.needs_croc, "40 MB of random data cannot fit inline"
            assert peak_mb < 8, (
                f"deciding croc for a 40 MB file held {peak_mb:.1f} MB — the file "
                f"is being read into memory instead of streamed"
            )
        finally:
            shutil.rmtree(plan.croc_staging_dir, ignore_errors=True)

    def test_large_compressible_file_still_goes_inline(self, temp_dir):
        """The decision is about COMPRESSED size - that semantic must not change.

        A short-circuit on raw size would push this 8 MB of zeros (which gzips to
        a few KB) onto the croc path, burning a relay admission for nothing.
        """
        path = os.path.join(temp_dir, "zeros.bin")
        create_file_of_size(path, 8 * 1024 * 1024, compressible=True)

        plan = prepare_files_with_croc([
            {"local_source_path": path, "remote_destination_path": "/tmp/zeros.bin"}
        ])
        try:
            assert not plan.needs_croc
            assert not plan.errors
            assert "/tmp/zeros.bin" in plan.inline_commands
        finally:
            shutil.rmtree(plan.croc_staging_dir, ignore_errors=True)

    def test_inline_payload_still_round_trips(self, temp_dir):
        """Whatever the compression path, the bytes the remote gets must match."""
        path = os.path.join(temp_dir, "payload.bin")
        original = os.urandom(50 * 1024)
        with open(path, "wb") as f:
            f.write(original)

        specs = [{"local_source_path": path, "remote_destination_path": "/tmp/payload.bin"}]
        plan = prepare_files_with_croc(specs)
        assert not plan.needs_croc

        # Pull the base64 gzip blob back out of the generated shell and decode it
        import re
        blobs = re.findall(r"echo '([A-Za-z0-9+/=]{40,})'", plan.inline_commands)
        assert blobs, "expected a base64 payload in the inline commands"
        assert gzip.decompress(base64.b64decode(blobs[0])) == original

    def test_directory_decision_is_also_streamed(self, temp_dir):
        src = os.path.join(temp_dir, "tree")
        os.makedirs(src)
        for i in range(4):
            create_file_of_size(os.path.join(src, f"f{i}.bin"), 8 * 1024 * 1024,
                                compressible=False)

        plan, peak_mb = self._peak_mb(lambda: prepare_files_with_croc([
            {"local_source_path": src, "remote_destination_path": "/tmp/tree"}
        ]))
        try:
            assert plan.needs_croc
            assert peak_mb < 8, (
                f"tarring a 32 MB directory held {peak_mb:.1f} MB in memory"
            )
        finally:
            shutil.rmtree(plan.croc_staging_dir, ignore_errors=True)

    def test_threshold_boundary_is_unchanged(self, temp_dir):
        """Just under the threshold stays inline; just over switches to croc."""
        under = os.path.join(temp_dir, "under.bin")
        create_file_of_size(under, croc_manager.CROC_THRESHOLD_BYTES - 50_000,
                            compressible=False)
        over = os.path.join(temp_dir, "over.bin")
        create_file_of_size(over, croc_manager.CROC_THRESHOLD_BYTES + 50_000,
                            compressible=False)

        plan_under = prepare_files_with_croc([
            {"local_source_path": under, "remote_destination_path": "/tmp/u"}])
        plan_over = prepare_files_with_croc([
            {"local_source_path": over, "remote_destination_path": "/tmp/o"}])
        try:
            assert not plan_under.needs_croc
            assert plan_over.needs_croc
        finally:
            shutil.rmtree(plan_under.croc_staging_dir, ignore_errors=True)
            shutil.rmtree(plan_over.croc_staging_dir, ignore_errors=True)


# ============================================================================
# The provable size bound (no I/O at all for obviously-too-big payloads)
# ============================================================================

class TestGzipRatioShortCircuit:
    """DEFLATE cannot do better than 1032:1, so anything above cap * 1032 needs
    croc no matter what is in it. A 15.7 GB image must be decided by a stat call,
    not by gzipping 15.7 GB.
    """

    def test_oversized_file_is_decided_without_opening_it(self, temp_dir):
        from torque_tunnel.mcp_tool import compress_file_if_inline, MAX_GZIP_RATIO

        cap = 100
        path = os.path.join(temp_dir, "big.bin")
        create_file_of_size(path, cap * MAX_GZIP_RATIO + 1, compressible=True)

        def refuse(*a, **kw):
            raise AssertionError("the file was opened despite being provably too big")

        with mock.patch("builtins.open", refuse):
            assert compress_file_if_inline(path, cap) is None

    def test_a_file_at_the_bound_is_still_read(self, temp_dir):
        """The bound must only skip work it can prove is pointless.

        At exactly cap * 1032 a file could in principle still fit, so the answer
        has to come from actually compressing it.
        """
        from torque_tunnel.mcp_tool import compress_file_if_inline, MAX_GZIP_RATIO

        cap = 4096
        path = os.path.join(temp_dir, "atbound.bin")
        create_file_of_size(path, cap * MAX_GZIP_RATIO, compressible=True)

        real_open = open
        opened = []

        def spy(file, *a, **kw):
            opened.append(str(file))
            return real_open(file, *a, **kw)

        with mock.patch("builtins.open", spy):
            compress_file_if_inline(path, cap)

        assert any(path in o for o in opened), "the file at the bound was not read"

    def test_compressible_file_well_under_the_bound_fits_inline(self, temp_dir):
        from torque_tunnel.mcp_tool import compress_file_if_inline

        cap = croc_manager.CROC_THRESHOLD_BYTES
        path = os.path.join(temp_dir, "zeros.bin")
        create_file_of_size(path, 8 * 1024 * 1024, compressible=True)

        result = compress_file_if_inline(path, cap)
        assert result is not None
        assert len(result) <= cap
        assert gzip.decompress(result) == b"A" * (8 * 1024 * 1024)

    def test_oversized_directory_is_decided_without_taring_it(self, temp_dir):
        from torque_tunnel.mcp_tool import compress_dir_if_inline, MAX_GZIP_RATIO

        cap = 100
        src = os.path.join(temp_dir, "tree")
        os.makedirs(src)
        create_file_of_size(os.path.join(src, "a.bin"), cap * MAX_GZIP_RATIO + 1,
                            compressible=True)

        def refuse(*a, **kw):
            raise AssertionError("the tree was read despite being provably too big")

        with mock.patch("builtins.open", refuse):
            assert compress_dir_if_inline(src, cap) is None


# ============================================================================
# The inline budget is per CALL, not per file
# ============================================================================

def _inline_payload_bytes(inline_commands: str) -> int:
    """Total decoded size of every base64 payload the inline commands carry."""
    import re
    blobs = re.findall(r"echo '([A-Za-z0-9+/=]+)' \| base64 -d", inline_commands)
    return sum(len(base64.b64decode(b)) for b in blobs)


class TestInlineBudgetIsPerCall:
    """Torque's payload limit (grain hangs ~450 KB, API 413 ~600 KB) applies to the
    whole call. Two 290 KB files used to pass the per-file check one by one and
    then travel together as a 774 KB payload."""

    def _cleanup(self, plan):
        if plan.croc_staging_dir:
            shutil.rmtree(plan.croc_staging_dir, ignore_errors=True)

    def test_two_files_that_each_fit_do_not_both_go_inline(self, temp_dir):
        specs = []
        for i in range(2):
            p = os.path.join(temp_dir, f"part{i}")
            create_file_of_size(p, 290 * 1024, compressible=False)
            specs.append({"local_source_path": p, "remote_destination_path": f"/tmp/part{i}"})

        plan = prepare_files_with_croc(specs)
        try:
            assert plan.needs_croc
            assert len(plan.croc_local_files) == 1
            assert _inline_payload_bytes(plan.inline_commands) <= croc_manager.CROC_THRESHOLD_BYTES
        finally:
            self._cleanup(plan)

    def test_many_small_files_never_exceed_the_budget_and_none_are_lost(self, temp_dir):
        specs = []
        for i in range(6):
            p = os.path.join(temp_dir, f"f{i}.bin")
            create_file_of_size(p, 80 * 1024, compressible=False)
            specs.append({"local_source_path": p, "remote_destination_path": f"/tmp/f{i}.bin"})

        plan = prepare_files_with_croc(specs)
        try:
            assert _inline_payload_bytes(plan.inline_commands) <= croc_manager.CROC_THRESHOLD_BYTES
            inline_dests = {f"/tmp/f{i}.bin" for i in range(6)
                            if f"'/tmp/f{i}.bin'" in plan.inline_commands}
            croc_dests = {f"/tmp/f{i}.bin" for i in range(6)
                          if f"'/tmp/f{i}.bin'" in plan.croc_init_commands}
            assert inline_dests | croc_dests == {f"/tmp/f{i}.bin" for i in range(6)}
            assert not inline_dests & croc_dests, "a file must travel exactly one way"
            assert croc_dests, "80 KB x 6 cannot all fit in one 300 KB payload"
        finally:
            self._cleanup(plan)

    def test_a_single_file_up_to_the_threshold_still_goes_inline(self, temp_dir):
        p = os.path.join(temp_dir, "one.bin")
        create_file_of_size(p, croc_manager.CROC_THRESHOLD_BYTES - 50_000, compressible=False)
        plan = prepare_files_with_croc([{"local_source_path": p, "remote_destination_path": "/tmp/one"}])
        try:
            assert not plan.needs_croc
        finally:
            self._cleanup(plan)

    def test_small_content_still_goes_inline(self):
        plan = prepare_files_with_croc([{"content": "#!/bin/sh\necho hi\n",
                                         "remote_destination_path": "/tmp/s.sh"}])
        assert not plan.needs_croc
        assert "/tmp/s.sh" in plan.inline_commands

    def test_content_counts_against_the_budget(self, temp_dir):
        import secrets
        p = os.path.join(temp_dir, "big.bin")
        create_file_of_size(p, 250 * 1024, compressible=False)
        content = secrets.token_hex(120 * 1024)  # ~240 KB of hex, gzips to ~130 KB

        plan = prepare_files_with_croc([
            {"local_source_path": p, "remote_destination_path": "/tmp/big.bin"},
            {"content": content, "remote_destination_path": "/tmp/generated.txt", "mode": "600"},
        ])
        try:
            assert plan.needs_croc, "250 KB + 130 KB cannot share one 300 KB payload"
            assert _inline_payload_bytes(plan.inline_commands) <= croc_manager.CROC_THRESHOLD_BYTES
        finally:
            self._cleanup(plan)

    def test_spilled_content_arrives_intact_with_its_mode(self, temp_dir):
        """Content that no longer fits inline has to take the croc path: it is
        staged as a real file whose bytes are exactly the content."""
        import secrets
        p = os.path.join(temp_dir, "big.bin")
        create_file_of_size(p, 290 * 1024, compressible=False)
        content = secrets.token_hex(60 * 1024)

        plan = prepare_files_with_croc([
            {"local_source_path": p, "remote_destination_path": "/tmp/big.bin"},
            {"content": content, "remote_destination_path": "/tmp/generated.txt", "mode": "600"},
        ])
        try:
            assert "/tmp/generated.txt" in plan.croc_init_commands
            assert "chmod 600 '/tmp/generated.txt'" in plan.croc_init_commands
            staged = [f for f in plan.croc_local_files if f.endswith("generated.txt")]
            assert len(staged) == 1
            with open(staged[0], "rb") as f:
                assert f.read() == content.encode("utf-8")
        finally:
            self._cleanup(plan)
