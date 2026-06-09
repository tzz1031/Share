from __future__ import annotations

import hashlib
import os
import socket
import tempfile
import time
import unittest
from pathlib import Path

from discovery import DiscoveredDevice
from sync import (
    STATUS_ACTIVE,
    STATUS_DELETED,
    FileEntry,
    FileIndex,
    should_send_entry,
)
from sync.index_exchange import request_file_index
from sync.paths import destination_for, normalize_relative_path
from sync.service import SyncService
from transfer import TCPFileServer
from transfer.protocol import (
    HASH_ALGORITHM,
    PROTOCOL_VERSION,
    recv_json_message,
    send_json_message,
)
from transfer.resume_state import transfer_id_for


def entry(
    relative_path: str,
    *,
    modified_time_ns: int,
    source_device_id: str,
    file_hash: str = "a" * 64,
    status: str = STATUS_ACTIVE,
    changed_at_ns: int | None = None,
    version: int = 1,
) -> FileEntry:
    return FileEntry(
        relative_path=relative_path,
        file_name=relative_path.rsplit("/", 1)[-1],
        file_size=1,
        modified_time_ns=modified_time_ns,
        file_hash=file_hash,
        version=version,
        source_device_id=source_device_id,
        status=status,
        changed_at_ns=(
            modified_time_ns if changed_at_ns is None else changed_at_ns
        ),
    )


class FileIndexTests(unittest.TestCase):
    def test_scan_tracks_nested_changes_and_deletion_tombstone(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            shared = Path(tmp) / "shared"
            nested = shared / "docs" / "message.txt"
            nested.parent.mkdir(parents=True)
            nested.write_text("first", encoding="utf-8")
            (shared / "ignored.part").write_text("temporary", encoding="utf-8")
            (shared / ".incoming-test.tmp").write_text("temporary", encoding="utf-8")

            index = FileIndex(shared, "device-a")
            first = {item.relative_path: item for item in index.scan()}

            self.assertEqual(set(first), {"docs/message.txt"})
            self.assertEqual(first["docs/message.txt"].version, 1)
            self.assertEqual(first["docs/message.txt"].status, STATUS_ACTIVE)

            nested.write_text("second", encoding="utf-8")
            future_ns = time.time_ns() + 2_000_000_000
            os.utime(nested, ns=(future_ns, future_ns))
            second = {item.relative_path: item for item in index.scan()}

            self.assertEqual(second["docs/message.txt"].version, 2)
            self.assertNotEqual(
                first["docs/message.txt"].file_hash,
                second["docs/message.txt"].file_hash,
            )

            nested.unlink()
            third = {item.relative_path: item for item in index.scan()}
            tombstone = third["docs/message.txt"]
            self.assertEqual(tombstone.status, STATUS_DELETED)
            self.assertEqual(tombstone.version, 3)
            self.assertEqual(tombstone.source_device_id, "device-a")

    def test_scan_skips_symbolic_links_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shared = root / "shared"
            shared.mkdir()
            outside = root / "outside.txt"
            outside.write_text("outside", encoding="utf-8")
            link = shared / "link.txt"
            try:
                link.symlink_to(outside)
            except (NotImplementedError, OSError):
                self.skipTest("symbolic links are not available")

            index = FileIndex(shared, "device-a")
            self.assertEqual(index.scan(), [])

    def test_record_received_preserves_remote_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            shared = Path(tmp)
            target = shared / "nested" / "file.bin"
            target.parent.mkdir()
            target.write_bytes(b"payload")
            modified_ns = time.time_ns() - 1_000_000_000
            os.utime(target, ns=(modified_ns, modified_ns))
            remote = FileEntry(
                relative_path="nested/file.bin",
                file_name="file.bin",
                file_size=7,
                modified_time_ns=modified_ns,
                file_hash=hashlib.sha256(b"payload").hexdigest(),
                version=7,
                source_device_id="device-b",
                status=STATUS_ACTIVE,
                changed_at_ns=modified_ns,
            )

            index = FileIndex(shared, "device-a")
            recorded = index.record_received(remote)
            index.scan()

            self.assertEqual(recorded.version, 7)
            self.assertEqual(index.get("nested/file.bin").source_device_id, "device-b")


class DifferenceRuleTests(unittest.TestCase):
    def test_newer_entry_and_device_id_tie_break_win(self) -> None:
        older = entry("same.txt", modified_time_ns=10, source_device_id="device-z")
        newer = entry(
            "same.txt",
            modified_time_ns=20,
            source_device_id="device-a",
            file_hash="b" * 64,
        )
        tie_winner = entry(
            "same.txt",
            modified_time_ns=20,
            source_device_id="device-z",
            file_hash="c" * 64,
        )

        self.assertTrue(should_send_entry(newer, older))
        self.assertFalse(should_send_entry(older, newer))
        self.assertTrue(should_send_entry(tie_winner, newer))
        self.assertFalse(
            should_send_entry(
                entry(
                    "same.txt",
                    modified_time_ns=20,
                    source_device_id="device-0",
                    file_hash="d" * 64,
                ),
                newer,
            )
        )

    def test_tombstone_blocks_old_file_but_not_new_file(self) -> None:
        tombstone = entry(
            "deleted.txt",
            modified_time_ns=10,
            source_device_id="device-a",
            status=STATUS_DELETED,
            changed_at_ns=30,
        )
        old_file = entry(
            "deleted.txt",
            modified_time_ns=20,
            source_device_id="device-b",
        )
        new_file = entry(
            "deleted.txt",
            modified_time_ns=40,
            source_device_id="device-b",
        )

        self.assertFalse(should_send_entry(old_file, tombstone))
        self.assertTrue(should_send_entry(new_file, tombstone))
        self.assertFalse(should_send_entry(tombstone, old_file))

    def test_same_hash_never_transfers(self) -> None:
        local = entry("same.txt", modified_time_ns=20, source_device_id="device-b")
        remote = entry("same.txt", modified_time_ns=10, source_device_id="device-a")
        self.assertFalse(should_send_entry(local, remote))

    def test_transfer_id_includes_relative_path(self) -> None:
        common = {
            "transfer_mode": "sync",
            "file_name": "same.txt",
            "file_size": 1,
            "file_hash": "a" * 64,
            "chunk_size": 1,
            "total_chunks": 1,
        }
        self.assertNotEqual(
            transfer_id_for(common | {"relative_path": "a/same.txt"}),
            transfer_id_for(common | {"relative_path": "b/same.txt"}),
        )


class PathSafetyTests(unittest.TestCase):
    def test_relative_path_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            shared = Path(tmp)
            self.assertEqual(normalize_relative_path("a/b.txt"), "a/b.txt")
            self.assertEqual(
                destination_for(shared, "a/b.txt"),
                shared / "a" / "b.txt",
            )
            for invalid in ("", "../escape.txt", "/absolute.txt", ".lan-sync/db"):
                with self.subTest(invalid=invalid):
                    with self.assertRaises(ValueError):
                        normalize_relative_path(invalid)

    def test_server_rejects_sync_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            shared = Path(tmp) / "shared"
            index = FileIndex(shared, "device-b")
            server = TCPFileServer(
                "127.0.0.1",
                0,
                shared,
                file_index=index,
            )
            server.start()
            try:
                with socket.create_connection(
                    ("127.0.0.1", server.bound_port),
                    timeout=5.0,
                ) as sock:
                    send_json_message(
                        sock,
                        {
                            "type": "FILE_SEND",
                            "protocol_version": PROTOCOL_VERSION,
                            "transfer_mode": "sync",
                            "file_name": "escape.txt",
                            "relative_path": "../escape.txt",
                            "file_size": 0,
                            "file_hash": hashlib.sha256(b"").hexdigest(),
                            "hash_algorithm": HASH_ALGORITHM,
                            "chunk_size": 1024,
                            "total_chunks": 0,
                            "modified_time_ns": 1,
                            "version": 1,
                            "source_device_id": "device-a",
                            "changed_at_ns": 1,
                        },
                    )
                    response = recv_json_message(sock)
            finally:
                server.stop()

            self.assertEqual(response["error_code"], "INVALID_PATH")
            self.assertFalse((Path(tmp) / "escape.txt").exists())


class StaticDiscovery:
    def __init__(self, devices: list[DiscoveredDevice]) -> None:
        self.devices = devices

    def list_devices(self) -> list[DiscoveredDevice]:
        return list(self.devices)


class IndexExchangeTests(unittest.TestCase):
    def test_large_index_is_exchanged_as_multiple_messages(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            shared = Path(tmp) / "shared"
            shared.mkdir()
            for number in range(400):
                (shared / f"document-{number:04d}-long-file-name.txt").write_text(
                    str(number),
                    encoding="utf-8",
                )

            index = FileIndex(shared, "device-a")
            index.scan()
            server = TCPFileServer(
                "127.0.0.1",
                0,
                shared,
                file_index=index,
            )
            server.start()
            try:
                remote = request_file_index("127.0.0.1", server.bound_port)
            finally:
                server.stop()

            self.assertEqual(len(remote), 400)
            self.assertGreater(
                sum(len(str(item.to_payload())) for item in remote),
                64 * 1024,
            )


class FolderSynchronizationTests(unittest.TestCase):
    def test_new_and_modified_files_sync_and_deletion_does_not_resurrect(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder_a = root / "a"
            folder_b = root / "b"
            index_a = FileIndex(folder_a, "device-a")
            index_b = FileIndex(folder_b, "device-b")
            server_a = TCPFileServer(
                "127.0.0.1",
                0,
                folder_a,
                chunk_size=8,
                file_index=index_a,
            )
            server_b = TCPFileServer(
                "127.0.0.1",
                0,
                folder_b,
                chunk_size=8,
                file_index=index_b,
            )
            server_a.start()
            server_b.start()
            try:
                device_a = DiscoveredDevice(
                    device_id="device-a",
                    device_name="A",
                    ip="127.0.0.1",
                    tcp_port=server_a.bound_port,
                    status="online",
                    last_seen=time.time(),
                )
                device_b = DiscoveredDevice(
                    device_id="device-b",
                    device_name="B",
                    ip="127.0.0.1",
                    tcp_port=server_b.bound_port,
                    status="online",
                    last_seen=time.time(),
                )
                sync_a = SyncService(
                    index_a,
                    StaticDiscovery([device_b]),
                    chunk_size=8,
                    interval_seconds=10,
                )
                sync_b = SyncService(
                    index_b,
                    StaticDiscovery([device_a]),
                    chunk_size=8,
                    interval_seconds=10,
                )

                source_a = folder_a / "docs" / "message.txt"
                source_a.parent.mkdir(parents=True)
                source_a.write_text("created on A", encoding="utf-8")
                target_b = folder_b / "docs" / "message.txt"
                sync_a.interval_seconds = 0.05
                sync_a.start()
                try:
                    deadline = time.time() + 3.0
                    while time.time() < deadline and not target_b.exists():
                        time.sleep(0.02)
                finally:
                    sync_a.stop()
                self.assertEqual(target_b.read_text(encoding="utf-8"), "created on A")

                target_b.write_text("modified on B", encoding="utf-8")
                newer_ns = time.time_ns() + 2_000_000_000
                os.utime(target_b, ns=(newer_ns, newer_ns))
                sync_b.sync_once()
                self.assertEqual(source_a.read_text(encoding="utf-8"), "modified on B")

                source_a.unlink()
                index_a.scan()
                sync_b.sync_once()
                self.assertFalse(source_a.exists())
                self.assertTrue(target_b.exists())
                self.assertEqual(
                    index_a.get("docs/message.txt").status,
                    STATUS_DELETED,
                )
            finally:
                server_a.stop()
                server_b.stop()


if __name__ == "__main__":
    unittest.main()
