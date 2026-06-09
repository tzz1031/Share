from __future__ import annotations

import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from discovery import DiscoveredDevice
from security import (
    PERMISSION_ADMIN,
    PERMISSION_BLOCKED,
    PERMISSION_READ,
    PERMISSION_WRITE,
    SecurityStore,
)
from security.pairing import pair_with_device
from sync import (
    STATUS_ACTIVE,
    STATUS_DELETED,
    FileEntry,
    FileIndex,
    SyncState,
    conflict_copy_relative_path,
    decide_conflict,
)
from sync.index_exchange import request_file_index
from sync.service import SyncService
from transfer import TCPFileServer, TransferError, calculate_sha256, send_file


class StaticDiscovery:
    def __init__(self, devices: list[DiscoveredDevice]) -> None:
        self.devices = devices

    def list_devices(self) -> list[DiscoveredDevice]:
        return list(self.devices)


def discovered(device_id: str, name: str, port: int) -> DiscoveredDevice:
    return DiscoveredDevice(
        device_id=device_id,
        device_name=name,
        ip="127.0.0.1",
        tcp_port=port,
        status="online",
        last_seen=time.time(),
    )


class SecurityStoreTests(unittest.TestCase):
    def test_pair_code_persists_and_permissions_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            shared = Path(tmp)
            first = SecurityStore(shared)
            original_code = first.pair_code
            second = SecurityStore(shared)
            self.assertEqual(second.pair_code, original_code)

            second.authorize_device("device-a", "A", "token-value", PERMISSION_READ)
            self.assertEqual(
                second.authenticate("device-a", "token-value", PERMISSION_READ).permission,
                PERMISSION_READ,
            )
            with self.assertRaisesRegex(ValueError, "write"):
                second.authenticate("device-a", "token-value", PERMISSION_WRITE)

            second.set_permission("device-a", PERMISSION_BLOCKED)
            with self.assertRaisesRegex(ValueError, "阻止"):
                second.authenticate("device-a", "token-value", PERMISSION_READ)
            self.assertNotEqual(second.regenerate_pair_code(), original_code)

    def test_stage_four_database_is_migrated_without_data_loss(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            shared = Path(tmp)
            internal = shared / ".lan-sync"
            internal.mkdir(parents=True)
            database = internal / "index.sqlite3"
            with sqlite3.connect(database) as connection:
                connection.execute(
                    """
                    CREATE TABLE file_index (
                        relative_path TEXT PRIMARY KEY,
                        file_name TEXT NOT NULL,
                        file_size INTEGER NOT NULL,
                        modified_time_ns INTEGER NOT NULL,
                        file_hash TEXT NOT NULL,
                        version INTEGER NOT NULL,
                        source_device_id TEXT NOT NULL,
                        status TEXT NOT NULL,
                        changed_at_ns INTEGER NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    INSERT INTO file_index VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "old.txt",
                        "old.txt",
                        3,
                        1,
                        "a" * 64,
                        4,
                        "old-device",
                        "active",
                        2,
                    ),
                )

            index = FileIndex(shared, "new-device", "New")
            entry = index.get("old.txt")
            self.assertIsNotNone(entry)
            self.assertEqual(entry.version, 4)
            self.assertEqual(entry.source_device_name, "")

    def test_conflict_resolution_columns_are_migrated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            shared = Path(tmp)
            internal = shared / ".lan-sync"
            internal.mkdir(parents=True)
            database = internal / "index.sqlite3"
            with sqlite3.connect(database) as connection:
                connection.execute(
                    """
                    CREATE TABLE conflict_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        relative_path TEXT NOT NULL,
                        local_version INTEGER NOT NULL,
                        remote_version INTEGER NOT NULL,
                        local_hash TEXT NOT NULL,
                        remote_hash TEXT NOT NULL,
                        local_device_id TEXT NOT NULL,
                        remote_device_id TEXT NOT NULL,
                        winner_device_id TEXT NOT NULL,
                        conflict_copy_path TEXT NOT NULL,
                        conflict_at_ns INTEGER NOT NULL
                    )
                    """
                )

            FileIndex(shared, "new-device", "New")
            with sqlite3.connect(database) as connection:
                columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(conflict_log)"
                    )
                }
            self.assertIn("resolved_at_ns", columns)
            self.assertIn("resolution_note", columns)


class PairingAndPermissionTests(unittest.TestCase):
    def test_pairing_is_bidirectional_and_permission_matrix_applies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder_a = root / "a"
            folder_b = root / "b"
            security_a = SecurityStore(folder_a)
            security_b = SecurityStore(folder_b)
            index_b = FileIndex(folder_b, "device-b", "B")
            (folder_b / "indexed.txt").write_text("index", encoding="utf-8")
            index_b.scan()
            server_b = TCPFileServer(
                "127.0.0.1",
                0,
                folder_b,
                file_index=index_b,
                security_store=security_b,
                device_id="device-b",
                device_name="B",
            )
            server_b.start()
            try:
                with self.assertRaisesRegex(ValueError, "配对"):
                    request_file_index(
                        "127.0.0.1",
                        server_b.bound_port,
                    )

                wrong_code = (
                    "000001"
                    if security_b.pair_code == "000000"
                    else "000000"
                )
                with self.assertRaises(TransferError) as wrong:
                    pair_with_device(
                        "127.0.0.1",
                        server_b.bound_port,
                        pair_code=wrong_code,
                        local_device_id="device-a",
                        local_device_name="A",
                        security_store=security_a,
                    )
                self.assertEqual(wrong.exception.code, "AUTH_FAILED")

                pair_with_device(
                    "127.0.0.1",
                    server_b.bound_port,
                    pair_code=security_b.pair_code,
                    local_device_id="device-a",
                    local_device_name="A",
                    security_store=security_a,
                )
                record_a = security_a.get_device("device-b")
                record_b = security_b.get_device("device-a")
                self.assertIsNotNone(record_a)
                self.assertIsNotNone(record_b)
                self.assertEqual(record_a.token, record_b.token)
                self.assertEqual(record_a.permission, PERMISSION_WRITE)

                credential = security_a.credential_for("device-b", "device-a")
                self.assertEqual(
                    len(
                        request_file_index(
                            "127.0.0.1",
                            server_b.bound_port,
                            credential=credential,
                        )
                    ),
                    1,
                )

                source = root / "manual.txt"
                source.write_text("manual", encoding="utf-8")
                security_b.set_permission("device-a", PERMISSION_BLOCKED)
                with self.assertRaisesRegex(ValueError, "阻止"):
                    request_file_index(
                        "127.0.0.1",
                        server_b.bound_port,
                        credential=credential,
                    )

                security_b.set_permission("device-a", PERMISSION_READ)
                with self.assertRaises(TransferError) as denied:
                    send_file(
                        "127.0.0.1",
                        server_b.bound_port,
                        source,
                        credential=credential,
                    )
                self.assertEqual(denied.exception.code, "PERMISSION_DENIED")

                security_b.set_permission("device-a", PERMISSION_ADMIN)
                send_file(
                    "127.0.0.1",
                    server_b.bound_port,
                    source,
                    credential=credential,
                )
                self.assertTrue((folder_b / "manual.txt").is_file())
            finally:
                server_b.stop()


class ConflictRuleTests(unittest.TestCase):
    @staticmethod
    def entry(
        file_hash: str,
        device_id: str,
        *,
        status: str = STATUS_ACTIVE,
        version: int = 2,
    ) -> FileEntry:
        return FileEntry(
            relative_path="same.txt",
            file_name="same.txt",
            file_size=1,
            modified_time_ns=version,
            file_hash=file_hash,
            version=version,
            source_device_id=device_id,
            status=status,
            changed_at_ns=version,
            source_device_name=device_id,
        )

    def test_baseline_distinguishes_one_sided_and_two_sided_changes(self) -> None:
        baseline_hash = "a" * 64
        state = SyncState(
            remote_device_id="device-b",
            relative_path="same.txt",
            baseline_hash=baseline_hash,
            baseline_status=STATUS_ACTIVE,
            local_version=1,
            remote_version=1,
            synced_at_ns=1,
        )
        unchanged = self.entry(baseline_hash, "device-a", version=1)
        local_changed = self.entry("b" * 64, "device-a")
        remote_changed = self.entry("c" * 64, "device-b")

        one_sided = decide_conflict(
            local_changed,
            unchanged,
            state,
            baseline_hash,
            STATUS_ACTIVE,
        )
        self.assertFalse(one_sided.conflict)
        self.assertTrue(one_sided.local_changed)
        self.assertFalse(one_sided.remote_changed)

        two_sided = decide_conflict(
            local_changed,
            remote_changed,
            state,
            baseline_hash,
            STATUS_ACTIVE,
        )
        self.assertTrue(two_sided.conflict)

        first_divergence = decide_conflict(
            local_changed,
            remote_changed,
            None,
            None,
            None,
        )
        self.assertTrue(first_divergence.conflict)

        same_content = decide_conflict(
            local_changed,
            self.entry("b" * 64, "device-b"),
            state,
            baseline_hash,
            STATUS_ACTIVE,
        )
        self.assertFalse(same_content.conflict)

    def test_active_file_wins_delete_modify_conflict(self) -> None:
        deleted = self.entry(
            "a" * 64,
            "device-a",
            status=STATUS_DELETED,
            version=3,
        )
        modified = self.entry("b" * 64, "device-b", version=2)
        decision = decide_conflict(deleted, modified, None, None, None)
        self.assertTrue(decision.conflict)
        self.assertEqual(decision.winner.status, STATUS_ACTIVE)

    def test_conflict_copy_name_collision_keeps_both_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            shared = Path(tmp)
            destination = shared / "same.txt"
            destination.write_text("losing content", encoding="utf-8")
            digest = calculate_sha256(destination)
            entry = self.entry(digest, "device-b")
            base_relative = conflict_copy_relative_path(entry)
            occupied = shared / base_relative
            occupied.write_text("already here", encoding="utf-8")
            server = TCPFileServer("127.0.0.1", 0, shared)

            actual_relative = server._preserve_conflict_copy(destination, entry)

            self.assertNotEqual(actual_relative, base_relative)
            self.assertEqual(occupied.read_text(encoding="utf-8"), "already here")
            self.assertEqual(
                (shared / actual_relative).read_text(encoding="utf-8"),
                "losing content",
            )


class ConflictSynchronizationTests(unittest.TestCase):
    def test_two_sided_modification_creates_conflict_copy_and_converges(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder_a = root / "a"
            folder_b = root / "b"
            security_a = SecurityStore(folder_a)
            security_b = SecurityStore(folder_b)
            token = SecurityStore.generate_token()
            security_a.authorize_device("device-b", "B", token, PERMISSION_WRITE)
            security_b.authorize_device("device-a", "A", token, PERMISSION_WRITE)
            index_a = FileIndex(folder_a, "device-a", "A")
            index_b = FileIndex(folder_b, "device-b", "B")
            server_a = TCPFileServer(
                "127.0.0.1",
                0,
                folder_a,
                chunk_size=8,
                file_index=index_a,
                security_store=security_a,
                device_id="device-a",
                device_name="A",
            )
            server_b = TCPFileServer(
                "127.0.0.1",
                0,
                folder_b,
                chunk_size=8,
                file_index=index_b,
                security_store=security_b,
                device_id="device-b",
                device_name="B",
            )
            server_a.start()
            server_b.start()
            try:
                sync_a = SyncService(
                    index_a,
                    StaticDiscovery(
                        [discovered("device-b", "B", server_b.bound_port)]
                    ),
                    chunk_size=8,
                    security_store=security_a,
                )
                sync_b = SyncService(
                    index_b,
                    StaticDiscovery(
                        [discovered("device-a", "A", server_a.bound_port)]
                    ),
                    chunk_size=8,
                    security_store=security_b,
                )
                path_a = folder_a / "docs" / "report.txt"
                path_a.parent.mkdir(parents=True)
                path_a.write_text("common", encoding="utf-8")
                sync_a.sync_once()
                path_b = folder_b / "docs" / "report.txt"
                self.assertEqual(path_b.read_text(encoding="utf-8"), "common")

                path_a.write_text("edited on A", encoding="utf-8")
                path_b.write_text("edited on B", encoding="utf-8")
                base_ns = time.time_ns() + 2_000_000_000
                os.utime(path_b, ns=(base_ns, base_ns))
                os.utime(path_a, ns=(base_ns + 1_000_000, base_ns + 1_000_000))
                index_a.scan()
                index_b.scan()
                losing_entry = index_b.get("docs/report.txt")
                conflict_relative = conflict_copy_relative_path(losing_entry)

                sync_a.sync_once()
                self.assertEqual(path_a.read_text(encoding="utf-8"), "edited on A")
                self.assertEqual(path_b.read_text(encoding="utf-8"), "edited on A")
                conflict_b = folder_b / Path(conflict_relative)
                self.assertEqual(
                    conflict_b.read_text(encoding="utf-8"),
                    "edited on B",
                )
                self.assertEqual(len(index_b.list_conflicts()), 1)

                sync_b.sync_once()
                conflict_a = folder_a / Path(conflict_relative)
                self.assertEqual(
                    conflict_a.read_text(encoding="utf-8"),
                    "edited on B",
                )
                self.assertIsNotNone(index_a.get_last_sync_time("device-b"))
                self.assertIsNotNone(index_b.get_last_sync_time("device-a"))

                sync_a.sync_once()
                sync_b.sync_once()
                self.assertEqual(len(index_b.list_conflicts()), 1)
                self.assertEqual(
                    list((folder_b / "docs").glob("*冲突副本*")),
                    [conflict_b],
                )
            finally:
                server_a.stop()
                server_b.stop()


if __name__ == "__main__":
    unittest.main()
