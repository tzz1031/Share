from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Iterable

from .paths import INTERNAL_FOLDER, destination_for, normalize_relative_path, should_ignore_path


STATUS_ACTIVE = "active"
STATUS_DELETED = "deleted"
VALID_STATUSES = {STATUS_ACTIVE, STATUS_DELETED}


@dataclass(frozen=True)
class FileEntry:
    relative_path: str
    file_name: str
    file_size: int
    modified_time_ns: int
    file_hash: str
    version: int
    source_device_id: str
    status: str
    changed_at_ns: int
    source_device_name: str = ""
    peer_baseline_hash: str | None = field(default=None, compare=False)
    peer_baseline_status: str | None = field(default=None, compare=False)

    @property
    def effective_time_ns(self) -> int:
        if self.status == STATUS_DELETED:
            return self.changed_at_ns
        return self.modified_time_ns

    def to_payload(self) -> dict[str, Any]:
        payload = {
            "relative_path": self.relative_path,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "modified_time_ns": self.modified_time_ns,
            "file_hash": self.file_hash,
            "version": self.version,
            "source_device_id": self.source_device_id,
            "source_device_name": self.source_device_name,
            "status": self.status,
            "changed_at_ns": self.changed_at_ns,
        }
        if self.peer_baseline_hash is not None:
            payload["peer_baseline_hash"] = self.peer_baseline_hash
        if self.peer_baseline_status is not None:
            payload["peer_baseline_status"] = self.peer_baseline_status
        return payload

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "FileEntry":
        try:
            relative_path = normalize_relative_path(payload["relative_path"])
            file_name = str(payload["file_name"])
            file_size = payload["file_size"]
            modified_time_ns = payload["modified_time_ns"]
            file_hash = str(payload["file_hash"]).lower()
            version = payload["version"]
            source_device_id = str(payload["source_device_id"])
            source_device_name = str(payload.get("source_device_name", ""))
            status = str(payload["status"])
            changed_at_ns = payload["changed_at_ns"]
            raw_peer_baseline_hash = payload.get("peer_baseline_hash")
            peer_baseline_hash = (
                str(raw_peer_baseline_hash).lower()
                if raw_peer_baseline_hash is not None
                else None
            )
            raw_peer_baseline_status = payload.get("peer_baseline_status")
            peer_baseline_status = (
                str(raw_peer_baseline_status)
                if raw_peer_baseline_status is not None
                else None
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"invalid file index entry: {exc}") from exc

        if file_name != _file_name(relative_path):
            raise ValueError("file_name does not match relative_path")
        if type(file_size) is not int or file_size < 0:
            raise ValueError("file_size must be a non-negative integer")
        if type(modified_time_ns) is not int or modified_time_ns < 0:
            raise ValueError("modified_time_ns must be a non-negative integer")
        if type(version) is not int or version < 1:
            raise ValueError("version must be a positive integer")
        if not source_device_id:
            raise ValueError("source_device_id must not be empty")
        if status not in VALID_STATUSES:
            raise ValueError("status must be active or deleted")
        if type(changed_at_ns) is not int or changed_at_ns < 0:
            raise ValueError("changed_at_ns must be a non-negative integer")
        if status == STATUS_ACTIVE:
            if len(file_hash) != 64 or any(
                character not in "0123456789abcdef" for character in file_hash
            ):
                raise ValueError("active entries require a SHA-256 file_hash")
        if peer_baseline_hash is not None and peer_baseline_hash != "":
            if len(peer_baseline_hash) != 64 or any(
                character not in "0123456789abcdef"
                for character in peer_baseline_hash
            ):
                raise ValueError("peer_baseline_hash must be a SHA-256 hash")
        if (
            peer_baseline_status is not None
            and peer_baseline_status not in VALID_STATUSES
        ):
            raise ValueError("peer_baseline_status is invalid")

        return cls(
            relative_path=relative_path,
            file_name=file_name,
            file_size=file_size,
            modified_time_ns=modified_time_ns,
            file_hash=file_hash,
            version=version,
            source_device_id=source_device_id,
            status=status,
            changed_at_ns=changed_at_ns,
            source_device_name=source_device_name,
            peer_baseline_hash=peer_baseline_hash,
            peer_baseline_status=peer_baseline_status,
        )


@dataclass(frozen=True)
class SyncState:
    remote_device_id: str
    relative_path: str
    baseline_hash: str
    baseline_status: str
    local_version: int
    remote_version: int
    synced_at_ns: int


@dataclass(frozen=True)
class ConflictRecord:
    relative_path: str
    local_version: int
    remote_version: int
    local_hash: str
    remote_hash: str
    local_device_id: str
    remote_device_id: str
    winner_device_id: str
    conflict_copy_path: str
    conflict_at_ns: int
    local_size: int = 0
    remote_size: int = 0
    local_modified_time_ns: int = 0
    remote_modified_time_ns: int = 0
    local_status: str = STATUS_ACTIVE
    remote_status: str = STATUS_ACTIVE
    reason_code: str = "BOTH_MODIFIED"
    resolved_at_ns: int | None = None
    resolution_note: str = ""
    conflict_id: int = 0


def _file_name(relative_path: str) -> str:
    return relative_path.rsplit("/", 1)[-1]


def entry_order_key(entry: FileEntry) -> tuple[int, str, int, str, str]:
    return (
        entry.effective_time_ns,
        entry.source_device_id,
        entry.version,
        entry.status,
        entry.file_hash,
    )


def should_send_entry(local: FileEntry, remote: FileEntry | None) -> bool:
    if local.status != STATUS_ACTIVE:
        return False
    if remote is None:
        return True
    if remote.status == STATUS_ACTIVE and remote.file_hash == local.file_hash:
        return False
    return entry_order_key(local) > entry_order_key(remote)


class FileIndex:
    def __init__(
        self,
        shared_folder: str | Path,
        device_id: str,
        device_name: str | None = None,
    ) -> None:
        self.shared_folder = Path(shared_folder)
        self.device_id = str(device_id)
        if not self.device_id:
            raise ValueError("device_id must not be empty")
        self.device_name = str(device_name or device_id)
        self.internal_folder = self.shared_folder / INTERNAL_FOLDER
        self.database_path = self.internal_folder / "index.sqlite3"
        self._lock = threading.RLock()

        self.shared_folder.mkdir(parents=True, exist_ok=True)
        self.internal_folder.mkdir(parents=True, exist_ok=True)
        self._initialize_database()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=30.0)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_database(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS file_index (
                    relative_path TEXT PRIMARY KEY,
                    file_name TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    modified_time_ns INTEGER NOT NULL,
                    file_hash TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    source_device_id TEXT NOT NULL,
                    source_device_name TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL,
                    changed_at_ns INTEGER NOT NULL
                )
                """
            )
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(file_index)")
            }
            if "source_device_name" not in columns:
                connection.execute(
                    """
                    ALTER TABLE file_index
                    ADD COLUMN source_device_name TEXT NOT NULL DEFAULT ''
                    """
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS sync_state (
                    remote_device_id TEXT NOT NULL,
                    relative_path TEXT NOT NULL,
                    baseline_hash TEXT NOT NULL,
                    baseline_status TEXT NOT NULL,
                    local_version INTEGER NOT NULL,
                    remote_version INTEGER NOT NULL,
                    synced_at_ns INTEGER NOT NULL,
                    PRIMARY KEY (remote_device_id, relative_path)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS device_sync_status (
                    remote_device_id TEXT PRIMARY KEY,
                    last_sync_at_ns INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS conflict_log (
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
                    conflict_at_ns INTEGER NOT NULL,
                    UNIQUE (
                        relative_path, local_hash, remote_hash,
                        local_device_id, remote_device_id
                    )
                )
                """
            )
            conflict_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(conflict_log)")
            }
            conflict_migrations = {
                "local_size": "INTEGER NOT NULL DEFAULT 0",
                "remote_size": "INTEGER NOT NULL DEFAULT 0",
                "local_modified_time_ns": "INTEGER NOT NULL DEFAULT 0",
                "remote_modified_time_ns": "INTEGER NOT NULL DEFAULT 0",
                "local_status": "TEXT NOT NULL DEFAULT 'active'",
                "remote_status": "TEXT NOT NULL DEFAULT 'active'",
                "reason_code": "TEXT NOT NULL DEFAULT 'BOTH_MODIFIED'",
                "resolved_at_ns": "INTEGER",
                "resolution_note": "TEXT NOT NULL DEFAULT ''",
            }
            for column, definition in conflict_migrations.items():
                if column not in conflict_columns:
                    connection.execute(
                        f"ALTER TABLE conflict_log ADD COLUMN {column} {definition}"
                    )

    def scan(self) -> list[FileEntry]:
        with self._lock:
            existing = {entry.relative_path: entry for entry in self.snapshot()}
            seen: set[str] = set()
            updates: list[FileEntry] = []

            for path in self._iter_files():
                relative_path = path.relative_to(self.shared_folder).as_posix()
                seen.add(relative_path)
                current = existing.get(relative_path)
                refreshed = self._entry_for_file(path, relative_path, current)
                if refreshed is not None and refreshed != current:
                    updates.append(refreshed)

            for relative_path, current in existing.items():
                if current.status != STATUS_ACTIVE or relative_path in seen:
                    continue
                updates.append(
                    FileEntry(
                        relative_path=relative_path,
                        file_name=current.file_name,
                        file_size=current.file_size,
                        modified_time_ns=current.modified_time_ns,
                        file_hash=current.file_hash,
                        version=current.version + 1,
                        source_device_id=self.device_id,
                        status=STATUS_DELETED,
                        changed_at_ns=max(
                            time.time_ns(),
                            current.effective_time_ns + 1,
                        ),
                        source_device_name=self.device_name,
                    )
                )

            self._upsert_many(updates)
            return self.snapshot()

    def snapshot(self) -> list[FileEntry]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT relative_path, file_name, file_size, modified_time_ns,
                       file_hash, version, source_device_id, source_device_name,
                       status, changed_at_ns
                FROM file_index
                ORDER BY relative_path
                """
            ).fetchall()
        return [self._row_to_entry(row) for row in rows]

    def get(self, relative_path: str) -> FileEntry | None:
        normalized = normalize_relative_path(relative_path)
        with self._lock, self._connect() as connection:
            row = connection.execute(
                """
                SELECT relative_path, file_name, file_size, modified_time_ns,
                       file_hash, version, source_device_id, source_device_name,
                       status, changed_at_ns
                FROM file_index
                WHERE relative_path = ?
                """,
                (normalized,),
            ).fetchone()
        return self._row_to_entry(row) if row is not None else None

    def refresh_path(self, relative_path: str) -> FileEntry | None:
        normalized = normalize_relative_path(relative_path)
        with self._lock:
            current = self.get(normalized)
            path = destination_for(self.shared_folder, normalized)
            if (
                path.is_file()
                and not path.is_symlink()
                and not should_ignore_path(self.shared_folder, path)
            ):
                refreshed = self._entry_for_file(path, normalized, current)
                if refreshed is not None and refreshed != current:
                    self._upsert_many([refreshed])
                    return refreshed
                return current

            if current is None or current.status == STATUS_DELETED:
                return current
            deleted = FileEntry(
                relative_path=normalized,
                file_name=current.file_name,
                file_size=current.file_size,
                modified_time_ns=current.modified_time_ns,
                file_hash=current.file_hash,
                version=current.version + 1,
                source_device_id=self.device_id,
                status=STATUS_DELETED,
                changed_at_ns=max(
                    time.time_ns(),
                    current.effective_time_ns + 1,
                ),
                source_device_name=self.device_name,
            )
            self._upsert_many([deleted])
            return deleted

    def record_received(self, entry: FileEntry) -> FileEntry:
        if entry.status != STATUS_ACTIVE:
            raise ValueError("only active files can be recorded as received")
        path = destination_for(self.shared_folder, entry.relative_path)
        stat = path.stat()
        if not path.is_file() or path.is_symlink():
            raise ValueError("received path is not a regular file")
        if stat.st_size != entry.file_size:
            raise ValueError("received file size does not match index entry")

        recorded = FileEntry(
            relative_path=entry.relative_path,
            file_name=entry.file_name,
            file_size=entry.file_size,
            modified_time_ns=stat.st_mtime_ns,
            file_hash=entry.file_hash,
            version=entry.version,
            source_device_id=entry.source_device_id,
            status=STATUS_ACTIVE,
            changed_at_ns=entry.changed_at_ns,
            source_device_name=entry.source_device_name,
        )
        with self._lock:
            self._upsert_many([recorded])
        return recorded

    def entry_for_peer(
        self,
        entry: FileEntry,
        remote_device_id: str,
    ) -> FileEntry:
        state = self.get_sync_state(remote_device_id, entry.relative_path)
        if state is None:
            return entry
        return replace(
            entry,
            peer_baseline_hash=state.baseline_hash,
            peer_baseline_status=state.baseline_status,
        )

    def get_sync_state(
        self,
        remote_device_id: str,
        relative_path: str,
    ) -> SyncState | None:
        normalized = normalize_relative_path(relative_path)
        with self._lock, self._connect() as connection:
            row = connection.execute(
                """
                SELECT remote_device_id, relative_path, baseline_hash,
                       baseline_status, local_version, remote_version,
                       synced_at_ns
                FROM sync_state
                WHERE remote_device_id = ? AND relative_path = ?
                """,
                (str(remote_device_id), normalized),
            ).fetchone()
        if row is None:
            return None
        return SyncState(
            remote_device_id=str(row["remote_device_id"]),
            relative_path=str(row["relative_path"]),
            baseline_hash=str(row["baseline_hash"]),
            baseline_status=str(row["baseline_status"]),
            local_version=int(row["local_version"]),
            remote_version=int(row["remote_version"]),
            synced_at_ns=int(row["synced_at_ns"]),
        )

    def record_sync(
        self,
        remote_device_id: str,
        entry: FileEntry,
        *,
        remote_version: int | None = None,
        synced_at_ns: int | None = None,
    ) -> SyncState:
        remote_device_id = str(remote_device_id)
        if not remote_device_id:
            raise ValueError("remote_device_id must not be empty")
        sync_time = time.time_ns() if synced_at_ns is None else int(synced_at_ns)
        peer_version = entry.version if remote_version is None else int(remote_version)
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO sync_state (
                    remote_device_id, relative_path, baseline_hash,
                    baseline_status, local_version, remote_version,
                    synced_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(remote_device_id, relative_path) DO UPDATE SET
                    baseline_hash = excluded.baseline_hash,
                    baseline_status = excluded.baseline_status,
                    local_version = excluded.local_version,
                    remote_version = excluded.remote_version,
                    synced_at_ns = excluded.synced_at_ns
                """,
                (
                    remote_device_id,
                    entry.relative_path,
                    entry.file_hash,
                    entry.status,
                    entry.version,
                    peer_version,
                    sync_time,
                ),
            )
            connection.execute(
                """
                INSERT INTO device_sync_status (
                    remote_device_id, last_sync_at_ns
                ) VALUES (?, ?)
                ON CONFLICT(remote_device_id) DO UPDATE SET
                    last_sync_at_ns = excluded.last_sync_at_ns
                """,
                (remote_device_id, sync_time),
            )
        return SyncState(
            remote_device_id=remote_device_id,
            relative_path=entry.relative_path,
            baseline_hash=entry.file_hash,
            baseline_status=entry.status,
            local_version=entry.version,
            remote_version=peer_version,
            synced_at_ns=sync_time,
        )

    def record_device_sync(self, remote_device_id: str) -> int:
        sync_time = time.time_ns()
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO device_sync_status (
                    remote_device_id, last_sync_at_ns
                ) VALUES (?, ?)
                ON CONFLICT(remote_device_id) DO UPDATE SET
                    last_sync_at_ns = excluded.last_sync_at_ns
                """,
                (str(remote_device_id), sync_time),
            )
        return sync_time

    def get_last_sync_time(self, remote_device_id: str) -> int | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                """
                SELECT last_sync_at_ns
                FROM device_sync_status
                WHERE remote_device_id = ?
                """,
                (str(remote_device_id),),
            ).fetchone()
        return int(row["last_sync_at_ns"]) if row is not None else None

    def record_conflict(
        self,
        *,
        relative_path: str,
        local_entry: FileEntry,
        remote_entry: FileEntry,
        remote_device_id: str,
        winner_device_id: str,
        conflict_copy_path: str,
        reason_code: str = "BOTH_MODIFIED",
    ) -> None:
        normalized = normalize_relative_path(relative_path)
        normalized_copy = (
            normalize_relative_path(conflict_copy_path)
            if conflict_copy_path
            else ""
        )
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO conflict_log (
                    relative_path, local_version, remote_version,
                    local_hash, remote_hash, local_device_id,
                    remote_device_id, winner_device_id,
                    conflict_copy_path, conflict_at_ns,
                    local_size, remote_size,
                    local_modified_time_ns, remote_modified_time_ns,
                    local_status, remote_status, reason_code
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    normalized,
                    local_entry.version,
                    remote_entry.version,
                    local_entry.file_hash,
                    remote_entry.file_hash,
                    self.device_id,
                    str(remote_device_id),
                    str(winner_device_id),
                    normalized_copy,
                    time.time_ns(),
                    local_entry.file_size,
                    remote_entry.file_size,
                    local_entry.modified_time_ns,
                    remote_entry.modified_time_ns,
                    local_entry.status,
                    remote_entry.status,
                    str(reason_code),
                ),
            )

    def list_conflicts(
        self,
        *,
        resolved: bool | None = None,
    ) -> list[ConflictRecord]:
        where = ""
        if resolved is True:
            where = "WHERE resolved_at_ns IS NOT NULL"
        elif resolved is False:
            where = "WHERE resolved_at_ns IS NULL"
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT id, relative_path, local_version, remote_version,
                       local_hash, remote_hash, local_device_id,
                       remote_device_id, winner_device_id,
                       conflict_copy_path, conflict_at_ns,
                       local_size, remote_size,
                       local_modified_time_ns, remote_modified_time_ns,
                       local_status, remote_status, reason_code,
                       resolved_at_ns, resolution_note
                FROM conflict_log
                {where}
                ORDER BY conflict_at_ns, id
                """
            ).fetchall()
        return [
            ConflictRecord(
                conflict_id=int(row["id"]),
                relative_path=str(row["relative_path"]),
                local_version=int(row["local_version"]),
                remote_version=int(row["remote_version"]),
                local_hash=str(row["local_hash"]),
                remote_hash=str(row["remote_hash"]),
                local_device_id=str(row["local_device_id"]),
                remote_device_id=str(row["remote_device_id"]),
                winner_device_id=str(row["winner_device_id"]),
                conflict_copy_path=str(row["conflict_copy_path"]),
                conflict_at_ns=int(row["conflict_at_ns"]),
                local_size=int(row["local_size"]),
                remote_size=int(row["remote_size"]),
                local_modified_time_ns=int(row["local_modified_time_ns"]),
                remote_modified_time_ns=int(row["remote_modified_time_ns"]),
                local_status=str(row["local_status"]),
                remote_status=str(row["remote_status"]),
                reason_code=str(row["reason_code"]),
                resolved_at_ns=(
                    int(row["resolved_at_ns"])
                    if row["resolved_at_ns"] is not None
                    else None
                ),
                resolution_note=str(row["resolution_note"]),
            )
            for row in rows
        ]

    def resolve_conflict(self, conflict_id: int, note: str = "") -> bool:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE conflict_log
                SET resolved_at_ns = ?, resolution_note = ?
                WHERE id = ? AND resolved_at_ns IS NULL
                """,
                (time.time_ns(), str(note).strip(), int(conflict_id)),
            )
        return cursor.rowcount > 0

    def get_conflict(self, conflict_id: int) -> ConflictRecord | None:
        for conflict in self.list_conflicts():
            if conflict.conflict_id == int(conflict_id):
                return conflict
        return None

    def _iter_files(self) -> Iterable[Path]:
        for root, directories, files in os.walk(
            self.shared_folder,
            topdown=True,
            followlinks=False,
        ):
            root_path = Path(root)
            directories[:] = [
                directory
                for directory in directories
                if directory != INTERNAL_FOLDER
                and not (root_path / directory).is_symlink()
            ]
            for file_name in files:
                path = root_path / file_name
                if path.is_symlink() or should_ignore_path(self.shared_folder, path):
                    continue
                try:
                    if path.is_file():
                        yield path
                except OSError:
                    continue

    def _entry_for_file(
        self,
        path: Path,
        relative_path: str,
        current: FileEntry | None,
    ) -> FileEntry | None:
        try:
            before = path.stat()
        except OSError:
            return None

        if (
            current is not None
            and current.status == STATUS_ACTIVE
            and current.file_size == before.st_size
            and current.modified_time_ns == before.st_mtime_ns
        ):
            return current

        try:
            digest = hashlib.sha256()
            with path.open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
            file_hash = digest.hexdigest()
            after = path.stat()
        except OSError:
            return None
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            return None

        version = 1 if current is None else current.version + 1
        return FileEntry(
            relative_path=relative_path,
            file_name=path.name,
            file_size=after.st_size,
            modified_time_ns=after.st_mtime_ns,
            file_hash=file_hash,
            version=version,
            source_device_id=self.device_id,
            status=STATUS_ACTIVE,
            changed_at_ns=time.time_ns(),
            source_device_name=self.device_name,
        )

    def _upsert_many(self, entries: Iterable[FileEntry]) -> None:
        values = [
            (
                entry.relative_path,
                entry.file_name,
                entry.file_size,
                entry.modified_time_ns,
                entry.file_hash,
                entry.version,
                entry.source_device_id,
                entry.source_device_name,
                entry.status,
                entry.changed_at_ns,
            )
            for entry in entries
        ]
        if not values:
            return
        with self._connect() as connection:
            connection.executemany(
                """
                INSERT INTO file_index (
                    relative_path, file_name, file_size, modified_time_ns,
                    file_hash, version, source_device_id, source_device_name,
                    status, changed_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(relative_path) DO UPDATE SET
                    file_name = excluded.file_name,
                    file_size = excluded.file_size,
                    modified_time_ns = excluded.modified_time_ns,
                    file_hash = excluded.file_hash,
                    version = excluded.version,
                    source_device_id = excluded.source_device_id,
                    source_device_name = excluded.source_device_name,
                    status = excluded.status,
                    changed_at_ns = excluded.changed_at_ns
                """,
                values,
            )

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> FileEntry:
        return FileEntry(
            relative_path=str(row["relative_path"]),
            file_name=str(row["file_name"]),
            file_size=int(row["file_size"]),
            modified_time_ns=int(row["modified_time_ns"]),
            file_hash=str(row["file_hash"]),
            version=int(row["version"]),
            source_device_id=str(row["source_device_id"]),
            status=str(row["status"]),
            changed_at_ns=int(row["changed_at_ns"]),
            source_device_name=str(row["source_device_name"]),
        )
