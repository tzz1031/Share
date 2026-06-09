from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from .file_index import (
    STATUS_ACTIVE,
    FileEntry,
    SyncState,
    entry_order_key,
)


@dataclass(frozen=True)
class ConflictDecision:
    conflict: bool
    local_changed: bool
    remote_changed: bool
    winner: FileEntry | None
    reason_code: str = "NO_CONFLICT"


def _matches_baseline(
    entry: FileEntry | None,
    baseline_hash: str,
    baseline_status: str,
) -> bool:
    if entry is None:
        return baseline_status != STATUS_ACTIVE
    return (
        entry.status == baseline_status
        and entry.file_hash == baseline_hash
    )


def decide_conflict(
    local: FileEntry | None,
    remote: FileEntry | None,
    local_state: SyncState | None,
    remote_baseline_hash: str | None,
    remote_baseline_status: str | None,
) -> ConflictDecision:
    if local is None or remote is None:
        return ConflictDecision(
            False,
            local is not None,
            remote is not None,
            None,
            "MISSING_SIDE",
        )
    if (
        local.status == STATUS_ACTIVE
        and remote.status == STATUS_ACTIVE
        and local.file_hash == remote.file_hash
    ):
        return ConflictDecision(False, False, False, local, "SAME_CONTENT")

    if (
        local_state is None
        or remote_baseline_hash is None
        or remote_baseline_status is None
        or local_state.baseline_hash != remote_baseline_hash
        or local_state.baseline_status != remote_baseline_status
    ):
        return ConflictDecision(
            True,
            True,
            True,
            choose_winner(local, remote),
            (
                "DELETE_MODIFY"
                if local.status != remote.status
                else "BASELINE_DIVERGED"
            ),
        )

    local_changed = not _matches_baseline(
        local,
        local_state.baseline_hash,
        local_state.baseline_status,
    )
    remote_changed = not _matches_baseline(
        remote,
        local_state.baseline_hash,
        local_state.baseline_status,
    )
    return ConflictDecision(
        local_changed and remote_changed,
        local_changed,
        remote_changed,
        choose_winner(local, remote),
        (
            "DELETE_MODIFY"
            if local_changed
            and remote_changed
            and local.status != remote.status
            else "BOTH_MODIFIED"
            if local_changed and remote_changed
            else "ONE_SIDE_CHANGED"
        ),
    )


def choose_winner(local: FileEntry, remote: FileEntry) -> FileEntry:
    if local.status == STATUS_ACTIVE and remote.status != STATUS_ACTIVE:
        return local
    if remote.status == STATUS_ACTIVE and local.status != STATUS_ACTIVE:
        return remote
    return max((local, remote), key=entry_order_key)


def conflict_copy_relative_path(entry: FileEntry) -> str:
    path = PurePosixPath(entry.relative_path)
    suffix = path.suffix
    stem = path.name[: -len(suffix)] if suffix else path.name
    device_name = entry.source_device_name or entry.source_device_id
    safe_device_name = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", device_name)
    safe_device_name = safe_device_name.strip(" ._") or "Unknown"
    copy_name = (
        f"{stem}_{safe_device_name}_{entry.source_device_id[:8]}"
        f"_冲突副本_{entry.file_hash[:8]}{suffix}"
    )
    return str(path.with_name(copy_name))
