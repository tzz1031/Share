from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Callable

from security import AuthCredential, TLSPolicy, open_connection
from sync.file_index import FileEntry, FileIndex, STATUS_ACTIVE
from sync.paths import destination_for

from .hash_utils import calculate_sha256
from .protocol import (
    PROTOCOL_VERSION,
    TransferError,
    is_sha256,
    recv_exact,
    recv_json_message,
    send_json_message,
    validate_chunk_size,
)


ProgressCallback = Callable[[int, int], None]


def entry_signature(entry: FileEntry | None) -> tuple[Any, ...] | None:
    if entry is None:
        return None
    return (
        entry.relative_path,
        entry.file_size,
        entry.modified_time_ns,
        entry.file_hash,
        entry.version,
        entry.source_device_id,
        entry.status,
        entry.changed_at_ns,
    )


def _raise_remote_error(message: dict[str, Any]) -> None:
    if message.get("type") == "TRANSFER_ERROR":
        raise TransferError.from_payload(message)


def fetch_sync_file(
    target_ip: str,
    target_port: int,
    *,
    remote_entry: FileEntry,
    remote_device_id: str,
    shared_folder: str | Path,
    file_index: FileIndex,
    expected_local_entry: FileEntry | None,
    credential: AuthCredential,
    tls_policy: TLSPolicy,
    timeout: float = 60.0,
    progress_callback: ProgressCallback | None = None,
    _allow_restart: bool = True,
) -> dict[str, Any]:
    if remote_entry.status != STATUS_ACTIVE:
        raise TransferError("FILE_NOT_FOUND", "不能下载已删除的远端文件。")

    root = Path(shared_folder)
    transfer_key = hashlib.sha256(
        f"{remote_device_id}\0{remote_entry.relative_path}\0{remote_entry.file_hash}".encode(
            "utf-8"
        )
    ).hexdigest()
    fetch_folder = root / ".lan-sync" / "fetch"
    fetch_folder.mkdir(parents=True, exist_ok=True)
    part_path = fetch_folder / f"{transfer_key}.part"
    offset = part_path.stat().st_size if part_path.is_file() else 0
    if offset > remote_entry.file_size:
        part_path.unlink(missing_ok=True)
        offset = 0

    request = {
        "type": "FILE_FETCH_REQUEST",
        "protocol_version": PROTOCOL_VERSION,
        "relative_path": remote_entry.relative_path,
        "expected_hash": remote_entry.file_hash,
        "offset": offset,
        **credential.to_payload(),
    }
    try:
        with open_connection(target_ip, target_port, timeout, tls_policy) as connection:
            connection.settimeout(timeout)
            send_json_message(connection, request)
            begin = recv_json_message(connection)
            _raise_remote_error(begin)
            if (
                begin.get("type") != "FILE_FETCH_BEGIN"
                or begin.get("protocol_version") != PROTOCOL_VERSION
                or begin.get("offset") != offset
            ):
                raise TransferError("INVALID_RESPONSE", "远端返回了无效的下载响应。")
            try:
                actual_entry = FileEntry.from_payload(begin["entry"])
                chunk_size = validate_chunk_size(begin["chunk_size"])
            except (KeyError, TypeError, ValueError) as exc:
                raise TransferError(
                    "INVALID_RESPONSE",
                    f"远端下载元数据无效：{exc}",
                ) from exc
            if entry_signature(actual_entry) != entry_signature(remote_entry):
                raise TransferError("PLAN_STALE", "远端文件已变化，请重新生成同步计划。")
            if offset != actual_entry.file_size and offset % chunk_size != 0:
                part_path.unlink(missing_ok=True)
                if _allow_restart:
                    return fetch_sync_file(
                        target_ip,
                        target_port,
                        remote_entry=remote_entry,
                        remote_device_id=remote_device_id,
                        shared_folder=root,
                        file_index=file_index,
                        expected_local_entry=expected_local_entry,
                        credential=credential,
                        tls_policy=tls_policy,
                        timeout=timeout,
                        progress_callback=progress_callback,
                        _allow_restart=False,
                    )
                raise TransferError("INVALID_OFFSET", "本地断点文件与远端分块不兼容。")

            received = offset
            if progress_callback is not None:
                progress_callback(received, actual_entry.file_size)
            with part_path.open("ab" if offset else "wb") as output:
                while received < actual_entry.file_size:
                    metadata = recv_json_message(connection)
                    _raise_remote_error(metadata)
                    if metadata.get("type") != "FILE_FETCH_CHUNK":
                        raise TransferError("INVALID_RESPONSE", "远端缺少下载分块。")
                    raw_size = metadata.get("chunk_size")
                    chunk_index = metadata.get("chunk_index")
                    expected_index = received // chunk_size
                    if (
                        type(raw_size) is not int
                        or raw_size <= 0
                        or raw_size > chunk_size
                        or chunk_index != expected_index
                        or not is_sha256(metadata.get("chunk_hash"))
                    ):
                        raise TransferError("INVALID_RESPONSE", "远端下载分块元数据无效。")
                    chunk = recv_exact(connection, raw_size)
                    if hashlib.sha256(chunk).hexdigest() != metadata["chunk_hash"]:
                        raise TransferError("CHUNK_HASH_MISMATCH", "下载分块校验失败。")
                    output.write(chunk)
                    output.flush()
                    received += len(chunk)
                    send_json_message(
                        connection,
                        {
                            "type": "FILE_FETCH_ACK",
                            "chunk_index": chunk_index,
                            "bytes_received": received,
                        },
                    )
                    if progress_callback is not None:
                        progress_callback(received, actual_entry.file_size)

            end = recv_json_message(connection)
            _raise_remote_error(end)
            if (
                end.get("type") != "FILE_FETCH_END"
                or end.get("bytes_sent") != actual_entry.file_size
                or end.get("file_hash") != actual_entry.file_hash
            ):
                raise TransferError("INVALID_RESPONSE", "远端下载完成响应无效。")
    except TransferError as exc:
        if exc.code == "INVALID_OFFSET" and offset and _allow_restart:
            part_path.unlink(missing_ok=True)
            return fetch_sync_file(
                target_ip,
                target_port,
                remote_entry=remote_entry,
                remote_device_id=remote_device_id,
                shared_folder=root,
                file_index=file_index,
                expected_local_entry=expected_local_entry,
                credential=credential,
                tls_policy=tls_policy,
                timeout=timeout,
                progress_callback=progress_callback,
                _allow_restart=False,
            )
        raise
    except (ConnectionError, OSError, ValueError) as exc:
        raise TransferError("CONNECTION_ERROR", f"下载连接失败：{exc}") from exc

    if part_path.stat().st_size != remote_entry.file_size:
        raise TransferError("SIZE_MISMATCH", "下载文件大小与远端索引不一致。")
    if calculate_sha256(part_path) != remote_entry.file_hash:
        part_path.unlink(missing_ok=True)
        if _allow_restart:
            return fetch_sync_file(
                target_ip,
                target_port,
                remote_entry=remote_entry,
                remote_device_id=remote_device_id,
                shared_folder=root,
                file_index=file_index,
                expected_local_entry=expected_local_entry,
                credential=credential,
                tls_policy=tls_policy,
                timeout=timeout,
                progress_callback=progress_callback,
                _allow_restart=False,
            )
        raise TransferError("FILE_HASH_MISMATCH", "下载文件最终 SHA-256 校验失败。")

    current_local = file_index.refresh_path(remote_entry.relative_path)
    if entry_signature(current_local) != entry_signature(expected_local_entry):
        part_path.unlink(missing_ok=True)
        raise TransferError("PLAN_STALE", "本地文件在审批后发生变化，已停止覆盖。")

    destination = destination_for(root, remote_entry.relative_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.replace(part_path, destination)
        os.utime(
            destination,
            ns=(destination.stat().st_atime_ns, remote_entry.modified_time_ns),
        )
    except OSError as exc:
        raise TransferError("WRITE_FAILED", f"保存下载文件失败：{exc}") from exc

    recorded = file_index.record_received(remote_entry)
    file_index.record_sync(
        remote_device_id,
        recorded,
        remote_version=remote_entry.version,
    )
    return {
        "type": "FILE_FETCHED",
        "status": "success",
        "relative_path": remote_entry.relative_path,
        "bytes_received": remote_entry.file_size,
        "file_hash": remote_entry.file_hash,
    }
