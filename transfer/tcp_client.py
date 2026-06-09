from __future__ import annotations

import hashlib
import socket
from pathlib import Path
from typing import Any, Callable

from security import (
    AuthCredential,
    TLSIdentityError,
    TLSPolicy,
    open_connection,
)

from .hash_utils import calculate_sha256
from .protocol import (
    HASH_ALGORITHM,
    PROTOCOL_VERSION,
    TransferError,
    is_sha256,
    recv_json_message,
    send_json_message,
    validate_chunk_size,
)


ProgressCallback = Callable[[int, int], None]
TERMINAL_SYNC_RESPONSES = {"FILE_UP_TO_DATE", "FILE_SKIPPED"}


def _file_signature(path: Path) -> tuple[int, int, int, int]:
    stat = path.stat()
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns


def _raise_for_error(response: dict[str, Any]) -> None:
    if response.get("type") == "TRANSFER_ERROR":
        raise TransferError.from_payload(response)


def _recv_response(sock: socket.socket) -> dict[str, Any]:
    try:
        response = recv_json_message(sock)
    except (UnicodeDecodeError, ValueError) as exc:
        raise TransferError(
            "INVALID_RESPONSE",
            f"接收端返回了无效的协议消息：{exc}",
        ) from exc
    _raise_for_error(response)
    return response


def _missing_chunks_from_response(
    response: dict[str, Any],
    total_chunks: int,
) -> list[int]:
    response_type = response.get("type")
    if response_type == "FILE_READY" and "missing_chunks" not in response:
        return list(range(total_chunks))
    if response_type not in {"FILE_READY", "RESUME_REQUEST"}:
        raise TransferError(
            "INVALID_RESPONSE",
            "接收端未返回有效的缺失块请求。",
        )

    raw_missing = response.get("missing_chunks")
    if not isinstance(raw_missing, list):
        raise TransferError("INVALID_RESPONSE", "接收端缺少 missing_chunks 列表。")
    if any(type(index) is not int for index in raw_missing):
        raise TransferError("INVALID_RESPONSE", "接收端返回了无效的分块编号。")

    missing_chunks = list(raw_missing)
    if missing_chunks != sorted(set(missing_chunks)):
        raise TransferError("INVALID_RESPONSE", "接收端返回的缺失块列表无序或重复。")
    if any(index < 0 or index >= total_chunks for index in missing_chunks):
        raise TransferError("INVALID_RESPONSE", "接收端请求了超出范围的分块。")
    return missing_chunks


def _prepare_metadata(
    path: Path,
    chunk_size: int,
    extra_metadata: dict[str, Any] | None = None,
    expected_hash: str | None = None,
    credential: AuthCredential | None = None,
) -> tuple[dict[str, Any], tuple[int, int, int, int]]:
    if not path.is_file():
        raise FileNotFoundError(f"file not found: {path}")

    chunk_size = validate_chunk_size(chunk_size)
    try:
        signature_before_hash = _file_signature(path)
        file_hash = calculate_sha256(path)
        signature_after_hash = _file_signature(path)
    except OSError as exc:
        raise TransferError("FILE_READ_ERROR", f"无法读取文件：{exc}") from exc

    if signature_before_hash != signature_after_hash:
        raise TransferError("FILE_CHANGED", "文件在计算哈希时发生了变化，请重新发送。")
    if expected_hash is not None and file_hash != expected_hash:
        raise TransferError("FILE_CHANGED", "文件内容与本地索引不一致，请等待重新扫描。")

    file_size = signature_after_hash[2]
    metadata: dict[str, Any] = {
        "type": "FILE_SEND",
        "protocol_version": PROTOCOL_VERSION,
        "transfer_mode": "manual",
        "file_name": path.name,
        "file_size": file_size,
        "file_hash": file_hash,
        "hash_algorithm": HASH_ALGORITHM,
        "chunk_size": chunk_size,
        "total_chunks": (file_size + chunk_size - 1) // chunk_size,
    }
    if extra_metadata:
        metadata.update(extra_metadata)
    if credential is not None:
        metadata.update(credential.to_payload())
    return metadata, signature_after_hash


def _send_prepared_file(
    target_ip: str,
    target_port: int,
    path: Path,
    metadata: dict[str, Any],
    signature: tuple[int, int, int, int],
    timeout: float,
    progress_callback: ProgressCallback | None,
    tls_policy: TLSPolicy | None,
) -> dict[str, Any]:
    file_size = metadata["file_size"]
    file_hash = metadata["file_hash"]
    chunk_size = metadata["chunk_size"]
    total_chunks = metadata["total_chunks"]

    try:
        with open_connection(
            target_ip,
            target_port,
            timeout,
            tls_policy,
        ) as sock:
            sock.settimeout(timeout)
            send_json_message(sock, metadata)

            sock.settimeout(min(timeout, 5.0))
            try:
                ready = _recv_response(sock)
            except TimeoutError as exc:
                raise TransferError(
                    "PROTOCOL_INCOMPATIBLE",
                    "接收端未返回阶段六握手响应，可能仍在运行旧版本。",
                ) from exc
            finally:
                sock.settimeout(timeout)

            if ready.get("protocol_version") != PROTOCOL_VERSION:
                raise TransferError(
                    "PROTOCOL_INCOMPATIBLE",
                    "接收端协议版本不兼容，请将两端都升级到阶段六。",
                )
            if ready.get("type") in TERMINAL_SYNC_RESPONSES:
                if ready.get("status") != "success":
                    raise TransferError("INVALID_RESPONSE", "接收端返回了无效的同步结果。")
                return ready

            missing_chunks = _missing_chunks_from_response(ready, total_chunks)
            missing_chunk_set = set(missing_chunks)
            resumed_bytes = file_size - sum(
                min(chunk_size, file_size - index * chunk_size)
                for index in missing_chunks
            )
            sent_hash = hashlib.sha256()
            bytes_received = resumed_bytes
            if progress_callback is not None and (resumed_bytes > 0 or file_size == 0):
                progress_callback(resumed_bytes, file_size)

            try:
                with path.open("rb") as source:
                    if _file_signature(path) != signature:
                        raise TransferError(
                            "FILE_CHANGED",
                            "文件在发送前发生了变化，请重新发送。",
                        )

                    for chunk_index in range(total_chunks):
                        expected_size = min(
                            chunk_size,
                            file_size - chunk_index * chunk_size,
                        )
                        chunk = source.read(expected_size)
                        if len(chunk) != expected_size:
                            raise TransferError(
                                "FILE_CHANGED",
                                "文件在发送过程中被截断，请重新发送。",
                                chunk_index,
                            )

                        sent_hash.update(chunk)
                        if chunk_index not in missing_chunk_set:
                            continue

                        send_json_message(
                            sock,
                            {
                                "type": "CHUNK",
                                "chunk_index": chunk_index,
                                "chunk_size": len(chunk),
                                "chunk_hash": hashlib.sha256(chunk).hexdigest(),
                            },
                        )
                        sock.sendall(chunk)

                        acknowledgement = _recv_response(sock)
                        if (
                            acknowledgement.get("type") != "CHUNK_ACK"
                            or acknowledgement.get("chunk_index") != chunk_index
                            or acknowledgement.get("bytes_received")
                            != bytes_received + len(chunk)
                        ):
                            raise TransferError(
                                "INVALID_RESPONSE",
                                f"接收端未正确确认第 {chunk_index} 块。",
                                chunk_index,
                            )

                        bytes_received += len(chunk)
                        if progress_callback is not None:
                            progress_callback(bytes_received, file_size)

                    if source.read(1):
                        raise TransferError(
                            "FILE_CHANGED",
                            "文件在发送过程中变大，请重新发送。",
                        )
            except OSError as exc:
                raise TransferError("FILE_READ_ERROR", f"读取文件失败：{exc}") from exc

            if sent_hash.hexdigest() != file_hash:
                raise TransferError(
                    "FILE_CHANGED",
                    "文件在发送过程中发生了变化，请重新发送。",
                )

            result = _recv_response(sock)
            if result.get("type") in TERMINAL_SYNC_RESPONSES:
                return result
            if result.get("type") != "FILE_RECEIVED" or result.get("status") != "success":
                raise TransferError("INVALID_RESPONSE", "接收端未返回有效的完成确认。")
            if (
                result.get("bytes_received") != file_size
                or result.get("chunks_received") != total_chunks
            ):
                raise TransferError(
                    "INVALID_RESPONSE",
                    "接收端返回的文件大小或分块数量不正确。",
                )
            if result.get("chunks_transferred") not in {None, len(missing_chunks)}:
                raise TransferError(
                    "INVALID_RESPONSE",
                    "接收端返回的本次传输分块数量不正确。",
                )

            received_hash = str(result.get("file_hash", "")).lower()
            if not is_sha256(received_hash) or received_hash != file_hash:
                raise TransferError(
                    "RECEIVER_HASH_MISMATCH",
                    "接收端返回的文件哈希与发送端不一致。",
                )
            return result
    except TransferError:
        raise
    except TLSIdentityError as exc:
        raise TransferError("TLS_IDENTITY_FAILED", str(exc)) from exc
    except TimeoutError as exc:
        raise TransferError("TIMEOUT", "连接或传输超时，请检查网络后重试。") from exc
    except ConnectionRefusedError as exc:
        raise TransferError(
            "CONNECTION_REFUSED",
            "目标设备拒绝连接，请确认接收端程序和 TCP 端口可用。",
        ) from exc
    except (ConnectionError, OSError) as exc:
        raise TransferError("CONNECTION_ERROR", f"网络连接失败：{exc}") from exc


def send_file(
    target_ip: str,
    target_port: int,
    file_path: str | Path,
    chunk_size: int = 1024 * 1024,
    timeout: float = 60.0,
    progress_callback: ProgressCallback | None = None,
    credential: AuthCredential | None = None,
    tls_policy: TLSPolicy | None = None,
) -> dict[str, Any]:
    path = Path(file_path)
    metadata, signature = _prepare_metadata(
        path,
        chunk_size,
        credential=credential,
    )
    return _send_prepared_file(
        target_ip,
        target_port,
        path,
        metadata,
        signature,
        timeout,
        progress_callback,
        tls_policy,
    )


def send_sync_file(
    target_ip: str,
    target_port: int,
    file_path: str | Path,
    *,
    relative_path: str,
    modified_time_ns: int,
    version: int,
    source_device_id: str,
    source_device_name: str = "",
    file_hash: str,
    changed_at_ns: int,
    baseline_hash: str | None = None,
    baseline_status: str | None = None,
    credential: AuthCredential | None = None,
    chunk_size: int = 1024 * 1024,
    timeout: float = 60.0,
    tls_policy: TLSPolicy | None = None,
    progress_callback: ProgressCallback | None = None,
) -> dict[str, Any]:
    path = Path(file_path)
    metadata, signature = _prepare_metadata(
        path,
        chunk_size,
        {
            "transfer_mode": "sync",
            "relative_path": relative_path,
            "modified_time_ns": modified_time_ns,
            "version": version,
            "source_device_id": source_device_id,
            "source_device_name": source_device_name,
            "changed_at_ns": changed_at_ns,
            "baseline_hash": baseline_hash,
            "baseline_status": baseline_status,
        },
        expected_hash=file_hash,
        credential=credential,
    )
    return _send_prepared_file(
        target_ip,
        target_port,
        path,
        metadata,
        signature,
        timeout,
        progress_callback,
        tls_policy,
    )
