from __future__ import annotations

import hashlib
import logging
import os
import shutil
import socket
import ssl
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from security import (
    PERMISSION_READ,
    PERMISSION_WRITE,
    PERMISSION_BLOCKED,
    AuthorizationError,
    SecurityStore,
    TLSIdentity,
    normalize_fingerprint,
)
from sync.conflict import conflict_copy_relative_path, decide_conflict
from sync.file_index import FileEntry, FileIndex, STATUS_ACTIVE, should_send_entry
from sync.paths import destination_for, normalize_relative_path

from .hash_utils import calculate_sha256
from .protocol import (
    HASH_ALGORITHM,
    PROTOCOL_VERSION,
    TransferError,
    is_sha256,
    recv_exact,
    recv_json_message,
    send_json_message,
    validate_chunk_size,
)
from .resume_state import ResumeState, transfer_id_for


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ReceivedFile:
    path: Path
    bytes_received: int
    peer: tuple[str, int]
    file_hash: str
    chunks_received: int
    resumed_chunks: int
    chunks_transferred: int
    relative_path: str | None = None
    conflict: bool = False
    conflict_copy_path: str | None = None
    winner_device_id: str | None = None


def safe_file_name(file_name: str) -> str:
    normalized = str(file_name).replace("\\", "/")
    name = Path(normalized).name.replace("\x00", "").strip()
    if name in {"", ".", ".."}:
        return "received_file"
    return name


def next_available_path(folder: Path, file_name: str) -> Path:
    target = folder / safe_file_name(file_name)
    if not target.exists():
        return target

    stem = target.stem
    suffix = target.suffix
    counter = 1
    while True:
        candidate = target.with_name(f"{stem}_{counter}{suffix}")
        if not candidate.exists():
            return candidate
        counter += 1


class TCPFileServer:
    def __init__(
        self,
        host: str,
        port: int,
        shared_folder: str | Path,
        chunk_size: int = 1024 * 1024,
        file_index: FileIndex | None = None,
        security_store: SecurityStore | None = None,
        device_id: str = "",
        device_name: str = "",
        tls_identity: TLSIdentity | None = None,
        audit_store: Any | None = None,
        event_callback=None,
    ) -> None:
        self.host = host
        self.port = port
        self.shared_folder = Path(shared_folder)
        self.chunk_size = chunk_size
        self.file_index = file_index
        self.security_store = security_store
        self.device_id = str(device_id)
        self.device_name = str(device_name)
        self.tls_identity = tls_identity
        self.audit_store = audit_store
        self.event_callback = event_callback
        self._tls_context = (
            tls_identity.server_context() if tls_identity is not None else None
        )
        self._stop_event = threading.Event()
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._client_threads: list[threading.Thread] = []
        self._clients_lock = threading.Lock()
        self._client_sockets: set[socket.socket] = set()
        self._destination_lock = threading.Lock()
        self._transfer_locks_guard = threading.Lock()
        self._transfer_locks: dict[str, threading.Lock] = {}

    @property
    def bound_port(self) -> int:
        if self._socket is None:
            return self.port
        return int(self._socket.getsockname()[1])

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        self.shared_folder.mkdir(parents=True, exist_ok=True)
        self._stop_event.clear()

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen()
        server_socket.settimeout(1.0)
        self._socket = server_socket

        self._thread = threading.Thread(target=self._serve_forever, daemon=True)
        self._thread.start()
        logger.info("TCP server listening on %s:%s", self.host, self.bound_port)

    def stop(self) -> None:
        self._stop_event.set()
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
        with self._clients_lock:
            client_sockets = list(self._client_sockets)
        for client_socket in client_sockets:
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                client_socket.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        for thread in list(self._client_threads):
            thread.join(timeout=2.0)

    def _serve_forever(self) -> None:
        assert self._socket is not None
        while not self._stop_event.is_set():
            try:
                conn, addr = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            thread = threading.Thread(
                target=self._handle_client,
                args=(conn, addr),
                daemon=True,
            )
            with self._clients_lock:
                self._client_sockets.add(conn)
            self._client_threads.append(thread)
            thread.start()

    def _handle_client(self, conn: socket.socket, addr: tuple[str, int]) -> None:
        transport: socket.socket = conn
        self._audit(
            "connection_opened",
            source_ip=addr[0],
            details={"source_port": addr[1], "tls": self._tls_context is not None},
        )
        try:
            if self._tls_context is not None:
                try:
                    conn.settimeout(15.0)
                    transport = self._tls_context.wrap_socket(
                        conn,
                        server_side=True,
                    )
                    with self._clients_lock:
                        self._client_sockets.discard(conn)
                        self._client_sockets.add(transport)
                    self._audit(
                        "tls_handshake",
                        source_ip=addr[0],
                        details={
                            "protocol": getattr(transport, "version", lambda: "")(),
                            "encrypted": True,
                        },
                    )
                except (ssl.SSLError, OSError) as exc:
                    self._audit(
                        "tls_handshake_failed",
                        severity="warning",
                        source_ip=addr[0],
                        outcome="rejected",
                        details={"error": str(exc)},
                    )
                    try:
                        conn.close()
                    except OSError:
                        pass
                    return
            with transport:
                transport.settimeout(60.0)
                try:
                    request = self._receive_request(transport)
                    if request.get("type") == "DIAGNOSTIC_PING":
                        self._handle_diagnostic_ping(transport, request, addr)
                    elif request.get("type") == "PAIR_REQUEST":
                        self._handle_pair_request(transport, request, addr)
                    elif request.get("type") == "INDEX_REQUEST":
                        self._handle_index_request(transport, request, addr)
                    else:
                        outcome = self._receive_file_request(transport, addr, request)
                        if isinstance(outcome, dict):
                            send_json_message(transport, outcome)
                        else:
                            payload = {
                                "type": "FILE_RECEIVED",
                                "status": "success",
                                "protocol_version": PROTOCOL_VERSION,
                                "file_name": outcome.path.name,
                                "bytes_received": outcome.bytes_received,
                                "file_hash": outcome.file_hash,
                                "chunks_received": outcome.chunks_received,
                                "resumed_chunks": outcome.resumed_chunks,
                                "chunks_transferred": outcome.chunks_transferred,
                            }
                            if outcome.relative_path is not None:
                                payload["relative_path"] = outcome.relative_path
                            if outcome.conflict:
                                payload.update(
                                    {
                                        "conflict": True,
                                        "conflict_copy_path": outcome.conflict_copy_path,
                                        "winner_device_id": outcome.winner_device_id,
                                    }
                                )
                            send_json_message(transport, payload)
                            logger.info("received %s from %s:%s", outcome.path, *addr)
                            self._audit(
                                "file_received",
                                source_ip=addr[0],
                                device_id=str(
                                    request.get("auth_device_id", "")
                                ),
                                request_type=str(
                                    request.get("transfer_mode", "manual")
                                ),
                                bytes_count=outcome.bytes_received,
                                details={
                                    "relative_path": outcome.relative_path,
                                    "resumed_chunks": outcome.resumed_chunks,
                                    "conflict": outcome.conflict,
                                },
                            )
                            self._notify(
                                "transfer_completed",
                                {
                                    "kind": "receive",
                                    "source_ip": addr[0],
                                    "device_id": str(
                                        request.get("auth_device_id", "")
                                    ),
                                    "file_name": outcome.path.name,
                                    "relative_path": outcome.relative_path,
                                    "total_bytes": outcome.bytes_received,
                                    "conflict": outcome.conflict,
                                },
                            )
                            if outcome.resumed_chunks:
                                self._audit(
                                    "transfer_resumed",
                                    source_ip=addr[0],
                                    device_id=str(
                                        request.get("auth_device_id", "")
                                    ),
                                    details={
                                        "resumed_chunks": outcome.resumed_chunks,
                                        "transferred_chunks": outcome.chunks_transferred,
                                    },
                                )
                            if outcome.conflict:
                                self._audit(
                                    "conflict_detected",
                                    severity="warning",
                                    source_ip=addr[0],
                                    device_id=str(
                                        request.get("auth_device_id", "")
                                    ),
                                    details={
                                        "relative_path": outcome.relative_path,
                                        "conflict_copy_path": outcome.conflict_copy_path,
                                        "winner_device_id": outcome.winner_device_id,
                                    },
                                )
                except TransferError as exc:
                    logger.warning(
                        "rejected transfer from %s:%s [%s]: %s",
                        *addr,
                        exc.code,
                        exc.message,
                    )
                    self._audit_rejection(addr, request if "request" in locals() else {}, exc)
                    self._notify_receive_failure(
                        request if "request" in locals() else {},
                        addr,
                        exc.message,
                        exc.code,
                    )
                    self._send_error(transport, exc)
                except socket.timeout:
                    logger.exception("timed out while receiving from %s:%s", *addr)
                    self._audit(
                        "connection_timeout",
                        severity="warning",
                        source_ip=addr[0],
                        outcome="failed",
                    )
                    self._notify_receive_failure(
                        request if "request" in locals() else {},
                        addr,
                        "接收文件超时，传输已取消。",
                    )
                    self._send_error(
                        transport,
                        TransferError("TIMEOUT", "接收文件超时，传输已取消。"),
                    )
                except (ConnectionError, OSError) as exc:
                    logger.warning(
                        "connection closed while receiving from %s:%s: %s",
                        *addr,
                        exc,
                    )
                    self._audit(
                        "connection_failed",
                        severity="warning",
                        source_ip=addr[0],
                        outcome="failed",
                        details={"error": str(exc)},
                    )
                    self._notify_receive_failure(
                        request if "request" in locals() else {},
                        addr,
                        f"连接中断：{exc}",
                    )
                    self._send_error(
                        transport,
                        TransferError("CONNECTION_ERROR", f"连接中断：{exc}"),
                    )
                except Exception as exc:
                    logger.exception("unexpected receive failure from %s:%s", *addr)
                    self._audit(
                        "internal_error",
                        severity="error",
                        source_ip=addr[0],
                        outcome="failed",
                        details={"error_type": type(exc).__name__},
                    )
                    self._notify_receive_failure(
                        request if "request" in locals() else {},
                        addr,
                        f"接收端内部错误：{exc}",
                    )
                    self._send_error(
                        transport,
                        TransferError("INTERNAL_ERROR", f"接收端内部错误：{exc}"),
                    )
        finally:
            with self._clients_lock:
                self._client_sockets.discard(conn)
                self._client_sockets.discard(transport)

    @staticmethod
    def _send_error(conn: socket.socket, error: TransferError) -> None:
        try:
            send_json_message(conn, error.to_payload())
        except (ConnectionError, OSError, ValueError):
            pass

    @staticmethod
    def _receive_request(conn: socket.socket) -> dict[str, Any]:
        try:
            return recv_json_message(conn)
        except (UnicodeDecodeError, ValueError) as exc:
            raise TransferError("INVALID_METADATA", f"文件元信息无效：{exc}") from exc

    def _handle_index_request(
        self,
        conn: socket.socket,
        request: dict[str, Any],
        addr: tuple[str, int] = ("", 0),
    ) -> None:
        if request.get("protocol_version") != PROTOCOL_VERSION:
            raise TransferError(
                "PROTOCOL_INCOMPATIBLE",
                "协议版本不兼容，请将两端都升级到阶段六。",
            )
        if self.file_index is None:
            raise TransferError("SYNC_DISABLED", "接收端未启用文件夹同步。")

        requester = self._authenticate_request(
            request,
            PERMISSION_READ,
            source_ip=addr[0],
        )
        requester_device_id = (
            requester.device_id
            if requester is not None
            else str(request.get("auth_device_id", ""))
        )
        entries = self.file_index.snapshot()
        send_json_message(
            conn,
            {
                "type": "INDEX_BEGIN",
                "protocol_version": PROTOCOL_VERSION,
                "entry_count": len(entries),
            },
        )
        for entry in entries:
            if requester_device_id:
                entry = self.file_index.entry_for_peer(
                    entry,
                    requester_device_id,
                )
            send_json_message(
                conn,
                {
                    "type": "INDEX_ENTRY",
                    "entry": entry.to_payload(),
                },
            )
        send_json_message(
            conn,
            {
                "type": "INDEX_END",
                "protocol_version": PROTOCOL_VERSION,
            },
        )
        self._audit(
            "index_read",
            source_ip=addr[0],
            device_id=requester_device_id,
            request_type="INDEX_REQUEST",
            details={"entry_count": len(entries)},
        )

    def _handle_diagnostic_ping(
        self,
        conn: socket.socket,
        request: dict[str, Any],
        addr: tuple[str, int],
    ) -> None:
        if request.get("protocol_version") != PROTOCOL_VERSION:
            raise TransferError(
                "PROTOCOL_INCOMPATIBLE",
                "协议版本不兼容，请将两端都升级到阶段六。",
            )
        send_json_message(
            conn,
            {
                "type": "DIAGNOSTIC_PONG",
                "protocol_version": PROTOCOL_VERSION,
                "tls_enabled": self._tls_context is not None,
            },
        )
        self._audit(
            "diagnostic_probe",
            source_ip=addr[0],
            request_type="DIAGNOSTIC_PING",
        )

    def _handle_pair_request(
        self,
        conn: socket.socket,
        request: dict[str, Any],
        addr: tuple[str, int] = ("", 0),
    ) -> None:
        if request.get("protocol_version") != PROTOCOL_VERSION:
            raise TransferError(
                "PROTOCOL_INCOMPATIBLE",
                "协议版本不兼容，请将两端都升级到阶段六。",
            )
        if self.security_store is None:
            raise TransferError("AUTH_DISABLED", "接收端未启用设备配对。")

        device_id = request.get("device_id")
        device_name = request.get("device_name")
        pair_code = request.get("pair_code")
        token = request.get("access_token")
        certificate_fingerprint = request.get("certificate_fingerprint")
        if not isinstance(device_id, str) or not device_id:
            raise TransferError("INVALID_METADATA", "配对设备 ID 无效。")
        if not isinstance(device_name, str) or not device_name.strip():
            raise TransferError("INVALID_METADATA", "配对设备名称无效。")
        if not isinstance(token, str) or len(token) < 32:
            raise TransferError("INVALID_METADATA", "配对访问令牌无效。")
        if not self.security_store.verify_pair_code(str(pair_code)):
            raise TransferError("AUTH_FAILED", "配对码错误。")
        try:
            normalized_fingerprint = normalize_fingerprint(
                certificate_fingerprint
            )
        except ValueError as exc:
            raise TransferError(
                "INVALID_METADATA",
                f"配对证书指纹无效：{exc}",
            ) from exc
        if self._tls_context is not None and normalized_fingerprint is None:
            raise TransferError(
                "TLS_IDENTITY_REQUIRED",
                "启用 TLS 时配对设备必须提供证书指纹。",
            )
        existing = self.security_store.get_device(device_id)
        if existing is not None and existing.permission == PERMISSION_BLOCKED:
            raise TransferError("AUTH_BLOCKED", "设备已被阻止，不能重新配对。")

        self.security_store.authorize_device(
            device_id,
            device_name,
            token,
            PERMISSION_WRITE,
            certificate_fingerprint=normalized_fingerprint,
        )
        send_json_message(
            conn,
            {
                "type": "PAIR_ACCEPTED",
                "status": "success",
                "protocol_version": PROTOCOL_VERSION,
                "device_id": self.device_id,
                "device_name": self.device_name,
                "permission": PERMISSION_WRITE,
                "certificate_fingerprint": (
                    self.tls_identity.fingerprint
                    if self.tls_identity is not None
                    else None
                ),
            },
        )
        self._audit(
            "pairing_succeeded",
            source_ip=addr[0],
            device_id=device_id,
            request_type="PAIR_REQUEST",
            details={"tls": self._tls_context is not None},
        )

    def _authenticate_request(
        self,
        request: dict[str, Any],
        required_permission: str,
        source_ip: str = "",
    ):
        if self.security_store is None:
            return None
        try:
            return self.security_store.authenticate(
                str(request.get("auth_device_id", "")),
                str(request.get("auth_token", "")),
                required_permission,
            )
        except AuthorizationError as exc:
            event_type = (
                "blocked_device_access"
                if exc.code == "AUTH_BLOCKED"
                else "authentication_failed"
            )
            self._audit(
                event_type,
                severity="warning",
                source_ip=source_ip,
                device_id=str(request.get("auth_device_id", "")),
                request_type=str(request.get("type", "")),
                outcome="rejected",
                details={"error_code": exc.code},
            )
            raise TransferError(exc.code, exc.message) from exc

    def receive_file(
        self,
        conn: socket.socket,
        addr: tuple[str, int],
    ) -> ReceivedFile | dict[str, Any]:
        metadata = self._receive_request(conn)
        return self._receive_file_request(conn, addr, metadata)

    def _receive_file_request(
        self,
        conn: socket.socket,
        addr: tuple[str, int],
        metadata: dict[str, Any],
    ) -> ReceivedFile | dict[str, Any]:
        validated = self._validate_metadata(metadata)
        authenticated = self._authenticate_request(
            metadata,
            PERMISSION_WRITE,
            source_ip=addr[0],
        )
        if authenticated is not None:
            validated["authenticated_device_id"] = authenticated.device_id
            validated["authenticated_device_name"] = authenticated.device_name
        with self._transfer_lock(validated):
            sync_result = self._check_sync_preflight(validated)
            if sync_result is not None:
                return sync_result
            return self._receive_validated_file(conn, addr, validated)

    def _check_sync_preflight(
        self,
        validated: dict[str, Any],
    ) -> dict[str, Any] | None:
        if validated["transfer_mode"] != "sync":
            return None
        if self.file_index is None:
            raise TransferError("SYNC_DISABLED", "接收端未启用文件夹同步。")

        incoming = self._entry_from_metadata(validated)
        remote_device_id = validated.get(
            "authenticated_device_id",
            incoming.source_device_id,
        )
        try:
            local = self.file_index.refresh_path(incoming.relative_path)
        except ValueError as exc:
            raise TransferError("INVALID_PATH", f"同步相对路径无效：{exc}") from exc
        if (
            local is not None
            and local.status == STATUS_ACTIVE
            and local.file_hash == incoming.file_hash
        ):
            self.file_index.record_sync(
                remote_device_id,
                local,
                remote_version=incoming.version,
            )
            return {
                "type": "FILE_UP_TO_DATE",
                "status": "success",
                "protocol_version": PROTOCOL_VERSION,
                "relative_path": incoming.relative_path,
                "file_hash": incoming.file_hash,
            }

        local_state = self.file_index.get_sync_state(
            remote_device_id,
            incoming.relative_path,
        )
        decision = decide_conflict(
            local,
            incoming,
            local_state,
            validated.get("baseline_hash"),
            validated.get("baseline_status"),
        )
        if decision.conflict:
            assert decision.winner is not None
            if decision.winner.file_hash != incoming.file_hash:
                return {
                    "type": "FILE_SKIPPED",
                    "status": "success",
                    "protocol_version": PROTOCOL_VERSION,
                    "relative_path": incoming.relative_path,
                    "conflict": True,
                    "winner_device_id": decision.winner.source_device_id,
                    "message": "检测到双端修改，接收端版本为主版本。",
                }
            validated["conflict"] = True
            validated["conflict_local_entry"] = local
            validated["winner_device_id"] = incoming.source_device_id
            validated["conflict_reason_code"] = decision.reason_code
            return None

        if decision.remote_changed and not decision.local_changed:
            return None
        if decision.local_changed and not decision.remote_changed:
            return {
                "type": "FILE_SKIPPED",
                "status": "success",
                "protocol_version": PROTOCOL_VERSION,
                "relative_path": incoming.relative_path,
                "message": "接收端已有相同或更新的版本。",
            }
        if not should_send_entry(incoming, local):
            return {
                "type": "FILE_SKIPPED",
                "status": "success",
                "protocol_version": PROTOCOL_VERSION,
                "relative_path": incoming.relative_path,
                "message": "接收端已有相同或更新的版本。",
            }
        return None

    def _receive_validated_file(
        self,
        conn: socket.socket,
        addr: tuple[str, int],
        validated: dict[str, Any],
    ) -> ReceivedFile:
        file_name = validated["file_name"]
        file_size = validated["file_size"]
        file_hash = validated["file_hash"]
        recv_chunk_size = validated["chunk_size"]
        total_chunks = validated["total_chunks"]
        transfer_mode = validated["transfer_mode"]

        try:
            resume_state = ResumeState.open(
                self.shared_folder,
                validated,
                PROTOCOL_VERSION,
            )
        except OSError as exc:
            raise TransferError("WRITE_FAILED", f"无法准备续传状态：{exc}") from exc

        initial_received_chunks = len(resume_state.received_chunks)
        missing_chunks = resume_state.missing_chunks
        self._notify(
            "transfer_queued",
            {
                "kind": "receive",
                "source_ip": addr[0],
                "device_id": str(
                    validated.get("authenticated_device_id", "")
                ),
                "file_name": file_name,
                "relative_path": validated.get("relative_path"),
                "total_bytes": file_size,
            },
        )
        try:
            send_json_message(
                conn,
                {
                    "type": "RESUME_REQUEST",
                    "status": "ready",
                    "protocol_version": PROTOCOL_VERSION,
                    "file_name": file_name,
                    "total_chunks": total_chunks,
                    "received_chunks": sorted(resume_state.received_chunks),
                    "missing_chunks": missing_chunks,
                    "bytes_received": resume_state.bytes_received,
                },
            )

            try:
                with resume_state.part_path.open("r+b") as output:
                    for expected_index in missing_chunks:
                        chunk_metadata = self._receive_chunk_metadata(
                            conn,
                            expected_index,
                            recv_chunk_size,
                            resume_state.chunk_size_at(expected_index),
                        )
                        chunk_size = chunk_metadata["chunk_size"]
                        try:
                            chunk = recv_exact(conn, chunk_size)
                        except (ConnectionError, OSError) as exc:
                            raise TransferError(
                                "TRANSFER_INCOMPLETE",
                                f"第 {expected_index} 块未接收完整。",
                                expected_index,
                            ) from exc

                        actual_chunk_hash = hashlib.sha256(chunk).hexdigest()
                        if actual_chunk_hash != chunk_metadata["chunk_hash"]:
                            raise TransferError(
                                "CHUNK_HASH_MISMATCH",
                                f"第 {expected_index} 块哈希校验失败。",
                                expected_index,
                            )

                        try:
                            output.seek(expected_index * recv_chunk_size)
                            output.write(chunk)
                            output.flush()
                            os.fsync(output.fileno())
                            resume_state.record_chunk(expected_index)
                        except OSError as exc:
                            raise TransferError(
                                "WRITE_FAILED",
                                f"写入第 {expected_index} 块失败：{exc}",
                                expected_index,
                            ) from exc

                        send_json_message(
                            conn,
                            {
                                "type": "CHUNK_ACK",
                                "status": "success",
                                "chunk_index": expected_index,
                                "bytes_received": resume_state.bytes_received,
                            },
                        )
                        self._notify(
                            "transfer_progress",
                            {
                                "kind": "receive",
                                "source_ip": addr[0],
                                "device_id": str(
                                    validated.get(
                                        "authenticated_device_id",
                                        "",
                                    )
                                ),
                                "file_name": file_name,
                                "relative_path": validated.get("relative_path"),
                                "transferred_bytes": resume_state.bytes_received,
                                "total_bytes": file_size,
                            },
                        )
            except TransferError:
                raise
            except OSError as exc:
                raise TransferError("WRITE_FAILED", f"写入接收文件失败：{exc}") from exc

            if resume_state.missing_chunks or resume_state.bytes_received != file_size:
                raise TransferError(
                    "SIZE_MISMATCH",
                    "接收状态不完整，仍有文件块缺失。",
                )

            try:
                actual_file_hash = calculate_sha256(resume_state.part_path)
            except OSError as exc:
                raise TransferError(
                    "WRITE_FAILED",
                    f"无法读取临时文件进行最终校验：{exc}",
                ) from exc
            if actual_file_hash != file_hash:
                resume_state.discard()
                raise TransferError(
                    "FILE_HASH_MISMATCH",
                    "接收端文件 SHA-256 与发送端不一致，文件已丢弃。",
                )

            conflict_copy_path: str | None = None
            moved_local_to_conflict = False
            with self._destination_lock:
                if transfer_mode == "sync":
                    try:
                        destination = destination_for(
                            self.shared_folder,
                            validated["relative_path"],
                        )
                    except ValueError as exc:
                        raise TransferError(
                            "INVALID_PATH",
                            f"同步相对路径无效：{exc}",
                        ) from exc
                    destination.parent.mkdir(parents=True, exist_ok=True)
                else:
                    destination = next_available_path(self.shared_folder, file_name)

                if transfer_mode == "sync" and validated.get("conflict"):
                    local_entry = self.file_index.refresh_path(
                        validated["relative_path"]
                    )
                    if (
                        local_entry is not None
                        and local_entry.status == STATUS_ACTIVE
                        and local_entry.file_hash != file_hash
                        and destination.is_file()
                    ):
                        conflict_copy_path = self._preserve_conflict_copy(
                            destination,
                            local_entry,
                        )
                        validated["conflict_local_entry"] = local_entry
                        moved_local_to_conflict = (
                            destination_for(
                                self.shared_folder,
                                conflict_copy_path,
                            ).exists()
                            and not destination.exists()
                        )
                try:
                    resume_state.part_path.replace(destination)
                    if transfer_mode == "sync":
                        os.utime(
                            destination,
                            ns=(
                                destination.stat().st_atime_ns,
                                validated["modified_time_ns"],
                            ),
                        )
                except OSError as exc:
                    if conflict_copy_path is not None:
                        conflict_path = destination_for(
                            self.shared_folder,
                            conflict_copy_path,
                        )
                        try:
                            if destination.exists():
                                destination.unlink()
                            if moved_local_to_conflict:
                                conflict_path.replace(destination)
                            else:
                                shutil.copy2(conflict_path, destination)
                        except OSError:
                            logger.exception(
                                "failed to restore local file after conflict save failure"
                            )
                    raise TransferError(
                        "WRITE_FAILED",
                        f"保存最终文件失败：{exc}",
                    ) from exc

            resume_state.remove_state_file()
            relative_path = (
                validated["relative_path"] if transfer_mode == "sync" else None
            )
            if transfer_mode == "sync":
                assert self.file_index is not None
                incoming_entry = self._entry_from_metadata(validated)
                recorded = self.file_index.record_received(incoming_entry)
                remote_device_id = validated.get(
                    "authenticated_device_id",
                    incoming_entry.source_device_id,
                )
                self.file_index.record_sync(
                    remote_device_id,
                    recorded,
                    remote_version=incoming_entry.version,
                )
                if conflict_copy_path is not None:
                    conflict_entry = self.file_index.refresh_path(conflict_copy_path)
                    if conflict_entry is None:
                        logger.warning(
                            "conflict copy was saved but not indexed: %s",
                            conflict_copy_path,
                        )
                local_entry = validated.get("conflict_local_entry")
                if validated.get("conflict") and local_entry is not None:
                    self.file_index.record_conflict(
                        relative_path=validated["relative_path"],
                        local_entry=local_entry,
                        remote_entry=incoming_entry,
                        remote_device_id=remote_device_id,
                        winner_device_id=validated.get(
                            "winner_device_id",
                            incoming_entry.source_device_id,
                        ),
                        conflict_copy_path=conflict_copy_path or "",
                        reason_code=validated.get(
                            "conflict_reason_code",
                            "BOTH_MODIFIED",
                        ),
                    )
            return ReceivedFile(
                path=destination,
                bytes_received=file_size,
                peer=addr,
                file_hash=actual_file_hash,
                chunks_received=total_chunks,
                resumed_chunks=initial_received_chunks,
                chunks_transferred=total_chunks - initial_received_chunks,
                relative_path=relative_path,
                conflict=bool(validated.get("conflict")),
                conflict_copy_path=conflict_copy_path,
                winner_device_id=validated.get("winner_device_id"),
            )
        except Exception:
            if not resume_state.received_chunks:
                try:
                    resume_state.discard()
                except OSError:
                    logger.warning(
                        "failed to clean empty transfer state %s",
                        resume_state.transfer_id,
                    )
            raise

    def _preserve_conflict_copy(
        self,
        destination: Path,
        local_entry: FileEntry,
    ) -> str:
        base_relative_path = conflict_copy_relative_path(local_entry)
        candidate_relative_path = base_relative_path
        counter = 1
        while True:
            candidate = destination_for(
                self.shared_folder,
                candidate_relative_path,
            )
            candidate.parent.mkdir(parents=True, exist_ok=True)
            if not candidate.exists():
                destination.replace(candidate)
                return candidate_relative_path
            if (
                candidate.is_file()
                and calculate_sha256(candidate) == local_entry.file_hash
            ):
                return candidate_relative_path

            base_path = Path(base_relative_path)
            candidate_relative_path = str(
                base_path.with_name(
                    f"{base_path.stem}_{counter}{base_path.suffix}"
                )
            ).replace("\\", "/")
            counter += 1

    def _transfer_lock(self, metadata: dict[str, Any]) -> threading.Lock:
        transfer_id = transfer_id_for(metadata)
        with self._transfer_locks_guard:
            return self._transfer_locks.setdefault(transfer_id, threading.Lock())

    @staticmethod
    def _receive_chunk_metadata(
        conn: socket.socket,
        expected_index: int,
        configured_chunk_size: int,
        expected_size: int,
    ) -> dict[str, Any]:
        try:
            metadata = recv_json_message(conn)
        except (ConnectionError, OSError) as exc:
            raise TransferError(
                "TRANSFER_INCOMPLETE",
                f"等待第 {expected_index} 块时连接中断。",
                expected_index,
            ) from exc
        except (UnicodeDecodeError, ValueError) as exc:
            raise TransferError(
                "INVALID_CHUNK",
                f"第 {expected_index} 块元信息无效：{exc}",
                expected_index,
            ) from exc

        if metadata.get("type") != "CHUNK":
            raise TransferError(
                "INVALID_CHUNK",
                f"期望接收第 {expected_index} 块。",
                expected_index,
            )

        chunk_index = metadata.get("chunk_index")
        if type(chunk_index) is not int or chunk_index != expected_index:
            raise TransferError(
                "CHUNK_OUT_OF_ORDER",
                f"分块顺序错误：期望 {expected_index}，收到 {chunk_index}。",
                expected_index,
            )

        chunk_size = metadata.get("chunk_size")
        if (
            type(chunk_size) is not int
            or chunk_size != expected_size
            or chunk_size > configured_chunk_size
        ):
            raise TransferError(
                "INVALID_CHUNK_SIZE",
                f"第 {expected_index} 块大小无效：期望 {expected_size}。",
                expected_index,
            )

        chunk_hash = metadata.get("chunk_hash")
        if not is_sha256(chunk_hash):
            raise TransferError(
                "INVALID_CHUNK_HASH",
                f"第 {expected_index} 块缺少有效的 SHA-256。",
                expected_index,
            )

        return {
            "chunk_size": chunk_size,
            "chunk_hash": str(chunk_hash).lower(),
        }

    @staticmethod
    def _validate_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
        if metadata.get("type") != "FILE_SEND":
            raise TransferError("UNSUPPORTED_REQUEST", "不支持的请求类型。")
        if metadata.get("protocol_version") != PROTOCOL_VERSION:
            raise TransferError(
                "PROTOCOL_INCOMPATIBLE",
                "协议版本不兼容，请将发送端和接收端都升级到阶段六。",
            )
        if metadata.get("hash_algorithm") != HASH_ALGORITHM:
            raise TransferError("UNSUPPORTED_HASH", "仅支持 SHA-256 哈希算法。")

        raw_file_name = metadata.get("file_name")
        if not isinstance(raw_file_name, str) or not raw_file_name.strip():
            raise TransferError("INVALID_METADATA", "缺少有效的 file_name。")
        file_name = safe_file_name(raw_file_name)

        file_size = metadata.get("file_size")
        if type(file_size) is not int:
            raise TransferError("INVALID_METADATA", "file_size 必须是整数。")
        if file_size < 0:
            raise TransferError("INVALID_METADATA", "file_size 不能为负数。")

        chunk_size = metadata.get("chunk_size")
        try:
            chunk_size = validate_chunk_size(chunk_size)
        except ValueError as exc:
            raise TransferError("INVALID_METADATA", f"chunk_size 无效：{exc}") from exc

        total_chunks = metadata.get("total_chunks")
        expected_chunks = (file_size + chunk_size - 1) // chunk_size
        if type(total_chunks) is not int or total_chunks != expected_chunks:
            raise TransferError(
                "INVALID_METADATA",
                f"total_chunks 无效：期望 {expected_chunks}。",
            )

        file_hash = metadata.get("file_hash")
        if not is_sha256(file_hash):
            raise TransferError("INVALID_METADATA", "缺少有效的文件 SHA-256。")

        transfer_mode = metadata.get("transfer_mode", "manual")
        if transfer_mode not in {"manual", "sync"}:
            raise TransferError("INVALID_METADATA", "transfer_mode 无效。")

        validated: dict[str, Any] = {
            "transfer_mode": transfer_mode,
            "file_name": file_name,
            "file_size": file_size,
            "file_hash": str(file_hash).lower(),
            "chunk_size": chunk_size,
            "total_chunks": total_chunks,
        }
        if transfer_mode == "sync":
            try:
                relative_path = normalize_relative_path(metadata["relative_path"])
            except (KeyError, TypeError, ValueError) as exc:
                raise TransferError(
                    "INVALID_PATH",
                    f"同步相对路径无效：{exc}",
                ) from exc
            if relative_path.rsplit("/", 1)[-1] != file_name:
                raise TransferError(
                    "INVALID_PATH",
                    "file_name 与 relative_path 不一致。",
                )

            modified_time_ns = metadata.get("modified_time_ns")
            version = metadata.get("version")
            changed_at_ns = metadata.get("changed_at_ns")
            source_device_id = metadata.get("source_device_id")
            source_device_name = metadata.get("source_device_name", "")
            baseline_hash = metadata.get("baseline_hash")
            baseline_status = metadata.get("baseline_status")
            if type(modified_time_ns) is not int or modified_time_ns < 0:
                raise TransferError("INVALID_METADATA", "modified_time_ns 无效。")
            if type(version) is not int or version < 1:
                raise TransferError("INVALID_METADATA", "version 无效。")
            if type(changed_at_ns) is not int or changed_at_ns < 0:
                raise TransferError("INVALID_METADATA", "changed_at_ns 无效。")
            if not isinstance(source_device_id, str) or not source_device_id:
                raise TransferError("INVALID_METADATA", "source_device_id 无效。")
            if not isinstance(source_device_name, str):
                raise TransferError("INVALID_METADATA", "source_device_name 无效。")
            if baseline_hash is not None and not is_sha256(baseline_hash):
                raise TransferError("INVALID_METADATA", "baseline_hash 无效。")
            if baseline_status is not None and baseline_status not in {
                "active",
                "deleted",
            }:
                raise TransferError("INVALID_METADATA", "baseline_status 无效。")

            validated.update(
                {
                    "relative_path": relative_path,
                    "modified_time_ns": modified_time_ns,
                    "version": version,
                    "source_device_id": source_device_id,
                    "source_device_name": source_device_name,
                    "changed_at_ns": changed_at_ns,
                    "baseline_hash": (
                        str(baseline_hash).lower()
                        if baseline_hash is not None
                        else None
                    ),
                    "baseline_status": baseline_status,
                }
            )
        return validated

    @staticmethod
    def _entry_from_metadata(metadata: dict[str, Any]) -> FileEntry:
        return FileEntry(
            relative_path=metadata["relative_path"],
            file_name=metadata["file_name"],
            file_size=metadata["file_size"],
            modified_time_ns=metadata["modified_time_ns"],
            file_hash=metadata["file_hash"],
            version=metadata["version"],
            source_device_id=metadata["source_device_id"],
            status=STATUS_ACTIVE,
            changed_at_ns=metadata["changed_at_ns"],
            source_device_name=metadata.get("source_device_name", ""),
        )

    def _audit_rejection(
        self,
        addr: tuple[str, int],
        request: dict[str, Any],
        error: TransferError,
    ) -> None:
        if error.code in {
            "INVALID_METADATA",
            "INVALID_PATH",
            "INVALID_CHUNK",
            "INVALID_CHUNK_SIZE",
            "INVALID_CHUNK_HASH",
            "CHUNK_OUT_OF_ORDER",
            "UNSUPPORTED_REQUEST",
        }:
            event_type = "malformed_request"
        elif error.code in {"AUTH_REQUIRED", "AUTH_FAILED"}:
            if request.get("type") != "PAIR_REQUEST":
                return
            event_type = (
                "pairing_failed"
                if request.get("type") == "PAIR_REQUEST"
                else "authentication_failed"
            )
        elif error.code == "AUTH_BLOCKED":
            if request.get("type") != "PAIR_REQUEST":
                return
            event_type = "blocked_device_access"
        else:
            event_type = "request_rejected"
        self._audit(
            event_type,
            severity="warning",
            source_ip=addr[0],
            device_id=str(
                request.get("auth_device_id")
                or request.get("device_id")
                or ""
            ),
            request_type=str(request.get("type", "")),
            outcome="rejected",
            details={"error_code": error.code},
        )

    def _audit(
        self,
        event_type: str,
        *,
        severity: str = "info",
        source_ip: str = "",
        device_id: str = "",
        request_type: str = "",
        outcome: str = "success",
        bytes_count: int = 0,
        details: dict[str, Any] | None = None,
    ) -> None:
        if self.audit_store is not None:
            self.audit_store.record_event(
                event_type,
                severity=severity,
                source_ip=source_ip,
                device_id=device_id,
                request_type=request_type,
                outcome=outcome,
                bytes_count=bytes_count,
                details=details,
            )

    def _notify(self, event_type: str, payload: dict[str, Any]) -> None:
        if self.event_callback is not None:
            self.event_callback(event_type, payload)

    def _notify_receive_failure(
        self,
        request: dict[str, Any],
        addr: tuple[str, int],
        error: str,
        error_code: str = "TRANSFER_FAILED",
    ) -> None:
        if request.get("type") != "FILE_SEND":
            return
        self._notify(
            "transfer_failed",
            {
                "kind": "receive",
                "source_ip": addr[0],
                "device_id": str(request.get("auth_device_id", "")),
                "file_name": request.get("file_name", ""),
                "relative_path": request.get("relative_path"),
                "total_bytes": request.get("file_size", 0),
                "error_code": error_code,
                "error": error,
            },
        )
