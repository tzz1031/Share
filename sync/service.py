from __future__ import annotations

import logging
import threading

from security import SecurityStore, TLSPolicy
from transfer import TransferError, send_sync_file

from .conflict import decide_conflict
from .file_index import FileIndex, STATUS_ACTIVE, should_send_entry
from .index_exchange import request_file_index
from .paths import destination_for


logger = logging.getLogger(__name__)


class SyncService:
    def __init__(
        self,
        file_index: FileIndex,
        discovery,
        chunk_size: int,
        interval_seconds: float = 10.0,
        request_timeout: float = 15.0,
        security_store: SecurityStore | None = None,
        tls_enabled: bool = False,
        audit_store=None,
        event_callback=None,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        self.file_index = file_index
        self.discovery = discovery
        self.chunk_size = chunk_size
        self.interval_seconds = float(interval_seconds)
        self.request_timeout = float(request_timeout)
        self.security_store = security_store
        self.tls_enabled = bool(tls_enabled)
        self.audit_store = audit_store
        self.event_callback = event_callback
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._sync_lock = threading.Lock()

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="folder-sync",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=max(2.0, self.request_timeout + 1.0))

    def sync_once(self) -> None:
        if not self._sync_lock.acquire(blocking=False):
            return
        try:
            self._notify("sync_started", {})
            self.file_index.scan()
            for device in self.discovery.list_devices():
                if self._stop_event.is_set():
                    break
                self._sync_to_device(device)
            self._notify("sync_completed", {})
        finally:
            self._sync_lock.release()

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.sync_once()
            except Exception:
                logger.exception("unexpected folder synchronization failure")
            self._stop_event.wait(self.interval_seconds)

    def _sync_to_device(self, device) -> None:
        credential = None
        tls_policy = TLSPolicy()
        if self.security_store is not None:
            credential = self.security_store.credential_for(
                device.device_id,
                self.file_index.device_id,
            )
            if credential is None:
                return
            if self.tls_enabled:
                fingerprint = self.security_store.trusted_fingerprint(
                    device.device_id
                )
                if fingerprint is None:
                    self._audit_sync_failure(
                        device,
                        "TLS_IDENTITY_REQUIRED",
                        "设备缺少已绑定的证书指纹，请重新配对。",
                    )
                    return
                if not getattr(device, "tls_enabled", False):
                    self._audit_sync_failure(
                        device,
                        "TLS_REQUIRED",
                        "本机要求 TLS，但目标设备广播为明文模式。",
                    )
                    return
                tls_policy = TLSPolicy(
                    enabled=True,
                    expected_fingerprint=fingerprint,
                )
        try:
            remote_entries = request_file_index(
                device.ip,
                device.tcp_port,
                timeout=self.request_timeout,
                credential=credential,
                requester_device_id=self.file_index.device_id,
                tls_policy=tls_policy,
            )
        except (ConnectionError, OSError, ValueError) as exc:
            logger.warning(
                "failed to fetch index from %s (%s:%s): %s",
                device.device_name,
                device.ip,
                device.tcp_port,
                exc,
            )
            self._audit_sync_failure(device, type(exc).__name__, str(exc))
            return

        self.file_index.record_device_sync(device.device_id)
        remote_by_path = {
            entry.relative_path: entry
            for entry in remote_entries
        }
        local_by_path = {
            entry.relative_path: entry
            for entry in self.file_index.snapshot()
        }
        all_paths = sorted(set(local_by_path) | set(remote_by_path))
        for relative_path in all_paths:
            if self._stop_event.is_set():
                return
            local = local_by_path.get(relative_path)
            remote = remote_by_path.get(relative_path)
            if local is None:
                continue
            if (
                remote is not None
                and local.status == STATUS_ACTIVE
                and remote.status == STATUS_ACTIVE
                and local.file_hash == remote.file_hash
            ):
                self.file_index.record_sync(
                    device.device_id,
                    local,
                    remote_version=remote.version,
                )
                continue

            local_state = self.file_index.get_sync_state(
                device.device_id,
                relative_path,
            )
            decision = decide_conflict(
                local,
                remote,
                local_state,
                remote.peer_baseline_hash if remote is not None else None,
                remote.peer_baseline_status if remote is not None else None,
            )
            if decision.conflict:
                if (
                    decision.winner is None
                    or decision.winner.file_hash != local.file_hash
                    or local.status != STATUS_ACTIVE
                ):
                    continue
            elif remote is None:
                if local.status != STATUS_ACTIVE:
                    continue
            elif decision.local_changed and not decision.remote_changed:
                if local.status != STATUS_ACTIVE:
                    continue
            elif decision.remote_changed and not decision.local_changed:
                continue
            elif not should_send_entry(local, remote):
                continue

            current = self.file_index.refresh_path(local.relative_path)
            if current is None or current != local:
                continue

            self._notify(
                "transfer_queued",
                {
                    "kind": "sync",
                    "device_id": device.device_id,
                    "relative_path": local.relative_path,
                    "total_bytes": local.file_size,
                },
            )
            try:
                source = destination_for(
                    self.file_index.shared_folder,
                    local.relative_path,
                )
                result = send_sync_file(
                    device.ip,
                    device.tcp_port,
                    source,
                    relative_path=local.relative_path,
                    modified_time_ns=local.modified_time_ns,
                    version=local.version,
                    source_device_id=local.source_device_id,
                    source_device_name=local.source_device_name,
                    file_hash=local.file_hash,
                    changed_at_ns=local.changed_at_ns,
                    baseline_hash=(
                        local_state.baseline_hash
                        if local_state is not None
                        else None
                    ),
                    baseline_status=(
                        local_state.baseline_status
                        if local_state is not None
                        else None
                    ),
                    credential=credential,
                    chunk_size=self.chunk_size,
                    timeout=max(60.0, self.request_timeout),
                    tls_policy=tls_policy,
                    progress_callback=lambda transferred, total: self._notify(
                        "transfer_progress",
                        {
                            "kind": "sync",
                            "device_id": device.device_id,
                            "relative_path": local.relative_path,
                            "transferred_bytes": transferred,
                            "total_bytes": total,
                        },
                    ),
                )
                logger.info(
                    "sync %s to %s: %s",
                    local.relative_path,
                    device.device_name,
                    result.get("type"),
                )
                if result.get("type") in {
                    "FILE_RECEIVED",
                    "FILE_UP_TO_DATE",
                }:
                    self.file_index.record_sync(
                        device.device_id,
                        local,
                        remote_version=local.version,
                    )
                    self._audit(
                        "file_sent",
                        source_ip=device.ip,
                        device_id=device.device_id,
                        request_type="sync",
                        bytes_count=local.file_size,
                        details={"result_type": result.get("type")},
                    )
                self._notify(
                    "transfer_completed",
                    {
                        "kind": "sync",
                        "device_id": device.device_id,
                        "relative_path": local.relative_path,
                        "total_bytes": local.file_size,
                    },
                )
            except (FileNotFoundError, OSError, TransferError, ValueError) as exc:
                logger.warning(
                    "failed to sync %s to %s (%s:%s): %s",
                    local.relative_path,
                    device.device_name,
                    device.ip,
                    device.tcp_port,
                    exc,
                )
                self._audit_sync_failure(
                    device,
                    getattr(exc, "code", type(exc).__name__),
                    str(exc),
                )
                self._notify(
                    "transfer_failed",
                        {
                            "kind": "sync",
                            "device_id": device.device_id,
                            "relative_path": local.relative_path,
                            "total_bytes": local.file_size,
                            "error_code": getattr(
                                exc,
                                "code",
                                type(exc).__name__,
                            ),
                            "error": str(exc),
                        },
                )

    def _audit_sync_failure(self, device, code: str, message: str) -> None:
        self._audit(
            "sync_failed",
            severity="warning",
            source_ip=device.ip,
            device_id=device.device_id,
            request_type="sync",
            outcome="failed",
            details={"error_code": code, "message": message},
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
        details=None,
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

    def _notify(self, event_type: str, payload: dict) -> None:
        if self.event_callback is not None:
            self.event_callback(event_type, payload)
