from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from pathlib import PurePosixPath
from typing import Any

from security import TLSPolicy
from sync import STATUS_ACTIVE, STATUS_DELETED, FileEntry, decide_conflict
from sync.index_exchange import request_file_index
from sync.paths import destination_for, normalize_relative_path
from transfer import TransferError, fetch_sync_file, send_sync_file
from transfer.fetch import entry_signature

from .store import AgentRunStore


def normalize_path_prefix(value: str) -> str:
    prefix = str(value or "").strip().strip("/")
    if not prefix:
        return ""
    if any(character in prefix for character in "*?[]"):
        raise ValueError("path_prefix must not contain wildcards")
    return normalize_relative_path(prefix)


def _matches_prefix(path: str, prefix: str) -> bool:
    return not prefix or path == prefix or path.startswith(f"{prefix}/")


def _entry_payload(entry: FileEntry | None) -> dict[str, Any] | None:
    return entry.to_payload() if entry is not None else None


def _snapshot_fingerprint(
    local: list[FileEntry],
    remote: list[FileEntry],
) -> str:
    payload = {
        "local": [entry.to_payload() for entry in local],
        "remote": [entry.to_payload() for entry in remote],
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


class SyncCoordinator:
    def __init__(self, runtime: Any, store: AgentRunStore) -> None:
        self.runtime = runtime
        self.store = store

    def discover_devices(self) -> list[dict[str, Any]]:
        return self.runtime.devices_payload()

    def _device(self, device_id: str):
        device = self.runtime.find_online_device(device_id)
        if device is None:
            raise KeyError("device is not online")
        trusted = self.runtime.security_store.get_device(device.device_id)
        if trusted is None or trusted.permission in {"blocked", "read"}:
            raise PermissionError("device requires write permission for bidirectional sync")
        credential = self.runtime.security_store.credential_for(
            device.device_id,
            self.runtime.device_id,
        )
        if credential is None:
            raise PermissionError("device is not paired or is blocked")
        policy = TLSPolicy(
            enabled=self.runtime.config.enable_tls,
            expected_fingerprint=trusted.certificate_fingerprint,
        )
        return device, trusted, credential, policy

    def list_local_files(self, path_prefix: str = "") -> list[FileEntry]:
        prefix = normalize_path_prefix(path_prefix)
        self.runtime.file_index.scan()
        return [
            entry
            for entry in self.runtime.file_index.snapshot()
            if _matches_prefix(entry.relative_path, prefix)
        ]

    def list_remote_files(
        self,
        device_id: str,
        path_prefix: str = "",
    ) -> list[FileEntry]:
        prefix = normalize_path_prefix(path_prefix)
        device, _, credential, policy = self._device(device_id)
        entries = request_file_index(
            device.ip,
            device.tcp_port,
            timeout=self.runtime.sync_service.request_timeout,
            credential=credential,
            requester_device_id=self.runtime.device_id,
            tls_policy=policy,
        )
        return [
            entry
            for entry in entries
            if _matches_prefix(entry.relative_path, prefix)
        ]

    def compare_file_indexes(
        self,
        device_id: str,
        path_prefix: str = "",
    ) -> dict[str, Any]:
        prefix = normalize_path_prefix(path_prefix)
        local_entries = self.list_local_files(prefix)
        remote_entries = self.list_remote_files(device_id, prefix)
        local_by_path = {entry.relative_path: entry for entry in local_entries}
        remote_by_path = {entry.relative_path: entry for entry in remote_entries}
        actions: list[dict[str, Any]] = []

        for relative_path in sorted(set(local_by_path) | set(remote_by_path)):
            local = local_by_path.get(relative_path)
            remote = remote_by_path.get(relative_path)
            direction = "same"
            reason = "SAME_CONTENT"
            executable = False

            if local is None:
                if remote is not None and remote.status == STATUS_ACTIVE:
                    direction, reason, executable = "download", "REMOTE_ONLY", True
                else:
                    direction, reason = "delete_report", "REMOTE_DELETED"
            elif remote is None:
                if local.status == STATUS_ACTIVE:
                    direction, reason, executable = "upload", "LOCAL_ONLY", True
                else:
                    direction, reason = "delete_report", "LOCAL_DELETED"
            elif (
                local.status == STATUS_ACTIVE
                and remote.status == STATUS_ACTIVE
                and local.file_hash == remote.file_hash
            ):
                direction, reason = "same", "SAME_CONTENT"
            elif local.status == STATUS_DELETED or remote.status == STATUS_DELETED:
                direction, reason = "delete_report", "DELETE_DIFFERENCE"
            else:
                state = self.runtime.file_index.get_sync_state(
                    device_id,
                    relative_path,
                )
                decision = decide_conflict(
                    local,
                    remote,
                    state,
                    remote.peer_baseline_hash,
                    remote.peer_baseline_status,
                )
                reason = decision.reason_code
                if decision.conflict:
                    direction = "conflict"
                elif decision.local_changed and not decision.remote_changed:
                    direction, executable = "upload", True
                elif decision.remote_changed and not decision.local_changed:
                    direction, executable = "download", True
                else:
                    direction = "same"

            actions.append(
                {
                    "action_id": uuid.uuid4().hex,
                    "direction": direction,
                    "relative_path": relative_path,
                    "bytes": (
                        local.file_size
                        if direction == "upload" and local is not None
                        else remote.file_size
                        if direction == "download" and remote is not None
                        else 0
                    ),
                    "reason": reason,
                    "executable": executable,
                    "status": "pending" if executable else "reported",
                    "transferred_bytes": 0,
                    "error_code": "",
                    "error_message": "",
                    "local": _entry_payload(local),
                    "remote": _entry_payload(remote),
                }
            )

        counts = {
            name: sum(action["direction"] == name for action in actions)
            for name in ("upload", "download", "same", "conflict", "delete_report")
        }
        return {
            "device_id": device_id,
            "path_prefix": prefix,
            "snapshot_fingerprint": _snapshot_fingerprint(
                local_entries,
                remote_entries,
            ),
            "actions": actions,
            "counts": counts,
            "total_bytes": sum(
                action["bytes"] for action in actions if action["executable"]
            ),
        }

    def generate_sync_plan(
        self,
        run_id: str,
        device_id: str,
        path_prefix: str = "",
    ) -> dict[str, Any]:
        comparison = self.compare_file_indexes(device_id, path_prefix)
        device, _, _, _ = self._device(device_id)
        plan = {
            "plan_id": uuid.uuid4().hex,
            "run_id": run_id,
            "device_id": device.device_id,
            "device_name": device.device_name,
            "path_prefix": comparison["path_prefix"],
            "snapshot_fingerprint": comparison["snapshot_fingerprint"],
            "actions": comparison["actions"],
            "counts": comparison["counts"],
            "total_bytes": comparison["total_bytes"],
            "risks": [
                "文件传输将在审批后执行。",
                "删除差异只报告，不会传播删除。",
                "冲突文件不会自动覆盖，需要人工处理。",
            ],
            "status": "waiting_approval",
            "approved_at_ns": None,
            "created_at_ns": time.time_ns(),
            "verification": None,
        }
        self.store.save_plan(plan["plan_id"], run_id, plan)
        return plan

    def _current_fingerprint(self, plan: dict[str, Any]) -> str:
        comparison = self.compare_file_indexes(
            plan["device_id"],
            plan["path_prefix"],
        )
        return comparison["snapshot_fingerprint"]

    def execute_sync_plan(self, plan_id: str) -> dict[str, Any]:
        plan = self.store.load_plan(plan_id)
        if plan is None:
            raise KeyError("sync plan does not exist")
        if plan["status"] != "approved":
            raise PermissionError("sync plan has not been approved")
        if self._current_fingerprint(plan) != plan["snapshot_fingerprint"]:
            plan["status"] = "stale"
            self.store.save_plan(plan_id, plan["run_id"], plan)
            raise TransferError("PLAN_STALE", "索引已变化，请重新生成同步计划。")

        device, _, credential, policy = self._device(plan["device_id"])
        plan["status"] = "running"
        self.store.save_plan(plan_id, plan["run_id"], plan)
        for action in plan["actions"]:
            if not action["executable"]:
                continue
            action["status"] = "running"
            self.store.save_plan(plan_id, plan["run_id"], plan)
            self.runtime.events.publish(
                "agent_action",
                {
                    "run_id": plan["run_id"],
                    "plan_id": plan_id,
                    "action": action,
                },
            )
            try:
                def progress(transferred: int, total: int) -> None:
                    action["transferred_bytes"] = max(0, int(transferred))
                    action["bytes"] = max(0, int(total))
                    self.store.save_plan(plan_id, plan["run_id"], plan)
                    self.runtime.events.publish(
                        "agent_action",
                        {
                            "run_id": plan["run_id"],
                            "plan_id": plan_id,
                            "action": action,
                        },
                    )

                local = (
                    FileEntry.from_payload(action["local"])
                    if action["local"] is not None
                    else None
                )
                remote = (
                    FileEntry.from_payload(action["remote"])
                    if action["remote"] is not None
                    else None
                )
                if action["direction"] == "upload":
                    if local is None or local.status != STATUS_ACTIVE:
                        raise TransferError("PLAN_STALE", "待上传文件已不存在。")
                    current = self.runtime.file_index.refresh_path(
                        local.relative_path
                    )
                    if entry_signature(current) != entry_signature(local):
                        raise TransferError("PLAN_STALE", "待上传文件已发生变化。")
                    state = self.runtime.file_index.get_sync_state(
                        device.device_id,
                        local.relative_path,
                    )
                    result = send_sync_file(
                        device.ip,
                        device.tcp_port,
                        destination_for(
                            self.runtime.config.shared_folder,
                            local.relative_path,
                        ),
                        relative_path=local.relative_path,
                        modified_time_ns=local.modified_time_ns,
                        version=local.version,
                        source_device_id=local.source_device_id,
                        source_device_name=local.source_device_name,
                        file_hash=local.file_hash,
                        changed_at_ns=local.changed_at_ns,
                        baseline_hash=state.baseline_hash if state else None,
                        baseline_status=state.baseline_status if state else None,
                        credential=credential,
                        chunk_size=self.runtime.config.chunk_size,
                        tls_policy=policy,
                        progress_callback=progress,
                    )
                    if result.get("type") in {"FILE_RECEIVED", "FILE_UP_TO_DATE"}:
                        self.runtime.file_index.record_sync(
                            device.device_id,
                            local,
                            remote_version=local.version,
                        )
                else:
                    if remote is None:
                        raise TransferError("PLAN_STALE", "待下载文件已不存在。")
                    fetch_sync_file(
                        device.ip,
                        device.tcp_port,
                        remote_entry=remote,
                        remote_device_id=device.device_id,
                        shared_folder=self.runtime.config.shared_folder,
                        file_index=self.runtime.file_index,
                        expected_local_entry=local,
                        credential=credential,
                        tls_policy=policy,
                        progress_callback=progress,
                    )
                action["status"] = "success"
            except Exception as exc:
                action["status"] = "failed"
                action["error_code"] = getattr(exc, "code", type(exc).__name__)
                action["error_message"] = str(exc)
            self.store.save_plan(plan_id, plan["run_id"], plan)
            self.runtime.events.publish(
                "agent_action",
                {
                    "run_id": plan["run_id"],
                    "plan_id": plan_id,
                    "action": action,
                },
            )

        plan["status"] = (
            "executed"
            if all(
                not action["executable"] or action["status"] == "success"
                for action in plan["actions"]
            )
            else "execution_failed"
        )
        self.store.save_plan(plan_id, plan["run_id"], plan)
        return plan

    def verify_sync_plan(self, plan_id: str) -> dict[str, Any]:
        plan = self.store.load_plan(plan_id)
        if plan is None:
            raise KeyError("sync plan does not exist")
        local = {
            entry.relative_path: entry
            for entry in self.list_local_files(plan["path_prefix"])
        }
        remote = {
            entry.relative_path: entry
            for entry in self.list_remote_files(
                plan["device_id"],
                plan["path_prefix"],
            )
        }
        checks = []
        for action in plan["actions"]:
            if not action["executable"]:
                continue
            expected = (
                action["local"]["file_hash"]
                if action["direction"] == "upload"
                else action["remote"]["file_hash"]
            )
            local_entry = local.get(action["relative_path"])
            remote_entry = remote.get(action["relative_path"])
            success = bool(
                local_entry
                and remote_entry
                and local_entry.status == STATUS_ACTIVE
                and remote_entry.status == STATUS_ACTIVE
                and local_entry.file_hash == expected
                and remote_entry.file_hash == expected
            )
            checks.append(
                {
                    "relative_path": action["relative_path"],
                    "success": success,
                    "expected_hash": expected,
                    "local_hash": local_entry.file_hash if local_entry else None,
                    "remote_hash": remote_entry.file_hash if remote_entry else None,
                }
            )
        verification = {
            "success": all(check["success"] for check in checks)
            and plan["status"] == "executed",
            "checks": checks,
            "verified_at_ns": time.time_ns(),
        }
        plan["verification"] = verification
        plan["status"] = "verified" if verification["success"] else "verification_failed"
        self.store.save_plan(plan_id, plan["run_id"], plan)
        self.runtime.events.publish(
            "agent_verification",
            {
                "run_id": plan["run_id"],
                "plan_id": plan_id,
                "verification": verification,
            },
        )
        return verification

    def transfer_status(self, plan_id: str) -> dict[str, Any]:
        plan = self.store.load_plan(plan_id)
        if plan is None:
            raise KeyError("sync plan does not exist")
        return {
            "plan_id": plan_id,
            "status": plan["status"],
            "actions": plan["actions"],
            "verification": plan.get("verification"),
        }

    def device_candidates(
        self,
        request: str,
    ) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
        candidates = [
            device
            for device in self.discover_devices()
            if device["online"]
            and device["paired"]
            and device["permission"] in {"write", "admin"}
        ]
        named = [
            device
            for device in candidates
            if device["device_name"].lower() in request.lower()
            or device["device_id"] in request
        ]
        selected = (
            named[0]
            if len(named) == 1
            else candidates[0]
            if len(candidates) == 1
            else None
        )
        return selected, candidates

    def resolve_request(
        self,
        request: str,
        selected_device_id: str = "",
    ) -> tuple[str, str]:
        selected, candidates = self.device_candidates(request)
        if selected_device_id:
            selected = next(
                (
                    device
                    for device in candidates
                    if device["device_id"] == selected_device_id
                ),
                None,
            )
        if selected is None:
            raise ValueError("无法唯一确定目标设备，请在请求中写明设备名称。")

        entries = self.list_local_files("") + self.list_remote_files(
            str(selected["device_id"]),
            "",
        )
        possible_prefixes = {
            PurePosixPath(entry.relative_path).parts[0]
            for entry in entries
            if PurePosixPath(entry.relative_path).parts
        }
        mentioned = re.findall(
            r"(?:的|同步)\s*([A-Za-z0-9_.\-/\u4e00-\u9fff]+)\s*文件夹",
            request,
        )
        if mentioned:
            try:
                requested_prefix = normalize_path_prefix(mentioned[-1])
            except ValueError:
                requested_prefix = ""
            if requested_prefix:
                return str(selected["device_id"]), requested_prefix
        prefix = next(
            (
                value
                for value in sorted(possible_prefixes, key=len, reverse=True)
                if value.lower() in request.lower()
            ),
            "",
        )
        return str(selected["device_id"]), prefix
