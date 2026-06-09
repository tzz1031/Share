from __future__ import annotations

import os
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from audit import AuditStore
from security import PERMISSION_ADMIN, SecurityStore, TLSIdentity
from sync.paths import INTERNAL_FOLDER

from .models import AgentResult


class SecurityAuditAgent:
    def __init__(
        self,
        *,
        shared_folder: str | Path,
        security_store: SecurityStore,
        audit_store: AuditStore,
        discovery,
        tls_enabled: bool,
        tls_identity: TLSIdentity | None,
        size_risk_bytes: int = 10 * 1024**3,
        file_count_risk: int = 10_000,
    ) -> None:
        self.shared_folder = Path(shared_folder)
        self.security_store = security_store
        self.audit_store = audit_store
        self.discovery = discovery
        self.tls_enabled = bool(tls_enabled)
        self.tls_identity = tls_identity
        self.size_risk_bytes = int(size_risk_bytes)
        self.file_count_risk = int(file_count_risk)

    def analyze(self) -> AgentResult:
        file_count, size_bytes = _folder_usage(self.shared_folder)
        authorized = self.security_store.list_devices()
        authorized_ids = {device.device_id for device in authorized}
        strangers = [
            device
            for device in self.discovery.list_devices()
            if device.device_id not in authorized_ids
        ]
        since = time.time_ns() - 3600 * 1_000_000_000
        failure_count = self.audit_store.count_events(
            ("authentication_failed", "pairing_failed"),
            since_ns=since,
        )
        alerts = self.audit_store.recent_alerts(100, unread_only=True)
        certificate_days = None
        if self.tls_identity is not None:
            certificate_days = max(
                0,
                (self.tls_identity.expires_at - datetime.now(UTC)).days,
            )

        evidence = [
            f"共享文件：{file_count} 个",
            f"共享大小：{size_bytes} 字节",
            f"授权设备：{len(authorized)} 台",
            f"陌生在线设备：{len(strangers)} 台",
            f"最近一小时认证/配对失败：{failure_count} 次",
            f"未读异常告警：{len(alerts)} 条",
            f"TLS：{'已启用' if self.tls_enabled else '未启用'}",
        ]
        causes: list[str] = []
        recommendations: list[str] = []
        cause_codes: list[str] = []
        severity = "info"

        if not self.tls_enabled:
            causes.append("TCP 传输未启用 TLS，令牌和文件内容可能被局域网抓包读取。")
            recommendations.append("启用 enable_tls，并重新配对旧授权设备。")
            cause_codes.append("TLS_DISABLED")
            severity = "error"
        if self.tls_enabled and self.tls_identity is None:
            causes.append("配置要求 TLS，但本机证书未成功初始化。")
            recommendations.append("检查 .lan-sync/tls 目录权限并重启程序。")
            cause_codes.append("TLS_IDENTITY_MISSING")
            severity = "error"
        if certificate_days is not None and certificate_days <= 30:
            causes.append("TLS 证书将在 30 天内到期。")
            recommendations.append("安排证书轮换，并准备让已配对设备重新确认指纹。")
            cause_codes.append("TLS_CERT_EXPIRING")
            severity = max_severity(severity, "warning")
        if size_bytes >= self.size_risk_bytes or file_count >= self.file_count_risk:
            causes.append("共享目录超过配置的大小或文件数量风险阈值。")
            recommendations.append("缩小共享范围，移除不需要同步的大文件或归档目录。")
            cause_codes.append("SHARE_TOO_LARGE")
            severity = max_severity(severity, "warning")
        if strangers:
            causes.append("局域网内存在尚未配对的在线设备。")
            recommendations.append("核对设备列表，不要向不认识的设备提供配对码。")
            cause_codes.append("UNKNOWN_DEVICES")
            severity = max_severity(severity, "warning")
        if failure_count >= 5:
            causes.append("最近一小时存在多次认证或配对失败。")
            recommendations.append("查看异常告警并核对来源，必要时重新生成配对码。")
            cause_codes.append("AUTH_FAILURES")
            severity = max_severity(severity, "warning")
        if alerts:
            causes.append("异常访问检测存在尚未查看的告警。")
            recommendations.append("查看最近异常告警，确认是否为合法批量同步。")
            cause_codes.append("UNREAD_ALERTS")
            severity = max_severity(severity, "warning")
        admin_count = sum(
            device.permission == PERMISSION_ADMIN for device in authorized
        )
        if admin_count > 1:
            causes.append("多个远端设备拥有 admin 权限，授权面较大。")
            recommendations.append("将无需管理权限的设备降级为 write 或 read。")
            cause_codes.append("EXCESS_ADMIN")
            severity = max_severity(severity, "warning")

        if not causes:
            summary = "未发现明显的共享安全风险。"
            recommendations.append("继续定期检查授权设备、异常告警和证书有效期。")
        else:
            summary = f"安全审计发现 {len(causes)} 项需要关注的风险。"

        return AgentResult(
            agent="security",
            summary=summary,
            severity=severity,
            evidence=tuple(evidence),
            causes=tuple(causes),
            recommendations=tuple(recommendations),
            facts={
                "alert_count": len(alerts),
                "authorized_count": len(authorized),
                "certificate_days_remaining": certificate_days,
                "failure_count": failure_count,
                "file_count": file_count,
                "size_bytes": size_bytes,
                "stranger_count": len(strangers),
                "tls_enabled": self.tls_enabled,
                "cause_codes": tuple(cause_codes),
            },
        )


class SecurityAuditService:
    def __init__(
        self,
        agent: SecurityAuditAgent,
        audit_store: AuditStore,
        interval_seconds: float = 600.0,
    ) -> None:
        self.agent = agent
        self.audit_store = audit_store
        self.interval_seconds = max(1.0, float(interval_seconds))
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="security-audit",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            result = self.agent.analyze()
            self.audit_store.record_event(
                "security_audit",
                severity=result.severity,
                outcome="risk" if result.causes else "success",
                details={
                    "risk_count": len(result.causes),
                    "cause_codes": result.facts.get("cause_codes", ()),
                },
                detect_anomalies=False,
            )
            self._stop_event.wait(self.interval_seconds)


def _folder_usage(root: Path) -> tuple[int, int]:
    file_count = 0
    size_bytes = 0
    for current_root, directories, files in os.walk(root, followlinks=False):
        current = Path(current_root)
        directories[:] = [
            name
            for name in directories
            if name != INTERNAL_FOLDER and not (current / name).is_symlink()
        ]
        for name in files:
            path = current / name
            if path.is_symlink():
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            file_count += 1
            size_bytes += stat.st_size
    return file_count, size_bytes


def max_severity(left: str, right: str) -> str:
    order = {"info": 0, "warning": 1, "error": 2}
    return left if order[left] >= order[right] else right
