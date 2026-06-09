from __future__ import annotations

import json
import logging
import logging.handlers
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_ERROR = "error"
VALID_SEVERITIES = {SEVERITY_INFO, SEVERITY_WARNING, SEVERITY_ERROR}
SENSITIVE_KEYS = {
    "access_token",
    "api_key",
    "auth_token",
    "pair_code",
    "password",
    "private_key",
    "token",
}


@dataclass(frozen=True)
class AuditEvent:
    event_id: int
    created_at_ns: int
    event_type: str
    severity: str
    source_ip: str
    device_id: str
    request_type: str
    outcome: str
    bytes_count: int
    details: dict[str, Any]


@dataclass(frozen=True)
class AuditAlert:
    alert_id: int
    created_at_ns: int
    rule_code: str
    severity: str
    source_key: str
    message: str
    event_count: int
    read: bool


class AuditStore:
    def __init__(
        self,
        shared_folder: str | Path,
        *,
        retention_days: int = 30,
        alert_cooldown_seconds: float = 600.0,
        max_log_bytes: int = 5 * 1024 * 1024,
        backup_count: int = 5,
    ) -> None:
        self.internal_folder = Path(shared_folder) / ".lan-sync"
        self.database_path = self.internal_folder / "audit.sqlite3"
        self.log_path = self.internal_folder / "access.log"
        self.retention_days = max(1, int(retention_days))
        self.alert_cooldown_ns = int(max(0, alert_cooldown_seconds) * 1_000_000_000)
        self._lock = threading.RLock()
        self.internal_folder.mkdir(parents=True, exist_ok=True)
        self._initialize_database()
        self._logger = self._build_logger(max_log_bytes, backup_count)
        self.prune()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=30.0)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_database(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at_ns INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    request_type TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    bytes_count INTEGER NOT NULL,
                    details_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS audit_events_lookup
                ON audit_events (event_type, source_ip, created_at_ns)
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at_ns INTEGER NOT NULL,
                    rule_code TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_key TEXT NOT NULL,
                    message TEXT NOT NULL,
                    event_count INTEGER NOT NULL,
                    is_read INTEGER NOT NULL DEFAULT 0
                )
                """
            )

    def _build_logger(
        self,
        max_log_bytes: int,
        backup_count: int,
    ) -> logging.Logger:
        logger = logging.getLogger(f"lan_sync.audit.{self.database_path}")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        if not logger.handlers:
            handler = logging.handlers.RotatingFileHandler(
                self.log_path,
                maxBytes=max(1024, int(max_log_bytes)),
                backupCount=max(1, int(backup_count)),
                encoding="utf-8",
            )
            handler.setFormatter(
                logging.Formatter(
                    "[%(asctime)s] %(levelname)s %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
            )
            logger.addHandler(handler)
        return logger

    def record_event(
        self,
        event_type: str,
        *,
        severity: str = SEVERITY_INFO,
        source_ip: str = "",
        device_id: str = "",
        request_type: str = "",
        outcome: str = "success",
        bytes_count: int = 0,
        details: dict[str, Any] | None = None,
        detect_anomalies: bool = True,
    ) -> AuditEvent:
        if severity not in VALID_SEVERITIES:
            raise ValueError("invalid audit severity")
        created_at_ns = time.time_ns()
        safe_details = _sanitize(details or {})
        details_json = json.dumps(
            safe_details,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO audit_events (
                    created_at_ns, event_type, severity, source_ip,
                    device_id, request_type, outcome, bytes_count, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    created_at_ns,
                    str(event_type),
                    severity,
                    str(source_ip),
                    str(device_id),
                    str(request_type),
                    str(outcome),
                    max(0, int(bytes_count)),
                    details_json,
                ),
            )
            event_id = int(cursor.lastrowid)
        self._logger.log(
            {
                SEVERITY_INFO: logging.INFO,
                SEVERITY_WARNING: logging.WARNING,
                SEVERITY_ERROR: logging.ERROR,
            }[severity],
            "%s source=%s device=%s request=%s outcome=%s bytes=%s details=%s",
            event_type,
            source_ip or "-",
            device_id or "-",
            request_type or "-",
            outcome,
            max(0, int(bytes_count)),
            details_json,
        )
        event = AuditEvent(
            event_id=event_id,
            created_at_ns=created_at_ns,
            event_type=str(event_type),
            severity=severity,
            source_ip=str(source_ip),
            device_id=str(device_id),
            request_type=str(request_type),
            outcome=str(outcome),
            bytes_count=max(0, int(bytes_count)),
            details=safe_details,
        )
        if detect_anomalies:
            self._detect_anomalies(event)
        return event

    def recent_events(self, limit: int = 50) -> list[AuditEvent]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, created_at_ns, event_type, severity, source_ip,
                       device_id, request_type, outcome, bytes_count, details_json
                FROM audit_events
                ORDER BY created_at_ns DESC, id DESC
                LIMIT ?
                """,
                (max(1, int(limit)),),
            ).fetchall()
        return [_row_to_event(row) for row in rows]

    def recent_alerts(
        self,
        limit: int = 50,
        *,
        unread_only: bool = False,
    ) -> list[AuditAlert]:
        where = "WHERE is_read = 0" if unread_only else ""
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT id, created_at_ns, rule_code, severity, source_key,
                       message, event_count, is_read
                FROM audit_alerts
                {where}
                ORDER BY created_at_ns DESC, id DESC
                LIMIT ?
                """,
                (max(1, int(limit)),),
            ).fetchall()
        return [_row_to_alert(row) for row in rows]

    def unread_high_risk_count(self) -> int:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM audit_alerts
                WHERE is_read = 0 AND severity = ?
                """,
                (SEVERITY_ERROR,),
            ).fetchone()
        return int(row["count"])

    def mark_alerts_read(self) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("UPDATE audit_alerts SET is_read = 1 WHERE is_read = 0")

    def mark_alert_read(self, alert_id: int) -> bool:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                "UPDATE audit_alerts SET is_read = 1 WHERE id = ?",
                (int(alert_id),),
            )
        return cursor.rowcount > 0

    def query_events(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        device_id: str = "",
        event_type: str = "",
        severity: str = "",
        outcome: str = "",
        started_at_ns: int | None = None,
        ended_at_ns: int | None = None,
    ) -> tuple[list[AuditEvent], int]:
        clauses: list[str] = []
        values: list[Any] = []
        for column, value in (
            ("device_id", device_id),
            ("event_type", event_type),
            ("severity", severity),
            ("outcome", outcome),
        ):
            if value:
                clauses.append(f"{column} = ?")
                values.append(str(value))
        if started_at_ns is not None:
            clauses.append("created_at_ns >= ?")
            values.append(int(started_at_ns))
        if ended_at_ns is not None:
            clauses.append("created_at_ns <= ?")
            values.append(int(ended_at_ns))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock, self._connect() as connection:
            count_row = connection.execute(
                f"SELECT COUNT(*) AS count FROM audit_events {where}",
                values,
            ).fetchone()
            rows = connection.execute(
                f"""
                SELECT id, created_at_ns, event_type, severity, source_ip,
                       device_id, request_type, outcome, bytes_count, details_json
                FROM audit_events
                {where}
                ORDER BY created_at_ns DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                [*values, max(1, min(int(limit), 200)), max(0, int(offset))],
            ).fetchall()
        return [_row_to_event(row) for row in rows], int(count_row["count"])

    def count_events(
        self,
        event_types: tuple[str, ...],
        *,
        since_ns: int,
        source_ip: str | None = None,
        outcomes: tuple[str, ...] | None = None,
    ) -> int:
        if not event_types:
            return 0
        clauses = [
            f"event_type IN ({','.join('?' for _ in event_types)})",
            "created_at_ns >= ?",
        ]
        values: list[Any] = [*event_types, int(since_ns)]
        if source_ip is not None:
            clauses.append("source_ip = ?")
            values.append(str(source_ip))
        if outcomes:
            clauses.append(f"outcome IN ({','.join('?' for _ in outcomes)})")
            values.extend(outcomes)
        with self._lock, self._connect() as connection:
            row = connection.execute(
                f"SELECT COUNT(*) AS count FROM audit_events WHERE {' AND '.join(clauses)}",
                values,
            ).fetchone()
        return int(row["count"])

    def transfer_totals(self, since_ns: int, source_ip: str) -> tuple[int, int]:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS count, COALESCE(SUM(bytes_count), 0) AS bytes
                FROM audit_events
                WHERE event_type IN ('file_received', 'file_sent')
                  AND created_at_ns >= ? AND source_ip = ?
                  AND outcome = 'success'
                """,
                (int(since_ns), str(source_ip)),
            ).fetchone()
        return int(row["count"]), int(row["bytes"])

    def prune(self) -> None:
        cutoff = time.time_ns() - self.retention_days * 86_400 * 1_000_000_000
        with self._lock, self._connect() as connection:
            connection.execute(
                "DELETE FROM audit_events WHERE created_at_ns < ?",
                (cutoff,),
            )
            connection.execute(
                "DELETE FROM audit_alerts WHERE created_at_ns < ?",
                (cutoff,),
            )

    def _detect_anomalies(self, event: AuditEvent) -> None:
        source = event.source_ip or event.device_id or "unknown"
        now = event.created_at_ns
        rules: list[tuple[str, str, int, int, tuple[str, ...]]] = [
            (
                "AUTH_FAILURE_BURST",
                "5 分钟内认证或配对失败达到 5 次。",
                300,
                5,
                ("authentication_failed", "pairing_failed"),
            ),
            (
                "MALFORMED_REQUEST_BURST",
                "1 分钟内畸形请求达到 10 次。",
                60,
                10,
                ("malformed_request",),
            ),
            (
                "CONNECTION_BURST",
                "1 分钟内连接次数达到 30 次。",
                60,
                30,
                ("connection_opened",),
            ),
            (
                "INDEX_READ_BURST",
                "5 分钟内索引读取达到 60 次。",
                300,
                60,
                ("index_read",),
            ),
        ]
        for code, message, window_seconds, threshold, event_types in rules:
            if event.event_type not in event_types:
                continue
            count = self.count_events(
                event_types,
                since_ns=now - window_seconds * 1_000_000_000,
                source_ip=event.source_ip,
            )
            if count >= threshold:
                self._create_alert(code, source, message, count)

        if event.event_type in {"file_received", "file_sent"}:
            count, bytes_count = self.transfer_totals(
                now - 3600 * 1_000_000_000,
                event.source_ip,
            )
            if count >= 100 or bytes_count >= 5 * 1024**3:
                self._create_alert(
                    "BULK_TRANSFER",
                    source,
                    "1 小时内传输达到 100 个文件或 5 GiB。",
                    count,
                    severity=SEVERITY_WARNING,
                )
        if event.event_type == "blocked_device_access":
            self._create_alert(
                "BLOCKED_DEVICE_ACCESS",
                source,
                "已阻止设备再次尝试访问。",
                1,
                severity=SEVERITY_ERROR,
            )

    def _create_alert(
        self,
        rule_code: str,
        source_key: str,
        message: str,
        event_count: int,
        *,
        severity: str = SEVERITY_ERROR,
    ) -> None:
        now = time.time_ns()
        with self._lock, self._connect() as connection:
            recent = connection.execute(
                """
                SELECT id FROM audit_alerts
                WHERE rule_code = ? AND source_key = ? AND created_at_ns >= ?
                LIMIT 1
                """,
                (rule_code, source_key, now - self.alert_cooldown_ns),
            ).fetchone()
            if recent is not None:
                return
            connection.execute(
                """
                INSERT INTO audit_alerts (
                    created_at_ns, rule_code, severity, source_key,
                    message, event_count, is_read
                ) VALUES (?, ?, ?, ?, ?, ?, 0)
                """,
                (now, rule_code, severity, source_key, message, int(event_count)),
            )
        self._logger.warning(
            "anomaly rule=%s source=%s count=%s message=%s",
            rule_code,
            source_key,
            event_count,
            message,
        )


def _sanitize(value: Any, key: str = "") -> Any:
    lowered = key.lower()
    if lowered in SENSITIVE_KEYS or any(
        marker in lowered for marker in ("secret", "credential")
    ):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(item_key): _sanitize(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _row_to_event(row: sqlite3.Row) -> AuditEvent:
    return AuditEvent(
        event_id=int(row["id"]),
        created_at_ns=int(row["created_at_ns"]),
        event_type=str(row["event_type"]),
        severity=str(row["severity"]),
        source_ip=str(row["source_ip"]),
        device_id=str(row["device_id"]),
        request_type=str(row["request_type"]),
        outcome=str(row["outcome"]),
        bytes_count=int(row["bytes_count"]),
        details=json.loads(str(row["details_json"])),
    )


def _row_to_alert(row: sqlite3.Row) -> AuditAlert:
    return AuditAlert(
        alert_id=int(row["id"]),
        created_at_ns=int(row["created_at_ns"]),
        rule_code=str(row["rule_code"]),
        severity=str(row["severity"]),
        source_key=str(row["source_key"]),
        message=str(row["message"]),
        event_count=int(row["event_count"]),
        read=bool(row["is_read"]),
    )
