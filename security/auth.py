from __future__ import annotations

import hmac
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .tls import normalize_fingerprint


PERMISSION_BLOCKED = "blocked"
PERMISSION_READ = "read"
PERMISSION_WRITE = "write"
PERMISSION_ADMIN = "admin"
VALID_PERMISSIONS = {
    PERMISSION_BLOCKED,
    PERMISSION_READ,
    PERMISSION_WRITE,
    PERMISSION_ADMIN,
}
PERMISSION_RANK = {
    PERMISSION_BLOCKED: 0,
    PERMISSION_READ: 1,
    PERMISSION_WRITE: 2,
    PERMISSION_ADMIN: 3,
}


class AuthorizationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class AuthCredential:
    device_id: str
    token: str

    def to_payload(self) -> dict[str, str]:
        return {
            "auth_device_id": self.device_id,
            "auth_token": self.token,
        }


@dataclass(frozen=True)
class AuthorizedDevice:
    device_id: str
    device_name: str
    token: str
    permission: str
    paired_at_ns: int
    last_authenticated_at_ns: int | None
    certificate_fingerprint: str | None = None


class SecurityStore:
    def __init__(
        self,
        shared_folder: str | Path,
        audit_store: Any | None = None,
    ) -> None:
        root = Path(shared_folder)
        self.internal_folder = root / ".lan-sync"
        self.database_path = self.internal_folder / "security.sqlite3"
        self.audit_store = audit_store
        self._lock = threading.RLock()
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
                CREATE TABLE IF NOT EXISTS security_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS authorized_devices (
                    device_id TEXT PRIMARY KEY,
                    device_name TEXT NOT NULL,
                    token TEXT NOT NULL,
                    permission TEXT NOT NULL,
                    paired_at_ns INTEGER NOT NULL,
                    last_authenticated_at_ns INTEGER,
                    certificate_fingerprint TEXT
                )
                """
            )
            columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(authorized_devices)"
                )
            }
            if "certificate_fingerprint" not in columns:
                connection.execute(
                    """
                    ALTER TABLE authorized_devices
                    ADD COLUMN certificate_fingerprint TEXT
                    """
                )
            row = connection.execute(
                "SELECT value FROM security_settings WHERE key = 'pair_code'"
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO security_settings (key, value) VALUES ('pair_code', ?)",
                    (self._new_pair_code(),),
                )

    @staticmethod
    def _new_pair_code() -> str:
        return f"{secrets.randbelow(1_000_000):06d}"

    @property
    def pair_code(self) -> str:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT value FROM security_settings WHERE key = 'pair_code'"
            ).fetchone()
        if row is None:
            raise RuntimeError("pair code is not initialized")
        return str(row["value"])

    def regenerate_pair_code(self) -> str:
        pair_code = self._new_pair_code()
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO security_settings (key, value)
                VALUES ('pair_code', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (pair_code,),
            )
        return pair_code

    def verify_pair_code(self, pair_code: str) -> bool:
        return hmac.compare_digest(self.pair_code, str(pair_code))

    @staticmethod
    def generate_token() -> str:
        return secrets.token_urlsafe(32)

    def authorize_device(
        self,
        device_id: str,
        device_name: str,
        token: str,
        permission: str = PERMISSION_WRITE,
        certificate_fingerprint: str | None = None,
    ) -> AuthorizedDevice:
        device_id = str(device_id).strip()
        device_name = str(device_name).strip() or "Unknown"
        token = str(token).strip()
        if not device_id:
            raise ValueError("device_id must not be empty")
        if not token:
            raise ValueError("token must not be empty")
        if permission not in VALID_PERMISSIONS:
            raise ValueError("invalid permission")
        fingerprint = normalize_fingerprint(certificate_fingerprint)

        paired_at_ns = time.time_ns()
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO authorized_devices (
                    device_id, device_name, token, permission,
                    paired_at_ns, last_authenticated_at_ns,
                    certificate_fingerprint
                ) VALUES (?, ?, ?, ?, ?, NULL, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    device_name = excluded.device_name,
                    token = excluded.token,
                    permission = excluded.permission,
                    paired_at_ns = excluded.paired_at_ns,
                    last_authenticated_at_ns = NULL,
                    certificate_fingerprint = excluded.certificate_fingerprint
                """,
                (
                    device_id,
                    device_name,
                    token,
                    permission,
                    paired_at_ns,
                    fingerprint,
                ),
            )
        device = self.get_device(device_id)
        assert device is not None
        return device

    def get_device(self, device_id: str) -> AuthorizedDevice | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                """
                SELECT device_id, device_name, token, permission,
                       paired_at_ns, last_authenticated_at_ns,
                       certificate_fingerprint
                FROM authorized_devices
                WHERE device_id = ?
                """,
                (str(device_id),),
            ).fetchone()
        return self._row_to_device(row) if row is not None else None

    def list_devices(self) -> list[AuthorizedDevice]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT device_id, device_name, token, permission,
                       paired_at_ns, last_authenticated_at_ns,
                       certificate_fingerprint
                FROM authorized_devices
                ORDER BY lower(device_name), device_id
                """
            ).fetchall()
        return [self._row_to_device(row) for row in rows]

    def credential_for(
        self,
        remote_device_id: str,
        local_device_id: str,
    ) -> AuthCredential | None:
        device = self.get_device(remote_device_id)
        if device is None or device.permission == PERMISSION_BLOCKED:
            return None
        return AuthCredential(device_id=str(local_device_id), token=device.token)

    def authenticate(
        self,
        device_id: str,
        token: str,
        required_permission: str,
    ) -> AuthorizedDevice:
        if required_permission not in {
            PERMISSION_READ,
            PERMISSION_WRITE,
            PERMISSION_ADMIN,
        }:
            raise ValueError("invalid required permission")

        device = self.get_device(str(device_id))
        if device is None:
            raise AuthorizationError("AUTH_REQUIRED", "设备尚未配对。")
        if not hmac.compare_digest(device.token, str(token)):
            raise AuthorizationError("AUTH_FAILED", "设备访问令牌无效。")
        if device.permission == PERMISSION_BLOCKED:
            raise AuthorizationError("AUTH_BLOCKED", "设备已被阻止访问。")
        if PERMISSION_RANK[device.permission] < PERMISSION_RANK[required_permission]:
            raise AuthorizationError(
                "PERMISSION_DENIED",
                f"该操作需要 {required_permission} 权限。",
            )

        authenticated_at_ns = time.time_ns()
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                UPDATE authorized_devices
                SET last_authenticated_at_ns = ?
                WHERE device_id = ?
                """,
                (authenticated_at_ns, device.device_id),
            )
        return AuthorizedDevice(
            device_id=device.device_id,
            device_name=device.device_name,
            token=device.token,
            permission=device.permission,
            paired_at_ns=device.paired_at_ns,
            last_authenticated_at_ns=authenticated_at_ns,
            certificate_fingerprint=device.certificate_fingerprint,
        )

    def set_permission(self, device_id: str, permission: str) -> None:
        if permission not in VALID_PERMISSIONS:
            raise ValueError("invalid permission")
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE authorized_devices
                SET permission = ?
                WHERE device_id = ?
                """,
                (permission, str(device_id)),
            )
        if cursor.rowcount == 0:
            raise KeyError(device_id)
        self._audit(
            "permission_changed",
            device_id=str(device_id),
            details={"permission": permission},
        )

    def revoke(self, device_id: str) -> bool:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM authorized_devices WHERE device_id = ?",
                (str(device_id),),
            )
        revoked = cursor.rowcount > 0
        if revoked:
            self._audit("authorization_revoked", device_id=str(device_id))
        return revoked

    def trusted_fingerprint(self, remote_device_id: str) -> str | None:
        device = self.get_device(remote_device_id)
        return device.certificate_fingerprint if device is not None else None

    @staticmethod
    def _row_to_device(row: sqlite3.Row) -> AuthorizedDevice:
        raw_last_authenticated = row["last_authenticated_at_ns"]
        raw_fingerprint = row["certificate_fingerprint"]
        return AuthorizedDevice(
            device_id=str(row["device_id"]),
            device_name=str(row["device_name"]),
            token=str(row["token"]),
            permission=str(row["permission"]),
            paired_at_ns=int(row["paired_at_ns"]),
            last_authenticated_at_ns=(
                int(raw_last_authenticated)
                if raw_last_authenticated is not None
                else None
            ),
            certificate_fingerprint=(
                str(raw_fingerprint) if raw_fingerprint is not None else None
            ),
        )

    def _audit(
        self,
        event_type: str,
        *,
        device_id: str = "",
        details: dict[str, Any] | None = None,
    ) -> None:
        if self.audit_store is not None:
            self.audit_store.record_event(
                event_type,
                device_id=device_id,
                details=details,
            )
