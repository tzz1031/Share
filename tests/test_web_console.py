from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from dataclasses import dataclass
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from runtime import AppRuntime, EventBus
from webapp import CSRF_HEADER, create_app


def write_config(root: Path) -> Path:
    config_path = root / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "device_name": "Test Node",
                "udp_port": 0,
                "tcp_port": 0,
                "broadcast_ip": "127.0.0.1",
                "shared_folder": "./shared",
                "chunk_size": 4096,
                "enable_tls": False,
                "sync_enabled": False,
                "sync_interval_seconds": 10,
                "security_audit_interval_seconds": 600,
                "audit_log_retention_days": 30,
                "shared_size_risk_bytes": 1024,
                "shared_file_count_risk": 100,
                "web_port": 8765,
            }
        ),
        encoding="utf-8",
    )
    return config_path


@dataclass
class ASGIResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)


async def asgi_request(
    app,
    method: str,
    path: str,
    *,
    query: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> ASGIResponse:
    request_messages = [
        {"type": "http.request", "body": body, "more_body": False}
    ]
    response_messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        if request_messages:
            return request_messages.pop(0)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        response_messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method.upper(),
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": urlencode(query or {}).encode("ascii"),
        "root_path": "",
        "headers": [
            (key.lower().encode("latin-1"), value.encode("latin-1"))
            for key, value in (headers or {}).items()
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8765),
    }
    await app(scope, receive, send)
    start = next(
        item
        for item in response_messages
        if item["type"] == "http.response.start"
    )
    response_headers = {
        key.decode("latin-1"): value.decode("latin-1")
        for key, value in start["headers"]
    }
    response_body = b"".join(
        item.get("body", b"")
        for item in response_messages
        if item["type"] == "http.response.body"
    )
    return ASGIResponse(
        status_code=int(start["status"]),
        headers=response_headers,
        body=response_body,
    )


class WebConsoleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.runtime = AppRuntime(write_config(self.root))
        self.app = create_app(self.runtime, manage_runtime=False)
        session = self.request("GET", "/api/session")
        self.assertEqual(session.status_code, 200)
        self.assertEqual(session.headers["cache-control"], "no-store")
        self.assertEqual(session.headers["x-frame-options"], "DENY")
        self.csrf = session.json()["csrf_token"]
        cookie = SimpleCookie()
        cookie.load(session.headers["set-cookie"])
        self.session_cookie = (
            f"lan_sync_session={cookie['lan_sync_session'].value}"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> ASGIResponse:
        request_headers = dict(headers or {})
        if hasattr(self, "session_cookie"):
            request_headers.setdefault("Cookie", self.session_cookie)
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        return asyncio.run(
            asgi_request(
                self.app,
                method,
                path,
                query=query,
                headers=request_headers,
                body=body,
            )
        )

    def test_csrf_and_settings_restart_marker(self) -> None:
        rejected = self.request(
            "PATCH",
            "/api/settings",
            json_body={"sync_interval_seconds": 12},
        )
        self.assertEqual(rejected.status_code, 403)

        immediate = self.request(
            "PATCH",
            "/api/settings",
            headers={CSRF_HEADER: self.csrf},
            json_body={"sync_interval_seconds": 12},
        )
        self.assertEqual(immediate.status_code, 200)
        self.assertFalse(immediate.json()["pending_restart"])
        self.assertEqual(immediate.json()["active"]["sync_interval_seconds"], 12)

        restart = self.request(
            "PATCH",
            "/api/settings",
            headers={CSRF_HEADER: self.csrf},
            json_body={"device_name": "Renamed Node"},
        )
        self.assertEqual(restart.status_code, 200)
        self.assertTrue(restart.json()["pending_restart"])
        self.assertEqual(
            restart.json()["configured"]["device_name"],
            "Renamed Node",
        )
        self.assertEqual(
            restart.json()["active"]["device_name"],
            "Test Node",
        )

    def test_failed_upload_is_cleaned_up(self) -> None:
        response = self.request(
            "POST",
            "/api/transfers/upload",
            query={"device_id": "missing"},
            headers={
                CSRF_HEADER: self.csrf,
                "X-File-Name": "example.txt",
                "Content-Type": "application/octet-stream",
            },
            body=b"payload",
        )
        self.assertEqual(response.status_code, 404)
        upload_dir = (
            self.runtime.config.shared_folder / ".lan-sync" / "uploads"
        )
        self.assertEqual(list(upload_dir.iterdir()), [])

    def test_transfer_observer(self) -> None:
        common = {
            "kind": "sync",
            "device_id": "peer",
            "relative_path": "docs/report.txt",
            "total_bytes": 10,
        }
        self.runtime.transfers.observe_event("transfer_queued", common)
        self.runtime.transfers.observe_event(
            "transfer_progress",
            {**common, "transferred_bytes": 5},
        )
        self.runtime.transfers.observe_event("transfer_completed", common)
        task = self.runtime.transfers.list_tasks(1)[0]
        self.assertEqual(task["status"], "success")
        self.assertEqual(task["progress"], 100.0)

    def test_log_filters_accept_time_range(self) -> None:
        first = self.runtime.audit_store.record_event(
            "pairing_succeeded",
            device_id="peer-a",
        )
        second = self.runtime.audit_store.record_event(
            "file_sent",
            device_id="peer-b",
        )
        response = self.request(
            "GET",
            "/api/logs",
            query={
                "device_id": "peer-b",
                "started_at_ns": first.created_at_ns + 1,
                "ended_at_ns": second.created_at_ns,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["total"], 1)
        self.assertEqual(response.json()["items"][0]["event_type"], "file_sent")

    def test_alert_can_be_marked_read_by_id(self) -> None:
        self.runtime.audit_store._create_alert(
            "TEST_ALERT",
            "127.0.0.1",
            "测试告警",
            1,
        )
        alert = self.runtime.audit_store.recent_alerts(1)[0]
        response = self.request(
            "POST",
            f"/api/security/alerts/{alert.alert_id}/read",
            headers={CSRF_HEADER: self.csrf},
        )
        self.assertEqual(response.status_code, 200)
        refreshed = self.runtime.audit_store.recent_alerts(1)[0]
        self.assertTrue(refreshed.read)


class EventBusTests(unittest.TestCase):
    def test_event_bus_delivers_to_subscribers(self) -> None:
        bus = EventBus()
        subscriber = bus.subscribe()
        bus.publish("runtime_started", {"running": True})
        self.assertEqual(subscriber.get_nowait()["payload"], {"running": True})
        bus.unsubscribe(subscriber)


if __name__ == "__main__":
    unittest.main()
