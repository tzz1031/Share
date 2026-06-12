from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any


class AgentRunStore:
    def __init__(self, shared_folder: str | Path) -> None:
        internal = Path(shared_folder) / ".lan-sync"
        internal.mkdir(parents=True, exist_ok=True)
        self.database_path = internal / "agent-runs.sqlite3"
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=30.0)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS agent_runs (
                    run_id TEXT PRIMARY KEY,
                    thread_id TEXT NOT NULL,
                    request TEXT NOT NULL,
                    status TEXT NOT NULL,
                    plan_id TEXT,
                    report TEXT NOT NULL DEFAULT '',
                    error TEXT NOT NULL DEFAULT '',
                    created_at_ns INTEGER NOT NULL,
                    updated_at_ns INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_agent_runs_thread
                ON agent_runs(thread_id, created_at_ns);

                CREATE TABLE IF NOT EXISTS agent_steps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    created_at_ns INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    input_json TEXT NOT NULL,
                    output_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_agent_steps_run
                ON agent_steps(run_id, id);

                CREATE TABLE IF NOT EXISTS sync_plans (
                    plan_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at_ns INTEGER NOT NULL,
                    updated_at_ns INTEGER NOT NULL
                );
                """
            )

    def create_run(
        self,
        run_id: str,
        thread_id: str,
        request: str,
        status: str = "queued",
    ) -> None:
        now = time.time_ns()
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO agent_runs (
                    run_id, thread_id, request, status,
                    created_at_ns, updated_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (run_id, thread_id, request, status, now, now),
            )

    def update_run(self, run_id: str, **changes: Any) -> None:
        allowed = {"status", "plan_id", "report", "error"}
        values = {key: value for key, value in changes.items() if key in allowed}
        if not values:
            return
        values["updated_at_ns"] = time.time_ns()
        assignments = ", ".join(f"{key} = ?" for key in values)
        with self._lock, self._connect() as connection:
            connection.execute(
                f"UPDATE agent_runs SET {assignments} WHERE run_id = ?",
                (*values.values(), run_id),
            )

    def append_step(
        self,
        run_id: str,
        *,
        kind: str,
        name: str,
        status: str,
        input_data: Any = None,
        output_data: Any = None,
    ) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO agent_steps (
                    run_id, created_at_ns, kind, name, status,
                    input_json, output_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    time.time_ns(),
                    str(kind),
                    str(name),
                    str(status),
                    json.dumps(input_data, ensure_ascii=False, default=str),
                    json.dumps(output_data, ensure_ascii=False, default=str),
                ),
            )

    def save_plan(self, plan_id: str, run_id: str, payload: dict[str, Any]) -> None:
        now = time.time_ns()
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO sync_plans (
                    plan_id, run_id, payload_json, created_at_ns, updated_at_ns
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(plan_id) DO UPDATE SET
                    payload_json = excluded.payload_json,
                    updated_at_ns = excluded.updated_at_ns
                """,
                (plan_id, run_id, encoded, now, now),
            )
        self.update_run(run_id, plan_id=plan_id)

    def load_plan(self, plan_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT payload_json FROM sync_plans WHERE plan_id = ?",
                (plan_id,),
            ).fetchone()
        return json.loads(row["payload_json"]) if row is not None else None

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM agent_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            steps = connection.execute(
                """
                SELECT created_at_ns, kind, name, status,
                       input_json, output_json
                FROM agent_steps
                WHERE run_id = ?
                ORDER BY id
                """,
                (run_id,),
            ).fetchall()
        if row is None:
            return None
        payload = dict(row)
        payload["steps"] = [
            {
                "created_at_ns": int(step["created_at_ns"]),
                "kind": str(step["kind"]),
                "name": str(step["name"]),
                "status": str(step["status"]),
                "input": json.loads(step["input_json"]),
                "output": json.loads(step["output_json"]),
            }
            for step in steps
        ]
        payload["plan"] = (
            self.load_plan(str(row["plan_id"])) if row["plan_id"] else None
        )
        payload["messages"] = [{"role": "user", "content": str(row["request"])}]
        if row["report"]:
            payload["messages"].append(
                {"role": "assistant", "content": str(row["report"])}
            )
        return payload

    def list_threads(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT r.*
                FROM agent_runs r
                JOIN (
                    SELECT thread_id, MAX(created_at_ns) AS latest
                    FROM agent_runs
                    GROUP BY thread_id
                ) t ON t.thread_id = r.thread_id
                   AND t.latest = r.created_at_ns
                ORDER BY r.created_at_ns DESC
                LIMIT ?
                """,
                (max(1, min(int(limit), 200)),),
            ).fetchall()
        return [
            {
                "thread_id": str(row["thread_id"]),
                "latest_run_id": str(row["run_id"]),
                "title": str(row["request"])[:80],
                "status": str(row["status"]),
                "updated_at_ns": int(row["updated_at_ns"]),
            }
            for row in rows
        ]

    def thread_context(
        self,
        thread_id: str,
        *,
        exclude_run_id: str = "",
        limit: int = 6,
    ) -> list[dict[str, str]]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT run_id, request, report
                FROM agent_runs
                WHERE thread_id = ?
                ORDER BY created_at_ns DESC
                LIMIT ?
                """,
                (str(thread_id), max(1, min(int(limit) + 1, 20))),
            ).fetchall()
        messages: list[dict[str, str]] = []
        for row in reversed(rows):
            if exclude_run_id and row["run_id"] == exclude_run_id:
                continue
            messages.append({"role": "user", "content": str(row["request"])})
            if row["report"]:
                messages.append(
                    {"role": "assistant", "content": str(row["report"])}
                )
        return messages[-limit * 2 :]
