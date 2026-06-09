from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


STATE_VERSION = 1
STATE_SUFFIX = ".state.json"
PART_SUFFIX = ".part"


def transfer_id_for(metadata: dict[str, Any]) -> str:
    identity = {
        "transfer_mode": metadata.get("transfer_mode", "manual"),
        "relative_path": metadata.get("relative_path"),
        "file_name": metadata["file_name"],
        "file_size": metadata["file_size"],
        "file_hash": metadata["file_hash"],
        "chunk_size": metadata["chunk_size"],
        "total_chunks": metadata["total_chunks"],
    }
    encoded = json.dumps(
        identity,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass
class ResumeState:
    transfer_id: str
    state_path: Path
    part_path: Path
    protocol_version: int
    file_name: str
    transfer_mode: str
    relative_path: str | None
    file_size: int
    file_hash: str
    chunk_size: int
    total_chunks: int
    received_chunks: set[int] = field(default_factory=set)

    @classmethod
    def open(
        cls,
        folder: Path,
        metadata: dict[str, Any],
        protocol_version: int,
    ) -> "ResumeState":
        transfer_id = transfer_id_for(metadata)
        state = cls(
            transfer_id=transfer_id,
            state_path=folder / f".incoming-{transfer_id}{STATE_SUFFIX}",
            part_path=folder / f".incoming-{transfer_id}{PART_SUFFIX}",
            protocol_version=protocol_version,
            file_name=metadata["file_name"],
            transfer_mode=metadata.get("transfer_mode", "manual"),
            relative_path=metadata.get("relative_path"),
            file_size=metadata["file_size"],
            file_hash=metadata["file_hash"],
            chunk_size=metadata["chunk_size"],
            total_chunks=metadata["total_chunks"],
        )

        if state._load_existing():
            return state

        state.discard()
        with state.part_path.open("w+b") as output:
            output.truncate(state.file_size)
            output.flush()
            os.fsync(output.fileno())
        state.persist()
        return state

    @property
    def missing_chunks(self) -> list[int]:
        return [
            chunk_index
            for chunk_index in range(self.total_chunks)
            if chunk_index not in self.received_chunks
        ]

    @property
    def bytes_received(self) -> int:
        return sum(self.chunk_size_at(index) for index in self.received_chunks)

    def chunk_size_at(self, chunk_index: int) -> int:
        if chunk_index < 0 or chunk_index >= self.total_chunks:
            raise ValueError(f"invalid chunk index: {chunk_index}")
        offset = chunk_index * self.chunk_size
        return min(self.chunk_size, self.file_size - offset)

    def record_chunk(self, chunk_index: int) -> None:
        self.received_chunks.add(chunk_index)
        self.persist()

    def persist(self) -> None:
        payload = self._expected_payload()
        payload["received_chunks"] = sorted(self.received_chunks)
        temporary_path = self.state_path.with_name(self.state_path.name + ".tmp")
        with temporary_path.open("w", encoding="utf-8") as output:
            json.dump(payload, output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, self.state_path)

    def remove_state_file(self) -> None:
        self._unlink(self.state_path)
        self._unlink(self.state_path.with_name(self.state_path.name + ".tmp"))

    def discard(self) -> None:
        self.remove_state_file()
        self._unlink(self.part_path)

    def _load_existing(self) -> bool:
        if not self.state_path.is_file() or not self.part_path.is_file():
            return False

        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                return False
            expected = self._expected_payload()
            if any(payload.get(key) != value for key, value in expected.items()):
                return False
            if self.part_path.stat().st_size != self.file_size:
                return False

            raw_chunks = payload.get("received_chunks")
            if not isinstance(raw_chunks, list):
                return False
            if any(type(index) is not int for index in raw_chunks):
                return False

            received_chunks = set(raw_chunks)
            if len(received_chunks) != len(raw_chunks):
                return False
            if any(
                index < 0 or index >= self.total_chunks
                for index in received_chunks
            ):
                return False
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return False

        self.received_chunks = received_chunks
        return True

    def _expected_payload(self) -> dict[str, Any]:
        return {
            "state_version": STATE_VERSION,
            "protocol_version": self.protocol_version,
            "transfer_id": self.transfer_id,
            "file_name": self.file_name,
            "transfer_mode": self.transfer_mode,
            "relative_path": self.relative_path,
            "file_size": self.file_size,
            "file_hash": self.file_hash,
            "chunk_size": self.chunk_size,
            "total_chunks": self.total_chunks,
            "part_file": self.part_path.name,
        }

    @staticmethod
    def _unlink(path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
