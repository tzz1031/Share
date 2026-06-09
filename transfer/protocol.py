from __future__ import annotations

import json
import socket
import string
import struct
from typing import Any


HEADER_SIZE = 4
MAX_METADATA_BYTES = 64 * 1024
PROTOCOL_VERSION = 6
HASH_ALGORITHM = "sha256"
MIN_CHUNK_SIZE = 1
MAX_CHUNK_SIZE = 64 * 1024 * 1024
SHA256_HEX_LENGTH = 64


class TransferError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        chunk_index: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.chunk_index = chunk_index

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "type": "TRANSFER_ERROR",
            "status": "error",
            "error_code": self.code,
            "message": self.message,
        }
        if self.chunk_index is not None:
            payload["chunk_index"] = self.chunk_index
        return payload

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "TransferError":
        raw_chunk_index = payload.get("chunk_index")
        chunk_index = (
            raw_chunk_index
            if type(raw_chunk_index) is int and raw_chunk_index >= 0
            else None
        )
        return cls(
            code=str(payload.get("error_code", "REMOTE_ERROR")),
            message=str(payload.get("message", "接收端返回未知错误")),
            chunk_index=chunk_index,
        )


def validate_chunk_size(chunk_size: int) -> int:
    if type(chunk_size) is not int:
        raise ValueError("chunk_size must be an integer")
    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise ValueError(
            f"chunk_size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE} bytes"
        )
    return chunk_size


def is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != SHA256_HEX_LENGTH:
        return False
    return all(character in string.hexdigits for character in value)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connection closed before enough data was received")
        data.extend(chunk)
    return bytes(data)


def send_json_message(sock: socket.socket, payload: dict[str, Any]) -> None:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if len(data) > MAX_METADATA_BYTES:
        raise ValueError("metadata is too large")
    sock.sendall(struct.pack("!I", len(data)))
    sock.sendall(data)


def recv_json_message(sock: socket.socket) -> dict[str, Any]:
    raw_size = recv_exact(sock, HEADER_SIZE)
    size = struct.unpack("!I", raw_size)[0]
    if size <= 0 or size > MAX_METADATA_BYTES:
        raise ValueError(f"invalid metadata size: {size}")
    data = recv_exact(sock, size)
    payload = json.loads(data.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("metadata must be a JSON object")
    return payload
