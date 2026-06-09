from __future__ import annotations

import hashlib
import socket
import tempfile
import unittest
from pathlib import Path
from typing import Any

from transfer import TCPFileServer, TransferError, calculate_sha256, send_file
from transfer.protocol import (
    HASH_ALGORITHM,
    PROTOCOL_VERSION,
    recv_json_message,
    send_json_message,
)


def file_metadata(
    file_name: str,
    data: bytes,
    chunk_size: int,
    file_hash: str | None = None,
) -> dict[str, Any]:
    return {
        "type": "FILE_SEND",
        "protocol_version": PROTOCOL_VERSION,
        "file_name": file_name,
        "file_size": len(data),
        "file_hash": file_hash or hashlib.sha256(data).hexdigest(),
        "hash_algorithm": HASH_ALGORITHM,
        "chunk_size": chunk_size,
        "total_chunks": (len(data) + chunk_size - 1) // chunk_size,
    }


def chunk_metadata(index: int, data: bytes, chunk_hash: str | None = None) -> dict[str, Any]:
    return {
        "type": "CHUNK",
        "chunk_index": index,
        "chunk_size": len(data),
        "chunk_hash": chunk_hash or hashlib.sha256(data).hexdigest(),
    }


def assert_resume_request(
    test_case: unittest.TestCase,
    response: dict[str, Any],
) -> None:
    test_case.assertEqual(response["type"], "RESUME_REQUEST")
    test_case.assertEqual(
        response["missing_chunks"],
        list(range(response["total_chunks"])),
    )


class HashTests(unittest.TestCase):
    def test_calculate_sha256_for_known_content_and_empty_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            known = root / "known.txt"
            empty = root / "empty.bin"
            known.write_bytes(b"abc")
            empty.write_bytes(b"")

            self.assertEqual(
                calculate_sha256(known),
                "ba7816bf8f01cfea414140de5dae2223"
                "b00361a396177a9cb410ff61f20015ad",
            )
            self.assertEqual(
                calculate_sha256(empty),
                "e3b0c44298fc1c149afbf4c8996fb924"
                "27ae41e4649b934ca495991b7852b855",
            )


class ReliableTransferTests(unittest.TestCase):
    def test_large_file_hash_chunks_and_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "large.bin"
            received_dir = root / "received"
            chunk_size = 1024 * 1024

            with source.open("wb") as output:
                for value in range(8):
                    output.write(bytes([value]) * chunk_size)
                output.write(bytes(range(123)))

            progress: list[tuple[int, int]] = []
            server = TCPFileServer("127.0.0.1", 0, received_dir)
            server.start()
            try:
                result = send_file(
                    "127.0.0.1",
                    server.bound_port,
                    source,
                    chunk_size=chunk_size,
                    progress_callback=lambda current, total: progress.append(
                        (current, total)
                    ),
                )
            finally:
                server.stop()

            received = received_dir / source.name
            source_hash = calculate_sha256(source)
            self.assertEqual(source.stat().st_size, 8 * chunk_size + 123)
            self.assertEqual(result["status"], "success")
            self.assertEqual(result["chunks_received"], 9)
            self.assertEqual(result["file_hash"], source_hash)
            self.assertEqual(calculate_sha256(received), source_hash)
            self.assertEqual(progress[-1], (source.stat().st_size, source.stat().st_size))
            self.assertEqual(
                [current for current, _ in progress],
                sorted(current for current, _ in progress),
            )

    def test_empty_file_reports_complete_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "empty.bin"
            received_dir = root / "received"
            source.write_bytes(b"")

            progress: list[tuple[int, int]] = []
            server = TCPFileServer("127.0.0.1", 0, received_dir)
            server.start()
            try:
                result = send_file(
                    "127.0.0.1",
                    server.bound_port,
                    source,
                    progress_callback=lambda current, total: progress.append(
                        (current, total)
                    ),
                )
            finally:
                server.stop()

            self.assertEqual(progress, [(0, 0)])
            self.assertEqual(result["chunks_received"], 0)
            self.assertEqual(
                calculate_sha256(received_dir / "empty.bin"),
                calculate_sha256(source),
            )

    def test_file_changed_during_transfer_is_reported_and_discarded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "changing.bin"
            received_dir = root / "received"
            chunk_size = 1024 * 1024
            source.write_bytes(b"A" * chunk_size + b"B" * chunk_size)
            changed = False

            def change_second_chunk(transferred: int, total: int) -> None:
                nonlocal changed
                if changed or transferred != chunk_size:
                    return
                with source.open("r+b") as output:
                    output.seek(chunk_size)
                    output.write(b"C" * chunk_size)
                changed = True

            server = TCPFileServer("127.0.0.1", 0, received_dir)
            server.start()
            try:
                with self.assertRaises(TransferError) as raised:
                    send_file(
                        "127.0.0.1",
                        server.bound_port,
                        source,
                        chunk_size=chunk_size,
                        progress_callback=change_second_chunk,
                    )
            finally:
                server.stop()

            self.assertTrue(changed)
            self.assertEqual(raised.exception.code, "FILE_CHANGED")
            self.assertEqual(list(received_dir.iterdir()), [])


class ProtocolFailureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.received_dir = self.root / "received"
        self.server = TCPFileServer("127.0.0.1", 0, self.received_dir)
        self.server.start()

    def tearDown(self) -> None:
        self.server.stop()
        self.temp_dir.cleanup()

    def connect(self) -> socket.socket:
        sock = socket.create_connection(("127.0.0.1", self.server.bound_port))
        sock.settimeout(5.0)
        return sock

    def assert_no_received_files(self) -> None:
        self.assertEqual(list(self.received_dir.iterdir()), [])

    def test_invalid_protocol_version_is_rejected(self) -> None:
        metadata = file_metadata("invalid.bin", b"x", 1)
        metadata["protocol_version"] = 1

        with self.connect() as sock:
            send_json_message(sock, metadata)
            response = recv_json_message(sock)

        self.assertEqual(response["type"], "TRANSFER_ERROR")
        self.assertEqual(response["error_code"], "PROTOCOL_INCOMPATIBLE")
        self.assert_no_received_files()

    def test_wrong_chunk_hash_is_rejected_and_temp_file_removed(self) -> None:
        data = b"chunk-content"
        with self.connect() as sock:
            send_json_message(sock, file_metadata("bad-chunk.bin", data, len(data)))
            assert_resume_request(self, recv_json_message(sock))
            send_json_message(sock, chunk_metadata(0, data, "0" * 64))
            sock.sendall(data)
            response = recv_json_message(sock)

        self.assertEqual(response["error_code"], "CHUNK_HASH_MISMATCH")
        self.assertEqual(response["chunk_index"], 0)
        self.assert_no_received_files()

    def test_wrong_file_hash_is_rejected_and_temp_file_removed(self) -> None:
        data = b"complete-but-declared-wrong"
        with self.connect() as sock:
            send_json_message(
                sock,
                file_metadata("bad-file.bin", data, len(data), "0" * 64),
            )
            assert_resume_request(self, recv_json_message(sock))
            send_json_message(sock, chunk_metadata(0, data))
            sock.sendall(data)
            self.assertEqual(recv_json_message(sock)["type"], "CHUNK_ACK")
            response = recv_json_message(sock)

        self.assertEqual(response["error_code"], "FILE_HASH_MISMATCH")
        self.assert_no_received_files()

    def test_out_of_order_chunk_is_rejected(self) -> None:
        data = b"ordered"
        with self.connect() as sock:
            send_json_message(sock, file_metadata("order.bin", data, len(data)))
            assert_resume_request(self, recv_json_message(sock))
            send_json_message(sock, chunk_metadata(1, data))
            response = recv_json_message(sock)

        self.assertEqual(response["error_code"], "CHUNK_OUT_OF_ORDER")
        self.assert_no_received_files()

    def test_truncated_chunk_is_rejected_and_temp_file_removed(self) -> None:
        data = b"abcdefgh"
        with self.connect() as sock:
            send_json_message(sock, file_metadata("truncated.bin", data, len(data)))
            assert_resume_request(self, recv_json_message(sock))
            send_json_message(sock, chunk_metadata(0, data))
            sock.sendall(data[:3])
            sock.shutdown(socket.SHUT_WR)
            response = recv_json_message(sock)

        self.assertEqual(response["error_code"], "TRANSFER_INCOMPLETE")
        self.assert_no_received_files()


if __name__ == "__main__":
    unittest.main()
