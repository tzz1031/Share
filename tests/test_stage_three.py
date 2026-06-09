from __future__ import annotations

import json
import socket
import tempfile
import unittest
from pathlib import Path

from transfer import TCPFileServer, calculate_sha256, send_file
from transfer.protocol import recv_json_message, send_json_message
from tests.test_stage_two import chunk_metadata, file_metadata


class ResumeTransferTests(unittest.TestCase):
    def test_interrupted_transfer_resumes_after_server_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "large-resume.bin"
            received_dir = root / "received"
            chunk_size = 256 * 1024
            chunks = [
                bytes([value]) * chunk_size
                for value in range(5)
            ]
            source.write_bytes(b"".join(chunks) + b"last-block")
            data = source.read_bytes()
            metadata = file_metadata(source.name, data, chunk_size)

            first_server = TCPFileServer("127.0.0.1", 0, received_dir)
            first_server.start()
            try:
                with socket.create_connection(
                    ("127.0.0.1", first_server.bound_port),
                    timeout=5.0,
                ) as sock:
                    sock.settimeout(5.0)
                    send_json_message(sock, metadata)
                    request = recv_json_message(sock)
                    self.assertEqual(request["type"], "RESUME_REQUEST")
                    self.assertEqual(request["missing_chunks"], list(range(6)))

                    for index in range(2):
                        chunk = chunks[index]
                        send_json_message(sock, chunk_metadata(index, chunk))
                        sock.sendall(chunk)
                        acknowledgement = recv_json_message(sock)
                        self.assertEqual(acknowledgement["chunk_index"], index)
                    first_server.stop()
            finally:
                first_server.stop()

            state_files = list(received_dir.glob(".incoming-*.state.json"))
            part_files = list(received_dir.glob(".incoming-*.part"))
            self.assertEqual(len(state_files), 1)
            self.assertEqual(len(part_files), 1)
            saved_state = json.loads(state_files[0].read_text(encoding="utf-8"))
            self.assertEqual(saved_state["received_chunks"], [0, 1])

            progress: list[tuple[int, int]] = []
            second_server = TCPFileServer("127.0.0.1", 0, received_dir)
            second_server.start()
            try:
                result = send_file(
                    "127.0.0.1",
                    second_server.bound_port,
                    source,
                    chunk_size=chunk_size,
                    progress_callback=lambda current, total: progress.append(
                        (current, total)
                    ),
                )
            finally:
                second_server.stop()

            self.assertEqual(result["resumed_chunks"], 2)
            self.assertEqual(result["chunks_transferred"], 4)
            self.assertEqual(progress[0], (2 * chunk_size, len(data)))
            self.assertEqual(progress[-1], (len(data), len(data)))
            self.assertEqual(
                calculate_sha256(received_dir / source.name),
                calculate_sha256(source),
            )
            self.assertEqual(
                list(received_dir.glob(".incoming-*.state.json")),
                [],
            )
            self.assertEqual(list(received_dir.glob(".incoming-*.part")), [])


if __name__ == "__main__":
    unittest.main()
