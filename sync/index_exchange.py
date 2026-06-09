from __future__ import annotations

from security import AuthCredential, TLSPolicy, open_connection
from transfer.protocol import PROTOCOL_VERSION, recv_json_message, send_json_message

from .file_index import FileEntry


def request_file_index(
    target_ip: str,
    target_port: int,
    timeout: float = 15.0,
    credential: AuthCredential | None = None,
    requester_device_id: str | None = None,
    tls_policy: TLSPolicy | None = None,
) -> list[FileEntry]:
    with open_connection(
        target_ip,
        target_port,
        timeout,
        tls_policy,
    ) as sock:
        sock.settimeout(timeout)
        request = {
            "type": "INDEX_REQUEST",
            "protocol_version": PROTOCOL_VERSION,
        }
        if credential is not None:
            request.update(credential.to_payload())
        elif requester_device_id is not None:
            request["auth_device_id"] = str(requester_device_id)
        send_json_message(sock, request)
        begin = recv_json_message(sock)
        if begin.get("type") == "TRANSFER_ERROR":
            raise ValueError(str(begin.get("message", "remote index request failed")))
        if (
            begin.get("type") != "INDEX_BEGIN"
            or begin.get("protocol_version") != PROTOCOL_VERSION
            or type(begin.get("entry_count")) is not int
            or begin["entry_count"] < 0
        ):
            raise ValueError("remote returned an invalid index header")

        entries: list[FileEntry] = []
        while True:
            message = recv_json_message(sock)
            message_type = message.get("type")
            if message_type == "INDEX_END":
                if message.get("protocol_version") != PROTOCOL_VERSION:
                    raise ValueError("remote returned an invalid index footer")
                break
            if message_type != "INDEX_ENTRY" or not isinstance(
                message.get("entry"),
                dict,
            ):
                raise ValueError("remote returned an invalid index entry")
            entries.append(FileEntry.from_payload(message["entry"]))

        if len(entries) != begin["entry_count"]:
            raise ValueError("remote index entry count does not match")
        return entries
