from __future__ import annotations

from typing import Any

from .tls import (
    TLSIdentity,
    TLSPolicy,
    certificate_fingerprint,
    normalize_fingerprint,
    open_connection,
)
from transfer.protocol import (
    PROTOCOL_VERSION,
    TransferError,
    recv_json_message,
    send_json_message,
)

from .auth import PERMISSION_WRITE, SecurityStore


def pair_with_device(
    target_ip: str,
    target_port: int,
    *,
    pair_code: str,
    local_device_id: str,
    local_device_name: str,
    security_store: SecurityStore,
    timeout: float = 15.0,
    tls_policy: TLSPolicy | None = None,
    local_tls_identity: TLSIdentity | None = None,
) -> dict[str, Any]:
    token = security_store.generate_token()
    pairing_policy = tls_policy
    if pairing_policy is not None and pairing_policy.enabled:
        pairing_policy = TLSPolicy(
            enabled=True,
            expected_fingerprint=pairing_policy.expected_fingerprint,
            allow_untrusted=True,
        )
    with open_connection(
        target_ip,
        target_port,
        timeout,
        pairing_policy,
    ) as sock:
        sock.settimeout(timeout)
        peer_fingerprint = None
        if pairing_policy is not None and pairing_policy.enabled:
            certificate = sock.getpeercert(binary_form=True)
            peer_fingerprint = certificate_fingerprint(certificate)
        send_json_message(
            sock,
            {
                "type": "PAIR_REQUEST",
                "protocol_version": PROTOCOL_VERSION,
                "device_id": str(local_device_id),
                "device_name": str(local_device_name),
                "pair_code": str(pair_code),
                "access_token": token,
                "certificate_fingerprint": (
                    local_tls_identity.fingerprint
                    if local_tls_identity is not None
                    else None
                ),
            },
        )
        response = recv_json_message(sock)

    if response.get("type") == "TRANSFER_ERROR":
        raise TransferError.from_payload(response)
    if (
        response.get("type") != "PAIR_ACCEPTED"
        or response.get("protocol_version") != PROTOCOL_VERSION
        or not isinstance(response.get("device_id"), str)
        or not response["device_id"]
    ):
        raise TransferError("INVALID_RESPONSE", "目标设备返回了无效的配对结果。")
    response_fingerprint = normalize_fingerprint(
        response.get("certificate_fingerprint")
    )
    if peer_fingerprint is not None and response_fingerprint != peer_fingerprint:
        raise TransferError(
            "TLS_IDENTITY_FAILED",
            "目标设备返回的证书指纹与 TLS 握手不一致。",
        )
    advertised = (
        normalize_fingerprint(tls_policy.expected_fingerprint)
        if tls_policy is not None
        else None
    )
    if advertised is not None and peer_fingerprint != advertised:
        raise TransferError(
            "TLS_IDENTITY_FAILED",
            "目标设备证书指纹与发现广播不一致。",
        )

    security_store.authorize_device(
        response["device_id"],
        str(response.get("device_name", "Unknown")),
        token,
        PERMISSION_WRITE,
        certificate_fingerprint=response_fingerprint,
    )
    return response
