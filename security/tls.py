from __future__ import annotations

import hashlib
import os
import socket
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


class TLSIdentityError(ConnectionError):
    pass


@dataclass(frozen=True)
class TLSIdentity:
    certificate_path: Path
    private_key_path: Path
    fingerprint: str
    expires_at: datetime

    def server_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(
            certfile=str(self.certificate_path),
            keyfile=str(self.private_key_path),
        )
        return context


@dataclass(frozen=True)
class TLSPolicy:
    enabled: bool = False
    expected_fingerprint: str | None = None
    allow_untrusted: bool = False


def certificate_fingerprint(certificate_der: bytes) -> str:
    return hashlib.sha256(certificate_der).hexdigest()


def ensure_tls_identity(
    shared_folder: str | Path,
    device_name: str,
) -> TLSIdentity:
    tls_folder = Path(shared_folder) / ".lan-sync" / "tls"
    certificate_path = tls_folder / "certificate.pem"
    private_key_path = tls_folder / "private_key.pem"
    tls_folder.mkdir(parents=True, exist_ok=True)

    if certificate_path.is_file() and private_key_path.is_file():
        try:
            identity = _load_identity(certificate_path, private_key_path)
            if identity.expires_at > datetime.now(UTC) + timedelta(days=1):
                _restrict_private_key(private_key_path)
                return identity
        except (OSError, ValueError):
            pass

    private_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    common_name = (str(device_name).strip() or "LAN Sync")[:64]
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LAN Sync"),
        ]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    private_key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    _restrict_private_key(private_key_path)
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return _load_identity(certificate_path, private_key_path)


def open_connection(
    target_ip: str,
    target_port: int,
    timeout: float,
    tls_policy: TLSPolicy | None = None,
) -> socket.socket:
    policy = tls_policy or TLSPolicy()
    raw_socket = socket.create_connection(
        (target_ip, int(target_port)),
        timeout=timeout,
    )
    if not policy.enabled:
        return raw_socket

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    tls_socket: ssl.SSLSocket | None = None
    try:
        tls_socket = context.wrap_socket(raw_socket, server_hostname=target_ip)
        peer_certificate = tls_socket.getpeercert(binary_form=True)
        if not peer_certificate:
            raise TLSIdentityError("目标设备未提供 TLS 证书。")
        actual_fingerprint = certificate_fingerprint(peer_certificate)
        expected = normalize_fingerprint(policy.expected_fingerprint)
        if expected is None and not policy.allow_untrusted:
            raise TLSIdentityError("目标设备缺少已绑定的 TLS 证书指纹，请重新配对。")
        if expected is not None and actual_fingerprint != expected:
            raise TLSIdentityError(
                "目标设备 TLS 证书指纹已变化，连接可能被冒充，请重新配对确认。"
            )
        return tls_socket
    except Exception:
        if tls_socket is not None:
            tls_socket.close()
        else:
            raw_socket.close()
        raise


def normalize_fingerprint(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).replace(":", "").strip().lower()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError("certificate fingerprint must be a SHA-256 hex digest")
    return normalized


def _load_identity(
    certificate_path: Path,
    private_key_path: Path,
) -> TLSIdentity:
    certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
    private_key = serialization.load_pem_private_key(
        private_key_path.read_bytes(),
        password=None,
    )
    certificate_key = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_public_key = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if certificate_key != private_public_key:
        raise ValueError("TLS certificate and private key do not match")
    return TLSIdentity(
        certificate_path=certificate_path,
        private_key_path=private_key_path,
        fingerprint=certificate_fingerprint(
            certificate.public_bytes(serialization.Encoding.DER)
        ),
        expires_at=certificate.not_valid_after_utc,
    )


def _restrict_private_key(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
