from __future__ import annotations

import ipaddress
import socket

from discovery.udp_discovery import get_local_ip
from security import TLSIdentityError, SecurityStore, TLSPolicy, open_connection
from transfer.protocol import (
    PROTOCOL_VERSION,
    recv_json_message,
    send_json_message,
)

from .models import AgentResult


class ConnectionDiagnosticAgent:
    def __init__(
        self,
        *,
        discovery,
        tcp_server,
        udp_port: int,
        tls_enabled: bool,
        security_store: SecurityStore,
    ) -> None:
        self.discovery = discovery
        self.tcp_server = tcp_server
        self.udp_port = int(udp_port)
        self.tls_enabled = bool(tls_enabled)
        self.security_store = security_store

    def analyze(self, device=None) -> AgentResult:
        devices = self.discovery.list_devices()
        target = device or (devices[0] if devices else None)
        local_ip = get_local_ip()
        local_ip_valid = _is_lan_address(local_ip)
        stop_event = getattr(self.discovery, "_stop_event", None)
        udp_active = getattr(self.discovery, "_listen_socket", None) is not None and (
            stop_event is None or not stop_event.is_set()
        )
        tcp_active = (
            getattr(self.tcp_server, "_thread", None) is not None
            and self.tcp_server._thread.is_alive()
        )
        target_discovered = target is not None
        tcp_reachable = False
        tls_ok = not self.tls_enabled
        same_subnet = None
        probe_error = ""

        if target is not None:
            same_subnet = _same_common_subnet(local_ip, target.ip)
            try:
                policy = TLSPolicy()
                if self.tls_enabled:
                    fingerprint = self.security_store.trusted_fingerprint(
                        target.device_id
                    )
                    policy = TLSPolicy(
                        enabled=True,
                        expected_fingerprint=fingerprint,
                        allow_untrusted=fingerprint is None,
                    )
                with open_connection(
                    target.ip,
                    target.tcp_port,
                    3.0,
                    policy,
                ) as connection:
                    connection.settimeout(3.0)
                    send_json_message(
                        connection,
                        {
                            "type": "DIAGNOSTIC_PING",
                            "protocol_version": PROTOCOL_VERSION,
                        },
                    )
                    response = recv_json_message(connection)
                    if (
                        response.get("type") != "DIAGNOSTIC_PONG"
                        or response.get("protocol_version") != PROTOCOL_VERSION
                    ):
                        raise ConnectionError("目标设备未返回有效的诊断响应。")
                    tcp_reachable = True
                    tls_ok = (
                        not self.tls_enabled
                        or bool(response.get("tls_enabled"))
                    )
            except TLSIdentityError as exc:
                tcp_reachable = True
                probe_error = str(exc)
            except (ConnectionError, OSError, ValueError) as exc:
                probe_error = str(exc)

        evidence = [
            f"本机 IP：{local_ip}",
            f"UDP {self.udp_port} 监听：{'正常' if udp_active else '异常'}",
            f"TCP 服务：{'运行中' if tcp_active else '未运行'}",
            f"发现设备数：{len(devices)}",
        ]
        causes: list[str] = []
        recommendations: list[str] = []
        cause_codes: list[str] = []
        severity = "info"

        if not local_ip_valid:
            causes.append("本机没有可用的局域网 IPv4 地址。")
            recommendations.append("检查网卡、Wi-Fi 或有线网络连接。")
            cause_codes.append("LOCAL_IP_INVALID")
        if not udp_active:
            causes.append("UDP 发现监听线程未正常运行或端口绑定失败。")
            recommendations.append(f"检查 UDP {self.udp_port} 是否被占用。")
            cause_codes.append("UDP_LISTENER_DOWN")
        if not tcp_active:
            causes.append("本机 TCP 接收服务未运行。")
            recommendations.append("重启程序并检查 TCP 端口绑定错误。")
            cause_codes.append("TCP_SERVER_DOWN")
        if target is None:
            causes.append("当前没有发现其他在线设备。")
            recommendations.extend(
                [
                    "确认双方处于同一局域网且程序均已启动。",
                    f"检查防火墙是否允许 UDP {self.udp_port} 广播。",
                    "必要时将 broadcast_ip 设置为当前网段的广播地址。",
                ]
            )
            cause_codes.append("TARGET_NOT_DISCOVERED")
        elif not tcp_reachable:
            evidence.append(f"目标 TCP/TLS 探测失败：{probe_error or '未知错误'}")
            causes.append("目标端口不可达、被防火墙阻止，或 TLS 身份校验失败。")
            recommendations.extend(
                [
                    "确认目标程序仍在线且 TCP 端口与广播信息一致。",
                    "检查双方防火墙规则。",
                    "若证书指纹变化，请核实目标设备后重新配对。",
                ]
            )
            cause_codes.append("TARGET_PROBE_FAILED")
        elif same_subnet is False:
            causes.append("本机与目标地址不在常见的 /24 局域网网段。")
            recommendations.append("检查双方子网掩码、网关和访客网络隔离设置。")
            cause_codes.append("SUBNET_MISMATCH")
        if tcp_reachable and self.tls_enabled and not tls_ok:
            causes.append("TCP 端口可达，但 TLS 证书身份校验失败。")
            recommendations.append("核对目标证书指纹，确认后重新配对。")
            cause_codes.append("TLS_IDENTITY_FAILED")
        if causes:
            severity = "error" if not tcp_active or target_discovered else "warning"
            summary = "连接诊断发现可能导致网络失败的问题。"
        else:
            summary = "设备发现、TCP 服务和 TLS 探测均正常。"
            recommendations.append("当前连接状态正常，无需处理。")

        return AgentResult(
            agent="connection",
            summary=summary,
            severity=severity,
            evidence=tuple(evidence),
            causes=tuple(causes),
            recommendations=tuple(dict.fromkeys(recommendations)),
            facts={
                "target_discovered": target_discovered,
                "tcp_reachable": tcp_reachable,
                "same_subnet": same_subnet,
                "tls_enabled": self.tls_enabled,
                "tls_ok": tls_ok,
                "udp_listener_active": udp_active,
                "cause_codes": tuple(cause_codes),
            },
        )


def _is_lan_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return isinstance(address, ipaddress.IPv4Address) and not address.is_unspecified


def _same_common_subnet(left: str, right: str) -> bool | None:
    try:
        left_address = ipaddress.ip_address(left)
        right_address = ipaddress.ip_address(right)
    except ValueError:
        return None
    if not isinstance(left_address, ipaddress.IPv4Address) or not isinstance(
        right_address,
        ipaddress.IPv4Address,
    ):
        return None
    return right_address in ipaddress.ip_network(f"{left_address}/24", strict=False)
