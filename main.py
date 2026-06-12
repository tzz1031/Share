from __future__ import annotations

import argparse
import time
from datetime import datetime
from pathlib import Path

from agents import (
    ConflictAnalysisAgent,
    ConnectionDiagnosticAgent,
    SecurityAuditAgent,
    SecurityAuditService,
)
from audit import AuditStore
from config import load_config
from discovery import DiscoveryService, make_device_id
from discovery.udp_discovery import get_local_ip
from security import (
    VALID_PERMISSIONS,
    SecurityStore,
    TLSPolicy,
    ensure_tls_identity,
)
from security.pairing import pair_with_device
from sync import FileIndex
from sync.service import SyncService
from transfer import TCPFileServer, TransferError, send_file
from runtime import AppRuntime


def format_device_line(
    index: int,
    device,
    security_store: SecurityStore | None = None,
) -> str:
    age = max(0, int(time.time() - device.last_seen))
    permission = None
    if security_store is not None:
        authorized = security_store.get_device(device.device_id)
        permission = authorized.permission if authorized is not None else "未配对"
    return (
        f"{index}. {device.device_name} "
        f"({device.ip}:{device.tcp_port}, {device.status}, {age}s ago"
        f"{f', 权限: {permission}' if permission is not None else ''})"
    )


def list_devices(
    discovery: DiscoveryService,
    security_store: SecurityStore | None = None,
) -> list:
    devices = discovery.list_devices()
    if not devices:
        print("暂未发现其他设备。请确认对方程序已启动，且防火墙允许 UDP 广播。")
        return []

    print("\n在线设备：")
    for index, device in enumerate(devices, start=1):
        print(format_device_line(index, device, security_store))
    return devices


def choose_device(
    discovery: DiscoveryService,
    security_store: SecurityStore | None = None,
):
    devices = list_devices(discovery, security_store)
    if not devices:
        return None

    choice = input("请选择目标设备编号：").strip()
    try:
        selected_index = int(choice)
    except ValueError:
        print("请输入有效的数字编号。")
        return None

    if selected_index < 1 or selected_index > len(devices):
        print("设备编号超出范围。")
        return None
    return devices[selected_index - 1]


def format_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{size} B"


def handle_send_file(
    discovery: DiscoveryService,
    chunk_size: int,
    security_store: SecurityStore,
    local_device_id: str,
    tls_enabled: bool = False,
    audit_store: AuditStore | None = None,
) -> None:
    device = choose_device(discovery, security_store)
    if device is None:
        return
    credential = security_store.credential_for(
        device.device_id,
        local_device_id,
    )
    if credential is None:
        print("该设备尚未配对或已被阻止，请先完成配对。")
        return

    raw_path = input("请输入要发送的文件路径：").strip()
    file_path = Path(raw_path).expanduser()
    if not file_path.is_file():
        print(f"文件不存在：{file_path}")
        return

    progress_started = False

    def show_progress(transferred: int, total: int) -> None:
        nonlocal progress_started
        progress_started = True
        percentage = 100.0 if total == 0 else transferred * 100 / total
        print(
            "\r发送进度："
            f"{percentage:6.2f}% "
            f"({format_bytes(transferred)} / {format_bytes(total)})",
            end="",
            flush=True,
        )

    print("正在计算文件 SHA-256 并准备传输...")
    authorized = security_store.get_device(device.device_id)
    tls_policy = TLSPolicy(
        enabled=tls_enabled,
        expected_fingerprint=(
            authorized.certificate_fingerprint
            if authorized is not None
            else None
        ),
    )
    try:
        result = send_file(
            device.ip,
            device.tcp_port,
            file_path,
            chunk_size=chunk_size,
            progress_callback=show_progress,
            credential=credential,
            tls_policy=tls_policy,
        )
    except TransferError as exc:
        if progress_started:
            print()
        chunk_detail = (
            f"，分块编号：{exc.chunk_index}" if exc.chunk_index is not None else ""
        )
        print(f"发送失败 [{exc.code}]{chunk_detail}：{exc.message}")
        if audit_store is not None:
            audit_store.record_event(
                "file_send_failed",
                severity="warning",
                source_ip=device.ip,
                device_id=device.device_id,
                request_type="manual",
                outcome="failed",
                details={"error_code": exc.code},
            )
        return
    except ValueError as exc:
        if progress_started:
            print()
        print(f"发送失败 [INVALID_ARGUMENT]：{exc}")
        return
    except OSError as exc:
        if progress_started:
            print()
        print(f"发送失败：{exc}")
        return

    if progress_started:
        print()
    if result.get("status") == "success":
        resumed_chunks = int(result.get("resumed_chunks", 0))
        resume_detail = (
            f"\n已复用分块：{resumed_chunks}，"
            f"本次传输分块：{int(result.get('chunks_transferred', 0))}"
            if resumed_chunks
            else ""
        )
        print(
            "发送成功："
            f"{result.get('file_name')} "
            f"({format_bytes(int(result.get('bytes_received', 0)))})\n"
            f"SHA-256：{result.get('file_hash')}"
            f"{resume_detail}"
        )
        if audit_store is not None:
            audit_store.record_event(
                "file_sent",
                source_ip=device.ip,
                device_id=device.device_id,
                request_type="manual",
                bytes_count=int(result.get("bytes_received", 0)),
                details={"resumed_chunks": int(result.get("resumed_chunks", 0))},
            )
    else:
        print(f"发送失败：{result.get('message', '接收端返回未知错误')}")


def handle_pair_device(
    discovery: DiscoveryService,
    security_store: SecurityStore,
    local_device_id: str,
    local_device_name: str,
    tls_enabled: bool = False,
    local_tls_identity=None,
    audit_store: AuditStore | None = None,
) -> None:
    device = choose_device(discovery, security_store)
    if device is None:
        return
    pair_code = input(f"请输入 {device.device_name} 上显示的六位配对码：").strip()
    try:
        pair_with_device(
            device.ip,
            device.tcp_port,
            pair_code=pair_code,
            local_device_id=local_device_id,
            local_device_name=local_device_name,
            security_store=security_store,
            tls_policy=TLSPolicy(
                enabled=tls_enabled,
                expected_fingerprint=device.certificate_fingerprint,
                allow_untrusted=tls_enabled,
            ),
            local_tls_identity=local_tls_identity,
        )
    except (TransferError, OSError, ValueError) as exc:
        print(f"配对失败：{exc}")
        if audit_store is not None:
            audit_store.record_event(
                "pairing_failed",
                severity="warning",
                source_ip=device.ip,
                device_id=device.device_id,
                outcome="failed",
                details={"error_type": type(exc).__name__},
            )
        return
    if audit_store is not None:
        audit_store.record_event(
            "pairing_succeeded",
            source_ip=device.ip,
            device_id=device.device_id,
            details={"tls": tls_enabled},
        )
    print(f"已与 {device.device_name} 建立双向配对，默认权限为 write。")


def list_authorized_devices(security_store: SecurityStore) -> list:
    devices = security_store.list_devices()
    if not devices:
        print("暂无已授权设备。")
        return []
    print("\n已授权设备：")
    for index, device in enumerate(devices, start=1):
        print(
            f"{index}. {device.device_name} "
            f"({device.device_id[:8]}..., 权限: {device.permission})"
        )
    return devices


def choose_authorized_device(security_store: SecurityStore):
    devices = list_authorized_devices(security_store)
    if not devices:
        return None
    choice = input("请选择设备编号：").strip()
    try:
        index = int(choice)
    except ValueError:
        print("请输入有效的数字编号。")
        return None
    if index < 1 or index > len(devices):
        print("设备编号超出范围。")
        return None
    return devices[index - 1]


def handle_set_permission(security_store: SecurityStore) -> None:
    device = choose_authorized_device(security_store)
    if device is None:
        return
    permission = input("请输入权限（read/write/admin/blocked）：").strip().lower()
    if permission not in VALID_PERMISSIONS:
        print("权限无效。")
        return
    security_store.set_permission(device.device_id, permission)
    print(f"已将 {device.device_name} 的权限设置为 {permission}。")


def handle_revoke_device(security_store: SecurityStore) -> None:
    device = choose_authorized_device(security_store)
    if device is None:
        return
    security_store.revoke(device.device_id)
    print(f"已解除 {device.device_name} 的本机授权。")


def print_menu(unread_alerts: int = 0) -> None:
    if unread_alerts:
        print(f"\n安全提示：有 {unread_alerts} 条未读高风险异常告警。")
    print("\n请选择操作：")
    print("1. 查看在线设备")
    print("2. 发送单个文件")
    print("3. 配对在线设备")
    print("4. 查看授权设备")
    print("5. 修改设备权限")
    print("6. 解除设备授权")
    print("7. 查看本机配对码")
    print("8. 重新生成本机配对码")
    print("9. 查看最近访问日志")
    print("10. 查看异常访问告警")
    print("11. 运行连接诊断 Agent")
    print("12. 运行冲突分析 Agent")
    print("13. 运行安全审计 Agent")
    print("0. 退出")


def print_agent_result(result) -> None:
    print(f"\n[{result.severity.upper()}] {result.summary}")
    if result.evidence:
        print("证据：")
        for item in result.evidence:
            print(f"- {item}")
    if result.causes:
        print("可能原因：")
        for item in result.causes:
            print(f"- {item}")
    if result.recommendations:
        print("建议：")
        for item in result.recommendations:
            print(f"- {item}")
    if result.enhancement_note:
        print(result.enhancement_note)


def show_recent_events(audit_store: AuditStore) -> None:
    events = audit_store.recent_events(30)
    if not events:
        print("暂无访问日志。")
        return
    print("\n最近访问事件：")
    for event in events:
        timestamp = datetime.fromtimestamp(event.created_at_ns / 1_000_000_000)
        print(
            f"{timestamp:%Y-%m-%d %H:%M:%S} "
            f"[{event.severity}] {event.event_type} "
            f"source={event.source_ip or '-'} outcome={event.outcome}"
        )


def show_alerts(audit_store: AuditStore) -> None:
    alerts = audit_store.recent_alerts(30)
    if not alerts:
        print("暂无异常访问告警。")
        return
    print("\n异常访问告警：")
    for alert in alerts:
        timestamp = datetime.fromtimestamp(alert.created_at_ns / 1_000_000_000)
        print(
            f"{timestamp:%Y-%m-%d %H:%M:%S} "
            f"[{alert.severity}] {alert.rule_code} "
            f"source={alert.source_key} count={alert.event_count} "
            f"{alert.message}"
        )
    audit_store.mark_alerts_read()


def run_cli(runtime: AppRuntime) -> int:
    config = runtime.config
    runtime.start()
    print("局域网文件共享系统已启动")
    print(f"设备名称：{config.device_name}")
    print(f"本机 IP：{get_local_ip()}")
    print(f"UDP 发现端口：{config.udp_port}")
    print(f"TCP 接收端口：{runtime.tcp_server.bound_port}")
    print(f"接收目录：{config.shared_folder}")
    print(f"本机配对码：{runtime.security_store.pair_code}")
    print(f"TLS 加密：{'已启用' if config.enable_tls else '未启用'}")
    if runtime.tls_identity is not None:
        print(f"证书指纹：{runtime.tls_identity.fingerprint}")
    if config.sync_enabled:
        print(f"自动同步：已启用（每 {config.sync_interval_seconds:g} 秒扫描）")
    else:
        print("自动同步：未启用")

    try:
        while True:
            print_menu(runtime.audit_store.unread_high_risk_count())
            choice = input("> ").strip()
            if choice == "1":
                list_devices(runtime.discovery, runtime.security_store)
            elif choice == "2":
                handle_send_file(
                    runtime.discovery,
                    config.chunk_size,
                    runtime.security_store,
                    runtime.device_id,
                    config.enable_tls,
                    runtime.audit_store,
                )
            elif choice == "3":
                handle_pair_device(
                    runtime.discovery,
                    runtime.security_store,
                    runtime.device_id,
                    config.device_name,
                    config.enable_tls,
                    runtime.tls_identity,
                    runtime.audit_store,
                )
            elif choice == "4":
                list_authorized_devices(runtime.security_store)
            elif choice == "5":
                handle_set_permission(runtime.security_store)
            elif choice == "6":
                handle_revoke_device(runtime.security_store)
            elif choice == "7":
                print(f"本机配对码：{runtime.security_store.pair_code}")
            elif choice == "8":
                print(
                    "新的本机配对码："
                    f"{runtime.security_store.regenerate_pair_code()}"
                )
            elif choice == "9":
                show_recent_events(runtime.audit_store)
            elif choice == "10":
                show_alerts(runtime.audit_store)
            elif choice == "11":
                devices = runtime.discovery.list_devices()
                target = (
                    choose_device(runtime.discovery, runtime.security_store)
                    if devices
                    else None
                )
                print_agent_result(
                    runtime.deepseek.enhance(
                        runtime.connection_agent.analyze(target)
                    )
                )
            elif choice == "12":
                print_agent_result(
                    runtime.deepseek.enhance(runtime.conflict_agent.analyze())
                )
            elif choice == "13":
                print_agent_result(
                    runtime.deepseek.enhance(runtime.security_agent.analyze())
                )
            elif choice == "0":
                break
            else:
                print("未知操作，请重新选择。")
    except KeyboardInterrupt:
        print("\n正在退出...")
    finally:
        runtime.stop()
        print("已停止。")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="LANSync Agent")
    parser.add_argument(
        "--cli",
        action="store_true",
        help="使用兼容的命令行菜单，而不是 Web 控制台",
    )
    parser.add_argument(
        "--config",
        default="config.json",
        help="配置文件路径",
    )
    args = parser.parse_args(argv)
    runtime = AppRuntime(args.config)
    if args.cli:
        return run_cli(runtime)

    import uvicorn

    from webapp import create_app

    print("LANSync Agent Web 控制台正在启动")
    print(f"访问地址：http://127.0.0.1:{runtime.config.web_port}")
    uvicorn.run(
        create_app(runtime),
        host="127.0.0.1",
        port=runtime.config.web_port,
        log_level="info",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
