import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AgentsPage, DevicesPage, SyncPage } from "./App";
import { api, uploadFile } from "./api";
import type { AgentResult, Device, RuntimeStatus } from "./types";

vi.mock("./api", () => ({
  api: vi.fn(),
  eventSocket: vi.fn(),
  uploadFile: vi.fn()
}));

const apiMock = vi.mocked(api);
const uploadMock = vi.mocked(uploadFile);
const notify = vi.fn();

const device: Device = {
  device_id: "peer-123456789",
  device_name: "PC-B",
  online: true,
  status: "online",
  ip: "192.168.1.8",
  tcp_port: 9001,
  last_seen: Date.now() / 1000,
  tls_enabled: true,
  paired: true,
  permission: "write",
  paired_at_ns: Date.now() * 1_000_000,
  last_authenticated_at_ns: null,
  certificate_fingerprint: "AA:BB",
  last_sync_at_ns: null,
  stranger: false
};

const runtime: RuntimeStatus = {
  running: true,
  started_at_ns: Date.now() * 1_000_000,
  device_id: "local",
  device_name: "PC-A",
  local_ip: "127.0.0.1",
  udp_port: 9000,
  tcp_port: 9001,
  web_port: 8765,
  shared_folder: "/tmp/shared",
  tls_enabled: true,
  certificate_fingerprint: "CC:DD",
  sync_enabled: true,
  sync_interval_seconds: 10,
  pending_restart: false
};

const agentResult: AgentResult = {
  agent: "security",
  summary: "安全状态正常",
  severity: "info",
  evidence: ["TLS 已启用"],
  causes: [],
  recommendations: [],
  facts: {},
  enhanced: false,
  enhancement_note: "",
  source: "local"
};

describe("LANSync console pages", () => {
  beforeEach(() => {
    apiMock.mockReset();
    uploadMock.mockReset();
    notify.mockReset();
  });

  it("renders the device empty state", async () => {
    apiMock.mockResolvedValueOnce({ items: [] });
    render(<DevicesPage liveVersion={0} notify={notify} />);
    expect(await screen.findByText("尚未发现设备")).toBeInTheDocument();
  });

  it("opens the device management drawer", async () => {
    apiMock.mockResolvedValueOnce({ items: [device] });
    render(<DevicesPage liveVersion={0} notify={notify} />);
    fireEvent.click(await screen.findByRole("button", { name: "管理" }));
    expect(screen.getByText("设备控制")).toBeInTheDocument();
    expect(screen.getByText("ACCESS CONTROL")).toBeInTheDocument();
  });

  it("keeps authorization when the revoke confirmation is cancelled", async () => {
    apiMock.mockResolvedValueOnce({ items: [device] });
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    render(<DevicesPage liveVersion={0} notify={notify} />);
    fireEvent.click(await screen.findByRole("button", { name: "管理" }));
    fireEvent.click(screen.getByRole("button", { name: "解除授权" }));
    expect(confirm).toHaveBeenCalledOnce();
    expect(apiMock).toHaveBeenCalledTimes(1);
    confirm.mockRestore();
  });

  it("shows browser upload progress and queues the file", async () => {
    apiMock.mockImplementation(async (path: string) => {
      if (path.startsWith("/api/files")) return { items: [], total: 0 };
      if (path === "/api/devices") return { items: [device] };
      if (path === "/api/transfers") return { items: [] };
      if (path === "/api/runtime") return runtime;
      throw new Error(`unexpected path: ${path}`);
    });
    uploadMock.mockImplementation(async (_deviceId, _file, onProgress) => {
      onProgress?.(42);
      await Promise.resolve();
      return { status: "queued" };
    });
    const { container } = render(<SyncPage liveVersion={0} notify={notify} />);
    const input = container.querySelector('input[type="file"]') as HTMLInputElement;
    fireEvent.change(input, {
      target: { files: [new File(["hello"], "report.txt", { type: "text/plain" })] }
    });
    fireEvent.change(await screen.findByRole("combobox", { name: "目标设备" }), {
      target: { value: device.device_id }
    });
    fireEvent.click(screen.getByRole("button", { name: "上传并发送" }));
    expect(await screen.findByRole("progressbar")).toHaveAttribute(
      "aria-valuenow",
      "42"
    );
    await waitFor(() =>
      expect(notify).toHaveBeenCalledWith("文件已上传到本机发送队列")
    );
  });

  it("recovers from an Agent request error", async () => {
    apiMock
      .mockRejectedValueOnce(new Error("DeepSeek 暂时不可用"))
      .mockResolvedValueOnce(agentResult);
    render(<AgentsPage notify={notify} />);
    fireEvent.click(screen.getAllByRole("button", { name: "运行 Agent" })[0]);
    expect(await screen.findByText("DeepSeek 暂时不可用")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "重试" }));
    expect(await screen.findByText("安全状态正常")).toBeInTheDocument();
  });
});
