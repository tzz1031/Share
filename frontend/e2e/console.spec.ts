import { expect, test } from "@playwright/test";

const runtime = {
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
  certificate_fingerprint: "AA:BB",
  sync_enabled: true,
  sync_interval_seconds: 10,
  pending_restart: false
};

const agent = {
  agent: "security",
  summary: "本地安全状态正常",
  severity: "info",
  evidence: [],
  causes: [],
  recommendations: [],
  facts: {
    tls_enabled: true,
    authorized_count: 0,
    stranger_count: 0,
    failure_count: 0
  },
  enhanced: false,
  enhancement_note: "",
  source: "local"
};

test("navigates all seven console areas", async ({ page }) => {
  let socketConnections = 0;
  await page.routeWebSocket("**/api/events", (socket) => {
    socketConnections += 1;
    socket.send(JSON.stringify({ type: "connected", payload: runtime }));
    if (socketConnections === 1) {
      setTimeout(() => {
        void socket.close({ code: 1012, reason: "restart test" });
      }, 100);
    }
  });
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const payload: Record<string, unknown> = {
      "/api/session": { csrf_token: "test-token" },
      "/api/runtime": runtime,
      "/api/dashboard": {
        runtime,
        counts: {
          online_devices: 0,
          paired_devices: 0,
          files: 0,
          unresolved_conflicts: 0,
          risk_alerts: 0
        },
        security: agent,
        recent_events: [],
        transfers: []
      },
      "/api/devices": { items: [] },
      "/api/files": { items: [], total: 0 },
      "/api/transfers": { items: [] },
      "/api/conflicts": { items: [] },
      "/api/security/summary": agent,
      "/api/security/alerts": { items: [] },
      "/api/logs": { items: [], total: 0 },
      "/api/settings": {
        active: {},
        configured: {},
        pending_restart: false,
        restart_fields: [],
        immediate_fields: [],
        deepseek_api_key_configured: false,
        openai_api_key_configured: false
      }
    };
    const key = Object.keys(payload).find((candidate) => path === candidate);
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify(key ? payload[key] : { status: "success" })
    });
  });

  await page.goto("/");
  await expect(page.getByRole("heading", { name: "总览", level: 1 })).toBeVisible();
  for (const name of [
    "设备",
    "同步中心",
    "冲突中心",
    "安全中心",
    "智能 Agent",
    "日志与设置"
  ]) {
    await page.getByRole("button", { name }).click();
    await expect(
      page.getByRole("heading", { name, exact: true, level: 1 })
    ).toBeVisible();
  }
  await expect.poll(() => socketConnections).toBeGreaterThan(1);
});
