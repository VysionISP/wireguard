import path from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { buildApp } from "../src/server.js";
import { RouterStore } from "../src/store.js";
import { MetricsStore } from "../src/metrics.js";
import { DryRunManager } from "../src/wireguard.js";
import { fakeKey, tempDir, testConfig } from "./helpers.js";
import type { Config } from "../src/config.js";

let cfg: Config;
let store: RouterStore;
let metrics: MetricsStore;
let app: ReturnType<typeof buildApp>;

const fetchProfile = async () => ({
  identity: "TowerA",
  resource: { uptime: "2d", version: "7.16", cpuLoad: 8, freeMemory: 100, totalMemory: 256, boardName: "CCR", cpuCount: "4", architecture: "arm64" },
  routerboard: { model: "CCR2004", serialNumber: "HEX1", firmware: "7.16", firmwareType: "ccr", upgradeAvailable: "7.16" },
  health: [{ name: "temperature", value: "41", type: "C" }],
  ipAddresses: [{ address: "192.168.88.1/24", network: "192.168.88.0", interface: "bridge", disabled: false }],
  dhcpLeases: [
    { address: "192.168.88.10", macAddress: "AA:BB:CC:00:11:22", hostName: "laptop", status: "bound", server: "dhcp1", expiresAfter: "9m", lastSeen: "1s", dynamic: true, comment: "" },
  ],
  interfaces: [{ name: "ether1", type: "ether", running: true, rxByte: 5, txByte: 5 }],
});

function A() {
  return `Bearer ${cfg.auth.adminToken}`;
}

beforeEach(() => {
  cfg = testConfig();
  store = new RouterStore(cfg.storePath);
  metrics = new MetricsStore(path.join(tempDir(), "m.jsonl"));
  app = buildApp({
    config: cfg, store, wg: new DryRunManager("wg0", true), metrics, fetchProfile,
    fetchPing: async (_h, _u, _p, address) => ({ sent: 4, received: address === "192.168.88.10" ? 4 : 0, avgMs: 1.5 }),
  });
});

function register(serial: string, key: number) {
  return request(app).post("/api/register").send({ token: cfg.auth.provisioningToken, publicKey: fakeKey(key), serialNumber: serial });
}

describe("GET /api/routers/:ref/profile", () => {
  it("returns DHCP leases, IP addresses and health over the tunnel", async () => {
    await register("HEX1", 1);
    const res = await request(app).get("/api/routers/HEX1/profile").set("authorization", A());
    expect(res.status).toBe(200);
    expect(res.body.dhcpLeases).toHaveLength(1);
    expect(res.body.dhcpLeases[0].hostName).toBe("laptop");
    expect(res.body.ipAddresses[0].interface).toBe("bridge");
    expect(res.body.health[0].name).toBe("temperature");
  });

  it("requires auth", async () => {
    await register("HEX1", 1);
    const res = await request(app).get("/api/routers/HEX1/profile");
    expect(res.status).toBe(401);
  });
});

describe("POST /api/routers/:ref/ping", () => {
  it("returns replies/loss for a reachable address", async () => {
    await register("HEX1", 1);
    const res = await request(app).post("/api/routers/HEX1/ping").set("authorization", A()).send({ address: "192.168.88.10" });
    expect(res.status).toBe(200);
    expect(res.body.received).toBe(4);
    expect(res.body.lossPct).toBe(0);
  });

  it("reports 100% loss for an unreachable address", async () => {
    await register("HEX1", 1);
    const res = await request(app).post("/api/routers/HEX1/ping").set("authorization", A()).send({ address: "10.0.0.254" });
    expect(res.body.received).toBe(0);
    expect(res.body.lossPct).toBe(100);
  });

  it("rejects a non-IPv4 address", async () => {
    await register("HEX1", 1);
    const res = await request(app).post("/api/routers/HEX1/ping").set("authorization", A()).send({ address: "not-an-ip" });
    expect(res.status).toBe(400);
  });
});

describe("GET /api/routers/:ref/traffic", () => {
  it("returns per-interface throughput and a previous-period comparison", async () => {
    await register("HEX1", 1);
    const now = Date.now();
    const S = cfg.metrics.sampleSeconds * 1000;
    // Previous window: two samples, +100000 bytes rx. Current window: +300000 bytes rx.
    metrics.record("HEX1", { at: now - S - 25 * 3600_000, cpu: 1, memUsed: 0, memTotal: 1, ifaces: { ether1: { rx: 0, tx: 0 } } });
    metrics.record("HEX1", { at: now - 25 * 3600_000, cpu: 1, memUsed: 0, memTotal: 1, ifaces: { ether1: { rx: 100_000, tx: 0 } } });
    metrics.record("HEX1", { at: now - S, cpu: 1, memUsed: 0, memTotal: 1, ifaces: { ether1: { rx: 100_000, tx: 0 } } });
    metrics.record("HEX1", { at: now, cpu: 1, memUsed: 0, memTotal: 1, ifaces: { ether1: { rx: 400_000, tx: 0 } } });

    const res = await request(app).get("/api/routers/HEX1/traffic?hours=24").set("authorization", A());
    expect(res.status).toBe(200);
    expect(res.body.interfaces).toContain("ether1");
    expect(res.body.busiest).toBe("ether1");
    expect(res.body.totals.ether1.rx).toBe(300_000); // current window
    expect(res.body.prevTotals.ether1.rx).toBe(100_000); // previous window
    expect(res.body.series.ether1.length).toBeGreaterThan(0);
  });

  it("excludes the management tunnel interface", async () => {
    await register("HEX1", 1);
    const now = Date.now();
    const S = cfg.metrics.sampleSeconds * 1000;
    metrics.record("HEX1", { at: now - S, cpu: 1, memUsed: 0, memTotal: 1, ifaces: { "wg-mgmt": { rx: 0, tx: 0 } } });
    metrics.record("HEX1", { at: now, cpu: 1, memUsed: 0, memTotal: 1, ifaces: { "wg-mgmt": { rx: 999_999, tx: 0 } } });
    const res = await request(app).get("/api/routers/HEX1/traffic?hours=24").set("authorization", A());
    expect(res.body.interfaces).not.toContain("wg-mgmt");
  });
});
