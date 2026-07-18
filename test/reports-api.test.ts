import path from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { buildApp } from "../src/server.js";
import { RouterStore } from "../src/store.js";
import { OutageStore } from "../src/outages.js";
import { MaintenanceStore } from "../src/maintenance.js";
import { DryRunManager } from "../src/wireguard.js";
import { fakeKey, tempDir, testConfig } from "./helpers.js";
import type { Config } from "../src/config.js";

let cfg: Config;
let store: RouterStore;
let outages: OutageStore;
let maintenance: MaintenanceStore;
let app: ReturnType<typeof buildApp>;

const H = 3600_000;

beforeEach(() => {
  cfg = testConfig();
  store = new RouterStore(cfg.storePath);
  outages = new OutageStore(path.join(tempDir(), "o.json"));
  maintenance = new MaintenanceStore(path.join(tempDir(), "m.json"));
  app = buildApp({ config: cfg, store, wg: new DryRunManager("wg0", true), outages, maintenance });
});

function A() {
  return `Bearer ${cfg.auth.adminToken}`;
}
function register(serial: string, key: number) {
  return request(app).post("/api/register").send({ token: cfg.auth.provisioningToken, publicKey: fakeKey(key), serialNumber: serial });
}

describe("GET /api/reports/sla", () => {
  it("computes per-device and fleet uptime from the outage log", async () => {
    await register("HEX1", 1);
    const r = store.findBySerial("HEX1")!;
    // Backdate creation so the whole window counts.
    r.createdAt = new Date(Date.now() - 100 * H).toISOString();
    r.customerGroup = "Acme";
    store.save(r);

    // One 1h outage inside a 100h window -> ~99% uptime.
    const start = new Date(Date.now() - 50 * H).toISOString();
    const end = new Date(Date.now() - 49 * H).toISOString();
    outages.open("HEX1", "HEX1", start);
    outages.close("HEX1", end);

    const from = Date.now() - 100 * H;
    const res = await request(app).get(`/api/reports/sla?from=${from}&to=${Date.now()}`).set("authorization", A());
    expect(res.status).toBe(200);
    const dev = res.body.devices.find((d: any) => d.serialNumber === "HEX1");
    expect(dev.uptimePct).toBeGreaterThan(98.5);
    expect(dev.uptimePct).toBeLessThan(99.5);
    expect(dev.outages).toBe(1);
    expect(dev.slaTarget).toBeNull(); // none set
    expect(res.body.customers[0].name).toBe("Acme");
    expect(res.body.fleet.devices).toBe(1);
  });

  it("excludes downtime covered by a maintenance window", async () => {
    await register("HEX2", 2);
    const r = store.findBySerial("HEX2")!;
    r.createdAt = new Date(Date.now() - 100 * H).toISOString();
    store.save(r);
    const start = new Date(Date.now() - 50 * H).toISOString();
    const end = new Date(Date.now() - 49 * H).toISOString();
    outages.open("HEX2", "HEX2", start);
    outages.close("HEX2", end);
    maintenance.add({ scopeKind: "device", scopeValue: "HEX2", startsAt: start, endsAt: end, categories: ["offline"], note: "", createdBy: "t" });

    const from = Date.now() - 100 * H;
    const res = await request(app).get(`/api/reports/sla?from=${from}&to=${Date.now()}`).set("authorization", A());
    const dev = res.body.devices.find((d: any) => d.serialNumber === "HEX2");
    expect(dev.uptimePct).toBe(100); // the outage was planned
    expect(dev.downMs).toBe(0);
  });

  it("flags a device that breaches its per-router SLA target", async () => {
    await register("HEX3", 3);
    const r = store.findBySerial("HEX3")!;
    r.createdAt = new Date(Date.now() - 100 * H).toISOString();
    r.slaTarget = 99.9;
    store.save(r);
    // 2h outage over 100h -> ~98% uptime, below the 99.9% target.
    outages.open("HEX3", "HEX3", new Date(Date.now() - 50 * H).toISOString());
    outages.close("HEX3", new Date(Date.now() - 48 * H).toISOString());

    const from = Date.now() - 100 * H;
    const res = await request(app).get(`/api/reports/sla?from=${from}&to=${Date.now()}`).set("authorization", A());
    const dev = res.body.devices.find((d: any) => d.serialNumber === "HEX3");
    expect(dev.slaTarget).toBe(99.9);
    expect(dev.meetsTarget).toBe(false);
    expect(res.body.fleet.breaching).toBeGreaterThanOrEqual(1);
  });

  it("per-device SLA reset re-bases uptime so past outages stop counting", async () => {
    await register("HEX4", 4);
    const r = store.findBySerial("HEX4")!;
    r.createdAt = new Date(Date.now() - 100 * H).toISOString();
    store.save(r);
    // A 5h outage 50h ago — a big dent over a 100h window.
    outages.open("HEX4", "HEX4", new Date(Date.now() - 50 * H).toISOString());
    outages.close("HEX4", new Date(Date.now() - 45 * H).toISOString());

    const from = Date.now() - 100 * H;
    const before = await request(app).get(`/api/reports/sla?from=${from}&to=${Date.now()}`).set("authorization", A());
    const dBefore = before.body.devices.find((d: any) => d.serialNumber === "HEX4");
    expect(dBefore.uptimePct).toBeLessThan(96);
    expect(dBefore.slaResetAt).toBeNull();

    // Reset: baseline moves to now, so the old outage is before the window start.
    const reset = await request(app).post("/api/routers/HEX4/sla-reset").set("authorization", A());
    expect(reset.status).toBe(200);
    expect(reset.body.slaResetAt).toBeTruthy();

    const after = await request(app).get(`/api/reports/sla?from=${from}&to=${Date.now()}`).set("authorization", A());
    const dAfter = after.body.devices.find((d: any) => d.serialNumber === "HEX4");
    expect(dAfter.uptimePct).toBe(100); // clean slate — the pre-reset outage no longer counts
    expect(dAfter.downMs).toBe(0);
    expect(dAfter.slaResetAt).toBeTruthy();

    // Undo restores the full history.
    const undo = await request(app).post("/api/routers/HEX4/sla-reset").set("authorization", A()).send({ undo: true });
    expect(undo.body.slaResetAt).toBeNull();
    const restored = await request(app).get(`/api/reports/sla?from=${from}&to=${Date.now()}`).set("authorization", A());
    expect(restored.body.devices.find((d: any) => d.serialNumber === "HEX4").uptimePct).toBeLessThan(96);
  });

  it("SLA reset is admin-only", async () => {
    await register("HEX5", 5);
    expect((await request(app).post("/api/routers/HEX5/sla-reset")).status).toBe(401);
    expect((await request(app).post("/api/routers/NOPE/sla-reset").set("authorization", A())).status).toBe(404);
  });
});
