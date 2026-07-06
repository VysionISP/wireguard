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
});
