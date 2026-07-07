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
let rebootCalls: Array<{ ip: string; user: string }>;
let execCalls: string[];
let app: ReturnType<typeof buildApp>;

function A() {
  return `Bearer ${cfg.auth.adminToken}`;
}

beforeEach(() => {
  cfg = testConfig();
  store = new RouterStore(cfg.storePath);
  metrics = new MetricsStore(path.join(tempDir(), "m.jsonl"));
  rebootCalls = [];
  execCalls = [];
  app = buildApp({
    config: cfg,
    store,
    wg: new DryRunManager("wg0", true),
    metrics,
    reboot: async (ip, user) => {
      rebootCalls.push({ ip, user });
    },
    sshRun: async (_ip, _u, _p, command) => {
      execCalls.push(command);
      return { ok: true, output: `ran: ${command}` };
    },
  });
});

function register(serial: string, key: number) {
  return request(app).post("/api/register").send({ token: cfg.auth.provisioningToken, publicKey: fakeKey(key), serialNumber: serial });
}

describe("POST /api/routers/:ref/reboot", () => {
  it("issues a reboot over the tunnel for an online device", async () => {
    await register("HEX1", 1);
    const res = await request(app).post("/api/routers/HEX1/reboot").set("authorization", A());
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(rebootCalls).toHaveLength(1);
    // Records a device event so the reboot shows up in the audit trail.
    const events = await request(app).get("/api/routers/HEX1/events").set("authorization", A());
    expect(events.body.some((e: { message: string }) => /Reboot issued/.test(e.message))).toBe(true);
  });

  it("requires an admin token", async () => {
    await register("HEX1", 1);
    const res = await request(app).post("/api/routers/HEX1/reboot");
    expect(res.status).toBe(401);
    expect(rebootCalls).toHaveLength(0);
  });

  it("404s for an unknown device", async () => {
    const res = await request(app).post("/api/routers/NOPE/reboot").set("authorization", A());
    expect(res.status).toBe(404);
  });

  it("surfaces a router-side failure as 502", async () => {
    app = buildApp({
      config: cfg, store, wg: new DryRunManager("wg0", true), metrics,
      reboot: async () => { throw new Error("timeout"); },
    });
    await register("HEX1", 1);
    const res = await request(app).post("/api/routers/HEX1/reboot").set("authorization", A());
    expect(res.status).toBe(502);
    expect(res.body.error).toMatch(/reboot failed/);
  });
});

describe("POST /api/routers/:ref/exec", () => {
  it("runs an arbitrary command and returns its output", async () => {
    await register("HEX1", 1);
    const res = await request(app).post("/api/routers/HEX1/exec").set("authorization", A()).send({ command: "/system/resource/print" });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.output).toContain("/system/resource/print");
    expect(execCalls).toEqual(["/system/resource/print"]);
  });

  it("rejects an empty command", async () => {
    await register("HEX1", 1);
    const res = await request(app).post("/api/routers/HEX1/exec").set("authorization", A()).send({ command: "  " });
    expect(res.status).toBe(400);
    expect(execCalls).toHaveLength(0);
  });

  it("requires an admin token", async () => {
    await register("HEX1", 1);
    const res = await request(app).post("/api/routers/HEX1/exec").send({ command: "/export" });
    expect(res.status).toBe(401);
  });
});
