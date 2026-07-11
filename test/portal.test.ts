import path from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { buildApp } from "../src/server.js";
import { RouterStore } from "../src/store.js";
import { MetricsStore } from "../src/metrics.js";
import { UserStore, SessionManager } from "../src/users.js";
import { CustomerStore } from "../src/customers.js";
import { DryRunManager } from "../src/wireguard.js";
import { fakeKey, tempDir, testConfig } from "./helpers.js";
import type { Config } from "../src/config.js";

let cfg: Config;
let store: RouterStore;
let users: UserStore;
let sessions: SessionManager;
let customers: CustomerStore;
let metrics: MetricsStore;
let app: ReturnType<typeof buildApp>;

beforeEach(() => {
  cfg = testConfig();
  store = new RouterStore(cfg.storePath);
  users = new UserStore(cfg.usersPath);
  sessions = new SessionManager(cfg.auth.sessionHours);
  customers = new CustomerStore(path.join(tempDir(), "cust.json"));
  metrics = new MetricsStore(path.join(tempDir(), "m.jsonl"));
  customers.upsert("Acme", { contact: "Jo", phone: "0400" });
  customers.upsert("Globex", {});
  app = buildApp({ config: cfg, store, wg: new DryRunManager("wg0", true), users, sessions, customers, metrics });
});

const A = () => `Bearer ${cfg.auth.adminToken}`;

async function register(serial: string, key: number, group?: string) {
  await request(app).post("/api/register").send({ token: cfg.auth.provisioningToken, publicKey: fakeKey(key), serialNumber: serial });
  if (group) {
    await request(app).patch(`/api/routers/${serial}`).set("authorization", A()).send({ customerGroup: group });
  }
  return store.findBySerial(serial)!;
}

async function customerLogin(username: string, group: string): Promise<string> {
  await request(app).post("/api/users").set("authorization", A()).send({ username, role: "customer", password: "portalpass1", customerGroup: group });
  const r = await request(app).post("/api/login").send({ username, password: "portalpass1" });
  return r.body.session;
}

describe("customer role scoping", () => {
  it("customer login reports role + group and cannot touch the ops API", async () => {
    const sess = await customerLogin("acme-view", "Acme");
    const auth = `Bearer ${sess}`;
    const me = await request(app).get("/api/me").set("authorization", auth);
    expect(me.body.role).toBe("customer");
    expect(me.body.customerGroup).toBe("Acme");
    // Every staff endpoint is 403 for a customer.
    expect((await request(app).get("/api/routers").set("authorization", auth)).status).toBe(403);
    expect((await request(app).get("/api/compliance").set("authorization", auth)).status).toBe(403);
    expect((await request(app).post("/api/upgrades").set("authorization", auth).send({ refs: ["x"] })).status).toBe(403);
    expect((await request(app).get("/api/users").set("authorization", auth)).status).toBe(403);
    expect((await request(app).get("/api/audit").set("authorization", auth)).status).toBe(403);
  });

  it("creating a customer account requires an existing customer group", async () => {
    const bad = await request(app).post("/api/users").set("authorization", A()).send({ username: "nope", role: "customer", password: "portalpass1", customerGroup: "Nonexistent" });
    expect(bad.status).toBe(400);
    const noGroup = await request(app).post("/api/users").set("authorization", A()).send({ username: "nope2", role: "customer", password: "portalpass1" });
    expect(noGroup.status).toBe(400);
  });
});

describe("portal API", () => {
  it("overview returns only the account's own devices", async () => {
    await register("ACME1", 1, "Acme");
    await register("ACME2", 2, "Acme");
    await register("GLOBEX1", 3, "Globex");
    const sess = await customerLogin("acme-view", "Acme");
    const auth = `Bearer ${sess}`;
    const ov = await request(app).get("/api/portal/overview").set("authorization", auth);
    expect(ov.status).toBe(200);
    expect(ov.body.customer).toBe("Acme");
    expect(ov.body.devices.map((d: { label: string }) => d.label).sort()).not.toContain("GLOBEX1");
    expect(ov.body.devices).toHaveLength(2);
    expect(ov.body.devices[0].uptime30d).toBeTypeOf("number");
  });

  it("device traffic is scoped: a foreign device id 404s (no cross-customer probing)", async () => {
    const mine = await register("ACME1", 1, "Acme");
    const theirs = await register("GLOBEX1", 3, "Globex");
    const sess = await customerLogin("acme-view", "Acme");
    const auth = `Bearer ${sess}`;
    expect((await request(app).get(`/api/portal/devices/${mine.id}/traffic`).set("authorization", auth)).status).toBe(200);
    expect((await request(app).get(`/api/portal/devices/${theirs.id}/traffic`).set("authorization", auth)).status).toBe(404);
  });

  it("staff accounts (no group) cannot use the portal API", async () => {
    const ov = await request(app).get("/api/portal/overview").set("authorization", A());
    expect(ov.status).toBe(403);
  });

  it("the portal API needs auth", async () => {
    expect((await request(app).get("/api/portal/overview")).status).toBe(401);
  });
});

describe("tech role is unaffected", () => {
  it("a tech can still read the fleet but not admin-only endpoints", async () => {
    users.add("tech1", "techpass1", "tech");
    const login = await request(app).post("/api/login").send({ username: "tech1", password: "techpass1" });
    const auth = `Bearer ${login.body.session}`;
    expect((await request(app).get("/api/routers").set("authorization", auth)).status).toBe(200);
    expect((await request(app).get("/api/users").set("authorization", auth)).status).toBe(403);
    expect((await request(app).get("/api/portal/overview").set("authorization", auth)).status).toBe(403);
  });
});
