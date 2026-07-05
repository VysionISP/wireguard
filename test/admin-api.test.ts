import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { buildApp } from "../src/server.js";
import { RouterStore } from "../src/store.js";
import { DryRunManager } from "../src/wireguard.js";
import { fakeKey, testConfig } from "./helpers.js";
import type { Config } from "../src/config.js";
import type { FetchInfoFn } from "../src/actions.js";

let cfg: Config;
let store: RouterStore;
let wg: DryRunManager;

const okInfo: FetchInfoFn = async () => ({
  identity: "cust-router",
  boardName: "hEX",
  version: "7.15.3",
  uptime: "1d2h",
});
const failInfo: FetchInfoFn = async () => {
  throw new Error("connect ETIMEDOUT");
};

function app(fetchInfo: FetchInfoFn = okInfo) {
  return buildApp({ config: cfg, store, wg, fetchInfo });
}

function admin(a: ReturnType<typeof app>, method: "get" | "post", path: string) {
  return request(a)[method](path).set("authorization", `Bearer ${cfg.auth.adminToken}`);
}

beforeEach(async () => {
  cfg = testConfig();
  store = new RouterStore(cfg.storePath);
  wg = new DryRunManager(cfg.wireguard.interface, true);
  await request(app())
    .post("/api/register")
    .send({
      token: cfg.auth.provisioningToken,
      publicKey: fakeKey(1),
      serialNumber: "HEX0001",
      boardName: "hEX",
      rosVersion: "7.15.3",
      identity: "MikroTik",
    });
});

describe("admin API", () => {
  it("rejects all admin endpoints without the token", async () => {
    const a = app();
    for (const [method, path] of [
      ["get", "/api/routers"],
      ["get", "/api/routers/HEX0001"],
      ["post", "/api/routers/HEX0001/verify"],
      ["post", "/api/routers/HEX0001/revoke"],
      ["get", "/api/bootstrap-info"],
    ] as const) {
      expect((await request(a)[method](path)).status, `${method} ${path}`).toBe(401);
    }
  });

  it("lists routers with handshake age and no password", async () => {
    const res = await admin(app(), "get", "/api/routers");
    expect(res.status).toBe(200);
    expect(res.body[0]).toMatchObject({ serialNumber: "HEX0001", handshakeAge: null });
    expect(res.body[0].password).toBeUndefined();
  });

  it("returns full details including credentials for a single router", async () => {
    const res = await admin(app(), "get", "/api/routers/HEX0001");
    expect(res.status).toBe(200);
    expect(res.body.password).toHaveLength(24);
    expect(res.body.tunnelIp).toBe("10.99.0.2");
  });

  it("verify marks the router verified when it responds", async () => {
    const res = await admin(app(okInfo), "post", "/api/routers/HEX0001/verify");
    expect(res.status).toBe(200);
    expect(res.body.reachable).toBe(true);
    expect(res.body.info.identity).toBe("cust-router");
    expect(store.findBySerial("HEX0001")!.state).toBe("verified");
    expect(store.findBySerial("HEX0001")!.identity).toBe("cust-router");
  });

  it("verify reports unreachable without changing state", async () => {
    const res = await admin(app(failInfo), "post", "/api/routers/HEX0001/verify");
    expect(res.status).toBe(200);
    expect(res.body.reachable).toBe(false);
    expect(res.body.error).toContain("ETIMEDOUT");
    expect(store.findBySerial("HEX0001")!.state).toBe("registered");
  });

  it("revoke removes the peer and blocks re-registration", async () => {
    const res = await admin(app(), "post", "/api/routers/HEX0001/revoke");
    expect(res.status).toBe(200);
    expect(store.findBySerial("HEX0001")!.state).toBe("revoked");
    expect(wg.calls).toContainEqual(`wg set wg0 peer ${fakeKey(1)} remove`);

    const rereg = await request(app())
      .post("/api/register")
      .send({ token: cfg.auth.provisioningToken, publicKey: fakeKey(2), serialNumber: "HEX0001" });
    expect(rereg.status).toBe(403);
  });

  it("serves the bootstrap one-liner and 404s unknown refs", async () => {
    const boot = await admin(app(), "get", "/api/bootstrap-info");
    expect(boot.body.oneLiner).toContain("/tool fetch");
    expect((await admin(app(), "get", "/api/routers/NOPE")).status).toBe(404);
  });

  it("serves the dashboard at /", async () => {
    const res = await request(app()).get("/");
    expect(res.status).toBe(200);
    expect(res.text).toContain("KORVIX");
  });
});
