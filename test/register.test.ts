import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { buildApp } from "../src/server.js";
import { RouterStore } from "../src/store.js";
import { DryRunManager } from "../src/wireguard.js";
import { fakeKey, testConfig } from "./helpers.js";
import type { Config } from "../src/config.js";

let cfg: Config;
let store: RouterStore;
let wg: DryRunManager;
let app: ReturnType<typeof buildApp>;

beforeEach(() => {
  cfg = testConfig();
  store = new RouterStore(cfg.storePath);
  wg = new DryRunManager(cfg.wireguard.interface, true);
  app = buildApp({ config: cfg, store, wg });
});

function register(overrides: Record<string, unknown> = {}) {
  return request(app)
    .post("/api/register")
    .send({
      token: cfg.auth.provisioningToken,
      publicKey: fakeKey(1),
      serialNumber: "HEX0001",
      boardName: "hEX S",
      rosVersion: "7.15.3",
      identity: "MikroTik",
      ...overrides,
    });
}

describe("POST /api/register", () => {
  it("rejects a bad token", async () => {
    const res = await register({ token: "wrong" });
    expect(res.status).toBe(401);
  });

  it("rejects a malformed public key", async () => {
    const res = await register({ publicKey: "not-a-key" });
    expect(res.status).toBe(400);
  });

  it("registers a new router: allocates an IP, adds the peer, returns a script", async () => {
    const res = await register();
    expect(res.status).toBe(200);
    expect(res.text).toContain("address=10.99.0.2/24"); // .1 reserved for the server
    expect(res.text).toContain("/interface/wireguard/peers/add");

    const router = store.findBySerial("HEX0001")!;
    expect(router.tunnelIp).toBe("10.99.0.2");
    expect(router.state).toBe("registered");
    expect(router.password).toHaveLength(24);
    expect(wg.calls).toContainEqual(
      `wg set wg0 peer ${fakeKey(1)} allowed-ips 10.99.0.2/32`,
    );
  });

  it("allocates distinct IPs to distinct routers", async () => {
    await register();
    const res = await register({ serialNumber: "HEX0002", publicKey: fakeKey(2) });
    expect(res.text).toContain("address=10.99.0.3/24");
  });

  it("re-registration keeps the IP and swaps the peer key", async () => {
    await register();
    const res = await register({ publicKey: fakeKey(3) });
    expect(res.status).toBe(200);
    expect(res.text).toContain("address=10.99.0.2/24");
    expect(wg.calls).toContainEqual(`wg set wg0 peer ${fakeKey(1)} remove`);
    expect(wg.calls).toContainEqual(
      `wg set wg0 peer ${fakeKey(3)} allowed-ips 10.99.0.2/32`,
    );
    expect(store.findBySerial("HEX0001")!.publicKey).toBe(fakeKey(3));
  });

  it("refuses revoked routers", async () => {
    await register();
    const router = store.findBySerial("HEX0001")!;
    router.state = "revoked";
    store.save(router);
    const res = await register({ publicKey: fakeKey(4) });
    expect(res.status).toBe(403);
  });
});

describe("POST /api/confirm", () => {
  it("marks a registered router confirmed", async () => {
    await register();
    const res = await request(app)
      .post("/api/confirm")
      .send({ token: cfg.auth.provisioningToken, serialNumber: "HEX0001" });
    expect(res.status).toBe(200);
    expect(store.findBySerial("HEX0001")!.state).toBe("confirmed");
  });

  it("404s for unknown serials", async () => {
    const res = await request(app)
      .post("/api/confirm")
      .send({ token: cfg.auth.provisioningToken, serialNumber: "NOPE" });
    expect(res.status).toBe(404);
  });
});

describe("GET /bootstrap.rsc", () => {
  it("requires the provisioning token", async () => {
    const res = await request(app).get("/bootstrap.rsc?token=wrong");
    expect(res.status).toBe(401);
  });

  it("serves the bootstrap script", async () => {
    const res = await request(app).get(
      `/bootstrap.rsc?token=${encodeURIComponent(cfg.auth.provisioningToken)}`,
    );
    expect(res.status).toBe(200);
    expect(res.text).toContain("/interface/wireguard/add");
  });

  it("sets WWW-Authenticate on a 401 (RouterOS fetch compatibility)", async () => {
    const res = await request(app).get("/bootstrap.rsc?token=nope");
    expect(res.status).toBe(401);
    expect(res.headers["www-authenticate"]).toBeTruthy();
  });
});

describe("GET /api/routers", () => {
  it("requires the admin token and never leaks passwords", async () => {
    await register();
    expect((await request(app).get("/api/routers")).status).toBe(401);

    const res = await request(app)
      .get("/api/routers")
      .set("authorization", `Bearer ${cfg.auth.adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
    expect(res.body[0].tunnelIp).toBe("10.99.0.2");
    expect(res.body[0].password).toBeUndefined();
  });
});
