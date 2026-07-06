import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { buildApp } from "../src/server.js";
import { RouterStore } from "../src/store.js";
import { CustomerStore } from "../src/customers.js";
import { DryRunManager } from "../src/wireguard.js";
import { fakeKey, testConfig } from "./helpers.js";
import type { Config } from "../src/config.js";

let cfg: Config;
let store: RouterStore;
let customers: CustomerStore;
let app: ReturnType<typeof buildApp>;

beforeEach(async () => {
  cfg = testConfig();
  store = new RouterStore(cfg.storePath);
  customers = new CustomerStore(cfg.customersPath);
  app = buildApp({ config: cfg, store, wg: new DryRunManager("wg0", true), customers });
  await request(app).post("/api/register").send({ token: cfg.auth.provisioningToken, publicKey: fakeKey(1), serialNumber: "HEX1", identity: "site-a" });
  const r = store.findBySerial("HEX1")!;
  r.customerGroup = "Acme";
  r.label = "North Tower";
  r.health = "up";
  store.save(r);
  customers.upsert("Acme", { contact: "John" });
});

const A = () => `Bearer ${cfg.auth.adminToken}`;

describe("customer status page", () => {
  it("issues a token, serves sanitized public status, and rotation kills the old link", async () => {
    const t1 = await request(app).post("/api/customers/Acme/status-token").set("authorization", A());
    expect(t1.status).toBe(200);
    expect(t1.body.url).toContain("/status/");

    const pub = await request(app).get("/api/status/" + t1.body.token);
    expect(pub.status).toBe(200);
    expect(pub.body.customer).toBe("Acme");
    expect(pub.body.overall).toBe("operational");
    expect(pub.body.devices[0].label).toBe("North Tower");
    // Sanitized: no serials, tunnel IPs or credentials in the payload.
    const raw = JSON.stringify(pub.body);
    expect(raw).not.toContain("HEX1");
    expect(raw).not.toContain("10.99.");

    // Rotate: old token dies, new one works.
    const t2 = await request(app).post("/api/customers/Acme/status-token").set("authorization", A());
    expect((await request(app).get("/api/status/" + t1.body.token)).status).toBe(404);
    expect((await request(app).get("/api/status/" + t2.body.token)).status).toBe(200);

    // Disable: everything dies.
    await request(app).delete("/api/customers/Acme/status-token").set("authorization", A());
    expect((await request(app).get("/api/status/" + t2.body.token)).status).toBe(404);
  });

  it("requires admin to mint tokens and rejects junk tokens", async () => {
    expect((await request(app).post("/api/customers/Acme/status-token")).status).toBe(401);
    expect((await request(app).get("/api/status/st-nope")).status).toBe(404);
  });

  it("serves the public HTML shell at /status/:token", async () => {
    const res = await request(app).get("/status/anything");
    expect(res.status).toBe(200);
    expect(res.text).toContain("KORVIX");
  });
});
