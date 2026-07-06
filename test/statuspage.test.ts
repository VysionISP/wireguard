import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { buildApp } from "../src/server.js";
import { RouterStore } from "../src/store.js";
import { CustomerStore } from "../src/customers.js";
import { TopologyStore } from "../src/topology.js";
import { HostStore } from "../src/hosts.js";
import { DryRunManager } from "../src/wireguard.js";
import { fakeKey, testConfig } from "./helpers.js";
import type { Config } from "../src/config.js";

let cfg: Config;
let store: RouterStore;
let customers: CustomerStore;
let topology: TopologyStore;
let hosts: HostStore;
let app: ReturnType<typeof buildApp>;

beforeEach(async () => {
  cfg = testConfig();
  store = new RouterStore(cfg.storePath);
  customers = new CustomerStore(cfg.customersPath);
  topology = new TopologyStore(cfg.topologyPath);
  hosts = new HostStore(cfg.hostsPath);
  app = buildApp({ config: cfg, store, wg: new DryRunManager("wg0", true), customers, topology, hosts });
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
  it("issues a STABLE token, serves sanitized public status; explicit rotate kills the old link", async () => {
    const t1 = await request(app).post("/api/customers/Acme/status-token").set("authorization", A());
    expect(t1.status).toBe(200);
    expect(t1.body.url).toContain("/status/");

    // Asking again returns the SAME link — safe to reopen after giving it out.
    const again = await request(app).post("/api/customers/Acme/status-token").set("authorization", A());
    expect(again.body.token).toBe(t1.body.token);

    const pub = await request(app).get("/api/status/" + t1.body.token);
    expect(pub.status).toBe(200);
    expect(pub.body.customer).toBe("Acme");
    expect(pub.body.overall).toBe("operational");
    expect(pub.body.devices[0].label).toBe("North Tower");
    // Sanitized: no serials, tunnel IPs or credentials in the payload.
    const raw = JSON.stringify(pub.body);
    expect(raw).not.toContain("HEX1");
    expect(raw).not.toContain("10.99.");

    // Explicit rotate: old token dies, new one works.
    const t2 = await request(app).post("/api/customers/Acme/status-token").set("authorization", A()).send({ rotate: true });
    expect(t2.body.token).not.toBe(t1.body.token);
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

  it("includes a sanitized topology map (opaque node keys, no router ids)", async () => {
    await request(app).post("/api/register").send({ token: cfg.auth.provisioningToken, publicKey: fakeKey(2), serialNumber: "HEX2", identity: "site-b" });
    const r2 = store.findBySerial("HEX2")!;
    r2.customerGroup = "Acme";
    r2.label = "Reception AP";
    store.save(r2);
    const r1 = store.findBySerial("HEX1")!;
    topology.set(
      "Acme",
      { nodes: { [r1.id]: { x: 100, y: 100 }, [r2.id]: { x: 400, y: 200 } }, links: [{ id: "l1", a: r1.id, aIface: "ether2", b: r2.id, bIface: "ether1" }] },
      new Set([r1.id, r2.id]),
    );
    const t = await request(app).post("/api/customers/Acme/status-token").set("authorization", A());
    const pub = await request(app).get("/api/status/" + t.body.token);
    expect(pub.body.map.nodes).toHaveLength(2);
    expect(pub.body.map.links).toEqual([{ a: expect.stringMatching(/^n\d$/), b: expect.stringMatching(/^n\d$/), aIface: "ether2", bIface: "ether1" }]);
    // Internal router ids (uuids) must not leak.
    expect(JSON.stringify(pub.body.map)).not.toContain(r1.id);
  });

  it("shows the device's SLA commitment + status, and monitored hosts nested under it", async () => {
    const r = store.findBySerial("HEX1")!;
    r.slaTarget = 99.9;
    store.save(r);
    hosts.add({ routerSerial: "HEX1", routerId: r.id, address: "192.168.88.20", name: "nvr", createdBy: "t" });
    const h = hosts.forRouter("HEX1")[0];
    h.state = "offline";
    hosts.save(h);

    const t = await request(app).post("/api/customers/Acme/status-token").set("authorization", A());
    const pub = await request(app).get("/api/status/" + t.body.token);
    const dev = pub.body.devices[0];
    expect(dev.slaTarget).toBe(99.9);
    expect(dev.meetsSla).toBe(true); // no outages logged
    expect(dev.uptime30d).toBe(100);
    expect(dev.hosts).toEqual([{ label: "nvr", state: "down" }]);
  });

  it("serves the public HTML shell at /status/:token", async () => {
    const res = await request(app).get("/status/anything");
    expect(res.status).toBe(200);
    expect(res.text).toContain("KORVIX");
  });
});
