import path from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { buildApp } from "../src/server.js";
import { RouterStore } from "../src/store.js";
import { TopologyStore } from "../src/topology.js";
import { DryRunManager } from "../src/wireguard.js";
import { fakeKey, tempDir, testConfig } from "./helpers.js";
import type { Config } from "../src/config.js";

describe("TopologyStore", () => {
  it("prunes nodes/links referencing routers not in the group and assigns link ids", () => {
    const store = new TopologyStore(path.join(tempDir(), "topo.json"));
    const valid = new Set(["r1", "r2"]);
    const saved = store.set("Smith", {
      nodes: { r1: { x: 10.6, y: 20.2 }, r3: { x: 5, y: 5 } },
      links: [
        { id: "", a: "r1", aIface: "sfp1", b: "r2", bIface: "ether1" },
        { id: "", a: "r1", aIface: "x", b: "r9", bIface: "y" }, // r9 not valid → dropped
        { id: "", a: "r1", aIface: "x", b: "r1", bIface: "y" }, // self-link → dropped
      ],
    } as any, valid);
    expect(Object.keys(saved.nodes)).toEqual(["r1"]); // r3 pruned, rounded
    expect(saved.nodes.r1).toEqual({ x: 11, y: 20 });
    expect(saved.links).toHaveLength(1);
    expect(saved.links[0].id).toMatch(/^lnk-/);
  });

  it("removeRouter drops it from nodes and links across groups", () => {
    const p = path.join(tempDir(), "topo.json");
    const store = new TopologyStore(p);
    store.set("G", { nodes: { r1: { x: 0, y: 0 }, r2: { x: 1, y: 1 } }, links: [{ id: "l1", a: "r1", aIface: "a", b: "r2", bIface: "b" }] } as any, new Set(["r1", "r2"]));
    store.removeRouter("r1");
    const g = new TopologyStore(p).get("G");
    expect(g.nodes.r1).toBeUndefined();
    expect(g.links).toHaveLength(0);
  });
});

describe("groups API", () => {
  let cfg: Config;
  let store: RouterStore;
  let app: ReturnType<typeof buildApp>;
  const A = () => `Bearer ${cfg.auth.adminToken}`;

  beforeEach(async () => {
    cfg = testConfig();
    store = new RouterStore(cfg.storePath);
    app = buildApp({ config: cfg, store, wg: new DryRunManager("wg0", true) });
    for (let i = 1; i <= 2; i++) {
      await request(app).post("/api/register").send({ token: cfg.auth.provisioningToken, publicKey: fakeKey(i), serialNumber: `G${i}` });
    }
  });

  it("lists customers by device group with counts and merges records", async () => {
    await request(app).patch("/api/routers/G1").set("authorization", A()).send({ customerGroup: "Smith" });
    await request(app).patch("/api/routers/G2").set("authorization", A()).send({ customerGroup: "Smith" });
    // a customer record with no devices yet
    await request(app).post("/api/customers").set("authorization", A()).send({ name: "Jones", contact: "Jane", phone: "0400" });
    const list = await request(app).get("/api/customers").set("authorization", A());
    const byName = Object.fromEntries(list.body.map((c: any) => [c.name, c]));
    expect(byName.Smith.count).toBe(2);
    expect(byName.Jones).toMatchObject({ count: 0, contact: "Jane", phone: "0400", hasRecord: true });
  });

  it("deleting a customer unassigns its devices and clears the map", async () => {
    await request(app).patch("/api/routers/G1").set("authorization", A()).send({ customerGroup: "Smith" });
    await request(app).post("/api/customers").set("authorization", A()).send({ name: "Smith", contact: "x" });
    const del = await request(app).delete("/api/customers/Smith").set("authorization", A());
    expect(del.status).toBe(200);
    expect(store.findBySerial("G1")!.customerGroup).toBe("");
    expect((await request(app).get("/api/customers").set("authorization", A())).body).toEqual([]);
  });

  it("customer create/delete is admin-only", async () => {
    expect((await request(app).post("/api/customers").send({ name: "x" })).status).toBe(401);
    expect((await request(app).delete("/api/customers/x")).status).toBe(401);
  });

  it("returns a group's routers + topology and saves a validated layout", async () => {
    await request(app).patch("/api/routers/G1").set("authorization", A()).send({ customerGroup: "Smith" });
    await request(app).patch("/api/routers/G2").set("authorization", A()).send({ customerGroup: "Smith" });
    const g = await request(app).get("/api/groups/Smith").set("authorization", A());
    const [r1, r2] = g.body.routers;

    const put = await request(app).put("/api/groups/Smith/topology").set("authorization", A()).send({
      nodes: { [r1.id]: { x: 100, y: 100 }, [r2.id]: { x: 300, y: 100 } },
      links: [{ a: r1.id, aIface: "sfp1", b: r2.id, bIface: "ether1" }],
    });
    expect(put.status).toBe(200);
    expect(put.body.topology.links[0].id).toMatch(/^lnk-/);

    const g2 = await request(app).get("/api/groups/Smith").set("authorization", A());
    expect(g2.body.topology.links).toHaveLength(1);
    expect(g2.body.topology.nodes[r1.id]).toEqual({ x: 100, y: 100 });
  });

  it("saving topology is admin-only", async () => {
    const res = await request(app).put("/api/groups/Smith/topology").send({ nodes: {}, links: [] });
    expect(res.status).toBe(401);
  });
});
