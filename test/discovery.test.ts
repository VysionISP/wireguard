import { describe, expect, it } from "vitest";
import request from "supertest";
import { beforeEach } from "vitest";
import { discoverLinks, localPort } from "../src/discovery.js";
import { buildApp } from "../src/server.js";
import { RouterStore } from "../src/store.js";
import { DryRunManager } from "../src/wireguard.js";
import { fakeKey, testConfig } from "./helpers.js";
import type { NeighborEntry } from "../src/routeros.js";
import type { Config } from "../src/config.js";

function nb(over: Partial<NeighborEntry>): NeighborEntry {
  return { interface: "", identity: "", interfaceName: "", macAddress: "", address: "", board: "", ...over };
}

describe("localPort", () => {
  it("picks the physical port out of a bridge-prefixed list", () => {
    expect(localPort("bridge,ether2")).toBe("ether2");
    expect(localPort("sfp-sfpplus1")).toBe("sfp-sfpplus1");
    expect(localPort("bridge")).toBe("bridge");
  });
});

describe("discoverLinks", () => {
  const devices = [
    { id: "A", identity: "Tower-North", label: "North Tower" },
    { id: "B", identity: "POP-core", label: "Ballarat POP" },
  ];

  it("builds one link from two directed observations, preferring each side's own port name", () => {
    const neighbors = new Map([
      ["A", [nb({ interface: "bridge,sfp1", identity: "POP-core", interfaceName: "wrong-remote-guess" })]],
      ["B", [nb({ interface: "sfp-sfpplus3", identity: "Tower-North", interfaceName: "sfp1" })]],
    ]);
    const r = discoverLinks(devices, neighbors, []);
    expect(r.added).toBe(1);
    expect(r.links).toHaveLength(1);
    const l = r.links[0];
    const ends = [`${l.a}:${l.aIface}`, `${l.b}:${l.bIface}`].sort();
    expect(ends).toEqual(["A:sfp1", "B:sfp-sfpplus3"]);
  });

  it("confirms instead of duplicating an existing link, and reports unmatched neighbors", () => {
    const existing = [{ id: "x", a: "A", aIface: "sfp1", b: "B", bIface: "sfp-sfpplus3" }];
    const neighbors = new Map([
      ["A", [
        nb({ interface: "sfp1", identity: "POP-core", interfaceName: "sfp-sfpplus3" }),
        nb({ interface: "ether5", identity: "SomeRandomAP", address: "192.168.88.9" }),
      ]],
    ]);
    const r = discoverLinks(devices, neighbors, existing);
    expect(r.added).toBe(0);
    expect(r.confirmed).toBe(1);
    expect(r.links).toHaveLength(1);
    expect(r.unmatched[0].identity).toBe("SomeRandomAP");
  });

  it("skips factory-default identities as ambiguous", () => {
    const devs = [...devices, { id: "C", identity: "MikroTik", label: "fresh" }];
    const neighbors = new Map([["A", [nb({ interface: "ether1", identity: "MikroTik" })]]]);
    const r = discoverLinks(devs, neighbors, []);
    expect(r.added).toBe(0);
    expect(r.unmatched).toHaveLength(1);
  });
});

describe("POST /api/groups/:name/discover", () => {
  let cfg: Config;
  let store: RouterStore;
  let app: ReturnType<typeof buildApp>;

  beforeEach(() => {
    cfg = testConfig();
    store = new RouterStore(cfg.storePath);
    app = buildApp({
      config: cfg, store, wg: new DryRunManager("wg0", true),
      fetchNeighbors: async (tunnelIp) =>
        tunnelIp === "10.99.0.2"
          ? [nb({ interface: "bridge,ether5", identity: "site-b", interfaceName: "ether1" })]
          : [nb({ interface: "ether1", identity: "site-a", interfaceName: "ether5" })],
    });
  });

  it("polls the group's devices and saves discovered links", async () => {
    const A = `Bearer ${cfg.auth.adminToken}`;
    for (const [serial, key, ident] of [["SN-A", 1, "site-a"], ["SN-B", 2, "site-b"]] as const) {
      await request(app).post("/api/register").send({ token: cfg.auth.provisioningToken, publicKey: fakeKey(key), serialNumber: serial, identity: ident });
      const r = store.findBySerial(serial)!;
      r.customerGroup = "Acme";
      store.save(r);
    }
    const res = await request(app).post("/api/groups/Acme/discover").set("authorization", A);
    expect(res.status).toBe(200);
    expect(res.body.polled).toBe(2);
    expect(res.body.added).toBe(1);
    expect(res.body.topology.links).toHaveLength(1);
    // Second run: nothing new, link confirmed.
    const res2 = await request(app).post("/api/groups/Acme/discover").set("authorization", A);
    expect(res2.body.added).toBe(0);
    expect(res2.body.confirmed).toBe(1);
  });
});
