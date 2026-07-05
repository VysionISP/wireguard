import path from "node:path";
import { describe, expect, it } from "vitest";
import { monitorTick } from "../src/monitor.js";
import { RouterStore } from "../src/store.js";
import type { WireguardManager } from "../src/wireguard.js";
import type { RouterRecord } from "../src/types.js";
import { fakeKey, tempDir } from "./helpers.js";

function record(serial: string, seed: number, state: RouterRecord["state"] = "confirmed"): RouterRecord {
  const now = new Date().toISOString();
  return {
    id: crypto.randomUUID(),
    serialNumber: serial,
    publicKey: fakeKey(seed),
    boardName: "hEX",
    rosVersion: "7.15",
    identity: "MikroTik",
    tunnelIp: `10.99.0.${seed + 1}`,
    username: "wg-mgmt",
    password: "secret",
    state,
    createdAt: now,
    updatedAt: now,
    lastSeenAt: null,
  };
}

function fakeWg(handshakes: Record<string, number | null>): WireguardManager {
  return {
    addPeer: async () => {},
    removePeer: async () => {},
    latestHandshake: async (k) => handshakes[k] ?? null,
    latestHandshakes: async () => handshakes,
  };
}

describe("monitorTick", () => {
  it("baselines quietly on first tick, records transitions on change", async () => {
    const store = new RouterStore(path.join(tempDir(), "routers.json"));
    store.save(record("A", 1));
    store.save(record("B", 2));

    // first tick: A online, B offline — no transitions recorded, just baseline
    let stats = await monitorTick(store, fakeWg({ [fakeKey(1)]: 30, [fakeKey(2)]: null }), 180);
    expect(stats).toMatchObject({ online: 1, offline: 1, changed: 0 });
    expect(store.findBySerial("A")!.lastOnline).toBe(true);
    expect(store.findBySerial("A")!.lastSeenAt).not.toBeNull();
    expect(store.findBySerial("B")!.lastOnline).toBe(false);
    expect(store.findBySerial("B")!.transitions).toBeUndefined();

    // second tick: A drops (stale handshake), B comes up
    stats = await monitorTick(store, fakeWg({ [fakeKey(1)]: 900, [fakeKey(2)]: 10 }), 180);
    expect(stats.changed).toBe(2);
    expect(store.findBySerial("A")!.lastOnline).toBe(false);
    expect(store.findBySerial("A")!.transitions).toHaveLength(1);
    expect(store.findBySerial("A")!.transitions![0].online).toBe(false);
    expect(store.findBySerial("B")!.transitions![0].online).toBe(true);

    // third tick: nothing changed — no new transitions
    stats = await monitorTick(store, fakeWg({ [fakeKey(1)]: 960, [fakeKey(2)]: 20 }), 180);
    expect(stats.changed).toBe(0);
    expect(store.findBySerial("A")!.transitions).toHaveLength(1);
  });

  it("skips revoked routers", async () => {
    const store = new RouterStore(path.join(tempDir(), "routers.json"));
    store.save(record("R", 3, "revoked"));
    const stats = await monitorTick(store, fakeWg({ [fakeKey(3)]: 5 }), 180);
    expect(stats).toEqual({ online: 0, offline: 0, changed: 0 });
    expect(store.findBySerial("R")!.lastOnline).toBeUndefined();
  });
});
