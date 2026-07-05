import { describe, expect, it } from "vitest";
import path from "node:path";
import { syncPeers } from "../src/sync.js";
import { RouterStore } from "../src/store.js";
import { DryRunManager } from "../src/wireguard.js";
import type { RouterRecord } from "../src/types.js";
import { fakeKey, tempDir } from "./helpers.js";

function record(serial: string, ip: string, seed: number, state: RouterRecord["state"]): RouterRecord {
  const now = new Date().toISOString();
  return {
    id: crypto.randomUUID(),
    serialNumber: serial,
    publicKey: fakeKey(seed),
    boardName: "hEX",
    rosVersion: "7.15",
    identity: "MikroTik",
    tunnelIp: ip,
    username: "wg-mgmt",
    password: "secret",
    state,
    createdAt: now,
    updatedAt: now,
    lastSeenAt: null,
  };
}

describe("syncPeers", () => {
  it("re-applies all peers except revoked ones", async () => {
    const store = new RouterStore(path.join(tempDir(), "routers.json"));
    store.save(record("A", "10.99.0.2", 1, "confirmed"));
    store.save(record("B", "10.99.0.3", 2, "registered"));
    store.save(record("C", "10.99.0.4", 3, "revoked"));

    const wg = new DryRunManager("wg0", true);
    const result = await syncPeers(store, wg);

    expect(result).toEqual({ applied: 2, failed: 0 });
    expect(wg.calls).toContainEqual(`wg set wg0 peer ${fakeKey(1)} allowed-ips 10.99.0.2/32`);
    expect(wg.calls).toContainEqual(`wg set wg0 peer ${fakeKey(2)} allowed-ips 10.99.0.3/32`);
    expect(wg.calls).toHaveLength(2);
  });
});
