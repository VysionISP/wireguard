import path from "node:path";
import { describe, expect, it } from "vitest";
import { RouterStore } from "../src/store.js";
import type { RouterRecord } from "../src/types.js";
import { tempDir } from "./helpers.js";

function record(serial: string, ip: string): RouterRecord {
  const now = new Date().toISOString();
  return {
    id: crypto.randomUUID(),
    serialNumber: serial,
    publicKey: "x".repeat(43) + "=",
    boardName: "hEX",
    rosVersion: "7.15",
    identity: "MikroTik",
    tunnelIp: ip,
    username: "wg-mgmt",
    password: "secret",
    state: "registered",
    createdAt: now,
    updatedAt: now,
    lastSeenAt: null,
  };
}

describe("RouterStore", () => {
  it("persists and reloads records", () => {
    const file = path.join(tempDir(), "routers.json");
    const store = new RouterStore(file);
    const r = record("SER123", "10.99.0.2");
    store.save(r);

    const reloaded = new RouterStore(file);
    expect(reloaded.findBySerial("SER123")?.tunnelIp).toBe("10.99.0.2");
    expect(reloaded.usedTunnelIps()).toEqual(["10.99.0.2"]);
  });

  it("saveExisting refuses to resurrect a deleted record", () => {
    const file = path.join(tempDir(), "routers.json");
    const store = new RouterStore(file);
    const r = record("SER5", "10.99.0.5");
    store.save(r);
    store.delete(r.id);
    // A slow monitor tick finishing after the delete must not re-insert it.
    expect(store.saveExisting(r)).toBe(false);
    expect(store.get(r.id)).toBeUndefined();
    expect(new RouterStore(file).get(r.id)).toBeUndefined();
    // But a still-present record persists fine.
    const r2 = record("SER6", "10.99.0.6");
    store.save(r2);
    r2.state = "confirmed";
    expect(store.saveExisting(r2)).toBe(true);
    expect(new RouterStore(file).get(r2.id)?.state).toBe("confirmed");
  });

  it("finds by id, serial and tunnel IP", () => {
    const store = new RouterStore(path.join(tempDir(), "routers.json"));
    const r = record("SER9", "10.99.0.9");
    store.save(r);
    expect(store.find(r.id)?.serialNumber).toBe("SER9");
    expect(store.find("SER9")?.id).toBe(r.id);
    expect(store.find("10.99.0.9")?.id).toBe(r.id);
    expect(store.find("nope")).toBeUndefined();
  });
});
