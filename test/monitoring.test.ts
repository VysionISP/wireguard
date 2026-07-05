import path from "node:path";
import { describe, expect, it } from "vitest";
import { IssueStore } from "../src/issues.js";
import { EventLog } from "../src/events.js";
import { deviceMonitorTick } from "../src/devicemonitor.js";
import { RouterStore } from "../src/store.js";
import { Alerter } from "../src/alerts.js";
import type { WireguardManager } from "../src/wireguard.js";
import type { RouterRecord } from "../src/types.js";
import { defaultMonitoring } from "../src/types.js";
import type { IfaceState, LogEntry } from "../src/routeros.js";
import { fakeKey, tempDir } from "./helpers.js";

describe("IssueStore", () => {
  it("dedupes by (serial,type), resolves, acks and counts", () => {
    const s = new IssueStore(path.join(tempDir(), "issues.json"));
    expect(s.open("A", "A", "offline", "critical", "down")).toBe(true);
    expect(s.open("A", "A", "offline", "critical", "still down")).toBe(false); // dedup
    s.open("B", "B", "link-down", "warning", "port5 down");
    expect(s.counts()).toEqual({ critical: 1, warning: 1, unacked: 2 });

    const openIssue = s.list().find((i) => i.serialNumber === "A")!;
    expect(s.ack(openIssue.id, "lockie")).toBe(true);
    expect(s.counts().unacked).toBe(1);

    expect(s.resolve("A", "offline")).toBe(true);
    expect(s.counts().critical).toBe(0);
    expect(s.list(true).some((i) => i.resolvedAt)).toBe(true);
  });

  it("persists across reloads and clears by serial", () => {
    const p = path.join(tempDir(), "issues.json");
    const s = new IssueStore(p);
    s.open("A", "A", "offline", "critical", "x");
    expect(new IssueStore(p).counts().critical).toBe(1);
    s.clearSerial("A");
    expect(new IssueStore(p).counts().critical).toBe(0);
  });
});

describe("EventLog", () => {
  it("appends and filters by serial, newest first", () => {
    const log = new EventLog(path.join(tempDir(), "events.jsonl"));
    log.add({ at: "2026-01-01T00:00:00Z", serialNumber: "A", label: "A", type: "login", severity: "info", message: "user admin logged in via ssh" });
    log.add({ at: "2026-01-02T00:00:00Z", serialNumber: "B", label: "B", type: "offline", severity: "critical", message: "B went offline" });
    expect(log.recent()[0].serialNumber).toBe("B");
    expect(log.forSerial("A")).toHaveLength(1);
  });
});

function router(serial: string, seed: number, mon = true): RouterRecord {
  const now = new Date().toISOString();
  return {
    id: crypto.randomUUID(), serialNumber: serial, publicKey: fakeKey(seed), boardName: "hEX",
    rosVersion: "7.16", identity: "site", tunnelIp: `10.99.0.${seed + 1}`, username: "wg-mgmt",
    password: "p", state: "confirmed", createdAt: now, updatedAt: now, lastSeenAt: now,
    deviceType: "infrastructure",
    monitoring: mon ? defaultMonitoring("infrastructure", true, true) : undefined,
  };
}

function wgFresh(keys: string[]): WireguardManager {
  const hs = Object.fromEntries(keys.map((k) => [k, 10]));
  return { addPeer: async () => {}, removePeer: async () => {}, latestHandshake: async () => 10, latestHandshakes: async () => hs };
}

describe("deviceMonitorTick", () => {
  it("baselines on first poll, then alerts on link-down and new logins", async () => {
    const store = new RouterStore(path.join(tempDir(), "routers.json"));
    const r = router("INFRA1", 1);
    store.save(r);
    const issues = new IssueStore(path.join(tempDir(), "issues.json"));
    const events = new EventLog(path.join(tempDir(), "events.jsonl"));
    const alerts: string[] = [];
    const alerter = new Alerter({ webhookUrl: "https://h.test", notifyOnRegister: true, notifyOnline: true, suppressMinutes: 0 } as any, async (t) => { alerts.push(t); });

    let ifaces: IfaceState[] = [
      { name: "ether1", type: "ether", running: true, disabled: false },
      { name: "sfp1", type: "sfp", running: true, disabled: false },
    ];
    let log: LogEntry[] = [
      { id: "*1", time: "jan/01 10:00:00", topics: "system,info,account", message: "user admin logged in from 10.0.0.5 via winbox" },
    ];
    const deps = {
      store, wg: wgFresh([fakeKey(1)]), issues, events, alerter, offlineAfterSeconds: 180,
      fetchInterfaces: async () => ifaces,
      fetchLog: async () => log,
    };

    // First poll: baseline. No issues, no login alerts (history ignored).
    await deviceMonitorTick(deps);
    expect(issues.counts().warning).toBe(0);
    expect(alerts).toHaveLength(0);
    expect(store.findBySerial("INFRA1")!.monState!.initialised).toBe(true);

    // ether1 drops + a new login appears.
    ifaces = [
      { name: "ether1", type: "ether", running: false, disabled: false },
      { name: "sfp1", type: "sfp", running: true, disabled: false },
    ];
    log = [
      ...log,
      { id: "*2", time: "jan/01 11:00:00", topics: "system,info,account", message: "user tech logged in from 10.0.0.9 via ssh" },
    ];
    await deviceMonitorTick(deps);
    expect(issues.counts().warning).toBe(1);
    expect(events.forSerial("INFRA1").some((e) => e.type === "link-down")).toBe(true);
    expect(events.forSerial("INFRA1").some((e) => e.type === "login" && /ssh/.test(e.message))).toBe(true);
    expect(alerts.some((a) => /link went DOWN/i.test(a))).toBe(true);
    expect(alerts.some((a) => /logged in.*ssh/i.test(a))).toBe(true);

    // ether1 comes back: issue clears, link-up event.
    ifaces = [
      { name: "ether1", type: "ether", running: true, disabled: false },
      { name: "sfp1", type: "sfp", running: true, disabled: false },
    ];
    await deviceMonitorTick(deps);
    expect(issues.counts().warning).toBe(0);
    expect(events.forSerial("INFRA1").some((e) => e.type === "link-up")).toBe(true);
  });

  it("skips routers without monitoring, offline routers, and staged/revoked", async () => {
    const store = new RouterStore(path.join(tempDir(), "routers.json"));
    store.save(router("NOTMON", 1, false));
    const offline = router("OFFL", 2); store.save(offline);
    const issues = new IssueStore(path.join(tempDir(), "issues.json"));
    const events = new EventLog(path.join(tempDir(), "events.jsonl"));
    const alerter = new Alerter({ suppressMinutes: 0 } as any, async () => {});
    let polled = 0;
    const res = await deviceMonitorTick({
      store, issues, events, alerter, offlineAfterSeconds: 180,
      // only NOTMON's key is fresh; OFFL has no handshake
      wg: wgFresh([fakeKey(1)]),
      fetchInterfaces: async () => { polled++; return []; },
      fetchLog: async () => [],
    });
    // NOTMON has no monitoring, OFFL is offline → nothing polled
    expect(res.polled).toBe(0);
    expect(polled).toBe(0);
  });
});
