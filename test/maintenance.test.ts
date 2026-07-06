import path from "node:path";
import { describe, expect, it } from "vitest";
import { MaintenanceStore } from "../src/maintenance.js";
import { livenessTick } from "../src/liveness.js";
import { RouterStore } from "../src/store.js";
import { IssueStore } from "../src/issues.js";
import { EventLog } from "../src/events.js";
import { Alerter } from "../src/alerts.js";
import type { RouterRecord } from "../src/types.js";
import { tempDir } from "./helpers.js";

function win(store: MaintenanceStore, over: Partial<Parameters<MaintenanceStore["add"]>[0]> = {}) {
  const now = Date.now();
  return store.add({
    scopeKind: "all",
    startsAt: new Date(now - 60_000).toISOString(),
    endsAt: new Date(now + 3600_000).toISOString(),
    categories: [],
    note: "",
    createdBy: "t",
    ...over,
  });
}

describe("MaintenanceStore", () => {
  it("matches scope (all / device / customer) and category, only while active", () => {
    const s = new MaintenanceStore(path.join(tempDir(), "m.json"));
    win(s, { scopeKind: "device", scopeValue: "HEX1", categories: ["offline"] });
    expect(s.suppressed("HEX1", undefined, "offline")).toBe(true);
    expect(s.suppressed("HEX1", undefined, "link")).toBe(false); // category not covered
    expect(s.suppressed("HEX2", undefined, "offline")).toBe(false); // wrong device

    const s2 = new MaintenanceStore(path.join(tempDir(), "m2.json"));
    win(s2, { scopeKind: "customer", scopeValue: "Acme" });
    expect(s2.suppressed("HEXX", "Acme", "host")).toBe(true); // empty categories = all
    expect(s2.suppressed("HEXX", "Other", "host")).toBe(false);
  });

  it("ignores windows that are not currently active", () => {
    const s = new MaintenanceStore(path.join(tempDir(), "m.json"));
    const future = Date.now() + 3600_000;
    s.add({ scopeKind: "all", startsAt: new Date(future).toISOString(), endsAt: new Date(future + 3600_000).toISOString(), categories: [], note: "", createdBy: "t" });
    expect(s.suppressed("HEX1", undefined, "offline")).toBe(false);
  });
});

describe("liveness respects maintenance", () => {
  function router(): RouterRecord {
    const now = new Date().toISOString();
    return {
      id: "r", serialNumber: "DEV1", publicKey: "k", boardName: "hEX", rosVersion: "7", identity: "s",
      tunnelIp: "10.99.0.9", username: "u", password: "p", state: "confirmed",
      createdAt: now, updatedAt: now, lastSeenAt: now, health: "up", lastOnline: true,
    };
  }
  it("does not open an offline issue while a window suppresses it", async () => {
    const store = new RouterStore(path.join(tempDir(), "r.json"));
    store.save(router());
    const issues = new IssueStore(path.join(tempDir(), "i.json"));
    const events = new EventLog(path.join(tempDir(), "e.jsonl"));
    const alerts: string[] = [];
    const alerter = new Alerter({ webhookUrl: "https://h.test", notifyOnline: true, suppressMinutes: 0 } as any, async (t) => { alerts.push(t); });
    const maint = new MaintenanceStore(path.join(tempDir(), "m.json"));
    win(maint); // whole fleet, all categories, active

    const r = store.findBySerial("DEV1")!;
    r.lastPingOkAt = new Date(Date.now() - 200_000).toISOString(); // long offline
    store.save(r);
    await livenessTick({
      store, issues, events, alerter, warnAfterSeconds: 20, offlineAfterSeconds: 60, port: 80, timeoutMs: 100,
      ping: async () => false,
      suppressed: (serial, group, cat) => maint.suppressed(serial, group, cat as any),
    });
    expect(store.findBySerial("DEV1")!.health).toBe("offline"); // state still tracked
    expect(issues.counts().critical).toBe(0); // but no issue/alert
    expect(alerts.length).toBe(0);
  });

  it("reconciles: a device that died during a window gets its issue when the window ends", async () => {
    const store = new RouterStore(path.join(tempDir(), "r.json"));
    store.save(router());
    const issues = new IssueStore(path.join(tempDir(), "i.json"));
    const events = new EventLog(path.join(tempDir(), "e.jsonl"));
    const alerts: string[] = [];
    const alerter = new Alerter({ webhookUrl: "https://h.test", notifyOnline: true, suppressMinutes: 0 } as any, async (t) => { alerts.push(t); });
    const maint = new MaintenanceStore(path.join(tempDir(), "m.json"));
    const w = win(maint);
    const r = store.findBySerial("DEV1")!;
    r.lastPingOkAt = new Date(Date.now() - 200_000).toISOString();
    store.save(r);
    const deps = {
      store, issues, events, alerter, warnAfterSeconds: 20, offlineAfterSeconds: 60, port: 80, timeoutMs: 100,
      ping: async () => false, suppressed: (s: string, g: string | undefined, c: string) => maint.suppressed(s, g, c as any),
    };
    await livenessTick(deps); // muted → offline state, no issue
    expect(issues.counts().critical).toBe(0);

    maint.remove(w.id); // window ends
    await livenessTick(deps); // reconcile → issue opens now, no transition needed
    expect(issues.counts().critical).toBe(1);
    expect(alerts.some((a) => /OFFLINE/i.test(a))).toBe(true);
  });
});
