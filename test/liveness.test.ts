import path from "node:path";
import { describe, expect, it } from "vitest";
import { livenessTick } from "../src/liveness.js";
import { RouterStore } from "../src/store.js";
import { IssueStore } from "../src/issues.js";
import { EventLog } from "../src/events.js";
import { Alerter } from "../src/alerts.js";
import type { RouterRecord } from "../src/types.js";
import { tempDir } from "./helpers.js";

function router(serial: string): RouterRecord {
  const now = new Date().toISOString();
  return {
    id: crypto.randomUUID(), serialNumber: serial, publicKey: "k-" + serial, boardName: "hEX",
    rosVersion: "7.16", identity: "site", tunnelIp: "10.99.0.9", username: "wg-mgmt",
    password: "p", state: "confirmed", createdAt: now, updatedAt: now, lastSeenAt: now,
  };
}

function setup() {
  const store = new RouterStore(path.join(tempDir(), "routers.json"));
  store.save(router("DEV1"));
  const issues = new IssueStore(path.join(tempDir(), "issues.json"));
  const events = new EventLog(path.join(tempDir(), "events.jsonl"));
  const alerts: string[] = [];
  const alerter = new Alerter({ webhookUrl: "https://h.test", notifyOnRegister: true, notifyOnline: true, suppressMinutes: 0 } as any, async (t) => { alerts.push(t); });
  return { store, issues, events, alerts, alerter };
}

function deps(base: ReturnType<typeof setup>, alive: () => boolean) {
  return {
    store: base.store, issues: base.issues, events: base.events, alerter: base.alerter,
    warnAfterSeconds: 20, offlineAfterSeconds: 60, port: 80, timeoutMs: 500,
    ping: async () => alive(),
  };
}
// Pretend the last successful probe was `secs` ago.
function backdate(store: RouterStore, secs: number) {
  const r = store.findBySerial("DEV1")!;
  r.lastPingOkAt = new Date(Date.now() - secs * 1000).toISOString();
  store.save(r);
}

describe("livenessTick", () => {
  it("marks a reachable device up on the first probe, no issue", async () => {
    const base = setup();
    await livenessTick(deps(base, () => true));
    expect(base.store.findBySerial("DEV1")!.health).toBe("up");
    expect(base.issues.counts().critical).toBe(0);
  });

  it("goes up -> warning -> offline as probes keep failing, opening the issue only at offline", async () => {
    const base = setup();
    let alive = true;
    const d = deps(base, () => alive);
    await livenessTick(d); // baseline up

    // Stops responding; 25s since last reply -> warning, no issue yet.
    alive = false;
    backdate(base.store, 25);
    await livenessTick(d);
    expect(base.store.findBySerial("DEV1")!.health).toBe("warning");
    expect(base.issues.counts().critical).toBe(0);

    // 70s since last reply -> offline: issue + alert.
    backdate(base.store, 70);
    await livenessTick(d);
    expect(base.store.findBySerial("DEV1")!.health).toBe("offline");
    expect(base.issues.counts().critical).toBe(1);
    expect(base.alerts.some((a) => /offline/i.test(a))).toBe(true);
  });

  it("clears the offline issue and alerts when it comes back", async () => {
    const base = setup();
    let alive = false;
    const d = deps(base, () => alive);
    backdate(base.store, 70); // never really up
    // Prime a baseline so the first transition isn't swallowed:
    const r = base.store.findBySerial("DEV1")!;
    r.health = "up"; r.lastOnline = true; base.store.save(r);
    await livenessTick(d); // -> offline
    expect(base.issues.counts().critical).toBe(1);

    alive = true;
    await livenessTick(d); // -> up
    expect(base.store.findBySerial("DEV1")!.health).toBe("up");
    expect(base.issues.counts().critical).toBe(0);
    expect(base.alerts.some((a) => /back online|online/i.test(a))).toBe(true);
  });
});
