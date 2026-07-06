import path from "node:path";
import { describe, expect, it } from "vitest";
import { hostMonitorTick } from "../src/hostmonitor.js";
import { HostStore } from "../src/hosts.js";
import { RouterStore } from "../src/store.js";
import { IssueStore } from "../src/issues.js";
import { EventLog } from "../src/events.js";
import { Alerter } from "../src/alerts.js";
import type { RouterRecord } from "../src/types.js";
import { tempDir } from "./helpers.js";

function router(): RouterRecord {
  const now = new Date().toISOString();
  return {
    id: "r1", serialNumber: "HEX1", publicKey: "k", boardName: "hEX", rosVersion: "7.16",
    identity: "gw", tunnelIp: "10.99.0.9", username: "wg-mgmt", password: "p",
    state: "confirmed", createdAt: now, updatedAt: now, lastSeenAt: now, health: "up",
  };
}

function setup(pingResult: () => { received: number }) {
  const store = new RouterStore(path.join(tempDir(), "routers.json"));
  store.save(router());
  const hostStore = new HostStore(path.join(tempDir(), "hosts.json"));
  const host = hostStore.add({ routerSerial: "HEX1", routerId: "r1", address: "192.168.88.10", name: "nvr", createdBy: "t" });
  const issues = new IssueStore(path.join(tempDir(), "issues.json"));
  const events = new EventLog(path.join(tempDir(), "events.jsonl"));
  const alerts: string[] = [];
  const alerter = new Alerter({ webhookUrl: "https://h.test", notifyOnRegister: true, notifyOnline: true, suppressMinutes: 0 } as any, async (t) => { alerts.push(t); });
  const deps = {
    store, hosts: hostStore, issues, events, alerter,
    warnAfterSeconds: 30, offlineAfterSeconds: 90, pingCount: 2,
    ping: async () => ({ sent: 2, received: pingResult().received, avgMs: 1.2 }),
  };
  return { store, hostStore, host, issues, events, alerts, deps };
}
function backdate(hostStore: HostStore, id: string, secs: number) {
  const h = hostStore.get(id)!;
  h.lastOkAt = new Date(Date.now() - secs * 1000).toISOString();
  hostStore.save(h);
}

describe("HostStore", () => {
  it("dedupes by (router,address) and removes by router", () => {
    const s = new HostStore(path.join(tempDir(), "hosts.json"));
    const a = s.add({ routerSerial: "HEX1", routerId: "r1", address: "1.1.1.1", name: "x", createdBy: "t" });
    const b = s.add({ routerSerial: "HEX1", routerId: "r1", address: "1.1.1.1", name: "y", createdBy: "t" });
    expect(a.id).toBe(b.id);
    expect(s.forRouter("HEX1")).toHaveLength(1);
    s.removeRouter("HEX1");
    expect(s.forRouter("HEX1")).toHaveLength(0);
  });
});

describe("hostMonitorTick", () => {
  it("marks a reachable host up, no issue", async () => {
    const t = setup(() => ({ received: 2 }));
    await hostMonitorTick(t.deps);
    expect(t.hostStore.get(t.host.id)!.state).toBe("up");
    expect(t.issues.counts().critical).toBe(0);
  });

  it("goes up -> warning -> offline, opening the host-down issue only at offline", async () => {
    let recv = 2;
    const t = setup(() => ({ received: recv }));
    await hostMonitorTick(t.deps); // up baseline

    recv = 0;
    backdate(t.hostStore, t.host.id, 40); // > warn(30), < offline(90)
    await hostMonitorTick(t.deps);
    expect(t.hostStore.get(t.host.id)!.state).toBe("warning");
    expect(t.issues.counts().critical).toBe(0);

    backdate(t.hostStore, t.host.id, 100); // > offline(90)
    await hostMonitorTick(t.deps);
    expect(t.hostStore.get(t.host.id)!.state).toBe("offline");
    expect(t.issues.counts().critical).toBe(1);
    expect(t.alerts.some((a) => /OFFLINE/i.test(a))).toBe(true);
  });

  it("does not penalise a host whose router is itself offline", async () => {
    const t = setup(() => ({ received: 0 }));
    const r = t.store.findBySerial("HEX1")!;
    r.health = "offline";
    t.store.save(r);
    backdate(t.hostStore, t.host.id, 500);
    await hostMonitorTick(t.deps);
    // Skipped — state unchanged (undefined), no issue.
    expect(t.issues.counts().critical).toBe(0);
  });
});
