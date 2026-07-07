import path from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { PingMetricsStore } from "../src/pingmetrics.js";
import { pingMonitorTick, resetPingLatches, type PingMonitorDeps } from "../src/pingmonitor.js";
import { RouterStore } from "../src/store.js";
import { IssueStore } from "../src/issues.js";
import { EventLog } from "../src/events.js";
import { Alerter } from "../src/alerts.js";
import { upstreamTargets, DEFAULT_UPSTREAM_TARGETS } from "../src/types.js";
import type { RouterRecord } from "../src/types.js";
import { tempDir } from "./helpers.js";

function router(over: Partial<RouterRecord> = {}): RouterRecord {
  const now = new Date().toISOString();
  return {
    id: "r1", serialNumber: "DEV1", publicKey: "k", boardName: "hEX", rosVersion: "7", identity: "cpe",
    tunnelIp: "10.99.0.9", username: "u", password: "p", state: "confirmed",
    createdAt: now, updatedAt: now, lastSeenAt: now, health: "up",
    monitoring: { enabled: true, alertOnLogin: true, alertOnLinkDown: true, watchInterfaces: [] },
    ...over,
  };
}

describe("upstreamTargets", () => {
  it("defaults to 8.8.8.8 + 1.1.1.1 for monitored devices", () => {
    expect(upstreamTargets(router().monitoring)).toEqual(DEFAULT_UPSTREAM_TARGETS);
  });
  it("is empty when monitoring or upstream ping is off", () => {
    expect(upstreamTargets(undefined)).toEqual([]);
    const mon = router().monitoring!;
    mon.enabled = false;
    expect(upstreamTargets(mon)).toEqual([]);
    const mon2 = router().monitoring!;
    mon2.upstreamPing = { enabled: false, targets: [] };
    expect(upstreamTargets(mon2)).toEqual([]);
  });
  it("uses the custom list when provided, deduped", () => {
    const mon = router().monitoring!;
    mon.upstreamPing = { enabled: true, targets: ["9.9.9.9", "9.9.9.9", "8.8.8.8"] };
    expect(upstreamTargets(mon)).toEqual(["9.9.9.9", "8.8.8.8"]);
  });
});

describe("PingMetricsStore", () => {
  it("records, reloads and windows samples", () => {
    const file = path.join(tempDir(), "p.jsonl");
    const store = new PingMetricsStore(file);
    const now = Date.now();
    store.record("DEV1", { at: now - 3600_000, targets: { "8.8.8.8": { rtt: 12.34, loss: 0 } } });
    store.record("DEV1", { at: now, targets: { "8.8.8.8": { rtt: null, loss: 100 }, "1.1.1.1": { rtt: 8.1, loss: 0 } } });
    const reloaded = new PingMetricsStore(file);
    const s = reloaded.samples("DEV1", 24);
    expect(s).toHaveLength(2);
    expect(s[1].targets["8.8.8.8"].loss).toBe(100);
    expect(s[1].targets["8.8.8.8"].rtt).toBeNull();
    expect(s[1].targets["1.1.1.1"].rtt).toBeCloseTo(8.1);
    expect(reloaded.samples("DEV1", 0.5)).toHaveLength(1); // window excludes the old one
  });
});

describe("pingMonitorTick", () => {
  let store: RouterStore;
  let pings: PingMetricsStore;
  let issues: IssueStore;
  let events: EventLog;
  let alerts: string[];
  let deps: PingMonitorDeps;
  // Per-target scripted responses the fake ping serves.
  let responses: Record<string, { sent: number; received: number; avgMs: number | null }>;

  beforeEach(() => {
    resetPingLatches();
    store = new RouterStore(path.join(tempDir(), "r.json"));
    store.save(router());
    pings = new PingMetricsStore(path.join(tempDir(), "p.jsonl"));
    issues = new IssueStore(path.join(tempDir(), "i.json"));
    events = new EventLog(path.join(tempDir(), "e.jsonl"));
    alerts = [];
    responses = {
      "8.8.8.8": { sent: 3, received: 3, avgMs: 14.2 },
      "1.1.1.1": { sent: 3, received: 3, avgMs: 9.8 },
    };
    deps = {
      store, pings, issues, events, pingCount: 3,
      alerter: new Alerter({ webhookUrl: "https://h.test", notifyOnline: true, suppressMinutes: 0 } as any, async (t) => { alerts.push(t); }),
      ping: async (_ip, _u, _p, address) => responses[address] ?? { sent: 3, received: 0, avgMs: null },
    };
  });

  it("records a sample per router with rtt+loss per target", async () => {
    await pingMonitorTick(deps);
    const s = pings.samples("DEV1", 1);
    expect(s).toHaveLength(1);
    expect(s[0].targets["8.8.8.8"].rtt).toBeCloseTo(14.2);
    expect(s[0].targets["1.1.1.1"].loss).toBe(0);
    expect(issues.counts().warning).toBe(0);
  });

  it("needs two consecutive full-loss ticks before opening the issue, and recovers", async () => {
    responses["8.8.8.8"] = { sent: 3, received: 0, avgMs: null };
    await pingMonitorTick(deps); // first bad tick: streak=1, no alarm yet
    expect(issues.list().filter((i) => !i.resolvedAt)).toHaveLength(0);
    await pingMonitorTick(deps); // second bad tick: alarm
    const open = issues.list().filter((i) => !i.resolvedAt);
    expect(open).toHaveLength(1);
    expect(open[0].type).toBe("upstream-down");
    expect(open[0].ref).toBe("8.8.8.8");
    expect(alerts.some((a) => /upstream ping to 8\.8\.8\.8 FAILING/.test(a))).toBe(true);
    await pingMonitorTick(deps); // still down: no duplicate alert
    expect(alerts.filter((a) => /FAILING/.test(a))).toHaveLength(1);

    responses["8.8.8.8"] = { sent: 3, received: 3, avgMs: 15 };
    await pingMonitorTick(deps); // recovery
    expect(issues.list().filter((i) => !i.resolvedAt)).toHaveLength(0);
    expect(alerts.some((a) => /upstream ping to 8\.8\.8\.8 recovered/.test(a))).toBe(true);
  });

  it("flags sustained high latency when a threshold is set", async () => {
    const r = store.findBySerial("DEV1")!;
    r.monitoring!.upstreamPing = { enabled: true, targets: ["8.8.8.8"], alertAboveMs: 100 };
    store.save(r);
    responses["8.8.8.8"] = { sent: 3, received: 3, avgMs: 250 };
    await pingMonitorTick(deps);
    await pingMonitorTick(deps);
    const open = issues.list().filter((i) => !i.resolvedAt);
    expect(open).toHaveLength(1);
    expect(open[0].type).toBe("upstream-latency");
    expect(alerts.some((a) => /latency to 8\.8\.8\.8 high/.test(a))).toBe(true);
    responses["8.8.8.8"] = { sent: 3, received: 3, avgMs: 20 };
    await pingMonitorTick(deps);
    expect(issues.list().filter((i) => !i.resolvedAt)).toHaveLength(0);
  });

  it("skips offline routers and unmonitored devices", async () => {
    const r = store.findBySerial("DEV1")!;
    r.health = "offline";
    store.save(r);
    await pingMonitorTick(deps);
    expect(pings.samples("DEV1", 1)).toHaveLength(0);
  });

  it("respects maintenance suppression (records data, no issue/alert)", async () => {
    responses["8.8.8.8"] = { sent: 3, received: 0, avgMs: null };
    deps.suppressed = () => true;
    await pingMonitorTick(deps);
    await pingMonitorTick(deps);
    expect(pings.samples("DEV1", 1)).toHaveLength(2); // data still graphed
    expect(issues.list().filter((i) => !i.resolvedAt)).toHaveLength(0);
    expect(alerts).toHaveLength(0);
  });
});
