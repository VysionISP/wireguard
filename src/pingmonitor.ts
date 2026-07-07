import type { RouterStore } from "./store.js";
import type { IssueStore } from "./issues.js";
import type { EventLog } from "./events.js";
import type { Alerter } from "./alerts.js";
import type { PingMetricsStore, PingSample } from "./pingmetrics.js";
import type { RouterRecord } from "./types.js";
import { upstreamTargets } from "./types.js";
import { fetchPing, type FetchPingFn } from "./routeros.js";

export interface PingMonitorDeps {
  store: RouterStore;
  pings: PingMetricsStore;
  issues: IssueStore;
  events: EventLog;
  alerter?: Alerter;
  /** Echoes per target per tick. */
  pingCount: number;
  /** Injectable for tests; defaults to the real RouterOS /ping. */
  ping?: FetchPingFn;
  /** Returns true when an active maintenance window mutes this category. */
  suppressed?: (serial: string, group: string | undefined, category: string) => boolean;
}

function label(r: RouterRecord): string {
  return r.label || r.identity || r.serialNumber;
}

// Edge-trigger latches, per (serial, target): a target alerts once when it
// goes bad and once when it recovers, not every tick. In-memory is fine —
// after a restart the worst case is one repeated notification.
const downLatch = new Set<string>();
const slowLatch = new Set<string>();
// A target only alarms after two consecutive bad ticks, so one lost burst
// (a busy CPE dropping a couple of ICMP echoes) doesn't page anyone.
const badStreak = new Map<string, number>();

/** Test hook: forget all latches (fresh state between test cases). */
export function resetPingLatches(): void {
  downLatch.clear();
  slowLatch.clear();
  badStreak.clear();
}

/**
 * One upstream-ping pass. Every monitored, currently-reachable router pings
 * its anchor targets (8.8.8.8 / 1.1.1.1 / custom) over the tunnel; RTT+loss
 * are recorded for the latency graph, and full loss or above-threshold RTT
 * opens an issue + alert (edge-triggered, with recovery).
 */
export async function pingMonitorTick(deps: PingMonitorDeps): Promise<{ checked: number }> {
  const ping = deps.ping ?? fetchPing;
  const routers = deps.store
    .list()
    .filter((r) => r.tunnelIp && r.state !== "staged" && r.state !== "revoked")
    // A router that is itself offline is already reported by liveness; piling
    // upstream-down alerts on top would just blame the wrong layer.
    .filter((r) => r.health !== "offline")
    .filter((r) => upstreamTargets(r.monitoring).length > 0);

  let checked = 0;
  const CONCURRENCY = 8;
  for (let i = 0; i < routers.length; i += CONCURRENCY) {
    await Promise.all(routers.slice(i, i + CONCURRENCY).map((r) => checkRouter(r)));
  }
  return { checked };

  async function checkRouter(r: RouterRecord): Promise<void> {
    const targets = upstreamTargets(r.monitoring);
    const alertAboveMs = r.monitoring?.upstreamPing?.alertAboveMs ?? 0;
    const sample: PingSample = { at: Date.now(), targets: {} };
    for (const target of targets) {
      let rtt: number | null = null;
      let loss = 100;
      try {
        const res = await ping(r.tunnelIp, r.username, r.password, target, deps.pingCount);
        loss = res.sent ? Math.round(((res.sent - res.received) / res.sent) * 100) : 100;
        rtt = res.received > 0 ? res.avgMs : null;
      } catch {
        // Tunnel hiccup mid-tick: count it as full loss for this target.
      }
      sample.targets[target] = { rtt, loss };
      judge(r, target, rtt, loss, alertAboveMs);
    }
    deps.pings.record(r.serialNumber, sample);
    checked++;
  }

  function judge(r: RouterRecord, target: string, rtt: number | null, loss: number, alertAboveMs: number): void {
    const key = `${r.serialNumber}:${target}`;
    const l = label(r);
    const muted = deps.suppressed?.(r.serialNumber, r.customerGroup, "link") ?? false;
    const now = new Date().toISOString();

    const down = loss >= 100;
    const slow = !down && alertAboveMs > 0 && rtt !== null && rtt > alertAboveMs;
    badStreak.set(key, down || slow ? (badStreak.get(key) ?? 0) + 1 : 0);
    const confirmed = (badStreak.get(key) ?? 0) >= 2;

    if (down && confirmed && !downLatch.has(key)) {
      downLatch.add(key);
      slowLatch.delete(key); // unreachable supersedes slow
      deps.issues.resolve(r.serialNumber, "upstream-latency", target);
      const msg = `Upstream ping to ${target} is failing (100% loss from the router)`;
      deps.events.add({ at: now, serialNumber: r.serialNumber, label: l, type: "upstream-down", severity: "warning", message: msg });
      if (!muted) {
        deps.issues.open(r.serialNumber, l, "upstream-down", "warning", msg, target);
        deps.alerter?.custom(r, `🟠 ${l}: upstream ping to ${target} FAILING (100% loss)`, "upstream-down", `upstream:${key}`).catch(() => {});
      }
    } else if (!down && downLatch.has(key)) {
      downLatch.delete(key);
      badStreak.set(key, 0);
      deps.issues.resolve(r.serialNumber, "upstream-down", target);
      deps.events.add({ at: now, serialNumber: r.serialNumber, label: l, type: "upstream-up", severity: "info", message: `Upstream ping to ${target} recovered (${rtt != null ? rtt.toFixed(1) + " ms" : "replies again"})` });
      if (!muted) deps.alerter?.custom(r, `🟢 ${l}: upstream ping to ${target} recovered${rtt != null ? ` (${rtt.toFixed(1)} ms)` : ""}`, "upstream-up").catch(() => {});
      return;
    }

    if (slow && confirmed && !downLatch.has(key) && !slowLatch.has(key)) {
      slowLatch.add(key);
      const msg = `Upstream latency to ${target} is ${rtt!.toFixed(1)} ms (threshold ${alertAboveMs} ms)`;
      deps.events.add({ at: now, serialNumber: r.serialNumber, label: l, type: "upstream-latency", severity: "warning", message: msg });
      if (!muted) {
        deps.issues.open(r.serialNumber, l, "upstream-latency", "warning", msg, target);
        deps.alerter?.custom(r, `🟠 ${l}: upstream latency to ${target} high — ${rtt!.toFixed(1)} ms (limit ${alertAboveMs} ms)`, "upstream-latency", `upslow:${key}`).catch(() => {});
      }
    } else if (!slow && !down && slowLatch.has(key)) {
      slowLatch.delete(key);
      deps.issues.resolve(r.serialNumber, "upstream-latency", target);
      deps.events.add({ at: now, serialNumber: r.serialNumber, label: l, type: "upstream-up", severity: "info", message: `Upstream latency to ${target} back to ${rtt != null ? rtt.toFixed(1) + " ms" : "normal"}` });
      if (!muted) deps.alerter?.custom(r, `🟢 ${l}: upstream latency to ${target} back to normal${rtt != null ? ` (${rtt.toFixed(1)} ms)` : ""}`, "upstream-up").catch(() => {});
    }
  }
}

export function startPingMonitor(deps: PingMonitorDeps, intervalSeconds: number): () => void {
  let busy = false;
  const run = async () => {
    if (busy) return; // a slow fleet pass must not stack a second pass on top
    busy = true;
    try {
      await pingMonitorTick(deps);
    } catch (err) {
      console.error("ping monitor tick failed:", (err as Error).message);
    } finally {
      busy = false;
    }
  };
  void run();
  const timer = setInterval(run, intervalSeconds * 1000);
  return () => clearInterval(timer);
}
