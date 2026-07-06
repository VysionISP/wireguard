import type { RouterStore } from "./store.js";
import type { IssueStore } from "./issues.js";
import type { EventLog } from "./events.js";
import type { Alerter } from "./alerts.js";
import type { HostStore, MonitoredHost } from "./hosts.js";
import type { HealthState, RouterRecord } from "./types.js";
import { fetchPing, type FetchPingFn } from "./routeros.js";

export interface HostMonitorDeps {
  store: RouterStore;
  hosts: HostStore;
  issues: IssueStore;
  events: EventLog;
  alerter?: Alerter;
  warnAfterSeconds: number;
  offlineAfterSeconds: number;
  pingCount: number;
  /** Injectable for tests; defaults to the real RouterOS /ping. */
  ping?: FetchPingFn;
}

function routerLabel(r: RouterRecord): string {
  return r.label || r.identity || r.serialNumber;
}
function hostName(h: MonitoredHost): string {
  return h.name ? `${h.name} (${h.address})` : h.address;
}

/**
 * One host-monitor pass. For each enabled monitored host whose router is
 * reachable, asks the router to ping it and moves the host through
 * up -> warning -> offline. If the router itself is unreachable we skip the
 * host (the router being down is the real, separately-reported problem) rather
 * than blaming the internal device.
 */
export async function hostMonitorTick(deps: HostMonitorDeps): Promise<{ checked: number }> {
  const ping = deps.ping ?? fetchPing;
  const nowMs = Date.now();
  const now = new Date(nowMs).toISOString();
  const targets = deps.hosts.list().filter((h) => h.enabled);

  let checked = 0;
  const CONCURRENCY = 10;
  for (let i = 0; i < targets.length; i += CONCURRENCY) {
    await Promise.all(targets.slice(i, i + CONCURRENCY).map((h) => checkOne(h)));
  }
  return { checked };

  async function checkOne(host: MonitoredHost): Promise<void> {
    const router = deps.store.findBySerial(host.routerSerial);
    if (!router || router.state === "revoked" || router.state === "staged" || !router.tunnelIp) return;
    // Don't penalise the host when we can't even reach its router.
    if (router.health === "offline") return;

    let received: number | null = null;
    let rtt: number | null = null;
    try {
      const r = await ping(router.tunnelIp, router.username, router.password, host.address, deps.pingCount, Math.max(4000, (deps.pingCount + 3) * 1000));
      received = r.received;
      rtt = r.avgMs;
    } catch {
      // Router REST unreachable this pass — skip without changing host state.
      return;
    }
    checked++;

    const alive = received > 0;
    if (alive) {
      host.lastOkAt = now;
      host.lastRttMs = rtt;
    }
    host.lastCheckAt = now;

    const okMs = host.lastOkAt ? Date.parse(host.lastOkAt) : null;
    const downFor = okMs === null ? Infinity : (nowMs - okMs) / 1000;
    let next: HealthState;
    if (alive || downFor < deps.warnAfterSeconds) next = "up";
    else if (downFor < deps.offlineAfterSeconds) next = "warning";
    else next = "offline";

    const prev = host.state;
    host.state = next;
    if (prev !== undefined && prev !== next) transition(router, host, prev, next, now);
    deps.hosts.save(host);
  }

  function transition(router: RouterRecord, host: MonitoredHost, prev: HealthState, next: HealthState, at: string): void {
    const rl = routerLabel(router);
    const label = `${hostName(host)} · ${rl}`;
    const ref = `host:${host.address}`;
    if (next === "warning") {
      deps.events.add({ at, serialNumber: router.serialNumber, label, type: "host-down", severity: "warning", message: `${hostName(host)} not responding — degraded` });
      return;
    }
    if (next === "offline") {
      deps.issues.open(router.serialNumber, label, "host-down", "critical", `Internal host ${hostName(host)} is offline (no ping reply for ${deps.offlineAfterSeconds}s)`, ref);
      deps.events.add({ at, serialNumber: router.serialNumber, label, type: "host-down", severity: "critical", message: `${hostName(host)} went offline` });
      deps.alerter?.custom(router, `🔴 ${rl}: internal host ${hostName(host)} is OFFLINE`, "host-down", `hostdown:${router.serialNumber}:${host.address}`).catch(() => {});
      return;
    }
    if (next === "up" && prev === "offline") {
      deps.issues.resolve(router.serialNumber, "host-down", ref);
      deps.events.add({ at, serialNumber: router.serialNumber, label, type: "host-up", severity: "info", message: `${hostName(host)} came back online` });
      deps.alerter?.custom(router, `🟢 ${rl}: internal host ${hostName(host)} is back online`, "host-up").catch(() => {});
    } else if (next === "up" && prev === "warning") {
      deps.events.add({ at, serialNumber: router.serialNumber, label, type: "host-up", severity: "info", message: `${hostName(host)} responding again` });
    }
  }
}

export function startHostMonitor(deps: HostMonitorDeps, intervalSeconds: number): () => void {
  const timer = setInterval(() => {
    hostMonitorTick(deps).catch((err) => console.error(`host-monitor: ${(err as Error).message}`));
  }, intervalSeconds * 1000);
  timer.unref?.();
  void hostMonitorTick(deps).catch(() => undefined);
  return () => clearInterval(timer);
}
