import net from "node:net";
import type { RouterStore } from "./store.js";
import type { IssueStore } from "./issues.js";
import type { EventLog } from "./events.js";
import type { Alerter } from "./alerts.js";
import type { RouterRecord, HealthState } from "./types.js";

const MAX_TRANSITIONS = 30;

/**
 * Active liveness probe: a plain TCP connect to a device over the management
 * tunnel. Far faster than WireGuard handshake age (which only re-handshakes
 * every ~2 min on a healthy link), so we can flag trouble in seconds.
 *
 * A successful connect means "up". A connection *refused/reset* also means the
 * host answered — it's alive, just not listening on that port — so we treat it
 * as up too. Only a timeout / unreachable (no answer at all) counts as down.
 */
export function tcpPing(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let done = false;
    const finish = (alive: boolean): void => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve(alive);
    };
    sock.setTimeout(timeoutMs);
    sock.once("connect", () => finish(true));
    sock.once("timeout", () => finish(false));
    sock.once("error", (err: NodeJS.ErrnoException) => {
      finish(err.code === "ECONNREFUSED" || err.code === "ECONNRESET");
    });
    sock.connect(port, host);
  });
}

export type PingFn = (host: string, port: number, timeoutMs: number) => Promise<boolean>;

export interface LivenessDeps {
  store: RouterStore;
  issues: IssueStore;
  events: EventLog;
  alerter?: Alerter;
  /** No probe success for this long -> warning. */
  warnAfterSeconds: number;
  /** No probe success for this long -> offline (opens the issue). */
  offlineAfterSeconds: number;
  port: number;
  timeoutMs: number;
  /** Injectable for tests; defaults to a real TCP connect. */
  ping?: PingFn;
}

function labelOf(r: RouterRecord): string {
  return r.label || r.identity || r.serialNumber;
}

/**
 * One liveness pass. Probes every non-staged/non-revoked device that has a
 * tunnel IP, then moves each through up -> warning -> offline based on how long
 * it's been since the last successful probe. Only "offline" raises the issue +
 * alert; "warning" is a soft, visual-only degraded state.
 */
export async function livenessTick(deps: LivenessDeps): Promise<{ up: number; warning: number; offline: number }> {
  const ping = deps.ping ?? tcpPing;
  const nowMs = Date.now();
  const now = new Date(nowMs).toISOString();
  const stats = { up: 0, warning: 0, offline: 0 };

  const targets = deps.store.list().filter(
    (r) => r.state !== "revoked" && r.state !== "staged" && r.tunnelIp,
  );

  const CONCURRENCY = 20;
  for (let i = 0; i < targets.length; i += CONCURRENCY) {
    await Promise.all(targets.slice(i, i + CONCURRENCY).map((r) => probeOne(r)));
  }
  return stats;

  async function probeOne(router: RouterRecord): Promise<void> {
    const alive = await ping(router.tunnelIp, deps.port, deps.timeoutMs).catch(() => false);
    if (alive) router.lastPingOkAt = now;

    // Seconds since we last saw it (huge if never seen).
    const okMs = router.lastPingOkAt ? Date.parse(router.lastPingOkAt) : null;
    const downFor = okMs === null ? Infinity : (nowMs - okMs) / 1000;

    let next: HealthState;
    if (alive || downFor < deps.warnAfterSeconds) next = "up";
    else if (downFor < deps.offlineAfterSeconds) next = "warning";
    else next = "offline";

    if (next === "up") stats.up++;
    else if (next === "warning") stats.warning++;
    else stats.offline++;

    const prev = router.health;
    let dirty = false;
    if (alive && router.lastSeenAt !== now) {
      router.lastSeenAt = now;
      dirty = true;
    }

    if (prev === undefined) {
      // First probe after deploy: set the baseline quietly (don't fire an
      // offline for a device that has simply never come up yet — but if it IS
      // reachable, record that as an up transition so the dot goes green).
      router.health = next;
      router.lastOnline = next !== "offline";
      dirty = true;
    } else if (prev !== next) {
      router.health = next;
      dirty = true;
      handleTransition(router, prev, next, now);
    }

    if (dirty) deps.store.save(router);
  }

  function handleTransition(router: RouterRecord, prev: HealthState, next: HealthState, at: string): void {
    const label = labelOf(router);
    const wasOffline = prev === "offline";
    const isOffline = next === "offline";
    const online = next !== "offline";

    if (router.lastOnline !== online) {
      router.lastOnline = online;
      router.transitions = [...(router.transitions ?? []), { at, online }].slice(-MAX_TRANSITIONS);
      router.updatedAt = at;
    }

    if (next === "warning") {
      // Degraded — record it, but don't open an issue or hard-alert yet.
      deps.events.add({ at, serialNumber: router.serialNumber, label, type: "offline", severity: "warning", message: `${label} not responding — degraded` });
      return;
    }
    if (isOffline) {
      console.log(`liveness: ${router.serialNumber} went offline`);
      deps.issues.open(router.serialNumber, label, "offline", "critical", `${label} is offline (no response for ${deps.offlineAfterSeconds}s)`);
      deps.events.add({ at, serialNumber: router.serialNumber, label, type: "offline", severity: "critical", message: `${label} went offline` });
      deps.alerter?.routerTransition(router, false).catch((err) => console.error(`alert failed: ${(err as Error).message}`));
      return;
    }
    if (next === "up" && wasOffline) {
      console.log(`liveness: ${router.serialNumber} back online`);
      deps.issues.resolve(router.serialNumber, "offline");
      deps.events.add({ at, serialNumber: router.serialNumber, label, type: "online", severity: "info", message: `${label} came back online` });
      deps.alerter?.routerTransition(router, true).catch((err) => console.error(`alert failed: ${(err as Error).message}`));
    } else if (next === "up" && prev === "warning") {
      // Recovered from a brief blip before it ever hit offline — clear silently.
      deps.events.add({ at, serialNumber: router.serialNumber, label, type: "online", severity: "info", message: `${label} responding again` });
    }
  }
}

/** Runs livenessTick on an interval; returns a stop function. */
export function startLiveness(deps: LivenessDeps, intervalSeconds: number): () => void {
  const timer = setInterval(() => {
    livenessTick(deps).catch((err) => console.error(`liveness: ${(err as Error).message}`));
  }, intervalSeconds * 1000);
  timer.unref?.();
  void livenessTick(deps).catch(() => undefined);
  return () => clearInterval(timer);
}
