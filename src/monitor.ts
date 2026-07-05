import type { RouterStore } from "./store.js";
import type { WireguardManager } from "./wireguard.js";
import type { Alerter } from "./alerts.js";
import type { IssueStore } from "./issues.js";
import type { EventLog } from "./events.js";

const MAX_TRANSITIONS = 30;

export interface MonitorHooks {
  issues?: IssueStore;
  events?: EventLog;
}

export interface MonitorStats {
  online: number;
  offline: number;
  changed: number;
}

/**
 * One monitoring pass: reads all handshake ages in a single `wg show` call,
 * updates lastSeenAt for online routers and records online/offline
 * transitions so link flapping is visible in the dashboard.
 */
export async function monitorTick(
  store: RouterStore,
  wg: WireguardManager,
  offlineAfterSeconds: number,
  alerter?: Alerter,
  hooks: MonitorHooks = {},
): Promise<MonitorStats> {
  const handshakes = await wg.latestHandshakes().catch(() => null);
  if (handshakes === null) return { online: 0, offline: 0, changed: 0 };

  const now = new Date().toISOString();
  const stats: MonitorStats = { online: 0, offline: 0, changed: 0 };

  for (const router of store.list()) {
    if (router.state === "revoked" || router.state === "staged") continue;
    const age = handshakes[router.publicKey] ?? null;
    const isOnline = age !== null && age < offlineAfterSeconds;
    if (isOnline) stats.online++;
    else stats.offline++;

    let dirty = false;
    if (isOnline && router.lastSeenAt !== now) {
      router.lastSeenAt = now;
      dirty = true;
    }
    if (router.lastOnline === undefined) {
      // First tick after deploy/registration: set the baseline quietly so we
      // don't record a bogus "went offline" for routers that were never up.
      router.lastOnline = isOnline;
      dirty = true;
    } else if (router.lastOnline !== isOnline) {
      router.lastOnline = isOnline;
      router.transitions = [...(router.transitions ?? []), { at: now, online: isOnline }].slice(
        -MAX_TRANSITIONS,
      );
      router.updatedAt = now;
      stats.changed++;
      dirty = true;
      console.log(`monitor: ${router.serialNumber} went ${isOnline ? "online" : "offline"}`);
      alerter?.routerTransition(router, isOnline).catch((err) =>
        console.error(`alert failed: ${(err as Error).message}`),
      );
      const label = router.label || router.identity || router.serialNumber;
      if (isOnline) {
        hooks.issues?.resolve(router.serialNumber, "offline");
        hooks.events?.add({ at: now, serialNumber: router.serialNumber, label, type: "online", severity: "info", message: `${label} came back online` });
      } else {
        hooks.issues?.open(router.serialNumber, label, "offline", "critical", `${label} is offline (no WireGuard handshake)`);
        hooks.events?.add({ at: now, serialNumber: router.serialNumber, label, type: "offline", severity: "critical", message: `${label} went offline` });
      }
    }
    if (dirty) store.save(router);
  }
  return stats;
}

/** Runs monitorTick on an interval; returns a stop function. */
export function startMonitor(
  store: RouterStore,
  wg: WireguardManager,
  intervalSeconds: number,
  offlineAfterSeconds: number,
  alerter?: Alerter,
  hooks: MonitorHooks = {},
): () => void {
  const timer = setInterval(() => {
    monitorTick(store, wg, offlineAfterSeconds, alerter, hooks).catch((err) =>
      console.error(`monitor: ${(err as Error).message}`),
    );
  }, intervalSeconds * 1000);
  timer.unref();
  return () => clearInterval(timer);
}
