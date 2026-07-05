import type { RouterStore } from "./store.js";
import type { WireguardManager } from "./wireguard.js";
import type { IssueStore } from "./issues.js";
import type { EventLog } from "./events.js";
import type { Alerter } from "./alerts.js";
import type { RouterRecord, DeviceMonitoring } from "./types.js";
import {
  fetchInterfaces as realFetchInterfaces,
  fetchLog as realFetchLog,
  type FetchIfacesFn,
  type FetchLogFn,
  type LogEntry,
} from "./routeros.js";

const MAX_SEEN_LOGINS = 500;
const AUTO_WATCH_TYPES = new Set(["ether", "sfp", "sfp-plus", "wlan", "lte"]);

export interface DeviceMonitorDeps {
  store: RouterStore;
  wg: WireguardManager;
  issues: IssueStore;
  events: EventLog;
  alerter: Alerter;
  offlineAfterSeconds: number;
  fetchInterfaces?: FetchIfacesFn;
  fetchLog?: FetchLogFn;
}

function labelOf(r: RouterRecord): string {
  return r.label || r.identity || r.serialNumber;
}

/** Which interfaces this device's rules watch (explicit list, or auto). */
function watchedInterfaces(mon: DeviceMonitoring, all: string[], auto: Set<string>): string[] {
  if (mon.watchInterfaces.length > 0) return mon.watchInterfaces.filter((n) => all.includes(n));
  return [...auto];
}

/** Extract a stable signature + human summary for a login log line. */
function loginInfo(entry: LogEntry): { key: string; summary: string } | null {
  if (!/logged in/i.test(entry.message)) return null;
  if (!/account/i.test(entry.topics) && !/logged in/i.test(entry.message)) return null;
  // Message forms: "user admin logged in from 10.0.0.5 via winbox"
  return { key: `${entry.time}|${entry.message}`, summary: entry.message };
}

/**
 * One device-monitor pass. For each monitored, currently-online router it
 * polls interface state and the log over the tunnel, then:
 *   - raises/clears a "link-down" issue + event when a watched port flaps
 *   - emits a "login" event + alert for each new login it sees
 * All detection state lives on the router record (monState) so it survives
 * restarts and never double-fires.
 */
export async function deviceMonitorTick(deps: DeviceMonitorDeps): Promise<{ polled: number; errors: number }> {
  const { store, wg, issues, events, alerter, offlineAfterSeconds } = deps;
  const fetchIfaces = deps.fetchInterfaces ?? realFetchInterfaces;
  const fetchLog = deps.fetchLog ?? realFetchLog;

  const handshakes = await wg.latestHandshakes().catch(() => ({}) as Record<string, number | null>);
  const targets = store.list().filter((r) => {
    if (!r.monitoring?.enabled) return false;
    if (r.state === "revoked" || r.state === "staged") return false;
    const age = handshakes[r.publicKey] ?? null;
    return age !== null && age < offlineAfterSeconds;
  });

  let errors = 0;
  const CONCURRENCY = 5;
  for (let i = 0; i < targets.length; i += CONCURRENCY) {
    await Promise.all(
      targets.slice(i, i + CONCURRENCY).map((r) => pollOne(r).catch(() => (errors++, undefined))),
    );
  }
  return { polled: targets.length, errors };

  async function pollOne(router: RouterRecord): Promise<void> {
    const mon = router.monitoring!;
    const state = (router.monState ??= { ifaceRunning: {}, seenLogins: [], initialised: false });
    const now = new Date().toISOString();
    let dirty = false;

    // ---- interface link state
    if (mon.alertOnLinkDown) {
      const ifaces = await fetchIfaces(router.tunnelIp, router.username, router.password);
      const names = ifaces.map((i) => i.name);
      const auto = new Set(ifaces.filter((i) => AUTO_WATCH_TYPES.has(i.type)).map((i) => i.name));
      const watch = new Set(watchedInterfaces(mon, names, auto));
      for (const iface of ifaces) {
        if (!watch.has(iface.name) || iface.disabled) continue;
        const prev = state.ifaceRunning[iface.name];
        if (prev === undefined) {
          state.ifaceRunning[iface.name] = iface.running;
          dirty = true;
          continue;
        }
        if (prev !== iface.running) {
          state.ifaceRunning[iface.name] = iface.running;
          dirty = true;
          if (!iface.running) {
            const msg = `Port ${iface.name} link went DOWN`;
            events.add({ at: now, serialNumber: router.serialNumber, label: labelOf(router), type: "link-down", severity: "warning", message: msg });
            issues.open(router.serialNumber, labelOf(router), "link-down", "warning", msg, iface.name);
            alerter.custom(router, `🟠 ${labelOf(router)}: ${msg}`, "link-down", `linkdown:${router.serialNumber}:${iface.name}`).catch(() => {});
          } else {
            // Only announce recovery if we'd actually opened an issue for this
            // port — avoids a spurious "restored" when a port that was down at
            // baseline simply comes up.
            const hadIssue = issues.resolve(router.serialNumber, "link-down", iface.name);
            if (hadIssue) {
              events.add({ at: now, serialNumber: router.serialNumber, label: labelOf(router), type: "link-up", severity: "info", message: `Port ${iface.name} link restored` });
              alerter.custom(router, `🟢 ${labelOf(router)}: port ${iface.name} link restored`, "link-up").catch(() => {});
            }
          }
        }
      }
    }

    // ---- logins
    if (mon.alertOnLogin) {
      const log = await fetchLog(router.tunnelIp, router.username, router.password);
      const prevSeen = new Set(state.seenLogins);
      // Every login currently in the router's memory log. This IS the source
      // of truth: an entry can't reappear once the ring buffer rotates it out,
      // so we set (not accumulate+truncate) — which fixes false re-alerts when
      // the log holds more login lines than the old cap.
      const current: { key: string; summary: string }[] = [];
      for (const entry of log) {
        const info = loginInfo(entry);
        if (info) current.push(info);
      }
      if (state.initialised) {
        for (const c of current) {
          if (prevSeen.has(c.key)) continue;
          events.add({ at: now, serialNumber: router.serialNumber, label: labelOf(router), type: "login", severity: "info", message: c.summary });
          alerter.custom(router, `🔑 ${labelOf(router)}: ${c.summary}`, "login").catch(() => {});
        }
      }
      // Keep a generous bound; RouterOS memory logs are far smaller than this.
      state.seenLogins = current.map((c) => c.key).slice(-MAX_SEEN_LOGINS);
      dirty = true;
    }

    if (!state.initialised) {
      state.initialised = true;
      dirty = true;
    }
    if (dirty) {
      router.lastSeenAt = now;
      store.save(router);
    }
  }
}

export function startDeviceMonitor(deps: DeviceMonitorDeps, intervalSeconds: number): () => void {
  const timer = setInterval(() => {
    deviceMonitorTick(deps).catch((err) => console.error(`device-monitor: ${(err as Error).message}`));
  }, intervalSeconds * 1000);
  timer.unref();
  return () => clearInterval(timer);
}
