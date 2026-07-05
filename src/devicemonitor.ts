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
  /** The management account we log in as; its logins are our own polling. */
  managementUsername: string;
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

/**
 * Extract a login from a log line, or null to ignore it. Logins by the
 * management account are dropped — those are this server's own REST/API
 * polling.
 */
function loginInfo(entry: LogEntry, mgmtUser: string): { summary: string } | null {
  if (!/logged in/i.test(entry.message)) return null;
  const who = /^user (\S+) logged in/i.exec(entry.message)?.[1];
  if (who && mgmtUser && who === mgmtUser) return null;
  return { summary: entry.message.trim() };
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
      // Each login log line, keyed by time+message so it's a stable per-entry
      // identity across polls — a genuinely new login (new timestamp) is a new
      // key and always alerts, even if the text matches a past login.
      const entries: Array<{ key: string; msg: string }> = [];
      for (const entry of log) {
        const info = loginInfo(entry, deps.managementUsername);
        if (info) entries.push({ key: `${entry.time}|${info.summary}`, msg: info.summary });
      }
      if (state.initialised) {
        // Collapse the burst of identical lines Winbox writes for ONE login
        // (same message within this poll) to a single alert, while still
        // recording every entry key below so we don't re-alert next poll.
        const alertedThisPoll = new Set<string>();
        for (const e of entries) {
          if (prevSeen.has(e.key) || alertedThisPoll.has(e.msg)) continue;
          alertedThisPoll.add(e.msg);
          events.add({ at: now, serialNumber: router.serialNumber, label: labelOf(router), type: "login", severity: "info", message: e.msg });
          alerter.custom(router, `🔑 ${labelOf(router)}: ${e.msg}`, "login").catch(() => {});
        }
      }
      state.seenLogins = entries.map((e) => e.key).slice(-MAX_SEEN_LOGINS);
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
