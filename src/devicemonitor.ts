import type { RouterStore } from "./store.js";
import type { WireguardManager } from "./wireguard.js";
import type { IssueStore } from "./issues.js";
import type { EventLog } from "./events.js";
import type { Alerter } from "./alerts.js";
import type { RouterRecord, DeviceMonState, PortRule } from "./types.js";
import { effectivePorts } from "./types.js";
import {
  fetchInterfaces as realFetchInterfaces,
  fetchLog as realFetchLog,
  type FetchIfacesFn,
  type FetchLogFn,
  type IfaceState,
  type LogEntry,
} from "./routeros.js";

const MAX_SEEN_LOGINS = 500;

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

/** Human-readable bits/sec, for alert text. */
function fmtBps(bps: number): string {
  if (!bps || bps < 1) return "0 bps";
  const u = ["bps", "Kbps", "Mbps", "Gbps"];
  const i = Math.min(u.length - 1, Math.floor(Math.log(bps) / Math.log(1000)));
  return (bps / 1000 ** i).toFixed(i ? 1 : 0) + " " + u[i];
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
    const tickMs = Date.now();
    let dirty = false;

    // ---- per-port monitoring: link state (optionally inverted) + traffic.
    // Any configured port rule is evaluated — the device is already gated by
    // monitoring.enabled, so having a rule at all means "watch this port".
    {
      const rules = new Map(effectivePorts(mon).map((p) => [p.name, p]));
      if (rules.size > 0) {
        const ifaces = await fetchIfaces(router.tunnelIp, router.username, router.password);
        state.ifaceBytes ??= {};
        state.portAlarm ??= {};
        for (const iface of ifaces) {
          const rule = rules.get(iface.name);
          if (!rule || iface.disabled) continue;
          if (evalPort(router, state, rule, iface, now, tickMs)) dirty = true;
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

  /**
   * Evaluate one port against its rule: link state (optionally inverted) and
   * traffic high/low thresholds. Returns true if any state changed (so the
   * caller persists monState). All alerts are edge-triggered off latched state
   * so a sustained condition doesn't re-fire every poll.
   */
  function evalPort(
    router: RouterRecord,
    state: DeviceMonState,
    rule: PortRule,
    iface: IfaceState,
    now: string,
    tickMs: number,
  ): boolean {
    const label = labelOf(router);
    const name = iface.name;
    let dirty = false;

    // --- link state (inverted flips which state is the alarm) ---
    if (rule.link) {
      const prev = state.ifaceRunning[name];
      if (prev === undefined) {
        state.ifaceRunning[name] = iface.running;
        dirty = true;
      } else if (prev !== iface.running) {
        state.ifaceRunning[name] = iface.running;
        dirty = true;
        // A running transition always flips the alarm condition, whatever the
        // inversion: alarm = inverted ? up : down.
        const alarm = rule.inverted ? iface.running : !iface.running;
        if (alarm) {
          const msg = rule.inverted
            ? `Port ${name} came UP (expected DOWN)`
            : `Port ${name} link went DOWN`;
          events.add({ at: now, serialNumber: router.serialNumber, label, type: "link-down", severity: "warning", message: msg });
          issues.open(router.serialNumber, label, "link-down", "warning", msg, name);
          alerter.custom(router, `🟠 ${label}: ${msg}`, "link-down", `linkdown:${router.serialNumber}:${name}`).catch(() => {});
        } else {
          const hadIssue = issues.resolve(router.serialNumber, "link-down", name);
          if (hadIssue) {
            const msg = rule.inverted
              ? `Port ${name} returned to DOWN (expected)`
              : `Port ${name} link restored`;
            events.add({ at: now, serialNumber: router.serialNumber, label, type: "link-up", severity: "info", message: msg });
            alerter.custom(router, `🟢 ${label}: ${msg}`, "link-up").catch(() => {});
          }
        }
      }
    }

    // --- traffic thresholds (combined rx+tx bits/sec) ---
    if (rule.highBps || rule.lowBps) {
      const prevB = state.ifaceBytes![name];
      const alarm = (state.portAlarm![name] ??= {});
      let bps: number | null = null;
      if (prevB) {
        const dt = (tickMs - prevB.at) / 1000;
        if (dt > 0) {
          const drx = iface.rxByte >= prevB.rx ? iface.rxByte - prevB.rx : 0;
          const dtx = iface.txByte >= prevB.tx ? iface.txByte - prevB.tx : 0;
          bps = ((drx + dtx) * 8) / dt;
        }
      }
      state.ifaceBytes![name] = { rx: iface.rxByte, tx: iface.txByte, at: tickMs };
      dirty = true;
      if (bps !== null) {
        // High: fire when crossing above; clear with 10% hysteresis.
        if (rule.highBps) {
          if (!alarm.high && bps > rule.highBps) {
            alarm.high = true;
            const msg = `Port ${name} traffic ${fmtBps(bps)} above threshold ${fmtBps(rule.highBps)}`;
            events.add({ at: now, serialNumber: router.serialNumber, label, type: "traffic-high", severity: "warning", message: msg });
            issues.open(router.serialNumber, label, "traffic-high", "warning", msg, name);
            alerter.custom(router, `🔺 ${label}: ${msg}`, "traffic-high", `trafhigh:${router.serialNumber}:${name}`).catch(() => {});
          } else if (alarm.high && bps < rule.highBps * 0.9) {
            alarm.high = false;
            issues.resolve(router.serialNumber, "traffic-high", name);
            alerter.custom(router, `✅ ${label}: port ${name} traffic back below ${fmtBps(rule.highBps)}`, "traffic-high").catch(() => {});
          }
        }
        // Low: only meaningful while the link is up.
        if (rule.lowBps) {
          if (!alarm.low && iface.running && bps < rule.lowBps) {
            alarm.low = true;
            const msg = `Port ${name} traffic ${fmtBps(bps)} below threshold ${fmtBps(rule.lowBps)}`;
            events.add({ at: now, serialNumber: router.serialNumber, label, type: "traffic-low", severity: "warning", message: msg });
            issues.open(router.serialNumber, label, "traffic-low", "warning", msg, name);
            alerter.custom(router, `🔻 ${label}: ${msg}`, "traffic-low", `traflow:${router.serialNumber}:${name}`).catch(() => {});
          } else if (alarm.low && (!iface.running || bps > rule.lowBps * 1.1)) {
            alarm.low = false;
            issues.resolve(router.serialNumber, "traffic-low", name);
            alerter.custom(router, `✅ ${label}: port ${name} traffic back above ${fmtBps(rule.lowBps)}`, "traffic-low").catch(() => {});
          }
        }
      }
    }
    return dirty;
  }
}

export function startDeviceMonitor(deps: DeviceMonitorDeps, intervalSeconds: number): () => void {
  const timer = setInterval(() => {
    deviceMonitorTick(deps).catch((err) => console.error(`device-monitor: ${(err as Error).message}`));
  }, intervalSeconds * 1000);
  timer.unref();
  return () => clearInterval(timer);
}
