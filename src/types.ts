export type RouterState = "staged" | "registered" | "confirmed" | "verified" | "revoked";

/**
 * customer       — CPE at a subscriber site. Watch WAN/uplink + logins, pull
 *                  access stats (LTE/5G signal, uptime).
 * infrastructure — towers, PoPs, core routers. Watch every port + logins,
 *                  pull port traffic/throughput.
 */
export type DeviceType = "customer" | "infrastructure";

/** Active-ping liveness state. */
export type HealthState = "up" | "warning" | "offline";

export interface RouterRecord {
  /** Stable internal id (uuid). */
  id: string;
  /** RouterBOARD serial number — the zero-touch identity of the device. */
  serialNumber: string;
  /** Current WireGuard public key of the router. */
  publicKey: string;
  boardName: string;
  rosVersion: string;
  identity: string;
  /** Management IP allocated inside the WireGuard tunnel subnet. */
  tunnelIp: string;
  /** Management credentials created on the router during provisioning. */
  username: string;
  password: string;
  state: RouterState;
  createdAt: string;
  updatedAt: string;
  lastSeenAt: string | null;
  /** Operator-set friendly name (customer, site…). Absent on old records. */
  label?: string;
  /** Customer group this device belongs to (for grouping + topology maps). */
  customerGroup?: string;
  /** Operator notes. Absent on old records. */
  notes?: string;
  /** Last online/offline verdict from the monitor; undefined until first tick. */
  lastOnline?: boolean;
  /**
   * Three-state liveness from the active ping monitor:
   * "up" (reachable), "warning" (missed pings, degrading), "offline" (down).
   * Undefined until the first probe.
   */
  health?: HealthState;
  /** ISO time of the last successful liveness probe. */
  lastPingOkAt?: string | null;
  /** Recent online/offline transitions (bounded), newest last. */
  transitions?: Array<{ at: string; online: boolean }>;
  /** When the router last pushed a config backup that we stored or matched. */
  lastBackupAt?: string | null;
  /** Classification driving monitoring profile and which stats we pull. */
  deviceType?: DeviceType;
  /** Per-device active monitoring rules. Absent = not monitored. */
  monitoring?: DeviceMonitoring;
  /** Internal bookkeeping for the device monitor; not user-facing. */
  monState?: DeviceMonState;
}

/** Per-port monitoring rule. A device watches zero or more of these. */
export interface PortRule {
  /** Interface name, e.g. "ether1" / "sfp-sfpplus1". */
  name: string;
  /** Alert on link state changes for this port. */
  link: boolean;
  /**
   * Invert the link logic: the alarm state is the port being UP, and DOWN is
   * "normal". Use for ports that are meant to stay unplugged (a spare WAN, a
   * disabled uplink) so someone plugging in gets flagged.
   */
  inverted: boolean;
  /** Alert when combined throughput rises above this many bits/sec (0 = off). */
  highBps?: number;
  /** Alert when combined throughput (while up) falls below this many bits/sec (0 = off). */
  lowBps?: number;
}

export interface DeviceMonitoring {
  /** Master switch: poll this device over the tunnel for logins / link state. */
  enabled: boolean;
  /** Notify + log when someone logs into the router (Winbox/SSH/WebFig/etc). */
  alertOnLogin: boolean;
  /** Master switch for port monitoring (link state + traffic thresholds). */
  alertOnLinkDown: boolean;
  /** Legacy plain watch-list (link-down only); migrated into `ports`. */
  watchInterfaces: string[];
  /** Per-port rules: link (optionally inverted) + traffic thresholds. */
  ports?: PortRule[];
}

/**
 * The effective set of port rules, migrating a legacy plain watch-list into
 * the richer per-port shape (link on, not inverted, no traffic thresholds).
 */
export function effectivePorts(mon: DeviceMonitoring): PortRule[] {
  if (mon.ports && mon.ports.length) return mon.ports;
  return (mon.watchInterfaces ?? []).map((name) => ({ name, link: true, inverted: false }));
}

/** Default monitoring rules for a device type. */
export function defaultMonitoring(type: DeviceType, alertOnLogin: boolean, alertOnLinkDown: boolean): DeviceMonitoring {
  return {
    enabled: true,
    alertOnLogin,
    // Infrastructure links are load-bearing — always watch them; a customer's
    // single uplink dropping is often just the customer's own power/modem.
    alertOnLinkDown: type === "infrastructure" ? true : alertOnLinkDown,
    watchInterfaces: [],
    ports: [],
  };
}

export interface DeviceMonState {
  /** Last known running state per interface, to detect transitions. */
  ifaceRunning: Record<string, boolean>;
  /** Last counter reading per interface, to derive throughput between polls. */
  ifaceBytes?: Record<string, { rx: number; tx: number; at: number }>;
  /** Latched traffic-threshold alarm state per interface (edge-triggering). */
  portAlarm?: Record<string, { high?: boolean; low?: boolean }>;
  /** Recently-seen login log signatures (bounded) so we don't re-alert. */
  seenLogins: string[];
  /** False until the first successful poll establishes a baseline. */
  initialised: boolean;
}

export interface RegisterRequest {
  token: string;
  publicKey: string;
  serialNumber: string;
  boardName?: string;
  rosVersion?: string;
  identity?: string;
}
