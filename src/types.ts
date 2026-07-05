export type RouterState = "staged" | "registered" | "confirmed" | "verified" | "revoked";

/**
 * customer       — CPE at a subscriber site. Watch WAN/uplink + logins, pull
 *                  access stats (LTE/5G signal, uptime).
 * infrastructure — towers, PoPs, core routers. Watch every port + logins,
 *                  pull port traffic/throughput.
 */
export type DeviceType = "customer" | "infrastructure";

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

export interface DeviceMonitoring {
  /** Master switch: poll this device over the tunnel for logins / link state. */
  enabled: boolean;
  /** Notify + log when someone logs into the router (Winbox/SSH/WebFig/etc). */
  alertOnLogin: boolean;
  /** Notify + raise an issue when a watched port's link drops. */
  alertOnLinkDown: boolean;
  /** Ports to watch for link-down; empty = watch nothing (opt in per port). */
  watchInterfaces: string[];
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
  };
}

export interface DeviceMonState {
  /** Last known running state per interface, to detect transitions. */
  ifaceRunning: Record<string, boolean>;
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
