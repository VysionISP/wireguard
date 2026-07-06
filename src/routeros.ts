/**
 * Minimal RouterOS REST client, used over the management tunnel.
 *
 * RouterOS v7 serves its REST API on the `www` service under /rest. We talk
 * plain HTTP because the traffic already rides inside the WireGuard tunnel.
 */

export interface RouterInfo {
  identity: string;
  boardName: string;
  version: string;
  uptime: string;
}

export async function fetchRouterInfo(
  tunnelIp: string,
  username: string,
  password: string,
  timeoutMs = 8000,
): Promise<RouterInfo> {
  const auth = Buffer.from(`${username}:${password}`).toString("base64");
  const opts: RequestInit = {
    headers: { authorization: `Basic ${auth}` },
    signal: AbortSignal.timeout(timeoutMs),
  };
  const base = `http://${tunnelIp}/rest`;
  const [resourceRes, identityRes] = await Promise.all([
    fetch(`${base}/system/resource`, opts),
    fetch(`${base}/system/identity`, opts),
  ]);
  if (!resourceRes.ok || !identityRes.ok) {
    throw new Error(
      `RouterOS REST error: resource=${resourceRes.status} identity=${identityRes.status}`,
    );
  }
  const resource = (await resourceRes.json()) as Record<string, string>;
  const identity = (await identityRes.json()) as Record<string, string>;
  return {
    identity: identity.name ?? "unknown",
    boardName: resource["board-name"] ?? "unknown",
    version: resource.version ?? "unknown",
    uptime: resource.uptime ?? "unknown",
  };
}

export interface IfaceState {
  name: string;
  type: string;
  running: boolean;
  disabled: boolean;
  rxByte: number;
  txByte: number;
}

export interface LogEntry {
  id: string;
  time: string;
  topics: string;
  message: string;
}

export type FetchIfacesFn = typeof fetchInterfaces;
export type FetchLogFn = typeof fetchLog;

/** Light interface-state read for the device monitor (link up/down). */
export async function fetchInterfaces(
  tunnelIp: string,
  username: string,
  password: string,
  timeoutMs = 8000,
): Promise<IfaceState[]> {
  const auth = Buffer.from(`${username}:${password}`).toString("base64");
  const res = await fetch(`http://${tunnelIp}/rest/interface`, {
    headers: { authorization: `Basic ${auth}` },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`RouterOS REST /interface: ${res.status}`);
  const raw = (await res.json()) as Array<Record<string, string>>;
  return raw.map((i) => ({
    name: i.name ?? "?",
    type: i.type ?? "?",
    running: i.running === "true",
    disabled: i.disabled === "true",
    rxByte: Number(i["rx-byte"] ?? 0),
    txByte: Number(i["tx-byte"] ?? 0),
  }));
}

/** Recent log entries — used to detect logins. */
export async function fetchLog(
  tunnelIp: string,
  username: string,
  password: string,
  timeoutMs = 8000,
): Promise<LogEntry[]> {
  const auth = Buffer.from(`${username}:${password}`).toString("base64");
  const res = await fetch(`http://${tunnelIp}/rest/log`, {
    headers: { authorization: `Basic ${auth}` },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`RouterOS REST /log: ${res.status}`);
  const raw = (await res.json()) as Array<Record<string, string>>;
  return raw.map((l) => ({
    id: l[".id"] ?? "",
    time: l.time ?? "",
    topics: l.topics ?? "",
    message: l.message ?? "",
  }));
}

export interface PingResult {
  sent: number;
  received: number;
  avgMs: number | null;
}

export type FetchPingFn = typeof fetchPing;

/**
 * Ask the router to ping an address on its own LAN and summarise the result.
 * This is how we reach *internal* devices (DHCP clients, cameras, APs) that
 * live behind the router and aren't routable from the provisioning server.
 * RouterOS REST /ping returns one row per echo; a row with a `time` and no
 * error status counts as received.
 */
export async function fetchPing(
  tunnelIp: string,
  username: string,
  password: string,
  address: string,
  count = 2,
  timeoutMs = 8000,
): Promise<PingResult> {
  const auth = Buffer.from(`${username}:${password}`).toString("base64");
  const res = await fetch(`http://${tunnelIp}/rest/ping`, {
    method: "POST",
    headers: { authorization: `Basic ${auth}`, "content-type": "application/json" },
    body: JSON.stringify({ address, count: String(count) }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`RouterOS REST /ping: ${res.status}`);
  const rows = (await res.json()) as Array<Record<string, string>>;
  let received = 0;
  let sumMs = 0;
  let timed = 0;
  for (const r of rows) {
    const ok = (r.status ?? "") === "" && r.time != null && r.time !== "";
    if (ok) {
      received++;
      const ms = parseFloat(String(r.time).replace(/[^\d.]/g, ""));
      if (!Number.isNaN(ms)) {
        sumMs += /ms/.test(r.time) || !/us|s/.test(r.time) ? ms : ms; // RouterOS reports ms
        timed++;
      }
    }
  }
  return { sent: rows.length || count, received, avgMs: timed ? sumMs / timed : null };
}

export interface LiveInterface {
  name: string;
  type: string;
  running: boolean;
  rxByte: number;
  txByte: number;
}

export interface LiveStats {
  at: number;
  resource: {
    uptime: string;
    version: string;
    cpuLoad: number;
    freeMemory: number;
    totalMemory: number;
    boardName: string;
  };
  interfaces: LiveInterface[];
  /** Signal metrics for LTE/5G interfaces (Chateau etc.); best-effort. */
  lte: Array<Record<string, string>>;
}

export type FetchLiveFn = typeof fetchLiveStats;

/** Live snapshot over the tunnel: system resources, interfaces, LTE signal. */
export async function fetchLiveStats(
  tunnelIp: string,
  username: string,
  password: string,
  timeoutMs = 8000,
): Promise<LiveStats> {
  const auth = Buffer.from(`${username}:${password}`).toString("base64");
  const headers = { authorization: `Basic ${auth}`, "content-type": "application/json" };
  const base = `http://${tunnelIp}/rest`;
  const opts: RequestInit = { headers, signal: AbortSignal.timeout(timeoutMs) };

  const [resourceRes, ifaceRes] = await Promise.all([
    fetch(`${base}/system/resource`, opts),
    fetch(`${base}/interface`, opts),
  ]);
  if (!resourceRes.ok || !ifaceRes.ok) {
    throw new Error(`RouterOS REST error: resource=${resourceRes.status} interface=${ifaceRes.status}`);
  }
  const resource = (await resourceRes.json()) as Record<string, string>;
  const rawIfaces = (await ifaceRes.json()) as Array<Record<string, string>>;

  const interfaces: LiveInterface[] = rawIfaces.map((i) => ({
    name: i.name ?? "?",
    type: i.type ?? "?",
    running: i.running === "true",
    rxByte: Number(i["rx-byte"] ?? 0),
    txByte: Number(i["tx-byte"] ?? 0),
  }));

  // LTE/5G signal via `/interface/lte/monitor once` — parameter names vary a
  // little across ROS versions, so try the common forms and tolerate failure.
  const lte: Array<Record<string, string>> = [];
  for (const iface of interfaces.filter((i) => i.type === "lte")) {
    for (const body of [
      { numbers: iface.name, once: "true" },
      { ".id": iface.name, once: "true" },
    ]) {
      try {
        const res = await fetch(`${base}/interface/lte/monitor`, {
          method: "POST",
          headers,
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!res.ok) continue;
        const data = (await res.json()) as Array<Record<string, string>> | Record<string, string>;
        const entry = Array.isArray(data) ? data[0] : data;
        if (entry) {
          lte.push({ interface: iface.name, ...entry });
          break;
        }
      } catch {
        // try next parameter form / skip
      }
    }
  }

  return {
    at: Date.now(),
    resource: {
      uptime: resource.uptime ?? "?",
      version: resource.version ?? "?",
      cpuLoad: Number(resource["cpu-load"] ?? 0),
      freeMemory: Number(resource["free-memory"] ?? 0),
      totalMemory: Number(resource["total-memory"] ?? 0),
      boardName: resource["board-name"] ?? "?",
    },
    interfaces,
    lte,
  };
}

// ---- device profile: DHCP leases, IP addresses, health, firmware ---------

export interface DhcpLease {
  address: string;
  macAddress: string;
  hostName: string;
  status: string;
  server: string;
  expiresAfter: string;
  lastSeen: string;
  dynamic: boolean;
  comment: string;
}

export interface IpAddress {
  address: string;
  network: string;
  interface: string;
  disabled: boolean;
}

export interface HealthItem {
  name: string;
  value: string;
  type: string;
}

export interface RouterBoardInfo {
  model: string;
  serialNumber: string;
  firmware: string;
  firmwareType: string;
  upgradeAvailable: string;
}

export interface DeviceProfile {
  identity: string;
  resource: {
    uptime: string;
    version: string;
    cpuLoad: number;
    freeMemory: number;
    totalMemory: number;
    boardName: string;
    cpuCount: string;
    architecture: string;
  };
  routerboard: RouterBoardInfo | null;
  health: HealthItem[];
  ipAddresses: IpAddress[];
  dhcpLeases: DhcpLease[];
  interfaces: LiveInterface[];
}

export type FetchProfileFn = typeof fetchDeviceProfile;

/**
 * Aggregate device profile over the tunnel. Every section is best-effort: a
 * board with no DHCP server, no health sensors or an older ROS simply yields
 * an empty list for that section rather than failing the whole request.
 */
export async function fetchDeviceProfile(
  tunnelIp: string,
  username: string,
  password: string,
  timeoutMs = 8000,
): Promise<DeviceProfile> {
  const auth = Buffer.from(`${username}:${password}`).toString("base64");
  const base = `http://${tunnelIp}/rest`;
  const get = async (path: string): Promise<unknown> => {
    const res = await fetch(`${base}${path}`, {
      headers: { authorization: `Basic ${auth}` },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`${path}: ${res.status}`);
    return res.json();
  };
  const arr = (v: unknown): Array<Record<string, string>> => (Array.isArray(v) ? v : []);
  const obj = (v: unknown): Record<string, string> =>
    v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, string>) : {};

  const [identityR, resourceR, boardR, healthR, ipR, leaseR, ifaceR] = await Promise.allSettled([
    get("/system/identity"),
    get("/system/resource"),
    get("/system/routerboard"),
    get("/system/health"),
    get("/ip/address"),
    get("/ip/dhcp-server/lease"),
    get("/interface"),
  ]);
  const val = <T>(r: PromiseSettledResult<unknown>, f: (v: unknown) => T, fallback: T): T =>
    r.status === "fulfilled" ? f(r.value) : fallback;

  const identity = val(identityR, obj, {});
  const resource = val(resourceR, obj, {});
  const board = val(boardR, obj, {});
  // /system/health is an array of {name,value,type} on newer ROS but a flat
  // object ({temperature, voltage, ...}) on older v7 — normalise both.
  const health: HealthItem[] = val(
    healthR,
    (v) =>
      Array.isArray(v)
        ? v.map((h) => ({ name: h.name ?? "?", value: h.value ?? "", type: h.type ?? "" }))
        : Object.entries(obj(v))
            .filter(([k]) => k !== ".id")
            .map(([k, val]) => ({ name: k, value: String(val), type: "" })),
    [],
  );
  const ip = val(ipR, arr, []);
  const leases = val(leaseR, arr, []);
  const ifaces = val(ifaceR, arr, []);

  return {
    identity: identity.name ?? "unknown",
    resource: {
      uptime: resource.uptime ?? "?",
      version: resource.version ?? "?",
      cpuLoad: Number(resource["cpu-load"] ?? 0),
      freeMemory: Number(resource["free-memory"] ?? 0),
      totalMemory: Number(resource["total-memory"] ?? 0),
      boardName: resource["board-name"] ?? "?",
      cpuCount: resource["cpu-count"] ?? "?",
      architecture: resource["architecture-name"] ?? "?",
    },
    routerboard:
      Object.keys(board).length > 0
        ? {
            model: board.model ?? board["board-name"] ?? "?",
            serialNumber: board["serial-number"] ?? "?",
            firmware: board["current-firmware"] ?? "?",
            firmwareType: board["firmware-type"] ?? "?",
            upgradeAvailable: board["upgrade-firmware"] ?? "",
          }
        : null,
    health,
    ipAddresses: ip.map((a) => ({
      address: a.address ?? "?",
      network: a.network ?? "",
      interface: a.interface ?? "?",
      disabled: a.disabled === "true",
    })),
    dhcpLeases: leases.map((l) => ({
      address: l.address ?? l["active-address"] ?? "?",
      macAddress: l["mac-address"] ?? l["active-mac-address"] ?? "?",
      hostName: l["host-name"] ?? l.comment ?? "",
      status: l.status ?? "",
      server: l.server ?? "",
      expiresAfter: l["expires-after"] ?? "",
      lastSeen: l["last-seen"] ?? "",
      dynamic: l.dynamic === "true",
      comment: l.comment ?? "",
    })),
    interfaces: ifaces.map((i) => ({
      name: i.name ?? "?",
      type: i.type ?? "?",
      running: i.running === "true",
      rxByte: Number(i["rx-byte"] ?? 0),
      txByte: Number(i["tx-byte"] ?? 0),
    })),
  };
}
