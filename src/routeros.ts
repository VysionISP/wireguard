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
