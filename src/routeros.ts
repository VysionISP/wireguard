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
