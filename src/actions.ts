import type { RouterStore } from "./store.js";
import type { WireguardManager } from "./wireguard.js";
import type { RouterRecord } from "./types.js";
import { fetchRouterInfo, type RouterInfo } from "./routeros.js";

/** Router management actions shared by the CLI and the web UI / HTTP API. */

export type FetchInfoFn = typeof fetchRouterInfo;

export interface VerifyResult {
  reachable: boolean;
  handshakeAge: number | null;
  info?: RouterInfo;
  error?: string;
}

export async function verifyRouter(
  store: RouterStore,
  wg: WireguardManager,
  router: RouterRecord,
  fetchInfo: FetchInfoFn = fetchRouterInfo,
  timeoutMs = 8000,
): Promise<VerifyResult> {
  const handshakeAge = await wg.latestHandshake(router.publicKey).catch(() => null);
  try {
    const info = await fetchInfo(router.tunnelIp, router.username, router.password, timeoutMs);
    const now = new Date().toISOString();
    router.state = "verified";
    router.identity = info.identity;
    router.rosVersion = info.version;
    router.lastSeenAt = now;
    router.updatedAt = now;
    store.save(router);
    return { reachable: true, handshakeAge, info };
  } catch (err) {
    return { reachable: false, handshakeAge, error: (err as Error).message };
  }
}

export async function revokeRouter(
  store: RouterStore,
  wg: WireguardManager,
  router: RouterRecord,
): Promise<void> {
  await wg.removePeer(router.publicKey).catch((err: Error) => {
    console.warn(`peer removal for ${router.serialNumber}: ${err.message} (continuing)`);
  });
  router.state = "revoked";
  router.updatedAt = new Date().toISOString();
  store.save(router);
}
