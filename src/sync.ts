import type { RouterStore } from "./store.js";
import type { WireguardManager } from "./wireguard.js";

/**
 * Re-applies every non-revoked router's peer to the WireGuard interface.
 * Needed after the interface (or the host) restarts, because peers added at
 * registration time with `wg set` are runtime state, not persisted config.
 */
export async function syncPeers(
  store: RouterStore,
  wg: WireguardManager,
): Promise<{ applied: number; failed: number }> {
  let applied = 0;
  let failed = 0;
  for (const router of store.list()) {
    if (router.state === "revoked") continue;
    try {
      await wg.addPeer(router.publicKey, router.tunnelIp);
      applied++;
    } catch (err) {
      failed++;
      console.error(`sync: failed to apply peer for ${router.serialNumber}: ${(err as Error).message}`);
    }
  }
  return { applied, failed };
}
