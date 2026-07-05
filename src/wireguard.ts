import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const PUBKEY_RE = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$/;

export function isValidWgKey(key: string): boolean {
  return PUBKEY_RE.test(key);
}

export interface WireguardManager {
  addPeer(publicKey: string, tunnelIp: string): Promise<void>;
  removePeer(publicKey: string): Promise<void>;
  /** Seconds since the last handshake, or null if the peer never connected. */
  latestHandshake(publicKey: string): Promise<number | null>;
}

/** Applies peers live on this host using the `wg` command. */
export class WgCommandManager implements WireguardManager {
  constructor(private readonly iface: string) {}

  private assertKey(publicKey: string): void {
    // Keys are passed as argv entries (never through a shell), but reject
    // malformed values anyway so garbage can't reach `wg`.
    if (!isValidWgKey(publicKey)) throw new Error(`Invalid WireGuard key: ${publicKey}`);
  }

  async addPeer(publicKey: string, tunnelIp: string): Promise<void> {
    this.assertKey(publicKey);
    await execFileAsync("wg", [
      "set",
      this.iface,
      "peer",
      publicKey,
      "allowed-ips",
      `${tunnelIp}/32`,
    ]);
  }

  async removePeer(publicKey: string): Promise<void> {
    this.assertKey(publicKey);
    await execFileAsync("wg", ["set", this.iface, "peer", publicKey, "remove"]);
  }

  async latestHandshake(publicKey: string): Promise<number | null> {
    this.assertKey(publicKey);
    const { stdout } = await execFileAsync("wg", ["show", this.iface, "latest-handshakes"]);
    for (const line of stdout.split("\n")) {
      const [key, ts] = line.trim().split(/\s+/);
      if (key === publicKey) {
        const epoch = Number(ts);
        if (!epoch) return null;
        return Math.max(0, Math.floor(Date.now() / 1000) - epoch);
      }
    }
    return null;
  }
}

/** Logs what would be done instead of touching the system. For dev/tests. */
export class DryRunManager implements WireguardManager {
  readonly calls: string[] = [];

  constructor(private readonly iface: string, private readonly quiet = false) {}

  private record(msg: string): void {
    this.calls.push(msg);
    if (!this.quiet) console.log(`[dry-run] ${msg}`);
  }

  async addPeer(publicKey: string, tunnelIp: string): Promise<void> {
    this.record(`wg set ${this.iface} peer ${publicKey} allowed-ips ${tunnelIp}/32`);
  }

  async removePeer(publicKey: string): Promise<void> {
    this.record(`wg set ${this.iface} peer ${publicKey} remove`);
  }

  async latestHandshake(): Promise<number | null> {
    return null;
  }
}
