import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseConfig, type Config } from "../src/config.js";

export function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "mtprov-test-"));
}

export function testConfig(overrides: Partial<Record<string, unknown>> = {}): Config {
  return parseConfig({
    server: { host: "127.0.0.1", port: 8442, publicUrl: "https://provision.test" },
    auth: {
      provisioningToken: "test-provisioning-token-123",
      adminToken: "test-admin-token-456789012",
    },
    wireguard: {
      interface: "wg0",
      serverPublicKey: "hLNXPz4rDcbIkbTD30yvM8wIWjGOWb+IybOhFOWlN0Y=",
      endpointHost: "vpn.test",
      endpointPort: 51820,
      mgmtCidr: "10.99.0.0/24",
      serverTunnelIp: "10.99.0.1",
      persistentKeepalive: 25,
      applyMode: "dry-run",
    },
    router: { wgInterfaceName: "wg-mgmt", username: "wg-mgmt", strictTls: false },
    storePath: path.join(tempDir(), "routers.json"),
    ...overrides,
  });
}

/** A syntactically valid WireGuard public key for tests. */
export function fakeKey(seed: number): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let key = "";
  for (let i = 0; i < 42; i++) key += alphabet[(seed * 7 + i * 13) % alphabet.length];
  return key + "A=";
}
