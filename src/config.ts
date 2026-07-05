import fs from "node:fs";
import path from "node:path";
import { z } from "zod";

const configSchema = z.object({
  server: z.object({
    /** Address the provisioning HTTP server binds to. */
    host: z.string().default("0.0.0.0"),
    port: z.number().int().min(1).max(65535).default(8442),
    /**
     * URL routers use to reach this server from the field (before the tunnel
     * exists), e.g. "https://provision.example.com". Used inside generated
     * RouterOS scripts.
     */
    publicUrl: z.string().url(),
  }),
  auth: z.object({
    /** Shared secret embedded in the bootstrap script; authorises /api/register. */
    provisioningToken: z.string().min(16),
    /** Secret for admin endpoints (router listing etc). */
    adminToken: z.string().min(16),
  }),
  wireguard: z.object({
    /** WireGuard interface on THIS host that terminates management tunnels. */
    interface: z.string().default("wg0"),
    /** Public key of the interface above; routers add it as their peer. */
    serverPublicKey: z.string().min(42),
    /** Endpoint routers connect to (usually this host's public address). */
    endpointHost: z.string(),
    endpointPort: z.number().int().min(1).max(65535).default(51820),
    /** Subnet management tunnel IPs are allocated from. */
    mgmtCidr: z.string().regex(/^\d+\.\d+\.\d+\.\d+\/\d+$/),
    /** This server's own IP inside mgmtCidr (never allocated to routers). */
    serverTunnelIp: z.string().regex(/^\d+\.\d+\.\d+\.\d+$/),
    persistentKeepalive: z.number().int().min(0).default(25),
    /**
     * "wg"      — apply peers live with the `wg` command (requires root or CAP_NET_ADMIN)
     * "dry-run" — log the commands instead of running them (dev/testing)
     */
    applyMode: z.enum(["wg", "dry-run"]).default("wg"),
  }),
  router: z.object({
    /** Name of the WireGuard interface created on each MikroTik. */
    wgInterfaceName: z.string().default("wg-mgmt"),
    /** Management user created on each MikroTik. */
    username: z.string().default("wg-mgmt"),
    /** When true, RouterOS fetch verifies the TLS certificate of publicUrl. */
    strictTls: z.boolean().default(false),
  }),
  /** Path of the JSON router inventory. */
  storePath: z.string().default("data/routers.json"),
});

export type Config = z.infer<typeof configSchema>;

export function loadConfig(filePath?: string): Config {
  const p = filePath ?? process.env.MTPROV_CONFIG ?? "config.json";
  const resolved = path.resolve(p);
  if (!fs.existsSync(resolved)) {
    throw new Error(
      `Config file not found: ${resolved}. Copy config.example.json to config.json and edit it.`,
    );
  }
  const raw = JSON.parse(fs.readFileSync(resolved, "utf8"));
  return configSchema.parse(raw);
}

export function parseConfig(raw: unknown): Config {
  return configSchema.parse(raw);
}
