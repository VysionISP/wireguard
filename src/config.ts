import fs from "node:fs";
import path from "node:path";
import { z } from "zod";

/** Treat "" (common in hand-edited config) as absent. */
function emptyToUndef<T extends z.ZodTypeAny>(schema: T) {
  return z.preprocess((v) => (v === "" ? undefined : v), schema.optional());
}

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
    /**
     * When false, only one-time tokens issued from the dashboard can register
     * routers — the shared provisioningToken is refused. Turn this off once
     * you've switched your workflow to one-time tokens.
     */
    allowMasterProvisioningToken: z.boolean().default(true),
    /** Session lifetime for dashboard logins. */
    sessionHours: z.number().int().min(1).default(12),
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
  /** Background fleet monitoring (handshake-based online/offline tracking). */
  monitor: z
    .object({
      intervalSeconds: z.number().int().min(10).default(60),
      /** A router is considered offline when its last handshake is older than this. */
      offlineAfterSeconds: z.number().int().min(30).default(180),
    })
    .default({}),
  /** Opinionated defaults applied to every router at provision time. */
  hardening: z
    .object({
      /** RouterOS services to disable. ssh/www/api are never disabled (we need them). */
      disableServices: z.array(z.string()).default(["telnet", "ftp"]),
      /** When set, /ip/dns servers are configured on the router. */
      dns: z.array(z.string()).default([]),
      /** When set, the NTP client is enabled with these servers. */
      ntpServers: z.array(z.string()).default([]),
      /**
       * When set, routers still carrying the factory identity "MikroTik" get
       * renamed to "<prefix>-<serial>". Custom identities are left alone.
       */
      identityPrefix: z.string().default(""),
    })
    .default({}),
  /** Router-pushed config backups (/export uploaded on a schedule). */
  backup: z
    .object({
      enabled: z.boolean().default(true),
      intervalHours: z.number().int().min(1).default(24),
      dir: z.string().default("data/backups"),
      /** Versions kept per router; older ones are pruned. */
      keep: z.number().int().min(1).default(30),
    })
    .default({}),
  /** Offline/online/registration notifications. */
  alerts: z
    .object({
      /**
       * POSTed {text, event, router} as JSON — point it at Slack, Discord,
       * n8n, anything. Empty string is treated as "not set" so the example
       * config validates as-is.
       */
      webhookUrl: emptyToUndef(z.string().url()).optional(),
      telegramBotToken: emptyToUndef(z.string()).optional(),
      telegramChatId: emptyToUndef(z.string()).optional(),
      notifyOnRegister: z.boolean().default(true),
      /** Also alert when a router comes back online (not just when it drops). */
      notifyOnline: z.boolean().default(true),
      /** Max one offline + one online alert per router per this window (flap guard). */
      suppressMinutes: z.number().int().min(0).default(15),
    })
    .default({}),
  /** Active per-device monitoring (logins, port link state) over the tunnel. */
  deviceMonitor: z
    .object({
      enabled: z.boolean().default(true),
      intervalSeconds: z.number().int().min(15).default(30),
      /** New routers get monitoring on by default with the flags below. */
      enableNewByDefault: z.boolean().default(true),
      defaultAlertOnLogin: z.boolean().default(true),
      defaultAlertOnLinkDown: z.boolean().default(true),
    })
    .default({}),
  /** Time-series sampling for the per-device traffic graph + history. */
  metrics: z
    .object({
      enabled: z.boolean().default(true),
      /** How often each online device's counters are sampled. */
      sampleSeconds: z.number().int().min(30).default(300),
      /** How long samples are kept before pruning. */
      retentionDays: z.number().int().min(1).default(14),
    })
    .default({}),
  /** Append-only metrics samples (JSONL). */
  metricsPath: z.string().default("data/metrics.jsonl"),
  /** Active issues (status board). */
  issuesPath: z.string().default("data/issues.json"),
  /** Per-device + global event log (logins, link flaps, on/offline). */
  eventsPath: z.string().default("data/events.jsonl"),
  /** Path of the JSON router inventory. */
  storePath: z.string().default("data/routers.json"),
  /** One-time bootstrap tokens. */
  tokensPath: z.string().default("data/tokens.json"),
  /** Dashboard user accounts. */
  usersPath: z.string().default("data/users.json"),
  /** Append-only audit log (JSONL). */
  auditPath: z.string().default("data/audit.jsonl"),
  /** Dashboard-editable runtime settings (Telegram routing). */
  settingsPath: z.string().default("data/settings.json"),
  /** Per-customer-group topology map layouts. */
  topologyPath: z.string().default("data/topology.json"),
  /** Customer records (contact details). */
  customersPath: z.string().default("data/customers.json"),
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
