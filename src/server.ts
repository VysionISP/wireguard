import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import express, { type Express, type Request, type Response, type NextFunction } from "express";
import { z } from "zod";
import { createTwoFilesPatch } from "diff";
import type { Config } from "./config.js";
import type { RouterStore } from "./store.js";
import type { WireguardManager } from "./wireguard.js";
import { isValidWgKey } from "./wireguard.js";
import { allocateIp } from "./ipam.js";
import { renderBootstrap, renderOneLiner, renderProvision, renderReason } from "./templates.js";
import { revokeRouter, verifyRouter, type FetchInfoFn } from "./actions.js";
import { BackupStore } from "./backups.js";
import { Alerter } from "./alerts.js";
import { TokenStore } from "./tokens.js";
import { UserStore, SessionManager, type Role } from "./users.js";
import { AuditLog } from "./audit.js";
import { IssueStore } from "./issues.js";
import { EventLog } from "./events.js";
import { SettingsStore, ROUTE_KEYS, type RouteChat } from "./settings.js";
import { telegram as realTelegram, type TelegramClient } from "./telegram.js";
import { interfaceRates, type Sample } from "./stream.js";
import { TopologyStore, type GroupTopology } from "./topology.js";
import { CustomerStore } from "./customers.js";
import { fetchLiveStats, fetchInterfaces as realFetchInterfaces, fetchDeviceProfile, fetchPing, fetchNeighbors, type FetchLiveFn, type FetchIfacesFn, type FetchProfileFn, type FetchPingFn, type FetchNeighborsFn, type NeighborEntry } from "./routeros.js";
import { discoverLinks } from "./discovery.js";
import { MetricsStore, computeTraffic } from "./metrics.js";
import { PingMetricsStore } from "./pingmetrics.js";
import { HostStore } from "./hosts.js";
import { MaintenanceStore, MAINT_CATEGORIES, maintCategory, type MaintCategory } from "./maintenance.js";
import { OutageStore } from "./outages.js";
import { computeSla, type Span } from "./sla.js";
import { sshRun as realSshRun, sftpPut as realSftpPut, type SshRunFn, type SftpPutFn, type SshShellFn } from "./ssh.js";
import { ConsoleManager } from "./console.js";
import { UpgradeManager, updateAvailable } from "./upgrade.js";
import { rebootRouter, type RebootFn } from "./routeros.js";
import { defaultMonitoring, effectivePorts, upstreamTargets, DEFAULT_UPSTREAM_TARGETS, MAX_UPSTREAM_TARGETS, type RouterRecord, type DeviceType } from "./types.js";

export interface AppDeps {
  config: Config;
  store: RouterStore;
  wg: WireguardManager;
  /** Overrides for tests; default to the real implementations. */
  fetchInfo?: FetchInfoFn;
  fetchLive?: FetchLiveFn;
  fetchIfaces?: FetchIfacesFn;
  fetchProfile?: FetchProfileFn;
  fetchPing?: FetchPingFn;
  fetchNeighbors?: FetchNeighborsFn;
  metrics?: MetricsStore;
  pings?: PingMetricsStore;
  hosts?: HostStore;
  maintenance?: MaintenanceStore;
  outages?: OutageStore;
  /** Chats the Telegram callback poller has seen (merged into chat discovery). */
  extraChats?: () => Array<{ id: string; title: string; type: string }>;
  backups?: BackupStore;
  alerter?: Alerter;
  tokens?: TokenStore;
  users?: UserStore;
  sessions?: SessionManager;
  audit?: AuditLog;
  issues?: IssueStore;
  events?: EventLog;
  settings?: SettingsStore;
  telegram?: TelegramClient;
  topology?: TopologyStore;
  customers?: CustomerStore;
  sshRun?: SshRunFn;
  shell?: SshShellFn;
  /** Test knobs for the upgrade job runner. */
  upgrade?: { pollMs?: number; onlineTimeoutMs?: number };
  sftpPut?: SftpPutFn;
  reboot?: RebootFn;
}

interface AuthedRequest extends Request {
  authUser?: { username: string; role: Role };
}

// Works from both src/ (tsx dev) and dist/ (build) — web/ sits beside them.
const WEB_INDEX = fileURLToPath(new URL("../web/index.html", import.meta.url));
const WEB_NOC = fileURLToPath(new URL("../web/noc.html", import.meta.url));
const WEB_STATUS = fileURLToPath(new URL("../web/status.html", import.meta.url));

const registerSchema = z.object({
  token: z.string(),
  publicKey: z.string().refine(isValidWgKey, "not a valid WireGuard public key"),
  // Kept in sync with BackupStore.SERIAL_SAFE (no dot) so backups always work.
  serialNumber: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/, "invalid serial number"),
  boardName: z.string().max(128).default("unknown"),
  rosVersion: z.string().max(128).default("unknown"),
  identity: z.string().max(128).default("MikroTik"),
});

const confirmSchema = z.object({
  token: z.string(),
  serialNumber: z.string().min(1).max(64),
});

function generatePassword(length = 24): string {
  // Alphanumeric only: safe to embed in RouterOS scripts and to type by hand.
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
  const bytes = crypto.randomBytes(length);
  return [...bytes].map((b) => alphabet[b % alphabet.length]).join("");
}

function tokenEquals(a: string, b: string): boolean {
  const ha = crypto.createHash("sha256").update(a).digest();
  const hb = crypto.createHash("sha256").update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

const patchSchema = z.object({
  label: z.string().max(120).optional(),
  notes: z.string().max(4000).optional(),
  customerGroup: z.string().max(80).optional(),
  /** Committed uptime target %, 0 clears it. */
  slaTarget: z.number().min(0).max(100).optional(),
});

export function buildApp(deps: AppDeps): Express {
  const { config, store, wg } = deps;
  const backups = deps.backups ?? new BackupStore(config.backup.dir, config.backup.keep);
  const alerter = deps.alerter ?? new Alerter(config.alerts);
  const tokens = deps.tokens ?? new TokenStore(config.tokensPath);
  const users = deps.users ?? new UserStore(config.usersPath);
  const sessions = deps.sessions ?? new SessionManager(config.auth.sessionHours);
  const audit = deps.audit ?? new AuditLog(config.auditPath);
  const issues = deps.issues ?? new IssueStore(config.issuesPath);
  const events = deps.events ?? new EventLog(config.eventsPath);
  const settings = deps.settings ?? new SettingsStore(config.settingsPath);
  const telegram = deps.telegram ?? realTelegram;
  const topology = deps.topology ?? new TopologyStore(config.topologyPath);
  const customers = deps.customers ?? new CustomerStore(config.customersPath);
  const sshRun = deps.sshRun ?? realSshRun;
  const consoles = new ConsoleManager(deps.shell);
  const upgradeCfg = deps.upgrade ?? {};
  const reboot = deps.reboot ?? rebootRouter;
  const sftpPut = deps.sftpPut ?? realSftpPut;
  const fetchLive = deps.fetchLive ?? fetchLiveStats;
  const fetchIfaces = deps.fetchIfaces ?? realFetchInterfaces;
  const fetchProfile = deps.fetchProfile ?? fetchDeviceProfile;
  const fetchPingFn = deps.fetchPing ?? fetchPing;
  const fetchNeighborsFn = deps.fetchNeighbors ?? fetchNeighbors;
  const metrics =
    deps.metrics ?? new MetricsStore(config.metricsPath, config.metrics.retentionDays * 24 * 3600_000);
  const pings =
    deps.pings ?? new PingMetricsStore(config.pingMetricsPath, config.upstreamPing.retentionDays * 24 * 3600_000);
  const hosts = deps.hosts ?? new HostStore(config.hostsPath);
  const maintenance = deps.maintenance ?? new MaintenanceStore(config.maintenancePath);
  const upgrades = new UpgradeManager({
    store, events, maintenance, sshRun,
    pollMs: upgradeCfg.pollMs, onlineTimeoutMs: upgradeCfg.onlineTimeoutMs,
    filePath: config.upgradesPath,
  });
  const outages = deps.outages ?? new OutageStore(config.outagesPath);

  // Serialises the register critical section so concurrent phone-homes can't
  // both read the same "lowest free IP" or both burn the same one-time token
  // across the `await wg.addPeer` in the middle. Single-process server, so a
  // promise-chain lock is sufficient.
  let registerLock: Promise<unknown> = Promise.resolve();
  function withRegisterLock<T>(fn: () => Promise<T>): Promise<T> {
    const run = registerLock.then(fn, fn);
    registerLock = run.then(() => {}, () => {});
    return run;
  }
  const app = express();
  app.use(express.json({ limit: "64kb" }));

  /**
   * A provisioning-side token is accepted when it is the master token (if
   * allowed) or a one-time token. Burned one-time tokens stay valid for the
   * serial that used them, so confirm/backup calls keep working.
   */
  function provisioningAuth(candidate: string, serial: string | null): "master" | "one-time" | null {
    if (!candidate) return null; // fail closed even if a secret is misconfigured empty
    if (
      config.auth.allowMasterProvisioningToken &&
      tokenEquals(candidate, config.auth.provisioningToken)
    ) {
      return "master";
    }
    const t = tokens.find(candidate);
    if (!t) return null;
    if (!t.usedAt) {
      if (t.expiresAt && Date.parse(t.expiresAt) < Date.now()) return null;
      return "one-time";
    }
    return serial !== null && t.usedBySerial === serial ? "one-time" : null;
  }

  app.get("/healthz", (_req, res) => {
    res.json({ ok: true });
  });

  // Explain, in plain English, why a registration attempt failed. The bootstrap
  // script fetches this on-error and imports it so the reason is printed on the
  // RouterOS terminal (a /tool fetch of /api/register discards the body on a
  // non-2xx status, so the router can never see the register response itself).
  // No auth: it only reveals why a token/serial was rejected, nothing sensitive.
  function registrationReason(token: string, serial: string): string {
    const rec = serial ? store.findBySerial(serial) : undefined;
    if (rec?.state === "revoked")
      return `router serial ${serial} has been revoked - remove it in the dashboard before re-provisioning`;
    if (config.auth.allowMasterProvisioningToken && tokenEquals(token, config.auth.provisioningToken))
      return "the token is valid - the failure was server- or network-side; check the server log (journalctl -u mtprov)";
    const t = tokens.find(token);
    if (!t) return "this bootstrap token is not recognised - generate a fresh link for this router";
    if (t.expiresAt && Date.parse(t.expiresAt) < Date.now())
      return "this bootstrap token has expired - generate a fresh link for this router";
    if (t.usedBySerial && t.usedBySerial !== serial)
      return `this bootstrap token was already used by another device (serial ${t.usedBySerial}) - one token onboards one router, so generate a fresh link for this one`;
    return "the token is valid - the failure was server- or network-side; check the server log (journalctl -u mtprov)";
  }

  app.get("/api/register-reason", (req: Request, res: Response) => {
    const token = String(req.query.token ?? "");
    const serial = String(req.query.serial ?? "");
    res.type("text/plain").send(renderReason(registrationReason(token, serial)));
  });

  // The bootstrap script a tech fetches onto a fresh router. Accepts the
  // master token, or any one-time token that exists and hasn't expired —
  // INCLUDING a used one, so re-running the one-liner (or reflashing the same
  // device) works. The one-time + serial binding is still enforced at
  // /api/register, so serving the script here is harmless.
  app.get("/bootstrap.rsc", (req: Request, res: Response) => {
    const token = String(req.query.token ?? "");
    const master =
      config.auth.allowMasterProvisioningToken && tokenEquals(token, config.auth.provisioningToken);
    const ot = master ? null : tokens.find(token);
    const otOk = Boolean(ot && !(ot.expiresAt && Date.parse(ot.expiresAt) < Date.now()));
    if (!master && !otOk) {
      // RouterOS /tool fetch requires a WWW-Authenticate header on a 401 or it
      // reports the unhelpful "401 should contain www-authenticate header".
      res
        .status(401)
        .set("WWW-Authenticate", 'Bearer realm="korvix"')
        .type("text/plain")
        .send(':log error "wg-provision: invalid or expired bootstrap token"\n');
      return;
    }
    res.type("text/plain").send(renderBootstrap(config, token));
  });

  // Router phone-home: allocate an IP, register the WireGuard peer, respond
  // with the tailored provisioning script.
  app.post("/api/register", async (req: Request, res: Response) => {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.issues.map((i) => i.message).join("; ") });
      return;
    }
    const body = parsed.data;
    await withRegisterLock(async () => {
    const tokenKind = provisioningAuth(body.token, body.serialNumber);
    if (!tokenKind) {
      res.status(401).set("WWW-Authenticate", 'Bearer realm="korvix"').json({ error: "invalid provisioning token" });
      return;
    }
    // A one-time token may carry a customer + label to apply at onboarding.
    const otToken = tokenKind === "one-time" ? tokens.find(body.token) : undefined;

    const now = new Date().toISOString();
    let router = store.findBySerial(body.serialNumber);
    const isRereg = Boolean(router && router.state !== "staged");

    if (router?.state === "revoked") {
      res.status(403).json({ error: "router has been revoked" });
      return;
    }

    try {
      if (router && router.state === "staged") {
        // Pre-staged: keep label/notes/credentials, fill in the live bits.
        router.tunnelIp = allocateIp(config.wireguard.mgmtCidr, store.usedTunnelIps(), [
          config.wireguard.serverTunnelIp,
        ]);
        router.publicKey = body.publicKey;
        router.boardName = body.boardName;
        router.rosVersion = body.rosVersion;
        router.identity = body.identity;
        router.state = "registered";
        router.updatedAt = now;
        router.lastSeenAt = now;
        if (!router.deviceType) router.deviceType = "customer";
        if (!router.monitoring && config.deviceMonitor.enableNewByDefault) {
          router.monitoring = defaultMonitoring(router.deviceType, config.deviceMonitor.defaultAlertOnLogin, config.deviceMonitor.defaultAlertOnLinkDown);
        }
        await wg.addPeer(router.publicKey, router.tunnelIp);
      } else if (router) {
        // Re-registration (reset/reflashed device): keep the tunnel IP and
        // credentials stable, swap the WireGuard key if it changed.
        if (router.publicKey !== body.publicKey) {
          await wg.removePeer(router.publicKey).catch(() => {});
          await wg.addPeer(body.publicKey, router.tunnelIp);
          router.publicKey = body.publicKey;
        }
        router.boardName = body.boardName;
        router.rosVersion = body.rosVersion;
        router.identity = body.identity;
        router.updatedAt = now;
        router.lastSeenAt = now;
        if (router.state === "verified") router.state = "confirmed";
      } else {
        const tunnelIp = allocateIp(config.wireguard.mgmtCidr, store.usedTunnelIps(), [
          config.wireguard.serverTunnelIp,
        ]);
        router = {
          id: crypto.randomUUID(),
          serialNumber: body.serialNumber,
          publicKey: body.publicKey,
          boardName: body.boardName,
          rosVersion: body.rosVersion,
          identity: body.identity,
          tunnelIp,
          username: config.router.username,
          password: generatePassword(),
          state: "registered",
          createdAt: now,
          updatedAt: now,
          lastSeenAt: now,
          deviceType: "customer",
          customerGroup: otToken?.customer || undefined,
          // Prefer the token's label; else use the router's own identity as the
          // label, unless it's still the factory default "MikroTik".
          label: otToken?.label || (body.identity && body.identity !== "MikroTik" ? body.identity : undefined),
          monitoring: config.deviceMonitor.enableNewByDefault
            ? defaultMonitoring("customer", config.deviceMonitor.defaultAlertOnLogin, config.deviceMonitor.defaultAlertOnLinkDown)
            : undefined,
        } satisfies RouterRecord;
        await wg.addPeer(router.publicKey, router.tunnelIp);
      }
      store.save(router);
      if (tokenKind === "one-time") tokens.markUsed(body.token, router.serialNumber);
    } catch (err) {
      console.error("register failed:", err);
      res.status(500).json({ error: "failed to register peer" });
      return;
    }

    console.log(
      `registered ${router.serialNumber} (${router.boardName}) -> ${router.tunnelIp}`,
    );
    audit.log("router", "register", router.serialNumber, `${router.boardName} -> ${router.tunnelIp}`);
    alerter.routerRegistered(router, isRereg).catch(() => {});
    res.type("text/plain").send(renderProvision(config, router, body.token));
    });
  });

  // Router confirms it applied the provisioning script.
  app.post("/api/confirm", (req: Request, res: Response) => {
    const parsed = confirmSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid request" });
      return;
    }
    if (!provisioningAuth(parsed.data.token, parsed.data.serialNumber)) {
      res.status(401).json({ error: "invalid provisioning token" });
      return;
    }
    const router = store.findBySerial(parsed.data.serialNumber);
    if (!router || router.state === "revoked" || router.state === "staged") {
      res.status(404).json({ error: "unknown router" });
      return;
    }
    const now = new Date().toISOString();
    if (router.state === "registered") router.state = "confirmed";
    router.lastSeenAt = now;
    router.updatedAt = now;
    store.save(router);
    console.log(`confirmed ${router.serialNumber} at ${router.tunnelIp}`);
    res.json({ ok: true });
  });

  // ------------------------------------------------------- admin API + UI

  // Resolve a bearer/query token to a user (session or legacy admin token).
  function userFromToken(raw: string): { username: string; role: Role } | null {
    if (!raw) return null;
    const sess = sessions.get(raw);
    if (sess) return { username: sess.username, role: sess.role };
    if (tokenEquals(raw, config.auth.adminToken)) return { username: "admin-token", role: "admin" };
    return null;
  }

  // Auth: a dashboard session token (user accounts) or the legacy admin
  // token (break-glass / API scripting, always role admin).
  const requireRole =
    (min: Role) =>
    (req: Request, res: Response, next: NextFunction): void => {
      const raw = (req.get("authorization") ?? "").replace(/^Bearer\s+/i, "");
      const user = userFromToken(raw);
      if (!user) {
        res.status(401).json({ error: "unauthorized" });
        return;
      }
      if (min === "admin" && user.role !== "admin") {
        res.status(403).json({ error: "admin role required" });
        return;
      }
      (req as AuthedRequest).authUser = user;
      next();
    };
  const requireAdmin = requireRole("admin");
  const requireTech = requireRole("tech");
  const who = (req: Request): string => (req as AuthedRequest).authUser?.username ?? "?";

  // ---- login / sessions
  app.post("/api/login", (req: Request, res: Response) => {
    const parsed = z
      .object({ username: z.string().max(64), password: z.string().max(256) })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid request" });
      return;
    }
    const user = users.verify(parsed.data.username, parsed.data.password);
    if (!user) {
      audit.log(parsed.data.username, "login.fail", "-");
      res.status(401).json({ error: "invalid username or password" });
      return;
    }
    const session = sessions.create(user.username, user.role);
    audit.log(user.username, "login", "-");
    res.json({ session: session.token, username: user.username, role: user.role });
  });

  app.post("/api/logout", requireTech, (req: Request, res: Response) => {
    const raw = (req.get("authorization") ?? "").replace(/^Bearer\s+/i, "");
    sessions.destroy(raw);
    res.json({ ok: true });
  });

  // Who am I — lets the UI restore a session and adapt to the role.
  app.get("/api/me", requireTech, (req: Request, res: Response) => {
    res.json((req as AuthedRequest).authUser);
  });

  // Change your own password (real accounts only, not the admin-token login).
  app.post("/api/account/password", requireTech, (req: Request, res: Response) => {
    const parsed = z
      .object({ current: z.string().max(256), next: z.string().max(256) })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid request" });
      return;
    }
    const username = (req as AuthedRequest).authUser!.username;
    if (!users.has(username)) {
      res.status(400).json({ error: "the admin-token login has no password to change" });
      return;
    }
    if (!users.verify(username, parsed.data.current)) {
      res.status(403).json({ error: "current password is incorrect" });
      return;
    }
    try {
      users.changePassword(username, parsed.data.next);
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
      return;
    }
    audit.log(username, "password.change", username);
    res.json({ ok: true });
  });

  // Inventory listing with live handshake ages (credentials excluded).
  app.get("/api/routers", requireTech, async (_req: Request, res: Response) => {
    const handshakes = await wg.latestHandshakes().catch(() => ({}) as Record<string, number | null>);
    res.json(
      store.list().map(({ password: _password, ...rest }) => {
        const handshakeAge = handshakes[rest.publicKey] ?? null;
        const handshakeOnline =
          rest.state !== "revoked" &&
          handshakeAge !== null &&
          handshakeAge < config.monitor.offlineAfterSeconds;
        const win = maintenance.activeForRouter(rest.serialNumber, rest.customerGroup);
        return {
          ...rest,
          handshakeAge,
          // Prefer the active-ping health when the liveness probe is running;
          // fall back to handshake age otherwise.
          online: rest.health ? rest.health !== "offline" : handshakeOnline,
          maintenanceUntil: win ? win.endsAt : null,
        };
      }),
    );
  });

  // Operator metadata: friendly label + notes.
  app.patch("/api/routers/:ref", requireTech, (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    if (!router) {
      res.status(404).json({ error: "not found" });
      return;
    }
    const parsed = patchSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid request" });
      return;
    }
    if (parsed.data.label !== undefined) router.label = parsed.data.label;
    if (parsed.data.notes !== undefined) router.notes = parsed.data.notes;
    if (parsed.data.customerGroup !== undefined) router.customerGroup = parsed.data.customerGroup.trim();
    if (parsed.data.slaTarget !== undefined) router.slaTarget = parsed.data.slaTarget || undefined;
    router.updatedAt = new Date().toISOString();
    store.save(router);
    audit.log(who(req), "label", router.serialNumber, router.label);
    res.json({ ok: true });
  });

  // Router-pushed config backup (RouterOS `/tool fetch upload=yes`). The
  // token travels as a query parameter because fetch upload mode cannot
  // reliably set headers.
  app.post(
    "/api/backup",
    express.raw({ type: () => true, limit: "4mb" }),
    (req: Request, res: Response) => {
      const token = String(req.query.token ?? "");
      const serial = String(req.query.serial ?? "");
      if (!provisioningAuth(token, serial)) {
        res.status(401).json({ error: "invalid provisioning token" });
        return;
      }
      const router = store.findBySerial(serial);
      if (!router || router.state === "revoked" || router.state === "staged") {
        res.status(404).json({ error: "unknown router" });
        return;
      }
      if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
        res.status(400).json({ error: "empty backup" });
        return;
      }
      try {
        const { stored } = backups.saveIfChanged(router.serialNumber, req.body);
        const now = new Date().toISOString();
        router.lastBackupAt = now;
        router.lastSeenAt = now;
        store.save(router);
        if (stored) console.log(`backup stored for ${router.serialNumber} (${req.body.length} bytes)`);
        res.json({ ok: true, stored });
      } catch (err) {
        console.error("backup failed:", err);
        res.status(500).json({ error: "failed to store backup" });
      }
    },
  );

  // On-demand backup: run /export over SSH, capture stdout, store it. Handy
  // for a snapshot right before a change instead of waiting for the schedule.
  app.post("/api/routers/:ref/backup-now", requireTech, async (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    if (!router) {
      res.status(404).json({ error: "not found" });
      return;
    }
    if (router.state === "staged" || router.state === "revoked") {
      res.status(400).json({ error: "router is not online" });
      return;
    }
    try {
      // RouterOS `/export` with no file= prints the config to stdout.
      const result = await sshRun(router.tunnelIp, router.username, router.password, "/export");
      const text = result.output.trim();
      if (!text) {
        res.status(502).json({ error: "router returned an empty export" });
        return;
      }
      const { stored, name } = backups.saveIfChanged(router.serialNumber, Buffer.from(text + "\n"));
      const now = new Date().toISOString();
      router.lastBackupAt = now;
      router.lastSeenAt = now;
      store.save(router);
      audit.log(who(req), "backup.now", router.serialNumber, stored ? name ?? "" : "unchanged");
      res.json({ ok: true, stored, name });
    } catch (err) {
      res.status(502).json({ error: `backup failed: ${(err as Error).message}` });
    }
  });

  app.get("/api/routers/:ref/backups", requireTech, (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    if (!router) {
      res.status(404).json({ error: "not found" });
      return;
    }
    res.json(backups.list(router.serialNumber));
  });

  app.get("/api/routers/:ref/backups/:name", requireTech, (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    const content = router ? backups.read(router.serialNumber, req.params.name) : null;
    if (!router || content === null) {
      res.status(404).json({ error: "not found" });
      return;
    }
    res
      .type("text/plain")
      .setHeader(
        "content-disposition",
        `attachment; filename="${router.serialNumber}-${req.params.name}"`,
      )
      .send(content);
  });

  // Full details for one router, credentials included.
  app.get("/api/routers/:ref", requireTech, async (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    if (!router) {
      res.status(404).json({ error: "not found" });
      return;
    }
    const handshakeAge = await wg.latestHandshake(router.publicKey).catch(() => null);
    res.json({ ...router, handshakeAge });
  });

  app.post("/api/routers/:ref/verify", requireTech, async (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    if (!router) {
      res.status(404).json({ error: "not found" });
      return;
    }
    if (router.state === "staged") {
      res.status(400).json({ error: "router has not registered yet" });
      return;
    }
    audit.log(who(req), "verify", router.serialNumber);
    res.json(await verifyRouter(store, wg, router, deps.fetchInfo));
  });

  app.post("/api/routers/:ref/revoke", requireAdmin, async (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    if (!router) {
      res.status(404).json({ error: "not found" });
      return;
    }
    await revokeRouter(store, wg, router);
    issues.clearSerial(router.serialNumber);
    audit.log(who(req), "revoke", router.serialNumber, router.tunnelIp);
    console.log(`revoked ${router.serialNumber} (${router.tunnelIp}) via web`);
    res.json({ ok: true });
  });

  // Permanently remove a router from the inventory. Two-step by design: a
  // router must be revoked first, so a live device can't be deleted by
  // accident (and its peer is already gone).
  app.delete("/api/routers/:ref", requireAdmin, (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    if (!router) {
      res.status(404).json({ error: "not found" });
      return;
    }
    if (router.state !== "revoked") {
      res.status(409).json({ error: "revoke the router before removing it" });
      return;
    }
    issues.clearSerial(router.serialNumber);
    topology.removeRouter(router.id);
    hosts.removeRouter(router.serialNumber);
    store.delete(router.id);
    audit.log(who(req), "remove", router.serialNumber, router.tunnelIp);
    console.log(`removed ${router.serialNumber} from inventory`);
    res.json({ ok: true });
  });

  // The tech-facing bootstrap one-liner, for display in the UI.
  app.get("/api/bootstrap-info", requireTech, (_req: Request, res: Response) => {
    res.json({
      oneLiner: renderOneLiner(config),
      masterTokenAllowed: config.auth.allowMasterProvisioningToken,
    });
  });

  // ---- pre-staging: create the record before the router ships
  app.post("/api/prestage", requireAdmin, (req: Request, res: Response) => {
    const parsed = z
      .object({
        serialNumber: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/),
        label: z.string().max(120).default(""),
        notes: z.string().max(4000).default(""),
      })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid request" });
      return;
    }
    if (store.findBySerial(parsed.data.serialNumber)) {
      res.status(409).json({ error: "serial already exists" });
      return;
    }
    const now = new Date().toISOString();
    const router: RouterRecord = {
      id: crypto.randomUUID(),
      serialNumber: parsed.data.serialNumber,
      publicKey: "",
      boardName: "unknown",
      rosVersion: "unknown",
      identity: "MikroTik",
      tunnelIp: "",
      username: config.router.username,
      password: generatePassword(),
      state: "staged",
      createdAt: now,
      updatedAt: now,
      lastSeenAt: null,
      label: parsed.data.label,
      notes: parsed.data.notes,
    };
    store.save(router);
    audit.log(who(req), "prestage", router.serialNumber, router.label);
    res.json({ ok: true, id: router.id });
  });

  // ---- one-time bootstrap tokens
  app.get("/api/tokens", requireAdmin, (_req: Request, res: Response) => {
    res.json(tokens.list());
  });

  app.post("/api/tokens", requireAdmin, (req: Request, res: Response) => {
    const parsed = z
      .object({
        note: z.string().max(200).default(""),
        ttlHours: z.number().int().min(1).max(24 * 365).nullable().default(72),
        customer: z.string().max(80).optional(),
        label: z.string().max(120).optional(),
      })
      .safeParse(req.body ?? {});
    if (!parsed.success) {
      res.status(400).json({ error: "invalid request" });
      return;
    }
    const t = tokens.create(parsed.data.note, who(req), parsed.data.ttlHours, {
      customer: parsed.data.customer?.trim(),
      label: parsed.data.label?.trim(),
    });
    audit.log(who(req), "token.create", t.customer || t.note || t.token.slice(0, 12));
    res.json({ ...t, oneLiner: renderOneLiner(config, t.token) });
  });

  app.delete("/api/tokens/:token", requireAdmin, (req: Request, res: Response) => {
    if (!tokens.delete(req.params.token)) {
      res.status(404).json({ error: "not found" });
      return;
    }
    audit.log(who(req), "token.delete", req.params.token.slice(0, 12));
    res.json({ ok: true });
  });

  // ---- dashboard users
  app.get("/api/users", requireAdmin, (_req: Request, res: Response) => {
    res.json(users.list());
  });

  app.post("/api/users", requireAdmin, (req: Request, res: Response) => {
    const parsed = z
      .object({
        username: z.string().max(32),
        role: z.enum(["admin", "tech"]),
        password: z.string().max(256).optional(),
      })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid request" });
      return;
    }
    const password = parsed.data.password ?? generatePassword(16);
    try {
      users.add(parsed.data.username, password, parsed.data.role);
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
      return;
    }
    audit.log(who(req), "user.add", parsed.data.username, parsed.data.role);
    // Password is returned exactly once, at creation.
    res.json({ ok: true, username: parsed.data.username, password });
  });

  // Admin resets another user's password (or generates one). Also ends that
  // user's active sessions so the new password takes effect everywhere.
  app.post("/api/users/:username/password", requireAdmin, (req: Request, res: Response) => {
    const parsed = z.object({ password: z.string().max(256).optional() }).safeParse(req.body ?? {});
    if (!parsed.success) {
      res.status(400).json({ error: "invalid request" });
      return;
    }
    if (!users.has(req.params.username)) {
      res.status(404).json({ error: "not found" });
      return;
    }
    const password = parsed.data.password ?? generatePassword(16);
    try {
      users.changePassword(req.params.username, password);
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
      return;
    }
    sessions.destroyForUser(req.params.username);
    audit.log(who(req), "user.reset-password", req.params.username);
    res.json({ ok: true, username: req.params.username, password });
  });

  app.delete("/api/users/:username", requireAdmin, (req: Request, res: Response) => {
    if (!users.remove(req.params.username)) {
      res.status(404).json({ error: "not found" });
      return;
    }
    sessions.destroyForUser(req.params.username);
    audit.log(who(req), "user.remove", req.params.username);
    res.json({ ok: true });
  });

  // ---- audit trail
  app.get("/api/audit", requireAdmin, (_req: Request, res: Response) => {
    res.json(audit.recent(200));
  });

  // ---- settings (Telegram notifications)
  app.get("/api/settings", requireAdmin, (_req: Request, res: Response) => {
    const tg = settings.telegram();
    const g = settings.general();
    // Never return the raw token; just whether one is set and a hint.
    res.json({
      telegram: {
        hasToken: Boolean(tg.botToken),
        tokenHint: tg.botToken ? tg.botToken.slice(0, 8) + "…" : "",
        chats: tg.chats,
      },
      general: {
        // Effective values (dashboard override, else config default).
        notifyOnRegister: g.notifyOnRegister ?? config.alerts.notifyOnRegister,
        notifyOnline: g.notifyOnline ?? config.alerts.notifyOnline,
        suppressMinutes: g.suppressMinutes ?? config.alerts.suppressMinutes,
      },
      monitor: {
        intervalSeconds: config.deviceMonitor.intervalSeconds,
        offlineAfterSeconds: config.monitor.offlineAfterSeconds,
      },
      routeKeys: ROUTE_KEYS,
    });
  });

  app.post("/api/settings/general", requireAdmin, (req: Request, res: Response) => {
    const parsed = z
      .object({
        notifyOnRegister: z.boolean(),
        notifyOnline: z.boolean(),
        suppressMinutes: z.number().int().min(0).max(1440),
      })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid settings" });
      return;
    }
    settings.setGeneral(parsed.data);
    audit.log(who(req), "settings.general", `suppress=${parsed.data.suppressMinutes}m`);
    res.json({ ok: true });
  });

  // Validate a bot token and list the chats it can reach.
  app.post("/api/settings/telegram/verify", requireAdmin, async (req: Request, res: Response) => {
    const parsed = z.object({ botToken: z.string().min(20).max(200) }).safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "provide a bot token" });
      return;
    }
    try {
      const me = await telegram.getMe(parsed.data.botToken);
      // Merge a fresh getUpdates read with chats the escalation poller has
      // already consumed (the poller advances the update offset, so a plain
      // read alone would miss chats it has seen).
      const byId = new Map((deps.extraChats?.() ?? []).map((c) => [c.id, c]));
      for (const c of await telegram.getChats(parsed.data.botToken)) byId.set(c.id, c);
      res.json({ ok: true, username: me.username, chats: [...byId.values()] });
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
    }
  });

  // Save the token + per-chat routing.
  app.post("/api/settings/telegram", requireAdmin, (req: Request, res: Response) => {
    const parsed = z
      .object({
        botToken: z.string().max(200),
        chats: z
          .array(
            z.object({
              id: z.string().max(64),
              title: z.string().max(200),
              type: z.string().max(32),
              events: z.record(z.boolean()),
            }),
          )
          .max(200),
      })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid settings" });
      return;
    }
    // Normalise events to the known keys.
    const chats: RouteChat[] = parsed.data.chats.map((c) => ({
      id: c.id,
      title: c.title,
      type: c.type,
      events: Object.fromEntries(ROUTE_KEYS.map((k) => [k, Boolean(c.events[k])])) as RouteChat["events"],
    }));
    settings.setTelegram(parsed.data.botToken.trim(), chats);
    audit.log(who(req), "settings.telegram", `${chats.length} chat(s)`);
    res.json({ ok: true });
  });

  // Send a test message to one chat.
  app.post("/api/settings/telegram/test", requireAdmin, async (req: Request, res: Response) => {
    const parsed = z.object({ chatId: z.string().max(64) }).safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "provide a chatId" });
      return;
    }
    const tg = settings.telegram();
    if (!tg.botToken) {
      res.status(400).json({ error: "no bot token saved — verify and save first" });
      return;
    }
    try {
      await telegram.send(tg.botToken, parsed.data.chatId, "✅ Korvix test notification — routing works.");
      res.json({ ok: true });
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
    }
  });

  // ---- status board: issues + events
  app.get("/api/issues", requireTech, (req: Request, res: Response) => {
    const all = req.query.all === "1";
    res.json({ counts: issues.counts(), issues: issues.list(all) });
  });

  app.post("/api/issues/:id/ack", requireTech, (req: Request, res: Response) => {
    if (!issues.ack(req.params.id, who(req))) {
      res.status(404).json({ error: "not found" });
      return;
    }
    audit.log(who(req), "issue.ack", req.params.id.slice(0, 8));
    res.json({ ok: true });
  });

  app.post("/api/issues/:id/resolve", requireTech, (req: Request, res: Response) => {
    const found = issues.list(true).find((i) => i.id === req.params.id);
    if (!found) {
      res.status(404).json({ error: "not found" });
      return;
    }
    // Resolve by id so a port-scoped issue (with a ref like "ether1") clears —
    // resolving by (serial,type) alone would miss anything with a ref.
    issues.resolveById(req.params.id);
    audit.log(who(req), "issue.resolve", found.serialNumber, `${found.type}${found.ref ? " " + found.ref : ""}`);
    res.json({ ok: true });
  });

  app.get("/api/events", requireTech, (_req: Request, res: Response) => {
    res.json(events.recent(200));
  });

  app.get("/api/routers/:ref/events", requireTech, (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    if (!router) {
      res.status(404).json({ error: "not found" });
      return;
    }
    res.json(events.forSerial(router.serialNumber, 50));
  });

  // ---- per-device type + monitoring settings
  app.patch("/api/routers/:ref/monitoring", requireAdmin, (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    if (!router) {
      res.status(404).json({ error: "not found" });
      return;
    }
    const parsed = z
      .object({
        deviceType: z.enum(["customer", "infrastructure"]).optional(),
        enabled: z.boolean().optional(),
        alertOnLogin: z.boolean().optional(),
        alertOnLinkDown: z.boolean().optional(),
        watchInterfaces: z.array(z.string().max(64)).max(64).optional(),
        ports: z
          .array(
            z.object({
              name: z.string().max(64),
              link: z.boolean().default(true),
              inverted: z.boolean().default(false),
              highBps: z.number().min(0).optional(),
              lowBps: z.number().min(0).optional(),
            }),
          )
          .max(64)
          .optional(),
        upstreamPing: z
          .object({
            enabled: z.boolean(),
            targets: z.array(z.string().regex(/^\d{1,3}(\.\d{1,3}){3}$/)).max(MAX_UPSTREAM_TARGETS),
            alertAboveMs: z.number().min(0).max(60000).optional(),
          })
          .optional(),
      })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid request" });
      return;
    }
    const p = parsed.data;
    if (p.deviceType) router.deviceType = p.deviceType as DeviceType;
    const mon = router.monitoring ?? defaultMonitoring(router.deviceType ?? "customer", true, true);
    if (p.enabled !== undefined) mon.enabled = p.enabled;
    if (p.alertOnLogin !== undefined) mon.alertOnLogin = p.alertOnLogin;
    if (p.alertOnLinkDown !== undefined) mon.alertOnLinkDown = p.alertOnLinkDown;
    if (p.ports !== undefined) {
      mon.ports = p.ports;
      // Keep the legacy field in sync so old readers still see watched ports.
      mon.watchInterfaces = p.ports.filter((r) => r.link).map((r) => r.name);
    } else if (p.watchInterfaces !== undefined) {
      mon.watchInterfaces = p.watchInterfaces;
      mon.ports = p.watchInterfaces.map((name) => ({ name, link: true, inverted: false }));
    }
    if (p.upstreamPing !== undefined) mon.upstreamPing = p.upstreamPing;
    // Changing rules invalidates the detection baseline so we re-learn cleanly.
    router.monitoring = mon;
    router.monState = { ifaceRunning: {}, seenLogins: [], initialised: false };
    router.updatedAt = new Date().toISOString();
    store.save(router);
    audit.log(who(req), "monitoring", router.serialNumber, `${router.deviceType} enabled=${mon.enabled}`);
    res.json({ ok: true, deviceType: router.deviceType, monitoring: mon });
  });

  // ---- live stats over the tunnel (system, interfaces, LTE/5G signal)
  app.get("/api/routers/:ref/live", requireTech, async (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    if (!router) {
      res.status(404).json({ error: "not found" });
      return;
    }
    if (router.state === "staged" || router.state === "revoked") {
      res.status(400).json({ error: "router is not online" });
      return;
    }
    try {
      res.json(await fetchLive(router.tunnelIp, router.username, router.password));
    } catch (err) {
      res.status(502).json({ error: `router unreachable: ${(err as Error).message}` });
    }
  });

  // ---- device profile: DHCP leases, IP addresses, health, firmware
  app.get("/api/routers/:ref/profile", requireTech, async (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    if (!router) {
      res.status(404).json({ error: "not found" });
      return;
    }
    if (router.state === "staged" || router.state === "revoked") {
      res.status(400).json({ error: "router is not online" });
      return;
    }
    try {
      res.json(await fetchProfile(router.tunnelIp, router.username, router.password));
    } catch (err) {
      res.status(502).json({ error: `router unreachable: ${(err as Error).message}` });
    }
  });

  // ---- upstream ping latency history (router -> 8.8.8.8 / 1.1.1.1 / custom)
  app.get("/api/routers/:ref/pings", requireTech, (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    if (!router) {
      res.status(404).json({ error: "not found" });
      return;
    }
    const hours = Math.min(720, Math.max(1, Number(req.query.hours) || 24));
    const samples = pings.samples(router.serialNumber, hours);
    // Series per target, in the order configured (targets seen only in old
    // samples still chart, appended after the configured ones).
    const configured = upstreamTargets(router.monitoring);
    const targets = [...configured];
    const series: Record<string, Array<{ t: number; rtt: number | null; loss: number }>> = {};
    for (const s of samples) {
      for (const [addr, v] of Object.entries(s.targets)) {
        if (!series[addr]) {
          series[addr] = [];
          if (!targets.includes(addr)) targets.push(addr);
        }
        series[addr].push({ t: s.at, rtt: v.rtt, loss: v.loss });
      }
    }
    for (const t of targets) if (!series[t]) series[t] = [];
    const up = router.monitoring?.upstreamPing;
    res.json({
      hours,
      intervalSeconds: config.upstreamPing.intervalSeconds,
      enabled: configured.length > 0,
      configuredTargets: configured,
      defaultTargets: DEFAULT_UPSTREAM_TARGETS,
      alertAboveMs: up?.alertAboveMs ?? 0,
      targets,
      series,
    });
  });

  // ---- historical traffic + previous-period comparison (from stored metrics)
  app.get("/api/routers/:ref/traffic", requireTech, (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    if (!router) {
      res.status(404).json({ error: "not found" });
      return;
    }
    const hours = Math.min(720, Math.max(1, Number(req.query.hours) || 24));
    const windowMs = hours * 3600_000;
    const now = Date.now();
    const sampleSeconds = config.metrics.sampleSeconds;
    const exclude = new Set([config.router.wgInterfaceName]);
    // Pull two windows so we can compare this period against the previous one.
    const all = metrics.samples(router.serialNumber, now - windowMs * 2);
    const curr = all.filter((s) => s.at >= now - windowMs);
    const prev = all.filter((s) => s.at >= now - windowMs * 2 && s.at < now - windowMs);
    const c = computeTraffic(curr, sampleSeconds, exclude);
    const p = computeTraffic(prev, sampleSeconds, exclude);
    let busiest: string | null = null;
    let best = -1;
    for (const [name, t] of Object.entries(c.totals)) {
      const v = t.rx + t.tx;
      if (v > best) {
        best = v;
        busiest = name;
      }
    }
    res.json({
      hours,
      sampleSeconds,
      interfaces: c.interfaces,
      series: c.series,
      totals: c.totals,
      prevSeries: p.series,
      prevTotals: p.totals,
      busiest,
      samples: curr.length,
    });
  });

  // ---- planned maintenance windows (alert suppression) -----------------
  app.get("/api/maintenance", requireTech, (_req: Request, res: Response) => {
    res.json(maintenance.list());
  });
  const maintSchema = z.object({
    scopeKind: z.enum(["all", "device", "customer"]),
    scopeValue: z.string().max(120).optional(),
    startsAt: z.string(),
    endsAt: z.string(),
    categories: z.array(z.enum(MAINT_CATEGORIES)).default([]),
    note: z.string().max(300).default(""),
  });
  app.post("/api/maintenance", requireAdmin, (req: Request, res: Response) => {
    const parsed = maintSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.issues.map((i) => i.message).join("; ") });
      return;
    }
    const p = parsed.data;
    const start = Date.parse(p.startsAt);
    const end = Date.parse(p.endsAt);
    if (Number.isNaN(start) || Number.isNaN(end) || end <= start) {
      res.status(400).json({ error: "end must be after start" });
      return;
    }
    if ((p.scopeKind === "device" || p.scopeKind === "customer") && !p.scopeValue) {
      res.status(400).json({ error: "scopeValue required for device/customer scope" });
      return;
    }
    const win = maintenance.add({
      scopeKind: p.scopeKind,
      scopeValue: p.scopeValue,
      startsAt: new Date(start).toISOString(),
      endsAt: new Date(end).toISOString(),
      categories: p.categories,
      note: p.note,
      createdBy: who(req),
    });
    audit.log(who(req), "maintenance.add", `${p.scopeKind}:${p.scopeValue ?? "*"}`, `${win.startsAt}→${win.endsAt}`);
    res.status(201).json(win);
  });
  app.delete("/api/maintenance/:id", requireAdmin, (req: Request, res: Response) => {
    if (!maintenance.remove(req.params.id)) {
      res.status(404).json({ error: "not found" });
      return;
    }
    audit.log(who(req), "maintenance.remove", req.params.id.slice(0, 8));
    res.json({ ok: true });
  });

  // ---- SLA / uptime report over a period (excludes planned maintenance)
  app.get("/api/reports/sla", requireTech, (req: Request, res: Response) => {
    const now = Date.now();
    const to = Number(req.query.to) || now;
    const from = Number(req.query.from) || to - 30 * 24 * 3600_000;
    if (!(to > from)) {
      res.status(400).json({ error: "invalid range" });
      return;
    }
    const outByserial = new Map<string, Span[]>();
    for (const o of outages.list()) {
      const start = Date.parse(o.startAt);
      const end = o.endAt ? Date.parse(o.endAt) : now; // open outage runs to now
      (outByserial.get(o.serialNumber) ?? outByserial.set(o.serialNumber, []).get(o.serialNumber)!).push({ start, end });
    }
    const devices = store
      .list()
      .filter((r) => r.state !== "staged" && r.state !== "revoked")
      .map((r) => {
        const maint = maintenance
          .windowsCovering(r.serialNumber, r.customerGroup, "offline")
          .map((w) => ({ start: Date.parse(w.startsAt), end: Date.parse(w.endsAt) }));
        const sla = computeSla({
          createdAt: Date.parse(r.createdAt),
          from,
          to,
          outages: outByserial.get(r.serialNumber) ?? [],
          maintenance: maint,
        });
        const target = r.slaTarget && r.slaTarget > 0 ? r.slaTarget : null;
        return {
          serialNumber: r.serialNumber,
          label: r.label || r.identity || r.serialNumber,
          customerGroup: r.customerGroup ?? null,
          uptimePct: sla.uptimePct,
          downMs: sla.downMs,
          excludedMs: sla.excludedMs,
          effectiveMs: sla.effectiveMs,
          outages: sla.outages,
          longestMs: sla.longestMs,
          slaTarget: target,
          // null = no target set, true = meets it, false = breached
          meetsTarget: target === null ? null : sla.uptimePct + 1e-9 >= target,
        };
      });

    const agg = (rows: typeof devices) => {
      const down = rows.reduce((a, d) => a + d.downMs, 0);
      const eff = rows.reduce((a, d) => a + d.effectiveMs, 0);
      return {
        devices: rows.length,
        uptimePct: eff > 0 ? Math.max(0, (1 - down / eff) * 100) : 100,
        downMs: down,
        outages: rows.reduce((a, d) => a + d.outages, 0),
        withTarget: rows.filter((d) => d.slaTarget !== null).length,
        breaching: rows.filter((d) => d.meetsTarget === false).length,
      };
    };
    const byCustomer = new Map<string, typeof devices>();
    for (const d of devices) {
      const key = d.customerGroup || "— Unassigned";
      (byCustomer.get(key) ?? byCustomer.set(key, []).get(key)!).push(d);
    }
    const customers = [...byCustomer.entries()]
      .map(([name, rows]) => ({ name, ...agg(rows) }))
      .sort((a, b) => a.uptimePct - b.uptimePct);

    res.json({ from, to, fleet: agg(devices), customers, devices: devices.sort((a, b) => a.uptimePct - b.uptimePct) });
  });

  // ---- one-off ping test: ask the router to ping any address on its LAN
  app.post("/api/routers/:ref/ping", requireTech, async (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    if (!router) {
      res.status(404).json({ error: "not found" });
      return;
    }
    if (router.state === "staged" || router.state === "revoked") {
      res.status(400).json({ error: "router is not online" });
      return;
    }
    const address = String((req.body ?? {}).address ?? "").trim();
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(address)) {
      res.status(400).json({ error: "address must be an IPv4 address" });
      return;
    }
    const count = Math.min(10, Math.max(1, Number((req.body ?? {}).count) || 4));
    try {
      const r = await fetchPingFn(router.tunnelIp, router.username, router.password, address, count, (count + 4) * 1000);
      res.json({ address, ...r, lossPct: r.sent ? Math.round(((r.sent - r.received) / r.sent) * 100) : 100 });
    } catch (err) {
      res.status(502).json({ error: `ping failed: ${(err as Error).message}` });
    }
  });

  // ---- monitored internal hosts (ping targets behind a router) ----------
  app.get("/api/routers/:ref/hosts", requireTech, (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    if (!router) {
      res.status(404).json({ error: "not found" });
      return;
    }
    res.json(hosts.forRouter(router.serialNumber));
  });

  const hostSchema = z.object({
    address: z.string().regex(/^\d{1,3}(\.\d{1,3}){3}$/, "must be an IPv4 address"),
    name: z.string().max(80).optional(),
    mac: z.string().max(40).optional(),
  });
  app.post("/api/routers/:ref/hosts", requireTech, (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    if (!router) {
      res.status(404).json({ error: "not found" });
      return;
    }
    const parsed = hostSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.issues.map((i) => i.message).join("; ") });
      return;
    }
    const host = hosts.add({
      routerSerial: router.serialNumber,
      routerId: router.id,
      address: parsed.data.address,
      name: parsed.data.name ?? "",
      mac: parsed.data.mac,
      createdBy: who(req),
    });
    audit.log(who(req), "host.add", router.serialNumber, `${host.name || ""} ${host.address}`.trim());
    res.status(201).json(host);
  });

  app.patch("/api/hosts/:id", requireTech, (req: Request, res: Response) => {
    const host = hosts.get(req.params.id);
    if (!host) {
      res.status(404).json({ error: "not found" });
      return;
    }
    const body = req.body ?? {};
    if (typeof body.enabled === "boolean") host.enabled = body.enabled;
    if (typeof body.name === "string") host.name = body.name.slice(0, 80);
    hosts.save(host);
    res.json(host);
  });

  app.delete("/api/hosts/:id", requireTech, (req: Request, res: Response) => {
    const host = hosts.get(req.params.id);
    if (!hosts.remove(req.params.id)) {
      res.status(404).json({ error: "not found" });
      return;
    }
    if (host) {
      issues.resolve(host.routerSerial, "host-down", `host:${host.address}`);
      audit.log(who(req), "host.remove", host.routerSerial, host.address);
    }
    res.json({ ok: true });
  });

  // ---- live streaming (Server-Sent Events) -----------------------------
  // EventSource can't set headers, so these authenticate via ?token=.
  function openSse(res: Response): void {
    res.set({
      "content-type": "text/event-stream",
      "cache-control": "no-cache",
      connection: "keep-alive",
      "x-accel-buffering": "no", // don't let a proxy buffer the stream
    });
    res.flushHeaders?.();
    res.write(": connected\n\n");
  }
  const sseData = (res: Response, obj: unknown) => res.write(`data: ${JSON.stringify(obj)}\n\n`);

  // Fleet heartbeat: handshake age + online for every router, shared across
  // all connected dashboards by a single ticker.
  const fleetClients = new Set<Response>();
  let fleetTimer: ReturnType<typeof setInterval> | null = null;
  async function fleetTick(): Promise<void> {
    if (fleetClients.size === 0) return;
    const hs = await wg.latestHandshakes().catch(() => ({}) as Record<string, number | null>);
    const routers = store
      .list()
      .filter((r) => r.state !== "staged" && r.state !== "revoked")
      .map((r) => {
        const handshakeAge = hs[r.publicKey] ?? null;
        const handshakeOnline = handshakeAge !== null && handshakeAge < config.monitor.offlineAfterSeconds;
        return {
          id: r.id,
          handshakeAge,
          health: r.health ?? null,
          online: r.health ? r.health !== "offline" : handshakeOnline,
        };
      });
    const frame = `data: ${JSON.stringify({ type: "heartbeat", routers })}\n\n`;
    for (const c of fleetClients) c.write(frame);
  }
  app.get("/api/stream", (req: Request, res: Response) => {
    if (!userFromToken(String(req.query.token ?? ""))) {
      res.status(401).end();
      return;
    }
    openSse(res);
    fleetClients.add(res);
    if (!fleetTimer) {
      fleetTimer = setInterval(() => void fleetTick(), 3000);
      fleetTimer.unref?.();
    }
    void fleetTick();
    req.on("close", () => fleetClients.delete(res));
  });

  // NOC wallboard feed: open faults (critical first), a live event ticker and
  // fleet online/offline counts, pushed to every connected wallboard by one
  // shared ticker.
  const nocClients = new Set<Response>();
  let nocTimer: ReturnType<typeof setInterval> | null = null;
  async function nocTick(): Promise<void> {
    if (nocClients.size === 0) return;
    const hs = await wg.latestHandshakes().catch(() => ({}) as Record<string, number | null>);
    const live = store.list().filter((r) => r.state !== "staged" && r.state !== "revoked");
    let online = 0;
    const degraded: Array<{ id: string; label: string; serialNumber: string; sinceSeconds: number | null }> = [];
    for (const r of live) {
      if (r.health) {
        if (r.health === "warning") {
          const okMs = r.lastPingOkAt ? Date.parse(r.lastPingOkAt) : null;
          degraded.push({
            id: r.id,
            label: r.label || r.identity || r.serialNumber,
            serialNumber: r.serialNumber,
            sinceSeconds: okMs ? Math.round((Date.now() - okMs) / 1000) : null,
          });
        }
        if (r.health !== "offline") online++;
      } else {
        const age = hs[r.publicKey] ?? null;
        if (age !== null && age < config.monitor.offlineAfterSeconds) online++;
      }
    }
    const groupOf = new Map(store.list().map((r) => [r.serialNumber, r.customerGroup]));
    const rank = (s: string) => (s === "critical" ? 0 : 1);
    // Hide issues whose device+category is under an active maintenance window.
    const open = issues
      .list(false)
      .filter((i) => !maintenance.suppressed(i.serialNumber, groupOf.get(i.serialNumber), maintCategory(i.type)))
      .sort((a, b) => rank(a.severity) - rank(b.severity) || b.openedAt.localeCompare(a.openedAt));
    const critical = open.filter((i) => i.severity === "critical").length;
    const warning = open.filter((i) => i.severity !== "critical").length;
    const maint = maintenance.active().map((w) => ({
      id: w.id,
      scope: w.scopeKind === "all" ? "whole fleet" : w.scopeValue,
      scopeKind: w.scopeKind,
      endsAt: w.endsAt,
      note: w.note,
    }));
    const degradedShown = degraded.filter((d) => !maintenance.suppressed(d.serialNumber, groupOf.get(d.serialNumber), "offline"));
    const frame = `data: ${JSON.stringify({
      type: "noc",
      at: new Date().toISOString(),
      fleet: { online, offline: live.length - online, warning: degradedShown.length, total: live.length, maintenance: maint.length },
      counts: { critical, warning, unacked: open.filter((i) => !i.ackedAt).length },
      issues: open,
      degraded: degradedShown,
      maintenance: maint,
      events: events.recent(40),
    })}\n\n`;
    for (const c of nocClients) c.write(frame);
  }
  app.get("/api/noc/stream", (req: Request, res: Response) => {
    if (!userFromToken(String(req.query.token ?? ""))) {
      res.status(401).end();
      return;
    }
    openSse(res);
    nocClients.add(res);
    if (!nocTimer) {
      nocTimer = setInterval(() => void nocTick(), 2500);
      nocTimer.unref?.();
    }
    void nocTick();
    req.on("close", () => nocClients.delete(res));
  });

  // Per-device deep stats: CPU/mem, interface throughput (bits/sec) and LTE,
  // pushed every ~2s while a client is watching this router.
  app.get("/api/routers/:ref/stream", (req: Request, res: Response) => {
    if (!userFromToken(String(req.query.token ?? ""))) {
      res.status(401).end();
      return;
    }
    const router = store.find(req.params.ref);
    if (!router) {
      res.status(404).end();
      return;
    }
    if (router.state === "staged" || router.state === "revoked") {
      res.status(400).end();
      return;
    }
    openSse(res);
    let prev: Sample | null = null;
    let busy = false;
    const tick = async (): Promise<void> => {
      if (busy) return;
      busy = true;
      try {
        const live = await fetchLive(router.tunnelIp, router.username, router.password, 6000);
        const curr: Sample = { at: Date.now(), interfaces: live.interfaces };
        sseData(res, { type: "stats", resource: live.resource, interfaces: interfaceRates(prev, curr), lte: live.lte });
        prev = curr;
      } catch (err) {
        sseData(res, { type: "error", error: (err as Error).message });
      } finally {
        busy = false;
      }
    };
    const timer = setInterval(() => void tick(), 2000);
    void tick();
    req.on("close", () => clearInterval(timer));
  });

  // ---- customer groups + topology map -----------------------------------
  function groupRouters(name: string) {
    return store.list().filter((r) => (r.customerGroup ?? "") === name && r.state !== "revoked");
  }

  // Customers = customer records (details) unioned with any group names in
  // use on devices, each with a device count.
  app.get("/api/customers", requireTech, (_req: Request, res: Response) => {
    const counts = new Map<string, number>();
    for (const r of store.list()) {
      if (r.state === "revoked") continue;
      const g = r.customerGroup?.trim();
      if (g) counts.set(g, (counts.get(g) ?? 0) + 1);
    }
    const names = new Set<string>([...counts.keys(), ...customers.list().map((c) => c.name)]);
    const out = [...names].map((name) => {
      const rec = customers.get(name);
      return {
        name,
        count: counts.get(name) ?? 0,
        contact: rec?.contact ?? "",
        phone: rec?.phone ?? "",
        email: rec?.email ?? "",
        address: rec?.address ?? "",
        notes: rec?.notes ?? "",
        hasRecord: Boolean(rec),
        hasStatusPage: Boolean(rec?.statusToken),
      };
    });
    res.json(out.sort((a, b) => a.name.localeCompare(b.name)));
  });
  app.post("/api/customers", requireAdmin, (req: Request, res: Response) => {
    const parsed = z
      .object({
        name: z.string().min(1).max(80),
        contact: z.string().max(120).optional(),
        phone: z.string().max(60).optional(),
        email: z.string().max(160).optional(),
        address: z.string().max(400).optional(),
        notes: z.string().max(4000).optional(),
      })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid customer" });
      return;
    }
    const { name, ...fields } = parsed.data;
    const c = customers.upsert(name.trim(), fields);
    audit.log(who(req), "customer.save", c.name);
    res.json({ ok: true, customer: c });
  });

  app.delete("/api/customers/:name", requireAdmin, (req: Request, res: Response) => {
    const name = req.params.name;
    const existed = customers.delete(name);
    // Unassign devices + drop the map so nothing dangles.
    let unassigned = 0;
    for (const r of store.list()) {
      if ((r.customerGroup ?? "") === name) {
        r.customerGroup = "";
        r.updatedAt = new Date().toISOString();
        store.save(r);
        unassigned++;
      }
    }
    topology.set(name, { nodes: {}, links: [] }, new Set());
    if (!existed && unassigned === 0) {
      res.status(404).json({ error: "not found" });
      return;
    }
    audit.log(who(req), "customer.delete", name, `${unassigned} device(s) unassigned`);
    res.json({ ok: true });
  });

  // ---- public status page (tokenized, read-only) ------------------------
  // Get-or-create a customer's status-page link. The URL is STABLE — once
  // handed to a client it keeps working; pass {rotate:true} to explicitly
  // mint a new token (killing the old link, e.g. after a leak).
  app.post("/api/customers/:name/status-token", requireAdmin, (req: Request, res: Response) => {
    const name = req.params.name;
    if (!customers.has(name)) customers.upsert(name, {});
    const rotate = Boolean((req.body ?? {}).rotate);
    let token = customers.get(name)?.statusToken;
    if (!token || rotate) {
      token = "st-" + crypto.randomBytes(12).toString("hex");
      customers.setStatusToken(name, token);
      audit.log(who(req), "customer.statuspage", name, rotate ? "rotated" : "enabled");
    }
    res.json({ ok: true, token, url: `${config.server.publicUrl.replace(/\/$/, "")}/status/${token}` });
  });
  app.delete("/api/customers/:name/status-token", requireAdmin, (req: Request, res: Response) => {
    if (!customers.setStatusToken(req.params.name, undefined)) {
      res.status(404).json({ error: "not found" });
      return;
    }
    audit.log(who(req), "customer.statuspage", req.params.name, "disabled");
    res.json({ ok: true });
  });

  // The data behind the public page. No session auth — the unguessable token
  // IS the credential. Read-only, and deliberately sparse: labels and states
  // only, no serials, no IPs, no internal messages.
  app.get("/api/status/:token", (req: Request, res: Response) => {
    const customer = customers.byStatusToken(req.params.token);
    if (!customer) {
      res.status(404).json({ error: "unknown status page" });
      return;
    }
    const routers = groupRouters(customer.name).filter((r) => r.state !== "staged" && r.state !== "revoked");
    const now = Date.now();
    const from = now - 30 * 24 * 3600_000;
    const outByserial = new Map<string, Span[]>();
    for (const o of outages.list()) {
      const arr = outByserial.get(o.serialNumber) ?? outByserial.set(o.serialNumber, []).get(o.serialNumber)!;
      arr.push({ start: Date.parse(o.startAt), end: o.endAt ? Date.parse(o.endAt) : now });
    }
    let down = 0;
    let eff = 0;
    const hostState = (s: string | undefined): string =>
      s === "up" ? "up" : s === "warning" ? "degraded" : s === "offline" ? "down" : "unknown";
    const devices = routers.map((r) => {
      const maint = maintenance
        .windowsCovering(r.serialNumber, r.customerGroup, "offline")
        .map((w) => ({ start: Date.parse(w.startsAt), end: Date.parse(w.endsAt) }));
      const sla = computeSla({ createdAt: Date.parse(r.createdAt), from, to: now, outages: outByserial.get(r.serialNumber) ?? [], maintenance: maint });
      down += sla.downMs;
      eff += sla.effectiveMs;
      const state =
        r.health === "warning" ? "degraded" : (r.health ? r.health !== "offline" : r.lastOnline !== false) ? "up" : "down";
      const upSince = [...(r.transitions ?? [])].reverse().find((t) => t.online)?.at ?? null;
      const target = r.slaTarget && r.slaTarget > 0 ? r.slaTarget : null;
      return {
        label: r.label || r.identity || r.serialNumber,
        state,
        upSince: state === "up" ? upSince : null,
        // The device's committed SLA and where it stands against it right now.
        uptime30d: sla.uptimePct,
        slaTarget: target,
        meetsSla: target === null ? null : sla.uptimePct + 1e-9 >= target,
        // Internal equipment this router ping-monitors, shown nested under it.
        hosts: hosts
          .forRouter(r.serialNumber)
          .filter((h) => h.enabled)
          // Public page: never leak the internal LAN IP — fall back to a
          // generic label, not the address.
          .map((h) => ({ label: h.name || "Equipment", state: hostState(h.state) })),
      };
    });
    const serials = new Set(routers.map((r) => r.serialNumber));
    const incidents = issues
      .list(false)
      .filter((i) => serials.has(i.serialNumber) && i.type !== "login")
      .map((i) => ({ label: i.label, type: i.type, since: i.openedAt }));
    // Sanitized topology for the page's read-only map: internal router ids are
    // remapped to opaque n0/n1/... keys; only labels, states, positions and
    // port names go out.
    const topo = topology.get(customer.name);
    const keyOf = new Map(routers.map((r, i) => [r.id, `n${i}`]));
    const map = {
      nodes: routers.map((r, i) => ({
        key: `n${i}`,
        label: r.label || r.identity || "device",
        state: devices[i].state,
        // Lets the page pick a sensible tree root (core gear on top).
        kind: r.deviceType ?? "customer",
      })),
      links: topo.links
        .filter((l) => keyOf.has(l.a) && keyOf.has(l.b))
        .map((l) => ({ a: keyOf.get(l.a), b: keyOf.get(l.b), aIface: l.aIface, bIface: l.bIface })),
    };
    const maint = maintenance
      .active()
      .filter((w) => w.scopeKind === "all" || (w.scopeKind === "customer" && w.scopeValue === customer.name) || (w.scopeKind === "device" && routers.some((r) => r.serialNumber === w.scopeValue)))
      .map((w) => ({ note: w.note, endsAt: w.endsAt }));
    res.json({
      customer: customer.name,
      at: new Date(now).toISOString(),
      overall: incidents.length === 0 && devices.every((d) => d.state === "up") ? "operational" : devices.some((d) => d.state === "down") ? "outage" : "degraded",
      devices,
      incidents,
      maintenance: maint,
      map,
      uptime30d: eff > 0 ? Math.max(0, (1 - down / eff) * 100) : 100,
    });
  });

  app.get("/status/:token", (_req: Request, res: Response) => {
    res.sendFile(WEB_STATUS);
  });

  app.get("/api/groups/:name", requireTech, async (req: Request, res: Response) => {
    const name = req.params.name;
    const routers = groupRouters(name);
    const hs = await wg.latestHandshakes().catch(() => ({}) as Record<string, number | null>);
    const validIds = new Set(routers.map((r) => r.id));
    res.json({
      name,
      routers: routers.map((r) => {
        const age = hs[r.publicKey] ?? null;
        return {
          id: r.id,
          serialNumber: r.serialNumber,
          label: r.label ?? "",
          identity: r.identity,
          deviceType: r.deviceType ?? "customer",
          tunnelIp: r.tunnelIp,
          state: r.state,
          online: age !== null && age < config.monitor.offlineAfterSeconds,
        };
      }),
      topology: topology.get(name),
      validIds: [...validIds],
    });
  });

  app.put("/api/groups/:name/topology", requireAdmin, (req: Request, res: Response) => {
    const name = req.params.name;
    const parsed = z
      .object({
        nodes: z.record(z.object({ x: z.number(), y: z.number() })),
        links: z.array(
          z.object({
            id: z.string().max(64).optional(),
            a: z.string().max(64),
            aIface: z.string().max(64),
            b: z.string().max(64),
            bIface: z.string().max(64),
          }),
        ).max(500),
      })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid topology" });
      return;
    }
    const validIds = new Set(groupRouters(name).map((r) => r.id));
    const saved = topology.set(name, parsed.data as GroupTopology, validIds);
    audit.log(who(req), "topology", name, `${saved.links.length} link(s)`);
    res.json({ ok: true, topology: saved });
  });

  // Auto-discover links between the group's devices from MikroTik neighbor
  // discovery (MNDP/LLDP): each device's /ip/neighbor table names the identity
  // + port of whatever is plugged into it. Manual links are kept as-is.
  app.post("/api/groups/:name/discover", requireAdmin, async (req: Request, res: Response) => {
    const name = req.params.name;
    const routers = groupRouters(name).filter((r) => r.state !== "staged" && r.state !== "revoked" && r.tunnelIp);
    if (routers.length === 0) {
      res.status(400).json({ error: "no active devices in this customer" });
      return;
    }
    const neighborsById = new Map<string, NeighborEntry[]>();
    let polled = 0;
    const CONCURRENCY = 5;
    for (let i = 0; i < routers.length; i += CONCURRENCY) {
      await Promise.all(
        routers.slice(i, i + CONCURRENCY).map(async (r) => {
          try {
            neighborsById.set(r.id, await fetchNeighborsFn(r.tunnelIp, r.username, r.password));
            polled++;
          } catch {
            // unreachable device — its links can still be found from the other end
          }
        }),
      );
    }
    const current = topology.get(name);
    const result = discoverLinks(
      routers.map((r) => ({ id: r.id, identity: r.identity, label: r.label || r.identity || r.serialNumber })),
      neighborsById,
      current.links,
    );
    const validIds = new Set(routers.map((r) => r.id));
    const saved = topology.set(name, { nodes: current.nodes, links: result.links }, validIds);
    audit.log(who(req), "topology.discover", name, `${result.added} added, ${result.confirmed} confirmed`);
    res.json({ ok: true, polled, added: result.added, confirmed: result.confirmed, unmatched: result.unmatched, topology: saved });
  });

  // Live per-interface throughput for every device in a group — feeds the map.
  app.get("/api/groups/:name/stream", (req: Request, res: Response) => {
    if (!userFromToken(String(req.query.token ?? ""))) {
      res.status(401).end();
      return;
    }
    const name = req.params.name;
    openSse(res);
    const prev = new Map<string, Sample>();
    let busy = false;
    const tick = async (): Promise<void> => {
      if (busy) return;
      busy = true;
      try {
        const hs = await wg.latestHandshakes().catch(() => ({}) as Record<string, number | null>);
        const routers = groupRouters(name);
        const perRouter = await Promise.all(
          routers.map(async (r) => {
            const age = hs[r.publicKey] ?? null;
            const online = age !== null && age < config.monitor.offlineAfterSeconds;
            if (!online) return { id: r.id, online: false, interfaces: [] as unknown[] };
            try {
              const ifaces = await fetchIfaces(r.tunnelIp, r.username, r.password, 5000);
              const curr: Sample = { at: Date.now(), interfaces: ifaces };
              const rated = interfaceRates(prev.get(r.id) ?? null, curr);
              prev.set(r.id, curr);
              return {
                id: r.id,
                online: true,
                interfaces: rated.map((i) => ({ name: i.name, running: i.running, rxBps: i.rxBps, txBps: i.txBps })),
              };
            } catch {
              return { id: r.id, online: true, interfaces: [] as unknown[] };
            }
          }),
        );
        sseData(res, { type: "grouptraffic", routers: perRouter });
      } finally {
        busy = false;
      }
    };
    const timer = setInterval(() => void tick(), 2500);
    void tick();
    req.on("close", () => clearInterval(timer));
  });

  // ---- port map: the router's interfaces for the faceplate diagram
  app.get("/api/routers/:ref/interfaces", requireTech, async (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    if (!router) {
      res.status(404).json({ error: "not found" });
      return;
    }
    if (router.state === "staged" || router.state === "revoked") {
      res.status(400).json({ error: "router is not online" });
      return;
    }
    try {
      const ifaces = await fetchIfaces(router.tunnelIp, router.username, router.password);
      const ports = router.monitoring ? effectivePorts(router.monitoring) : [];
      res.json({ interfaces: ifaces, watched: ports.filter((p) => p.link).map((p) => p.name), ports });
    } catch (err) {
      res.status(502).json({ error: `router unreachable: ${(err as Error).message}` });
    }
  });

  // ---- bulk command runner (SSH over the tunnel)
  // ---- single-device control (admin) -----------------------------------
  function onlineRouter(ref: string, res: Response): RouterRecord | null {
    const router = store.find(ref);
    if (!router) {
      res.status(404).json({ error: "not found" });
      return null;
    }
    if (router.state === "staged" || router.state === "revoked") {
      res.status(400).json({ error: "router is not online" });
      return null;
    }
    return router;
  }

  app.post("/api/routers/:ref/reboot", requireAdmin, async (req: Request, res: Response) => {
    const router = onlineRouter(req.params.ref, res);
    if (!router) return;
    try {
      await reboot(router.tunnelIp, router.username, router.password);
      audit.log(who(req), "reboot", router.serialNumber, router.tunnelIp);
      events.add({ at: new Date().toISOString(), serialNumber: router.serialNumber, label: router.label || router.identity || router.serialNumber, type: "monitor-error", severity: "warning", message: `Reboot issued by ${who(req)}` });
      res.json({ ok: true });
    } catch (err) {
      res.status(502).json({ error: `reboot failed: ${(err as Error).message}` });
    }
  });

  app.post("/api/routers/:ref/exec", requireAdmin, async (req: Request, res: Response) => {
    const router = onlineRouter(req.params.ref, res);
    if (!router) return;
    const command = String((req.body ?? {}).command ?? "").trim();
    if (!command || command.length > 4000) {
      res.status(400).json({ error: "command required" });
      return;
    }
    try {
      const out = await sshRun(router.tunnelIp, router.username, router.password, command);
      audit.log(who(req), "exec", router.serialNumber, command);
      res.json({ ok: out.ok, output: out.output });
    } catch (err) {
      res.status(502).json({ error: `command failed: ${(err as Error).message}` });
    }
  });

  // ---- RouterOS upgrades: check, staged rollout jobs ---------------------
  app.post("/api/routers/:ref/upgrade-check", requireAdmin, async (req: Request, res: Response) => {
    const router = onlineRouter(req.params.ref, res);
    if (!router) return;
    try {
      const c = await upgrades.check(router);
      audit.log(who(req), "upgrade-check", router.serialNumber, `${c.installed} -> ${c.latest || "?"}`);
      res.json({ ...c, updateAvailable: updateAvailable(c) });
    } catch (err) {
      res.status(502).json({ error: `check failed: ${(err as Error).message}` });
    }
  });

  app.post("/api/upgrades", requireAdmin, (req: Request, res: Response) => {
    const parsed = z
      .object({ refs: z.array(z.string()).min(1).max(500), alsoFirmware: z.boolean().optional() })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid request" });
      return;
    }
    if (upgrades.busy()) {
      res.status(409).json({ error: "an upgrade job is already running - wait for it to finish or cancel it" });
      return;
    }
    const routers = parsed.data.refs.flatMap((ref) => store.find(ref) ?? []);
    const runnable = routers.filter((r) => r.tunnelIp && r.state !== "staged" && r.state !== "revoked");
    if (!runnable.length) {
      res.status(400).json({ error: "no online targets" });
      return;
    }
    const job = upgrades.start(runnable, who(req), parsed.data.alsoFirmware ?? false);
    audit.log(who(req), "upgrade", `${runnable.length} router(s)`, runnable.map((r) => r.serialNumber).join(", "));
    res.json(job);
  });

  app.get("/api/upgrades", requireTech, (_req: Request, res: Response) => {
    res.json(upgrades.list());
  });

  app.get("/api/upgrades/:id", requireTech, (req: Request, res: Response) => {
    const job = upgrades.get(req.params.id);
    if (!job) {
      res.status(404).json({ error: "not found" });
      return;
    }
    res.json(job);
  });

  app.post("/api/upgrades/:id/cancel", requireAdmin, (req: Request, res: Response) => {
    if (!upgrades.cancel(req.params.id)) {
      res.status(404).json({ error: "no running job with that id" });
      return;
    }
    audit.log(who(req), "upgrade-cancel", req.params.id);
    res.json({ ok: true });
  });

  // ---- live interactive console (real RouterOS CLI over an SSH PTY)
  app.post("/api/routers/:ref/console", requireAdmin, async (req: Request, res: Response) => {
    const router = onlineRouter(req.params.ref, res);
    if (!router) return;
    const cols = Math.min(500, Math.max(20, Number((req.body ?? {}).cols) || 120));
    const rows = Math.min(200, Math.max(5, Number((req.body ?? {}).rows) || 32));
    try {
      const sid = await consoles.open(router.tunnelIp, router.username, router.password, router.serialNumber, cols, rows);
      audit.log(who(req), "console", router.serialNumber, "session opened");
      res.json({ sid });
    } catch (err) {
      res.status(502).json({ error: `console failed: ${(err as Error).message}` });
    }
  });

  // SSE side of the console; token rides the query string (EventSource can't
  // set headers). Admin only, same as opening the session.
  app.get("/api/console/:sid/stream", (req: Request, res: Response) => {
    const user = userFromToken(String(req.query.token ?? ""));
    if (!user || user.role !== "admin") {
      res.status(401).end();
      return;
    }
    openSse(res);
    if (!consoles.attach(req.params.sid, res)) {
      res.write(`data: ${JSON.stringify({ end: "no such session" })}\n\n`);
      res.end();
    }
  });

  app.post("/api/console/:sid/input", requireAdmin, (req: Request, res: Response) => {
    const data = String((req.body ?? {}).data ?? "");
    if (!data) {
      res.status(400).json({ error: "data required" });
      return;
    }
    if (!consoles.input(req.params.sid, data)) {
      res.status(404).json({ error: "no such session" });
      return;
    }
    res.json({ ok: true });
  });

  app.post("/api/console/:sid/resize", requireAdmin, (req: Request, res: Response) => {
    const cols = Math.min(500, Math.max(20, Number((req.body ?? {}).cols) || 0));
    const rows = Math.min(200, Math.max(5, Number((req.body ?? {}).rows) || 0));
    if (!consoles.resize(req.params.sid, cols, rows)) {
      res.status(404).json({ error: "no such session" });
      return;
    }
    res.json({ ok: true });
  });

  app.delete("/api/console/:sid", requireAdmin, (req: Request, res: Response) => {
    const serial = consoles.serialOf(req.params.sid);
    if (!consoles.close(req.params.sid)) {
      res.status(404).json({ error: "no such session" });
      return;
    }
    audit.log(who(req), "console", serial ?? "?", "session closed");
    res.json({ ok: true });
  });

  app.post("/api/bulk", requireAdmin, async (req: Request, res: Response) => {
    const parsed = z
      .object({
        command: z.string().min(1).max(4000),
        refs: z.array(z.string()).max(1000).optional(),
      })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid request" });
      return;
    }
    const targets = parsed.data.refs
      ? parsed.data.refs.flatMap((r) => store.find(r) ?? [])
      : store.list();
    const runnable = targets.filter((r) => r.state !== "revoked" && r.state !== "staged");
    if (runnable.length === 0) {
      res.status(400).json({ error: "no runnable targets" });
      return;
    }
    audit.log(who(req), "bulk", `${runnable.length} routers`, parsed.data.command);

    const results: Array<{ serialNumber: string; label: string; ok: boolean; output: string }> = [];
    const CONCURRENCY = 5;
    for (let i = 0; i < runnable.length; i += CONCURRENCY) {
      const batch = runnable.slice(i, i + CONCURRENCY);
      const settled = await Promise.all(
        batch.map(async (r) => {
          try {
            const out = await sshRun(r.tunnelIp, r.username, r.password, parsed.data.command);
            return { serialNumber: r.serialNumber, label: r.label ?? "", ok: out.ok, output: out.output };
          } catch (err) {
            return {
              serialNumber: r.serialNumber,
              label: r.label ?? "",
              ok: false,
              output: (err as Error).message,
            };
          }
        }),
      );
      results.push(...settled);
    }
    res.json({ results });
  });

  // ---- backup diff & restore staging
  app.get("/api/routers/:ref/backups-diff", requireTech, (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    const a = String(req.query.a ?? "");
    const b = String(req.query.b ?? "");
    const aBuf = router ? backups.read(router.serialNumber, a) : null;
    const bBuf = router ? backups.read(router.serialNumber, b) : null;
    if (!router || !aBuf || !bBuf) {
      res.status(404).json({ error: "not found" });
      return;
    }
    const patch = createTwoFilesPatch(a, b, aBuf.toString(), bBuf.toString(), "", "", {
      context: 3,
    });
    res.type("text/plain").send(patch);
  });

  // Uploads a stored backup onto the router as wg-restore.rsc so an operator
  // can review and `/import` it. Deliberately not auto-imported: replaying a
  // full export onto a live config needs human eyes.
  app.post("/api/routers/:ref/restore", requireAdmin, async (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    const name = String((req.body ?? {}).name ?? "");
    const content = router ? backups.read(router.serialNumber, name) : null;
    if (!router || !content) {
      res.status(404).json({ error: "not found" });
      return;
    }
    if (router.state === "staged" || router.state === "revoked") {
      res.status(400).json({ error: "router is not online" });
      return;
    }
    try {
      await sftpPut(router.tunnelIp, router.username, router.password, content, "wg-restore.rsc");
      audit.log(who(req), "restore.stage", router.serialNumber, name);
      res.json({
        ok: true,
        instructions: `Uploaded as wg-restore.rsc. Review it on the router, then apply with: /import wg-restore.rsc  (ssh ${router.username}@${router.tunnelIp})`,
      });
    } catch (err) {
      res.status(502).json({ error: `upload failed: ${(err as Error).message}` });
    }
  });

  // The dashboard itself. Static, self-contained; auth happens client-side
  // against the admin API, so serving the shell is harmless.
  app.get("/", (_req: Request, res: Response) => {
    res.sendFile(WEB_INDEX);
  });

  // The live NOC wallboard — status + faults only, its own full-screen page.
  app.get("/noc", (_req: Request, res: Response) => {
    res.sendFile(WEB_NOC);
  });

  // Vendored terminal-emulator assets for the device console (self-hosted, no CDN).
  for (const f of ["xterm.js", "xterm.css", "addon-fit.js"]) {
    app.get(`/vendor/${f}`, (_req: Request, res: Response) => {
      res.sendFile(fileURLToPath(new URL(`../web/vendor/${f}`, import.meta.url)));
    });
  }

  return app;
}
