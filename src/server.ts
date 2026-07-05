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
import { renderBootstrap, renderOneLiner, renderProvision } from "./templates.js";
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
import { fetchLiveStats, fetchInterfaces as realFetchInterfaces, type FetchLiveFn, type FetchIfacesFn } from "./routeros.js";
import { sshRun as realSshRun, sftpPut as realSftpPut, type SshRunFn, type SftpPutFn } from "./ssh.js";
import { defaultMonitoring, type RouterRecord, type DeviceType } from "./types.js";

export interface AppDeps {
  config: Config;
  store: RouterStore;
  wg: WireguardManager;
  /** Overrides for tests; default to the real implementations. */
  fetchInfo?: FetchInfoFn;
  fetchLive?: FetchLiveFn;
  fetchIfaces?: FetchIfacesFn;
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
  sftpPut?: SftpPutFn;
}

interface AuthedRequest extends Request {
  authUser?: { username: string; role: Role };
}

// Works from both src/ (tsx dev) and dist/ (build) — web/ sits beside them.
const WEB_INDEX = fileURLToPath(new URL("../web/index.html", import.meta.url));

const registerSchema = z.object({
  token: z.string(),
  publicKey: z.string().refine(isValidWgKey, "not a valid WireGuard public key"),
  serialNumber: z.string().regex(/^[A-Za-z0-9_.-]{1,64}$/, "invalid serial number"),
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
  const sftpPut = deps.sftpPut ?? realSftpPut;
  const fetchLive = deps.fetchLive ?? fetchLiveStats;
  const fetchIfaces = deps.fetchIfaces ?? realFetchInterfaces;

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
        return {
          ...rest,
          handshakeAge,
          online:
            rest.state !== "revoked" &&
            handshakeAge !== null &&
            handshakeAge < config.monitor.offlineAfterSeconds,
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
      const chats = await telegram.getChats(parsed.data.botToken);
      res.json({ ok: true, username: me.username, chats });
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
    issues.resolve(found.serialNumber, found.type);
    audit.log(who(req), "issue.resolve", found.serialNumber, found.type);
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
    if (p.watchInterfaces !== undefined) mon.watchInterfaces = p.watchInterfaces;
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
        return {
          id: r.id,
          handshakeAge,
          online: handshakeAge !== null && handshakeAge < config.monitor.offlineAfterSeconds,
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
      res.json({ interfaces: ifaces, watched: router.monitoring?.watchInterfaces ?? [] });
    } catch (err) {
      res.status(502).json({ error: `router unreachable: ${(err as Error).message}` });
    }
  });

  // ---- bulk command runner (SSH over the tunnel)
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

  return app;
}
