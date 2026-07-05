import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import express, { type Express, type Request, type Response, type NextFunction } from "express";
import { z } from "zod";
import type { Config } from "./config.js";
import type { RouterStore } from "./store.js";
import type { WireguardManager } from "./wireguard.js";
import { isValidWgKey } from "./wireguard.js";
import { allocateIp } from "./ipam.js";
import { renderBootstrap, renderOneLiner, renderProvision } from "./templates.js";
import { revokeRouter, verifyRouter, type FetchInfoFn } from "./actions.js";
import { BackupStore } from "./backups.js";
import type { RouterRecord } from "./types.js";

export interface AppDeps {
  config: Config;
  store: RouterStore;
  wg: WireguardManager;
  /** Override for tests; defaults to the real RouterOS REST client. */
  fetchInfo?: FetchInfoFn;
  backups?: BackupStore;
}

// Works from both src/ (tsx dev) and dist/ (build) — web/ sits beside them.
const WEB_INDEX = fileURLToPath(new URL("../web/index.html", import.meta.url));

const registerSchema = z.object({
  token: z.string(),
  publicKey: z.string().refine(isValidWgKey, "not a valid WireGuard public key"),
  serialNumber: z.string().min(1).max(64),
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
});

export function buildApp(deps: AppDeps): Express {
  const { config, store, wg } = deps;
  const backups = deps.backups ?? new BackupStore(config.backup.dir, config.backup.keep);
  const app = express();
  app.use(express.json({ limit: "16kb" }));

  app.get("/healthz", (_req, res) => {
    res.json({ ok: true });
  });

  // The bootstrap script a tech fetches onto a fresh router.
  app.get("/bootstrap.rsc", (req: Request, res: Response) => {
    const token = String(req.query.token ?? "");
    if (!tokenEquals(token, config.auth.provisioningToken)) {
      res.status(401).type("text/plain").send(":log error \"wg-provision: invalid token\"\n");
      return;
    }
    res.type("text/plain").send(renderBootstrap(config));
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
    if (!tokenEquals(body.token, config.auth.provisioningToken)) {
      res.status(401).json({ error: "invalid provisioning token" });
      return;
    }

    const now = new Date().toISOString();
    let router = store.findBySerial(body.serialNumber);

    if (router?.state === "revoked") {
      res.status(403).json({ error: "router has been revoked" });
      return;
    }

    try {
      if (router) {
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
        } satisfies RouterRecord;
        await wg.addPeer(router.publicKey, router.tunnelIp);
      }
      store.save(router);
    } catch (err) {
      console.error("register failed:", err);
      res.status(500).json({ error: "failed to register peer" });
      return;
    }

    console.log(
      `registered ${router.serialNumber} (${router.boardName}) -> ${router.tunnelIp}`,
    );
    res.type("text/plain").send(renderProvision(config, router));
  });

  // Router confirms it applied the provisioning script.
  app.post("/api/confirm", (req: Request, res: Response) => {
    const parsed = confirmSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid request" });
      return;
    }
    if (!tokenEquals(parsed.data.token, config.auth.provisioningToken)) {
      res.status(401).json({ error: "invalid provisioning token" });
      return;
    }
    const router = store.findBySerial(parsed.data.serialNumber);
    if (!router || router.state === "revoked") {
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

  const requireAdmin = (req: Request, res: Response, next: NextFunction): void => {
    const auth = req.get("authorization") ?? "";
    const token = auth.replace(/^Bearer\s+/i, "");
    if (!tokenEquals(token, config.auth.adminToken)) {
      res.status(401).json({ error: "unauthorized" });
      return;
    }
    next();
  };

  // Inventory listing with live handshake ages (credentials excluded).
  app.get("/api/routers", requireAdmin, async (_req: Request, res: Response) => {
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
  app.patch("/api/routers/:ref", requireAdmin, (req: Request, res: Response) => {
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
    router.updatedAt = new Date().toISOString();
    store.save(router);
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
      if (!tokenEquals(token, config.auth.provisioningToken)) {
        res.status(401).json({ error: "invalid provisioning token" });
        return;
      }
      const router = store.findBySerial(serial);
      if (!router || router.state === "revoked") {
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

  app.get("/api/routers/:ref/backups", requireAdmin, (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    if (!router) {
      res.status(404).json({ error: "not found" });
      return;
    }
    res.json(backups.list(router.serialNumber));
  });

  app.get("/api/routers/:ref/backups/:name", requireAdmin, (req: Request, res: Response) => {
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
  app.get("/api/routers/:ref", requireAdmin, async (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    if (!router) {
      res.status(404).json({ error: "not found" });
      return;
    }
    const handshakeAge = await wg.latestHandshake(router.publicKey).catch(() => null);
    res.json({ ...router, handshakeAge });
  });

  app.post("/api/routers/:ref/verify", requireAdmin, async (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    if (!router) {
      res.status(404).json({ error: "not found" });
      return;
    }
    res.json(await verifyRouter(store, wg, router, deps.fetchInfo));
  });

  app.post("/api/routers/:ref/revoke", requireAdmin, async (req: Request, res: Response) => {
    const router = store.find(req.params.ref);
    if (!router) {
      res.status(404).json({ error: "not found" });
      return;
    }
    await revokeRouter(store, wg, router);
    console.log(`revoked ${router.serialNumber} (${router.tunnelIp}) via web`);
    res.json({ ok: true });
  });

  // The tech-facing bootstrap one-liner, for display in the UI.
  app.get("/api/bootstrap-info", requireAdmin, (_req: Request, res: Response) => {
    res.json({ oneLiner: renderOneLiner(config) });
  });

  // The dashboard itself. Static, self-contained; auth happens client-side
  // against the admin API, so serving the shell is harmless.
  app.get("/", (_req: Request, res: Response) => {
    res.sendFile(WEB_INDEX);
  });

  return app;
}
