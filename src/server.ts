import crypto from "node:crypto";
import express, { type Express, type Request, type Response } from "express";
import { z } from "zod";
import type { Config } from "./config.js";
import type { RouterStore } from "./store.js";
import type { WireguardManager } from "./wireguard.js";
import { isValidWgKey } from "./wireguard.js";
import { allocateIp } from "./ipam.js";
import { renderBootstrap, renderProvision } from "./templates.js";
import type { RouterRecord } from "./types.js";

export interface AppDeps {
  config: Config;
  store: RouterStore;
  wg: WireguardManager;
}

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

export function buildApp(deps: AppDeps): Express {
  const { config, store, wg } = deps;
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

  // Admin: inventory listing (credentials excluded; use the CLI on-host for those).
  app.get("/api/routers", (req: Request, res: Response) => {
    const auth = req.get("authorization") ?? "";
    const token = auth.replace(/^Bearer\s+/i, "");
    if (!tokenEquals(token, config.auth.adminToken)) {
      res.status(401).json({ error: "unauthorized" });
      return;
    }
    res.json(
      store.list().map(({ password: _password, ...rest }) => rest),
    );
  });

  return app;
}
