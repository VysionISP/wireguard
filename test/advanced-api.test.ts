import path from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { buildApp } from "../src/server.js";
import { RouterStore } from "../src/store.js";
import { BackupStore } from "../src/backups.js";
import { TokenStore } from "../src/tokens.js";
import { UserStore, SessionManager } from "../src/users.js";
import { AuditLog } from "../src/audit.js";
import { DryRunManager } from "../src/wireguard.js";
import { fakeKey, tempDir, testConfig } from "./helpers.js";
import type { Config } from "../src/config.js";

let cfg: Config;
let store: RouterStore;
let tokens: TokenStore;
let users: UserStore;
let sessions: SessionManager;
let app: ReturnType<typeof buildApp>;

const sshRun = async (_h: string, _u: string, _p: string, command: string) => ({
  ok: true,
  output: `ran: ${command}`,
});
const sftpPut = async () => {};
const fetchLive = async () => ({
  at: 0,
  resource: { uptime: "1d", version: "7.15", cpuLoad: 5, freeMemory: 100, totalMemory: 256, boardName: "Chateau" },
  interfaces: [{ name: "lte1", type: "lte", running: true, rxByte: 10, txByte: 20 }],
  lte: [{ interface: "lte1", rsrp: "-95", rsrq: "-10", sinr: "12" }],
});

function build() {
  return buildApp({ config: cfg, store, wg: new DryRunManager("wg0", true), tokens, users, sessions, sshRun, fetchLive, sftpPut,
    backups: new BackupStore(path.join(tempDir(), "b"), 5) });
}
const A = () => `Bearer ${cfg.auth.adminToken}`;
function req(method: "get" | "post" | "patch" | "delete", p: string, auth = A()) {
  return request(app)[method](p).set("authorization", auth);
}
function register(serial: string, key: number, token = cfg.auth.provisioningToken) {
  return request(app).post("/api/register").send({ token, publicKey: fakeKey(key), serialNumber: serial });
}

beforeEach(() => {
  cfg = testConfig();
  store = new RouterStore(cfg.storePath);
  tokens = new TokenStore(cfg.tokensPath);
  users = new UserStore(cfg.usersPath);
  sessions = new SessionManager(12);
  app = build();
});

describe("roles & login", () => {
  it("tech can view but not revoke; admin can", async () => {
    users.add("tech1", "techpass1", "tech");
    await register("HEX1", 1);
    const login = await request(app).post("/api/login").send({ username: "tech1", password: "techpass1" });
    expect(login.status).toBe(200);
    const techAuth = `Bearer ${login.body.session}`;

    expect((await req("get", "/api/routers", techAuth)).status).toBe(200);
    expect((await req("post", "/api/routers/HEX1/revoke", techAuth)).status).toBe(403);
    expect((await req("post", "/api/routers/HEX1/revoke", A())).status).toBe(200);
  });

  it("admin-token acts as admin; bad token is 401", async () => {
    expect((await req("get", "/api/users")).status).toBe(200);
    expect((await req("get", "/api/users", "Bearer nope")).status).toBe(401);
  });

  it("me reports identity", async () => {
    const me = await req("get", "/api/me");
    expect(me.body).toEqual({ username: "admin-token", role: "admin" });
  });
});

describe("one-time tokens", () => {
  it("registers exactly one router then rejects reuse", async () => {
    const t = await req("post", "/api/tokens").send({ note: "install", ttlHours: 24 });
    const tok = t.body.token;
    expect((await register("HEXA", 1, tok)).status).toBe(200);
    // reuse for a different serial fails
    expect((await register("HEXB", 2, tok)).status).toBe(401);
    // token now shows used
    const list = await req("get", "/api/tokens");
    expect(list.body[0].usedBySerial).toBe("HEXA");
  });

  it("disabling the master token blocks it but one-time still works", async () => {
    cfg.auth.allowMasterProvisioningToken = false;
    app = build();
    expect((await register("HEXC", 3)).status).toBe(401);
    const t = await req("post", "/api/tokens").send({ note: "x" });
    expect((await register("HEXC", 3, t.body.token)).status).toBe(200);
  });
});

describe("pre-staging", () => {
  it("staged router keeps its label when it registers", async () => {
    const ps = await req("post", "/api/prestage").send({ serialNumber: "HEXP", label: "Smith residence" });
    expect(ps.status).toBe(200);
    expect(store.findBySerial("HEXP")!.state).toBe("staged");

    const reg = await register("HEXP", 5);
    expect(reg.status).toBe(200);
    const r = store.findBySerial("HEXP")!;
    expect(r.state).toBe("registered");
    expect(r.label).toBe("Smith residence");
    expect(r.tunnelIp).toBe("10.99.0.2");
  });

  it("rejects duplicate serials", async () => {
    await req("post", "/api/prestage").send({ serialNumber: "HEXD", label: "x" });
    expect((await req("post", "/api/prestage").send({ serialNumber: "HEXD", label: "y" })).status).toBe(409);
  });
});

describe("live stats, bulk, diff, restore", () => {
  beforeEach(async () => {
    await register("HEXL", 1);
  });

  it("returns live stats including LTE signal", async () => {
    const res = await req("get", "/api/routers/HEXL/live");
    expect(res.status).toBe(200);
    expect(res.body.lte[0].rsrp).toBe("-95");
    expect(res.body.resource.boardName).toBe("Chateau");
  });

  it("runs a bulk command and returns per-router output", async () => {
    const res = await req("post", "/api/bulk").send({ command: "/system/identity/print" });
    expect(res.status).toBe(200);
    expect(res.body.results[0].ok).toBe(true);
    expect(res.body.results[0].output).toContain("identity/print");
  });

  it("bulk is admin-only", async () => {
    users.add("tech2", "techpass1", "tech");
    const login = await request(app).post("/api/login").send({ username: "tech2", password: "techpass1" });
    expect((await req("post", "/api/bulk", `Bearer ${login.body.session}`).send({ command: "x" })).status).toBe(403);
  });

  it("diffs two backups and stages a restore", async () => {
    // two distinct backups
    await request(app).post(`/api/backup?token=${cfg.auth.provisioningToken}&serial=HEXL`).set("content-type", "application/octet-stream").send(Buffer.from("# v1\nline"));
    await new Promise((r) => setTimeout(r, 5));
    await request(app).post(`/api/backup?token=${cfg.auth.provisioningToken}&serial=HEXL`).set("content-type", "application/octet-stream").send(Buffer.from("# v2\nline changed"));
    const list = await req("get", "/api/routers/HEXL/backups");
    const [b, a] = list.body; // newest first
    const diff = await req("get", `/api/routers/HEXL/backups-diff?a=${a.name}&b=${b.name}`);
    expect(diff.status).toBe(200);
    expect(diff.text).toContain("changed");

    const restore = await req("post", "/api/routers/HEXL/restore").send({ name: a.name });
    expect(restore.status).toBe(200);
    expect(restore.body.instructions).toContain("/import");
  });
});

describe("audit log", () => {
  it("records mutating actions", async () => {
    await register("HEXAU", 1);
    await req("post", "/api/routers/HEXAU/revoke");
    const audit = await req("get", "/api/audit");
    const actions = audit.body.map((e: any) => e.action);
    expect(actions).toContain("revoke");
    expect(actions).toContain("register");
  });
});
