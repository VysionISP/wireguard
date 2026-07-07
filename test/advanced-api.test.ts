import path from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { buildApp } from "../src/server.js";
import { RouterStore } from "../src/store.js";
import { BackupStore } from "../src/backups.js";
import { TokenStore } from "../src/tokens.js";
import { UserStore, SessionManager } from "../src/users.js";
import { AuditLog } from "../src/audit.js";
import { IssueStore } from "../src/issues.js";
import { EventLog } from "../src/events.js";
import { DryRunManager } from "../src/wireguard.js";
import { fakeKey, tempDir, testConfig } from "./helpers.js";
import type { Config } from "../src/config.js";

let cfg: Config;
let store: RouterStore;
let tokens: TokenStore;
let users: UserStore;
let sessions: SessionManager;
let issuesStore: IssueStore;
let eventsStore: EventLog;
let app: ReturnType<typeof buildApp>;

const sshRun = async (_h: string, _u: string, _p: string, command: string) => ({
  ok: true,
  output: `ran: ${command}`,
});
const sftpPut = async () => {};
const fetchIfaces = async () => [
  { name: "ether1", type: "ether", running: true, disabled: false },
  { name: "sfp1", type: "sfp", running: false, disabled: false },
];
const fetchLive = async () => ({
  at: 0,
  resource: { uptime: "1d", version: "7.15", cpuLoad: 5, freeMemory: 100, totalMemory: 256, boardName: "Chateau" },
  interfaces: [{ name: "lte1", type: "lte", running: true, rxByte: 10, txByte: 20 }],
  lte: [{ interface: "lte1", rsrp: "-95", rsrq: "-10", sinr: "12" }],
});

function build() {
  return buildApp({ config: cfg, store, wg: new DryRunManager("wg0", true), tokens, users, sessions, sshRun, fetchLive, fetchIfaces, sftpPut,
    issues: issuesStore, events: eventsStore,
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
  issuesStore = new IssueStore(cfg.issuesPath);
  eventsStore = new EventLog(cfg.eventsPath);
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

  it("concurrent registrations get distinct IPs and the token burns once", async () => {
    const t = await req("post", "/api/tokens").send({ note: "race" });
    const tok = t.body.token;
    // Two devices phone home with the SAME one-time token at the same instant.
    const [a, b] = await Promise.all([register("RACE-A", 21, tok), register("RACE-B", 22, tok)]);
    const statuses = [a.status, b.status].sort();
    // Exactly one succeeds; the other is rejected (token already burned).
    expect(statuses).toEqual([200, 401]);
    expect(store.list().filter((r) => r.serialNumber.startsWith("RACE")).length).toBe(1);
  });

  it("concurrent new registrations never collide on a tunnel IP", async () => {
    await Promise.all(
      Array.from({ length: 8 }, (_, i) => register(`BULK-${i}`, 30 + i)),
    );
    const ips = store.list().filter((r) => r.serialNumber.startsWith("BULK")).map((r) => r.tunnelIp);
    expect(new Set(ips).size).toBe(ips.length); // all distinct
  });

  it("rejects malformed serial numbers at registration", async () => {
    const res = await request(app).post("/api/register").send({
      token: cfg.auth.provisioningToken,
      publicKey: fakeKey(1),
      serialNumber: "bad serial\n/system reset",
    });
    expect(res.status).toBe(400);
  });

  it("uses the router identity as the label when it isn't the default MikroTik", async () => {
    // default identity → no label
    await register("IDN-DEF", 31);
    expect(store.findBySerial("IDN-DEF")!.label).toBeUndefined();
    // custom identity → becomes the label
    await request(app).post("/api/register").send({ token: cfg.auth.provisioningToken, publicKey: fakeKey(32), serialNumber: "IDN-SET", identity: "Reception-AP" });
    expect(store.findBySerial("IDN-SET")!.label).toBe("Reception-AP");
  });

  it("a token carrying a customer + label assigns them on bootstrap", async () => {
    const t = await req("post", "/api/tokens").send({ note: "Smith install", customer: "Smith — Ballarat", label: "Main router" });
    const reg = await register("SMITH-RB1", 11, t.body.token);
    expect(reg.status).toBe(200);
    const r = store.findBySerial("SMITH-RB1")!;
    expect(r.customerGroup).toBe("Smith — Ballarat");
    expect(r.label).toBe("Main router");
    // token records the customer for the listing
    const list = await req("get", "/api/tokens");
    expect(list.body[0].customer).toBe("Smith — Ballarat");
  });

  it("a used one-time token can still fetch bootstrap.rsc (re-run/reflash)", async () => {
    const t = await req("post", "/api/tokens").send({ note: "x" });
    const tok = t.body.token;
    await register("REFL-1", 41, tok); // burns the token
    // Re-fetching the bootstrap script with the now-used token still works...
    const boot = await request(app).get(`/bootstrap.rsc?token=${encodeURIComponent(tok)}`);
    expect(boot.status).toBe(200);
    // ...and re-registering the SAME serial with it succeeds (reflash path).
    expect((await register("REFL-1", 42, tok)).status).toBe(200);
    // but a DIFFERENT device with the used token is still rejected at register.
    expect((await register("REFL-OTHER", 43, tok)).status).toBe(401);
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

describe("on-demand backup", () => {
  it("runs /export over SSH and stores the result", async () => {
    await register("HEXBN", 1);
    const res = await req("post", "/api/routers/HEXBN/backup-now");
    expect(res.status).toBe(200);
    expect(res.body.stored).toBe(true);
    const list = await req("get", "/api/routers/HEXBN/backups");
    expect(list.body).toHaveLength(1);
    // second call with identical output dedupes
    const again = await req("post", "/api/routers/HEXBN/backup-now");
    expect(again.body.stored).toBe(false);
  });

  it("400s for a staged router", async () => {
    await req("post", "/api/prestage").send({ serialNumber: "HEXBS", label: "x" });
    expect((await req("post", "/api/routers/HEXBS/backup-now")).status).toBe(400);
  });
});

describe("password management", () => {
  it("a user can change their own password", async () => {
    users.add("carol", "carolpass1", "tech");
    const login = await request(app).post("/api/login").send({ username: "carol", password: "carolpass1" });
    const auth = `Bearer ${login.body.session}`;
    // wrong current password is rejected
    expect((await req("post", "/api/account/password", auth).send({ current: "nope", next: "brandnew99" })).status).toBe(403);
    // correct current password works
    expect((await req("post", "/api/account/password", auth).send({ current: "carolpass1", next: "brandnew99" })).status).toBe(200);
    // old password no longer logs in; new one does
    expect((await request(app).post("/api/login").send({ username: "carol", password: "carolpass1" })).status).toBe(401);
    expect((await request(app).post("/api/login").send({ username: "carol", password: "brandnew99" })).status).toBe(200);
  });

  it("the admin-token login has no password to change", async () => {
    const res = await req("post", "/api/account/password").send({ current: "x", next: "yyyyyyyy" });
    expect(res.status).toBe(400);
  });

  it("admin resets another user's password and ends their sessions", async () => {
    users.add("dave", "davepass1", "tech");
    const login = await request(app).post("/api/login").send({ username: "dave", password: "davepass1" });
    const daveAuth = `Bearer ${login.body.session}`;
    expect((await req("get", "/api/me", daveAuth)).status).toBe(200);

    const reset = await req("post", "/api/users/dave/password").send({});
    expect(reset.status).toBe(200);
    expect(reset.body.password).toHaveLength(16);
    // dave's old session is now dead
    expect((await req("get", "/api/me", daveAuth)).status).toBe(401);
    // and the new password logs in
    expect((await request(app).post("/api/login").send({ username: "dave", password: reset.body.password })).status).toBe(200);
  });

  it("admin can set a chosen password instead of generating one", async () => {
    users.add("frank", "frankpass1", "tech");
    const reset = await req("post", "/api/users/frank/password").send({ password: "chosenPw123" });
    expect(reset.status).toBe(200);
    expect(reset.body.password).toBe("chosenPw123");
    expect((await request(app).post("/api/login").send({ username: "frank", password: "chosenPw123" })).status).toBe(200);
  });

  it("rejects a chosen password that is too short", async () => {
    users.add("grace", "gracepass1", "tech");
    const reset = await req("post", "/api/users/grace/password").send({ password: "short" });
    expect(reset.status).toBe(400);
    // the old password still works since the reset was rejected
    expect((await request(app).post("/api/login").send({ username: "grace", password: "gracepass1" })).status).toBe(200);
  });

  it("admin can create a user with a chosen password", async () => {
    const created = await req("post", "/api/users").send({ username: "heidi", role: "tech", password: "createdPw123" });
    expect(created.status).toBe(200);
    expect(created.body.password).toBe("createdPw123");
    expect((await request(app).post("/api/login").send({ username: "heidi", password: "createdPw123" })).status).toBe(200);
  });

  it("password reset is admin-only", async () => {
    users.add("erin", "erinpass1", "tech");
    const login = await request(app).post("/api/login").send({ username: "erin", password: "erinpass1" });
    expect((await req("post", "/api/users/erin/password", `Bearer ${login.body.session}`).send({})).status).toBe(403);
  });
});

describe("remove router (two-step delete)", () => {
  it("refuses to remove a router that isn't revoked, then removes it after revoke", async () => {
    await register("DEL1", 1);
    // not revoked → 409
    expect((await req("delete", "/api/routers/DEL1")).status).toBe(409);
    expect(store.findBySerial("DEL1")).toBeDefined();

    await req("post", "/api/routers/DEL1/revoke");
    const del = await req("delete", "/api/routers/DEL1");
    expect(del.status).toBe(200);
    expect(store.findBySerial("DEL1")).toBeUndefined();
  });

  it("delete is admin-only and 404s for unknown routers", async () => {
    await register("DEL2", 2);
    await req("post", "/api/routers/DEL2/revoke");
    users.add("techd", "techpass1", "tech");
    const login = await request(app).post("/api/login").send({ username: "techd", password: "techpass1" });
    expect((await req("delete", "/api/routers/DEL2", `Bearer ${login.body.session}`)).status).toBe(403);
    expect((await req("delete", "/api/routers/NOPE")).status).toBe(404);
  });
});

describe("status board: issues, events, monitoring settings", () => {
  it("PATCH monitoring sets device type + rules and resets baseline", async () => {
    await register("MON1", 1);
    const res = await req("patch", "/api/routers/MON1/monitoring")
      .send({ deviceType: "infrastructure", enabled: true, alertOnLogin: true, alertOnLinkDown: true });
    expect(res.status).toBe(200);
    expect(res.body.deviceType).toBe("infrastructure");
    const r = store.findBySerial("MON1")!;
    expect(r.monitoring!.enabled).toBe(true);
    expect(r.monState!.initialised).toBe(false); // baseline reset
  });

  it("new routers get customer monitoring by default", async () => {
    await register("MON2", 2);
    const r = store.findBySerial("MON2")!;
    expect(r.deviceType).toBe("customer");
    expect(r.monitoring!.enabled).toBe(true);
  });

  it("lists issues with counts and supports ack/resolve", async () => {
    // seed an issue directly through the shared store
    issuesStore.open("MON3", "MON3", "offline", "critical", "down");
    const list = await req("get", "/api/issues");
    expect(list.body.counts.critical).toBe(1);
    const id = list.body.issues[0].id;
    expect((await req("post", `/api/issues/${id}/ack`)).status).toBe(200);
    expect((await req("post", `/api/issues/${id}/resolve`)).status).toBe(200);
    expect((await req("get", "/api/issues")).body.counts.critical).toBe(0);
  });

  it("serves the global and per-router event feed", async () => {
    eventsStore.add({ at: new Date().toISOString(), serialNumber: "MON4", label: "MON4", type: "login", severity: "info", message: "user admin logged in via ssh" });
    await register("MON4", 4);
    expect((await req("get", "/api/events")).body.length).toBeGreaterThan(0);
    const per = await req("get", "/api/routers/MON4/events");
    expect(per.body.some((e: any) => e.type === "login")).toBe(true);
  });

  it("returns interfaces for the port map with the watched list", async () => {
    await register("PORTS1", 7);
    await req("patch", "/api/routers/PORTS1/monitoring").send({ watchInterfaces: ["ether1"] });
    const res = await req("get", "/api/routers/PORTS1/interfaces");
    expect(res.status).toBe(200);
    expect(res.body.interfaces.map((i: any) => i.name)).toEqual(["ether1", "sfp1"]);
    expect(res.body.watched).toEqual(["ether1"]);
  });

  it("monitoring PATCH is admin-only", async () => {
    await register("MON5", 5);
    users.add("techm", "techpass1", "tech");
    const login = await request(app).post("/api/login").send({ username: "techm", password: "techpass1" });
    expect((await req("patch", "/api/routers/MON5/monitoring", `Bearer ${login.body.session}`).send({ enabled: false })).status).toBe(403);
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
