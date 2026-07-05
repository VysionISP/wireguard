import path from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { buildApp } from "../src/server.js";
import { RouterStore } from "../src/store.js";
import { BackupStore } from "../src/backups.js";
import { DryRunManager } from "../src/wireguard.js";
import { fakeKey, tempDir, testConfig } from "./helpers.js";
import type { Config } from "../src/config.js";

let cfg: Config;
let store: RouterStore;
let app: ReturnType<typeof buildApp>;

beforeEach(async () => {
  cfg = testConfig();
  store = new RouterStore(cfg.storePath);
  const wg = new DryRunManager(cfg.wireguard.interface, true);
  const backups = new BackupStore(path.join(tempDir(), "backups"), 5);
  app = buildApp({ config: cfg, store, wg, backups });
  await request(app).post("/api/register").send({
    token: cfg.auth.provisioningToken,
    publicKey: fakeKey(1),
    serialNumber: "HEX0001",
  });
});

function admin(method: "get" | "post" | "patch", path: string) {
  return request(app)[method](path).set("authorization", `Bearer ${cfg.auth.adminToken}`);
}

describe("labels & notes", () => {
  it("PATCH sets label and notes, visible in list and details", async () => {
    const res = await admin("patch", "/api/routers/HEX0001")
      .send({ label: "Smith residence", notes: "roof mount" });
    expect(res.status).toBe(200);

    const list = await admin("get", "/api/routers");
    expect(list.body[0].label).toBe("Smith residence");
    expect(list.body[0].notes).toBe("roof mount");
  });

  it("PATCH requires admin auth and an existing router", async () => {
    expect((await request(app).patch("/api/routers/HEX0001").send({ label: "x" })).status).toBe(401);
    expect((await admin("patch", "/api/routers/NOPE").send({ label: "x" })).status).toBe(404);
  });

  it("rejects oversized labels", async () => {
    const res = await admin("patch", "/api/routers/HEX0001").send({ label: "x".repeat(200) });
    expect(res.status).toBe(400);
  });
});

describe("router-pushed backups", () => {
  function push(serial: string, body: string, token = cfg.auth.provisioningToken) {
    return request(app)
      .post(`/api/backup?token=${encodeURIComponent(token)}&serial=${encodeURIComponent(serial)}`)
      .set("content-type", "application/octet-stream")
      .send(Buffer.from(body));
  }

  it("stores a backup and records lastBackupAt", async () => {
    const res = await push("HEX0001", "# export v1");
    expect(res.status).toBe(200);
    expect(res.body.stored).toBe(true);
    expect(store.findBySerial("HEX0001")!.lastBackupAt).toBeTruthy();

    const list = await admin("get", "/api/routers/HEX0001/backups");
    expect(list.body).toHaveLength(1);

    const dl = await admin("get", `/api/routers/HEX0001/backups/${list.body[0].name}`);
    expect(dl.status).toBe(200);
    expect(dl.text).toBe("# export v1");
  });

  it("deduplicates unchanged content", async () => {
    await push("HEX0001", "# export v1");
    const res = await push("HEX0001", "# export v1");
    expect(res.body.stored).toBe(false);
    const list = await admin("get", "/api/routers/HEX0001/backups");
    expect(list.body).toHaveLength(1);
  });

  it("rejects bad tokens, unknown serials and empty bodies", async () => {
    expect((await push("HEX0001", "# x", "wrong")).status).toBe(401);
    expect((await push("NOPE", "# x")).status).toBe(404);
    expect((await push("HEX0001", "")).status).toBe(400);
  });

  it("backup listing requires admin auth", async () => {
    expect((await request(app).get("/api/routers/HEX0001/backups")).status).toBe(401);
  });
});

describe("hardening & backup blocks in the provision script", () => {
  it("includes defaults: telnet/ftp disabled and the backup scheduler", async () => {
    const res = await request(app).post("/api/register").send({
      token: cfg.auth.provisioningToken,
      publicKey: fakeKey(5),
      serialNumber: "HEX0005",
    });
    expect(res.text).toContain('/ip/service/disable [find name="telnet"]');
    expect(res.text).toContain('/ip/service/disable [find name="ftp"]');
    expect(res.text).toContain('/system/scheduler/add name="wg-provision-backup" interval=1d');
    expect(res.text).toContain("/api/backup?token=");
    expect(res.text).toContain("serial=HEX0005");
    // never disable the services the tool depends on
    expect(res.text).not.toContain('disable [find name="ssh"]');
  });
});
