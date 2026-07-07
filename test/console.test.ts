import { describe, expect, it } from "vitest";
import request from "supertest";
import { EventEmitter } from "node:events";
import { ConsoleManager } from "../src/console.js";
import { buildApp } from "../src/server.js";
import { RouterStore } from "../src/store.js";
import { DryRunManager } from "../src/wireguard.js";
import { fakeKey, testConfig } from "./helpers.js";
import type { ShellSession, SshShellFn } from "../src/ssh.js";

/** A scripted PTY: echoes writes back as output, records everything. */
function fakeShell() {
  const ev = new EventEmitter();
  const writes: string[] = [];
  let closed = false;
  const session: ShellSession = {
    write: (d) => {
      writes.push(d);
      ev.emit("data", Buffer.from("echo:" + d));
    },
    resize: () => {},
    close: () => {
      closed = true;
      ev.emit("close");
    },
    onData: (cb) => ev.on("data", cb),
    onClose: (cb) => ev.on("close", cb),
  };
  const fn: SshShellFn = async () => {
    setTimeout(() => ev.emit("data", Buffer.from("[admin@r] > ")), 0);
    return session;
  };
  return { fn, writes, isClosed: () => closed };
}

/** Minimal SSE sink that quacks like an express Response. */
function sseSink() {
  const chunks: string[] = [];
  const ev = new EventEmitter();
  return {
    res: {
      write: (c: string) => { chunks.push(c); return true; },
      end: () => {},
      on: (name: string, cb: () => void) => ev.on(name, cb),
    } as any,
    chunks,
  };
}

describe("ConsoleManager", () => {
  it("opens a session, streams output, replays scrollback to a late subscriber", async () => {
    const { fn, writes } = fakeShell();
    const mgr = new ConsoleManager(fn);
    const sid = await mgr.open("10.99.0.9", "u", "p", "DEV1");
    expect(mgr.serialOf(sid)).toBe("DEV1");
    await new Promise((r) => setTimeout(r, 10)); // banner lands in the buffer

    const a = sseSink();
    expect(mgr.attach(sid, a.res)).toBe(true);
    // Late attach still sees the banner (base64 of "[admin@r] > ").
    expect(a.chunks.join("")).toContain(Buffer.from("[admin@r] > ").toString("base64"));

    expect(mgr.input(sid, "/ip service print\r")).toBe(true);
    expect(writes).toEqual(["/ip service print\r"]);
    expect(a.chunks.join("")).toContain(Buffer.from("echo:/ip service print\r").toString("base64"));
  });

  it("close ends the shell and notifies subscribers; ids become invalid", async () => {
    const { fn, isClosed } = fakeShell();
    const mgr = new ConsoleManager(fn);
    const sid = await mgr.open("10.99.0.9", "u", "p", "DEV1");
    const a = sseSink();
    mgr.attach(sid, a.res);
    expect(mgr.close(sid)).toBe(true);
    expect(isClosed()).toBe(true);
    expect(a.chunks.join("")).toContain('"end"');
    expect(mgr.input(sid, "x")).toBe(false);
    expect(mgr.attach(sid, sseSink().res)).toBe(false);
    expect(mgr.close(sid)).toBe(false);
  });
});

describe("console API", () => {
  function makeApp() {
    const cfg = testConfig();
    const store = new RouterStore(cfg.storePath);
    const { fn, writes } = fakeShell();
    const app = buildApp({ config: cfg, store, wg: new DryRunManager("wg0", true), shell: fn });
    return { app, cfg, writes };
  }

  it("open -> input -> close round trip (admin)", async () => {
    const { app, cfg, writes } = makeApp();
    const A = `Bearer ${cfg.auth.adminToken}`;
    await request(app).post("/api/register").send({ token: cfg.auth.provisioningToken, publicKey: fakeKey(1), serialNumber: "HEX1" });
    const open = await request(app).post("/api/routers/HEX1/console").set("authorization", A).send({ cols: 100, rows: 30 });
    expect(open.status).toBe(200);
    const sid = open.body.sid;
    expect(sid).toBeTruthy();
    const inp = await request(app).post(`/api/console/${sid}/input`).set("authorization", A).send({ data: "ls\r" });
    expect(inp.status).toBe(200);
    expect(writes).toEqual(["ls\r"]);
    expect((await request(app).post(`/api/console/${sid}/resize`).set("authorization", A).send({ cols: 90, rows: 20 })).status).toBe(200);
    expect((await request(app).delete(`/api/console/${sid}`).set("authorization", A)).status).toBe(200);
    expect((await request(app).post(`/api/console/${sid}/input`).set("authorization", A).send({ data: "x" })).status).toBe(404);
  });

  it("requires admin and an online router", async () => {
    const { app, cfg } = makeApp();
    const A = `Bearer ${cfg.auth.adminToken}`;
    expect((await request(app).post("/api/routers/HEX1/console").send({})).status).toBe(401);
    expect((await request(app).post("/api/routers/NOPE/console").set("authorization", A).send({})).status).toBe(404);
    expect((await request(app).get("/api/console/xyz/stream")).status).toBe(401);
    expect((await request(app).get("/api/console/xyz/stream?token=wrong")).status).toBe(401);
  });
});
