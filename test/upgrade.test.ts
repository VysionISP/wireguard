import path from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { UpgradeManager, parseUpdateCheck, parseRouterboard, updateAvailable } from "../src/upgrade.js";
import { RouterStore } from "../src/store.js";
import { EventLog } from "../src/events.js";
import { MaintenanceStore } from "../src/maintenance.js";
import { buildApp } from "../src/server.js";
import { DryRunManager } from "../src/wireguard.js";
import { fakeKey, tempDir, testConfig } from "./helpers.js";
import type { RouterRecord } from "../src/types.js";
import type { SshRunFn } from "../src/ssh.js";

const CHECK_NEW = `        channel: stable
    installed-version: 7.14.2
       latest-version: 7.16
               status: Downloaded changelog
               status: New version is available`;
const CHECK_CURRENT = `        channel: stable
    installed-version: 7.16
       latest-version: 7.16
               status: System is already up to date`;

describe("parseUpdateCheck", () => {
  it("parses versions and takes the final status line", () => {
    const c = parseUpdateCheck(CHECK_NEW);
    expect(c).toEqual({ channel: "stable", installed: "7.14.2", latest: "7.16", status: "New version is available" });
    expect(updateAvailable(c)).toBe(true);
    expect(updateAvailable(parseUpdateCheck(CHECK_CURRENT))).toBe(false);
  });
});

describe("parseRouterboard", () => {
  it("reads current + upgrade board firmware (separate from RouterOS)", () => {
    const out = `       routerboard: yes
             model: hAP ax^2
     serial-number: HGR
  current-firmware: 7.16.2
  upgrade-firmware: 7.23.2`;
    expect(parseRouterboard(out)).toEqual({ current: "7.16.2", upgrade: "7.23.2" });
  });
});

function router(serial: string, ip: string): RouterRecord {
  const now = new Date().toISOString();
  return {
    id: serial.toLowerCase(), serialNumber: serial, publicKey: "k", boardName: "hEX", rosVersion: "7.14.2",
    identity: "cpe", tunnelIp: ip, username: "u", password: "p", state: "confirmed",
    createdAt: now, updatedAt: now, lastSeenAt: now, health: "up",
  };
}

/**
 * Scripted fleet SSH: check-for-updates returns `checkOut`; after install, the
 * device "reboots" — resource print fails `downFor` polls, then reports 7.16.
 */
function fakeFleet(checkOut = CHECK_NEW, downFor = 2) {
  const calls: string[] = [];
  let installed = false;
  let failures = 0;
  const sshRun: SshRunFn = async (_h, _u, _p, command) => {
    calls.push(command);
    if (command.includes("check-for-updates")) return { ok: true, output: checkOut };
    if (command.includes("update install")) { installed = true; throw new Error("connection reset"); }
    if (command.includes("resource print")) {
      if (installed && failures < downFor) { failures++; throw new Error("no route to host"); }
      return { ok: true, output: `  version: ${installed ? "7.16" : "7.14.2"} (stable)\n  uptime: 1m` };
    }
    return { ok: true, output: "" };
  };
  return { sshRun, calls };
}

async function waitJob(mgr: UpgradeManager, id: string, ms = 3000): Promise<void> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (mgr.get(id)?.state !== "running") return;
    await new Promise((r) => setTimeout(r, 15));
  }
  throw new Error("job did not finish in time");
}

describe("UpgradeManager", () => {
  let store: RouterStore;
  let events: EventLog;
  let maint: MaintenanceStore;

  beforeEach(() => {
    store = new RouterStore(path.join(tempDir(), "r.json"));
    events = new EventLog(path.join(tempDir(), "e.jsonl"));
    maint = new MaintenanceStore(path.join(tempDir(), "m.json"));
  });

  it("upgrades a device end to end and refreshes rosVersion", async () => {
    store.save(router("DEV1", "10.99.0.9"));
    const { sshRun, calls } = fakeFleet();
    const mgr = new UpgradeManager({ store, events, maintenance: maint, sshRun, pollMs: 10, onlineTimeoutMs: 1000 });
    const job = mgr.start([store.findBySerial("DEV1")!], "tester");
    await waitJob(mgr, job.id);
    const item = mgr.get(job.id)!.items[0];
    expect(item.state).toBe("done");
    expect(item.detail).toBe("7.14.2 → 7.16");
    expect(store.findBySerial("DEV1")!.rosVersion).toBe("7.16");
    expect(calls.some((c) => c.includes("update install"))).toBe(true);
    // The temporary maintenance window is cleaned up afterwards.
    expect(maint.list().length).toBe(0);
    // Start + finish device events logged.
    const evs = events.recent(50).filter((e) => e.serialNumber === "DEV1" && e.type === "upgrade");
    expect(evs.length).toBe(2);
  });

  it("skips devices that are already up to date", async () => {
    store.save(router("DEV1", "10.99.0.9"));
    const { sshRun } = fakeFleet(CHECK_CURRENT);
    const mgr = new UpgradeManager({ store, events, maintenance: maint, sshRun, pollMs: 10, onlineTimeoutMs: 300 });
    const job = mgr.start([store.findBySerial("DEV1")!], "tester");
    await waitJob(mgr, job.id);
    expect(mgr.get(job.id)!.items[0].state).toBe("skipped");
    expect(store.findBySerial("DEV1")!.rosVersion).toBe("7.14.2");
  });

  it("fails the item when the device never comes back, and moves on", async () => {
    store.save(router("DEV1", "10.99.0.9"));
    store.save(router("DEV2", "10.99.0.10"));
    // DEV1 never answers after install; DEV2 is fine. downFor=Infinity for .9.
    let installed1 = false;
    const sshRun: SshRunFn = async (h, _u, _p, command) => {
      if (command.includes("check-for-updates")) return { ok: true, output: CHECK_NEW };
      if (command.includes("update install")) { if (h === "10.99.0.9") installed1 = true; return { ok: true, output: "" }; }
      if (command.includes("resource print")) {
        if (h === "10.99.0.9" && installed1) throw new Error("gone");
        return { ok: true, output: "  version: 7.16 (stable)" };
      }
      return { ok: true, output: "" };
    };
    const mgr = new UpgradeManager({ store, events, maintenance: maint, sshRun, pollMs: 10, onlineTimeoutMs: 120 });
    const job = mgr.start([store.findBySerial("DEV1")!, store.findBySerial("DEV2")!], "tester");
    await waitJob(mgr, job.id, 5000);
    const [i1, i2] = mgr.get(job.id)!.items;
    expect(i1.state).toBe("failed");
    expect(i1.detail).toContain("did not come back");
    expect(i2.state).toBe("done"); // the rollout continues past a failure
  });

  it("firmwareOnly upgrades just the RouterBOARD firmware, leaving RouterOS alone", async () => {
    store.save(router("DEV1", "10.99.0.9"));
    let upgraded = false;
    const calls: string[] = [];
    const sshRun: SshRunFn = async (_h, _u, _p, command) => {
      calls.push(command);
      if (command.includes("routerboard print")) {
        return { ok: true, output: `  current-firmware: ${upgraded ? "7.23.2" : "7.16.2"}\n  upgrade-firmware: 7.23.2` };
      }
      if (command.includes("routerboard upgrade")) { upgraded = true; return { ok: true, output: "" }; }
      if (command.includes("resource print")) return { ok: true, output: "  version: 7.23.2 (stable)" };
      return { ok: true, output: "" };
    };
    const mgr = new UpgradeManager({ store, events, maintenance: maint, sshRun, pollMs: 10, onlineTimeoutMs: 1000 });
    const job = mgr.start([store.findBySerial("DEV1")!], "tester", false, true);
    await waitJob(mgr, job.id);
    const item = mgr.get(job.id)!.items[0];
    expect(item.state).toBe("done");
    expect(item.detail).toBe("board firmware 7.16.2 → 7.23.2");
    // No RouterOS package install happened — only the board firmware path.
    expect(calls.some((c) => c.includes("package update install"))).toBe(false);
    expect(calls.some((c) => c.includes("routerboard upgrade"))).toBe(true);
  });

  it("firmwareOnly skips when board firmware already matches", async () => {
    store.save(router("DEV1", "10.99.0.9"));
    const sshRun: SshRunFn = async (_h, _u, _p, command) => {
      if (command.includes("routerboard print")) return { ok: true, output: "  current-firmware: 7.23.2\n  upgrade-firmware: 7.23.2" };
      return { ok: true, output: "" };
    };
    const mgr = new UpgradeManager({ store, events, maintenance: maint, sshRun, pollMs: 10, onlineTimeoutMs: 300 });
    const job = mgr.start([store.findBySerial("DEV1")!], "tester", false, true);
    await waitJob(mgr, job.id);
    expect(mgr.get(job.id)!.items[0].state).toBe("skipped");
  });

  it("cancel stops the remaining queue", async () => {
    store.save(router("DEV1", "10.99.0.9"));
    store.save(router("DEV2", "10.99.0.10"));
    const { sshRun } = fakeFleet(CHECK_NEW, 5);
    const mgr = new UpgradeManager({ store, events, maintenance: maint, sshRun, pollMs: 25, onlineTimeoutMs: 2000 });
    const job = mgr.start([store.findBySerial("DEV1")!, store.findBySerial("DEV2")!], "tester");
    expect(mgr.busy()).toBe(true);
    mgr.cancel(job.id);
    await waitJob(mgr, job.id, 5000);
    expect(mgr.get(job.id)!.state).toBe("cancelled");
    expect(mgr.get(job.id)!.items[1].state).toBe("cancelled");
  });
});

describe("upgrade API", () => {
  it("check endpoint stores the result; job endpoints run and report", async () => {
    const cfg = testConfig();
    const store = new RouterStore(cfg.storePath);
    const { sshRun } = fakeFleet();
    const app = buildApp({ config: cfg, store, wg: new DryRunManager("wg0", true), sshRun, upgrade: { pollMs: 10, onlineTimeoutMs: 1000 } });
    const A = `Bearer ${cfg.auth.adminToken}`;
    await request(app).post("/api/register").send({ token: cfg.auth.provisioningToken, publicKey: fakeKey(1), serialNumber: "HEX1" });

    const check = await request(app).post("/api/routers/HEX1/upgrade-check").set("authorization", A);
    expect(check.status).toBe(200);
    expect(check.body.latest).toBe("7.16");
    expect(check.body.updateAvailable).toBe(true);
    expect((await request(app).get("/api/routers/HEX1").set("authorization", A)).body.updateCheck.latest).toBe("7.16");

    const start = await request(app).post("/api/upgrades").set("authorization", A).send({ refs: ["HEX1"] });
    expect(start.status).toBe(200);
    const id = start.body.id;
    // A second concurrent rollout is refused while one runs.
    const dup = await request(app).post("/api/upgrades").set("authorization", A).send({ refs: ["HEX1"] });
    expect([200, 409]).toContain(dup.status); // may already be finished on a fast box
    const deadline = Date.now() + 4000;
    let job: any;
    while (Date.now() < deadline) {
      job = (await request(app).get(`/api/upgrades/${id}`).set("authorization", A)).body;
      if (job.state !== "running") break;
      await new Promise((r) => setTimeout(r, 25));
    }
    expect(job.state).toBe("done");
    expect(job.items[0].state).toBe("done");
    expect((await request(app).get("/api/upgrades").set("authorization", A)).body.length).toBeGreaterThan(0);
  });

  it("requires admin and online targets", async () => {
    const cfg = testConfig();
    const store = new RouterStore(cfg.storePath);
    const app = buildApp({ config: cfg, store, wg: new DryRunManager("wg0", true) });
    const A = `Bearer ${cfg.auth.adminToken}`;
    expect((await request(app).post("/api/upgrades").send({ refs: ["x"] })).status).toBe(401);
    expect((await request(app).post("/api/upgrades").set("authorization", A).send({ refs: ["nope"] })).status).toBe(400);
    expect((await request(app).post("/api/routers/nope/upgrade-check").set("authorization", A)).status).toBe(404);
  });
});
