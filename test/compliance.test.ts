import { describe, expect, it } from "vitest";
import request from "supertest";
import { evaluateCompliance, remediationCommands, type ComplianceBaseline } from "../src/compliance.js";
import type { ComplianceState } from "../src/routeros.js";
import { buildApp } from "../src/server.js";
import { RouterStore } from "../src/store.js";
import { DryRunManager } from "../src/wireguard.js";
import { fakeKey, testConfig } from "./helpers.js";

const BASELINE: ComplianceBaseline = {
  disableServices: ["telnet", "ftp"],
  dns: ["1.1.1.1", "8.8.8.8"],
  ntpServers: ["time.cloudflare.com"],
  identityPrefix: "VY",
  mgmtFirewallComment: "managed: wg-provision allow mgmt",
};

function goodState(): ComplianceState {
  return {
    identity: "VY-HGR12345",
    services: [
      { name: "telnet", disabled: true }, { name: "ftp", disabled: true },
      { name: "ssh", disabled: false }, { name: "www", disabled: false },
    ],
    dnsServers: ["1.1.1.1", "8.8.8.8"],
    ntpEnabled: true,
    ntpServers: ["time.cloudflare.com"],
    firewallComments: ["managed: wg-provision allow mgmt", "drop everything else"],
  };
}

describe("evaluateCompliance", () => {
  it("passes a fully-compliant device", () => {
    const r = evaluateCompliance(goodState(), BASELINE, "t");
    expect(r.ok).toBe(true);
    expect(r.failCount).toBe(0);
    expect(r.rules.map((x) => x.key).sort()).toEqual(["dns", "identity", "mgmt-firewall", "ntp", "services"]);
  });

  it("flags every kind of drift", () => {
    const s = goodState();
    s.services = [{ name: "telnet", disabled: false }, { name: "ftp", disabled: true }];
    s.dnsServers = ["1.1.1.1"]; // missing 8.8.8.8
    s.ntpEnabled = false;
    s.identity = "MikroTik";
    s.firewallComments = ["drop everything else"]; // mgmt rule gone
    const r = evaluateCompliance(s, BASELINE, "t");
    expect(r.ok).toBe(false);
    const fail = (k: string) => r.rules.find((x) => x.key === k)!;
    expect(fail("services").ok).toBe(false);
    expect(fail("services").detail).toContain("telnet");
    expect(fail("dns").ok).toBe(false);
    expect(fail("dns").detail).toContain("8.8.8.8");
    expect(fail("ntp").ok).toBe(false);
    expect(fail("identity").ok).toBe(false);
    expect(fail("identity").fixable).toBe(true); // factory default is auto-nameable
    expect(fail("mgmt-firewall").ok).toBe(false);
    expect(fail("mgmt-firewall").fixable).toBe(false);
  });

  it("does not offer to rename a deliberately-set (non-factory) identity", () => {
    const s = goodState();
    s.identity = "core-router-7"; // custom, wrong prefix
    const r = evaluateCompliance(s, BASELINE, "t");
    const id = r.rules.find((x) => x.key === "identity")!;
    expect(id.ok).toBe(false);
    expect(id.fixable).toBe(false);
  });

  it("only checks rules the baseline specifies", () => {
    const empty: ComplianceBaseline = { disableServices: [], dns: [], ntpServers: [], identityPrefix: "" };
    const r = evaluateCompliance(goodState(), empty, "t");
    // Only the always-on management firewall rule remains.
    expect(r.rules.map((x) => x.key)).toEqual(["mgmt-firewall"]);
  });
});

describe("remediationCommands", () => {
  it("emits fix commands only for failed, fixable rules", () => {
    const s = goodState();
    s.services = [{ name: "telnet", disabled: false }, { name: "ftp", disabled: true }];
    s.dnsServers = [];
    s.identity = "MikroTik";
    const r = evaluateCompliance(s, BASELINE, "t");
    const cmds = remediationCommands(r, BASELINE, "HGR12345");
    expect(cmds.some((c) => c.includes('/ip/service/disable') && c.includes("telnet"))).toBe(true);
    expect(cmds.some((c) => c.includes("/ip/dns/set servers=1.1.1.1,8.8.8.8"))).toBe(true);
    expect(cmds.some((c) => c.includes('/system/identity/set name="VY-HGR12345"'))).toBe(true);
    // NTP was fine, so no NTP commands.
    expect(cmds.some((c) => c.includes("ntp"))).toBe(false);
  });
});

describe("compliance API", () => {
  function makeApp(state: ComplianceState) {
    const cfg = testConfig();
    // Wire the baseline into the test config's hardening block.
    cfg.hardening = { disableServices: ["telnet", "ftp"], dns: ["1.1.1.1"], ntpServers: ["pool.ntp.org"], identityPrefix: "VY" } as any;
    const store = new RouterStore(cfg.storePath);
    const calls: string[] = [];
    const application = buildApp({
      config: cfg, store, wg: new DryRunManager("wg0", true),
      fetchCompliance: async () => state,
      sshRun: async (_h, _u, _p, command) => { calls.push(command); return { ok: true, output: "" }; },
    });
    return { app: application, cfg, store, calls };
  }

  it("GET runs a live check, caches it, and the fleet roll-up reflects it", async () => {
    const bad = goodState();
    bad.services = [{ name: "telnet", disabled: false }];
    bad.dnsServers = [];
    const { app, cfg } = makeApp(bad);
    const A = `Bearer ${cfg.auth.adminToken}`;
    await request(app).post("/api/register").send({ token: cfg.auth.provisioningToken, publicKey: fakeKey(1), serialNumber: "HEX1" });
    const chk = await request(app).get("/api/routers/HEX1/compliance").set("authorization", A);
    expect(chk.status).toBe(200);
    expect(chk.body.ok).toBe(false);
    const fleet = await request(app).get("/api/compliance").set("authorization", A);
    expect(fleet.body[0].compliance.failCount).toBeGreaterThan(0);
  });

  it("fix applies remediation and reports the improved result", async () => {
    // A mutable state the fake fetch returns; the fix "repairs" it.
    const state = goodState();
    state.services = [{ name: "telnet", disabled: false }, { name: "ftp", disabled: true }];
    state.dnsServers = [];
    const cfg = testConfig();
    cfg.hardening = { disableServices: ["telnet", "ftp"], dns: ["1.1.1.1"], ntpServers: [], identityPrefix: "" } as any;
    const store = new RouterStore(cfg.storePath);
    const calls: string[] = [];
    const application = buildApp({
      config: cfg, store, wg: new DryRunManager("wg0", true),
      fetchCompliance: async () => state,
      sshRun: async (_h, _u, _p, command) => {
        calls.push(command);
        if (command.includes("service/disable") && command.includes("telnet")) state.services[0].disabled = true;
        if (command.includes("/ip/dns/set")) state.dnsServers = ["1.1.1.1"];
        return { ok: true, output: "" };
      },
    });
    const A = `Bearer ${cfg.auth.adminToken}`;
    await request(application).post("/api/register").send({ token: cfg.auth.provisioningToken, publicKey: fakeKey(1), serialNumber: "HEX1" });
    const fix = await request(application).post("/api/routers/HEX1/compliance/fix").set("authorization", A);
    expect(fix.status).toBe(200);
    expect(fix.body.fixed).toBeGreaterThan(0);
    expect(fix.body.compliance.ok).toBe(true);
    expect(calls.some((c) => c.includes("telnet"))).toBe(true);
  });

  it("compliance check is tech-visible; fix is admin-only", async () => {
    const { app, cfg } = makeApp(goodState());
    await request(app).post("/api/register").send({ token: cfg.auth.provisioningToken, publicKey: fakeKey(1), serialNumber: "HEX1" });
    expect((await request(app).get("/api/routers/HEX1/compliance")).status).toBe(401);
    expect((await request(app).post("/api/routers/HEX1/compliance/fix")).status).toBe(401);
  });
});
