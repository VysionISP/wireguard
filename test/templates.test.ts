import { describe, expect, it } from "vitest";
import { renderBootstrap, renderOneLiner, renderProvision } from "../src/templates.js";
import type { RouterRecord } from "../src/types.js";
import { testConfig } from "./helpers.js";

const cfg = testConfig();

const router: RouterRecord = {
  id: "id-1",
  serialNumber: "HEX123456",
  publicKey: "k".repeat(43) + "=",
  boardName: "hEX",
  rosVersion: "7.15",
  identity: "MikroTik",
  tunnelIp: "10.99.0.7",
  username: "wg-mgmt",
  password: "Passw0rdPassw0rdPassw0rd",
  state: "registered",
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
  lastSeenAt: null,
};

describe("bootstrap script", () => {
  it("creates the wg interface and posts registration to the server", () => {
    const rsc = renderBootstrap(cfg);
    expect(rsc).toContain('/interface/wireguard/add name="wg-mgmt"');
    expect(rsc).toContain("https://provision.test/api/register");
    expect(rsc).toContain(cfg.auth.provisioningToken);
    expect(rsc).toContain("/import file-name=wg-provision.rsc");
    // RouterOS variables must survive TS template interpolation
    expect(rsc).toContain("http-data=$body");
    expect(rsc).toContain(":local pubkey");
  });
});

describe("provision script", () => {
  it("contains the peer, address, user and confirm call", () => {
    const rsc = renderProvision(cfg, router);
    expect(rsc).toContain(`public-key="${cfg.wireguard.serverPublicKey}"`);
    expect(rsc).toContain('endpoint-address="vpn.test"');
    expect(rsc).toContain("endpoint-port=51820");
    expect(rsc).toContain("allowed-address=10.99.0.0/24");
    expect(rsc).toContain("persistent-keepalive=25s");
    expect(rsc).toContain("address=10.99.0.7/24");
    expect(rsc).toContain(`password="${router.password}"`);
    expect(rsc).toContain("https://provision.test/api/confirm");
    expect(rsc).toContain('src-address=10.99.0.0/24 action=accept');
  });

  it("omits keepalive when disabled", () => {
    const noKeepalive = testConfig();
    noKeepalive.wireguard.persistentKeepalive = 0;
    expect(renderProvision(noKeepalive, router)).not.toContain("persistent-keepalive");
  });

  it("escapes RouterOS string metacharacters in interpolated values", () => {
    const nasty = { ...router, password: 'p"w$va\\lue' };
    const rsc = renderProvision(cfg, nasty);
    expect(rsc).toContain('password="p\\"w\\$va\\\\lue"');
  });
});

describe("hardening options", () => {
  it("renders dns, ntp and identity naming when configured", () => {
    const c = testConfig();
    c.hardening.dns = ["1.1.1.1", "8.8.8.8"];
    c.hardening.ntpServers = ["time.cloudflare.com"];
    c.hardening.identityPrefix = "vysion";
    const rsc = renderProvision(c, router);
    expect(rsc).toContain("/ip/dns/set servers=1.1.1.1,8.8.8.8");
    expect(rsc).toContain('/system/ntp/client/servers/add address="time.cloudflare.com"');
    expect(rsc).toContain('/system/identity/set name="vysion-HEX123456"');
    expect(rsc).toContain('= "MikroTik") do={'); // only renames factory-default identities
  });

  it("never disables required services even if configured to", () => {
    const c = testConfig();
    c.hardening.disableServices = ["telnet", "ssh", "www", "api"];
    const rsc = renderProvision(c, router);
    expect(rsc).toContain('/ip/service/disable [find name="telnet"]');
    expect(rsc).not.toContain('/ip/service/disable [find name="ssh"]');
    expect(rsc).not.toContain('/ip/service/disable [find name="www"]');
    expect(rsc).not.toContain('/ip/service/disable [find name="api"]');
  });

  it("omits the backup block when disabled", () => {
    const c = testConfig();
    c.backup.enabled = false;
    expect(renderProvision(c, router)).not.toContain("wg-provision-backup");
  });

  it("formats sub-day backup intervals in hours", () => {
    const c = testConfig();
    c.backup.intervalHours = 12;
    expect(renderProvision(c, router)).toContain("interval=12h");
  });
});

describe("one-liner", () => {
  it("fetches and imports the bootstrap script", () => {
    const line = renderOneLiner(cfg);
    expect(line).toContain("/tool fetch");
    expect(line).toContain("bootstrap.rsc?token=");
    expect(line).toContain("/import bootstrap.rsc");
  });
});
