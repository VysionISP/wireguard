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

describe("one-liner", () => {
  it("fetches and imports the bootstrap script", () => {
    const line = renderOneLiner(cfg);
    expect(line).toContain("/tool fetch");
    expect(line).toContain("bootstrap.rsc?token=");
    expect(line).toContain("/import bootstrap.rsc");
  });
});
