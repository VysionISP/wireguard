#!/usr/bin/env node
import { Command } from "commander";
import { loadConfig, type Config } from "./config.js";
import { RouterStore } from "./store.js";
import { buildApp } from "./server.js";
import { DryRunManager, WgCommandManager, type WireguardManager } from "./wireguard.js";
import { renderBootstrap, renderOneLiner } from "./templates.js";
import { fetchRouterInfo } from "./routeros.js";
import { syncPeers } from "./sync.js";

function makeWg(config: Config): WireguardManager {
  return config.wireguard.applyMode === "wg"
    ? new WgCommandManager(config.wireguard.interface)
    : new DryRunManager(config.wireguard.interface);
}

function open(configPath?: string): { config: Config; store: RouterStore; wg: WireguardManager } {
  const config = loadConfig(configPath);
  return { config, store: new RouterStore(config.storePath), wg: makeWg(config) };
}

const program = new Command();
program
  .name("mtprov")
  .description("Zero-touch WireGuard auto-provisioning for MikroTik routers")
  .option("-c, --config <path>", "path to config.json");

program
  .command("serve")
  .description("run the provisioning server")
  .action(async () => {
    const { config, store, wg } = open(program.opts().config);
    // Peers added with `wg set` don't survive an interface/host restart, so
    // re-apply the whole inventory before accepting traffic.
    const { applied, failed } = await syncPeers(store, wg);
    if (applied || failed) console.log(`peer sync: ${applied} applied, ${failed} failed`);
    const app = buildApp({ config, store, wg });
    app.listen(config.server.port, config.server.host, () => {
      console.log(
        `provisioning server listening on ${config.server.host}:${config.server.port} (public: ${config.server.publicUrl})`,
      );
      console.log(`wireguard apply mode: ${config.wireguard.applyMode}`);
    });
  });

program
  .command("bootstrap")
  .description("print the bootstrap script and the one-liner for techs")
  .option("--script", "print the full bootstrap.rsc instead of the one-liner")
  .action((opts: { script?: boolean }) => {
    const { config } = open(program.opts().config);
    if (opts.script) {
      console.log(renderBootstrap(config));
    } else {
      console.log("Run this on a factory-fresh RouterOS v7 device:\n");
      console.log(`  ${renderOneLiner(config)}\n`);
    }
  });

program
  .command("list")
  .description("list registered routers")
  .action(() => {
    const { store } = open(program.opts().config);
    const routers = store.list();
    if (routers.length === 0) {
      console.log("no routers registered yet");
      return;
    }
    console.table(
      routers.map((r) => ({
        serial: r.serialNumber,
        board: r.boardName,
        identity: r.identity,
        tunnelIp: r.tunnelIp,
        state: r.state,
        lastSeen: r.lastSeenAt ?? "-",
      })),
    );
  });

program
  .command("show <ref>")
  .description("show full details (including credentials) for a router by id, serial or tunnel IP")
  .action((ref: string) => {
    const { store } = open(program.opts().config);
    const router = store.find(ref);
    if (!router) {
      console.error(`no router matching "${ref}"`);
      process.exitCode = 1;
      return;
    }
    console.log(JSON.stringify(router, null, 2));
    console.log(`\nssh: ssh ${router.username}@${router.tunnelIp}`);
    console.log(`rest: http://${router.tunnelIp}/rest/  (basic auth)`);
  });

program
  .command("verify <ref>")
  .description("check tunnel handshake and query the router over REST")
  .action(async (ref: string) => {
    const { config, store, wg } = open(program.opts().config);
    const router = store.find(ref);
    if (!router) {
      console.error(`no router matching "${ref}"`);
      process.exitCode = 1;
      return;
    }
    const handshake = await wg.latestHandshake(router.publicKey).catch(() => null);
    console.log(
      handshake === null
        ? "handshake: none recorded"
        : `handshake: ${handshake}s ago`,
    );
    try {
      const info = await fetchRouterInfo(router.tunnelIp, router.username, router.password);
      console.log(`reachable: yes — ${info.identity} (${info.boardName}, ROS ${info.version}, up ${info.uptime})`);
      router.state = "verified";
      router.lastSeenAt = new Date().toISOString();
      router.updatedAt = router.lastSeenAt;
      store.save(router);
    } catch (err) {
      console.error(`reachable: no — ${(err as Error).message}`);
      process.exitCode = 1;
    }
  });

program
  .command("sync")
  .description("re-apply all non-revoked peers to the WireGuard interface (after restarts)")
  .action(async () => {
    const { store, wg } = open(program.opts().config);
    const { applied, failed } = await syncPeers(store, wg);
    console.log(`peer sync: ${applied} applied, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
  });

program
  .command("revoke <ref>")
  .description("remove the router's WireGuard peer and block re-registration")
  .action(async (ref: string) => {
    const { store, wg } = open(program.opts().config);
    const router = store.find(ref);
    if (!router) {
      console.error(`no router matching "${ref}"`);
      process.exitCode = 1;
      return;
    }
    await wg.removePeer(router.publicKey).catch((err: Error) => {
      console.warn(`peer removal: ${err.message} (continuing)`);
    });
    router.state = "revoked";
    router.updatedAt = new Date().toISOString();
    store.save(router);
    console.log(`revoked ${router.serialNumber} (${router.tunnelIp})`);
  });

program.parseAsync().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
