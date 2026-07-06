#!/usr/bin/env node
import { Command } from "commander";
import { loadConfig, type Config } from "./config.js";
import { RouterStore } from "./store.js";
import { buildApp } from "./server.js";
import { DryRunManager, WgCommandManager, type WireguardManager } from "./wireguard.js";
import { renderBootstrap, renderOneLiner } from "./templates.js";
import { revokeRouter, verifyRouter } from "./actions.js";
import { syncPeers } from "./sync.js";
import { startMonitor } from "./monitor.js";
import { startLiveness } from "./liveness.js";
import { startDeviceMonitor } from "./devicemonitor.js";
import { MetricsStore, startMetricsSampler } from "./metrics.js";
import { HostStore } from "./hosts.js";
import { startHostMonitor } from "./hostmonitor.js";
import { MaintenanceStore, type MaintCategory } from "./maintenance.js";
import { Alerter } from "./alerts.js";
import { TokenStore } from "./tokens.js";
import { UserStore } from "./users.js";
import { IssueStore } from "./issues.js";
import { EventLog } from "./events.js";
import { SettingsStore } from "./settings.js";

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
    const settings = new SettingsStore(config.settingsPath);
    const alerter = new Alerter(config.alerts, null, settings);
    const issues = new IssueStore(config.issuesPath);
    const events = new EventLog(config.eventsPath);
    const metrics = new MetricsStore(config.metricsPath, config.metrics.retentionDays * 24 * 3600_000);
    const hosts = new HostStore(config.hostsPath);
    const maintenance = new MaintenanceStore(config.maintenancePath);
    // The monitors pass a coarse category ("offline"/"link"/"host"/"login").
    const suppressed = (serial: string, group: string | undefined, category: string) =>
      maintenance.suppressed(serial, group, category as MaintCategory);
    const app = buildApp({ config, store, wg, alerter, issues, events, settings, metrics, hosts, maintenance });
    if (config.liveness.enabled) {
      // Active ping owns online/warning/offline; run the handshake monitor only
      // for handshake-age bookkeeping (no offline issues, to avoid duplicates).
      startLiveness(
        {
          store, issues, events, alerter,
          warnAfterSeconds: config.liveness.warnAfterSeconds,
          offlineAfterSeconds: config.liveness.offlineAfterSeconds,
          port: config.liveness.port,
          timeoutMs: config.liveness.timeoutMs,
          suppressed,
        },
        config.liveness.intervalSeconds,
      );
      console.log(`liveness probe: every ${config.liveness.intervalSeconds}s (warn ${config.liveness.warnAfterSeconds}s, offline ${config.liveness.offlineAfterSeconds}s, tcp/${config.liveness.port})`);
    } else {
      startMonitor(store, wg, config.monitor.intervalSeconds, config.monitor.offlineAfterSeconds, alerter, { issues, events });
    }
    if (config.deviceMonitor.enabled) {
      startDeviceMonitor(
        { store, wg, issues, events, alerter, offlineAfterSeconds: config.monitor.offlineAfterSeconds, managementUsername: config.router.username, suppressed },
        config.deviceMonitor.intervalSeconds,
      );
      console.log(`device monitor: every ${config.deviceMonitor.intervalSeconds}s (logins + link state)`);
    }
    if (config.metrics.enabled) {
      startMetricsSampler(
        { store, wg, metrics, offlineAfterSeconds: config.monitor.offlineAfterSeconds },
        config.metrics.sampleSeconds,
      );
      console.log(`metrics sampler: every ${config.metrics.sampleSeconds}s (traffic history, ${config.metrics.retentionDays}d retention)`);
    }
    if (config.hosts.enabled) {
      startHostMonitor(
        {
          store, hosts, issues, events, alerter,
          warnAfterSeconds: config.hosts.warnAfterSeconds,
          offlineAfterSeconds: config.hosts.offlineAfterSeconds,
          pingCount: config.hosts.pingCount,
          suppressed,
        },
        config.hosts.intervalSeconds,
      );
      console.log(`host monitor: every ${config.hosts.intervalSeconds}s (internal ping targets, warn ${config.hosts.warnAfterSeconds}s, offline ${config.hosts.offlineAfterSeconds}s)`);
    }
    if (alerter.enabled) console.log("alerts: enabled");
    app.listen(config.server.port, config.server.host, () => {
      console.log(
        `provisioning server listening on ${config.server.host}:${config.server.port} (public: ${config.server.publicUrl})`,
      );
      console.log(`wireguard apply mode: ${config.wireguard.applyMode}`);
      console.log(`monitor: every ${config.monitor.intervalSeconds}s, offline after ${config.monitor.offlineAfterSeconds}s`);
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
    const result = await verifyRouter(store, wg, router);
    console.log(
      result.handshakeAge === null
        ? "handshake: none recorded"
        : `handshake: ${result.handshakeAge}s ago`,
    );
    if (result.reachable && result.info) {
      const { info } = result;
      console.log(`reachable: yes — ${info.identity} (${info.boardName}, ROS ${info.version}, up ${info.uptime})`);
    } else {
      console.error(`reachable: no — ${result.error}`);
      process.exitCode = 1;
    }
  });

const user = program.command("user").description("manage dashboard users");

user
  .command("add <username> <role>")
  .description("add a dashboard user (role: admin or tech); prints a generated password")
  .option("--password <password>", "set an explicit password instead")
  .action((username: string, role: string, opts: { password?: string }) => {
    if (role !== "admin" && role !== "tech") {
      console.error('role must be "admin" or "tech"');
      process.exitCode = 1;
      return;
    }
    const { config } = open(program.opts().config);
    const users = new UserStore(config.usersPath);
    const password =
      opts.password ?? Buffer.from(crypto.getRandomValues(new Uint8Array(12))).toString("base64url");
    users.add(username, password, role);
    console.log(`user "${username}" (${role}) created`);
    if (!opts.password) console.log(`password: ${password}  (store it now — it is not shown again)`);
  });

user
  .command("list")
  .description("list dashboard users")
  .action(() => {
    const { config } = open(program.opts().config);
    const users = new UserStore(config.usersPath).list();
    if (users.length === 0) {
      console.log("no users — the dashboard accepts the admin token from config.json");
      return;
    }
    console.table(users);
  });

user
  .command("rm <username>")
  .description("remove a dashboard user")
  .action((username: string) => {
    const { config } = open(program.opts().config);
    if (new UserStore(config.usersPath).remove(username)) console.log(`removed ${username}`);
    else {
      console.error(`no user "${username}"`);
      process.exitCode = 1;
    }
  });

program
  .command("token [note...]")
  .description("issue a one-time bootstrap token and print its one-liner")
  .option("--ttl <hours>", "token validity in hours", "72")
  .action((noteWords: string[] = [], opts: { ttl: string }) => {
    const { config } = open(program.opts().config);
    const tokens = new TokenStore(config.tokensPath);
    const t = tokens.create(noteWords.join(" "), "cli", Number(opts.ttl) || 72);
    console.log(`one-time token (expires ${t.expiresAt}):\n`);
    console.log(`  ${renderOneLiner(config, t.token)}\n`);
  });

program
  .command("prestage <serial> [label...]")
  .description("pre-stage a router by serial so it gets its label the moment it registers")
  .action((serial: string, labelWords: string[] = []) => {
    const { config, store } = open(program.opts().config);
    if (store.findBySerial(serial)) {
      console.error(`serial ${serial} already exists`);
      process.exitCode = 1;
      return;
    }
    const now = new Date().toISOString();
    store.save({
      id: crypto.randomUUID(),
      serialNumber: serial,
      publicKey: "",
      boardName: "unknown",
      rosVersion: "unknown",
      identity: "MikroTik",
      tunnelIp: "",
      username: config.router.username,
      password: Buffer.from(crypto.getRandomValues(new Uint8Array(18))).toString("base64url"),
      state: "staged",
      createdAt: now,
      updatedAt: now,
      lastSeenAt: null,
      label: labelWords.join(" "),
      notes: "",
    });
    console.log(`staged ${serial}${labelWords.length ? ` as "${labelWords.join(" ")}"` : ""}`);
  });

program
  .command("label <ref> <label...>")
  .description("set a friendly label (customer/site) on a router")
  .action((ref: string, labelWords: string[]) => {
    const { store } = open(program.opts().config);
    const router = store.find(ref);
    if (!router) {
      console.error(`no router matching "${ref}"`);
      process.exitCode = 1;
      return;
    }
    router.label = labelWords.join(" ");
    router.updatedAt = new Date().toISOString();
    store.save(router);
    console.log(`${router.serialNumber} labelled "${router.label}"`);
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
    await revokeRouter(store, wg, router);
    console.log(`revoked ${router.serialNumber} (${router.tunnelIp})`);
  });

program.parseAsync().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
