import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { RouterStore } from "./store.js";
import type { EventLog } from "./events.js";
import type { MaintenanceStore } from "./maintenance.js";
import type { RouterRecord } from "./types.js";
import { sshRun as realSshRun, type SshRunFn } from "./ssh.js";

/**
 * RouterOS upgrades, done the way you'd do them by hand but babysat by the
 * server: check-for-updates, `/system package update install` (the router
 * downloads packages and reboots itself), then wait for it to come back and
 * confirm the version actually changed. Fleet rollouts run as a job — one
 * device at a time by default, so a bad build bricks one CPE, not fifty.
 * Each device gets a temporary maintenance window so its reboot doesn't page
 * anyone, and every step lands in the device event log.
 */

export interface UpdateCheck {
  channel: string;
  installed: string;
  latest: string;
  status: string;
}

/** Parse `/system package update check-for-updates` output (key: value rows). */
export function parseUpdateCheck(output: string): UpdateCheck {
  const grab = (key: string) => {
    const m = new RegExp(`${key}:\\s*(.+)`, "i").exec(output);
    return m ? m[1].trim() : "";
  };
  // The status line prints repeatedly as the check progresses; the last one
  // ("New version is available" / "System is already up to date") is the verdict.
  const statuses = [...output.matchAll(/status:\s*(.+)/gi)].map((m) => m[1].trim());
  return {
    channel: grab("channel"),
    installed: grab("installed-version"),
    latest: grab("latest-version"),
    status: statuses[statuses.length - 1] ?? "",
  };
}

export function updateAvailable(c: UpdateCheck): boolean {
  return /new version/i.test(c.status) || (!!c.latest && !!c.installed && c.latest !== c.installed);
}

export type UpgradeItemState = "pending" | "checking" | "installing" | "rebooting" | "firmware" | "done" | "skipped" | "failed" | "cancelled";

export interface UpgradeItem {
  serial: string;
  label: string;
  state: UpgradeItemState;
  detail: string;
  fromVersion: string;
  toVersion?: string;
  startedAt?: string;
  finishedAt?: string;
}

export interface UpgradeJob {
  id: string;
  createdAt: string;
  createdBy: string;
  alsoFirmware: boolean;
  state: "running" | "done" | "cancelled";
  items: UpgradeItem[];
}

export interface UpgradeDeps {
  store: RouterStore;
  events: EventLog;
  maintenance?: MaintenanceStore;
  sshRun?: SshRunFn;
  /** How often we probe a rebooting device (ms). */
  pollMs?: number;
  /** How long a device gets to come back before the item fails (ms). */
  onlineTimeoutMs?: number;
  /** Persisted job history (JSON). */
  filePath?: string;
}

const MAX_JOBS = 30;

export class UpgradeManager {
  private jobs: UpgradeJob[] = [];
  private cancelled = new Set<string>();
  private readonly ssh: SshRunFn;
  private readonly pollMs: number;
  private readonly onlineTimeoutMs: number;

  constructor(private readonly deps: UpgradeDeps) {
    this.ssh = deps.sshRun ?? realSshRun;
    this.pollMs = deps.pollMs ?? 10_000;
    this.onlineTimeoutMs = deps.onlineTimeoutMs ?? 12 * 60_000;
    if (deps.filePath && fs.existsSync(deps.filePath)) {
      try {
        this.jobs = JSON.parse(fs.readFileSync(deps.filePath, "utf8"));
        // A server restart orphans running jobs — mark them so the UI is honest.
        for (const j of this.jobs) {
          if (j.state === "running") {
            j.state = "cancelled";
            for (const i of j.items) if (i.state === "pending" || i.state === "checking" || i.state === "installing" || i.state === "rebooting" || i.state === "firmware") {
              i.state = "cancelled";
              i.detail = "server restarted mid-job";
            }
          }
        }
      } catch {
        this.jobs = [];
      }
    }
  }

  private persist(): void {
    if (!this.deps.filePath) return;
    fs.mkdirSync(path.dirname(this.deps.filePath), { recursive: true });
    const tmp = `${this.deps.filePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.jobs, null, 2));
    fs.renameSync(tmp, this.deps.filePath);
  }

  list(): UpgradeJob[] {
    return this.jobs;
  }

  get(id: string): UpgradeJob | undefined {
    return this.jobs.find((j) => j.id === id);
  }

  /** True if some job is still running (one rollout at a time keeps it sane). */
  busy(): boolean {
    return this.jobs.some((j) => j.state === "running");
  }

  cancel(id: string): boolean {
    const job = this.get(id);
    if (!job || job.state !== "running") return false;
    this.cancelled.add(id);
    return true;
  }

  /** Start a staged rollout over the given routers. Returns the job (already running). */
  start(routers: RouterRecord[], createdBy: string, alsoFirmware = false): UpgradeJob {
    const job: UpgradeJob = {
      id: crypto.randomUUID(),
      createdAt: new Date().toISOString(),
      createdBy,
      alsoFirmware,
      state: "running",
      items: routers.map((r) => ({
        serial: r.serialNumber,
        label: r.label || r.identity || r.serialNumber,
        state: "pending",
        detail: "",
        fromVersion: r.rosVersion,
      })),
    };
    this.jobs.unshift(job);
    if (this.jobs.length > MAX_JOBS) this.jobs.length = MAX_JOBS;
    this.persist();
    void this.run(job);
    return job;
  }

  private async run(job: UpgradeJob): Promise<void> {
    for (const item of job.items) {
      if (this.cancelled.has(job.id)) {
        item.state = "cancelled";
        item.detail = "job cancelled";
        continue;
      }
      try {
        await this.upgradeOne(job, item);
      } catch (err) {
        item.state = "failed";
        item.detail = (err as Error).message;
        item.finishedAt = new Date().toISOString();
      }
      this.persist();
    }
    job.state = this.cancelled.has(job.id) ? "cancelled" : "done";
    this.cancelled.delete(job.id);
    this.persist();
  }

  private async upgradeOne(job: UpgradeJob, item: UpgradeItem): Promise<void> {
    const r = this.deps.store.findBySerial(item.serial);
    if (!r || !r.tunnelIp || r.state === "staged" || r.state === "revoked") {
      item.state = "skipped";
      item.detail = "not online / not registered";
      return;
    }
    item.startedAt = new Date().toISOString();
    item.state = "checking";
    this.persist();

    const checkOut = await this.ssh(r.tunnelIp, r.username, r.password, "/system package update check-for-updates", 30_000);
    const check = parseUpdateCheck(checkOut.output);
    if (check.installed) this.recordCheck(r, check);
    if (!updateAvailable(check)) {
      item.state = "skipped";
      item.detail = check.status || "already up to date";
      item.finishedAt = new Date().toISOString();
      return;
    }
    item.toVersion = check.latest;
    item.detail = `${check.installed} → ${check.latest}`;

    // Mute this device while it reboots — a planned upgrade must not page.
    const windowMinutes = Math.ceil(this.onlineTimeoutMs / 60_000) + (job.alsoFirmware ? 15 : 5);
    const win = this.deps.maintenance?.add({
      scopeKind: "device",
      scopeValue: r.serialNumber,
      startsAt: new Date().toISOString(),
      endsAt: new Date(Date.now() + windowMinutes * 60_000).toISOString(),
      categories: [],
      note: `RouterOS upgrade to ${check.latest}`,
      createdBy: job.createdBy,
    });

    try {
      this.deps.events.add({
        at: new Date().toISOString(), serialNumber: r.serialNumber, label: item.label,
        type: "upgrade", severity: "info", message: `RouterOS upgrade started: ${check.installed} → ${check.latest}`,
      });
      item.state = "installing";
      this.persist();
      // The install downloads packages then reboots; the SSH session usually
      // dies mid-command, so a failure here just means "it's rebooting".
      await this.ssh(r.tunnelIp, r.username, r.password, "/system package update install", 90_000).catch(() => {});

      item.state = "rebooting";
      this.persist();
      const version = await this.waitBack(r, check.installed);
      if (version === null) {
        item.state = "failed";
        item.detail = `did not come back within ${Math.round(this.onlineTimeoutMs / 60_000)} min — check it manually`;
        this.deps.events.add({
          at: new Date().toISOString(), serialNumber: r.serialNumber, label: item.label,
          type: "monitor-error", severity: "warning", message: `Upgrade to ${check.latest}: device not back online in time`,
        });
        return;
      }
      if (version === check.installed) {
        item.state = "failed";
        item.detail = `rebooted but still on ${version}`;
        return;
      }
      r.rosVersion = version;
      r.updatedAt = new Date().toISOString();
      this.deps.store.saveExisting(r);

      if (job.alsoFirmware) {
        item.state = "firmware";
        this.persist();
        await this.ssh(r.tunnelIp, r.username, r.password, "/system routerboard upgrade", 30_000).catch(() => {});
        await this.ssh(r.tunnelIp, r.username, r.password, "/system reboot", 15_000).catch(() => {});
        await this.waitBack(r, ""); // best-effort second reboot; version already new
      }

      item.state = "done";
      item.toVersion = version;
      item.detail = `${check.installed} → ${version}`;
      this.deps.events.add({
        at: new Date().toISOString(), serialNumber: r.serialNumber, label: item.label,
        type: "upgrade", severity: "info", message: `RouterOS upgraded: ${check.installed} → ${version}${job.alsoFirmware ? " (+ RouterBOARD firmware)" : ""}`,
      });
    } finally {
      item.finishedAt = new Date().toISOString();
      if (win) this.deps.maintenance?.remove(win.id);
    }
  }

  /**
   * Poll the device over SSH until it answers with its version (upgraded or
   * not), or the timeout passes. Returns the reported version, or null.
   */
  private async waitBack(r: RouterRecord, _oldVersion: string): Promise<string | null> {
    const deadline = Date.now() + this.onlineTimeoutMs;
    // Give the box a moment to actually go down before we start knocking.
    await sleep(this.pollMs);
    while (Date.now() < deadline) {
      try {
        const out = await this.ssh(r.tunnelIp, r.username, r.password, "/system resource print", 8_000);
        const m = /version:\s*([^\s(]+)/i.exec(out.output);
        if (m) return m[1];
      } catch {
        // still rebooting
      }
      await sleep(this.pollMs);
    }
    return null;
  }

  private recordCheck(r: RouterRecord, c: UpdateCheck): void {
    r.updateCheck = { at: new Date().toISOString(), channel: c.channel, installed: c.installed, latest: c.latest, status: c.status };
    this.deps.store.saveExisting(r);
  }

  /** Run just a check (no install) and persist the result on the record. */
  async check(r: RouterRecord): Promise<UpdateCheck> {
    const out = await this.ssh(r.tunnelIp, r.username, r.password, "/system package update check-for-updates", 30_000);
    const c = parseUpdateCheck(out.output);
    this.recordCheck(r, c);
    return c;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
