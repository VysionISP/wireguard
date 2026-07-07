import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

/**
 * Planned maintenance windows. While one is active, alerts / issues for the
 * covered devices are suppressed so a scheduled reboot or upgrade doesn't page
 * anyone, and the downtime is excluded from SLA reporting.
 */

/** Coarse alert categories a window can mute (empty list = mute everything). */
export const MAINT_CATEGORIES = ["offline", "link", "host", "login"] as const;
export type MaintCategory = (typeof MAINT_CATEGORIES)[number];

/** Map an issue/event type to its maintenance category. */
export function maintCategory(type: string): MaintCategory {
  if (type === "link-down" || type === "link-up" || type === "traffic-high" || type === "traffic-low") return "link";
  if (type.startsWith("upstream-")) return "link";
  if (type === "host-down" || type === "host-up") return "host";
  if (type === "login") return "login";
  return "offline"; // offline / online / monitor-error
}

export interface MaintenanceWindow {
  id: string;
  /** "all" = whole fleet, "device" = one serial, "customer" = a customer group. */
  scopeKind: "all" | "device" | "customer";
  scopeValue?: string;
  startsAt: string;
  endsAt: string;
  /** Categories to mute; empty = all. */
  categories: MaintCategory[];
  note: string;
  createdBy: string;
  createdAt: string;
}

export class MaintenanceStore {
  private windows: MaintenanceWindow[] = [];

  constructor(private readonly filePath: string) {
    if (fs.existsSync(filePath)) this.windows = JSON.parse(fs.readFileSync(filePath, "utf8"));
  }

  private persist(): void {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.windows, null, 2));
    fs.renameSync(tmp, this.filePath);
  }

  list(): MaintenanceWindow[] {
    return [...this.windows].sort((a, b) => b.startsAt.localeCompare(a.startsAt));
  }

  add(w: Omit<MaintenanceWindow, "id" | "createdAt">): MaintenanceWindow {
    const win: MaintenanceWindow = { id: crypto.randomUUID(), createdAt: new Date().toISOString(), ...w };
    this.windows.push(win);
    this.persist();
    return win;
  }

  remove(id: string): boolean {
    const before = this.windows.length;
    this.windows = this.windows.filter((w) => w.id !== id);
    if (this.windows.length !== before) {
      this.persist();
      return true;
    }
    return false;
  }

  /** Windows active at `nowMs` (default now). */
  active(nowMs = Date.now()): MaintenanceWindow[] {
    return this.windows.filter((w) => Date.parse(w.startsAt) <= nowMs && nowMs < Date.parse(w.endsAt));
  }

  private covers(w: MaintenanceWindow, serial: string, group: string | undefined): boolean {
    if (w.scopeKind === "all") return true;
    if (w.scopeKind === "device") return w.scopeValue === serial;
    return Boolean(group) && w.scopeValue === group;
  }

  /** The active window covering this device (for display), or undefined. */
  activeForRouter(serial: string, group: string | undefined, nowMs = Date.now()): MaintenanceWindow | undefined {
    return this.active(nowMs).find((w) => this.covers(w, serial, group));
  }

  /** True if an active window mutes `category` for this device. */
  suppressed(serial: string, group: string | undefined, category: MaintCategory, nowMs = Date.now()): boolean {
    return this.active(nowMs).some(
      (w) => this.covers(w, serial, group) && (w.categories.length === 0 || w.categories.includes(category)),
    );
  }

  /**
   * All windows (past/present/future) that cover this device for `category` —
   * used by SLA reporting to exclude planned downtime over a period.
   */
  windowsCovering(serial: string, group: string | undefined, category: MaintCategory): MaintenanceWindow[] {
    return this.windows.filter(
      (w) => this.covers(w, serial, group) && (w.categories.length === 0 || w.categories.includes(category)),
    );
  }
}
