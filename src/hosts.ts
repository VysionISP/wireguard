import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { HealthState } from "./types.js";

/**
 * An internal LAN device (a DHCP client, camera, AP…) that we ping-monitor
 * *through* its router, because it isn't routable from the provisioning
 * server. Keyed by id; grouped by the router that owns it.
 */
export interface MonitoredHost {
  id: string;
  /** The router (serial) that reaches this host and does the pinging. */
  routerSerial: string;
  /** Convenience back-link to the router record id. */
  routerId: string;
  /** IP address on the router's LAN. */
  address: string;
  /** Friendly name (DHCP host-name / operator label). */
  name: string;
  mac?: string;
  enabled: boolean;
  createdAt: string;
  createdBy: string;
  /**
   * Latest liveness verdict from the host monitor. "unknown" means its router
   * is offline, so we can't tell (and deliberately don't alert on the host).
   */
  state?: HealthState | "unknown";
  lastOkAt?: string | null;
  lastCheckAt?: string | null;
  lastRttMs?: number | null;
}

export class HostStore {
  private hosts: MonitoredHost[] = [];

  constructor(private readonly filePath: string) {
    if (fs.existsSync(filePath)) {
      this.hosts = JSON.parse(fs.readFileSync(filePath, "utf8"));
    }
  }

  private persist(): void {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.hosts, null, 2));
    fs.renameSync(tmp, this.filePath);
  }

  list(): MonitoredHost[] {
    return [...this.hosts];
  }

  forRouter(routerSerial: string): MonitoredHost[] {
    return this.hosts.filter((h) => h.routerSerial === routerSerial);
  }

  get(id: string): MonitoredHost | undefined {
    return this.hosts.find((h) => h.id === id);
  }

  /** Add a host, or return the existing one for the same (router, address). */
  add(input: Omit<MonitoredHost, "id" | "createdAt" | "enabled"> & { enabled?: boolean }): MonitoredHost {
    const existing = this.hosts.find(
      (h) => h.routerSerial === input.routerSerial && h.address === input.address,
    );
    if (existing) return existing;
    const host: MonitoredHost = {
      id: crypto.randomUUID(),
      createdAt: new Date().toISOString(),
      enabled: input.enabled ?? true,
      ...input,
    };
    this.hosts.push(host);
    this.persist();
    return host;
  }

  save(host: MonitoredHost): void {
    const i = this.hosts.findIndex((h) => h.id === host.id);
    if (i >= 0) this.hosts[i] = host;
    this.persist();
  }

  remove(id: string): boolean {
    const before = this.hosts.length;
    this.hosts = this.hosts.filter((h) => h.id !== id);
    if (this.hosts.length !== before) {
      this.persist();
      return true;
    }
    return false;
  }

  /** Drop every host belonging to a router (used when a router is removed). */
  removeRouter(routerSerial: string): void {
    const before = this.hosts.length;
    this.hosts = this.hosts.filter((h) => h.routerSerial !== routerSerial);
    if (this.hosts.length !== before) this.persist();
  }
}
