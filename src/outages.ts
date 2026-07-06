import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

/**
 * Durable per-device outage log — the source of truth for SLA/uptime reports.
 * The liveness monitor opens an outage when a device goes offline and closes it
 * when it recovers, so downtime survives restarts and the (bounded) event feed.
 */
export interface Outage {
  id: string;
  serialNumber: string;
  label: string;
  startAt: string;
  /** null while the device is still down. */
  endAt: string | null;
}

export class OutageStore {
  private outages: Outage[] = [];

  constructor(
    private readonly filePath: string,
    private readonly retentionMs = 400 * 24 * 3600_000,
  ) {
    if (fs.existsSync(filePath)) {
      const cutoff = Date.now() - retentionMs;
      this.outages = (JSON.parse(fs.readFileSync(filePath, "utf8")) as Outage[]).filter(
        (o) => o.endAt === null || Date.parse(o.endAt) >= cutoff,
      );
    }
  }

  private persist(): void {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.outages, null, 2));
    fs.renameSync(tmp, this.filePath);
  }

  private openFor(serial: string): Outage | undefined {
    return this.outages.find((o) => o.serialNumber === serial && o.endAt === null);
  }

  /** Start an outage (idempotent — one open outage per device). */
  open(serialNumber: string, label: string, at: string): void {
    if (this.openFor(serialNumber)) return;
    this.outages.push({ id: crypto.randomUUID(), serialNumber, label, startAt: at, endAt: null });
    this.persist();
  }

  /** Close the device's open outage, if any. */
  close(serialNumber: string, at: string): void {
    const open = this.openFor(serialNumber);
    if (!open) return;
    open.endAt = at;
    this.persist();
  }

  list(): Outage[] {
    return [...this.outages];
  }

  forSerial(serial: string): Outage[] {
    return this.outages.filter((o) => o.serialNumber === serial);
  }
}
