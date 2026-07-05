import fs from "node:fs";
import path from "node:path";

export type EventType =
  | "login"
  | "logout"
  | "link-down"
  | "link-up"
  | "offline"
  | "online"
  | "backup"
  | "monitor-error";

export interface DeviceEvent {
  at: string;
  serialNumber: string;
  label: string;
  type: EventType;
  severity: "info" | "warning" | "critical";
  message: string;
}

/**
 * Append-only device event feed (JSONL): logins, link flaps, on/offline.
 * The router's own record links to these; the status board shows the global
 * stream. Kept simple and durable — one line per event.
 */
const MAX_EVENTS = 5000;

export class EventLog {
  private sinceTrim = 0;

  constructor(private readonly filePath: string) {}

  add(e: DeviceEvent): void {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      fs.appendFileSync(this.filePath, JSON.stringify(e) + "\n");
      // Periodically trim so the file (and per-request read cost) stays bounded.
      if (++this.sinceTrim >= 200) {
        this.sinceTrim = 0;
        this.trim();
      }
    } catch (err) {
      console.error(`event write failed: ${(err as Error).message}`);
    }
  }

  private trim(): void {
    const all = this.readAll();
    if (all.length <= MAX_EVENTS) return;
    const kept = all.slice(-MAX_EVENTS).map((e) => JSON.stringify(e)).join("\n") + "\n";
    const tmp = `${this.filePath}.tmp`;
    fs.writeFileSync(tmp, kept);
    fs.renameSync(tmp, this.filePath);
  }

  private readAll(): DeviceEvent[] {
    if (!fs.existsSync(this.filePath)) return [];
    return fs
      .readFileSync(this.filePath, "utf8")
      .trim()
      .split("\n")
      .flatMap((l) => {
        try {
          return l ? [JSON.parse(l) as DeviceEvent] : [];
        } catch {
          return [];
        }
      });
  }

  /** Global feed, newest first. */
  recent(limit = 200): DeviceEvent[] {
    return this.readAll().slice(-limit).reverse();
  }

  forSerial(serialNumber: string, limit = 50): DeviceEvent[] {
    return this.readAll()
      .filter((e) => e.serialNumber === serialNumber)
      .slice(-limit)
      .reverse();
  }
}
