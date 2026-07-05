import fs from "node:fs";
import path from "node:path";
import type { RouterRecord } from "./types.js";

/**
 * JSON-file-backed router inventory. Writes are atomic (temp file + rename)
 * so a crash mid-write cannot corrupt the inventory.
 */
export class RouterStore {
  private routers = new Map<string, RouterRecord>();

  constructor(private readonly filePath: string) {
    this.load();
  }

  private load(): void {
    if (!fs.existsSync(this.filePath)) return;
    const raw = JSON.parse(fs.readFileSync(this.filePath, "utf8")) as RouterRecord[];
    this.routers = new Map(raw.map((r) => [r.id, r]));
  }

  private persist(): void {
    const dir = path.dirname(this.filePath);
    fs.mkdirSync(dir, { recursive: true });
    const tmp = `${this.filePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.list(), null, 2));
    fs.renameSync(tmp, this.filePath);
  }

  list(): RouterRecord[] {
    return [...this.routers.values()].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }

  get(id: string): RouterRecord | undefined {
    return this.routers.get(id);
  }

  findBySerial(serialNumber: string): RouterRecord | undefined {
    return this.list().find((r) => r.serialNumber === serialNumber);
  }

  /** Find by id, serial number or tunnel IP — convenient for CLI lookups. */
  find(ref: string): RouterRecord | undefined {
    return (
      this.routers.get(ref) ??
      this.list().find((r) => r.serialNumber === ref || r.tunnelIp === ref)
    );
  }

  usedTunnelIps(): string[] {
    return this.list().map((r) => r.tunnelIp);
  }

  save(record: RouterRecord): void {
    this.routers.set(record.id, record);
    this.persist();
  }
}
