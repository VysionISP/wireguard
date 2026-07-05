import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export interface BackupEntry {
  name: string;
  size: number;
  createdAt: string;
}

const SERIAL_SAFE = /^[A-Za-z0-9_-]+$/;

/**
 * Versioned per-router config backups on disk:
 *   <dir>/<serial>/<iso-timestamp>.rsc
 * A new version is only written when the content actually changed.
 */
export class BackupStore {
  constructor(
    private readonly dir: string,
    private readonly keep: number,
  ) {}

  private routerDir(serialNumber: string): string {
    if (!SERIAL_SAFE.test(serialNumber)) {
      throw new Error(`unsafe serial number: ${serialNumber}`);
    }
    return path.join(this.dir, serialNumber);
  }

  /** Stores `content` as a new version unless it matches the latest one. */
  saveIfChanged(serialNumber: string, content: Buffer): { stored: boolean; name: string | null } {
    const dir = this.routerDir(serialNumber);
    const latest = this.list(serialNumber)[0];
    if (latest) {
      const prev = fs.readFileSync(path.join(dir, latest.name));
      const same =
        crypto.createHash("sha256").update(prev).digest("hex") ===
        crypto.createHash("sha256").update(content).digest("hex");
      if (same) return { stored: false, name: latest.name };
    }
    fs.mkdirSync(dir, { recursive: true });
    const name = new Date().toISOString().replace(/[:.]/g, "-") + ".rsc";
    fs.writeFileSync(path.join(dir, name), content);
    this.prune(serialNumber);
    return { stored: true, name };
  }

  /** Newest first. */
  list(serialNumber: string): BackupEntry[] {
    const dir = this.routerDir(serialNumber);
    if (!fs.existsSync(dir)) return [];
    return fs
      .readdirSync(dir)
      .filter((f) => f.endsWith(".rsc"))
      .sort()
      .reverse()
      .map((name) => {
        const st = fs.statSync(path.join(dir, name));
        return { name, size: st.size, createdAt: st.mtime.toISOString() };
      });
  }

  read(serialNumber: string, name: string): Buffer | null {
    if (!/^[A-Za-z0-9-]+\.rsc$/.test(name)) return null; // no traversal
    const file = path.join(this.routerDir(serialNumber), name);
    return fs.existsSync(file) ? fs.readFileSync(file) : null;
  }

  private prune(serialNumber: string): void {
    const entries = this.list(serialNumber);
    for (const stale of entries.slice(this.keep)) {
      fs.unlinkSync(path.join(this.routerDir(serialNumber), stale.name));
    }
  }
}
