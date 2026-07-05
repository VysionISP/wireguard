import fs from "node:fs";
import path from "node:path";

export interface AuditEntry {
  at: string;
  user: string;
  action: string;
  target: string;
  detail?: string;
}

/** Append-only JSONL audit trail of who did what. */
export class AuditLog {
  constructor(private readonly filePath: string) {}

  log(user: string, action: string, target: string, detail?: string): void {
    const entry: AuditEntry = { at: new Date().toISOString(), user, action, target };
    if (detail) entry.detail = detail.slice(0, 500);
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      fs.appendFileSync(this.filePath, JSON.stringify(entry) + "\n");
    } catch (err) {
      console.error(`audit write failed: ${(err as Error).message}`);
    }
  }

  /** Most recent first. */
  recent(limit = 200): AuditEntry[] {
    if (!fs.existsSync(this.filePath)) return [];
    const lines = fs.readFileSync(this.filePath, "utf8").trim().split("\n");
    return lines
      .slice(-limit)
      .reverse()
      .flatMap((l) => {
        try {
          return [JSON.parse(l) as AuditEntry];
        } catch {
          return [];
        }
      });
  }
}
