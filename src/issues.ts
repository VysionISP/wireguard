import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export type Severity = "critical" | "warning";
export type IssueType =
  | "offline"
  | "link-down"
  | "traffic-high"
  | "traffic-low"
  | "login"
  | "monitor-error";

export interface Issue {
  id: string;
  serialNumber: string;
  label: string;
  type: IssueType;
  /** Optional sub-reference (e.g. interface name) so one router can hold
   *  several open issues of the same type — one per affected port. */
  ref: string;
  severity: Severity;
  message: string;
  openedAt: string;
  updatedAt: string;
  resolvedAt: string | null;
  ackedAt: string | null;
  ackedBy: string | null;
}

const MAX_RESOLVED = 200;

/**
 * Active problem tracker behind the status board. Issues are keyed by
 * (serial, type): opening the same key twice updates the existing open issue
 * instead of duplicating, and resolving clears it. Resolved issues are kept
 * (bounded) for history.
 */
export class IssueStore {
  private issues: Issue[] = [];

  constructor(private readonly filePath: string) {
    if (fs.existsSync(filePath)) {
      this.issues = JSON.parse(fs.readFileSync(filePath, "utf8"));
    }
  }

  private persist(): void {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.issues, null, 2));
    fs.renameSync(tmp, this.filePath);
  }

  private openOfKey(serialNumber: string, type: IssueType, ref: string): Issue | undefined {
    return this.issues.find(
      (i) => i.serialNumber === serialNumber && i.type === type && i.ref === ref && !i.resolvedAt,
    );
  }

  /** Open (or refresh) an issue. Returns true if a NEW issue was created. */
  open(
    serialNumber: string,
    label: string,
    type: IssueType,
    severity: Severity,
    message: string,
    ref = "",
  ): boolean {
    const now = new Date().toISOString();
    const existing = this.openOfKey(serialNumber, type, ref);
    if (existing) {
      existing.message = message;
      existing.updatedAt = now;
      existing.label = label;
      this.persist();
      return false;
    }
    this.issues.push({
      id: crypto.randomUUID(),
      serialNumber,
      label,
      type,
      ref,
      severity,
      message,
      openedAt: now,
      updatedAt: now,
      resolvedAt: null,
      ackedAt: null,
      ackedBy: null,
    });
    this.prune();
    this.persist();
    return true;
  }

  /** Resolve the open issue of this (serial, type, ref). Returns true if one closed. */
  resolve(serialNumber: string, type: IssueType, ref = ""): boolean {
    const existing = this.openOfKey(serialNumber, type, ref);
    if (!existing) return false;
    existing.resolvedAt = new Date().toISOString();
    existing.updatedAt = existing.resolvedAt;
    this.persist();
    return true;
  }

  /** Resolve a specific open issue by its id (matches the exact ref). */
  resolveById(id: string): boolean {
    const issue = this.issues.find((i) => i.id === id && !i.resolvedAt);
    if (!issue) return false;
    issue.resolvedAt = new Date().toISOString();
    issue.updatedAt = issue.resolvedAt;
    this.persist();
    return true;
  }

  ack(id: string, user: string): boolean {
    const issue = this.issues.find((i) => i.id === id && !i.resolvedAt);
    if (!issue) return false;
    issue.ackedAt = new Date().toISOString();
    issue.ackedBy = user;
    issue.updatedAt = issue.ackedAt;
    this.persist();
    return true;
  }

  /** Drop all issues for a router (used when it's revoked). */
  clearSerial(serialNumber: string): void {
    const before = this.issues.length;
    this.issues = this.issues.filter((i) => i.serialNumber !== serialNumber);
    if (this.issues.length !== before) this.persist();
  }

  open_(): Issue[] {
    return this.issues.filter((i) => !i.resolvedAt).sort((a, b) => b.openedAt.localeCompare(a.openedAt));
  }

  list(includeResolved = false): Issue[] {
    const items = includeResolved ? this.issues : this.issues.filter((i) => !i.resolvedAt);
    return [...items].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  }

  counts(): { critical: number; warning: number; unacked: number } {
    const open = this.open_();
    return {
      critical: open.filter((i) => i.severity === "critical").length,
      warning: open.filter((i) => i.severity === "warning").length,
      unacked: open.filter((i) => !i.ackedAt).length,
    };
  }

  private prune(): void {
    const resolved = this.issues.filter((i) => i.resolvedAt);
    if (resolved.length > MAX_RESOLVED) {
      const drop = new Set(
        resolved
          .sort((a, b) => (a.resolvedAt! < b.resolvedAt! ? -1 : 1))
          .slice(0, resolved.length - MAX_RESOLVED)
          .map((i) => i.id),
      );
      this.issues = this.issues.filter((i) => !drop.has(i.id));
    }
  }
}
