import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export interface OneTimeToken {
  token: string;
  note: string;
  createdAt: string;
  createdBy: string;
  expiresAt: string | null;
  usedAt: string | null;
  usedBySerial: string | null;
  /** When set, a device registering with this token joins this customer. */
  customer?: string;
  /** When set, the device is given this label on registration. */
  label?: string;
}

/**
 * One-time bootstrap tokens: each registers exactly one router, then burns.
 * Closes the "shared token leaked in a bootstrap script" hole.
 */
export class TokenStore {
  private tokens: OneTimeToken[] = [];

  constructor(private readonly filePath: string) {
    if (fs.existsSync(filePath)) {
      this.tokens = JSON.parse(fs.readFileSync(filePath, "utf8"));
    }
  }

  private persist(): void {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.tokens, null, 2));
    fs.renameSync(tmp, this.filePath);
  }

  create(
    note: string,
    createdBy: string,
    ttlHours: number | null,
    opts: { customer?: string; label?: string } = {},
  ): OneTimeToken {
    const t: OneTimeToken = {
      token: "ot-" + crypto.randomBytes(20).toString("hex"),
      note,
      createdBy,
      createdAt: new Date().toISOString(),
      expiresAt: ttlHours ? new Date(Date.now() + ttlHours * 3600_000).toISOString() : null,
      usedAt: null,
      usedBySerial: null,
      customer: opts.customer || undefined,
      label: opts.label || undefined,
    };
    this.tokens.push(t);
    this.persist();
    return t;
  }

  list(): OneTimeToken[] {
    return [...this.tokens].reverse();
  }

  /** Valid = exists, unused, unexpired. Constant-time comparison per entry. */
  findValid(candidate: string): OneTimeToken | undefined {
    const now = Date.now();
    const hc = crypto.createHash("sha256").update(candidate).digest();
    return this.tokens.find((t) => {
      const ht = crypto.createHash("sha256").update(t.token).digest();
      if (!crypto.timingSafeEqual(hc, ht)) return false;
      if (t.usedAt) return false;
      if (t.expiresAt && Date.parse(t.expiresAt) < now) return false;
      return true;
    });
  }

  /**
   * Like findValid but ignores used/expired state — used to let a router's
   * own burned token keep authorising its confirm/backup calls.
   */
  find(candidate: string): OneTimeToken | undefined {
    const hc = crypto.createHash("sha256").update(candidate).digest();
    return this.tokens.find((t) =>
      crypto.timingSafeEqual(hc, crypto.createHash("sha256").update(t.token).digest()),
    );
  }

  markUsed(token: string, serial: string): void {
    const t = this.tokens.find((x) => x.token === token);
    if (!t) return;
    t.usedAt = new Date().toISOString();
    t.usedBySerial = serial;
    this.persist();
  }

  delete(token: string): boolean {
    const before = this.tokens.length;
    this.tokens = this.tokens.filter((t) => t.token !== token);
    if (this.tokens.length !== before) {
      this.persist();
      return true;
    }
    return false;
  }
}
