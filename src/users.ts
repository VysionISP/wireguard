import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export type Role = "admin" | "tech";

export interface User {
  username: string;
  role: Role;
  salt: string;
  hash: string;
  createdAt: string;
}

export interface Session {
  token: string;
  username: string;
  role: Role;
  expiresAt: number;
}

function hashPassword(password: string, salt: string): string {
  return crypto.scryptSync(password, salt, 32).toString("hex");
}

/** Dashboard user accounts (scrypt-hashed passwords, admin/tech roles). */
export class UserStore {
  private users: User[] = [];

  constructor(private readonly filePath: string) {
    if (fs.existsSync(filePath)) {
      this.users = JSON.parse(fs.readFileSync(filePath, "utf8"));
    }
  }

  private persist(): void {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.users, null, 2));
    fs.renameSync(tmp, this.filePath);
  }

  list(): Array<Omit<User, "salt" | "hash">> {
    return this.users.map(({ salt: _s, hash: _h, ...rest }) => rest);
  }

  add(username: string, password: string, role: Role): void {
    if (!/^[a-z0-9._-]{2,32}$/i.test(username)) throw new Error("invalid username");
    if (password.length < 8) throw new Error("password must be at least 8 characters");
    if (this.users.some((u) => u.username === username)) throw new Error("user already exists");
    const salt = crypto.randomBytes(16).toString("hex");
    this.users.push({
      username,
      role,
      salt,
      hash: hashPassword(password, salt),
      createdAt: new Date().toISOString(),
    });
    this.persist();
  }

  changePassword(username: string, newPassword: string): void {
    if (newPassword.length < 8) throw new Error("password must be at least 8 characters");
    const user = this.users.find((u) => u.username === username);
    if (!user) throw new Error("no such user");
    user.salt = crypto.randomBytes(16).toString("hex");
    user.hash = hashPassword(newPassword, user.salt);
    this.persist();
  }

  has(username: string): boolean {
    return this.users.some((u) => u.username === username);
  }

  remove(username: string): boolean {
    const before = this.users.length;
    this.users = this.users.filter((u) => u.username !== username);
    if (this.users.length !== before) {
      this.persist();
      return true;
    }
    return false;
  }

  verify(username: string, password: string): User | null {
    const user = this.users.find((u) => u.username === username);
    // Always burn a hash to keep timing flat for unknown usernames.
    const salt = user?.salt ?? "0".repeat(32);
    const candidate = hashPassword(password, salt);
    if (!user) return null;
    const a = Buffer.from(candidate, "hex");
    const b = Buffer.from(user.hash, "hex");
    return a.length === b.length && crypto.timingSafeEqual(a, b) ? user : null;
  }
}

/** In-memory session tokens for dashboard logins (re-login after restart). */
export class SessionManager {
  private sessions = new Map<string, Session>();

  constructor(private readonly ttlHours: number) {}

  create(username: string, role: Role): Session {
    const s: Session = {
      token: "sess-" + crypto.randomBytes(24).toString("hex"),
      username,
      role,
      expiresAt: Date.now() + this.ttlHours * 3600_000,
    };
    this.sessions.set(s.token, s);
    return s;
  }

  get(token: string): Session | null {
    const s = this.sessions.get(token);
    if (!s) return null;
    if (s.expiresAt < Date.now()) {
      this.sessions.delete(token);
      return null;
    }
    // Sliding expiry: active users stay signed in.
    s.expiresAt = Date.now() + this.ttlHours * 3600_000;
    return s;
  }

  destroy(token: string): void {
    this.sessions.delete(token);
  }

  destroyForUser(username: string): void {
    for (const [t, s] of this.sessions) if (s.username === username) this.sessions.delete(t);
  }
}
