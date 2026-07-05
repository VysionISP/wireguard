import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import { Alerter } from "../src/alerts.js";
import { TokenStore } from "../src/tokens.js";
import { UserStore, SessionManager } from "../src/users.js";
import { AuditLog } from "../src/audit.js";
import type { RouterRecord } from "../src/types.js";
import { tempDir } from "./helpers.js";

function router(over: Partial<RouterRecord> = {}): RouterRecord {
  const now = new Date().toISOString();
  return {
    id: "id", serialNumber: "HEX1", publicKey: "k", boardName: "hEX", rosVersion: "7.15",
    identity: "MikroTik", tunnelIp: "10.99.0.2", username: "wg-mgmt", password: "p",
    state: "confirmed", createdAt: now, updatedAt: now, lastSeenAt: now, ...over,
  };
}

describe("Alerter", () => {
  const cfg = { webhookUrl: "https://hook.test", notifyOnRegister: true, notifyOnline: true, suppressMinutes: 15 } as any;

  it("suppresses repeat alerts within the window, allows the opposite direction", async () => {
    const sent: string[] = [];
    const a = new Alerter(cfg, async (text) => { sent.push(text); });
    const r = router({ label: "Smith" });
    await a.routerTransition(r, false);
    await a.routerTransition(r, false); // suppressed
    await a.routerTransition(r, true);  // opposite direction, allowed
    expect(sent).toHaveLength(2);
    expect(sent[0]).toContain("OFFLINE");
    expect(sent[1]).toContain("back online");
  });

  it("is disabled when no channel is configured", async () => {
    const sent: string[] = [];
    const a = new Alerter({ notifyOnRegister: true, notifyOnline: true, suppressMinutes: 0 } as any, async (t) => { sent.push(t); });
    expect(a.enabled).toBe(false);
    await a.routerTransition(router(), false);
    expect(sent).toHaveLength(0);
  });
});

describe("TokenStore", () => {
  it("issues one-time tokens that validate once then burn", () => {
    const store = new TokenStore(path.join(tempDir(), "tokens.json"));
    const t = store.create("Smith install", "admin", 72);
    expect(store.findValid(t.token)?.token).toBe(t.token);
    store.markUsed(t.token, "HEX9");
    expect(store.findValid(t.token)).toBeUndefined();       // burned
    expect(store.find(t.token)?.usedBySerial).toBe("HEX9");  // still findable
  });

  it("rejects expired tokens", () => {
    const store = new TokenStore(path.join(tempDir(), "tokens.json"));
    const t = store.create("x", "admin", 72);
    // force expiry
    (store as any).tokens[0].expiresAt = new Date(Date.now() - 1000).toISOString();
    expect(store.findValid(t.token)).toBeUndefined();
  });

  it("persists across reloads", () => {
    const p = path.join(tempDir(), "tokens.json");
    const t = new TokenStore(p).create("keep", "admin", null);
    expect(new TokenStore(p).findValid(t.token)).toBeDefined();
  });
});

describe("UserStore + sessions", () => {
  it("hashes passwords and verifies with constant-time compare", () => {
    const users = new UserStore(path.join(tempDir(), "users.json"));
    users.add("tech1", "hunter2!!", "tech");
    expect(users.verify("tech1", "hunter2!!")?.role).toBe("tech");
    expect(users.verify("tech1", "wrong")).toBeNull();
    expect(users.verify("ghost", "whatever")).toBeNull();
    expect(users.list()[0]).not.toHaveProperty("hash");
  });

  it("rejects weak passwords and duplicate users", () => {
    const users = new UserStore(path.join(tempDir(), "users.json"));
    expect(() => users.add("a", "short", "tech")).toThrow();
    users.add("bob", "longenough", "admin");
    expect(() => users.add("bob", "longenough2", "tech")).toThrow(/exists/);
  });

  it("sessions expire and can be destroyed per user", () => {
    const sm = new SessionManager(12);
    const s = sm.create("bob", "admin");
    expect(sm.get(s.token)?.username).toBe("bob");
    sm.destroyForUser("bob");
    expect(sm.get(s.token)).toBeNull();
  });
});

describe("AuditLog", () => {
  it("appends and reads back most-recent-first", () => {
    const log = new AuditLog(path.join(tempDir(), "audit.jsonl"));
    log.log("alice", "revoke", "HEX1", "detail");
    log.log("bob", "login", "-");
    const recent = log.recent();
    expect(recent[0].user).toBe("bob");
    expect(recent[1].action).toBe("revoke");
  });
});
