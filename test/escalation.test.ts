import path from "node:path";
import { describe, expect, it } from "vitest";
import { EscalationEngine } from "../src/escalation.js";
import { IssueStore } from "../src/issues.js";
import { EventLog } from "../src/events.js";
import { SettingsStore } from "../src/settings.js";
import { AuditLog } from "../src/audit.js";
import type { TelegramClient } from "../src/telegram.js";
import { tempDir } from "./helpers.js";

const MIN = 60_000;

function setup(cfgOver: Record<string, unknown> = {}) {
  const issues = new IssueStore(path.join(tempDir(), "i.json"));
  const events = new EventLog(path.join(tempDir(), "e.jsonl"));
  const settings = new SettingsStore(path.join(tempDir(), "s.json"));
  settings.setTelegram("test-bot-token", [
    { id: "-100", title: "NOC chat", type: "group", events: { registered: false, offline: true, online: false, login: false, link: false } },
  ]);
  const sent: Array<{ chatId: string; text: string; buttons?: unknown }> = [];
  const answered: string[] = [];
  const edited: string[] = [];
  const tg: TelegramClient = {
    getMe: async () => ({ username: "bot" }),
    getChats: async () => [],
    send: async (_t, chatId, text) => { sent.push({ chatId, text }); },
    sendWithButtons: async (_t, chatId, text, buttons) => { sent.push({ chatId, text, buttons }); },
    answerCallback: async (_t, _id, text) => { answered.push(text); },
    editText: async (_t, _c, _m, text) => { edited.push(text); },
  };
  const cfg = {
    notifyOnRegister: true, notifyOnline: true, suppressMinutes: 0,
    escalateAfterMinutes: 10, escalateEveryMinutes: 15, maxEscalations: 3,
    ...cfgOver,
  } as any;
  const engine = new EscalationEngine({ issues, events, settings, audit: new AuditLog(path.join(tempDir(), "a.jsonl")), cfg, tg });
  return { issues, events, engine, sent, answered, edited };
}

function openCritical(issues: IssueStore, ageMinutes: number): string {
  issues.open("HEX1", "North Tower", "offline", "critical", "North Tower is offline");
  const issue = issues.list().find((i) => i.serialNumber === "HEX1")!;
  issue.openedAt = new Date(Date.now() - ageMinutes * MIN).toISOString();
  return issue.id;
}

describe("EscalationEngine.tick", () => {
  it("escalates an unacked critical past the threshold, with an Ack button", async () => {
    const t = setup();
    openCritical(t.issues, 12);
    expect(await t.engine.tick()).toBe(1);
    expect(t.sent).toHaveLength(1);
    expect(t.sent[0].text).toContain("ESCALATION 1/3");
    expect(JSON.stringify(t.sent[0].buttons)).toContain("ack:");
  });

  it("leaves young, acked or warning issues alone", async () => {
    const t = setup();
    openCritical(t.issues, 5); // under 10m
    expect(await t.engine.tick()).toBe(0);

    const t2 = setup();
    const id = openCritical(t2.issues, 30);
    t2.issues.ack(id, "lockie");
    expect(await t2.engine.tick()).toBe(0);
  });

  it("repeats on the interval and stops at the cap", async () => {
    const t = setup();
    openCritical(t.issues, 30);
    const now = Date.now();
    expect(await t.engine.tick(now)).toBe(1); // escalation 1
    expect(await t.engine.tick(now + 5 * MIN)).toBe(0); // too soon
    expect(await t.engine.tick(now + 16 * MIN)).toBe(1); // escalation 2
    expect(await t.engine.tick(now + 32 * MIN)).toBe(1); // escalation 3 (cap)
    expect(await t.engine.tick(now + 60 * MIN)).toBe(0); // capped
    expect(t.sent).toHaveLength(3);
  });
});

describe("EscalationEngine.handleCallback", () => {
  it("acks the issue from a Telegram button and edits the message", async () => {
    const t = setup();
    const id = openCritical(t.issues, 12);
    await t.engine.handleCallback({ id: "cb1", data: `ack:${id}`, from: "lockie", chatId: "-100", messageId: 42 }, "tok");
    const issue = t.issues.list(true).find((i) => i.id === id)!;
    expect(issue.ackedBy).toBe("tg:lockie");
    expect(t.answered[0]).toContain("Acknowledged");
    expect(t.edited[0]).toContain("ACKED by lockie");
    // Second press: already acked.
    await t.engine.handleCallback({ id: "cb2", data: `ack:${id}`, from: "bob", chatId: "-100", messageId: 42 }, "tok");
    expect(t.answered[1]).toContain("Already acked");
  });
});
