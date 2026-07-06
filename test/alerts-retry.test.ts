import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Alerter } from "../src/alerts.js";
import { SettingsStore } from "../src/settings.js";
import type { TelegramClient } from "../src/telegram.js";
import type { RouterRecord } from "../src/types.js";
import { tempDir } from "./helpers.js";

function router(): RouterRecord {
  const now = new Date().toISOString();
  return {
    id: "r", serialNumber: "HEX1", publicKey: "k", boardName: "hEX", rosVersion: "7", identity: "s",
    tunnelIp: "10.99.0.2", username: "u", password: "p", state: "confirmed",
    createdAt: now, updatedAt: now, lastSeenAt: now,
  };
}

afterEach(() => vi.useRealTimers());

describe("alert delivery retry", () => {
  it("retries a failed Telegram send once and succeeds", async () => {
    vi.useFakeTimers();
    const settings = new SettingsStore(path.join(tempDir(), "s.json"));
    settings.setTelegram("tok", [
      { id: "-1", title: "chat", type: "group", events: { registered: true, offline: true, online: true, login: true, link: true } },
    ]);
    let calls = 0;
    const tg: TelegramClient = {
      getMe: async () => ({ username: "b" }),
      getChats: async () => [],
      send: async () => {
        calls++;
        if (calls === 1) throw new Error("fetch failed");
      },
    };
    const alerter = new Alerter(
      { notifyOnRegister: true, notifyOnline: true, suppressMinutes: 0 } as any,
      null, settings, tg,
    );
    const p = alerter.custom(router(), "test alert", "login");
    await vi.advanceTimersByTimeAsync(4000); // past the 3s retry pause
    await p;
    expect(calls).toBe(2); // failed once, retried, delivered
  });
});
