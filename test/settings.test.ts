import path from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { buildApp } from "../src/server.js";
import { RouterStore } from "../src/store.js";
import { SettingsStore } from "../src/settings.js";
import { Alerter, routeKey } from "../src/alerts.js";
import { DryRunManager } from "../src/wireguard.js";
import type { TelegramClient } from "../src/telegram.js";
import type { RouterRecord } from "../src/types.js";
import { tempDir, testConfig } from "./helpers.js";

function fakeTelegram(sent: Array<{ chatId: string; text: string }>): TelegramClient {
  return {
    getMe: async () => ({ username: "korvix_bot" }),
    getChats: async () => [
      { id: "-1001", title: "NOC alerts", type: "channel" },
      { id: "555", title: "Lockie", type: "private" },
    ],
    send: async (_t, chatId, text) => { sent.push({ chatId, text }); },
  };
}

describe("routeKey", () => {
  it("maps link events to the link category", () => {
    expect(routeKey("link-down")).toBe("link");
    expect(routeKey("link-up")).toBe("link");
    expect(routeKey("offline")).toBe("offline");
    expect(routeKey("registered")).toBe("registered");
  });
});

describe("settings API", () => {
  let cfg: ReturnType<typeof testConfig>;
  let settings: SettingsStore;
  let sent: Array<{ chatId: string; text: string }>;
  let app: ReturnType<typeof buildApp>;
  const A = () => `Bearer ${cfg.auth.adminToken}`;

  beforeEach(() => {
    cfg = testConfig();
    settings = new SettingsStore(path.join(tempDir(), "settings.json"));
    sent = [];
    app = buildApp({
      config: cfg, store: new RouterStore(cfg.storePath), wg: new DryRunManager("wg0", true),
      settings, telegram: fakeTelegram(sent),
    });
  });

  it("verifies a token and lists chats without saving", async () => {
    const res = await request(app).post("/api/settings/telegram/verify")
      .set("authorization", A()).send({ botToken: "123456789:abcdefabcdefabcdef" });
    expect(res.status).toBe(200);
    expect(res.body.username).toBe("korvix_bot");
    expect(res.body.chats).toHaveLength(2);
    // not persisted
    expect(settings.telegram().botToken).toBe("");
  });

  it("saves routing and never leaks the token back", async () => {
    await request(app).post("/api/settings/telegram").set("authorization", A()).send({
      botToken: "123456789:secret-token-value",
      chats: [{ id: "-1001", title: "NOC alerts", type: "channel", events: { offline: true, login: true, online: false, registered: false, link: true } }],
    }).expect(200);

    expect(settings.telegram().botToken).toBe("123456789:secret-token-value");
    const get = await request(app).get("/api/settings").set("authorization", A());
    expect(get.body.telegram.hasToken).toBe(true);
    expect(get.body.telegram).not.toHaveProperty("botToken");
    expect(get.body.telegram.chats[0].events.offline).toBe(true);
  });

  it("test-send uses the saved token", async () => {
    await request(app).post("/api/settings/telegram").set("authorization", A()).send({
      botToken: "t", chats: [],
    }).expect(200);
    const res = await request(app).post("/api/settings/telegram/test").set("authorization", A()).send({ chatId: "555" });
    expect(res.status).toBe(200);
    expect(sent.at(-1)).toMatchObject({ chatId: "555" });
  });

  it("saves general notification preferences and reflects them", async () => {
    await request(app).post("/api/settings/general").set("authorization", A())
      .send({ notifyOnRegister: false, notifyOnline: true, suppressMinutes: 5 }).expect(200);
    const g = await request(app).get("/api/settings").set("authorization", A());
    expect(g.body.general).toMatchObject({ notifyOnRegister: false, notifyOnline: true, suppressMinutes: 5 });
    expect(g.body.monitor.intervalSeconds).toBeGreaterThan(0);
  });

  it("general prefs override the config default in the Alerter", async () => {
    settings.setGeneral({ notifyOnRegister: false, notifyOnline: null, suppressMinutes: null });
    const seen: string[] = [];
    const alerter = new (await import("../src/alerts.js")).Alerter(
      { notifyOnRegister: true, notifyOnline: true, suppressMinutes: 0 } as any,
      async (t: string) => { seen.push(t); }, settings,
    );
    const now = new Date().toISOString();
    const r: any = { serialNumber: "S", identity: "x", boardName: "b", rosVersion: "7", tunnelIp: "10.0.0.2", label: "L" };
    await alerter.routerRegistered(r, false); // pref says false → no alert even though config says true
    expect(seen).toHaveLength(0);
  });

  it("all settings endpoints are admin-only", async () => {
    expect((await request(app).get("/api/settings")).status).toBe(401);
    expect((await request(app).post("/api/settings/telegram").send({})).status).toBe(401);
    expect((await request(app).post("/api/settings/general").send({})).status).toBe(401);
  });
});

describe("Alerter Telegram routing", () => {
  function router(): RouterRecord {
    const now = new Date().toISOString();
    return { id: "1", serialNumber: "S1", publicKey: "k", boardName: "hEX", rosVersion: "7", identity: "site",
      tunnelIp: "10.99.0.2", username: "u", password: "p", state: "confirmed", createdAt: now, updatedAt: now, lastSeenAt: now, label: "Smith" };
  }

  it("routes each event only to chats subscribed to its category", async () => {
    const settings = new SettingsStore(path.join(tempDir(), "settings.json"));
    settings.setTelegram("bottoken", [
      { id: "chan", title: "NOC", type: "channel", events: { offline: true, online: false, registered: false, login: false, link: true } },
      { id: "dm", title: "Lockie", type: "private", events: { offline: true, online: true, registered: true, login: true, link: true } },
    ]);
    const sent: Array<{ chatId: string; text: string }> = [];
    const alerter = new Alerter({ notifyOnRegister: true, notifyOnline: true, suppressMinutes: 0 } as any, null, settings, fakeTelegram(sent));

    await alerter.routerTransition(router(), false); // offline → both chats
    expect(sent.map((s) => s.chatId).sort()).toEqual(["chan", "dm"]);

    sent.length = 0;
    await alerter.custom(router(), "login!", "login"); // login → only dm
    expect(sent.map((s) => s.chatId)).toEqual(["dm"]);

    sent.length = 0;
    await alerter.custom(router(), "port down", "link-down"); // link → both
    expect(sent.map((s) => s.chatId).sort()).toEqual(["chan", "dm"]);
  });
});
