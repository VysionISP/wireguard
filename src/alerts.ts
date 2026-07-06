import type { Config } from "./config.js";
import type { RouterRecord } from "./types.js";
import type { SettingsStore, RouteKey } from "./settings.js";
import { telegram as realTelegram, type TelegramClient } from "./telegram.js";

type AlertEvent =
  | "offline"
  | "online"
  | "registered"
  | "login"
  | "link-down"
  | "link-up"
  | "traffic-high"
  | "traffic-low"
  | "host-down"
  | "host-up";

export type SendFn = (text: string, event: AlertEvent, router: RouterRecord) => Promise<void>;

/** Maps an alert event to the notification category a chat subscribes to. */
export function routeKey(event: AlertEvent): RouteKey {
  // Link flaps and traffic-threshold alerts are both port-health signals and
  // share the "link" subscription category.
  if (event === "link-down" || event === "link-up" || event === "traffic-high" || event === "traffic-low") return "link";
  // Monitored internal hosts going down/up ride the offline/online categories.
  if (event === "host-down") return "offline";
  if (event === "host-up") return "online";
  return event;
}

function routerName(r: RouterRecord): string {
  return r.label ? `${r.label} (${r.serialNumber})` : `${r.serialNumber} / ${r.identity}`;
}

/**
 * Fans alert events out to the configured channels (generic webhook and/or
 * Telegram), with a per-router-per-direction suppression window so a
 * flapping link produces at most one offline + one online alert per window.
 */
export class Alerter {
  private lastSent = new Map<string, number>();

  constructor(
    private readonly cfg: Config["alerts"],
    /** Injectable for tests; defaults to real webhook/Telegram delivery. */
    private readonly send: SendFn | null = null,
    /** Dashboard-configured Telegram routing (optional). */
    private readonly settings: SettingsStore | null = null,
    private readonly tg: TelegramClient = realTelegram,
  ) {}

  // Notification prefs: a dashboard-set value wins over the config.json default.
  private get notifyOnRegisterPref(): boolean {
    return this.settings?.general().notifyOnRegister ?? this.cfg.notifyOnRegister;
  }
  private get notifyOnlinePref(): boolean {
    return this.settings?.general().notifyOnline ?? this.cfg.notifyOnline;
  }
  private get suppressMinutesPref(): number {
    return this.settings?.general().suppressMinutes ?? this.cfg.suppressMinutes;
  }

  get enabled(): boolean {
    const tg = this.settings?.telegram();
    const settingsTelegram = Boolean(tg?.botToken && tg.chats.length);
    return Boolean(
      this.cfg.webhookUrl ||
        (this.cfg.telegramBotToken && this.cfg.telegramChatId) ||
        settingsTelegram,
    );
  }

  /**
   * Run one delivery with a retry: transient failures (DNS blip, timeout,
   * Telegram 5xx) get a second attempt after a short pause, and every failure
   * is logged with WHICH destination failed so "fetch failed" is debuggable.
   */
  private async attempt(name: string, job: () => Promise<unknown>): Promise<boolean> {
    for (let n = 1; n <= 2; n++) {
      try {
        await job();
        return true;
      } catch (err) {
        const msg = err instanceof Error ? (err.cause ? `${err.message} (${(err.cause as Error).message ?? err.cause})` : err.message) : String(err);
        console.error(`alert delivery failed (${name}, attempt ${n}/2): ${msg}`);
        if (n === 1) await new Promise((r) => setTimeout(r, 3000));
      }
    }
    return false;
  }

  private async deliver(text: string, event: AlertEvent, router: RouterRecord): Promise<void> {
    if (this.send) return this.send(text, event, router);
    const jobs: Promise<unknown>[] = [];
    if (this.cfg.webhookUrl) {
      const url = this.cfg.webhookUrl;
      jobs.push(
        this.attempt("webhook", () =>
          fetch(url, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              text,
              event,
              router: { serialNumber: router.serialNumber, label: router.label ?? "", tunnelIp: router.tunnelIp },
            }),
            signal: AbortSignal.timeout(10000),
          }).then((res) => {
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
          }),
        ),
      );
    }
    if (this.cfg.telegramBotToken && this.cfg.telegramChatId) {
      const { telegramBotToken, telegramChatId } = this.cfg;
      jobs.push(this.attempt(`telegram:${telegramChatId}`, () => this.tg.send(telegramBotToken!, telegramChatId!, text)));
    }
    // Dashboard-configured routing: send to each chat subscribed to this
    // event category.
    const tgSettings = this.settings?.telegram();
    if (tgSettings?.botToken) {
      const key = routeKey(event);
      for (const chat of tgSettings.chats) {
        if (chat.events?.[key]) {
          jobs.push(this.attempt(`telegram:${chat.title || chat.id}`, () => this.tg.send(tgSettings.botToken, chat.id, text)));
        }
      }
    }
    await Promise.allSettled(jobs);
  }

  /** Called by the monitor on every recorded transition. */
  async routerTransition(router: RouterRecord, online: boolean): Promise<void> {
    if (!this.enabled) return;
    if (online && !this.notifyOnlinePref) return;
    const key = `${router.serialNumber}:${online ? "online" : "offline"}`;
    const now = Date.now();
    const windowMs = this.suppressMinutesPref * 60_000;
    if (windowMs > 0 && now - (this.lastSent.get(key) ?? 0) < windowMs) return;
    this.lastSent.set(key, now);
    const text = online
      ? `🟢 ${routerName(router)} is back online (${router.tunnelIp})`
      : `🔴 ${routerName(router)} went OFFLINE (${router.tunnelIp})`;
    await this.deliver(text, online ? "online" : "offline", router);
  }

  /**
   * Generic alert used by the device monitor (logins, link flaps). An
   * optional suppressKey applies the same flap-guard window as transitions;
   * omit it (logins) to always deliver.
   */
  async custom(router: RouterRecord, text: string, event: AlertEvent, suppressKey?: string): Promise<void> {
    if (!this.enabled) return;
    if (suppressKey && this.suppressMinutesPref > 0) {
      const now = Date.now();
      const windowMs = this.suppressMinutesPref * 60_000;
      if (now - (this.lastSent.get(suppressKey) ?? 0) < windowMs) return;
      this.lastSent.set(suppressKey, now);
    }
    await this.deliver(text, event, router);
  }

  async routerRegistered(router: RouterRecord, rereg: boolean): Promise<void> {
    if (!this.enabled || !this.notifyOnRegisterPref) return;
    const text = rereg
      ? `🔄 ${routerName(router)} re-registered (${router.boardName}, ROS ${router.rosVersion}) — ${router.tunnelIp}`
      : `🆕 New router registered: ${routerName(router)} (${router.boardName}, ROS ${router.rosVersion}) — ${router.tunnelIp}`;
    await this.deliver(text, "registered", router);
  }
}
