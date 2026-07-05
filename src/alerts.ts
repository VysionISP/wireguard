import type { Config } from "./config.js";
import type { RouterRecord } from "./types.js";

type AlertEvent = "offline" | "online" | "registered";

export type SendFn = (text: string, event: AlertEvent, router: RouterRecord) => Promise<void>;

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
  ) {}

  get enabled(): boolean {
    return Boolean(this.cfg.webhookUrl || (this.cfg.telegramBotToken && this.cfg.telegramChatId));
  }

  private async deliver(text: string, event: AlertEvent, router: RouterRecord): Promise<void> {
    if (this.send) return this.send(text, event, router);
    const jobs: Promise<unknown>[] = [];
    if (this.cfg.webhookUrl) {
      jobs.push(
        fetch(this.cfg.webhookUrl, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            text,
            event,
            router: { serialNumber: router.serialNumber, label: router.label ?? "", tunnelIp: router.tunnelIp },
          }),
          signal: AbortSignal.timeout(10000),
        }),
      );
    }
    if (this.cfg.telegramBotToken && this.cfg.telegramChatId) {
      jobs.push(
        fetch(`https://api.telegram.org/bot${this.cfg.telegramBotToken}/sendMessage`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ chat_id: this.cfg.telegramChatId, text }),
          signal: AbortSignal.timeout(10000),
        }),
      );
    }
    const results = await Promise.allSettled(jobs);
    for (const r of results) {
      if (r.status === "rejected") console.error(`alert delivery failed: ${r.reason}`);
    }
  }

  /** Called by the monitor on every recorded transition. */
  async routerTransition(router: RouterRecord, online: boolean): Promise<void> {
    if (!this.enabled) return;
    if (online && !this.cfg.notifyOnline) return;
    const key = `${router.serialNumber}:${online ? "online" : "offline"}`;
    const now = Date.now();
    const windowMs = this.cfg.suppressMinutes * 60_000;
    if (windowMs > 0 && now - (this.lastSent.get(key) ?? 0) < windowMs) return;
    this.lastSent.set(key, now);
    const text = online
      ? `🟢 ${routerName(router)} is back online (${router.tunnelIp})`
      : `🔴 ${routerName(router)} went OFFLINE (${router.tunnelIp})`;
    await this.deliver(text, online ? "online" : "offline", router);
  }

  async routerRegistered(router: RouterRecord, rereg: boolean): Promise<void> {
    if (!this.enabled || !this.cfg.notifyOnRegister) return;
    const text = rereg
      ? `🔄 ${routerName(router)} re-registered (${router.boardName}, ROS ${router.rosVersion}) — ${router.tunnelIp}`
      : `🆕 New router registered: ${routerName(router)} (${router.boardName}, ROS ${router.rosVersion}) — ${router.tunnelIp}`;
    await this.deliver(text, "registered", router);
  }
}
