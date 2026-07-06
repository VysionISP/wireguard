import type { IssueStore, Issue } from "./issues.js";
import type { EventLog } from "./events.js";
import type { SettingsStore } from "./settings.js";
import type { AuditLog } from "./audit.js";
import type { Config } from "./config.js";
import { telegram as realTelegram, type TelegramClient, type TgChat } from "./telegram.js";
import { maintCategory } from "./maintenance.js";

/**
 * Escalation: a critical issue nobody acknowledges within
 * `escalateAfterMinutes` is re-announced — louder, with an inline **Ack**
 * button on Telegram — and keeps re-announcing every `escalateEveryMinutes`
 * (up to `maxEscalations`) until someone acks or it resolves.
 *
 * The same engine runs the Telegram callback poller that makes the Ack button
 * work, and caches every chat it sees so the Settings "Verify & fetch chats"
 * flow still finds chats even though the poller consumes getUpdates.
 */

export interface EscalationDeps {
  issues: IssueStore;
  events: EventLog;
  settings: SettingsStore;
  audit: AuditLog;
  cfg: Config["alerts"];
  tg?: TelegramClient;
  /** Generic webhook receives escalations too (when configured). */
  webhookUrl?: string;
  /** Maintenance-window suppression (issues under a window don't escalate). */
  suppressed?: (serial: string, group: string | undefined, category: string) => boolean;
  /** Look up a router's customer group for the suppression check. */
  groupOf?: (serial: string) => string | undefined;
}

function fmtAge(ms: number): string {
  const m = Math.floor(ms / 60000);
  return m >= 60 ? `${Math.floor(m / 60)}h ${m % 60}m` : `${m}m`;
}

export class EscalationEngine {
  /** issueId -> {count, lastAt} — in-memory; a restart just re-escalates. */
  private state = new Map<string, { count: number; lastAt: number }>();
  private offset = 0;
  private pollToken = "";
  private polling = false;
  private stopped = false;
  /** Chats observed by the poller — merged into Settings chat discovery. */
  readonly seenChats = new Map<string, TgChat>();

  constructor(private readonly deps: EscalationDeps) {}

  private get tg(): TelegramClient {
    return this.deps.tg ?? realTelegram;
  }

  /** One escalation pass; exported for tests. */
  async tick(nowMs = Date.now()): Promise<number> {
    const { cfg, issues } = this.deps;
    if (!cfg.escalateAfterMinutes) return 0;
    const open = issues.list(false).filter((i) => {
      if (i.severity !== "critical" || i.ackedAt) return false;
      // Don't escalate an issue muted by a maintenance window (a device that
      // dropped before planned work shouldn't page all night).
      return !this.deps.suppressed?.(i.serialNumber, this.deps.groupOf?.(i.serialNumber), maintCategory(i.type));
    });
    // Drop state for issues that no longer exist / got acked or resolved.
    const openIds = new Set(open.map((i) => i.id));
    for (const id of this.state.keys()) if (!openIds.has(id)) this.state.delete(id);

    let sent = 0;
    for (const issue of open) {
      const ageMs = nowMs - Date.parse(issue.openedAt);
      if (ageMs < cfg.escalateAfterMinutes * 60000) continue;
      const st = this.state.get(issue.id) ?? { count: 0, lastAt: 0 };
      if (st.count >= cfg.maxEscalations) continue;
      const gapMs = (st.count === 0 ? 0 : cfg.escalateEveryMinutes * 60000);
      if (st.count > 0 && nowMs - st.lastAt < gapMs) continue;
      st.count++;
      st.lastAt = nowMs;
      this.state.set(issue.id, st);
      await this.announce(issue, ageMs, st.count);
      sent++;
    }
    return sent;
  }

  private async announce(issue: Issue, ageMs: number, nth: number): Promise<void> {
    const text = `🚨 ESCALATION ${nth}/${this.deps.cfg.maxEscalations} — UNACKED for ${fmtAge(ageMs)}\n${issue.label}: ${issue.message}\nAck it or it re-pages every ${this.deps.cfg.escalateEveryMinutes}m.`;
    this.deps.events.add({
      at: new Date().toISOString(),
      serialNumber: issue.serialNumber,
      label: issue.label,
      type: "monitor-error",
      severity: "warning",
      message: `Escalated (${nth}): ${issue.message} — unacked ${fmtAge(ageMs)}`,
    });
    const jobs: Promise<unknown>[] = [];
    if (this.deps.webhookUrl) {
      jobs.push(
        fetch(this.deps.webhookUrl, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ text, event: "escalation", issue: { id: issue.id, serialNumber: issue.serialNumber, type: issue.type, message: issue.message } }),
          signal: AbortSignal.timeout(10000),
        }).catch((err) => console.error(`escalation webhook failed: ${(err as Error).message}`)),
      );
    }
    const tgSettings = this.deps.settings.telegram();
    if (tgSettings.botToken) {
      // Escalations go to every chat subscribed to "offline" (the paging category).
      for (const chat of tgSettings.chats) {
        if (!chat.events?.offline) continue;
        const send = this.tg.sendWithButtons
          ? this.tg.sendWithButtons(tgSettings.botToken, chat.id, text, [{ text: "✅ Ack", data: `ack:${issue.id}` }])
          : this.tg.send(tgSettings.botToken, chat.id, text);
        jobs.push(send.catch((err) => console.error(`escalation telegram (${chat.title || chat.id}) failed: ${(err as Error).message}`)));
      }
    }
    await Promise.allSettled(jobs);
  }

  /** Handle a Telegram button press. Exported for tests. */
  async handleCallback(cb: { id: string; data: string; from: string; chatId: string; messageId: number }, token: string): Promise<void> {
    const m = /^ack:(.+)$/.exec(cb.data);
    if (!m) return;
    const issue = this.deps.issues.list(true).find((i) => i.id === m[1]);
    const who = `tg:${cb.from}`;
    let reply: string;
    if (!issue) reply = "Issue not found (already cleared?)";
    else if (issue.resolvedAt) reply = "Already resolved";
    else if (issue.ackedAt) reply = `Already acked by ${issue.ackedBy}`;
    else if (this.deps.issues.ack(issue.id, who)) {
      reply = "Acknowledged ✔";
      this.deps.audit.log(who, "issue.ack", issue.serialNumber, issue.type);
      this.deps.events.add({
        at: new Date().toISOString(),
        serialNumber: issue.serialNumber,
        label: issue.label,
        type: "monitor-error",
        severity: "info",
        message: `Acknowledged by ${who} via Telegram`,
      });
      if (cb.messageId && this.tg.editText) {
        await this.tg.editText(token, cb.chatId, cb.messageId, `✅ ACKED by ${cb.from}\n${issue.label}: ${issue.message}`).catch(() => {});
      }
    } else reply = "Could not ack";
    await this.tg.answerCallback?.(token, cb.id, reply).catch(() => {});
  }

  /** Long-poll Telegram for button presses (and cache chats we see). */
  private async pollLoop(): Promise<void> {
    if (this.polling) return;
    this.polling = true;
    while (!this.stopped) {
      const token = this.deps.settings.telegram().botToken;
      if (!token || !this.tg.pollUpdates) {
        await new Promise((r) => setTimeout(r, 15000));
        continue;
      }
      if (token !== this.pollToken) {
        this.pollToken = token;
        this.offset = 0;
      }
      try {
        const r = await this.tg.pollUpdates(token, this.offset, 25);
        this.offset = r.nextOffset;
        for (const c of r.chats) this.seenChats.set(c.id, c);
        for (const cb of r.callbacks) await this.handleCallback(cb, token);
      } catch (err) {
        console.error(`telegram poller: ${(err as Error).message}`);
        await new Promise((r) => setTimeout(r, 15000));
      }
    }
    this.polling = false;
  }

  start(intervalSeconds = 60): () => void {
    const timer = setInterval(() => {
      this.tick().catch((err) => console.error(`escalation: ${(err as Error).message}`));
    }, intervalSeconds * 1000);
    timer.unref?.();
    void this.pollLoop();
    return () => {
      this.stopped = true;
      clearInterval(timer);
    };
  }
}
