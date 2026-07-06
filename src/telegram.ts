/** Minimal Telegram Bot API helper (getMe, discover chats, send message). */

export interface TgChat {
  id: string;
  title: string;
  type: string;
}

export interface TgCallback {
  id: string;
  data: string;
  from: string;
  chatId: string;
  messageId: number;
}

export interface TgUpdatesResult {
  nextOffset: number;
  chats: TgChat[];
  callbacks: TgCallback[];
}

export interface TelegramClient {
  getMe(token: string): Promise<{ username: string }>;
  getChats(token: string): Promise<TgChat[]>;
  send(token: string, chatId: string, text: string): Promise<void>;
  /** Send with inline buttons: [{text, data}] rendered as one callback row. */
  sendWithButtons?(token: string, chatId: string, text: string, buttons: Array<{ text: string; data: string }>): Promise<void>;
  /** Long-poll updates from `offset`; extracts chats + button callbacks. */
  pollUpdates?(token: string, offset: number, timeoutSec: number): Promise<TgUpdatesResult>;
  /** Acknowledge a button press (stops the client-side spinner). */
  answerCallback?(token: string, callbackId: string, text: string): Promise<void>;
  /** Replace a message's text (used to mark an alert as acked). */
  editText?(token: string, chatId: string, messageId: number, text: string): Promise<void>;
}

const API = "https://api.telegram.org";

async function call(token: string, method: string, body?: unknown, timeoutMs = 10000): Promise<any> {
  const res = await fetch(`${API}/bot${token}/${method}`, {
    method: body ? "POST" : "GET",
    headers: body ? { "content-type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(timeoutMs),
  });
  const data = (await res.json().catch(() => ({}))) as { ok?: boolean; result?: unknown; description?: string };
  if (!res.ok || !data.ok) {
    throw new Error(data.description || `Telegram ${method} failed (${res.status})`);
  }
  return data.result;
}

function chatLabel(chat: Record<string, string>): string {
  return chat.title || chat.username || [chat.first_name, chat.last_name].filter(Boolean).join(" ") || String(chat.id);
}

export const telegram: TelegramClient = {
  async getMe(token) {
    const me = (await call(token, "getMe")) as { username?: string };
    return { username: me.username ?? "unknown" };
  },

  /**
   * Discovers chats the bot can post to by reading recent updates. The bot
   * must have received at least one message / been added to the group or
   * channel (as admin) for the chat to appear here — this is the only way a
   * bot can enumerate its chats.
   */
  async getChats(token) {
    const updates = (await call(token, "getUpdates")) as Array<Record<string, any>>;
    const byId = new Map<string, TgChat>();
    for (const u of updates) {
      const chat =
        u.message?.chat ?? u.channel_post?.chat ?? u.my_chat_member?.chat ?? u.edited_message?.chat;
      if (chat && chat.id != null) {
        const id = String(chat.id);
        byId.set(id, { id, title: chatLabel(chat), type: chat.type ?? "?" });
      }
    }
    return [...byId.values()];
  },

  async send(token, chatId, text) {
    await call(token, "sendMessage", { chat_id: chatId, text });
  },

  async sendWithButtons(token, chatId, text, buttons) {
    await call(token, "sendMessage", {
      chat_id: chatId,
      text,
      reply_markup: { inline_keyboard: [buttons.map((b) => ({ text: b.text, callback_data: b.data }))] },
    });
  },

  async pollUpdates(token, offset, timeoutSec) {
    const updates = (await call(
      token,
      "getUpdates",
      { offset, timeout: timeoutSec, allowed_updates: ["message", "channel_post", "my_chat_member", "callback_query"] },
      (timeoutSec + 10) * 1000,
    )) as Array<Record<string, any>>;
    let nextOffset = offset;
    const chats = new Map<string, TgChat>();
    const callbacks: TgCallback[] = [];
    for (const u of updates) {
      if (typeof u.update_id === "number") nextOffset = Math.max(nextOffset, u.update_id + 1);
      const chat = u.message?.chat ?? u.channel_post?.chat ?? u.my_chat_member?.chat ?? u.callback_query?.message?.chat;
      if (chat && chat.id != null) {
        const id = String(chat.id);
        chats.set(id, { id, title: chatLabel(chat), type: chat.type ?? "?" });
      }
      const cq = u.callback_query;
      if (cq?.id && typeof cq.data === "string") {
        callbacks.push({
          id: String(cq.id),
          data: cq.data,
          from: cq.from?.username || [cq.from?.first_name, cq.from?.last_name].filter(Boolean).join(" ") || "telegram-user",
          chatId: String(cq.message?.chat?.id ?? ""),
          messageId: Number(cq.message?.message_id ?? 0),
        });
      }
    }
    return { nextOffset, chats: [...chats.values()], callbacks };
  },

  async answerCallback(token, callbackId, text) {
    await call(token, "answerCallbackQuery", { callback_query_id: callbackId, text });
  },

  async editText(token, chatId, messageId, text) {
    await call(token, "editMessageText", { chat_id: chatId, message_id: messageId, text });
  },
};
