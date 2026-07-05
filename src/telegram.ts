/** Minimal Telegram Bot API helper (getMe, discover chats, send message). */

export interface TgChat {
  id: string;
  title: string;
  type: string;
}

export interface TelegramClient {
  getMe(token: string): Promise<{ username: string }>;
  getChats(token: string): Promise<TgChat[]>;
  send(token: string, chatId: string, text: string): Promise<void>;
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
};
