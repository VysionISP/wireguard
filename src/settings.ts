import fs from "node:fs";
import path from "node:path";

/** Notification categories a chat can be subscribed to (see routeKey). */
export const ROUTE_KEYS = ["registered", "offline", "online", "login", "link"] as const;
export type RouteKey = (typeof ROUTE_KEYS)[number];

export interface RouteChat {
  id: string;
  title: string;
  type: string;
  events: Record<RouteKey, boolean>;
}

export interface TelegramSettings {
  botToken: string;
  chats: RouteChat[];
}

/** Notification preferences; null on a field means "use the config.json default". */
export interface GeneralSettings {
  notifyOnRegister: boolean | null;
  notifyOnline: boolean | null;
  suppressMinutes: number | null;
}

export interface Settings {
  telegram: TelegramSettings;
  general: GeneralSettings;
}

function empty(): Settings {
  return {
    telegram: { botToken: "", chats: [] },
    general: { notifyOnRegister: null, notifyOnline: null, suppressMinutes: null },
  };
}

/**
 * Runtime, dashboard-editable settings (Telegram routing). Kept separate from
 * the hand-edited config.json so the UI can own it without rewriting config.
 */
export class SettingsStore {
  private settings: Settings = empty();

  constructor(private readonly filePath: string) {
    if (fs.existsSync(filePath)) {
      try {
        this.settings = { ...empty(), ...JSON.parse(fs.readFileSync(filePath, "utf8")) };
      } catch {
        this.settings = empty();
      }
    }
  }

  private persist(): void {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.settings, null, 2));
    fs.renameSync(tmp, this.filePath);
  }

  get(): Settings {
    return this.settings;
  }

  telegram(): TelegramSettings {
    return this.settings.telegram;
  }

  setTelegram(botToken: string, chats: RouteChat[]): void {
    this.settings.telegram = { botToken, chats };
    this.persist();
  }

  general(): GeneralSettings {
    return this.settings.general ?? { notifyOnRegister: null, notifyOnline: null, suppressMinutes: null };
  }

  setGeneral(g: GeneralSettings): void {
    this.settings.general = g;
    this.persist();
  }
}
