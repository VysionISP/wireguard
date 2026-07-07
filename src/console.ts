import crypto from "node:crypto";
import type { Response } from "express";
import { sshShell, type ShellSession, type SshShellFn } from "./ssh.js";

/**
 * Live web-console sessions: each one is a real interactive SSH PTY to a
 * router, streamed to the browser over SSE with keystrokes POSTed back. The
 * browser side renders it with xterm.js, so techs get the actual RouterOS
 * CLI — tab-completion, `?` help, menus — not an emulation.
 */

interface Session {
  sid: string;
  serial: string;
  shell: ShellSession;
  /** Rolling scrollback so a reconnecting SSE picks up where it was. */
  buffer: Buffer[];
  bufferBytes: number;
  subscribers: Set<Response>;
  lastActive: number;
  closed: boolean;
}

const MAX_BUFFER = 256 * 1024;
const IDLE_MS = 15 * 60_000;

export class ConsoleManager {
  private sessions = new Map<string, Session>();
  private sweeper: NodeJS.Timeout;

  constructor(private readonly shellFn: SshShellFn = sshShell) {
    this.sweeper = setInterval(() => this.sweep(), 60_000);
    this.sweeper.unref?.();
  }

  async open(
    host: string,
    username: string,
    password: string,
    serial: string,
    cols = 120,
    rows = 32,
  ): Promise<string> {
    const shell = await this.shellFn(host, username, password, cols, rows);
    const sid = crypto.randomBytes(18).toString("base64url");
    const s: Session = { sid, serial, shell, buffer: [], bufferBytes: 0, subscribers: new Set(), lastActive: Date.now(), closed: false };
    shell.onData((chunk) => {
      s.lastActive = Date.now();
      s.buffer.push(chunk);
      s.bufferBytes += chunk.length;
      while (s.bufferBytes > MAX_BUFFER && s.buffer.length > 1) {
        s.bufferBytes -= s.buffer[0].length;
        s.buffer.shift();
      }
      const payload = `data: ${JSON.stringify({ d: chunk.toString("base64") })}\n\n`;
      for (const res of s.subscribers) res.write(payload);
    });
    shell.onClose(() => this.end(s, "closed by router"));
    this.sessions.set(sid, s);
    return sid;
  }

  /** Attach an SSE response: replay scrollback, then stream live. */
  attach(sid: string, res: Response): boolean {
    const s = this.sessions.get(sid);
    if (!s || s.closed) return false;
    if (s.buffer.length) {
      const replay = Buffer.concat(s.buffer).toString("base64");
      res.write(`data: ${JSON.stringify({ d: replay })}\n\n`);
    }
    s.subscribers.add(res);
    res.on("close", () => s.subscribers.delete(res));
    return true;
  }

  input(sid: string, data: string): boolean {
    const s = this.sessions.get(sid);
    if (!s || s.closed) return false;
    s.lastActive = Date.now();
    s.shell.write(data);
    return true;
  }

  resize(sid: string, cols: number, rows: number): boolean {
    const s = this.sessions.get(sid);
    if (!s || s.closed) return false;
    s.shell.resize(cols, rows);
    return true;
  }

  close(sid: string): boolean {
    const s = this.sessions.get(sid);
    if (!s) return false;
    this.end(s, "closed");
    return true;
  }

  serialOf(sid: string): string | undefined {
    return this.sessions.get(sid)?.serial;
  }

  private end(s: Session, reason: string): void {
    if (s.closed) return;
    s.closed = true;
    try {
      s.shell.close();
    } catch {
      /* already gone */
    }
    const bye = `data: ${JSON.stringify({ end: reason })}\n\n`;
    for (const res of s.subscribers) {
      res.write(bye);
      res.end();
    }
    s.subscribers.clear();
    this.sessions.delete(s.sid);
  }

  /** Kill sessions idle past the cap so forgotten tabs don't pin SSH forever. */
  private sweep(): void {
    const cutoff = Date.now() - IDLE_MS;
    for (const s of [...this.sessions.values()]) if (s.lastActive < cutoff) this.end(s, "idle timeout");
  }
}
