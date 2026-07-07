import { Client } from "ssh2";

export interface SshResult {
  ok: boolean;
  output: string;
}

export type SshRunFn = (
  host: string,
  username: string,
  password: string,
  command: string,
  timeoutMs?: number,
) => Promise<SshResult>;

export type SftpPutFn = (
  host: string,
  username: string,
  password: string,
  content: Buffer,
  remotePath: string,
  timeoutMs?: number,
) => Promise<void>;

function connect(host: string, username: string, password: string, timeoutMs: number): Promise<Client> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    const timer = setTimeout(() => {
      conn.end();
      reject(new Error("ssh connect timeout"));
    }, timeoutMs);
    conn
      .on("ready", () => {
        clearTimeout(timer);
        resolve(conn);
      })
      .on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      })
      .connect({ host, username, password, readyTimeout: timeoutMs });
  });
}

/** A live interactive shell channel to a router (PTY over SSH). */
export interface ShellSession {
  write(data: string): void;
  resize(cols: number, rows: number): void;
  close(): void;
  onData(cb: (chunk: Buffer) => void): void;
  onClose(cb: () => void): void;
}

export type SshShellFn = (
  host: string,
  username: string,
  password: string,
  cols: number,
  rows: number,
  timeoutMs?: number,
) => Promise<ShellSession>;

/**
 * Opens an interactive PTY shell on a RouterOS device — the real CLI, with
 * its own tab-completion, `?` help and menu system. The web console streams
 * this channel to the browser.
 */
export const sshShell: SshShellFn = async (host, username, password, cols, rows, timeoutMs = 15000) => {
  const conn = await connect(host, username, password, timeoutMs);
  return await new Promise<ShellSession>((resolve, reject) => {
    conn.shell({ term: "xterm-256color", cols, rows }, (err, stream) => {
      if (err) {
        conn.end();
        return reject(err);
      }
      const dataCbs: Array<(chunk: Buffer) => void> = [];
      const closeCbs: Array<() => void> = [];
      stream.on("data", (d: Buffer) => dataCbs.forEach((cb) => cb(d)));
      stream.stderr.on("data", (d: Buffer) => dataCbs.forEach((cb) => cb(d)));
      const done = () => {
        closeCbs.forEach((cb) => cb());
        closeCbs.length = 0;
        conn.end();
      };
      stream.on("close", done);
      conn.on("error", done);
      resolve({
        write: (data) => stream.write(data),
        resize: (c, r) => stream.setWindow(r, c, 0, 0),
        close: () => {
          stream.end();
          conn.end();
        },
        onData: (cb) => dataCbs.push(cb),
        onClose: (cb) => closeCbs.push(cb),
      });
    });
  });
};

/** Runs one command on a RouterOS device over SSH, capturing all output. */
export const sshRun: SshRunFn = async (host, username, password, command, timeoutMs = 20000) => {
  const conn = await connect(host, username, password, timeoutMs);
  try {
    return await new Promise<SshResult>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("ssh command timeout")), timeoutMs);
      conn.exec(command, (err, stream) => {
        if (err) {
          clearTimeout(timer);
          return reject(err);
        }
        let output = "";
        stream
          .on("data", (d: Buffer) => (output += d.toString()))
          .stderr.on("data", (d: Buffer) => (output += d.toString()));
        stream.on("close", (code: number | null) => {
          clearTimeout(timer);
          resolve({ ok: code === 0 || code === null, output: output.trim() });
        });
      });
    });
  } finally {
    conn.end();
  }
};

/** Uploads a file to the router (used to stage config restores). */
export const sftpPut: SftpPutFn = async (host, username, password, content, remotePath, timeoutMs = 20000) => {
  const conn = await connect(host, username, password, timeoutMs);
  try {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("sftp timeout")), timeoutMs);
      conn.sftp((err, sftp) => {
        if (err) {
          clearTimeout(timer);
          return reject(err);
        }
        sftp.writeFile(remotePath, content, (werr) => {
          clearTimeout(timer);
          werr ? reject(werr) : resolve();
        });
      });
    });
  } finally {
    conn.end();
  }
};
