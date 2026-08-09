// A raw stdio MCP client.
//
// This is NOT an SDK client. It is a byte-level driver, because half the
// battery consists of sending things an SDK would refuse to send. It gives
// tests:
//
//   * sendRaw(string)      -- exact bytes, no framing help, no validation
//   * send(obj)            -- one JSON object, newline framed
//   * waitFor(predicate)   -- deterministic synchronisation on a received
//                             message, NOT on elapsed time
//   * all messages, stdout bytes and stderr bytes retained for assertions
//
// Deterministic synchronisation note: every wait in this file is a wait for an
// OBSERVABLE EVENT (a matching message, or process exit). The only timeouts are
// failsafes to stop a hung CI job, and a test that relies on a failsafe firing
// is marked TIMING in its definition.

import { spawn } from 'node:child_process';
import { classify } from './jsonrpc.mjs';

const FAILSAFE_MS = Number(process.env.MCP_BATTERY_FAILSAFE_MS || 15000);

export class StdioPeer {
  constructor(command, args = [], opts = {}) {
    this.command = command;
    this.args = args;
    this.opts = opts;
    this.messages = [];        // parsed messages, in arrival order
    this.rawLines = [];        // every stdout line as received, pre-parse
    this.badLines = [];        // stdout lines that did not parse as JSON
    this.stderr = '';
    this.stdoutBytes = Buffer.alloc(0);
    this.exited = false;
    this.exitCode = null;
    this.exitSignal = null;
    this._buf = '';
    this._waiters = [];
    this._exitWaiters = [];
  }

  start() {
    this.proc = spawn(this.command, this.args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, ...(this.opts.env || {}) },
      cwd: this.opts.cwd,
    });
    this.proc.stdout.on('data', (chunk) => {
      this.stdoutBytes = Buffer.concat([this.stdoutBytes, chunk]);
      this._buf += chunk.toString('utf8');
      let idx;
      while ((idx = this._buf.indexOf('\n')) >= 0) {
        const line = this._buf.slice(0, idx);
        this._buf = this._buf.slice(idx + 1);
        this._onLine(line);
      }
    });
    this.proc.stderr.on('data', (c) => { this.stderr += c.toString('utf8'); });
    this.proc.on('exit', (code, signal) => {
      this.exited = true;
      this.exitCode = code;
      this.exitSignal = signal;
      for (const w of this._exitWaiters.splice(0)) w.resolve();
      // Wake message waiters so they fail fast instead of hanging to failsafe.
      for (const w of this._waiters.splice(0)) {
        w.reject(new Error(`peer exited (code=${code} signal=${signal}) while waiting for: ${w.label}`));
      }
    });
    this.proc.on('error', (err) => {
      this.spawnError = err;
      this.exited = true;
      for (const w of this._exitWaiters.splice(0)) w.resolve();
      for (const w of this._waiters.splice(0)) w.reject(err);
    });
    return this;
  }

  _onLine(line) {
    this.rawLines.push(line);
    const trimmed = line.replace(/\r$/, '');
    if (trimmed.trim() === '') return;      // blank line: recorded, not parsed
    let msg;
    try {
      msg = JSON.parse(trimmed);
    } catch {
      this.badLines.push(line);
      return;
    }
    this.messages.push(msg);
    for (let i = this._waiters.length - 1; i >= 0; i--) {
      const w = this._waiters[i];
      if (w.predicate(msg)) {
        this._waiters.splice(i, 1);
        w.resolve(msg);
      }
    }
  }

  /** Exact bytes. No newline appended. Tests append their own framing. */
  sendRaw(text) {
    this.proc.stdin.write(text);
    return this;
  }

  /** One JSON object as one newline-delimited frame. */
  send(obj) {
    this.proc.stdin.write((typeof obj === 'string' ? obj : JSON.stringify(obj)) + '\n');
    return this;
  }

  closeStdin() {
    this.proc.stdin.end();
    return this;
  }

  /**
   * Deterministic wait: resolves when a message matching `predicate` arrives.
   * Already-received messages are considered first, so there is no race
   * between sending and waiting.
   */
  waitFor(predicate, label = 'message', failsafeMs = FAILSAFE_MS) {
    for (const m of this.messages) {
      if (predicate(m)) return Promise.resolve(m);
    }
    return new Promise((resolve, reject) => {
      const w = { predicate, resolve, reject, label };
      this._waiters.push(w);
      const t = setTimeout(() => {
        const i = this._waiters.indexOf(w);
        if (i >= 0) this._waiters.splice(i, 1);
        reject(new Error(`failsafe timeout after ${failsafeMs}ms waiting for: ${label}`));
      }, failsafeMs);
      const clear = () => clearTimeout(t);
      const origResolve = w.resolve;
      const origReject = w.reject;
      w.resolve = (v) => { clear(); origResolve(v); };
      w.reject = (e) => { clear(); origReject(e); };
    });
  }

  /** Wait for the response (result or error) to a specific request id. */
  waitForId(id, failsafeMs = FAILSAFE_MS) {
    return this.waitFor(
      (m) => m && m.id === id && ('result' in m || 'error' in m),
      `response to id ${JSON.stringify(id)}`,
      failsafeMs,
    );
  }

  waitForExit(failsafeMs = FAILSAFE_MS) {
    if (this.exited) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const w = { resolve };
      this._exitWaiters.push(w);
      const t = setTimeout(() => {
        const i = this._exitWaiters.indexOf(w);
        if (i >= 0) this._exitWaiters.splice(i, 1);
        reject(new Error(`failsafe timeout after ${failsafeMs}ms waiting for peer exit`));
      }, failsafeMs);
      w.resolve = () => { clearTimeout(t); resolve(); };
    });
  }

  /**
   * Settle point. There is no observable event for "the peer has decided not
   * to reply", so tests that assert an ABSENCE need a bounded quiet period.
   * Any test using this is marked TIMING. Prefer waitFor wherever an event
   * exists.
   */
  async quiesce(ms = 400) {
    const before = this.messages.length;
    await new Promise((r) => setTimeout(r, ms));
    return this.messages.slice(before);
  }

  responsesFor(id) {
    return this.messages.filter((m) => m && m.id === id && ('result' in m || 'error' in m));
  }

  serverRequests() {
    return this.messages.filter((m) => classify(m) === 'request');
  }

  async stop() {
    if (this.exited || !this.proc) return;
    try { this.proc.stdin.end(); } catch { /* already closed */ }
    try {
      await this.waitForExit(2000);
    } catch {
      try { this.proc.kill('SIGKILL'); } catch { /* gone */ }
    }
  }
}

/** Parse a target spec like "python control_server.py" into command+args. */
export function parseLaunch(launch) {
  const parts = launch.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || [];
  const clean = parts.map((p) => p.replace(/^["']|["']$/g, ''));
  return { command: clean[0], args: clean.slice(1) };
}
