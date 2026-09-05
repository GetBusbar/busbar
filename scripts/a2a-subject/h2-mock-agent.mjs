#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// A MINIMAL, JWS-SIGNED A2A AGENT FOR THE H2 GATING SCENARIOS (tracker row H2,
// ARCHITECTURE.md #2.2).
//
// WHY THE CARD IS SIGNED. `pin.mechanism: unpinned` is a real, documented A2A pin, but
// `crates/busbar-a2a/src/a2a/pin.rs` caps it on purpose: "An Unpinned registration ... can never be
// approved" (`CardPin::Unpinned` has no `is_a_root()`). A registration this rig needs Busbar to
// actually SERVE therefore needs a real authenticity root, and the one that works over plaintext
// loopback with no PKI relationship is a JWS-signed card under an Ed25519 issuer key the operator
// holds out of band -- exactly what scripts/a2a-subject/signing-vendor.mjs already does for the
// official a2a-subject boot. This file borrows that EXACT canonicalization (`jcs`) and signing shape
// (`signCard`) rather than re-deriving it, so there is one implementation of "how busbar's JWS pin
// verifies a card" in this tree, not two that can drift.
//
// EGRESS CAPTURE, the same on-disk contract testing/shadow-oracle/mock-upstream.py and
// scripts/mcp-subject/h2-mock-upstream.mjs use: when A2A_MOCK_CAPTURE_DIR is set, every request this
// process receives (GET or POST) is written as its own JSON file `{ts}-{pid}-{seq}.json` holding
// `{path, method, headers, body}`.
//
// CONTROL: a control file (arg 2), if it exists and its contents (trimmed, lower-cased) are `down`,
// answers every `message/send` POST with a 502 (an unreachable-agent response a real vendor would
// give under a hard outage) instead of dispatching -- used by the route-failover scenario to trip
// the breaker. Checked per request, so a scenario can flip it mid-run with no restart.
//
// Usage: node h2-mock-agent.mjs <port> [control-file] [issuer-key-out]
import { createServer } from 'node:http';
import { generateKeyPairSync, sign, randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync, renameSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const [portArg, controlFile, keyOut] = process.argv.slice(2);
const PORT = Number(portArg);
if (!PORT) {
  console.error('usage: h2-mock-agent.mjs <port> [control-file] [issuer-key-out]');
  process.exit(2);
}

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const spkiB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
if (keyOut) writeFileSync(keyOut, spkiB64);
// Always printed too, so a caller that did not pass keyOut can still capture it off stdout.
console.log(`ISSUER_KEY ${spkiB64}`);

const b64url = (b) => Buffer.from(b).toString('base64url');

// RFC 8785, the subset a card needs. Byte-identical to signing-vendor.mjs's jcs() and to
// a2a/canonical.rs's own canonicalization.
function jcs(v) {
  if (v === null) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error('non-finite');
    if (Number.isInteger(v) && Math.abs(v) < 1e21) return String(v);
    return JSON.stringify(v);
  }
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  const names = Object.keys(v).sort((a, b) => {
    const ua = Buffer.from(a, 'utf16le'); const ub = Buffer.from(b, 'utf16le');
    return ua.compare(ub);
  });
  return '{' + names.map((n) => JSON.stringify(n) + ':' + jcs(v[n])).join(',') + '}';
}

function signCard(card) {
  const stripped = { ...card };
  delete stripped.signatures;
  const payload = b64url(jcs(stripped));
  const protectedB64 = b64url(jcs({ alg: 'EdDSA', kid: 'h2-fixture' }));
  const sig = sign(null, Buffer.from(`${protectedB64}.${payload}`), privateKey);
  return { ...card, signatures: [{ protected: protectedB64, signature: b64url(sig) }] };
}

function baseCard(baseUrl) {
  return {
    name: 'H2 Fixture Agent',
    description: 'A minimal, fully-controlled A2A agent used by busbar\'s own H2 gating scenarios '
      + '(tracker row H2). Not a conformance control peer.',
    url: baseUrl,
    version: '1.0.0',
    capabilities: { streaming: false, pushNotifications: false, extendedAgentCard: false },
    defaultInputModes: ['text/plain'],
    defaultOutputModes: ['text/plain'],
    skills: [{ id: 'echo', name: 'Echo', description: 'Returns the text it was given, unchanged.',
               tags: ['echo', 'h2'] }],
  };
}

let seq = 0;
function captureEgress(method, url, headers, body) {
  const dir = process.env.A2A_MOCK_CAPTURE_DIR;
  if (!dir) return;
  try {
    mkdirSync(dir, { recursive: true });
    const record = { path: url, method, headers, body };
    const name = `${process.hrtime.bigint()}-${process.pid}-${seq++}.json`;
    const tmp = join(dir, `.${name}.tmp`);
    writeFileSync(tmp, JSON.stringify(record));
    renameSync(tmp, join(dir, name));
  } catch {
    // best-effort
  }
}

function send(res, status, obj) {
  const raw = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': raw.length });
  res.end(raw);
}

function isDown() {
  if (!controlFile || !existsSync(controlFile)) return false;
  try {
    return readFileSync(controlFile, 'utf8').trim().toLowerCase() === 'down';
  } catch {
    return false;
  }
}

const server = createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const raw = Buffer.concat(chunks).toString('utf8');
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) headers[k.toLowerCase()] = v;
    captureEgress(req.method, req.url, headers, raw);

    if (req.method === 'GET' && req.url.endsWith('/.well-known/agent-card.json')) {
      const base = `http://127.0.0.1:${server.address().port}/`;
      return send(res, 200, signCard(baseCard(base)));
    }
    if (req.method !== 'POST') {
      res.writeHead(404, { 'content-length': 0 });
      return res.end();
    }
    let body = {};
    try { body = raw ? JSON.parse(raw) : {}; } catch { body = {}; }
    const rid = body.id ?? null;
    const method = body.method;
    if (isDown()) {
      return send(res, 502, { jsonrpc: '2.0', id: rid,
        error: { code: -32603, message: 'h2 fixture agent: down' } });
    }
    if (method === 'message/send' || method === 'SendMessage' || (req.url || '').endsWith('message:send')) {
      const params = body.params || {};
      const message = params.message || {};
      const text = (message.parts || []).map((p) => p.text || '').join('');
      const task = {
        id: randomUUID(),
        contextId: randomUUID(),
        status: { state: 'TASK_STATE_COMPLETED', timestamp: new Date().toISOString() },
        artifacts: [{ artifactId: randomUUID(), parts: [{ text: text || 'ok' }] }],
      };
      return send(res, 200, { jsonrpc: '2.0', id: rid, result: { task } });
    }
    return send(res, 404, { jsonrpc: '2.0', id: rid,
      error: { code: -32601, message: `unknown method ${method}` } });
  });
});

server.listen(PORT, '127.0.0.1', () => console.log(`h2 mock agent listening on 127.0.0.1:${PORT}`));
