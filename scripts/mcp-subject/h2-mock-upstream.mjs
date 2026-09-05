#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// A MINIMAL MCP UPSTREAM FOR THE H2 GATING SCENARIOS (tracker row H2, ARCHITECTURE.md #2.2).
//
// The official-suite fixtures (diagnostic-upstream.mjs) exist to serve the pinned conformance
// suite's own scenario names and carry no egress-capture instrumentation. The H2 gating scenarios
// (scripts/mcp-subject/h2-*.sh) need something narrower: one tool, on one path, that records EVERY
// request it receives so a scenario can assert "zero egress reached the upstream" the same way
// testing/shadow-oracle/mock-upstream.py does for the llm plane. This is that mock, written once
// and shared by every h2-*.sh script (each boots its own instance on its own port).
//
// Protocol surface: `2026-07-28` has no handshake (every request is self-describing via
// `params._meta`), so this answers `tools/list` and `tools/call` only, for one tool, `ping`, which
// echoes its `label` argument.
//
// Egress capture: when MCP_MOCK_CAPTURE_DIR is set, every POST this process receives is written as
// its own JSON file `{ts}-{pid}-{seq}.json` holding `{path, method, headers, body}` — read the
// directory's file count before/after a call to prove egress did or did not happen.
//
// Usage: node h2-mock-upstream.mjs <port>
import { createServer } from 'node:http';
import { mkdirSync, writeFileSync, renameSync } from 'node:fs';
import { join } from 'node:path';

const PORT = Number(process.argv[2]);
if (!PORT) {
  console.error('usage: h2-mock-upstream.mjs <port>');
  process.exit(2);
}

let seq = 0;
function captureEgress(method, url, headers, body) {
  const dir = process.env.MCP_MOCK_CAPTURE_DIR;
  if (!dir) return;
  try {
    mkdirSync(dir, { recursive: true });
    const record = { path: url, method, headers, body };
    const name = `${process.hrtime.bigint()}-${process.pid}-${seq++}.json`;
    const tmp = join(dir, `.${name}.tmp`);
    writeFileSync(tmp, JSON.stringify(record));
    renameSync(tmp, join(dir, name));
  } catch {
    // best-effort: a capture failure must never change the response busbar gets
  }
}

const TOOLS = [
  {
    name: 'ping',
    description: 'Returns the label it was given.',
    inputSchema: {
      type: 'object',
      properties: { label: { type: 'string' } },
      additionalProperties: false,
    },
  },
];

function send(res, status, obj) {
  const raw = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': raw.length });
  res.end(raw);
}

const server = createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const raw = Buffer.concat(chunks).toString('utf8');
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) headers[k.toLowerCase()] = v;
    captureEgress(req.method, req.url, headers, raw);
    let body = {};
    try { body = raw ? JSON.parse(raw) : {}; } catch { body = {}; }
    const id = body.id ?? null;
    const method = body.method;
    if (req.method !== 'POST') return send(res, 404, { error: 'GET not served' });
    if (method === 'tools/list') {
      return send(res, 200, { jsonrpc: '2.0', id, result: { tools: TOOLS } });
    }
    if (method === 'tools/call') {
      const args = body.params?.arguments ?? {};
      return send(res, 200, {
        jsonrpc: '2.0', id,
        result: { content: [{ type: 'text', text: `ping: ${args.label ?? ''}` }], isError: false },
      });
    }
    return send(res, 400, { jsonrpc: '2.0', id, error: { code: -32601, message: `unknown method ${method}` } });
  });
});

server.listen(PORT, '127.0.0.1', () => console.log(`h2 mock upstream listening on 127.0.0.1:${PORT}`));
