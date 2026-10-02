// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// A REAL, PINNED MCP SDK SERVER for busbar to call as an upstream, one revision per process.
//
//   node servers/sdk-server.mjs <revision> <port>
//
// 2024-11-05 (SDK 1.0.4): the HTTP+SSE transport. GET /sse opens the stream and names
//   /messages?sessionId=… as the POST address.
// 2025-06-18 (SDK 1.17.5) and 2025-11-25 (SDK 1.24.3): Streamable HTTP at /mcp, with sessions.
//
// It serves one tool, `echo` ({ text: string } -> the same text), and prints `ready <port>` once it
// is listening. It knows nothing about busbar.

import http from 'node:http';
import { randomUUID } from 'node:crypto';

const [revision, portArg] = process.argv.slice(2);
if (!revision || !portArg) {
  console.error('usage: sdk-server.mjs <2024-11-05|2025-06-18|2025-11-25> <port>');
  process.exit(2);
}
const port = Number(portArg);
const pkg = `sdk-${revision}`;

async function readJson(req) {
  let s = '';
  for await (const c of req) s += c;
  return s ? JSON.parse(s) : undefined;
}

const { Server } = await import(`${pkg}/server/index.js`);
const { ListToolsRequestSchema, CallToolRequestSchema, InitializeRequestSchema } = await import(`${pkg}/types.js`);
const newServer = () => {
  const server = new Server({ name: 'compat-echo', version: '1' }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [{ name: 'echo', description: 'echo', inputSchema: { type: 'object', properties: { text: { type: 'string' } } } }],
  }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => ({
    content: [{ type: 'text', text: String(req.params.arguments?.text ?? '') }],
  }));
  return server;
};

if (revision === '2024-11-05') {
  const { SSEServerTransport } = await import(`${pkg}/server/sse.js`);
  const transports = new Map();
  http
    .createServer(async (req, res) => {
      const url = new URL(req.url, `http://127.0.0.1:${port}`);
      if (req.method === 'GET' && url.pathname === '/sse') {
        const transport = new SSEServerTransport('/messages', res);
        transports.set(transport.sessionId, transport);
        res.on('close', () => transports.delete(transport.sessionId));
        await newServer().connect(transport);
        return;
      }
      if (req.method === 'POST' && url.pathname === '/messages') {
        const t = transports.get(url.searchParams.get('sessionId'));
        if (!t) {
          res.writeHead(404).end();
          return;
        }
        await t.handlePostMessage(req, res);
        return;
      }
      res.writeHead(404).end();
    })
    .listen(port, '127.0.0.1', function onListening() {
      console.log(`ready ${this.address().port}`);
    });
} else {
  const { StreamableHTTPServerTransport } = await import(`${pkg}/server/streamableHttp.js`);
  const isInitializeRequest = (b) => InitializeRequestSchema.safeParse(b).success;
  const sessions = new Map();
  http
    .createServer(async (req, res) => {
      const url = new URL(req.url, `http://127.0.0.1:${port}`);
      if (url.pathname !== '/mcp') {
        res.writeHead(404).end();
        return;
      }
      const sid = req.headers['mcp-session-id'];
      let transport = sid ? sessions.get(sid) : undefined;
      const body = req.method === 'POST' ? await readJson(req).catch(() => undefined) : undefined;
      if (!transport) {
        if (req.method !== 'POST' || !isInitializeRequest(body)) {
          res.writeHead(sid ? 404 : 400, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32000, message: 'No valid session' } }));
          return;
        }
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (id) => sessions.set(id, transport),
        });
        transport.onclose = () => transport.sessionId && sessions.delete(transport.sessionId);
        await newServer().connect(transport);
      }
      await transport.handleRequest(req, res, body);
    })
    .listen(port, '127.0.0.1', function onListening() {
      console.log(`ready ${this.address().port}`);
    });
}
