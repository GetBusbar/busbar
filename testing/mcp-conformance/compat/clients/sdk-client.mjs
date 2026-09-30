// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// A REAL, PINNED MCP SDK CLIENT driven against busbar's endpoint, one revision per run.
//
//   node clients/sdk-client.mjs <revision> <endpoint-url>
//
// <revision> selects the pinned SDK (package.json): 2024-11-05 (the HTTP+SSE transport, SDK 1.0.4),
// 2025-06-18 (Streamable HTTP, SDK 1.17.5) or 2025-11-25 (Streamable HTTP, SDK 1.24.3). The SDK does
// the talking; this file only drives it and checks what came back. It prints one JSON line and exits
// 0 only when every check passed.
//
// Checks: the SDK's own initialize handshake negotiates <revision>; tools/list and ping answer; a
// tool call returns a JSON-RPC result; on the Streamable HTTP revisions the session is named, its
// GET stream opens and resumes with Last-Event-ID, and DELETE ends it so the next use is 404.

const [revision, endpoint] = process.argv.slice(2);
if (!revision || !endpoint) {
  console.error('usage: sdk-client.mjs <2024-11-05|2025-06-18|2025-11-25> <endpoint-url>');
  process.exit(2);
}
const pkg = `sdk-${revision}`;
const { Client } = await import(`${pkg}/client/index.js`);

// Every request the SDK sends is recorded, so the negotiated revision is read off the wire (the
// version header the SDK sends after initialize) rather than off the SDK's own state.
const sent = [];
const realFetch = globalThis.fetch;
globalThis.fetch = async (input, init = {}) => {
  const headers = new Headers(init.headers ?? (input instanceof Request ? input.headers : undefined));
  sent.push({ method: init.method ?? 'GET', version: headers.get('mcp-protocol-version') });
  return realFetch(input, init);
};

const checks = {};
const failures = [];
const check = (name, ok, detail) => {
  checks[name] = Boolean(ok);
  if (!ok) failures.push(`${name}: ${detail ?? 'failed'}`);
};

let transport;
if (revision === '2024-11-05') {
  // SDK 1.0.4 was written for a browser-shaped runtime and reads EventSource as a global.
  if (typeof globalThis.EventSource === 'undefined') {
    globalThis.EventSource = (await import('eventsource')).EventSource;
  }
  const { SSEClientTransport } = await import(`${pkg}/client/sse.js`);
  transport = new SSEClientTransport(new URL(endpoint));
} else {
  const { StreamableHTTPClientTransport } = await import(`${pkg}/client/streamableHttp.js`);
  transport = new StreamableHTTPClientTransport(new URL(endpoint));
}
const client = new Client({ name: `compat-${revision}`, version: '1' }, { capabilities: {} });

try {
  await client.connect(transport);
  check('initialize', true);
  const info = client.getServerVersion?.();
  check('server named', info && typeof info.name === 'string', JSON.stringify(info));

  const tools = await client.listTools();
  check('tools/list', Array.isArray(tools.tools), JSON.stringify(tools).slice(0, 200));

  await client.ping();
  check('ping', true);

  const callable = (tools.tools ?? []).find((t) => !(t.inputSchema?.required?.length));
  if (callable) {
    try {
      const r = await client.callTool({ name: callable.name, arguments: {} });
      check('tools/call', r && (Array.isArray(r.content) || r.structuredContent !== undefined), JSON.stringify(r).slice(0, 200));
    } catch (e) {
      // A JSON-RPC error is still an answer in the session; only a transport failure is not.
      check('tools/call', typeof e?.code === 'number', String(e));
    }
  }

  if (revision === '2024-11-05') {
    check('no version header (the revision predates it)', sent.every((s) => !s.version), JSON.stringify(sent));
  } else {
    const after = sent.filter((s) => s.version);
    check('negotiated revision on the wire', after.length > 0 && after.every((s) => s.version === revision), JSON.stringify(sent));
    const sid = transport.sessionId;
    check('session named', typeof sid === 'string' && /^[0-9a-f]{32}$/.test(sid), String(sid));

    const stream = await realFetch(endpoint, {
      headers: { accept: 'text/event-stream', 'mcp-session-id': sid, 'mcp-protocol-version': revision },
    });
    check('GET stream opens', stream.status === 200 && (stream.headers.get('content-type') ?? '').startsWith('text/event-stream'), `${stream.status}`);
    let cursor;
    if (revision === '2025-11-25') {
      // The priming event carries the id a reconnecting client resumes from.
      const reader = stream.body.getReader();
      const { value } = await reader.read();
      cursor = /id: ([^\n]+)/.exec(new TextDecoder().decode(value ?? new Uint8Array()))?.[1];
      check('stream primed with an event id', Boolean(cursor), String(cursor));
      await reader.cancel();
    } else {
      await stream.body?.cancel();
    }
    if (cursor) {
      const resumed = await realFetch(endpoint, {
        headers: { accept: 'text/event-stream', 'mcp-session-id': sid, 'mcp-protocol-version': revision, 'last-event-id': cursor },
      });
      check('resume with Last-Event-ID', resumed.status === 200, `${resumed.status}`);
      await resumed.body?.cancel();
    }

    await transport.terminateSession();
    const gone = await realFetch(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'mcp-session-id': sid, 'mcp-protocol-version': revision },
      body: JSON.stringify({ jsonrpc: '2.0', id: 99, method: 'ping' }),
    });
    check('DELETE ends the session (next use is 404)', gone.status === 404, `${gone.status}`);
  }
} catch (e) {
  failures.push(`exception: ${e?.stack ?? e}`);
} finally {
  await client.close().catch(() => {});
}

const ok = failures.length === 0 && Object.keys(checks).length > 0;
console.log(JSON.stringify({ peer: `ts-sdk ${revision}`, direction: 'client -> busbar', ok, checks, failures }));
process.exit(ok ? 0 : 1);
