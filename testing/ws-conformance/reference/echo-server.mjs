#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// THE CONTROL PEER: a correct WebSocket echo server, built on the `ws` package (an independent
// third-party implementation the battery does not touch), so `autobahn-control` proves the harness
// can grade a known-good peer green BEFORE any busbar verdict is believed -- the same two-leg rule
// `mcp-conformance.yml`'s header documents.
//
// Prints `REFERENCE_PORT=<port>` once bound.

import { WebSocketServer } from 'ws';

const wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
wss.on('listening', () => {
  const { port } = wss.address();
  console.log(`REFERENCE_PORT=${port}`);
});
wss.on('connection', (ws) => {
  ws.on('message', (data, isBinary) => {
    ws.send(data, { binary: isBinary });
  });
});
