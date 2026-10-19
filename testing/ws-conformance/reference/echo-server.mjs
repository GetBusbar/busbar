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
  // A peer that breaks the protocol (Autobahn 2.5: a ping over 125 bytes) makes `ws` close that
  // connection with 1002 and emit 'error' on it. The error is THAT connection's, and is answered by
  // the close; an unheard 'error' would end the whole server and every case after it.
  ws.on('error', () => {});
  ws.on('message', (data, isBinary) => {
    ws.send(data, { binary: isBinary });
  });
});
