#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// THE NEGATIVE CONTROL: a deliberately broken WebSocket peer. `autobahn-negative-control` runs
// Autobahn against this and MUST see it graded RED -- proving the harness can fail a peer, not
// only pass one, the same "a deliberately broken peer MUST be red" discipline
// `mcp-conformance.yml`'s `battery-negative-control` leg holds the in-house battery to.
//
// The defect: this peer echoes every message TRUNCATED by one byte, which corrupts UTF-8 text
// frames and drops the trailing byte of every binary frame -- both of which flip clearly OK
// Autobahn echo cases (the 1.x / 2.x series) to FAILED.
//
// Prints `BROKEN_PORT=<port>` once bound.

import { WebSocketServer } from 'ws';

const wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
wss.on('listening', () => {
  const { port } = wss.address();
  console.log(`BROKEN_PORT=${port}`);
});
wss.on('connection', (ws) => {
  ws.on('message', (data, isBinary) => {
    const truncated = data.length > 0 ? data.subarray(0, data.length - 1) : data;
    ws.send(truncated, { binary: isBinary });
  });
});
