// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// THE CONFORMANCE SUITE'S CREDENTIAL, HELD WHERE A CLIENT WOULD HOLD IT.
//
// The official MCP conformance suite's `server` command takes ONE argument that matters here:
// `--url`. It has no `--header`, no `--token`, and reads no environment variable for either (its
// only `process.env` reference in the published build is `GITHUB_TOKEN`, for the unrelated
// `tier-check` subcommand). It is a TRANSPORT conformance suite: it assumes the endpoint it is
// pointed at will answer it.
//
// busbar will not, because busbar's MCP endpoint is an OAuth resource server and an unauthenticated
// POST gets `401` with an RFC 9728 challenge. A suite that receives `401` on all 37 required
// scenarios has proven nothing about busbar, which is the precise failure this leg exists to end.
//
// THIS IS THE CLIENT SIDE OF THE CONNECTION, NOT THE SERVER SIDE. The shim is the part of an MCP
// client that holds a credential and attaches it -- the thing every real MCP client does, and the
// thing this particular client cannot be told to do. It runs in the same job, on loopback, in front
// of a busbar whose auth is entirely untouched: the token it attaches is verified in full, and
// `mcp-conformance.sh` proves that in the same run by showing that the SAME busbar answers `401` to
// a token with no audience, to one bound to a different audience, and to one whose signature was
// altered. Nothing here is inside busbar's trust boundary and nothing here relaxes it.
//
// TRANSPARENCY IS THE WHOLE DESIGN, and it has exactly one deliberate exception.
//   * Method, path, query and body are forwarded byte-for-byte.
//   * Every request header is forwarded UNCHANGED -- including `Origin`, which the suite's
//     `dns-rebinding-protection` scenario varies on purpose and which busbar must judge itself, and
//     including `Mcp-Method` / `Mcp-Name` / `MCP-Protocol-Version`, which the suite deliberately
//     mangles to test the mirrored-header MUSTs.
//   * Every response header, status and body is forwarded back unchanged.
//   * `Host` is rewritten to the upstream authority, because a forwarded `Host` naming this shim
//     would describe a hop the origin server never had.
//   * `Authorization` is added ONLY when the request carries none. A suite scenario that sends its
//     own credential keeps it, so a future authorization scenario is not silently overwritten by
//     ours.
//
// Usage: node credential-shim.mjs <listen-port> <upstream-port> <bearer-token>

import http from 'node:http';

const [listenPort, upstreamPort, token] = process.argv.slice(2);
if (!listenPort || !upstreamPort || !token) {
  console.error('usage: credential-shim.mjs <listen-port> <upstream-port> <bearer-token>');
  process.exit(2);
}

const server = http.createServer((req, res) => {
  const headers = { ...req.headers, host: `127.0.0.1:${upstreamPort}` };
  // Case-insensitively, because a client may send `Authorization` in any case and Node lowercases
  // incoming header names but a future refactor of this object must not depend on that.
  const alreadyAuthenticated = Object.keys(headers).some((h) => h.toLowerCase() === 'authorization');
  if (!alreadyAuthenticated) headers.authorization = `Bearer ${token}`;

  const upstream = http.request(
    { host: '127.0.0.1', port: Number(upstreamPort), path: req.url, method: req.method, headers },
    (upstreamRes) => {
      res.writeHead(upstreamRes.statusCode, upstreamRes.headers);
      upstreamRes.pipe(res);
    },
  );
  // A dead upstream must look like a dead upstream, never like a conformance verdict: `502` with
  // the reason, so a scenario that fails because busbar exited says so instead of being read as a
  // protocol defect.
  upstream.on('error', (e) => {
    res.writeHead(502, { 'content-type': 'text/plain' });
    res.end(`credential-shim: upstream busbar at 127.0.0.1:${upstreamPort} did not answer: ${e}`);
  });
  req.pipe(upstream);
});

server.listen(Number(listenPort), '127.0.0.1');
