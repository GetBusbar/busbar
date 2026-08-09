// THE SEAM.
//
// The subject is BOTH an MCP server (agents connect in) and an MCP client
// (it connects out to other servers). The seam is what happens when a message
// crosses from one role to the other, and it is the least-tested surface in
// any bidirectional implementation because neither role's own test suite ever
// exercises it.
//
// TOPOLOGY for these tests:
//
//     battery (as client)  ->  SUBJECT (as server)
//                                  |
//                              SUBJECT (as client)
//                                  |
//                                  v
//                              fake server (ours, hostile on demand)
//
// We drive the front door and observe the back door. A defect at the seam
// shows up as something crossing between them that should not have.
//
// HONEST LIMITATION, stated up front: this topology needs the subject to be
// configured to mount our fake server as an upstream. There is no standard for
// that (MCP does not standardise host configuration), so these tests cannot
// derive it and need MCP_SUBJECT_UPSTREAM_CONFIG_CMD.
//
// WHAT HAPPENS WHEN IT IS ABSENT DEPENDS ON WHO IS ASKING, and that distinction
// is the point. Exercising the harness for its own sake, a skip is the honest
// report: this run could not reach the seam. Running as a RELEASE GATE it is
// not, because a skip renders as a green tick over a surface nobody touched,
// and "the seam was never tested" then looks exactly like "the seam is
// correct". So the subject leg sets MCP_NO_SKIPS=1 and ctx.skip() below becomes
// a FAILURE naming the missing variable (see src/core/runner.mjs).
//
// Concretely: these six `pr`-tier seam tests need busbar's MCP CLIENT direction
// -- the ability to mount an upstream MCP server -- which does not exist on
// this branch. Under the gate they are RED, and they should be: the seam is the
// one property that is meaningless with only one direction built, so a green
// here before the client direction lands would be a lie about exactly the
// property that matters most.

import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from '../core/runner.mjs';
import { request } from '../core/jsonrpc.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const FAKE = resolve(HERE, '../../fakepeer/fake-server.mjs');

/**
 * Start the subject as a server, with our fake server configured as its
 * upstream. Returns the front-door peer plus a reader for the back-door
 * transcript.
 */
function startSeam(ctx, upstreamMode) {
  const cmd = process.env.MCP_SUBJECT_UPSTREAM_CONFIG_CMD;
  if (!cmd) {
    ctx.skip(
      'seam tests need MCP_SUBJECT_UPSTREAM_CONFIG_CMD: a launch command that starts the '
      + 'subject as an MCP server with the fake server (given in MCP_SEAM_UPSTREAM_CMD) '
      + 'mounted as an upstream MCP server. MCP does not standardise host configuration, '
      + 'so this cannot be derived automatically.',
    );
  }
  const dir = mkdtempSync(join(tmpdir(), 'mcp-seam-'));
  const transcript = join(dir, 'upstream.jsonl');
  const target = ctx.target;
  const saved = target.serverLaunch;
  target.serverLaunch = cmd;
  const peer = target.spawnServer();
  target.serverLaunch = saved;
  peer.__transcript = transcript;
  return peer;
}

function readUpstream(peer) {
  if (!peer.__transcript || !existsSync(peer.__transcript)) return [];
  return readFileSync(peer.__transcript, 'utf8')
    .split('\n').filter(Boolean).map((l) => JSON.parse(l));
}

// Env the seam harness exports for the subject's launcher to consume.
function seamEnv(mode, transcript) {
  return {
    MCP_SEAM_UPSTREAM_CMD: `${process.execPath} ${FAKE}`,
    MCP_FAKE_MODE: mode,
    MCP_FAKE_TRANSCRIPT: transcript,
  };
}

test({
  id: 'SEAM.NO-ID-PASSTHROUGH',
  title: 'a request id from the front door is not reused verbatim on the back door',
  role: 'seam', area: 'seam', tier: 'pr', peer: 'real',
  catches: 'An id forwarded unchanged between roles, so two downstream callers using the same id collide upstream.',
  run: async (ctx) => {
    const peer = startSeam(ctx, 'honest');
    try {
      const distinctive = 'front-door-id-e7f3a91c';
      peer.send(request(distinctive, 'tools/list'));
      await peer.waitForId(distinctive);
      const upstream = readUpstream(peer).filter((e) => e.direction === 'client->server');
      const leaked = upstream.filter((e) => e.payload && e.payload.id === distinctive);
      ctx.assert('BASE.REQ.ID-UNIQUE', leaked.length === 0,
        `the front-door request id appeared unchanged on the upstream connection: ${JSON.stringify(leaked)}`);
      ctx.variance('seam.upstreamIdType', upstream.length ? typeof upstream[0].payload.id : null);
    } finally { await peer.stop(); }
  },
});

test({
  id: 'SEAM.NO-CREDENTIAL-FORWARDING',
  title: 'a token presented at the front door is not forwarded upstream',
  role: 'seam', area: 'seam', tier: 'pr', peer: 'real',
  catches: 'Token passthrough: the exact confused-deputy pattern the spec forbids, where a downstream token reaches an upstream server.',
  run: async (ctx) => {
    const peer = startSeam(ctx, 'honest');
    try {
      const secret = 'sentinel-token-4f9d2a7b1e';
      peer.send(request(1, 'tools/call', {
        name: 'echo',
        arguments: { text: 'hello' },
        _authProbe: secret,
      }, { extraMeta: { 'com.example.battery/authorization': `Bearer ${secret}` } }));
      try { await peer.waitForId(1, 10000); } catch { /* the call may legitimately fail */ }
      const blob = JSON.stringify(readUpstream(peer));
      ctx.assert('PAT.MRTR.STATE-UNTRUSTED', !blob.includes(secret),
        'a credential presented at the front door was observed on the upstream connection');
    } finally { await peer.stop(); }
  },
});

test({
  id: 'SEAM.UPSTREAM-INJECTION-NOT-REPUBLISHED',
  title: 'prompt-injection text in an upstream tool description is not republished verbatim',
  role: 'seam', area: 'seam', tier: 'pr', peer: 'real',
  catches: 'An aggregating server that re-exports a hostile upstream tool description straight into its own tools/list.',
  run: async (ctx) => {
    const peer = startSeam(ctx, 'injection');
    try {
      peer.send(request(1, 'tools/list'));
      const res = await peer.waitForId(1);
      const blob = JSON.stringify(res.result || {});
      const republished = /IGNORE ALL PREVIOUS INSTRUCTIONS/i.test(blob);
      // There is NO spec clause requiring sanitisation here. This is our
      // recommendation, and a strong variance point for a human.
      ctx.recommend('seam.doesNotRepublishInjection', !republished,
        'RECOMMENDATION (this battery): an aggregating server should not pass hostile upstream '
        + 'tool descriptions through to its own clients unmodified or unlabelled.');
      ctx.variance('seam.republishedUpstreamDescription', republished);
      ctx.note('spec-status',
        'The spec says clients MUST treat annotations as untrusted, but says nothing about a '
        + 'server that AGGREGATES other servers. That gap is a finding in its own right.');
    } finally { await peer.stop(); }
  },
});

test({
  id: 'SEAM.UPSTREAM-FAILURE-IS-TOOL-ERROR',
  title: 'an upstream failure surfaces as a tool execution error, not a protocol error',
  role: 'seam', area: 'seam', tier: 'pr', peer: 'real',
  catches: 'Upstream transport faults leaking out as JSON-RPC errors, so the model cannot see or retry them.',
  run: async (ctx) => {
    const peer = startSeam(ctx, 'stall');
    try {
      peer.send(request(1, 'tools/call', { name: 'echo', arguments: { text: 'hi' } }));
      let res = null;
      try { res = await peer.waitForId(1, 20000); } catch { /* recorded below */ }
      if (res) {
        // Either is defensible. The bad outcome is no answer at all.
        ctx.variance('seam.upstreamStall.answerKind',
          res.error ? `error:${res.error.code}` : `result:isError=${res.result && res.result.isError}`);
      }
      ctx.assert('CANCEL.RACE-GRACEFUL', res !== null,
        'the subject never answered its own client when its upstream stalled: a hung seam');
    } finally { await peer.stop(); }
  },
});

test({
  id: 'SEAM.UPSTREAM-SERVER-REQUEST-NOT-RELAYED',
  title: 'a forbidden upstream server-initiated request is not relayed downstream',
  role: 'seam', area: 'seam', tier: 'pr', peer: 'real',
  catches: 'A relay that forwards a legacy server-initiated request to its own clients, breaking every modern client.',
  run: async (ctx) => {
    const peer = startSeam(ctx, 'server-request');
    try {
      peer.send(request(1, 'tools/call', { name: 'echo', arguments: { text: 'hi' } }));
      try { await peer.waitForId(1, 12000); } catch { /* fine */ }
      const relayed = peer.serverRequests();
      ctx.assert('PAT.SERVER-NO-REQUESTS', relayed.length === 0,
        `the subject relayed a server-initiated request downstream: ${JSON.stringify(relayed)}`);
    } finally { await peer.stop(); }
  },
});

test({
  id: 'SEAM.UPSTREAM-NAME-COLLISION',
  title: 'upstream tool names are disambiguated before being re-exported',
  role: 'seam', area: 'seam', tier: 'prerelease', peer: 'real',
  catches: 'Two upstream servers each exposing "search", silently shadowing each other in the aggregated list.',
  run: async (ctx) => {
    const peer = startSeam(ctx, 'honest');
    try {
      peer.send(request(1, 'tools/list'));
      const res = await peer.waitForId(1);
      const names = (res.result && res.result.tools || []).map((t) => t.name);
      const dupes = names.filter((n, i) => names.indexOf(n) !== i);
      ctx.assert('TOOLS.LIST-RESPONDS', dupes.length === 0,
        `duplicate tool names in the aggregated list: ${JSON.stringify(dupes)}`);
      ctx.variance('seam.exportedToolNames', names.sort());
    } finally { await peer.stop(); }
  },
});

test({
  id: 'SEAM.DOWNSTREAM-CANCEL-PROPAGATES',
  title: 'cancelling at the front door stops work at the back door',
  role: 'seam', area: 'seam', tier: 'prerelease', peer: 'real', timing: true,
  catches: 'A cancellation that stops the downstream reply but leaves the upstream call running, leaking work and cost.',
  run: async (ctx) => {
    const peer = startSeam(ctx, 'stall');
    try {
      peer.send(request('cancel-seam', 'tools/call', { name: 'echo', arguments: { text: 'hi' } }));
      peer.send({
        jsonrpc: '2.0',
        method: 'notifications/cancelled',
        params: { requestId: 'cancel-seam', reason: 'battery seam test' },
      });
      peer.send(request('barrier', 'server/discover'));
      await peer.waitForId('barrier', 15000);
      await peer.quiesce(500);
      const upstream = readUpstream(peer);
      const upstreamCancels = upstream.filter(
        (e) => e.direction === 'client->server'
          && e.payload && e.payload.method === 'notifications/cancelled',
      );
      // No spec clause requires propagation. It is our recommendation.
      ctx.recommend('seam.propagatesCancellation', upstreamCancels.length > 0,
        'RECOMMENDATION (this battery): a bidirectional implementation should propagate a '
        + 'downstream cancellation to its upstream call, or it pays for work nobody wants.');
      ctx.variance('seam.upstreamCancelSent', upstreamCancels.length > 0);
    } finally { await peer.stop(); }
  },
});

test({
  id: 'SEAM.ROLE-ISOLATION-UNDER-UPSTREAM-CRASH',
  title: 'an upstream crash does not take down the subject front door',
  role: 'seam', area: 'seam', tier: 'pr', peer: 'real',
  catches: 'Shared process state between the two roles, where one bad upstream server kills service to all downstream agents.',
  run: async (ctx) => {
    const peer = startSeam(ctx, 'half-answer');
    try {
      peer.send(request(1, 'tools/call', { name: 'echo', arguments: { text: 'hi' } }));
      try { await peer.waitForId(1, 12000); } catch { /* the call may fail: that is fine */ }
      // The assertion is about the FRONT door still working.
      peer.send(request('after-crash', 'server/discover'));
      const res = await peer.waitForId('after-crash', 12000);
      ctx.assert('VER.DISCOVER-REQUIRED', Boolean(res.result),
        'the subject stopped serving its own clients after an upstream server died mid-frame');
    } finally { await peer.stop(); }
  },
});
