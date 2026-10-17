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
// AND WHEN IT IS PRESENT, THE ABSENCES THESE TESTS REPORT MUST STILL BE EARNED.
//
// Four of the six assert that something is NOT on the upstream connection: a
// forwarded request id, a forwarded credential, a relayed server-initiated
// request. Every one of those is satisfied by an upstream connection that was
// never opened -- so a subject that answers "unknown tool" to the seam's
// `tools/call`, or a launcher that mounts nothing, passes them all while
// proving nothing. That is a worse outcome than the red it replaces, because it
// is indistinguishable from the correct one.
//
// `requireUpstreamWasReached` below is the guard, and it THROWS rather than
// asserting: a silent observation channel is a finding about this RUN, not a
// spec violation by the subject, and the runner counts a throw as ERROR
// alongside every failure. What it can never be is a pass.

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
  // THE MODE AND THE TRANSCRIPT REACH THE LAUNCHER, which they could not before: `spawnServer` took
  // no environment, so `seamEnv` was dead code and `upstreamMode` was an unused argument. Every seam
  // test would have run against the honest baseline and read an empty transcript — and an empty
  // transcript satisfies four of these six assertions VACUOUSLY, because each of them is looking for
  // something that must NOT be in it. That is the worst possible failure for this suite, and it was
  // a defect in the battery rather than in any subject.
  const peer = target.spawnServer(seamEnv(upstreamMode, transcript));
  target.serverLaunch = saved;
  peer.__transcript = transcript;
  peer.__mode = upstreamMode;
  return peer;
}

/**
 * ASSERT THE OBSERVATION CHANNEL IS LIVE before believing anything read from it.
 *
 * Four of these six clauses assert that something is ABSENT from the upstream transcript — a
 * forwarded id, a forwarded credential. An absence read from a transcript that was never written is
 * not evidence of anything, and it is indistinguishable from the honest result. So a test whose
 * verdict rests on an absence first proves that the channel it is reading CARRIED SOMETHING: busbar
 * must have been observed talking to our upstream at all.
 *
 * It THROWS rather than asserting, because a silent observation channel is not a finding about the
 * subject and must not be reported as a spec violation by the subject. It is a finding about this
 * RUN, and the runner records a throw as ERROR, which the gate counts alongside every failure. What
 * it must never be is a pass.
 */
function requireUpstreamWasReached(peer, entries) {
  const outbound = entries.filter((e) => e.direction === 'client->server');
  if (outbound.length === 0) {
    throw new Error(
      `VACUOUS: the upstream transcript at ${peer.__transcript} recorded no request from the `
      + `subject in mode "${peer.__mode}", so every absence this test would otherwise report is `
      + 'evidence of nothing — the seam was never crossed. TWO CAUSES HAVE PRODUCED THIS, and the '
      + 'second one is the one that cost the most time, so check it FIRST:\n'
      + '  1. THE SUBJECT REFUSED TO DIAL AT ALL. Its circuit breaker cell for this registration '
      + 'was open, so the call was fast-failed before any socket was opened and nothing could '
      + 'reach us. This is NOT a mount problem and no amount of checking the config will show it. '
      + 'It is visible in the subject\'s own log as `-32030` / `upstream_unavailable` / '
      + '`retry_after_ms`, and because the battery shares ONE registration across every scenario, '
      + 'ONE earlier test that drove the cell open poisons every later one — look at what ran '
      + 'BEFORE this test, not at this test. A retry loop in the arm script counts as several '
      + 'failures and has tripped the cell on its own.\n'
      + '  2. The tool never routed here: check that MCP_SUBJECT_UPSTREAM_CONFIG_CMD mounts the '
      + 'fake server, and that the tool this test calls resolves to it rather than being answered '
      + '"unknown tool".',
    );
  }
  return outbound;
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
      // THE DISTINCTIVE ID RIDES THE REQUEST THAT CROSSES THE SEAM, and that is a correction.
      // It used to ride `tools/list`, which an aggregating server answers from its own catalogue
      // without contacting anybody — so the id had no back door to appear on and the assertion was
      // satisfied by a request that never left. A `tools/call` is the one front-door request whose
      // whole purpose is to become a back-door request, which is where a passthrough would show.
      const distinctive = 'front-door-id-e7f3a91c';
      peer.send(request(distinctive, 'tools/call', { name: 'echo', arguments: { text: 'hi' } }));
      try { await peer.waitForId(distinctive, 15000); } catch { /* the call may fail; the trace is what matters */ }
      const upstream = requireUpstreamWasReached(peer, readUpstream(peer));
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
      try { await peer.waitForId(1, 15000); } catch { /* the call may legitimately fail */ }
      const entries = readUpstream(peer);
      // The absence below is only evidence if there was a back door to be absent from.
      requireUpstreamWasReached(peer, entries);
      const blob = JSON.stringify(entries);
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
      // NOT VACUOUS: the aggregated list must actually CONTAIN the upstream's tool. A subject that
      // exposed none of it would also not republish its description, and would pass this test for
      // the one reason that proves nothing.
      const names = (res.result && res.result.tools || []).map((t) => t.name);
      if (!names.includes('echo')) {
        throw new Error(
          'VACUOUS: the hostile upstream\'s tool is not in the subject\'s aggregated tools/list '
          + `(saw ${JSON.stringify(names)}), so "the injection was not republished" is satisfied by `
          + 'the tool being absent rather than by anything this test is about.',
        );
      }
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
      // The subject must have TRIED. An answer produced without ever reaching the stalling upstream
      // (an "unknown tool", say) is an answer to a different question, and would pass this test
      // while proving nothing about a hung seam.
      requireUpstreamWasReached(peer, readUpstream(peer));
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
      try { await peer.waitForId(1, 15000); } catch { /* fine */ }
      // The hostile frame only exists if the upstream was reached, so an empty relay list means
      // nothing until that is established.
      requireUpstreamWasReached(peer, readUpstream(peer));
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
      try { await peer.waitForId(1, 15000); } catch { /* the call may fail: that is fine */ }
      // The upstream must actually have DIED under this subject. A front door that still works
      // after a crash that never happened is not evidence of role isolation.
      requireUpstreamWasReached(peer, readUpstream(peer));
      // The assertion is about the FRONT door still working.
      peer.send(request('after-crash', 'server/discover'));
      const res = await peer.waitForId('after-crash', 12000);
      ctx.assert('VER.DISCOVER-REQUIRED', Boolean(res.result),
        'the subject stopped serving its own clients after an upstream server died mid-frame');
    } finally { await peer.stop(); }
  },
});
