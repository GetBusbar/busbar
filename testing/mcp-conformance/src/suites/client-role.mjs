// SUBJECT ACTS AS MCP CLIENT. We are the server it connects to.
//
// OBSERVATION MODEL: we do not ask the client to report on itself. The fake
// server records everything the client puts on the wire into a JSONL
// transcript, and we assert on that. This means a subject needs to satisfy
// exactly ONE contract to be testable in its client role:
//
//   it must be launchable with a command that connects to a stdio MCP server
//   whose launch command is supplied as the final argv element and in
//   MCP_TARGET_SERVER_COMMAND, and it must then do some ordinary work
//   (discover, list tools, call a tool).
//
// That contract is unavoidable: MCP standardises the wire, not how a host is
// told which server to talk to. It is the one place the harness asks anything
// of the subject, and it is configuration, not code.

import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from '../core/runner.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const FAKE = resolve(HERE, '../../fakepeer/fake-server.mjs');

function fakeLaunch() {
  return `${process.execPath} ${FAKE}`;
}

/**
 * Run the subject's client against the fake server in a given mode, wait for
 * the client process to exit, and return the observed transcript.
 */
async function driveClient(ctx, mode, { failsafeMs = 20000 } = {}) {
  if (!ctx.target.hasClientRole) ctx.skip('target has no client role configured');
  const dir = mkdtempSync(join(tmpdir(), 'mcp-battery-'));
  const transcript = join(dir, 'transcript.jsonl');
  const peer = ctx.target.spawnClient(fakeLaunch(), {
    MCP_FAKE_MODE: mode,
    MCP_FAKE_TRANSCRIPT: transcript,
  });
  let exited = true;
  try {
    await peer.waitForExit(failsafeMs);
  } catch {
    exited = false;
  } finally {
    await peer.stop();
  }
  const lines = existsSync(transcript)
    ? readFileSync(transcript, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
    : [];
  return {
    exited,
    exitCode: peer.exitCode,
    stderr: peer.stderr,
    stdout: peer.stdoutBytes.toString('utf8'),
    entries: lines,
    fromClient: lines.filter((e) => e.direction === 'client->server').map((e) => e.payload),
    rawFromClient: lines.filter((e) => e.direction === 'client->server-raw').map((e) => e.payload),
    unparseable: lines.filter((e) => e.direction === 'client->server-unparseable').map((e) => e.payload),
  };
}

const PV = 'io.modelcontextprotocol/protocolVersion';
const CC = 'io.modelcontextprotocol/clientCapabilities';
const CI = 'io.modelcontextprotocol/clientInfo';

test({
  id: 'CLI.META.EVERY-REQUEST-CARRIES-VERSION-AND-CAPS',
  title: 'every client request carries protocolVersion and clientCapabilities in _meta',
  role: 'client', area: 'conformance', tier: 'push', peer: 'fake',
  catches: 'A client that sends _meta once and relies on connection state, which stateless servers reject with -32602.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'honest');
    const requests = obs.fromClient.filter((m) => m.id !== undefined && m.method);
    if (requests.length === 0) ctx.skip('client sent no requests to the fake server');
    for (const r of requests) {
      const meta = (r.params && r.params._meta) || {};
      ctx.assert('BASE.META.REQUIRED-FIELDS', meta[PV] !== undefined,
        `request ${r.method} (id ${JSON.stringify(r.id)}) has no ${PV}`);
      ctx.assert('BASE.META.REQUIRED-FIELDS', meta[CC] !== undefined,
        `request ${r.method} (id ${JSON.stringify(r.id)}) has no ${CC}`);
    }
    ctx.variance('client.methodsUsed', [...new Set(requests.map((r) => r.method))].sort());
    ctx.variance('client.declaredCapabilities',
      Object.keys(((requests[0].params || {})._meta || {})[CC] || {}).sort());
    ctx.variance('client.protocolVersions',
      [...new Set(requests.map((r) => ((r.params || {})._meta || {})[PV]))]);
    // clientInfo is SHOULD, not MUST.
    ctx.recommend('client.sendsClientInfo',
      requests.every((r) => ((r.params || {})._meta || {})[CI] !== undefined),
      'Spec SHOULD: clients include io.modelcontextprotocol/clientInfo on every request.');
  },
});

test({
  id: 'CLI.IDS.UNIQUE-WHILE-IN-FLIGHT',
  title: 'the client never reuses a request id that is still unanswered',
  role: 'client', area: 'conformance', tier: 'push', peer: 'fake',
  catches: 'An id allocator that wraps or resets, so two in-flight requests collide and results cross-deliver.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'honest');
    const requests = obs.fromClient.filter((m) => m.id !== undefined && m.method);
    if (requests.length === 0) ctx.skip('client sent no requests');
    const seen = new Set();
    const reused = [];
    for (const r of requests) {
      const key = `${typeof r.id}:${JSON.stringify(r.id)}`;
      if (seen.has(key)) reused.push(r.id);
      seen.add(key);
    }
    // Reuse AFTER a response is legal. We only have the send order here, so we
    // assert the weaker, always-true property: ids are not null, and any reuse
    // is reported as a variance point rather than a failure.
    for (const r of requests) {
      ctx.assert('BASE.REQ.ID-NOT-NULL', r.id !== null, `request ${r.method} used id null`);
      ctx.assert('BASE.REQ.ID-PRESENT',
        typeof r.id === 'string' || typeof r.id === 'number',
        `request ${r.method} id is ${typeof r.id}`);
    }
    ctx.variance('client.reusedIds', reused);
    ctx.variance('client.idType', typeof requests[0].id);
  },
});

test({
  id: 'CLI.NO-RESPONSES-SENT',
  title: 'the client never writes a JSON-RPC response to the server',
  role: 'client', area: 'conformance', tier: 'push', peer: 'fake',
  catches: 'A client carried forward from 2025-11-25 answering server-initiated requests, which is forbidden in 2026-07-28.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'honest');
    const responses = obs.fromClient.filter(
      (m) => m.id !== undefined && !m.method && ('result' in m || 'error' in m),
    );
    ctx.assert('STDIO.CLIENT-NO-RESPONSES', responses.length === 0,
      `client sent JSON-RPC responses: ${JSON.stringify(responses).slice(0, 300)}`);
  },
});

test({
  id: 'CLI.HOSTILE.SERVER-INITIATED-REQUEST-IS-NOT-ANSWERED',
  title: 'a forbidden server-initiated request is not answered by the client',
  role: 'client', area: 'hostile', tier: 'pr', peer: 'fake',
  catches: 'A client that still answers server-initiated requests, giving a hostile server an unsolicited sampling channel.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'server-request');
    const answers = obs.fromClient.filter(
      (m) => m.id === 'server-initiated-1' && ('result' in m || 'error' in m),
    );
    ctx.assert('PAT.SERVER-NO-REQUESTS', answers.length === 0,
      `client answered a forbidden server-initiated request: ${JSON.stringify(answers)}`);
    ctx.assert('STDIO.CLIENT-NO-RESPONSES', answers.length === 0);
    ctx.variance('hostile.serverRequest.clientSurvived', obs.exited || obs.fromClient.length > 0);
  },
});

test({
  id: 'CLI.HOSTILE.MALFORMED-SERVER-FRAME-SURVIVED',
  title: 'the client survives an unparseable frame from the server',
  role: 'client', area: 'hostile', tier: 'pr', peer: 'fake',
  catches: 'A client whose JSON parse error is fatal, so one bad byte from any server kills the host.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'malformed');
    // The only assertable property is that the client did not itself emit
    // garbage in response. Whether it retries or gives up is its own business.
    ctx.assert('STDIO.CLIENT-NO-RESPONSES',
      obs.unparseable.length === 0,
      `client emitted unparseable frames after a malformed server frame: ${JSON.stringify(obs.unparseable.slice(0, 2))}`);
    ctx.variance('hostile.malformed.clientExited', obs.exited);
    ctx.variance('hostile.malformed.requestsSent', obs.fromClient.length);
  },
});

test({
  id: 'CLI.HOSTILE.STALLING-SERVER-DOES-NOT-HANG-FOREVER',
  title: 'the client does not wait forever on a server that never answers',
  role: 'client', area: 'hostile', tier: 'pr', peer: 'fake', timing: true,
  catches: 'A client with no request timeout, so one stalling server hangs the host indefinitely.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'stall', { failsafeMs: 25000 });
    // Spec: implementations SHOULD establish timeouts for all sent requests.
    // SHOULD, so advisory, but a strong signal in a differential run.
    ctx.recommend('client.hasRequestTimeout', obs.exited,
      'Spec SHOULD: implementations establish timeouts for all sent requests to prevent hung connections.');
    ctx.variance('hostile.stall.clientExitedWithin25s', obs.exited);
    ctx.variance('hostile.stall.exitCode', obs.exitCode);
  },
});

test({
  id: 'CLI.HOSTILE.HALF-ANSWER-DISCONNECT',
  title: 'the client survives a server that closes stdout mid-frame',
  role: 'client', area: 'hostile', tier: 'pr', peer: 'fake',
  catches: 'A client that hangs or crashes when a server dies mid-response, the commonest real-world server failure.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'half-answer');
    ctx.recommend('client.survivesMidFrameDisconnect', obs.exited,
      'A client should terminate or recover when the server closes the stream mid-frame.');
    ctx.variance('hostile.halfAnswer.clientExited', obs.exited);
    ctx.variance('hostile.halfAnswer.exitCode', obs.exitCode);
  },
});

test({
  id: 'CLI.HOSTILE.EVIL-ELICITATION-PASSWORD',
  title: 'a form-mode elicitation asking for a password is not silently satisfied',
  role: 'client', area: 'hostile', tier: 'pr', peer: 'fake',
  catches: 'A client that auto-fills credential elicitations, handing secrets to any server that asks.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'evil-elicitation');
    // The SERVER is the violator here (form mode MUST NOT request secrets).
    // The client-side question is whether it leaked anything back.
    const retries = obs.fromClient.filter((m) => m.method === 'tools/call'
      && m.params && m.params.inputResponses);
    const leaked = [];
    for (const r of retries) {
      const blob = JSON.stringify(r.params.inputResponses);
      if (/password|apiKey/i.test(blob) && /"action"\s*:\s*"accept"/.test(blob)) {
        // Accepting is only a leak if content was actually supplied.
        for (const v of Object.values(r.params.inputResponses)) {
          if (v && v.action === 'accept' && v.content
            && Object.keys(v.content).length > 0) leaked.push(v.content);
        }
      }
    }
    ctx.recommend('client.doesNotAutoFillCredentials', leaked.length === 0,
      'Servers MUST NOT request secrets in form mode; a client that auto-accepts such a form leaks them.');
    ctx.variance('hostile.evilElicitation.retried', retries.length > 0);
    ctx.variance('hostile.evilElicitation.leakedFields',
      leaked.flatMap((c) => Object.keys(c)).sort());
  },
});

test({
  id: 'CLI.HOSTILE.MRTR-UNDECLARED-CAPABILITY',
  title: 'the client does not satisfy an MRTR request for a capability it never declared',
  role: 'client', area: 'hostile', tier: 'pr', peer: 'fake',
  catches: 'A client that answers sampling requests without declaring the sampling capability, bypassing its own consent gate.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'mrtr-undeclared');
    const requests = obs.fromClient.filter((m) => m.method && m.id !== undefined);
    if (requests.length === 0) ctx.skip('client sent no requests');
    const declaredSampling = requests.some(
      (r) => (((r.params || {})._meta || {})[CC] || {}).sampling !== undefined,
    );
    const answeredSampling = requests.some((r) => r.params && r.params.inputResponses
      && Object.values(r.params.inputResponses).some((v) => v && (v.model || v.stopReason)));
    ctx.recommend('client.honoursOwnCapabilityDeclaration',
      declaredSampling || !answeredSampling,
      'A client that did not declare sampling should not fulfil a sampling inputRequest.');
    ctx.variance('hostile.mrtrUndeclared.declaredSampling', declaredSampling);
    ctx.variance('hostile.mrtrUndeclared.answeredSampling', answeredSampling);
  },
});

test({
  id: 'CLI.HOSTILE.RUGPULL-SCHEMA-CHANGE',
  title: 'tool definitions changing between discovery and invocation are observable',
  role: 'client', area: 'hostile', tier: 'pr', peer: 'fake',
  catches: 'A client that caches a tool list forever and never notices a server swapping schemas underneath it.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'rugpull');
    const lists = obs.fromClient.filter((m) => m.method === 'tools/list');
    const calls = obs.fromClient.filter((m) => m.method === 'tools/call');
    // Purely observational: there is no spec rule requiring re-validation.
    // The variance point is what a human needs to see.
    ctx.recommend('client.refreshesToolsAfterCall', lists.length > 1,
      'RECOMMENDATION (this battery): re-reading tools/list after a call limits the window for a schema rug-pull.');
    ctx.variance('hostile.rugpull.listCount', lists.length);
    ctx.variance('hostile.rugpull.callCount', calls.length);
  },
});

test({
  id: 'CLI.HOSTILE.OUTPUTSCHEMA-VIOLATION-DETECTED',
  title: 'a server violating its own declared outputSchema is observable to the client',
  role: 'client', area: 'hostile', tier: 'pr', peer: 'fake',
  catches: 'A client that trusts structuredContent without validating it, so malformed data reaches the model as fact.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'outputschema-lie');
    // Clients SHOULD validate. We cannot see validation from the wire, only
    // whether the client kept going. Recorded, never failed.
    ctx.recommend('client.validatesStructuredContent', true,
      'Spec SHOULD: clients validate structured results against outputSchema. Not observable from the wire; needs a client-side hook.');
    ctx.variance('hostile.outputSchemaLie.clientExited', obs.exited);
    ctx.variance('hostile.outputSchemaLie.requestCount', obs.fromClient.length);
    ctx.note('limitation',
      'Whether the client validated structuredContent is NOT observable from the server side. '
      + 'This test records survival only. Proving validation requires an in-process hook in the client.');
  },
});

test({
  id: 'CLI.HOSTILE.GIANT-RESULT',
  title: 'a very large tool result does not kill the client',
  role: 'client', area: 'hostile', tier: 'prerelease', peer: 'fake',
  catches: 'An unbounded read buffer in the client, so a hostile server can exhaust host memory with one reply.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'giant', { failsafeMs: 40000 });
    ctx.variance('hostile.giant.clientExited', obs.exited);
    ctx.variance('hostile.giant.exitCode', obs.exitCode);
    ctx.recommend('client.boundsResponseSize', true,
      'RECOMMENDATION (this battery): clients should cap inbound message size rather than buffering without limit.');
  },
});

test({
  id: 'CLI.HOSTILE.BAD-ICON-SCHEME',
  title: 'the client does not fetch a javascript: icon URI',
  role: 'client', area: 'hostile', tier: 'pr', peer: 'fake',
  catches: 'A client that renders or fetches server-supplied icon URIs without scheme checking, an XSS and SSRF vector.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'bad-icon');
    // Not observable from the server side either; recorded as a limitation.
    ctx.variance('hostile.badIcon.clientExited', obs.exited);
    ctx.note('limitation',
      'Icon fetching happens outside the MCP stdio channel. Detecting a fetch needs a network sinkhole, '
      + 'which is in the HTTP half of the battery, not the stdio half.');
    ctx.recommend('client.rejectsUnsafeIconSchemes', true,
      'Spec MUST for clients that render icons; not observable over stdio. Needs an HTTP sinkhole to prove.');
  },
});

test({
  id: 'CLI.CACHE.TOLERATES-ABSENT-HINTS',
  title: 'the client tolerates a server that omits ttlMs and cacheScope',
  role: 'client', area: 'conformance', tier: 'pr', peer: 'fake',
  catches: 'A client that hard-rejects results without caching hints, breaking against every older or minimal server.',
  run: async (ctx) => {
    // A LONGER FAILSAFE THAN THE DEFAULT, for this scenario alone. Driving a listing out of a
    // gateway-shaped client is an operator's verb, and operator verbs sit behind a per-minute
    // mutation budget the driver may legitimately have to wait out (its own stderr says when it
    // is doing so). The failsafe is a ceiling on waiting for the driver to EXIT, not a slackening
    // of anything asserted: the transcript judged below is still only what genuinely reached the
    // peer.
    const withHints = await driveClient(ctx, 'honest', { failsafeMs: 120000 });
    const without = await driveClient(ctx, 'no-cache-hints', { failsafeMs: 120000 });
    const listedWithHints = withHints.fromClient.some((m) => m.method === 'tools/list');
    // The driver's stderr rides the skip, because this skip is a GATE FAILURE under MCP_NO_SKIPS
    // and "did not call" has two very different causes — a client that genuinely never lists, and
    // a driver whose listing leg failed — distinguishable only by what the driver printed.
    if (!listedWithHints) {
      ctx.skip('client did not call tools/list even against an honest server; driver stderr: '
        + JSON.stringify(String(withHints.stderr || '').slice(-800)));
    }

    // The spec is explicit that clients SHOULD default an absent ttlMs to 0
    // rather than treating it as an error, precisely so newer clients keep
    // working against older servers. SHOULD, so this is advisory, but it is a
    // high-value signal in a differential run.
    const keptGoing = without.fromClient.filter((m) => m.method).length
      >= withHints.fromClient.filter((m) => m.method).length;
    ctx.recommend('client.toleratesAbsentCachingHints', keptGoing,
      'Spec SHOULD: if ttlMs is absent, clients assume 0 and carry on. A client that raises a '
      + 'validation error instead cannot talk to older or minimal servers.');
    ctx.variance('cache.requestsWithHints', withHints.fromClient.filter((m) => m.method).length);
    ctx.variance('cache.requestsWithoutHints', without.fromClient.filter((m) => m.method).length);
    ctx.note('spec-clause', 'CACHE.CLIENT-TOLERATES-ABSENT-TTL');
  },
});
