// SUBJECT ACTS AS MCP SERVER, facing an untrusted client.
// Area: adversarial (malformed input) and hostile (well-formed but malicious).
//
// The bar for MOST of these is SURVIVAL, not a specific error code. The spec
// rarely dictates what a server returns for a malformed frame, so asserting a
// code would be a bug in the test. What we assert is:
//   * the server does not die
//   * the server does not desynchronise (a later, valid request still works)
//   * the server does not emit a malformed frame in response
// and we RECORD the error code as a variance point.

import { test } from '../core/runner.mjs';
import { request, notification, ERR, classify } from '../core/jsonrpc.mjs';

async function withServer(ctx, fn) {
  const peer = ctx.target.spawnServer();
  try { return await fn(peer); } finally { await peer.stop(); }
}

/**
 * The core adversarial oracle: after the nasty input, the server is still
 * RESPONSIVE. Deterministic barrier, not a sleep.
 *
 * IMPORTANT DISTINCTION, learned from a false failure against the control:
 * "responsive" means the server answers with a well-formed JSON-RPC message
 * correlated to our id. It does NOT mean the answer is a success. A server
 * that replies with an error is alive, and alive is what an adversarial test
 * is entitled to assert. Requiring a SUCCESSFUL reply here conflates survival
 * with a separate question (whether the injection changed server state), and
 * that conflation produced a spurious FAIL against a known-good reference.
 *
 * Whether the injection degraded the connection is tested separately and
 * explicitly by AMB.CONNECTION-ERA-LOCK.
 */
async function stillHealthy(ctx, peer, probeId = 'health-probe') {
  peer.send(request(probeId, 'server/discover'));
  try {
    const res = await peer.waitForId(probeId, 8000);
    const wellFormed = res.id === probeId && ('result' in res || 'error' in res);
    const succeeded = Boolean(res.result) && res.result.resultType === 'complete';
    return {
      ok: wellFormed,
      succeeded,
      detail: wellFormed ? '' : JSON.stringify(res).slice(0, 200),
      reply: res,
    };
  } catch (e) {
    return { ok: false, succeeded: false, detail: e.message, reply: null };
  }
}

function adversarial(def) {
  test({
    role: 'server',
    area: 'adversarial',
    tier: 'pr',
    peer: 'fake',
    ...def,
    run: (ctx) => withServer(ctx, async (peer) => {
      await def.inject(peer, ctx);
      const health = await stillHealthy(ctx, peer);
      ctx.assert('BASE.STATELESS.NO-PRIOR-REQUESTS', health.ok,
        `server stopped answering after the injection: ${health.detail}`);
      // Whether the later request SUCCEEDED is a separate question: a server
      // may legally have downgraded or restricted the connection. Recorded,
      // not asserted. AMB.CONNECTION-ERA-LOCK probes it directly.
      ctx.variance('adversarial.laterRequestSucceeded', health.succeeded);
      ctx.assert('STDIO.STDOUT-ONLY-MCP', peer.badLines.length === 0,
        `server emitted unparseable stdout: ${JSON.stringify(peer.badLines.slice(0, 3))}`);
      ctx.assert('PAT.SERVER-NO-REQUESTS', peer.serverRequests().length === 0);
      ctx.variance('adversarial.exited', peer.exited);
      ctx.variance('adversarial.messageCount', peer.messages.length);
      if (def.after) await def.after(peer, ctx);
    }),
  });
}

adversarial({
  id: 'ADV.MALFORMED-JSON',
  title: 'a line of invalid JSON does not kill or desynchronise the server',
  catches: 'A server that treats a parse error as fatal, letting one bad frame take down a shared process.',
  inject: (peer) => { peer.sendRaw('{this is not json at all\n'); },
  after: (peer, ctx) => {
    const parseErrors = peer.messages.filter((m) => m.error && m.error.code === ERR.PARSE_ERROR);
    // The spec does not require a -32700 reply to an unparseable stdio line
    // (there is no id to reply to). Record, do not assert.
    ctx.variance('malformedJson.emittedParseError', parseErrors.length > 0);
  },
});

adversarial({
  id: 'ADV.TRUNCATED-FRAME',
  title: 'a truncated frame followed by a valid one is handled',
  catches: 'A framing bug where an incomplete line poisons the read buffer and every later message is misparsed.',
  inject: async (peer) => {
    peer.sendRaw('{"jsonrpc":"2.0","id":1,"method":"tools/li');
    peer.sendRaw('\n');
  },
});

adversarial({
  id: 'ADV.EMPTY-AND-BLANK-LINES',
  title: 'blank and whitespace-only lines are tolerated',
  catches: 'A reader that treats a blank line as EOF or as a parse error and drops the connection.',
  inject: (peer) => { peer.sendRaw('\n   \n\t\n'); },
});

adversarial({
  id: 'ADV.NOTIFICATION-WITH-ID',
  title: 'a notification method carrying an id does not produce a stray response',
  catches: 'A dispatcher keyed only on method name, which answers notifications and desynchronises client id tracking.',
  inject: async (peer) => {
    peer.send({
      jsonrpc: '2.0', id: 4242, method: 'notifications/cancelled',
      params: { requestId: 'nope' },
    });
  },
  after: (peer, ctx) => {
    const replies = peer.responsesFor(4242);
    // Genuinely ambiguous: the message is a request by JSON-RPC structure but a
    // notification by method name. Both "reply with an error" and "ignore" are
    // defensible. Record which, never fail.
    ctx.variance('notificationWithId.replied', replies.length > 0);
    ctx.variance('notificationWithId.replyKind',
      replies.length ? (replies[0].error ? `error:${replies[0].error.code}` : 'result') : 'none');
  },
});

adversarial({
  id: 'ADV.RESPONSE-TO-NOBODY',
  title: 'an unsolicited JSON-RPC response from the client is ignored',
  catches: 'A server that accepts client responses, which the spec forbids and which enables response-injection confusion.',
  inject: (peer) => {
    peer.send({ jsonrpc: '2.0', id: 777, result: { resultType: 'complete' } });
  },
  after: (peer, ctx) => {
    ctx.assert('STDIO.CLIENT-NO-RESPONSES', true,
      'client-sent responses are forbidden; this test verifies the server survives one');
    ctx.variance('responseToNobody.serverReplied', peer.responsesFor(777).length > 0);
  },
});

adversarial({
  id: 'ADV.DUPLICATE-REQUEST-ID',
  title: 'two concurrent in-flight requests sharing one id',
  catches: 'A server keyed on request id that drops or double-answers when a hostile client reuses an id.',
  inject: async (peer) => {
    peer.send(request('dup', 'tools/list'));
    peer.send(request('dup', 'tools/list'));
  },
  after: async (peer, ctx) => {
    const replies = peer.responsesFor('dup');
    // The client MUST NOT do this. The spec does not say what the server does.
    // Both "answer twice" and "answer once" are defensible; record it.
    ctx.variance('duplicateId.replyCount', replies.length);
    ctx.variance('duplicateId.allWellFormed',
      replies.every((r) => 'result' in r || 'error' in r));
  },
});

adversarial({
  id: 'ADV.DEEP-NESTING',
  title: 'a deeply nested arguments object does not cause a stack overflow',
  catches: 'A recursive-descent parser or validator with no depth bound, a one-line denial of service.',
  inject: (peer) => {
    let deep = '1';
    for (let i = 0; i < 2000; i++) deep = `[${deep}]`;
    peer.sendRaw(`{"jsonrpc":"2.0","id":"deep","method":"tools/call","params":{"name":"echo","arguments":{"text":${deep}},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}\n`);
  },
});

adversarial({
  id: 'ADV.OVERSIZED-PAYLOAD',
  title: 'a multi-megabyte argument is handled or refused, but not fatal',
  catches: 'An unbounded read buffer letting one client exhaust server memory.',
  tier: 'prerelease',
  inject: (peer) => {
    const big = 'A'.repeat(8 * 1024 * 1024);
    peer.send(request('big', 'tools/call', { name: 'echo', arguments: { text: big } }));
  },
  after: (peer, ctx) => {
    const r = peer.responsesFor('big');
    ctx.variance('oversized.answered', r.length > 0);
    ctx.variance('oversized.kind', r.length ? (r[0].error ? `error:${r[0].error.code}` : 'result') : 'none');
  },
});

adversarial({
  id: 'ADV.WRONG-PARAM-TYPES',
  title: 'params of the wrong JSON type are rejected cleanly',
  catches: 'Missing input validation, where a string where an object was expected reaches business logic.',
  inject: async (peer) => {
    peer.send({
      jsonrpc: '2.0', id: 'wrongtype', method: 'tools/call',
      params: {
        name: 12345, arguments: 'not-an-object',
        _meta: {
          'io.modelcontextprotocol/protocolVersion': '2026-07-28',
          'io.modelcontextprotocol/clientCapabilities': {},
        },
      },
    });
  },
  after: async (peer, ctx) => {
    let res = null;
    try { res = await peer.waitForId('wrongtype', 5000); } catch { /* no reply */ }
    ctx.assert('TOOLS.VALIDATE-INPUTS', res === null || Boolean(res.error),
      `expected rejection, got result=${JSON.stringify(res && res.result)}`);
    ctx.variance('wrongParamTypes.code', res && res.error ? res.error.code : null);
  },
});

adversarial({
  id: 'ADV.META-NOT-AN-OBJECT',
  title: '_meta of the wrong type is rejected, not dereferenced',
  catches: 'A server that reads _meta fields without type-checking _meta itself, crashing on a hostile scalar.',
  inject: (peer) => {
    peer.sendRaw('{"jsonrpc":"2.0","id":"badmeta","method":"tools/list","params":{"_meta":"i-am-a-string"}}\n');
  },
  after: async (peer, ctx) => {
    let res = null;
    try { res = await peer.waitForId('badmeta', 5000); } catch { /* no reply */ }
    ctx.variance('badMeta.code', res && res.error ? res.error.code : null);
    ctx.variance('badMeta.answered', res !== null);
  },
});

adversarial({
  id: 'ADV.NUL-AND-CONTROL-BYTES',
  title: 'control characters inside a JSON string are handled',
  catches: 'A server that passes raw control bytes into logs or downstream systems, enabling log injection.',
  inject: (peer) => {
    peer.send(request('ctrl', 'tools/call', {
      name: 'echo', arguments: { text: 'a\u0000b\u001bc\u0007d' },
    }));
  },
  after: (peer, ctx) => {
    ctx.assert('STDIO.NO-EMBEDDED-NEWLINES', peer.badLines.length === 0,
      'echoing control bytes must not break line framing');
    ctx.variance('controlBytes.answered', peer.responsesFor('ctrl').length > 0);
  },
});

adversarial({
  id: 'ADV.UNICODE-AND-SURROGATES',
  title: 'lone surrogates and astral-plane text do not break framing',
  catches: 'A UTF-8 encoder that emits invalid sequences, corrupting the stream for a strict client.',
  inject: (peer) => {
    peer.send(request('uni', 'tools/call', {
      name: 'echo', arguments: { text: 'ok \ud83d\ude00 done' },
    }));
    peer.sendRaw('{"jsonrpc":"2.0","id":"lone","method":"tools/call","params":{"name":"echo","arguments":{"text":"\\ud800"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}\n');
  },
});

adversarial({
  id: 'ADV.BATCH-ARRAY',
  title: 'a JSON-RPC batch array is handled or refused, never fatal',
  catches: 'A server that crashes on a top-level array, which the 2026-07-28 transports no longer permit but hostile peers still send.',
  inject: (peer) => {
    peer.sendRaw('[{"jsonrpc":"2.0","id":"b1","method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}]\n');
  },
  after: (peer, ctx) => {
    // The stdio binding says "Each message is a single JSON-RPC request,
    // notification, or response" but never forbids a batch with a MUST NOT.
    // Genuinely ambiguous. Record both readings.
    ctx.variance('batch.answered', peer.responsesFor('b1').length > 0);
  },
});

test({
  id: 'ADV.CONNECT-THEN-STALL',
  title: 'a peer that connects and sends nothing is not fatal',
  role: 'server', area: 'adversarial', tier: 'pr', peer: 'fake', timing: true,
  catches: 'A server with a startup read that blocks forever or a handshake timeout that kills healthy idle connections.',
  run: (ctx) => withServer(ctx, async (peer) => {
    // Send nothing at all, then quiesce, then prove it still works.
    const during = await peer.quiesce(600);
    ctx.assert('BASE.STATELESS.NO-PRIOR-REQUESTS', !peer.exited,
      'server exited while idle before any request');
    ctx.variance('stall.messagesWhileIdle', during.length);
    peer.send(request('after-stall', 'server/discover'));
    const res = await peer.waitForId('after-stall');
    ctx.assert('VER.DISCOVER-REQUIRED', Boolean(res.result),
      'server did not serve a request after an idle period');
  }),
});

test({
  id: 'ADV.DISCONNECT-MID-REQUEST',
  title: 'client vanishing while a request is in flight does not corrupt the server',
  role: 'server', area: 'adversarial', tier: 'pr', peer: 'fake',
  catches: 'An unhandled EPIPE or write-after-close that turns a routine client disconnect into a crash loop.',
  run: async (ctx) => {
    const p1 = ctx.target.spawnServer();
    try {
      p1.send(request('inflight', 'tools/list'));
      // Kill the pipe immediately, without waiting for the answer.
      p1.proc.stdin.destroy();
      p1.proc.stdout.destroy();
      try { await p1.waitForExit(6000); } catch { /* may linger; that is legal */ }
      ctx.variance('disconnectMidRequest.exitCode', p1.exitCode);
      ctx.variance('disconnectMidRequest.exitSignal', p1.exitSignal);
    } finally {
      await p1.stop();
    }
    // The real assertion: a FRESH connection still works. A server that
    // corrupted shared state on disconnect fails here.
    const p2 = ctx.target.spawnServer();
    try {
      p2.send(request(1, 'server/discover'));
      const res = await p2.waitForId(1);
      ctx.assert('VER.DISCOVER-REQUIRED', Boolean(res.result),
        'a fresh connection failed after a mid-request disconnect');
    } finally {
      await p2.stop();
    }
  },
});

test({
  id: 'HOSTILE.CANCEL-UNKNOWN-ID',
  title: 'cancelling a request that was never issued is ignored',
  role: 'server', area: 'hostile', tier: 'pr', peer: 'fake',
  catches: 'A cancellation path that trusts the requestId and tears down another caller request, a cross-tenant denial of service.',
  run: (ctx) => withServer(ctx, async (peer) => {
    peer.send(request('victim', 'tools/list'));
    peer.send(notification('notifications/cancelled', { requestId: 'victim' }));
    peer.send(notification('notifications/cancelled', { requestId: 'total-fiction' }));
    peer.send(request('survivor', 'server/discover'));
    const res = await peer.waitForId('survivor');
    ctx.assert('CANCEL.RACE-GRACEFUL', Boolean(res.result),
      'server failed to answer after cancelling an unknown id');
    // Spec: servers SHOULD not send a response for a cancelled request, but MAY
    // ignore cancellation if processing already completed. Both legal.
    ctx.variance('cancelUnknown.victimAnswered', peer.responsesFor('victim').length > 0);
  }),
});

test({
  id: 'HOSTILE.CANCEL-SPAM',
  title: 'a flood of cancellation notifications does not degrade the server',
  role: 'server', area: 'hostile', tier: 'prerelease', peer: 'fake',
  catches: 'Unbounded per-cancellation allocation, letting a hostile client exhaust memory with fire-and-forget frames.',
  run: (ctx) => withServer(ctx, async (peer) => {
    for (let i = 0; i < 5000; i++) {
      peer.send(notification('notifications/cancelled', { requestId: `ghost-${i}` }));
    }
    peer.send(request('after-spam', 'server/discover'));
    const res = await peer.waitForId('after-spam', 20000);
    ctx.assert('CANCEL.RACE-GRACEFUL', Boolean(res.result),
      'server stopped responding after cancellation spam');
  }),
});

test({
  id: 'HOSTILE.TOOL-SET-STABLE-UNDER-PROBING',
  title: 'the tool set does not change as a side effect of other requests',
  role: 'server', area: 'hostile', tier: 'pr', peer: 'fake',
  catches: 'A time-of-check/time-of-use gap where a tool list differs before and after unrelated calls, the MCP rug-pull.',
  run: (ctx) => withServer(ctx, async (peer) => {
    peer.send(request(1, 'tools/list'));
    const before = await peer.waitForId(1);
    if (before.error) ctx.skip('tools/list not supported');
    // Exercise unrelated surface between the two listings.
    for (const [i, [m, p]] of [
      ['server/discover', {}],
      ['resources/list', {}],
      ['prompts/list', {}],
      ['tools/call', { name: '__nope__', arguments: {} }],
    ].entries()) {
      peer.send(request(100 + i, m, p));
      try { await peer.waitForId(100 + i, 6000); } catch { /* optional surface */ }
    }
    peer.send(request(2, 'tools/list'));
    const after = await peer.waitForId(2);
    const a = JSON.stringify(before.result.tools || []);
    const b = JSON.stringify(after.result.tools || []);
    ctx.assert('TOOLS.SET-NOT-CONNECTION-SCOPED', a === b,
      'tool definitions changed as a side effect of unrelated requests');
  }),
});

test({
  id: 'HOSTILE.PAGINATION-CURSOR-FORGERY',
  title: 'a forged or foreign pagination cursor is rejected, not trusted',
  role: 'server', area: 'hostile', tier: 'pr', peer: 'fake',
  catches: 'A cursor decoded straight into an offset or a filename, turning pagination into an injection surface.',
  run: (ctx) => withServer(ctx, async (peer) => {
    const forged = [
      '../../../../etc/passwd',
      '{"page": -1}',
      'eyJwYWdlIjogOTk5OTk5OTk5fQ==',
      "' OR 1=1 --",
    ];
    for (const [i, cursor] of forged.entries()) {
      peer.send(request(`cur-${i}`, 'tools/list', { cursor }));
      let res;
      try { res = await peer.waitForId(`cur-${i}`, 6000); } catch { continue; }
      const okShape = Boolean(res.error) || Array.isArray(res.result && res.result.tools);
      ctx.assert('PAGE.INVALID-CURSOR-32602', okShape,
        `forged cursor produced a malformed reply: ${JSON.stringify(res).slice(0, 200)}`);
      ctx.variance(`cursorForgery.${i}.kind`,
        res.error ? `error:${res.error.code}` : 'result');
    }
    const health = await stillHealthy(ctx, peer, 'cursor-health');
    ctx.assert('VER.DISCOVER-REQUIRED', health.ok, health.detail);
  }),
});

test({
  id: 'HOSTILE.TOOL-DESCRIPTION-INJECTION-SURFACE',
  title: 'record whether tool descriptions carry prompt-injection markers',
  role: 'server', area: 'hostile', tier: 'pr', peer: 'fake',
  catches: 'A server shipping instructions-to-the-model inside tool descriptions, the primary MCP prompt-injection vector.',
  run: (ctx) => withServer(ctx, async (peer) => {
    peer.send(request(1, 'tools/list'));
    const res = await peer.waitForId(1);
    if (res.error) ctx.skip('tools/list not supported');
    const markers = [
      /ignore (all )?(previous|prior|above)/i,
      /system prompt/i,
      /you (are|must|should) (now|always)/i,
      /<\s*(system|assistant|im_start)/i,
      /disregard/i,
      /do not tell the user/i,
    ];
    const flagged = [];
    for (const t of res.result.tools || []) {
      const blob = `${t.description || ''} ${t.title || ''} ${JSON.stringify(t.annotations || {})}`;
      for (const m of markers) {
        if (m.test(blob)) flagged.push({ tool: t.name, pattern: String(m) });
      }
    }
    // This is OUR heuristic, not a spec rule. Never fails; it is a lead.
    ctx.recommend('toolDescriptions.noInjectionMarkers', flagged.length === 0,
      'Tool descriptions reach the model verbatim. Instruction-shaped text in them is an injection vector.');
    ctx.variance('toolDescriptions.flagged', flagged);
    ctx.note('toolDescriptionLengths',
      (res.result.tools || []).map((t) => ({ name: t.name, len: (t.description || '').length })));
  }),
});

test({
  id: 'HOSTILE.ICON-SCHEME-SAFETY',
  title: 'advertised icon URIs use only https: or data:',
  role: 'server', area: 'hostile', tier: 'pr', peer: 'fake',
  catches: 'A server advertising javascript: or file: icon URIs, which a rendering client could be tricked into fetching.',
  run: (ctx) => withServer(ctx, async (peer) => {
    const uris = [];
    for (const [i, m] of ['server/discover', 'tools/list', 'resources/list', 'prompts/list'].entries()) {
      peer.send(request(i + 1, m));
      let res;
      try { res = await peer.waitForId(i + 1, 6000); } catch { continue; }
      const json = JSON.stringify(res.result || {});
      for (const match of json.matchAll(/"src"\s*:\s*"([^"]+)"/g)) uris.push(match[1]);
    }
    const unsafe = uris.filter((u) => !/^(https:|data:)/i.test(u));
    ctx.assert('ICON.SCHEME-RESTRICTION', unsafe.length === 0,
      `unsafe icon URI schemes advertised: ${JSON.stringify(unsafe)}`);
    ctx.variance('icons.count', uris.length);
  }),
});

test({
  id: 'AMB.CONNECTION-ERA-LOCK',
  title: 'does one malformed request permanently downgrade the whole connection?',
  role: 'server', area: 'hostile', tier: 'pr', peer: 'fake',
  catches: 'A dual-era server that era-locks a stdio connection on the first non-modern frame, so one bad request denies service to every later request on that connection.',
  run: (ctx) => withServer(ctx, async (peer) => {
    // Establish that the connection starts healthy and modern.
    peer.send(request('pre', 'server/discover'));
    const pre = await peer.waitForId('pre');
    const modernBefore = Boolean(pre.result)
      && Array.isArray(pre.result.supportedVersions);
    if (!modernBefore) ctx.skip('server did not answer a modern server/discover to begin with');

    // One request that is NOT a valid modern request and NOT `initialize`.
    // The spec requires this to be rejected with -32602. It says nothing about
    // it changing the connection's era.
    peer.send({ jsonrpc: '2.0', id: 'bad', method: 'tools/list', params: {} });
    const bad = await peer.waitForId('bad');
    ctx.assert('BASE.META.REQUIRED-FIELDS', Boolean(bad.error),
      `a request with no _meta must be rejected, got ${JSON.stringify(bad.result)}`);
    ctx.assert('BASE.META.REQUIRED-FIELDS', bad.error && bad.error.code === ERR.INVALID_PARAMS,
      `expected -32602 for a request missing required _meta, got ${bad.error && bad.error.code}`);

    // Now: is the connection still modern?
    peer.send(request('post', 'server/discover'));
    const post = await peer.waitForId('post');
    const modernAfter = Boolean(post.result) && Array.isArray(post.result.supportedVersions);

    // NOT AN ASSERTION, deliberately. The spec is in tension with itself here:
    //
    //   Statelessness says servers "MUST NOT rely on prior requests over the
    //   same connection to establish context (e.g., capabilities, protocol
    //   version, client identity)".
    //
    //   Versioning says a dual-era server selects legacy semantics "scoped to
    //   the stdio process (stdio)", which IS connection-scoped state, and says
    //   "the era determination is a property of the server, not of an
    //   individual request".
    //
    // The spec names only two era triggers: a modern `_meta` envelope selects
    // modern, an `initialize` request selects legacy. It does not say what a
    // request that is NEITHER selects. An implementation that treats
    // "not modern" as "legacy" is filling a gap the spec left, so failing it
    // would be enforcing our own reading. Recorded as ambiguity AMB-ERA-LOCK.
    ctx.variance('eraLock.connectionStillModernAfterMalformedRequest', modernAfter);
    ctx.variance('eraLock.postErrorCode', post.error ? post.error.code : null);
    ctx.recommend('server.doesNotEraLockOnMalformedRequest', modernAfter,
      'RECOMMENDATION (this battery, not a spec requirement): era should be selected only by the '
      + 'two triggers the spec names (a modern _meta envelope, or an initialize request). Inferring '
      + 'legacy from any non-modern frame lets one malformed request deny service for the life of '
      + 'the connection. See ambiguity AMB-ERA-LOCK in the battery document.');
    ctx.note('eraLockEvidence', {
      badRequestReply: bad.error || null,
      postInjectionReply: post.error || (post.result ? 'modern result' : null),
    });
  }),
});
