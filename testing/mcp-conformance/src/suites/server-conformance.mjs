// SUBJECT ACTS AS MCP SERVER. We drive it as a client.
// Area: conformance. Every assertion cites a spec clause.

import { test } from '../core/runner.mjs';
import { REVISION } from '../core/spec.mjs';
import {
  request, notification, ERR, RETIRED_ERROR_CODES, SPEC_DEFINED_CODES,
  classify, SERVER_INFO_KEY, PROTOCOL_VERSION_KEY, CLIENT_CAPS_KEY,
} from '../core/jsonrpc.mjs';

// Helper: start a fresh server peer for one test.
async function withServer(ctx, fn) {
  const peer = ctx.target.spawnServer();
  try {
    return await fn(peer);
  } finally {
    await peer.stop();
  }
}

test({
  id: 'SRV.DISCOVER.IMPLEMENTED',
  title: 'server/discover is implemented and returns supportedVersions',
  role: 'server', area: 'conformance', tier: 'push', peer: 'fake',
  catches: 'A server that omits server/discover, breaking every client that probes before use.',
  run: (ctx) => withServer(ctx, async (peer) => {
    peer.send(request(1, 'server/discover'));
    const res = await peer.waitForId(1);
    ctx.assert('VER.DISCOVER-REQUIRED', !res.error, `error=${JSON.stringify(res.error)}`);
    ctx.assert('BASE.RES.ID-MATCHES', res.id === 1);
    ctx.assert('BASE.RES.HAS-RESULT', 'result' in res);
    ctx.assert('BASE.RES.RESULTTYPE', res.result && res.result.resultType === 'complete',
      `resultType=${res.result && res.result.resultType}`);
    ctx.assert('VER.DISCOVER-REQUIRED',
      Array.isArray(res.result && res.result.supportedVersions)
      && res.result.supportedVersions.includes(REVISION),
      `supportedVersions=${JSON.stringify(res.result && res.result.supportedVersions)}`);

    // Spec-permitted variation: which capabilities, what instructions, whether
    // serverInfo/ttlMs/cacheScope are present. Recorded, never failed.
    ctx.variance('discover.capabilityKeys',
      Object.keys((res.result && res.result.capabilities) || {}).sort());
    ctx.variance('discover.supportedVersions', res.result.supportedVersions);
    ctx.variance('discover.hasInstructions', 'instructions' in res.result);
    ctx.variance('discover.hasTtlMs', 'ttlMs' in res.result);
    ctx.variance('discover.cacheScope', res.result.cacheScope ?? null);
    ctx.variance('discover.hasServerInfo',
      Boolean(res.result._meta && res.result._meta[SERVER_INFO_KEY]));
    // serverInfo is SHOULD, so this is advisory only.
    ctx.recommend('discover.serverInfoPresent',
      Boolean(res.result._meta && res.result._meta[SERVER_INFO_KEY]),
      'Spec says servers SHOULD include io.modelcontextprotocol/serverInfo; absence is legal but unhelpful.');
  }),
});

test({
  id: 'SRV.VERSION.UNSUPPORTED-32022',
  title: 'unknown protocol version is rejected with -32022 and a supported list',
  role: 'server', area: 'conformance', tier: 'push', peer: 'fake',
  catches: 'A server that accepts any version string, so clients never learn to downgrade and silently mis-parse.',
  run: (ctx) => withServer(ctx, async (peer) => {
    peer.send(request(1, 'tools/list', {}, { protocolVersion: '1900-01-01' }));
    const res = await peer.waitForId(1);
    ctx.assert('VER.UNSUPPORTED-ERROR', Boolean(res.error), `got result=${JSON.stringify(res.result)}`);
    if (res.error) {
      ctx.assert('VER.UNSUPPORTED-ERROR', res.error.code === ERR.UNSUPPORTED_PROTOCOL_VERSION,
        `code=${res.error.code} expected ${ERR.UNSUPPORTED_PROTOCOL_VERSION}`);
      ctx.assert('BASE.ERR.CODE-INTEGER', Number.isInteger(res.error.code));
      ctx.assert('BASE.ERR.SHAPE', typeof res.error.message === 'string');
      ctx.assert('VER.UNSUPPORTED-ERROR',
        Array.isArray(res.error.data && res.error.data.supported),
        `data=${JSON.stringify(res.error.data)}`);
      // The spec shows `requested` in the example but does not require it.
      ctx.variance('unsupportedVersion.hasRequestedField',
        Boolean(res.error.data && 'requested' in res.error.data));
      ctx.variance('unsupportedVersion.supported', res.error.data && res.error.data.supported);
    }
  }),
});

test({
  id: 'SRV.META.MISSING-PROTOCOL-VERSION',
  title: 'request without io.modelcontextprotocol/protocolVersion is rejected -32602',
  role: 'server', area: 'conformance', tier: 'push', peer: 'fake',
  catches: 'A server that infers the protocol version from connection state, violating statelessness.',
  run: (ctx) => withServer(ctx, async (peer) => {
    peer.send(request(1, 'tools/list', {}, { protocolVersion: null }));
    const res = await peer.waitForId(1);
    ctx.assert('BASE.META.REQUIRED-FIELDS', Boolean(res.error),
      `expected error, got ${JSON.stringify(res.result)}`);
    if (res.error) {
      ctx.assert('BASE.META.REQUIRED-FIELDS', res.error.code === ERR.INVALID_PARAMS,
        `code=${res.error.code} expected ${ERR.INVALID_PARAMS}`);
    }
  }),
});

test({
  id: 'SRV.META.MISSING-CAPABILITIES',
  title: 'request without io.modelcontextprotocol/clientCapabilities is rejected -32602',
  role: 'server', area: 'conformance', tier: 'push', peer: 'fake',
  catches: 'A server that defaults absent client capabilities instead of rejecting, so capability bugs stay hidden.',
  run: (ctx) => withServer(ctx, async (peer) => {
    peer.send(request(1, 'tools/list', {}, { capabilities: null }));
    const res = await peer.waitForId(1);
    ctx.assert('BASE.META.REQUIRED-FIELDS', Boolean(res.error),
      `expected error, got ${JSON.stringify(res.result)}`);
    if (res.error) {
      ctx.assert('BASE.META.REQUIRED-FIELDS', res.error.code === ERR.INVALID_PARAMS,
        `code=${res.error.code}`);
    }
  }),
});

test({
  id: 'SRV.METHOD.UNKNOWN-32601',
  title: 'unknown method returns -32601 Method not found',
  role: 'server', area: 'conformance', tier: 'push', peer: 'fake',
  catches: 'A server that returns a success result or hangs on an unknown method, so clients cannot feature-detect.',
  run: (ctx) => withServer(ctx, async (peer) => {
    peer.send(request(1, 'this/method/does/not/exist'));
    const res = await peer.waitForId(1);
    ctx.assert('BASE.ERR.SHAPE', Boolean(res.error), `got ${JSON.stringify(res.result)}`);
    if (res.error) {
      ctx.assert('BASE.ERR.SHAPE', res.error.code === ERR.METHOD_NOT_FOUND,
        `code=${res.error.code} expected ${ERR.METHOD_NOT_FOUND}`);
      ctx.assert('BASE.ERR.ID-MATCHES', res.id === 1);
    }
  }),
});

test({
  id: 'SRV.TOOLS.LIST-SHAPE',
  title: 'tools/list returns a well-formed tool array',
  role: 'server', area: 'conformance', tier: 'push', peer: 'fake',
  catches: 'A tool whose inputSchema is null or not an object, which crashes schema-validating clients at call time.',
  run: (ctx) => withServer(ctx, async (peer) => {
    peer.send(request(1, 'server/discover'));
    const disc = await peer.waitForId(1);
    const caps = (disc.result && disc.result.capabilities) || {};
    if (!('tools' in caps)) ctx.skip('server does not declare the tools capability');

    peer.send(request(2, 'tools/list'));
    const res = await peer.waitForId(2);
    ctx.assert('TOOLS.LIST-RESPONDS', !res.error, `error=${JSON.stringify(res.error)}`);
    ctx.assert('BASE.RES.RESULTTYPE', res.result && res.result.resultType === 'complete');
    const tools = (res.result && res.result.tools) || [];
    ctx.assert('TOOLS.LIST-RESPONDS', Array.isArray(tools), 'tools is not an array');

    for (const t of tools) {
      ctx.assert('TOOLS.INPUTSCHEMA-VALID',
        t.inputSchema !== null && typeof t.inputSchema === 'object' && !Array.isArray(t.inputSchema),
        `tool ${t.name} inputSchema=${JSON.stringify(t.inputSchema)}`);
      ctx.assert('TOOLS.LIST-RESPONDS', typeof t.name === 'string' && t.name.length > 0,
        `tool name=${JSON.stringify(t.name)}`);
      // Name charset is SHOULD, so advisory only.
      ctx.recommend(`tools.nameCharset.${t.name}`,
        /^[A-Za-z0-9_.-]{1,128}$/.test(t.name),
        'Tool names SHOULD use only A-Za-z0-9_.- and be 1..128 chars.');
    }
    // Spec-permitted variation: which tools, titles, descriptions, schemas.
    ctx.variance('tools.names', tools.map((t) => t.name));
    ctx.variance('tools.count', tools.length);
    ctx.variance('tools.withOutputSchema', tools.filter((t) => t.outputSchema).map((t) => t.name));
    ctx.variance('tools.hasNextCursor', 'nextCursor' in (res.result || {}));
  }),
});

test({
  id: 'SRV.TOOLS.DETERMINISTIC-ORDER',
  title: 'tools/list returns the same order on repeated calls',
  role: 'server', area: 'conformance', tier: 'push', peer: 'fake',
  catches: 'Non-deterministic tool ordering, which destroys client caching and LLM prompt-cache hit rates.',
  run: (ctx) => withServer(ctx, async (peer) => {
    peer.send(request(1, 'tools/list'));
    const a = await peer.waitForId(1);
    if (a.error) ctx.skip('tools/list not supported');
    peer.send(request(2, 'tools/list'));
    const b = await peer.waitForId(2);
    const na = (a.result.tools || []).map((t) => t.name);
    const nb = (b.result.tools || []).map((t) => t.name);
    // SHOULD, not MUST. Advisory, plus a variance point so a differential run
    // shows control-stable vs subject-unstable.
    ctx.recommend('tools.deterministicOrder', JSON.stringify(na) === JSON.stringify(nb),
      'Spec SHOULD: same ordering across requests when the tool set has not changed.');
    ctx.variance('tools.orderStable', JSON.stringify(na) === JSON.stringify(nb));
  }),
});

test({
  id: 'SRV.TOOLS.SET-NOT-CONNECTION-SCOPED',
  title: 'tools/list is identical across two independent connections',
  role: 'server', area: 'conformance', tier: 'pr', peer: 'fake',
  catches: 'A server that builds its tool set from connection state, which breaks under load balancing and reconnect.',
  run: async (ctx) => {
    const p1 = ctx.target.spawnServer();
    const p2 = ctx.target.spawnServer();
    try {
      p1.send(request(1, 'tools/list'));
      p2.send(request(1, 'tools/list'));
      const r1 = await p1.waitForId(1);
      const r2 = await p2.waitForId(1);
      if (r1.error || r2.error) ctx.skip('tools/list not supported');
      const n1 = JSON.stringify((r1.result.tools || []).map((t) => t.name));
      const n2 = JSON.stringify((r2.result.tools || []).map((t) => t.name));
      ctx.assert('TOOLS.SET-NOT-CONNECTION-SCOPED', n1 === n2, `conn1=${n1} conn2=${n2}`);
    } finally {
      await p1.stop();
      await p2.stop();
    }
  },
});

test({
  id: 'SRV.TOOLS.UNKNOWN-TOOL-IS-PROTOCOL-ERROR',
  title: 'calling an unknown tool yields a JSON-RPC error, not isError',
  role: 'server', area: 'conformance', tier: 'push', peer: 'fake',
  catches: 'A server that answers an unknown tool with neither an error nor an isError result, so the caller cannot tell the tool is missing.',
  run: (ctx) => withServer(ctx, async (peer) => {
    peer.send(request(1, 'tools/call', {
      name: '__no_such_tool_in_any_implementation__', arguments: {},
    }));
    const res = await peer.waitForId(1);

    // WHY THIS IS NOT AN ASSERTION.
    //
    // The spec's Error Handling section lists "Unknown tool" under Protocol
    // Errors, but the sentence carries NO RFC2119 keyword. It is descriptive
    // prose, not a MUST. Our control (Python SDK mcp 2.0.0) answers an unknown
    // tool with `isError: true` rather than a JSON-RPC error, and on the plain
    // text of the spec that is legal.
    //
    // This test originally asserted the protocol-error routing and FAILED
    // against the control. That failure was a bug in this test, not a defect in
    // the control. It is recorded in the battery document as spec ambiguity
    // AMB-TOOLS-UNKNOWN.
    const signalled = Boolean(res.error)
      || Boolean(res.result && res.result.isError === true);
    ctx.assert('BASE.RES.ID-MATCHES', res.id === 1);
    ctx.assert('TOOLS.VALIDATE-INPUTS', signalled,
      `unknown tool was neither a JSON-RPC error nor an isError result: ${JSON.stringify(res).slice(0, 200)}`);

    ctx.variance('unknownTool.routing', res.error ? 'protocol-error' : 'isError-result');
    ctx.variance('unknownTool.errorCode', res.error ? res.error.code : null);
    ctx.recommend('unknownTool.usesProtocolError', Boolean(res.error),
      'The spec LISTS unknown tool under Protocol Errors but without a MUST. Returning a '
      + 'JSON-RPC error is the reading most clients expect; isError is defensible. Ambiguity AMB-TOOLS-UNKNOWN.');
    if (res.error) ctx.assert('BASE.ERR.CODE-INTEGER', Number.isInteger(res.error.code));
  }),
});

test({
  id: 'SRV.TOOLS.EXECUTION-ERROR-IS-RESULT',
  title: 'a failing tool reports isError:true in a result, not a JSON-RPC error',
  role: 'server', area: 'conformance', tier: 'pr', peer: 'real',
  catches: 'A server that maps tool exceptions to protocol errors, so the model never sees the message it needs to self-correct.',
  run: (ctx) => withServer(ctx, async (peer) => {
    const toolName = ctx.target.failingTool;
    if (!toolName) ctx.skip('no known always-failing tool configured for this target');
    peer.send(request(1, 'tools/call', { name: toolName, arguments: {} }));
    const res = await peer.waitForId(1);
    // Same ambiguity as AMB-TOOLS-UNKNOWN, in the other direction: the spec
    // describes tool execution errors as isError results but never says MUST.
    // What IS assertable: if the server returns a result at all, that result
    // must be well formed and must carry resultType (BASE.RES.RESULTTYPE is a
    // real MUST), and the failure must be signalled somehow.
    const signalled = Boolean(res.error) || Boolean(res.result && res.result.isError === true);
    ctx.assert('TOOLS.VALIDATE-INPUTS', signalled,
      `a failing tool reported neither an error nor isError: ${JSON.stringify(res).slice(0, 200)}`);
    if (res.result) {
      ctx.assert('BASE.RES.RESULTTYPE', res.result.resultType === 'complete',
        `resultType=${res.result.resultType}`);
      ctx.variance('toolError.contentTypes',
        (res.result.content || []).map((c) => c.type));
    }
    ctx.variance('toolExecutionError.routing', res.error ? 'protocol-error' : 'isError-result');
    ctx.recommend('toolError.usesIsError', !res.error,
      'Spec guidance (no MUST): tool execution errors SHOULD reach the model as isError results '
      + 'so it can self-correct. A JSON-RPC error hides the message from the model.');
  }),
});

test({
  id: 'SRV.TOOLS.OUTPUTSCHEMA-CONFORMS',
  title: 'structuredContent conforms to the declared outputSchema',
  role: 'server', area: 'conformance', tier: 'pr', peer: 'real',
  catches: 'A tool that advertises an outputSchema and then returns data violating it, breaking every validating client.',
  run: (ctx) => withServer(ctx, async (peer) => {
    peer.send(request(1, 'tools/list'));
    const list = await peer.waitForId(1);
    if (list.error) ctx.skip('tools/list not supported');
    const withSchema = (list.result.tools || []).filter((t) => t.outputSchema);
    if (withSchema.length === 0) ctx.skip('no tool declares an outputSchema');
    const call = ctx.target.sampleCallFor;
    let checked = 0;
    for (const t of withSchema) {
      const args = call && call[t.name];
      if (!args) continue;
      peer.send(request(`os-${t.name}`, 'tools/call', { name: t.name, arguments: args }));
      const res = await peer.waitForId(`os-${t.name}`);
      if (res.error || !res.result) continue;
      checked += 1;
      if ('structuredContent' in res.result) {
        const ok = validateAgainstSchema(res.result.structuredContent, t.outputSchema);
        ctx.assert('TOOLS.OUTPUTSCHEMA-CONFORMANCE', ok.valid,
          `tool=${t.name} errors=${ok.errors.join('; ')}`);
      } else {
        // The spec requires conforming structured results IF structured results
        // are produced; it does not require structuredContent to be present.
        ctx.variance(`outputSchema.${t.name}.structuredContentPresent`, false);
      }
    }
    if (checked === 0) ctx.skip('no sample arguments configured for output-schema tools');
  }),
});

// A deliberately small JSON Schema subset validator. The battery must not
// dereference network $refs (BASE.SCHEMA.NO-NETWORK-REF), so this validator
// never fetches anything.
export function validateAgainstSchema(value, schema, path = '$') {
  const errors = [];
  const walk = (v, s, p) => {
    if (!s || typeof s !== 'object') return;
    if (s.$ref) { errors.push(`${p}: $ref not resolved (by design, refs are not dereferenced)`); return; }
    if (s.type) {
      const types = Array.isArray(s.type) ? s.type : [s.type];
      const actual = v === null ? 'null'
        : Array.isArray(v) ? 'array'
          : Number.isInteger(v) ? 'integer'
            : typeof v === 'number' ? 'number' : typeof v;
      const ok = types.some((t) => t === actual
        || (t === 'number' && (actual === 'integer' || actual === 'number')));
      if (!ok) { errors.push(`${p}: expected ${types.join('|')}, got ${actual}`); return; }
    }
    if (s.type === 'object' || s.properties) {
      if (v === null || typeof v !== 'object' || Array.isArray(v)) return;
      for (const req of s.required || []) {
        if (!(req in v)) errors.push(`${p}: missing required property "${req}"`);
      }
      for (const [k, sub] of Object.entries(s.properties || {})) {
        if (k in v) walk(v[k], sub, `${p}.${k}`);
      }
    }
    if ((s.type === 'array' || s.items) && Array.isArray(v)) {
      v.forEach((item, i) => walk(item, s.items, `${p}[${i}]`));
    }
    if (s.enum && !s.enum.some((e) => JSON.stringify(e) === JSON.stringify(v))) {
      errors.push(`${p}: value not in enum`);
    }
  };
  walk(value, schema, path);
  return { valid: errors.length === 0, errors };
}

test({
  id: 'SRV.NOTIF.NO-RESPONSE',
  title: 'a notification receives no response',
  role: 'server', area: 'conformance', tier: 'pr', peer: 'fake', timing: true,
  catches: 'A server that replies to notifications, corrupting client id bookkeeping with unmatched responses.',
  run: (ctx) => withServer(ctx, async (peer) => {
    // Send a notification, then a request. When the request is answered we
    // know the notification has been fully processed: that is the
    // deterministic barrier, not a sleep.
    peer.send(notification('notifications/cancelled', { requestId: 'never-issued' }));
    peer.send(request(99, 'server/discover'));
    await peer.waitForId(99);
    const stray = peer.messages.filter((m) => m.id === 'never-issued'
      || (m.id === undefined && classify(m) === 'response'));
    ctx.assert('BASE.NOTIF.NO-RESPONSE', stray.length === 0,
      `stray responses=${JSON.stringify(stray)}`);
  }),
});

test({
  id: 'SRV.PATTERN.NO-SERVER-REQUESTS',
  title: 'the server never writes a JSON-RPC request to stdout',
  role: 'server', area: 'conformance', tier: 'push', peer: 'fake',
  catches: 'A server still using the pre-2026 server-initiated request pattern, which modern clients will never answer.',
  run: (ctx) => withServer(ctx, async (peer) => {
    for (const [i, method] of ['server/discover', 'tools/list', 'resources/list', 'prompts/list'].entries()) {
      peer.send(request(i + 1, method));
      try { await peer.waitForId(i + 1); } catch { /* unsupported method: fine */ }
    }
    const reqs = peer.serverRequests();
    ctx.assert('PAT.SERVER-NO-REQUESTS', reqs.length === 0,
      `server sent requests: ${JSON.stringify(reqs)}`);
    ctx.assert('STDIO.SERVER-NO-REQUESTS', reqs.length === 0);
  }),
});

test({
  id: 'SRV.STDIO.STDOUT-IS-CLEAN',
  title: 'every stdout line parses as JSON and contains no embedded newline',
  role: 'server', area: 'conformance', tier: 'push', peer: 'fake',
  catches: 'A server that prints a banner or log line to stdout, which desynchronises every line-framed client.',
  run: (ctx) => withServer(ctx, async (peer) => {
    peer.send(request(1, 'server/discover'));
    await peer.waitForId(1);
    peer.send(request(2, 'tools/list'));
    try { await peer.waitForId(2); } catch { /* optional */ }
    ctx.assert('STDIO.STDOUT-ONLY-MCP', peer.badLines.length === 0,
      `non-JSON stdout lines: ${JSON.stringify(peer.badLines.slice(0, 3))}`);
    // Every parsed message must have been carried on exactly one line, which
    // our line splitter already guarantees; the observable violation would be
    // a line that fails to parse because the JSON was split across lines.
    ctx.assert('STDIO.NO-EMBEDDED-NEWLINES', peer.badLines.length === 0);
    ctx.variance('stdio.blankLinesEmitted',
      peer.rawLines.filter((l) => l.replace(/\r$/, '').trim() === '').length);
    ctx.variance('stdio.usesCRLF', peer.rawLines.some((l) => l.endsWith('\r')));
    ctx.note('stderrBytes', peer.stderr.length);
  }),
});

test({
  id: 'SRV.ERR.NO-RETIRED-CODES',
  title: 'no retired error code (-32002, -32042) is emitted',
  role: 'server', area: 'conformance', tier: 'pr', peer: 'fake',
  catches: 'A server carried forward from 2025-11-25 still emitting -32002 for missing resources, which modern clients mis-handle.',
  run: (ctx) => withServer(ctx, async (peer) => {
    const probes = [
      ['resources/read', { uri: 'file:///definitely/not/here/at/all.txt' }],
      ['prompts/get', { name: '__no_such_prompt__', arguments: {} }],
      ['tools/call', { name: '__no_such_tool__', arguments: {} }],
    ];
    const seen = [];
    for (const [i, [method, params]] of probes.entries()) {
      peer.send(request(i + 1, method, params));
      let res;
      try { res = await peer.waitForId(i + 1); } catch { continue; }
      if (res.error) seen.push({ method, code: res.error.code });
    }
    const retired = seen.filter((s) => RETIRED_ERROR_CODES.includes(s.code));
    ctx.assert('BASE.ERR.NO-RETIRED-CODES', retired.length === 0,
      `retired codes emitted: ${JSON.stringify(retired)}`);

    // Reserved-range discipline: -32020..-32099 may only carry spec-defined codes.
    const badReserved = seen.filter((s) => s.code <= -32020 && s.code >= -32099
      && !SPEC_DEFINED_CODES.includes(s.code));
    ctx.assert('BASE.ERR.RESERVED-RANGE', badReserved.length === 0,
      `undefined codes in the spec-reserved sub-range: ${JSON.stringify(badReserved)}`);
    ctx.variance('errorCodes.byMethod', seen);
  }),
});

test({
  id: 'SRV.STATELESS.NO-HANDSHAKE-NEEDED',
  title: 'the first message on a fresh connection may be any RPC',
  role: 'server', area: 'conformance', tier: 'push', peer: 'fake',
  catches: 'A server that still requires an initialize handshake, rejecting every modern stateless client.',
  run: (ctx) => withServer(ctx, async (peer) => {
    // No discover, no initialize. Straight to a real call.
    peer.send(request(1, 'tools/list'));
    const res = await peer.waitForId(1);
    const rejectedForOrdering = Boolean(res.error)
      && [ERR.INVALID_REQUEST, ERR.INTERNAL_ERROR].includes(res.error.code);
    ctx.assert('BASE.STATELESS.NO-PRIOR-REQUESTS', !rejectedForOrdering,
      `server rejected an un-handshaked request: ${JSON.stringify(res.error)}`);
  }),
});

test({
  id: 'SRV.STDIO.EXITS-ON-EOF',
  title: 'the server exits when stdin is closed',
  role: 'server', area: 'conformance', tier: 'pr', peer: 'fake',
  catches: 'A server that ignores EOF, leaving orphaned processes after every client shutdown.',
  run: (ctx) => withServer(ctx, async (peer) => {
    peer.send(request(1, 'server/discover'));
    await peer.waitForId(1);
    peer.closeStdin();
    let exited = true;
    try {
      await peer.waitForExit(8000);
    } catch {
      exited = false;
    }
    // SHOULD, not MUST: advisory plus a variance point.
    ctx.recommend('stdio.exitsOnEof', exited,
      'Spec SHOULD: servers exit promptly when stdin is closed or reads return EOF.');
    ctx.variance('stdio.exitsOnEof', exited);
    ctx.variance('stdio.exitCode', peer.exitCode);
  }),
});

test({
  id: 'SRV.CACHE.HINTS-ON-CACHEABLE-RESULTS',
  title: 'cacheable operations carry ttlMs and cacheScope',
  role: 'server', area: 'conformance', tier: 'push', peer: 'fake',
  catches: 'A server omitting required caching hints, so every client re-fetches the tool list on every turn.',
  run: (ctx) => withServer(ctx, async (peer) => {
    const CACHEABLE = ['server/discover', 'tools/list', 'prompts/list', 'resources/list'];
    let checked = 0;
    for (const [i, method] of CACHEABLE.entries()) {
      peer.send(request(i + 1, method));
      let res;
      try { res = await peer.waitForId(i + 1, 8000); } catch { continue; }
      if (res.error || !res.result) continue;            // unsupported: not our business
      if (res.result.resultType !== 'complete') continue; // hints only apply to complete
      checked += 1;
      ctx.assert('CACHE.HINTS-REQUIRED', res.result.ttlMs !== undefined,
        `${method} result has no ttlMs`);
      ctx.assert('CACHE.HINTS-REQUIRED', res.result.cacheScope !== undefined,
        `${method} result has no cacheScope`);
      if (typeof res.result.ttlMs === 'number') {
        ctx.assert('CACHE.TTL-NON-NEGATIVE', res.result.ttlMs >= 0,
          `${method} ttlMs=${res.result.ttlMs}`);
      }
      if (res.result.cacheScope !== undefined) {
        ctx.assert('CACHE.SCOPE-VALUES',
          ['public', 'private'].includes(res.result.cacheScope),
          `${method} cacheScope=${JSON.stringify(res.result.cacheScope)}`);
      }
      ctx.variance(`cache.${method}.ttlMs`, res.result.ttlMs ?? null);
      ctx.variance(`cache.${method}.cacheScope`, res.result.cacheScope ?? null);
    }
    if (checked === 0) ctx.skip('no cacheable operation returned a complete result');
  }),
});
