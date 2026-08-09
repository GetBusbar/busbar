// SUBJECT ACTS AS MCP SERVER. Area: stateful and concurrent behaviour.
//
// Note on ordering: the spec nowhere requires responses to arrive in request
// order. Out-of-order completion is LEGAL. So ordering is a variance point,
// never an assertion. What IS assertable is that every id is answered exactly
// once and no id is invented.

import { test } from '../core/runner.mjs';
import { request, notification } from '../core/jsonrpc.mjs';

async function withServer(ctx, fn) {
  const peer = ctx.target.spawnServer();
  try { return await fn(peer); } finally { await peer.stop(); }
}

test({
  id: 'CONC.INTERLEAVED-REQUESTS',
  title: 'many interleaved requests are each answered exactly once',
  role: 'server', area: 'concurrency', tier: 'pr', peer: 'fake',
  catches: 'A dispatcher that drops or double-answers a request under pipelining, the classic single-slot response bug.',
  run: (ctx) => withServer(ctx, async (peer) => {
    const N = 25;
    const ids = [];
    for (let i = 0; i < N; i++) {
      const id = `c-${i}`;
      ids.push(id);
      peer.send(request(id, i % 2 === 0 ? 'server/discover' : 'tools/list'));
    }
    // Deterministic barrier: wait for every id, not for a duration.
    for (const id of ids) await peer.waitForId(id, 20000);

    const counts = new Map();
    for (const m of peer.messages) {
      if (m && m.id !== undefined && ('result' in m || 'error' in m)) {
        counts.set(m.id, (counts.get(m.id) || 0) + 1);
      }
    }
    const doubled = ids.filter((id) => (counts.get(id) || 0) > 1);
    const missing = ids.filter((id) => !counts.has(id));
    const invented = [...counts.keys()].filter((id) => !ids.includes(id));

    ctx.assert('BASE.RES.ID-MATCHES', doubled.length === 0, `answered more than once: ${doubled}`);
    ctx.assert('BASE.RES.ID-MATCHES', missing.length === 0, `never answered: ${missing}`);
    ctx.assert('BASE.RES.ID-MATCHES', invented.length === 0, `responses to ids never sent: ${invented}`);

    // Ordering is legal either way. Record it so the differential run shows
    // control-ordered vs subject-reordered without failing anyone.
    const order = peer.messages
      .filter((m) => m && ids.includes(m.id))
      .map((m) => m.id);
    ctx.variance('interleaved.responsesInRequestOrder',
      JSON.stringify(order) === JSON.stringify(ids));
  }),
});

test({
  id: 'CONC.ID-TYPES',
  title: 'string, integer and unusual-but-legal ids are all correlated correctly',
  role: 'server', area: 'concurrency', tier: 'pr', peer: 'fake',
  catches: 'An id compared with == or coerced to string, so request 1 and request "1" collide and cross-deliver.',
  run: (ctx) => withServer(ctx, async (peer) => {
    // 1 and "1" are DIFFERENT ids in JSON-RPC. A server that stringifies its
    // id table will cross-deliver these two.
    peer.send(request(1, 'server/discover'));
    peer.send(request('1', 'tools/list'));
    peer.send(request(0, 'server/discover'));
    peer.send(request(-7, 'server/discover'));
    peer.send(request('', 'server/discover'));

    const wanted = [1, '1', 0, -7, ''];
    for (const id of wanted) {
      try { await peer.waitForId(id, 8000); } catch { /* recorded below */ }
    }
    for (const id of wanted) {
      const replies = peer.messages.filter((m) => m
        && typeof m.id === typeof id && m.id === id
        && ('result' in m || 'error' in m));
      ctx.assert('BASE.RES.ID-MATCHES', replies.length <= 1,
        `id ${JSON.stringify(id)} (${typeof id}) answered ${replies.length} times`);
      ctx.variance(`idTypes.${typeof id}.${JSON.stringify(id)}.answered`, replies.length === 1);
    }
    // Cross-delivery check: the reply to integer 1 must not be the tools/list
    // answer that belongs to string "1".
    const intOne = peer.messages.find((m) => m && m.id === 1 && typeof m.id === 'number' && 'result' in m);
    const strOne = peer.messages.find((m) => m && m.id === '1' && typeof m.id === 'string' && 'result' in m);
    if (intOne && strOne) {
      ctx.assert('BASE.RES.ID-MATCHES',
        JSON.stringify(intOne.result) !== JSON.stringify(strOne.result)
        || !('supportedVersions' in intOne.result && 'tools' in strOne.result),
        'integer id 1 and string id "1" appear to have been conflated');
    }
  }),
});

test({
  id: 'CONC.NULL-ID-REJECTED',
  title: 'a request with id null is not treated as a valid request',
  role: 'server', area: 'concurrency', tier: 'pr', peer: 'fake',
  catches: 'Accepting id:null, which MCP forbids, producing responses no client can correlate.',
  run: (ctx) => withServer(ctx, async (peer) => {
    peer.sendRaw('{"jsonrpc":"2.0","id":null,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}\n');
    peer.send(request('after-null', 'server/discover'));
    await peer.waitForId('after-null');
    const nullReplies = peer.messages.filter((m) => m && m.id === null && 'result' in m);
    // The spec forbids the CLIENT from sending id:null. It does not state the
    // server's obligation. A successful RESULT for id:null is the bad outcome,
    // because no client can match it; an error reply is fine, silence is fine.
    ctx.assert('BASE.REQ.ID-NOT-NULL', nullReplies.length === 0,
      'server returned a success result for a null id, which is uncorrelatable');
    ctx.variance('nullId.replyKind',
      peer.messages.some((m) => m && m.id === null && m.error) ? 'error'
        : nullReplies.length ? 'result' : 'none');
  }),
});

test({
  id: 'CONC.CANCEL-STOPS-RESPONSE',
  title: 'a cancelled request either completes or goes silent, never both',
  role: 'server', area: 'concurrency', tier: 'pr', peer: 'fake', timing: true,
  catches: 'A cancellation path that stops the work but still emits a response, or emits two.',
  run: (ctx) => withServer(ctx, async (peer) => {
    peer.send(request('cancelme', 'tools/list'));
    peer.send(notification('notifications/cancelled', { requestId: 'cancelme' }));
    // Barrier: a later request completing proves the earlier one was fully
    // processed one way or the other.
    peer.send(request('barrier', 'server/discover'));
    await peer.waitForId('barrier');
    await peer.quiesce(300);
    const replies = peer.responsesFor('cancelme');
    ctx.assert('CANCEL.NO-FURTHER-MESSAGES', replies.length <= 1,
      `cancelled request produced ${replies.length} responses`);
    // Both 0 and 1 are legal: the spec permits ignoring a cancellation that
    // arrives after completion.
    ctx.variance('cancel.responseCount', replies.length);
  }),
});

test({
  id: 'CONC.SERVER-CANCELLED-ONLY-FOR-SUBSCRIPTIONS',
  title: 'the server never sends notifications/cancelled outside a subscription teardown',
  role: 'server', area: 'concurrency', tier: 'pr', peer: 'fake',
  catches: 'A server reusing notifications/cancelled as a generic abort signal, which the 2026-07-28 spec forbids.',
  run: (ctx) => withServer(ctx, async (peer) => {
    for (const [i, m] of ['server/discover', 'tools/list', 'prompts/list'].entries()) {
      peer.send(request(i + 1, m));
      try { await peer.waitForId(i + 1, 6000); } catch { /* optional */ }
    }
    peer.send(request('c1', 'tools/call', { name: '__nope__', arguments: {} }));
    try { await peer.waitForId('c1', 6000); } catch { /* fine */ }
    const cancels = peer.messages.filter((m) => m && m.method === 'notifications/cancelled');
    ctx.assert('CANCEL.SERVER-ONLY-SUBSCRIPTIONS', cancels.length === 0,
      `server sent notifications/cancelled with no subscription open: ${JSON.stringify(cancels)}`);
  }),
});

test({
  id: 'CONC.SUBSCRIPTION-ACK-FIRST',
  title: 'subscriptions/listen acknowledges before any notification and tags every message',
  role: 'server', area: 'concurrency', tier: 'pr', peer: 'real', timing: true,
  catches: 'A subscription stream that emits events before the acknowledgement, so clients cannot correlate the first events.',
  run: (ctx) => withServer(ctx, async (peer) => {
    peer.send(request(1, 'server/discover'));
    const disc = await peer.waitForId(1);
    const caps = (disc.result && disc.result.capabilities) || {};
    const supportsListChanged = Object.values(caps).some((c) => c && c.listChanged);
    if (!supportsListChanged) ctx.skip('server declares no listChanged capability');

    peer.send(request(50, 'subscriptions/listen', {
      notifications: { toolsListChanged: true },
    }));

    let ack = null;
    try {
      ack = await peer.waitFor(
        (m) => m && m.method === 'notifications/subscriptions/acknowledged',
        'subscription acknowledgement', 8000,
      );
    } catch {
      // The server may legally answer subscriptions/listen with an error if it
      // does not support the requested filter.
      const err = peer.responsesFor(50)[0];
      ctx.variance('subscriptions.listenRejected', Boolean(err && err.error));
      if (err && err.error) ctx.skip(`server rejected subscriptions/listen: ${err.error.code}`);
      throw new Error('no acknowledgement and no error response to subscriptions/listen');
    }

    const SUB_KEY = 'io.modelcontextprotocol/subscriptionId';
    ctx.assert('SUB.ACK-FIRST',
      Boolean(ack.params && ack.params._meta && ack.params._meta[SUB_KEY] !== undefined),
      `acknowledgement lacks ${SUB_KEY}: ${JSON.stringify(ack.params)}`);
    ctx.assert('SUB.ACK-FIRST',
      ack.params._meta[SUB_KEY] === 50,
      `subscriptionId=${ack.params._meta[SUB_KEY]} expected the listen request id 50`);

    // Every notification arriving before the ack on this subscription is a
    // violation. Notifications for OTHER subscriptions may interleave.
    const ackIndex = peer.messages.indexOf(ack);
    const earlyForThisSub = peer.messages.slice(0, ackIndex).filter(
      (m) => m && m.method && m.method.startsWith('notifications/')
        && m.params && m.params._meta && m.params._meta[SUB_KEY] === 50,
    );
    ctx.assert('SUB.ACK-FIRST', earlyForThisSub.length === 0,
      `notifications preceded the acknowledgement: ${JSON.stringify(earlyForThisSub)}`);

    await peer.quiesce(300);
    const onStream = peer.messages.filter(
      (m) => m && m.method && m.method.startsWith('notifications/')
        && m.method !== 'notifications/subscriptions/acknowledged',
    );
    for (const n of onStream) {
      ctx.assert('SUB.ID-ON-EVERY-NOTIFICATION',
        Boolean(n.params && n.params._meta && n.params._meta[SUB_KEY] !== undefined),
        `notification ${n.method} lacks ${SUB_KEY}`);
    }
    ctx.variance('subscriptions.acknowledgedFilter',
      ack.params && ack.params.notifications ? Object.keys(ack.params.notifications).sort() : null);
  }),
});

test({
  id: 'CONC.SUBSCRIPTION-NO-UNREQUESTED-TYPES',
  title: 'the server sends only notification types the client asked for',
  role: 'server', area: 'concurrency', tier: 'prerelease', peer: 'real', timing: true,
  catches: 'A server broadcasting every event to every stream, leaking activity between unrelated subscriptions.',
  run: (ctx) => withServer(ctx, async (peer) => {
    peer.send(request(60, 'subscriptions/listen', {
      notifications: { toolsListChanged: true },
    }));
    try {
      await peer.waitFor((m) => m && m.method === 'notifications/subscriptions/acknowledged',
        'ack', 8000);
    } catch {
      ctx.skip('server did not acknowledge a subscriptions/listen request');
    }
    await peer.quiesce(600);
    const allowed = new Set([
      'notifications/subscriptions/acknowledged',
      'notifications/tools/list_changed',
      'notifications/message',
      'notifications/progress',
    ]);
    const unrequested = peer.messages
      .filter((m) => m && m.method && m.method.startsWith('notifications/'))
      .filter((m) => !allowed.has(m.method));
    ctx.assert('SUB.NO-UNREQUESTED-TYPES', unrequested.length === 0,
      `unrequested notification types: ${JSON.stringify(unrequested.map((m) => m.method))}`);
  }),
});
