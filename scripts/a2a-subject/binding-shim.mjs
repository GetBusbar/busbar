// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// THE CONFORMANCE SUITE'S CREDENTIAL, HELD WHERE A CLIENT WOULD HOLD IT — ON BOTH OF BUSBAR'S A2A
// BINDINGS, OVER ONE PORT.
//
// WHY THIS EXISTS BESIDE `scripts/mcp-subject/credential-shim.mjs` RATHER THAN REPLACING IT.
//
// That shim is the A2A JSON-RPC leg's credential holder and it was reused here rather than copied,
// which was right while this leg spoke one protocol. It cannot serve the gRPC binding, and the
// reason is structural rather than a missing feature: it is an `http.createServer`, i.e. HTTP/1.1,
// and gRPC is HTTP/2. Adding h2c to it would put a second protocol into the MCP leg's rig, where
// nothing speaks it.
//
// AND THE TWO BINDINGS CANNOT BE GIVEN TWO PORTS. busbar serves gRPC on the SAME listener as its
// HTTP bindings (h2c prior knowledge, which `axum::serve`'s hyper-util auto builder already
// accepts), and the address its agent card publishes for the gRPC interface is derived from ONE
// `public_url` — deliberately, so the audience a token must be minted for, the endpoint the card
// advertises and the address the suite dials cannot drift apart. A rig that put the two bindings on
// two ports would be testing a topology busbar does not have.
//
// So this shim does what busbar's own listener does: it serves whichever protocol arrived on the
// connection, over one port.
//
// TRANSPARENCY IS THE WHOLE DESIGN, on both halves, with one deliberate exception each.
//   * Method, path, query, body, trailers and every header are forwarded unchanged.
//   * `Host` / `:authority` is rewritten to the upstream authority, because a forwarded one naming
//     this shim would describe a hop the origin server never had.
//   * `Authorization` is added ONLY when the request carries none, so a scenario that sends its own
//     credential keeps it.
//
// NOTHING HERE IS INSIDE BUSBAR'S TRUST BOUNDARY. The token it attaches is verified in full by the
// same busbar, and `boot.sh::prove_the_boundary_is_intact` shows in the same run that that busbar
// refuses a token with no audience, one bound to a different audience, and one whose signature was
// altered.
//
// Usage: node binding-shim.mjs <listen-port> <upstream-port> <bearer-token>

import net from 'node:net';
import http from 'node:http';
import http2 from 'node:http2';

const [listenPort, upstreamPort, token] = process.argv.slice(2);
if (!listenPort || !upstreamPort || !token) {
  console.error('usage: binding-shim.mjs <listen-port> <upstream-port> <bearer-token>');
  process.exit(2);
}

const UPSTREAM = `127.0.0.1:${upstreamPort}`;

// THE UPSTREAM SOCKET IS NEVER POOLED, AND THAT IS A CORRECTNESS FIX RATHER THAN A TUNING CHOICE.
//
// Node's GLOBAL agent has `keepAlive: true`, so without an explicit agent this shim kept idle
// sockets to busbar in a pool and reused them. busbar advertises `Keep-Alive: timeout=5` and closes
// an idle connection when that elapses — correct, and every well-behaved client honours it. Node's
// agent does NOT read that header: it hands out a socket busbar has already closed, the write loses
// the race, and `upstream.on('error')` fires with `ECONNRESET`.
//
// WHAT THAT COST, MEASURED RATHER THAN GUESSED. The shim answered `502`, and the connection it had
// already half-written left the NEXT request on that client connection answering `400` with a
// ZERO-LENGTH BODY. The official suite's `test_data_model.py` fixture is module-scoped, so one such
// answer errored its whole module: ten MUST requirements reported `NOT TESTED` having never run,
// and `JSONRPC-FMT-001` reported `Response is not a JSON object` — ELEVEN requirements scored
// against busbar for a byte busbar never sent. The same race read as `send_message failed: timed
// out` on four `STREAM-*` requirements, and it is why two runs of one binary disagreed.
//
// THE DISPROOF THAT IT WAS EVER BUSBAR'S. The identical request sequence, with the identical gaps,
// run TWELVE times straight at busbar's own listener with no shim in the path (the `instrument`
// credential topology) answered `200` with valid JSON every time. Through the shim, the same
// sequence produced `502`, an empty-bodied `400` and a read timeout. The defect was in this file.
//
// A fresh connection per hop is what a shim in front of a conformance subject owes the reading: it
// is measurably slower and it cannot manufacture a failure the subject did not commit.
const upstreamAgent = new http.Agent({ keepAlive: false, maxSockets: Infinity });

// ── THE HTTP/1.1 HALF: the JSON-RPC binding, and every discovery document beside it. ──
const h1 = http.createServer((req, res) => {
  const headers = { ...req.headers, host: UPSTREAM };
  const alreadyAuthenticated = Object.keys(headers).some((h) => h.toLowerCase() === 'authorization');
  if (!alreadyAuthenticated) headers.authorization = `Bearer ${token}`;

  const upstream = http.request(
    {
      host: '127.0.0.1',
      port: Number(upstreamPort),
      path: req.url,
      method: req.method,
      headers,
      agent: upstreamAgent,
    },
    (upstreamRes) => {
      res.writeHead(upstreamRes.statusCode, upstreamRes.headers);
      upstreamRes.pipe(res);
    },
  );
  // A dead upstream must look like a dead upstream, never like a conformance verdict.
  //
  // AND IT MUST NOT CORRUPT THE CONNECTION IT IS ANSWERING ON. Writing a second set of headers
  // after the upstream response has already begun streaming throws `ERR_HTTP_HEADERS_SENT`, which
  // desynchronises this client connection and is how the empty-bodied `400` above was produced. If
  // the answer is already in flight the only honest move is to destroy the connection, so the
  // client sees a broken transfer rather than a well-formed lie.
  upstream.on('error', (e) => {
    if (res.headersSent) {
      res.destroy(e);
      return;
    }
    res.writeHead(502, { 'content-type': 'text/plain' });
    res.end(`binding-shim: upstream busbar at ${UPSTREAM} did not answer: ${e}`);
  });
  req.pipe(upstream);
});

// ── THE HTTP/2 HALF: the gRPC binding. ──
//
// gRPC's answer is not complete until its TRAILERS arrive — `grpc-status` is the call's outcome and
// it is sent AFTER the message frames. A proxy that forwarded headers and body and dropped trailers
// would turn every successful call into a client-side "no status received", which reads as a server
// defect and is not one. So the response is opened with `waitForTrailers` and the upstream's
// trailers are relayed verbatim.
//
// A "trailers-only" response — an error carrying `grpc-status` in the HEADERS frame with no body at
// all — needs nothing special: it arrives as ordinary response headers and is forwarded as such.
const h2 = http2.createServer();
h2.on('stream', (stream, headers) => {
  const out = { ...headers, ':authority': UPSTREAM };
  delete out.host;
  const alreadyAuthenticated = Object.keys(out).some((h) => h.toLowerCase() === 'authorization');
  if (!alreadyAuthenticated) out.authorization = `Bearer ${token}`;

  const client = http2.connect(`http://${UPSTREAM}`);
  let answered = false;
  const fail = (e) => {
    console.error(`binding-shim h2: ${e && e.stack ? e.stack : e}`);
    if (!answered && !stream.destroyed) {
      answered = true;
      // `INTERNAL` rather than a made-up HTTP status: this is inside a gRPC call, and a client
      // applies the HTTP-status mapping only to a response that carries no `grpc-status` at all.
      try {
        stream.respond({
          ':status': 200,
          'content-type': 'application/grpc',
          'grpc-status': '13',
          'grpc-message': `binding-shim: ${e}`,
        });
        stream.end();
      } catch {
        stream.destroy();
      }
    }
    client.close();
  };
  client.on('error', fail);
  stream.on('error', fail);

  const upstream = client.request(out);
  upstream.on('error', fail);

  // THE REQUEST BODY. gRPC's length-prefixed message frames arrive on this stream after the HEADERS
  // frame, and forgetting to forward them is not a partial failure but a total one: busbar receives
  // a call with no message and every RPC on the leg answers about a request nobody made. Piped
  // rather than buffered so a client-streaming or long-bodied call is not held in this process.
  stream.pipe(upstream);

  let trailers = null;
  upstream.on('trailers', (t) => {
    trailers = t;
  });
  upstream.on('response', (responseHeaders, flags) => {
    if (answered || stream.destroyed) return;
    answered = true;
    const forwarded = {};
    for (const [k, v] of Object.entries(responseHeaders)) {
      // Pseudo-headers other than `:status` are the request's, never the response's, and HTTP/2
      // refuses a response that carries them.
      if (k.startsWith(':') && k !== ':status') continue;
      // `content-length` describes the framing of the connection it arrived on, not of the one
      // being written. Relaying it makes this half promise a body length before it knows one, and
      // Node then frames the answer to match the promise instead of to match the upstream.
      if (k.toLowerCase() === 'content-length') continue;
      forwarded[k] = v;
    }

    // A TRAILERS-ONLY ANSWER IS FORWARDED AS ONE, and getting this wrong is not a cosmetic
    // difference. tonic answers every error status that way: one HEADERS frame carrying
    // `grpc-status`, END_STREAM set on it, no body and no trailers at all. Relaying that as a
    // headers frame plus a separate end — which is what `waitForTrailers` arranges — makes Node
    // frame the tail as an empty DATA frame, and a gRPC client that expected a status reports
    // `UNKNOWN: Stream removed (Data frame with END_STREAM flag received)`. Every refusal on the
    // leg then reads as a transport fault, and busbar's own `NOT_FOUND` never reaches the suite.
    if (flags & http2.constants.NGHTTP2_FLAG_END_STREAM) {
      stream.respond(forwarded, { endStream: true });
      return;
    }

    stream.respond(forwarded, { waitForTrailers: true });
    // `sendTrailers` IS ALWAYS CALLED, EVEN WITH NOTHING TO SEND, and that is not defensiveness.
    // `waitForTrailers` means the stream is not closed by `end()` — it is closed by this call — so
    // an upstream answer that carried no trailers at all leaves the stream OPEN for ever, and the
    // TCK's unary calls are made with NO deadline: one such answer hung the whole suite, thirty-five
    // minutes of a pytest process using 0.8 seconds of CPU.
    stream.on('wantTrailers', () => {
      try {
        stream.sendTrailers(trailers ?? {});
      } catch (e) {
        console.error(`binding-shim h2 trailers: ${e}`);
        stream.close();
      }
    });
    upstream.pipe(stream);
  });
  upstream.on('close', () => client.close());
  stream.on('close', () => client.close());
});

// ── THE DISPATCHER: which protocol arrived, decided from the connection preface. ──
//
// An HTTP/2 cleartext client with prior knowledge opens with the 24-byte connection preface, which
// begins `PRI * HTTP/2.0`. No HTTP/1.1 request line can: `PRI` is not a method any client sends, and
// RFC 9113 chose the sequence precisely so a server that speaks both can tell them apart.
//
// THE DISPATCH IS A TCP SPLICE, NOT A RE-EMITTED SOCKET, and both of the shorter routes were tried
// and rejected against a real gRPC client:
//
//   * `socket.unshift(chunk)` then `server.emit('connection', socket)` — the documented trick for
//     `http.Server` — is not accepted by `http2.Server`. It answers a connection-level GOAWAY with
//     `INTERNAL_ERROR`, which surfaces at the client as `UNAVAILABLE: Stream removed` and reads
//     exactly like a defect in the server being tested.
//   * `http2.createServer({ allowHTTP1: true })` handles the gRPC half correctly and answers a
//     cleartext HTTP/1.1 request with an HTTP/2 frame, which curl reports as
//     `Received HTTP/0.9 when not allowed`. The option is an ALPN fallback and there is no ALPN on a
//     cleartext port.
//
// So each half gets a real listener on an ephemeral loopback port and this dispatcher copies bytes.
// A byte copy cannot mis-frame either protocol, because it never parses either.
const h1Port = h1.listen(0, '127.0.0.1');
const h2Port = h2.listen(0, '127.0.0.1');

//
// THE SOCKET IS PAUSED THE INSTANT THE FIRST CHUNK IS IN HAND, AND THAT IS THE WHOLE CORRECTNESS OF
// THE SPLICE RATHER THAN A TIDINESS. Adding the `data` listener puts the socket in FLOWING mode, and
// `once` removes the listener but does NOT stop the flow — Node's `resume()` is sticky. `net.connect`
// is asynchronous, so between the first chunk and the `pipe()` in its callback there is a window in
// which the socket is still flowing with NOTHING LISTENING, and every byte the client sends in that
// window is emitted to no one and DISCARDED.
//
// THAT WINDOW IS NOT THEORETICAL AND IT IS EXACTLY THE REQUEST BODY. `httpx`/`h11` — the official
// suite's client stack — writes the request head and the request body as two separate `send()`
// calls. When the kernel coalesces them into one segment the request survives; when it does not, the
// SECOND segment is the JSON-RPC body, and it lands in the window. Measured with the dispatcher
// instrumented, driving `message/stream` ten times through it:
//
//     chunks: [('pre', 474, 'POST /a2a/agents/conformance')]                    -> dropped 0
//     chunks: [('pre', 233, 'POST /a2a/agents/conformance'),
//              ('WINDOW', 241, '{"jsonrpc":"2.0","id":"3fc66')]                 -> DROPPED 241 bytes
//
// WHAT THE LOSS LOOKS LIKE FROM EITHER END, and why it reads as a busbar defect. The h1 half's
// `req.pipe(upstream)` never sees a body, so `req` never ends, so `upstream` is never written to and
// never `end()`ed — and a Node `ClientRequest` flushes its head on its FIRST write. busbar therefore
// accepts a TCP connection and receives ZERO BYTES on it, for ever. Recorded at a byte-level origin
// standing in for busbar: `body_bytes_arrived: 0` on every lost request. The client waits on a
// response to a request the origin was never told about, and the suite records
// `httpcore.ReadTimeout`.
//
// MEASURED, BEFORE AND AFTER, with the suite's own client stack against the booted subject:
//   direct at busbar, no shim   60/60 streams completed        (and 210/210 over a split-write sweep)
//   through the shim, before    31/60 completed, 29 ReadTimeout, ZERO bytes received on each
//   through the shim, after     60/60 completed
// The disproof that it was ever busbar's: busbar answered every one of those 270 direct calls.
const dispatcher = net.createServer((socket) => {
  socket.on('error', () => {});
  socket.once('data', (chunk) => {
    socket.pause();
    const port = (chunk.toString('ascii', 0, 3) === 'PRI' ? h2Port : h1Port).address().port;
    const inner = net.connect(port, '127.0.0.1', () => {
      inner.write(chunk);
      // `pipe()` resumes the socket, so nothing buffered while it was paused is lost — it is
      // delivered here, in order, behind the chunk that was read off it first.
      socket.pipe(inner);
      inner.pipe(socket);
    });
    inner.on('error', () => socket.destroy());
  });
});

dispatcher.listen(Number(listenPort), '127.0.0.1');
