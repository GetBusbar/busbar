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

// ── THE HTTP/1.1 HALF: the JSON-RPC binding, and every discovery document beside it. ──
const h1 = http.createServer((req, res) => {
  const headers = { ...req.headers, host: UPSTREAM };
  const alreadyAuthenticated = Object.keys(headers).some((h) => h.toLowerCase() === 'authorization');
  if (!alreadyAuthenticated) headers.authorization = `Bearer ${token}`;

  const upstream = http.request(
    { host: '127.0.0.1', port: Number(upstreamPort), path: req.url, method: req.method, headers },
    (upstreamRes) => {
      res.writeHead(upstreamRes.statusCode, upstreamRes.headers);
      upstreamRes.pipe(res);
    },
  );
  // A dead upstream must look like a dead upstream, never like a conformance verdict.
  upstream.on('error', (e) => {
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

const dispatcher = net.createServer((socket) => {
  socket.on('error', () => {});
  socket.once('data', (chunk) => {
    const port = (chunk.toString('ascii', 0, 3) === 'PRI' ? h2Port : h1Port).address().port;
    const inner = net.connect(port, '127.0.0.1', () => {
      inner.write(chunk);
      socket.pipe(inner);
      inner.pipe(socket);
    });
    inner.on('error', () => socket.destroy());
  });
});

dispatcher.listen(Number(listenPort), '127.0.0.1');
