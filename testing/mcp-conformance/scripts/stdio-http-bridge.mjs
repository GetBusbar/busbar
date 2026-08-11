#!/usr/bin/env node
// THE TRANSPORT ADAPTER THAT ARMS THE SUBJECT LEG: stdio in, Streamable HTTP out.
//
// WHY THIS EXISTS AT ALL.
//
// This battery drives a target as a LAUNCH COMMAND speaking newline-delimited JSON-RPC on stdio
// (`src/core/stdio-peer.mjs`), because half of it consists of putting bytes on the wire that no SDK
// would produce -- truncated frames, duplicate ids, lone surrogates. busbar has no stdio MCP
// surface and is not going to grow one to be tested: it is an OAuth resource server whose MCP plane
// is HTTP POST, deliberately. So the battery and the subject speak two different transports, and
// for the whole of 1.5.5 the consequence was that the leg was simply never armed --
// `MCP_SUBJECT_SERVER_CMD` wanted a command nobody could write.
//
// THIS IS THE MISSING HALF OF THE CLIENT, NOT A STAND-IN FOR THE SERVER. It is the same class of
// object as `scripts/mcp-subject/credential-shim.mjs` on the official leg: the part of an MCP client
// that this particular harness cannot be told to be. Everything it does is what a conformant HTTP
// MCP client MUST do anyway, and everything it does NOT do is the point:
//
//   * IT NEVER REPAIRS A BODY. Whatever bytes arrive on a stdin line are the bytes POSTed. Invalid
//     JSON, a JSON-RPC batch array, a `_meta` that is a string, 8 MiB of `A`, a NUL byte -- all go
//     out verbatim, and busbar's own answer comes back. A bridge that "fixed up" a frame would be
//     answering the battery on busbar's behalf, and every adversarial verdict would be about this
//     file.
//   * IT NEVER SYNTHESISES A RESULT. If busbar answers nothing, nothing is written.
//   * THE MIRRORED HEADERS ARE DERIVED FROM THE BODY, NEVER INVENTED. Revision 2026-07-28 requires
//     `MCP-Protocol-Version`, `Mcp-Method` and (on tools/call, resources/read, prompts/get)
//     `Mcp-Name` to mirror the body. Deriving them is exactly what an HTTP client does; inventing
//     one the body does not carry would be putting a well-formed request on the wire in place of the
//     malformed one the battery sent. So when the body omits the value, the header is OMITTED --
//     which is how, for example, `SRV.META.MISSING-PROTOCOL-VERSION` still reaches busbar's own
//     `-32602` for the body defect rather than being converted into a header defect by this file.
//
// WHAT THIS COSTS, SAID OUT LOUD. The battery's `STDIO.*` clauses -- stdout carries only MCP,
// blank lines are tolerated, a truncated line does not poison the reader -- are, on this leg,
// statements about THIS FILE and not about busbar, because busbar has no stdio surface for them to
// be about. They are left in the run rather than filtered out: a filter is a knob, and the moment
// there is a knob the number is negotiable. Read them as adapter checks, and read the JSON-RPC
// semantics (error codes, catalogue shape, survival, concurrency, statelessness) as busbar.
//
// Usage:  node stdio-http-bridge.mjs <url>          (or MCP_BRIDGE_URL=<url>)
//         MCP_BRIDGE_BEARER=<token>                 optional; the official leg's shim usually
//                                                   supplies the credential instead.

const url = process.argv[2] || process.env.MCP_BRIDGE_URL;
if (!url) {
  process.stderr.write('usage: stdio-http-bridge.mjs <mcp-endpoint-url>\n');
  process.exit(2);
}
const bearer = process.env.MCP_BRIDGE_BEARER || '';

// `application/json` FIRST and deliberately: busbar answers `text/event-stream` only when a client
// prefers it (or asks for progress), and this harness asserts on single JSON-RPC frames. Both types
// are named because a client that cannot receive a stream at all cannot receive progress, and the
// SSE branch below exists so that a stream, if one ever comes back, is unpacked rather than dumped
// on stdout as prose.
const ACCEPT = 'application/json, text/event-stream';

/** The three methods whose target name the `Mcp-Name` header mirrors, and where it lives. */
function nameSourceOf(method) {
  if (method === 'tools/call' || method === 'prompts/get') return 'name';
  if (method === 'resources/read') return 'uri';
  return null;
}

/**
 * A header value must be printable ASCII with no CR/LF. A tool name that is not -- and the battery
 * sends some -- is carried in the revision's own `=?base64?...?=` sentinel, which busbar decodes
 * before comparing. Dropping such a header instead would turn a name the client CAN mirror into a
 * header mismatch, i.e. into an answer about this file.
 */
function headerValue(s) {
  if (/^[\x20-\x7e]*$/.test(s) && !s.startsWith('=?base64?')) return s;
  return `=?base64?${Buffer.from(s, 'utf8').toString('base64')}?=`;
}

/** The mirrored headers this body implies. Nothing the body does not state is stated here. */
function headersFor(parsed) {
  const h = { 'content-type': 'application/json', accept: ACCEPT };
  if (bearer) h.authorization = `Bearer ${bearer}`;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return h;
  const method = parsed.method;
  if (typeof method !== 'string') return h;
  h['mcp-method'] = headerValue(method);
  const meta = parsed.params && typeof parsed.params === 'object'
    ? parsed.params._meta : undefined;
  const version = meta && typeof meta === 'object'
    ? meta['io.modelcontextprotocol/protocolVersion'] : undefined;
  if (typeof version === 'string' && version !== '') h['mcp-protocol-version'] = headerValue(version);
  const source = nameSourceOf(method);
  if (source) {
    const target = parsed.params && typeof parsed.params === 'object'
      ? parsed.params[source] : undefined;
    if (typeof target === 'string') h['mcp-name'] = headerValue(target);
  }
  return h;
}

// One writer for stdout so two concurrent responses cannot interleave inside a line.
function emit(obj) {
  process.stdout.write(`${JSON.stringify(obj)}\n`);
}

/**
 * What comes back. A JSON-RPC message goes to stdout as one frame; ANYTHING ELSE goes to stderr.
 *
 * That split is not tidying. A stdio MCP stream may carry nothing but MCP messages, so a 401
 * challenge body or an HTML error page cannot be written to stdout without this file itself
 * breaking the framing MUST -- and the battery would then report an unparseable-stdout failure
 * against busbar for a body busbar was entitled to send over HTTP. Sent to stderr it stays visible
 * to whoever reads the run.
 */
function deliver(status, contentType, text) {
  if (text === '') return;                       // e.g. an accepted notification. Nothing to frame.
  const frames = [];
  if (/text\/event-stream/i.test(contentType || '')) {
    for (const line of text.split('\n')) {
      const m = /^data:\s?(.*)$/.exec(line.replace(/\r$/, ''));
      if (m) frames.push(m[1]);
    }
  } else {
    frames.push(text);
  }
  for (const f of frames) {
    if (f.trim() === '') continue;
    let parsed;
    try { parsed = JSON.parse(f); } catch {
      process.stderr.write(`bridge: non-JSON body (HTTP ${status}): ${f.slice(0, 400)}\n`);
      continue;
    }
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && 'jsonrpc' in parsed) {
      emit(parsed);
    } else {
      process.stderr.write(
        `bridge: HTTP ${status} body is not a JSON-RPC message: ${f.slice(0, 400)}\n`,
      );
    }
  }
}

/**
 * One stdin line -> one POST. NOT awaited by the reader: the battery has concurrency tests that put
 * several requests in flight before reading any answer, and a bridge that serialised them would
 * make every one of those tests a statement about this file.
 */
async function forward(raw) {
  let parsed = null;
  try { parsed = JSON.parse(raw.toString('utf8')); } catch { /* forwarded verbatim; see header */ }
  let res;
  try {
    res = await fetch(url, { method: 'POST', headers: headersFor(parsed), body: raw });
  } catch (e) {
    // A dead endpoint must look like a dead endpoint, never like a conformance verdict.
    process.stderr.write(`bridge: POST ${url} failed: ${e}\n`);
    return;
  }
  const text = await res.text();
  deliver(res.status, res.headers.get('content-type'), text);
}

// FRAMING, ON BYTES. Lines are split on 0x0A and forwarded as Buffers, never as re-encoded strings:
// the battery sends lone surrogates and NUL bytes on purpose, and a round trip through a JS string
// would sanitise exactly the input under test.
let buf = Buffer.alloc(0);
process.stdin.on('data', (chunk) => {
  buf = Buffer.concat([buf, chunk]);
  let i;
  while ((i = buf.indexOf(0x0a)) >= 0) {
    const line = buf.subarray(0, i);
    buf = buf.subarray(i + 1);
    // A blank or whitespace-only line carries no message. Not an error, not a POST: the stdio
    // framing says a frame is a line, and an empty line is not a frame.
    if (line.toString('utf8').trim() === '') continue;
    void forward(Buffer.from(line));
  }
});

// EOF on stdin is the shutdown signal for a stdio server, and this adapter is what stands in for
// one. Exiting keeps `SHUTDOWN`-shaped tests honest instead of hanging them to a failsafe.
process.stdin.on('end', () => {
  // A short grace so an answer already in flight is still written; the reader is closed either way.
  setTimeout(() => process.exit(0), 250).unref();
});
