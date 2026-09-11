#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// THE COLLECTOR FIXTURE: a process outside busbar that speaks OTLP/HTTP, receives a real export
// from the real binary, and writes down what it read.
//
// It is the half of the OTLP oracle that a unit cell cannot be. The root's
// `a_span_this_process_emitted_decodes_as_that_span_at_a_collector` drives the real layer, the real
// gate, the real drain and the real sink and decodes the protobuf back — but it takes the bytes off
// a FAKE wire, inside the test process, with the publisher's own generated types on both sides. It
// pins what crosses the wire's door. This pins what crosses A SOCKET: the release binary's own
// egress client dials this server, this server reads the body with a decoder that shares not one
// line with the writer, and what it decoded is compared byte-for-byte against a checked-in
// expectation. A producer that minted a parent link the sink dropped, a sink that framed a field
// number the schema does not use, or an egress client that mangled the body would pass every cell
// in the tree and fail here.
//
// NO TOOLCHAIN IS ADDED. Node, stdlib only, exactly as scripts/mcp-subject/h2-mock-upstream.mjs and
// scripts/a2a-subject/h2-mock-agent.mjs are — no protobuf runtime, no OTLP SDK, no npm install. The
// protobuf reader below is ~100 lines of wire-format walking against the field numbers the
// opentelemetry-proto `.proto` files declare, which is the point: a hand-written READER disagreeing
// with the generated WRITER is how a framing bug shows up. (The reverse — a hand-written reader
// beside a hand-written writer — would prove nothing, which is why nothing here writes protobuf.)
//
// ── THE NORMALISATION RULES, AND THEY ARE THE ORACLE'S OWN ──────────────────────────────────────
// A span carries facts that are true of THE RUN and not of the export: ids minted from a
// per-process seed, a wall clock, a correlation stamp off a boot-seeded counter, this build's
// version. Comparing those byte-for-byte would pin the afternoon, not the contract. Each is
// replaced by what IS the contract, and each rule is stated here rather than applied silently:
//
//   1. `trace_id`/`span_id` become `trace-N`/`span-N` by FIRST APPEARANCE, in arrival order. What
//      is pinned is the SHAPE of the identity — which spans share a trace, which ids are distinct
//      — and that is the whole of what a collector can rebuild a tree from.
//   2. `parent_span_id` becomes that same token for the span it names, or `null` when it is empty.
//      An id naming a span this collector never received becomes `unknown`, which is a fact worth
//      seeing rather than one worth hiding.
//   3. `start_time_unix_nano`/`end_time_unix_nano` leave, and `window` arrives: `forwards` when the
//      start is non-zero and the end is not before it, `not-a-window` otherwise. The clock is the
//      run's; that the window runs forwards is the contract.
//   4. the `service.version` resource attribute becomes `<version>`: it is a fact about which build
//      exported, and pinning it would red this rig on every version bump for no defect.
//   5. an INTEGER attribute whose key ends in `_id` becomes `<u64>`: those are correlation stamps
//      off a boot-seeded counter (`request_id`), unique per process by design. That the span
//      CARRIES one is the contract; which number it is is not.
//
// Everything else — every span name, every kind, every status code and message, every attribute key
// and every non-normalised value, the resource, the scope, the dropped counts, the number of
// deliveries — crosses untouched. Keys are emitted SORTED at every level and the file ends in one
// newline, so the comparison is `cmp`, not a JSON walk that could quietly tolerate a field.
//
// Usage:
//   otlp-collector.mjs <port> <out-file> [--capture <body-file>]
//     POST /v1/traces  -> 200, an empty ExportTraceServiceResponse; the request is decoded, folded
//                         into the accumulated view, and <out-file> is rewritten
//     GET  /received   -> {"deliveries":N,"spans":M} (what the scenario polls)
//     --capture        -> also write the RAW protobuf body of the first delivery to <body-file>,
//                         which is what the offline half of the scenario's selftest replays
//   otlp-collector.mjs --decode <body-file> <out-file>
//     the same decode and the same canonical write, over a body from a file instead of a socket:
//     the selftest's offline arm, so the reader can be held to a recorded real export with no
//     binary, no build and no port.
import fs from 'node:fs';
import http from 'node:http';

// ── the protobuf wire reader ───────────────────────────────────────────────────────────────────
// Wire types: 0 varint, 1 fixed64, 2 length-delimited, 5 fixed32. Nothing else appears in the OTLP
// trace schema, and an unknown wire type is an error rather than a skip: a field this reader cannot
// walk past is a field it cannot claim to have read the message around.

/** Read one base-128 varint at `p.at`, advancing it. */
function varint(buf, p) {
  let result = 0n;
  let shift = 0n;
  for (;;) {
    if (p.at >= buf.length) throw new Error('truncated varint');
    const byte = buf[p.at++];
    result |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return result;
    shift += 7n;
    if (shift > 70n) throw new Error('varint too long');
  }
}

/**
 * Walk one length-delimited message, calling `onField(fieldNumber, value)` for every field in the
 * order it appears. `value` is a BigInt for varints and fixed64, a Number for fixed32, and a Buffer
 * slice for length-delimited fields.
 */
function fields(buf, onField) {
  const p = { at: 0 };
  while (p.at < buf.length) {
    const tag = varint(buf, p);
    const number = Number(tag >> 3n);
    const wire = Number(tag & 7n);
    if (wire === 0) {
      onField(number, varint(buf, p));
    } else if (wire === 1) {
      const v = buf.readBigUInt64LE(p.at);
      p.at += 8;
      onField(number, v);
    } else if (wire === 2) {
      const len = Number(varint(buf, p));
      if (p.at + len > buf.length) throw new Error('truncated length-delimited field');
      onField(number, buf.subarray(p.at, p.at + len));
      p.at += len;
    } else if (wire === 5) {
      const v = buf.readUInt32LE(p.at);
      p.at += 4;
      onField(number, v);
    } else {
      throw new Error(`unsupported protobuf wire type ${wire} on field ${number}`);
    }
  }
}

const SPAN_KIND = ['UNSPECIFIED', 'INTERNAL', 'SERVER', 'CLIENT', 'PRODUCER', 'CONSUMER'];
const STATUS_CODE = ['UNSET', 'OK', 'ERROR'];

/** opentelemetry.proto.common.v1.AnyValue -> a JSON value, tagged so an int is not a string. */
function anyValue(buf) {
  let out = null;
  fields(buf, (n, v) => {
    if (n === 1) out = { kind: 'str', value: v.toString('utf8') };
    else if (n === 2) out = { kind: 'bool', value: v !== 0n };
    else if (n === 3) out = { kind: 'int', value: BigInt.asIntN(64, v).toString() };
    else if (n === 4) {
      // `double_value` is a fixed64 on the wire, so `v` is the raw 64 bits; read them back as the
      // IEEE-754 double they are rather than as the integer they are not.
      const bits = Buffer.alloc(8);
      bits.writeBigUInt64LE(v);
      out = { kind: 'double', value: bits.readDoubleLE(0) };
    }
    else if (n === 7) out = { kind: 'bytes', value: v.toString('hex') };
    else out = { kind: `field-${n}`, value: null };
  });
  return out;
}

/** opentelemetry.proto.common.v1.KeyValue -> [key, tagged value]. */
function keyValue(buf) {
  let key = '';
  let value = null;
  fields(buf, (n, v) => {
    if (n === 1) key = v.toString('utf8');
    else if (n === 2) value = anyValue(v);
  });
  return [key, value];
}

/** opentelemetry.proto.trace.v1.Status -> {code, message}. */
function status(buf) {
  let message = '';
  let code = 0;
  fields(buf, (n, v) => {
    if (n === 2) message = v.toString('utf8');
    else if (n === 3) code = Number(v);
  });
  return { code: STATUS_CODE[code] ?? `CODE_${code}`, message };
}

/** opentelemetry.proto.trace.v1.Span, in the schema's own field numbers. */
function span(buf) {
  const out = {
    trace_id: '',
    span_id: '',
    parent_span_id: '',
    name: '',
    kind: 0,
    start: 0n,
    end: 0n,
    attributes: [],
    dropped_attributes: 0,
    status: { code: 'UNSET', message: '' },
  };
  fields(buf, (n, v) => {
    if (n === 1) out.trace_id = v.toString('hex');
    else if (n === 2) out.span_id = v.toString('hex');
    else if (n === 4) out.parent_span_id = v.toString('hex');
    else if (n === 5) out.name = v.toString('utf8');
    else if (n === 6) out.kind = Number(v);
    else if (n === 7) out.start = v;
    else if (n === 8) out.end = v;
    else if (n === 9) out.attributes.push(keyValue(v));
    else if (n === 10) out.dropped_attributes = Number(v);
    else if (n === 15) out.status = status(v);
  });
  return out;
}

/** ExportTraceServiceRequest -> {resource, scope, spans} as the collector read them. */
function exportRequest(body) {
  const resources = [];
  const scopes = [];
  const spans = [];
  fields(body, (n, resourceSpans) => {
    if (n !== 1) return;
    fields(resourceSpans, (rn, rv) => {
      if (rn === 1) {
        fields(rv, (an, av) => {
          if (an === 1) resources.push(keyValue(av));
        });
      } else if (rn === 2) {
        fields(rv, (sn, sv) => {
          if (sn === 1) {
            fields(sv, (in_, iv) => {
              if (in_ === 1) scopes.push(iv.toString('utf8'));
            });
          } else if (sn === 2) {
            spans.push(span(sv));
          }
        });
      }
    });
  });
  return { resources, scopes, spans };
}

// ── the canonical view ─────────────────────────────────────────────────────────────────────────

const STATE = { deliveries: 0, resources: [], scopes: [], spans: [], ids: new Map() };

/** Rules 1 and 2: an id becomes its first-appearance token. */
function token(prefix, hex) {
  if (!hex) return null;
  if (!STATE.ids.has(hex)) STATE.ids.set(hex, `${prefix}-${[...STATE.ids.values()].filter((t) => t.startsWith(`${prefix}-`)).length + 1}`);
  const got = STATE.ids.get(hex);
  return got.startsWith(`${prefix}-`) ? got : 'unknown';
}

/** Rules 4 and 5: the two values that are facts about the run rather than about the export. */
function normalisedAttribute(key, value, isResource) {
  if (isResource && key === 'service.version') return '<version>';
  if (value === null) return null;
  if (value.kind === 'int' && key.endsWith('_id')) return '<u64>';
  if (value.kind === 'bool') return value.value;
  if (value.kind === 'int') return Number(value.value);
  return value.value;
}

/** A plain object with its keys sorted, so `JSON.stringify` emits one canonical order. */
function sorted(pairs, isResource) {
  const out = {};
  for (const key of pairs.map(([k]) => k).sort()) {
    const found = pairs.find(([k]) => k === key);
    out[key] = normalisedAttribute(key, found[1], isResource);
  }
  return out;
}

function fold(decoded) {
  STATE.deliveries += 1;
  for (const r of decoded.resources) if (!STATE.resources.some(([k]) => k === r[0])) STATE.resources.push(r);
  for (const s of decoded.scopes) if (!STATE.scopes.includes(s)) STATE.scopes.push(s);
  // TWO PASSES, AND THE FIRST ONE IS THE POINT. Spans arrive in the order they CLOSED, so a child
  // is in the batch before its parent: resolving parents in one pass would tokenise every parent
  // link as `unknown` and a broken link would be indistinguishable from a working one. Registering
  // every id of the delivery first is what lets rule 2 answer `null`, a token, or `unknown` and
  // mean three different things.
  for (const s of decoded.spans) {
    token('trace', s.trace_id);
    token('span', s.span_id);
  }
  for (const s of decoded.spans) {
    STATE.spans.push({
      attributes: sorted(s.attributes, false),
      dropped_attributes: s.dropped_attributes,
      kind: SPAN_KIND[s.kind] ?? `KIND_${s.kind}`,
      name: s.name,
      // Rule 2. A root is `null`; a parent this collector never received is `unknown`.
      parent: s.parent_span_id ? (STATE.ids.has(s.parent_span_id) ? token('span', s.parent_span_id) : 'unknown') : null,
      span: token('span', s.span_id),
      status: { code: s.status.code, message: s.status.message },
      trace: token('trace', s.trace_id),
      // Rule 3.
      window: s.start > 0n && s.end >= s.start ? 'forwards' : 'not-a-window',
    });
  }
}

/** The whole received view, canonical: sorted keys, two-space indent, one trailing newline. */
function canonical() {
  return `${JSON.stringify(
    {
      deliveries: STATE.deliveries,
      resource: sorted(STATE.resources, true),
      scopes: [...STATE.scopes].sort(),
      spans: STATE.spans,
    },
    null,
    2,
  )}\n`;
}

// ── the two entry points ───────────────────────────────────────────────────────────────────────

const argv = process.argv.slice(2);

if (argv[0] === '--decode') {
  const [, bodyFile, outFile] = argv;
  if (!bodyFile || !outFile) {
    process.stderr.write('usage: otlp-collector.mjs --decode <body-file> <out-file>\n');
    process.exit(2);
  }
  fold(exportRequest(fs.readFileSync(bodyFile)));
  fs.writeFileSync(outFile, canonical());
  process.exit(0);
}

const port = Number(argv[0]);
const outFile = argv[1];
const captureIndex = argv.indexOf('--capture');
const captureFile = captureIndex === -1 ? null : argv[captureIndex + 1];
if (!port || !outFile) {
  process.stderr.write('usage: otlp-collector.mjs <port> <out-file> [--capture <body-file>]\n');
  process.exit(2);
}
// WRITTEN BEFORE THE FIRST DELIVERY, deliberately: a scenario that reads this file after a busbar
// that exported nothing must read an EMPTY view and fail the comparison, never fail to find a file
// and be tempted to call that an infrastructure problem.
fs.writeFileSync(outFile, canonical());

http
  .createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/received') {
      const body = JSON.stringify({ deliveries: STATE.deliveries, spans: STATE.spans.length });
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(body.length) });
      res.end(body);
      return;
    }
    if (req.method !== 'POST' || req.url !== '/v1/traces') {
      // A collector that answered 200 to a path the binding does not name would let a wrong
      // endpoint pass as a right one.
      res.writeHead(404, { 'content-length': '0' });
      res.end();
      return;
    }
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      try {
        if (captureFile && STATE.deliveries === 0) fs.writeFileSync(captureFile, body);
        fold(exportRequest(body));
        fs.writeFileSync(outFile, canonical());
      } catch (e) {
        process.stderr.write(`otlp-collector: undecodable export request: ${e.message}\n`);
        res.writeHead(400, { 'content-length': '0' });
        res.end();
        return;
      }
      // An empty ExportTraceServiceResponse IS the success answer: every field of it is optional and
      // proto3 elides the defaults, so zero bytes is a whole, valid message.
      res.writeHead(200, { 'content-type': 'application/x-protobuf', 'content-length': '0' });
      res.end();
    });
  })
  .listen(port, '127.0.0.1');
