#!/usr/bin/env node
// THE HONEST-APPROVAL HELPER: compute, for every tool an upstream ACTUALLY SERVES, the same
// per-tool digest busbar's rug-pull defence computes — so the conformance rig's `schema_hash:`
// approvals can be the truth about the fixture upstreams instead of placeholder strings.
//
// WHY THIS EXISTS. busbar's `tools_allow.<tool>.schema_hash` is the operator's APPROVED digest,
// and `mcp::connect::refresh` compares it against the digest of what the upstream serves — on the
// operator's `connect` verb and, unattended, on the trust sweep's first tick. The rig used to
// write values like `"sha256:diagnostic-simple-text"`, which no served tool can ever hash to, so
// the first successful observation of any registration was a DRIFT and the registration was
// QUARANTINED — correctly, by a defence working exactly as built, against a rig that was lying
// about what it had approved. Every battery verdict downstream of that moment was a race against
// `SWEEP_TICK`. This helper is the honest fix: ask the fixture upstream what it serves, digest it
// the way busbar will, and approve THAT.
//
// THE DIGEST IS A RE-IMPLEMENTATION AND SAYS SO. The layout lives in
// `crates/busbar/src/mcp/client/catalogue.rs::tool_digest`: sha256 over, for each of
// [name, description, canonical(inputSchema)], an 8-byte big-endian length prefix followed by the
// UTF-8 bytes; the canonical form renders objects with keys sorted, recursively. Two
// implementations of one byte layout drift silently, so `--selftest` pins this one to the SAME
// fixture and constant as the Rust side's
// `the_digest_of_the_cross_language_pin_fixture_is_pinned`, and boot.sh runs it before trusting
// any digest printed here. Change the layout deliberately, in both places, or arming fails loudly.
//
// Usage:
//   tool-digest.mjs --selftest          exit 0 iff the pinned fixture digests to the pinned value
//   tool-digest.mjs <tools-list-url>    POST tools/list, print "<name> <digest>" per served tool

import { createHash } from 'node:crypto';

// `serde_json`'s rendering of a string (used for both keys and string scalars) and of scalars
// agrees with JSON.stringify for everything these fixtures can contain; the selftest is what makes
// that claim checked rather than assumed.
function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
}

function toolDigest(name, description, inputSchema) {
  const h = createHash('sha256');
  for (const part of [name, description, canonical(inputSchema)]) {
    const bytes = Buffer.from(part, 'utf8');
    const len = Buffer.alloc(8);
    len.writeBigUInt64BE(BigInt(bytes.length));
    h.update(len);
    h.update(bytes);
  }
  return `sha256:${h.digest('hex')}`;
}

// THE SHARED FIXTURE, byte-identical to the Rust pin test's. The expected value is the constant
// both sides assert; neither side derives it from the other at run time.
const PIN_EXPECTED = 'sha256:9a5b7d6295550c8e7a74b6c3068639c5497d2fc0856d554d2ce8cee17f30fd5d';
const PIN_FIXTURE = {
  name: 'pin',
  description: 'the cross-language digest pin',
  inputSchema: {
    type: 'object',
    properties: { a: { type: 'string' }, n: { type: 'integer' } },
    required: ['a'],
    additionalProperties: false,
  },
};

if (process.argv[2] === '--selftest') {
  const got = toolDigest(PIN_FIXTURE.name, PIN_FIXTURE.description, PIN_FIXTURE.inputSchema);
  if (got !== PIN_EXPECTED) {
    process.stderr.write(
      `tool-digest.mjs DISAGREES with busbar's digest layout: fixture digested to\n  ${got}\n`
      + `but the pinned constant is\n  ${PIN_EXPECTED}\n`
      + 'No digest this script prints can be trusted until the two implementations are '
      + 're-aligned (see the_digest_of_the_cross_language_pin_fixture_is_pinned).\n',
    );
    process.exit(1);
  }
  process.exit(0);
}

const url = process.argv[2];
if (!url) {
  process.stderr.write('usage: tool-digest.mjs --selftest | <tools-list-url>\n');
  process.exit(2);
}

// The same defaulting `mcp::connect::parse_tool_list` applies: a missing description is the empty
// string and a missing inputSchema is `{}`, BOTH digested at their defaulted value — an upstream
// that later supplies one has drifted, and this helper must agree about that baseline.
const body = JSON.stringify({
  jsonrpc: '2.0',
  id: 'tool-digest',
  method: 'tools/list',
  params: {
    _meta: {
      'io.modelcontextprotocol/protocolVersion': '2026-07-28',
      'io.modelcontextprotocol/clientCapabilities': {},
    },
  },
});
const res = await fetch(url, {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'mcp-method': 'tools/list' },
  body,
});
const answer = await res.json();
const tools = answer?.result?.tools;
if (!Array.isArray(tools) || tools.length === 0) {
  process.stderr.write(
    `tool-digest.mjs: ${url} answered no tools array (HTTP ${res.status}): `
    + `${JSON.stringify(answer).slice(0, 300)}\n`,
  );
  process.exit(1);
}
for (const t of tools) {
  process.stdout.write(
    `${t.name} ${toolDigest(t.name, t.description ?? '', t.inputSchema ?? {})}\n`,
  );
}
