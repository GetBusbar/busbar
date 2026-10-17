// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// MINT AN AUDIENCE-BOUND BUSBAR TOKEN FOR THE CONFORMANCE SUBJECT LEG.
//
// WHY THIS EXISTS AT ALL, AND WHY IT IS NOT A BYPASS.
//
// busbar's MCP endpoint is an OAuth RESOURCE server. Every request must carry a bearer whose
// audience is exactly this deployment's `mcp.canonical_uri`, or the verifier rejects it. The
// authorization server that mints such a token is somebody else's component -- busbar deliberately
// has no issuance surface, and the in-tree mint helper that the plane-boundary tests use is
// `cfg(test)`, so it cannot be reached from any shipped binary. A transport-conformance suite
// pointed at busbar therefore receives `401` on every scenario and proves nothing.
//
// So the CI job takes the role the authorization server takes in production: it HOLDS THE SIGNING
// KEY (it generated it, with `busbar --generate-signing-key`, and handed busbar the same bytes via
// `auth.signing_key`) and signs one token with it. That is exactly the trust relationship busbar's
// own design describes -- a fleet-shared ed25519 secret that whoever issues tokens must possess --
// and it changes nothing about busbar: the audience comparison, the signature check, the expiry and
// the generation check all run, unmodified, on every request. `mcp-conformance.sh` proves that
// rather than asserting it, by requiring `401` from the SAME booted process for a token with no
// audience, for a token bound to a different audience, and for a token whose signature was flipped.
//
// THE WIRE FORMAT IS BUSBAR'S, RESTATED HERE, AND THAT IS THE ONE REAL COST. This is a second
// implementation of a shape whose first implementation is `governance/signing.rs`, and a second
// implementation can drift from the first. The drift is contained by making it IMPOSSIBLE FOR THIS
// SCRIPT TO BE WRONG AND THE GATE STILL PASS: the token it emits is presented to a real busbar
// verifier in a preflight that must return 200 before the suite is allowed to start. If the payload
// shape moves, that preflight goes red naming the fact, in the same job, before any verdict.
//
// The format (see `governance/signing.rs`): NOT a JWT -- no header, no `alg`, therefore no
// algorithm-confusion surface. `bbk_<base64url(payload)>.<base64url(ed25519 signature))>`, the
// signature computed over the payload BYTES, and the payload the compact JSON
// `{ sub, exp, kid, g?, a?, cid? }` where `a` is the audience and `g` the binding generation.
//
// Usage: node mint-audience-token.mjs <signing-key-file> <plain-token> <audience>
//   <signing-key-file>  64 hex characters: the ed25519 secret busbar was configured with.
//   <plain-token>       a token from `POST /api/v1/admin/keys`. Read, never trusted: its payload
//                       supplies the `sub` and the binding `g`, both of which must match a real
//                       binding busbar minted, because the verifier checks the generation against
//                       the durable row. Nothing here invents a subject.
//   <audience>          the deployment's `mcp.canonical_uri`.

import { createPrivateKey, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';

const [keyPath, plainToken, audience] = process.argv.slice(2);
if (!keyPath || !plainToken || !audience) {
  console.error('usage: mint-audience-token.mjs <signing-key-file> <plain-token> <audience>');
  process.exit(2);
}

const hex = readFileSync(keyPath, 'utf8').trim();
if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
  console.error(
    `the signing key at ${keyPath} is not 64 hex characters. busbar's ed25519 secret is exactly ` +
      `32 bytes; anything else is a wrong file, not a wrong format.`,
  );
  process.exit(2);
}

// Node will not take a bare ed25519 seed, so the 32 bytes are wrapped in the fixed PKCS#8 preamble
// for `id-Ed25519`. The prefix is constant for every ed25519 key -- it encodes the algorithm OID and
// the length, and carries no key material -- so this is an encoding step, not a transformation.
const PKCS8_ED25519_PREFIX = '302e020100300506032b657004220420';
const key = createPrivateKey({
  key: Buffer.from(PKCS8_ED25519_PREFIX + hex, 'hex'),
  format: 'der',
  type: 'pkcs8',
});

const PREFIX = 'bbk_';
if (!plainToken.startsWith(PREFIX)) {
  console.error(`the plain token does not start with \`${PREFIX}\`; it is not a busbar key.`);
  process.exit(2);
}
const payload = JSON.parse(
  Buffer.from(plainToken.slice(PREFIX.length).split('.')[0], 'base64url').toString('utf8'),
);
if (!payload.sub || !payload.exp || !payload.kid) {
  console.error(`the plain token's payload is missing sub/exp/kid: ${JSON.stringify(payload)}`);
  process.exit(2);
}

// `g` is COPIED, never synthesised. busbar stamps a fresh generation into the durable binding on
// every rotate and refuses a token carrying a stale one; a generation this script made up would be
// refused, and a generation this script OMITTED would be refused too. Copying the one the mint
// returned is the only value that can be correct.
const claims = { sub: payload.sub, exp: payload.exp, kid: payload.kid, a: audience };
if (payload.g) claims.g = payload.g;

const body = Buffer.from(JSON.stringify(claims), 'utf8');
process.stdout.write(`${PREFIX}${body.toString('base64url')}.${sign(null, body, key).toString('base64url')}`);
