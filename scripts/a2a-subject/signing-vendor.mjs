// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// THE VENDOR, in the A2A conformance rig: a signed-card front for the pinned `a2a-go` control agent.
//
// WHY IT HAS TO EXIST, and why it is not a fixture that fakes anything.
//
// busbar will not APPROVE an `unpinned` registration, by construction — `a2a/pin.rs` caps it, and
// that cap is correct: an approval with no authenticity root is trust on first use wearing a
// ceremony. Of the three roots busbar accepts, two (`cert_spki`, `mtls`) are transport-layer and
// need a certificate the PLATFORM trusts, which a hermetic loopback rig cannot arrange without
// touching the machine's trust store. The third works over plaintext and is the one a real vendor
// with no PKI relationship uses: a JWS-signed Agent Card under an Ed25519 issuer key the operator
// holds out of band.
//
// So this process IS that vendor. It generates the issuer key, signs the control agent's OWN card
// with it — the same RFC 8785 canonicalization and the same detached-JWS shape `a2a/sign.rs`
// produces and `a2a/jws.rs` verifies — and proxies every other request through untouched. Nothing
// about busbar is relaxed to accommodate it: busbar performs the full fetch, the full signature
// verification against the operator-supplied key, and the full fingerprint pin, and REFUSES if any
// of them fails. The alternative — handing busbar a synthetic card, or weakening the approval cap
// for the rig — would be reporting conformance for a busbar nobody can run.
//
// usage: node signing-vendor.mjs <listen-port> <backend-port> <issuer-key-out>
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";

const [listenPort, backendPort, keyOut] = process.argv.slice(2);

const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
const spkiDer = publicKey.export({ type: "spki", format: "der" });
fs.writeFileSync(keyOut, spkiDer.toString("base64"));

const b64url = (b) => Buffer.from(b).toString("base64url");

// RFC 8785, the subset a card needs. Matches a2a/canonical.rs.
function jcs(v) {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("non-finite");
    if (Number.isInteger(v) && Math.abs(v) < 1e21) return String(v);
    return JSON.stringify(v);
  }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  const names = Object.keys(v).sort((a, b) => {
    const ua = Buffer.from(a, "utf16le"), ub = Buffer.from(b, "utf16le");
    return ua.compare(ub);
  });
  return "{" + names.map((n) => JSON.stringify(n) + ":" + jcs(v[n])).join(",") + "}";
}

function signCard(card) {
  const stripped = { ...card };
  delete stripped.signatures;
  const payload = b64url(jcs(stripped));
  const protectedB64 = b64url(jcs({ alg: "EdDSA", kid: "conformance-vendor" }));
  const sig = crypto.sign(null, Buffer.from(`${protectedB64}.${payload}`), privateKey);
  return { ...card, signatures: [{ protected: protectedB64, signature: b64url(sig) }] };
}

const CARD_PATHS = new Set(["/.well-known/agent-card.json", "/.well-known/agent.json"]);

http
  .createServer((req, res) => {
    const url = new URL(req.url, "http://x");
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      const up = http.request(
        {
          host: "127.0.0.1",
          port: Number(backendPort),
          path: req.url,
          method: req.method,
          headers: { ...req.headers, host: `127.0.0.1:${backendPort}` },
        },
        (ur) => {
          if (!CARD_PATHS.has(url.pathname)) {
            res.writeHead(ur.statusCode, ur.headers);
            ur.pipe(res);
            return;
          }
          const bufs = [];
          ur.on("data", (c) => bufs.push(c));
          ur.on("end", () => {
            let out;
            try {
              out = JSON.stringify(signCard(JSON.parse(Buffer.concat(bufs).toString())));
            } catch (e) {
              res.writeHead(502).end(String(e));
              return;
            }
            res.writeHead(ur.statusCode, {
              "content-type": "application/json",
              "content-length": Buffer.byteLength(out),
            });
            res.end(out);
          });
        },
      );
      up.on("error", (e) => res.writeHead(502).end(String(e)));
      if (body.length) up.write(body);
      up.end();
    });
  })
  .listen(Number(listenPort), "127.0.0.1", () => console.log("signing proxy up"));
