#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// check-proof-manifest-public.mjs -- THE PUBLIC-SAFETY GUARD for the proof manifest.
//
// The manifest (docs/proof/<version>.json) is rendered PUBLIC by the marketing site while the busbar
// source stays PRIVATE. This guard is fail-closed: it asserts the manifest carries ONLY verdicts,
// counts, gate/test/field NAMES, and evidence POINTERS -- and NOTHING source-like. It mirrors the
// marketing repo's existing check-staged-claims.mjs / check-facts-provenance.mjs posture: any smell of
// source, secrets, or file CONTENTS fails the build rather than leaking.
//
// Usage: node scripts/check-proof-manifest-public.mjs docs/proof/dev.json [more.json ...]
//        node scripts/check-proof-manifest-public.mjs            # defaults to all docs/proof/*.json

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = dirname(HERE);

// Keys allowed to appear anywhere in the manifest tree. Anything else -> fail closed.
const ALLOWED_KEYS = new Set([
  "schema_version", "release", "provenance", "verdicts",
  // release block
  "version", "tag", "qa_sha", "staging_tag", "digest", "run_id", "run_url", "recorded_at",
  // provenance block
  "content_digest", "collator",
  // verdict + source
  "class", "title", "status", "evidence_count", "evidence_total", "unit", "meter", "sources",
  "id", "kind", "count", "total", "lane_count", "breakdown", "selftest", "runs_in", "note",
  "drilldown", "planes", "legs", "dialects", "carried", "waived", "missing", "by_dialect", "waivers",
  // drilldown + waiver
  "type", "path", "artifact", "lanes", "lane", "cases", "field", "date", "reason",
]);

const STATUS_ENUM = new Set(["pass", "fail", "report-only", "reserved", "unknown", "present"]);

// Fields whose VALUE is a map with dynamic keys (category / dialect / plane / conformance-leg names).
// Their keys are not whitelisted individually; instead each key must be a short safe token and each
// value must be a number or a status string. This keeps the map public-safe without hard-coding every
// dialect/leg name.
const VALUE_MAP_KEYS = new Set(["breakdown", "planes", "legs", "dialects", "by_dialect"]);
const SAFE_TOKEN = /^[A-Za-z0-9_.-]+$/;

// Source-like smells that must never appear in any string value.
const SOURCE_SMELLS = [
  /\bfn\s+\w+\s*\(/,          // a Rust fn signature body
  /\bimpl\s+\w/,             // impl block
  /\blet\s+\w+\s*=/,         // rust/js binding
  /\buse\s+busbar_/,         // a use import
  /=>|::<|\bunsafe\b/,       // rust operators / unsafe
  /-----BEGIN [A-Z ]+-----/, // PEM key
  /\bAKIA[0-9A-Z]{16}\b/,    // AWS access key id
  /\bxox[baprs]-[0-9A-Za-z-]+/, // slack token
  /\bghp_[0-9A-Za-z]{20,}/,  // github PAT
  /\bBearer\s+[A-Za-z0-9._-]{20,}/i,
  /\bhttps?:\/\/(localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/, // internal URLs
  /password|secret|api[_-]?key|token\s*[:=]/i,
];

// The only URL host allowed in run_url (public GitHub Actions).
const RUN_URL_OK = /^https:\/\/github\.com\/GetBusbar\/busbar\/actions(\/|$)|^$/;

let errors = [];

function fail(where, msg) {
  errors.push(`${where}: ${msg}`);
}

function checkString(where, s) {
  for (const re of SOURCE_SMELLS) {
    if (re.test(s)) {
      fail(where, `value looks source-like / secret-like (matched ${re}): ${JSON.stringify(s).slice(0, 80)}`);
    }
  }
  // A multi-line string is a strong smell of embedded file contents.
  if (s.includes("\n")) fail(where, "multi-line string (embedded file contents?)");
}

function checkValueMap(where, node) {
  if (node === null || typeof node !== "object" || Array.isArray(node)) {
    fail(where, "expected an object map of name -> count/status");
    return;
  }
  for (const [k, v] of Object.entries(node)) {
    if (!SAFE_TOKEN.test(k) || k.length > 40) fail(where, `map key ${JSON.stringify(k)} is not a short safe token`);
    if (typeof v === "number") continue;
    if (typeof v === "string" && STATUS_ENUM.has(v)) continue;
    fail(`${where}.${k}`, `map value must be a number or status string, got ${JSON.stringify(v)}`);
  }
}

function walk(where, node) {
  if (node === null) return;
  if (typeof node === "string") { checkString(where, node); return; }
  if (typeof node === "number" || typeof node === "boolean") return;
  if (Array.isArray(node)) { node.forEach((v, i) => walk(`${where}[${i}]`, v)); return; }
  if (typeof node === "object") {
    for (const [k, v] of Object.entries(node)) {
      if (!ALLOWED_KEYS.has(k)) fail(where, `unexpected key ${JSON.stringify(k)} (not in the public whitelist)`);
      if (VALUE_MAP_KEYS.has(k)) { checkValueMap(`${where}.${k}`, v); continue; }
      walk(`${where}.${k}`, v);
    }
    return;
  }
}

function checkManifest(file) {
  let m;
  try {
    m = JSON.parse(readFileSync(file, "utf8"));
  } catch (e) {
    fail(file, `not valid JSON: ${e.message}`);
    return;
  }
  if (m.schema_version !== "1") fail(file, `schema_version must be "1", got ${JSON.stringify(m.schema_version)}`);
  if (!Array.isArray(m.verdicts) || m.verdicts.length === 0) fail(file, "verdicts[] missing or empty");
  const runUrl = m?.release?.run_url ?? "";
  if (!RUN_URL_OK.test(runUrl)) fail(file, `release.run_url is not a public GetBusbar Actions URL: ${runUrl}`);
  // statuses must be from the closed enum
  for (const v of m.verdicts || []) {
    if (!STATUS_ENUM.has(v.status)) fail(file, `verdict ${v.class}: illegal status ${JSON.stringify(v.status)}`);
    for (const s of v.sources || []) {
      if (!STATUS_ENUM.has(s.status)) fail(file, `source ${s.id}: illegal status ${JSON.stringify(s.status)}`);
    }
  }
  walk(basename(file), m);
}

let files = process.argv.slice(2);
if (files.length === 0) {
  const dir = join(REPO, "docs/proof");
  if (existsSync(dir)) {
    files = readdirSync(dir).filter((f) => f.endsWith(".json") && f !== "index.json").map((f) => join(dir, f));
  }
}
if (files.length === 0) {
  console.error("check-proof-manifest-public: no manifest files found to check.");
  process.exit(0);
}

for (const f of files) checkManifest(f);

if (errors.length) {
  console.error("check-proof-manifest-public: FAIL -- the manifest is not public-safe:");
  for (const e of errors) console.error("  - " + e);
  process.exit(1);
}
console.error(`check-proof-manifest-public: PASS -- ${files.length} manifest(s) are verdicts-only and public-safe.`);
