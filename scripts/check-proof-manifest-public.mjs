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
//        node scripts/check-proof-manifest-public.mjs --selftest # prove every refusal RED first
//
// NOTHING TO CHECK IS NOT NOTHING TO LEAK. A guard that was handed no manifest used to print
// "no manifest files found to check." and exit 0 -- its PASS, on the one input it never proved it
// had. docs/proof/ renamed, emptied, or written to a different path by the collator all reach that
// line, and all of them look exactly like a manifest set that is clean. Zero manifests is now RED.

import { readFileSync, readdirSync, existsSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { tmpdir } from "node:os";
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
  // Per-source provenance of the claim itself. `evidence` is a repo-relative path to a test file or
  // corpus directory — the same class of datum as `drilldown.path`, which is already public and is
  // what the dashboard links to. `evidence_present` is a boolean. `shared_with` is a list of source
  // ids stamped from the SAME sibling job result, present so a reader cannot mistake one CI job's
  // verdict for N independent measurements. None of the three can carry source text: the path
  // shape is checked below exactly as `path` is.
  "evidence", "evidence_present", "shared_with",
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

// ── SELF-TEST: a guard that has never been watched refuse is not a guard ─────────────────────────
// Drives the REAL checkManifest/walk over fixtures whose verdict is known, so the PASS line above is
// only trusted after the refusals below have been seen to happen. Both directions are proven: each
// smell is proven to fire AND the clean twin is proven to stay silent, or a guard that rejected
// everything would look correct.
function selftest() {
  const cases = [
    ["a clean verdicts-only manifest", MIN_GOOD, 0],
    ["an embedded Rust fn signature", withVerdictNote(MIN_GOOD, "fn resolve_hook(x: &T) {"), 1],
    ["an embedded multi-line blob", withVerdictNote(MIN_GOOD, "line one\nline two"), 1],
    ["a leaked bearer token", withVerdictNote(MIN_GOOD, "Bearer abcdefghijklmnopqrstuvwxyz012345"), 1],
    ["a key that is not on the public whitelist",
     { ...MIN_GOOD, source_text: "anything at all" }, 1],
    ["an internal run_url", { ...MIN_GOOD, release: { run_url: "https://10.0.0.4/actions" } }, 1],
    ["an illegal verdict status",
     { ...MIN_GOOD, verdicts: [{ class: "c", status: "probably" }] }, 1],
    ["a manifest with no verdicts at all", { ...MIN_GOOD, verdicts: [] }, 1],
    ["the wrong schema_version", { ...MIN_GOOD, schema_version: "2" }, 1],
  ];
  let bad = 0;
  const tmp = mkdtempSync(join(tmpdir(), "proof-manifest-selftest-"));
  try {
    for (const [name, doc, want] of cases) {
      errors = [];
      const p = join(tmp, "case.json");
      writeFileSync(p, JSON.stringify(doc));
      checkManifest(p);
      const got = errors.length ? 1 : 0;
      if (got === want) {
        console.error(`  ok       ${want ? "REFUSED" : "accepted"}: ${name}`);
      } else {
        console.error(`  FAILED   ${name}: wanted ${want ? "a refusal" : "silence"}, got ${errors.join("; ") || "silence"}`);
        bad++;
      }
    }
    // THE VACUOUS PASS ITSELF. A guard handed no manifest used to print a message and exit 0 --
    // the whole check, reduced to a sentence, on the one input it never proved it had.
    errors = [];
    const rc = verdict([], "selftest");
    if (rc === 0) {
      console.error("  FAILED   an EMPTY manifest set was accepted; the guard passes having read nothing");
      bad++;
    } else {
      console.error("  ok       REFUSED: an empty manifest set is not a public-safe manifest set");
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
  errors = [];
  if (bad) {
    console.error(`\ncheck-proof-manifest-public selftest: RED (${bad} case(s) failed)`);
    return 1;
  }
  console.error(`\ncheck-proof-manifest-public selftest: GREEN (${cases.length + 1} cases)`);
  return 0;
}

const MIN_GOOD = {
  schema_version: "1",
  release: { version: "1.6.0", run_url: "https://github.com/GetBusbar/busbar/actions/runs/1" },
  verdicts: [{ class: "gates", title: "gates", status: "pass", count: 3 }],
};

function withVerdictNote(doc, note) {
  return { ...doc, verdicts: [{ ...doc.verdicts[0], note }] };
}

// The one place the run's verdict is decided, so `--selftest` can prove the empty case above rather
// than restate it.
function verdict(files, label) {
  if (files.length === 0) {
    console.error(
      `check-proof-manifest-public: FAIL -- no manifest file was checked (${label}).\n` +
      "  A public-safety guard handed nothing to read has proven nothing about what is published.\n" +
      "  Zero manifests is how docs/proof/ being renamed, emptied, or written to a different path\n" +
      "  looks from here, and it is indistinguishable from a manifest set that is clean. If the\n" +
      "  manifests legitimately moved, point this guard at their new home in a reviewed diff.",
    );
    return 1;
  }
  if (errors.length) {
    console.error("check-proof-manifest-public: FAIL -- the manifest is not public-safe:");
    for (const e of errors) console.error("  - " + e);
    return 1;
  }
  console.error(`check-proof-manifest-public: PASS -- ${files.length} manifest(s) are verdicts-only and public-safe.`);
  return 0;
}

let args = process.argv.slice(2);
if (args.includes("--selftest")) process.exit(selftest());

let files = args;
let where = "explicit arguments";
if (files.length === 0) {
  where = join(REPO, "docs/proof");
  if (existsSync(where)) {
    files = readdirSync(where).filter((f) => f.endsWith(".json") && f !== "index.json").map((f) => join(where, f));
  }
}

for (const f of files) checkManifest(f);
process.exit(verdict(files, where));
