#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# config-stability-gate.sh — the CONFIG-STABILITY CI GATE.
#
# 1.5.3 is the LAST config-breaking release. After it, the config grammar is FROZEN and every future
# feature may add only NEW OPTIONAL keys/sections/enum-variants. This gate ENFORCES that, per-PR, the
# same way the admin-API openapi.json drift guard enforces the served contract — READ a committed
# snapshot, REGENERATE from the source, DIFF — plus the mechanic the openapi guard does NOT have: an
# ADDITIVE-ONLY classifier that fails RED on any breaking delta.
#
# TWO checks, mirroring `openapi_json_matches_committed_file` + a new additive test:
#
#   1. DRIFT GUARD  — the committed `config-schema.snapshot.json` must byte-equal a fresh render of
#                     the config surface. A config-type change that forgets to regenerate the snapshot
#                     fails LOUD with the exact `UPDATE_CONFIG_SCHEMA=1` regen command — identical
#                     ergonomics to `UPDATE_OPENAPI=1`.
#
#   2. ADDITIVE-ONLY — the committed BASELINE (read from a git ref, NEVER the working tree) vs the
#                     fresh render, classified node-by-node: new optional field / new section / enum
#                     append = GREEN; field removed/retyped, newly-required, enum-variant dropped =
#                     RED. Because the baseline is a git ref, refreshing the snapshot file CANNOT
#                     launder a break through a snapshot rewrite.
#
# SELF-TEST (`--selftest`, run FIRST in CI like every other scripts/*-lint.sh): drives the classifier
# against fixture snapshot pairs whose verdict is known, proving the gate RED-flags a removal / retype
# / newly-required / enum-drop and GREEN-passes an additive add / new-section / enum-append / reorder
# — and that a snapshot "refresh" does not launder a break. The self-test cannot be lied to: it feeds
# the classifier known inputs and asserts the exact exit codes.
#
# It also drives the GENERATOR over throwaway Rust fixtures, because a classifier that judges deltas
# perfectly proves nothing about a generator that renders no delta to judge. Those cases assert that
# a hand-written `Deserialize` (its accepted spellings AND their types), a `deny_unknown_fields`
# flip and a container `rename_all` on a struct each move the fingerprint, and that the real tracked
# source set actually covers the secret-reference and upstream-credential grammars. A missing
# fixture is a FAILURE, never a skip, and the suite asserts its own executed case count so deleted
# coverage cannot present itself as a pass.
#
# No external deps beyond python3 (stdlib only) + git — the same bare-runner posture as the sibling
# lints. `UPDATE_CONFIG_SCHEMA=1` regenerates the snapshot (the reviewed-intentional-change path).

set -uo pipefail
cd "$(dirname "$0")/.."

PY=python3
GEN="scripts/config-schema.py"
# The TRACKED SOURCE SET lives in ONE place — `SOURCES` in config-schema.py — so `gen` is called
# with no path argument. It used to be a lone `crates/busbar/src/config` argument here, which is how
# `SecretRef` (its own crate) and `UpstreamCreds` (auth/mod.rs) came to be config grammar that no
# fingerprint covered. A gate whose reach is a directory glob covers where types live, not what they
# are, and both of those types moved out from under it.
# Core split (step 3.7): the config grammar lives in the engine library crate.
CORE="crates/busbar/src"
SNAPSHOT="${CORE}/config/config-schema.snapshot.json"
# The per-path break-waiver file (see config-schema.py load_waivers). A COMMITTED file, deliberately
# not an env var: every excused break is a reviewable line in the PR diff. Empty by default.
WAIVERS="${CORE}/config/config-schema.waivers"
BASELINE_REF="${CONFIG_SCHEMA_BASELINE_REF:-HEAD}"

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }

command -v "$PY" >/dev/null 2>&1 || { echo "config-stability-gate: python3 not found" >&2; exit 2; }

# ── SELF-TEST ──────────────────────────────────────────────────────────────────────────────────────
selftest() {
  hdr "config-stability gate SELF-TEST (the gate proves itself before it judges the tree)"
  local tmp rc fails=0 cases=0
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  # A tiny baseline fingerprint the fixtures mutate. Shapes mirror the REAL 1.5.3 grammar surface:
  # a named-definition map alias (`hooks:` = HookDefs), its definition struct, and the `phase:` stage
  # enum. There is deliberately NO `plane`/`bindings`/`principal` fixture — that grammar was DELETED
  # in 1.5.3 and must not survive even as a test fixture.
  cat >"$tmp/base.json" <<'JSON'
{
  "_meta": {"frozen_at": "1.5.3"},
  "types": {
    "Root": {"kind": "struct", "fields": {
      "keep":     {"type": "String", "optional": false},
      "opt":      {"type": "String", "optional": true}
    }},
    "HookStage": {"kind": "enum", "variants": ["request", "response"]},
    "type HookDefs": {"kind": "alias", "target": "indexmap::IndexMap<String, HookDefCfg>"}
  }
}
JSON

  # Each case: name · expected-exit(0=green,3=red,4=stale-waiver) · a python mutation producing
  # fresh.json · OPTIONAL waiver-file body (4th arg) fed to the classifier.
  run_case() {
    local name="$1" want="$2" mut="$3" waiver_body="${4-}"
    "$PY" - "$tmp/base.json" "$tmp/fresh.json" <<PY
import json, sys
d = json.load(open(sys.argv[1]))
$mut
json.dump(d, open(sys.argv[2], "w"))
PY
    if [ -n "$waiver_body" ]; then
      printf '%s\n' "$waiver_body" >"$tmp/waivers"
      "$PY" "$GEN" classify "$tmp/base.json" "$tmp/fresh.json" "$tmp/waivers" >/dev/null 2>&1
    else
      "$PY" "$GEN" classify "$tmp/base.json" "$tmp/fresh.json" >/dev/null 2>&1
    fi
    rc=$?
    verdict "$name" "$want" "$rc"
  }

  # ONE place that records a case outcome, so `cases` cannot drift from what actually ran.
  verdict() {
    local name="$1" want="$2" rc="$3"
    cases=$((cases + 1))
    if [ "$rc" -eq "$want" ]; then
      note "PASS  $name (exit $rc)"
    else
      red  "  FAIL  $name (want exit $want, got $rc)"
      fails=$((fails + 1))
    fi
  }

  # ── GREEN (additive) cases ──
  run_case "additive: new OPTIONAL field is GREEN"        0 'd["types"]["Root"]["fields"]["added"]={"type":"String","optional":True}'
  run_case "additive: new whole section is GREEN"         0 'd["types"]["NewSection"]={"kind":"struct","fields":{"x":{"type":"u32","optional":True}}}'
  run_case "additive: enum-variant append is GREEN"       0 'd["types"]["HookStage"]["variants"].append("candidate")'
  run_case "additive: required->optional relax is GREEN"  0 'd["types"]["Root"]["fields"]["keep"]["optional"]=True'
  run_case "no-op: key reorder / reformat is GREEN"       0 'd["types"]={k:d["types"][k] for k in sorted(d["types"],reverse=True)}'

  # ── RED (breaking) cases ──
  run_case "breaking: field REMOVAL is RED"               3 'del d["types"]["Root"]["fields"]["keep"]'
  run_case "breaking: field RETYPE is RED"                3 'd["types"]["Root"]["fields"]["keep"]["type"]="u32"'
  run_case "breaking: newly-REQUIRED field is RED"        3 'd["types"]["Root"]["fields"]["opt"]["optional"]=False'
  run_case "breaking: new REQUIRED field is RED"          3 'd["types"]["Root"]["fields"]["added"]={"type":"String","optional":False}'
  run_case "breaking: enum-variant DROP is RED"           3 'd["types"]["HookStage"]["variants"]=["request"]'
  run_case "breaking: enum-variant RENAME is RED"         3 'd["types"]["HookStage"]["variants"]=["request","respond"]'
  run_case "breaking: whole-section REMOVAL is RED"       3 'del d["types"]["HookStage"]'
  run_case "breaking: kind change (struct->enum) is RED"  3 'd["types"]["Root"]={"kind":"enum","variants":["a"]}'

  # The named-definition-map aliases ARE the `hooks:`/`export:`/`identity-providers:` grammar shape
  # Retargeting a map alias to a list breaks every config using the map form.
  run_case "breaking: def-map alias RETARGET is RED"      3 'd["types"]["type HookDefs"]["target"]="Vec<HookDefCfg>"'
  run_case "additive: NEW def-map alias is GREEN"         0 'd["types"]["type ExportDefs"]={"kind":"alias","target":"indexmap::IndexMap<String, ExportDefCfg>"}'

  # ── anti-launder: a snapshot "refresh" must NOT launder a break. The classifier's baseline
  # is the git-ref fingerprint (here base.json), independent of any working-tree snapshot rewrite:
  # even when the fresh render already dropped the field (exactly what a laundered snapshot looks
  # like), classify(baseline, fresh) still sees base.json's field and fails RED.
  run_case "anti-launder: refreshed snapshot still RED"   3 'del d["types"]["Root"]["fields"]["keep"]'

  # ── WAIVER discipline: the escape hatch must be NARROW, and must not become a blanket override. ──
  run_case "waiver: exact-path waiver excuses ITS break"  0 \
    'del d["types"]["Root"]["fields"]["keep"]' \
    'Root.keep = reviewed 1.5.3 break (self-test fixture)'
  # The decisive one: a waiver for path A must NOT suppress an unrelated break at path B.
  run_case "waiver: does NOT excuse an UNWAIVED break"    3 \
    'del d["types"]["Root"]["fields"]["keep"]; del d["types"]["HookStage"]' \
    'Root.keep = reviewed 1.5.3 break (self-test fixture)'
  # A waiver that no longer matches anything is dead standing permission to break that path later.
  run_case "waiver: STALE waiver is itself an error"      4 \
    'd["types"]["Root"]["fields"]["added"]={"type":"String","optional":True}' \
    'Root.keep = stale — the break it excused is gone'
  # A wildcard would turn the hatch into a rubber stamp; it must be refused outright (exit 1 from
  # SystemExit, i.e. neither a silent pass (0) nor a normal RED (3)).
  run_case "waiver: WILDCARD waiver is refused"           1 \
    'del d["types"]["Root"]["fields"]["keep"]' \
    'Root.* = wildcards must be refused'
  # An empty/absent waiver file must not weaken anything.
  run_case "waiver: empty waiver file changes nothing"    3 \
    'del d["types"]["Root"]["fields"]["keep"]' \
    '# no waivers'

  # ══ GENERATOR-SURFACE CASES ══════════════════════════════════════════════════════════════════
  # The cases above feed the CLASSIFIER hand-written JSON. They prove the classifier judges a delta
  # correctly and nothing else — every one of them stays green while the GENERATOR emits no delta at
  # all for a breaking source change, and four such changes did exactly that: a retyped secret
  # reference, a dropped upstream-credential value, a flipped `deny_unknown_fields` and a `rename_all`
  # added to a config struct all rendered byte-identical fingerprints. These cases therefore drive the
  # real `gen` over throwaway Rust fixtures, so a capability regression in the EXTRACTOR is caught
  # rather than papered over by a healthy classifier.

  mkdir -p "$tmp/fx"

  # (1) The secret-reference grammar: a hand-written `Deserialize` accepting a canonical form plus
  #     two sugar spellings. This shape is `SecretRef`, which lives in its own crate.
  cat >"$tmp/fx/secretref-base.rs" <<'RS'
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SecretRefFx {
    pub module: String,
    pub settings: serde_json::Map<String, serde_json::Value>,
}

impl<'de> Deserialize<'de> for SecretRefFx {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> {
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "module" => module = Some(map.next_value()?),
                "settings" => settings = Some(map.next_value()?),
                "env" => sugar = Some(map.next_value()?),
                "file" => sugar = Some(map.next_value()?),
                other => return Err(de::Error::unknown_field(other, FIELDS)),
            }
        }
    }
}
RS
  sed 's/pub module: String,/pub module: Vec<String>,/' \
    "$tmp/fx/secretref-base.rs" >"$tmp/fx/secretref-retyped.rs"
  sed 's/"env" =>/"environment" =>/' \
    "$tmp/fx/secretref-base.rs" >"$tmp/fx/secretref-sugar-renamed.rs"

  # (2) The upstream-credential grammar, which lives beside the auth middleware.
  cat >"$tmp/fx/creds-base.rs" <<'RS'
#[derive(Debug, Clone, Copy, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UpstreamCredsFx {
    #[default]
    Own,
    Passthrough,
}
RS
  sed '/    Passthrough,/d' "$tmp/fx/creds-base.rs" >"$tmp/fx/creds-dropped.rs"

  # (3) deny_unknown_fields: the knob that decides whether a document carrying an extra key parses.
  cat >"$tmp/fx/deny-off.rs" <<'RS'
#[derive(serde::Deserialize)]
pub(crate) struct DenyFx {
    pub(crate) protocol: String,
}
RS
  cat >"$tmp/fx/deny-on.rs" <<'RS'
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DenyFx {
    pub(crate) protocol: String,
}
RS

  # (4) container rename_all on a STRUCT: it rewrites the wire key of every field it covers.
  cat >"$tmp/fx/rename-none.rs" <<'RS'
#[derive(serde::Deserialize)]
pub(crate) struct RenameFx {
    pub(crate) max_tokens: u32,
    pub(crate) on_error: String,
}
RS
  cat >"$tmp/fx/rename-kebab.rs" <<'RS'
#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RenameFx {
    pub(crate) max_tokens: u32,
    pub(crate) on_error: String,
}
RS

  # (5) a test-only type is NOT config grammar, and must never be able to displace a real one.
  cat >"$tmp/fx/cfgtest.rs" <<'RS'
#[derive(serde::Deserialize)]
pub(crate) struct RealFx {
    pub(crate) real_key: String,
}

#[cfg(test)]
mod tests {
    #[derive(serde::Deserialize)]
    struct TestOnlyFx {
        fixture_key: String,
    }

    #[derive(serde::Deserialize)]
    struct RealFx {
        displaced: String,
    }
}
RS

  # (6) TWO PLANES, ONE BARE NAME. The fingerprint is keyed by the bare Rust ident with no module
  #     path, so a second file declaring a same-named type would REPLACE the first — the replaced
  #     grammar stops being covered at all, and the classifier reports the swap as a break in a
  #     grammar nobody edited. This is not hypothetical: `a2a/config.rs` and `mcp/config.rs` both
  #     had a `PinMechanism`, with different variants, and adding the second to the tracked set
  #     produced `PinMechanism::jws_issuer_key: enum variant REMOVED` out of a commit that did not
  #     touch A2A. The generator must REFUSE, not last-one-wins.
  mkdir -p "$tmp/collide"
  cat >"$tmp/collide/plane_a.rs" <<'RS'
#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PinMechanismFx {
    JwsIssuerKey,
    Unpinned,
}
RS
  cat >"$tmp/collide/plane_b.rs" <<'RS'
#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PinMechanismFx {
    PinnedPubkey,
    Unpinned,
}
RS

  gen_fp() { # <fixture.rs> <out.json> — fingerprint one throwaway source tree
    rm -rf "$tmp/gsrc"
    mkdir -p "$tmp/gsrc"
    # A fixture that is not there is a FAILURE, never a skip: a self-test that quietly stops
    # exercising its cases is the false green this gate is supposed to be immune to.
    [ -f "$1" ] || { red "  self-test fixture MISSING: $1"; return 9; }
    cp "$1" "$tmp/gsrc/fixture.rs"
    "$PY" "$GEN" gen "$tmp/gsrc" >"$2"
  }

  gen_case() { # <name> <want-exit> <base.rs> <fresh.rs>
    local name="$1" want="$2" rc
    if ! gen_fp "$3" "$tmp/gbase.json" || ! gen_fp "$4" "$tmp/gfresh.json"; then
      verdict "$name (generator failed / fixture missing)" "$want" 9
      return
    fi
    "$PY" "$GEN" classify "$tmp/gbase.json" "$tmp/gfresh.json" >/dev/null 2>&1
    rc=$?
    verdict "$name" "$want" "$rc"
  }

  py_assert() { # <name> <python body, `t` = the types map> [json-file, default the real render]
    local name="$1" code="$2" src="${3:-$tmp/real.json}" rc
    "$PY" - "$src" >/dev/null 2>&1 <<PY
import json, sys
t = json.load(open(sys.argv[1]))["types"]
$code
PY
    rc=$?
    verdict "$name" 0 "$rc"
  }

  hdr "self-test: GENERATOR surface (the four reach/fidelity holes, driven through \`gen\`)"

  # Controls first: an unchanged fixture must render identically, so a RED below is the sabotage
  # and never the fixture.
  gen_case "control: identical secret-ref render is GREEN"        0 \
    "$tmp/fx/secretref-base.rs" "$tmp/fx/secretref-base.rs"
  gen_case "control: identical upstream-creds render is GREEN"    0 \
    "$tmp/fx/creds-base.rs" "$tmp/fx/creds-base.rs"

  # HOLE 1 — the secret-reference grammar was outside the gate's reach entirely.
  gen_case "secret-ref canonical form RETYPED is RED"        3 \
    "$tmp/fx/secretref-base.rs" "$tmp/fx/secretref-retyped.rs"
  gen_case "secret-ref SUGAR spelling renamed is RED"        3 \
    "$tmp/fx/secretref-base.rs" "$tmp/fx/secretref-sugar-renamed.rs"
  gen_fp "$tmp/fx/secretref-base.rs" "$tmp/fx-secretref.json" || fails=$((fails + 1))
  py_assert "hand-written Deserialize: wire keys fingerprinted" \
    'assert set(t["manual-de SecretRefFx"]["wire_keys"]) == {"module", "settings", "env", "file"}, t["manual-de SecretRefFx"]' \
    "$tmp/fx-secretref.json"
  py_assert "hand-written Deserialize: member types fingerprinted" \
    'assert t["manual-de SecretRefFx"]["fields"]["module"]["type"] == "String", t["manual-de SecretRefFx"]' \
    "$tmp/fx-secretref.json"

  # HOLE 2 — same reach problem, the `upstream_credentials:` value grammar.
  gen_case "upstream-creds value DROPPED is RED"             3 \
    "$tmp/fx/creds-base.rs" "$tmp/fx/creds-dropped.rs"

  # HOLE 3 — deny_unknown_fields was parsed and then discarded.
  gen_case "deny_unknown_fields turned ON is RED"            3 \
    "$tmp/fx/deny-off.rs" "$tmp/fx/deny-on.rs"
  gen_case "deny_unknown_fields turned OFF is GREEN"         0 \
    "$tmp/fx/deny-on.rs" "$tmp/fx/deny-off.rs"
  gen_fp "$tmp/fx/deny-on.rs" "$tmp/fx-deny.json" || fails=$((fails + 1))
  py_assert "deny_unknown_fields is RECORDED, not discarded" \
    'assert t["DenyFx"]["deny_unknown_fields"] is True, t["DenyFx"]' \
    "$tmp/fx-deny.json"

  # HOLE 4 — container rename_all reached enum variants but never struct fields.
  gen_case "rename_all ADDED to a struct is RED"             3 \
    "$tmp/fx/rename-none.rs" "$tmp/fx/rename-kebab.rs"
  gen_case "rename_all REMOVED from a struct is RED"         3 \
    "$tmp/fx/rename-kebab.rs" "$tmp/fx/rename-none.rs"
  gen_fp "$tmp/fx/rename-kebab.rs" "$tmp/fx-rename.json" || fails=$((fails + 1))
  py_assert "rename_all is APPLIED to struct field keys" \
    'assert sorted(t["RenameFx"]["fields"]) == ["max-tokens", "on-error"], t["RenameFx"]' \
    "$tmp/fx-rename.json"

  # A test-only type is not grammar, and must not displace a same-named real one.
  gen_fp "$tmp/fx/cfgtest.rs" "$tmp/fx-cfgtest.json" || fails=$((fails + 1))
  py_assert "cfg(test) types are EXCLUDED from the grammar" \
    'assert "TestOnlyFx" not in t and sorted(t["RealFx"]["fields"]) == ["real_key"], sorted(t)' \
    "$tmp/fx-cfgtest.json"

  # HOLE 5 — a DUPLICATE bare name across two tracked files was a silent last-one-wins overwrite.
  # The control proves the two fixtures each fingerprint fine ALONE, so the RED below is the
  # collision and not a broken fixture.
  "$PY" "$GEN" gen "$tmp/collide/plane_a.rs" >/dev/null 2>&1
  verdict "control: one plane's PinMechanism alone is fine" 0 "$?"
  "$PY" "$GEN" gen "$tmp/collide/plane_b.rs" >/dev/null 2>&1
  verdict "control: the other plane's alone is fine" 0 "$?"
  # Together they collide. Exit 1 (SystemExit) — neither a silent pass nor a normal RED.
  "$PY" "$GEN" gen "$tmp/collide/plane_a.rs" "$tmp/collide/plane_b.rs" >/dev/null 2>&1
  verdict "a DUPLICATE bare name across files is REFUSED" 1 "$?"
  # And the refusal must NAME both files, or an operator cannot act on it. The message is captured to
  # a FILE and grepped separately rather than piped: under `set -o pipefail` the pipeline would carry
  # python's exit 1 no matter what grep found, and reading a pipe's status as the command's is how
  # this repo has already manufactured a false verdict.
  "$PY" "$GEN" gen "$tmp/collide/plane_a.rs" "$tmp/collide/plane_b.rs" >/dev/null 2>"$tmp/collide.err"
  grep -q "plane_a.rs.*plane_b.rs" "$tmp/collide.err"
  verdict "the collision refusal names BOTH declaring files" 0 "$?"

  # ── COVERAGE: the assertions above are about fixtures. These are about the REAL tracked set, so
  # the gate cannot be capable-in-principle while covering nothing that ships.
  hdr "self-test: COVERAGE of the real tracked source set"
  "$PY" "$GEN" gen >"$tmp/real.json" 2>/dev/null
  verdict "coverage: \`gen\` over the tracked source set succeeds" 0 "$?"
  py_assert "coverage: the surface is non-trivial (>= 50 types)" \
    'assert len(t) >= 50, len(t)'
  py_assert "coverage: SecretRef IS fingerprinted" \
    'assert "SecretRef" in t and set(t["manual-de SecretRef"]["wire_keys"]) >= {"module", "settings", "env", "file"}, sorted(k for k in t if "Secret" in k)'
  py_assert "coverage: SecretRef member types are fingerprinted" \
    'assert t["manual-de SecretRef"]["fields"]["module"]["type"] == "String", t["manual-de SecretRef"]'
  py_assert "coverage: UpstreamCreds IS fingerprinted" \
    'assert t["UpstreamCreds"]["variants"] == ["own", "passthrough"], t.get("UpstreamCreds")'
  py_assert "coverage: every derived container records its serde flags" \
    'bad = [k for k, v in t.items() if v.get("kind") in ("struct", "enum") and v.get("deserialize") != "manual" and not {"deny_unknown_fields", "transparent"} <= set(v)]
assert not bad, bad'
  py_assert "coverage: deny_unknown_fields is read from the source, not stubbed" \
    'assert any(v.get("deny_unknown_fields") for v in t.values()), "no type reported deny_unknown_fields"'
  # The `tools:` grammar (#60). `tools: ToolsCfg` was in the snapshot as a bare TYPE NAME and
  # nothing under it was, so `tools.<server>.url` could be retyped and a `transport:` value dropped
  # with ZERO delta. These assert the per-server keys an operator actually writes.
  # `url` is `optional` at the SERDE layer since `transport: stdio` landed — a spawned server has no
  # address, so requiredness moved to `mcp::config::validate_endpoint`, which can name the key the
  # operator is actually missing. The assertion follows it rather than pinning the old shape: the
  # TYPE is still fingerprinted, and the four SPAWN keys are now fingerprinted beside it. They are
  # the grammar of "busbar launches this binary with these arguments in this environment", which is
  # the single most security-relevant thing an operator can write in this file — a retype or a
  # silent drop there must never be a zero-delta change.
  py_assert "coverage: the MCP \`tools:\` server grammar IS fingerprinted" \
    'f = t["McpServerDefCfg"]["fields"]
assert f["url"]["type"] == "String", f["url"]
assert f["command"] == {"type": "String", "optional": True}, f["command"]
assert f["args"]["type"] == "Vec<String>", f["args"]
assert f["cwd"]["type"] == "String", f["cwd"]
assert "ChildEnvValue" in f["env"]["type"], f["env"]
assert t["ChildEnvValue"]["variants"] == ["Plain", "Secret"], t["ChildEnvValue"]
assert {"pin", "tools_allow", "prompts_allow", "resources_allow", "grants"} <= set(f), sorted(f)'
  py_assert "coverage: the MCP pin mechanisms are fingerprinted" \
    'assert t["McpPinMechanism"]["variants"] == ["cert_spki", "mtls", "pinned_pubkey", "unpinned"], t["McpPinMechanism"]'
  # The collision resolution, asserted as a PROPERTY rather than trusted to a rename: the A2A pin
  # grammar must still be present and still be A2A's. If a future edit reintroduces the clash, the
  # generator now refuses outright — this is the belt to that braces.
  py_assert "coverage: the A2A pin grammar SURVIVED the MCP addition" \
    'assert t["PinMechanism"]["variants"] == ["cert_spki", "jws_issuer_key", "mtls", "unpinned"], t["PinMechanism"]'

  # A tracked source that vanished must be a HARD ERROR. If a rename could silently shrink the
  # tracked set, the whole gate could be disabled by moving a file.
  if "$PY" "$GEN" gen "$tmp/no-such-source.rs" >/dev/null 2>&1; then rc=1; else rc=0; fi
  verdict "a MISSING tracked source is an error, never a skip" 0 "$rc"

  # ── The self-test's own honesty check. A suite that runs zero cases reports zero failures, which
  # is the false green this project has already been burned by three times in one night. Assert the
  # cases actually EXECUTED, and pin the floor to the count at the time of writing so deleting
  # coverage is itself RED.
  local want_cases=50
  if [ "$cases" -lt "$want_cases" ]; then
    red "  FAIL  self-test executed only $cases case(s); expected at least $want_cases."
    red "        Coverage was deleted, or the suite exited early — either way this is NOT a pass."
    fails=$((fails + 1))
  else
    note "PASS  self-test executed $cases case(s) (floor $want_cases)"
  fi

  if [ "$fails" -eq 0 ]; then
    grn "config-stability gate self-test: ALL GREEN ($cases cases; classifier RED/GREEN discipline"
    grn "and generator surface coverage both proven)"
    return 0
  fi
  red "config-stability gate self-test: $fails FAILED (of $cases)"
  return 1
}

# ── DRIFT GUARD ─────────────────────────────────────────────────────────────────────────────────────
check() {
  local tmp fresh rc
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  fresh="$tmp/fresh.json"

  "$PY" "$GEN" gen >"$fresh" || { red "config-schema gen failed"; return 2; }

  # UPDATE path: the reviewed-intentional-change escape hatch (identical role to UPDATE_OPENAPI=1).
  if [ "${UPDATE_CONFIG_SCHEMA:-}" = "1" ]; then
    cp "$fresh" "$SNAPSHOT"
    grn "UPDATE_CONFIG_SCHEMA=1: rewrote $SNAPSHOT"
    note "the additive check below STILL runs against the committed baseline — a refresh cannot launder a break."
  fi

  hdr "DRIFT GUARD — committed snapshot vs fresh render"
  if [ ! -f "$SNAPSHOT" ]; then
    red "missing committed snapshot: $SNAPSHOT"
    note "seed it with:  UPDATE_CONFIG_SCHEMA=1 scripts/config-stability-gate.sh"
    return 1
  fi
  if diff -u "$SNAPSHOT" "$fresh" >"$tmp/drift.diff" 2>&1; then
    grn "no drift — committed config-schema.snapshot.json matches the config source"
  else
    red "config-schema.snapshot.json is STALE — the config surface changed but the snapshot was not regenerated."
    sed 's/^/    /' "$tmp/drift.diff" | head -60
    echo
    note "regenerate (reviewed, intentional change) with:"
    note "    UPDATE_CONFIG_SCHEMA=1 scripts/config-stability-gate.sh"
    return 1
  fi

  # ── ADDITIVE-ONLY — baseline from a git ref (NEVER the working tree) ──
  hdr "ADDITIVE-ONLY — baseline ($BASELINE_REF) vs fresh render"

  # FIRST: does the ref itself resolve? This distinction is load-bearing. A single `cat-file` on
  # `<ref>:<path>` cannot tell "valid ref, snapshot not committed there yet" (a legitimate one-time
  # bootstrap) apart from "that ref does not exist at all" (a shallow clone, a missing `fetch-depth:
  # 0`, or a typo'd CONFIG_SCHEMA_BASELINE_REF). Collapsing both into a friendly "skipped" would hand
  # anyone a silent bypass: point the gate at a nonexistent ref and every breaking change sails
  # through green. An unresolvable ref is therefore a HARD ERROR, never a skip.
  if ! git rev-parse --verify --quiet "${BASELINE_REF}^{commit}" >/dev/null 2>&1; then
    red "config-stability gate: baseline ref '$BASELINE_REF' does NOT resolve — refusing to run."
    note "the additive check is the whole gate; silently skipping it would be a free bypass."
    note "in CI this almost always means the checkout was shallow — use actions/checkout with"
    note "    with: { fetch-depth: 0 }   (and for a PR, fetch the base branch)"
    note "locally, set CONFIG_SCHEMA_BASELINE_REF to a ref that exists (default: HEAD)."
    return 2
  fi

  if git cat-file -e "$BASELINE_REF:$SNAPSHOT" 2>/dev/null; then
    git show "$BASELINE_REF:$SNAPSHOT" >"$tmp/baseline.json" 2>/dev/null
    if "$PY" "$GEN" classify "$tmp/baseline.json" "$fresh" "$WAIVERS"; then
      grn "additive-only: every config-surface delta is additive (or no change)"
    else
      rc=$?
      red "config-stability gate: NON-ADDITIVE config change (see above)."
      return "$rc"
    fi
  else
    # The ref resolves but carries no snapshot: the genuine one-time bootstrap, i.e. the very commit
    # that introduces this gate. Narrow and self-extinguishing — true only until the snapshot lands.
    ylw "baseline $BASELINE_REF resolves but has no committed snapshot yet (ONE-TIME bootstrap: the"
    ylw "commit that introduces this gate) — additive check has nothing to diff against this run."
    note "every later commit/PR IS diffed against the committed snapshot. If you see this after the"
    note "snapshot is committed, the baseline ref is wrong — investigate, do not ignore."
  fi
  return 0
}

case "${1:-}" in
  --selftest) selftest ;;
  --check | "") check ;;
  -h | --help)
    sed -n '2,40p' "$0"
    ;;
  *) echo "usage: $0 [--selftest|--check]" >&2; exit 2 ;;
esac
