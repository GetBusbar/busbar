#!/usr/bin/env bash
# Settings-leak enforcement lint — the can't-forget guarantee behind the "an admin READ never serves
# an operator settings bag's VALUES" rule.
#
# THE RULE: an admin-facing PROJECTION may carry the KEY NAMES of an opaque `settings:` bag
# (`settings_keys`, produced by `admin::v1::service::settings_keys` or, structurally, by
# `service::redact_settings_bags`) but NEVER the bag itself.
#
# WHY A LINT AND NOT FOUR PATCHES. This defect class has now been found FOUR times, in four different
# projections, each written independently and each accompanied by a doc comment asserting the bag was
# safe:
#   * `NamedDefView` (`identity-providers`/`export` reads) — the bag holds an OIDC `client_secret` /
#     a webhook `auth_header.value`. Fixed first; its doc had claimed secrets are "never projected".
#   * `HookView` (`GET /hooks[/{name}]`) — its doc claimed hook settings are "never a secret by
#     contract". A hook's bag is a `SecretRef` carrier by design.
#   * `GET /hooks/{name}/status` — served the hook's ECHO of the SECRET-RESOLVED bag, i.e. the
#     PLAINTEXT of every `SecretRef`, at READ-ONLY scope.
#   * `GET /config/settings` — serialized the whole `RootSettings`, carrying `store.settings`, whose
#     `url` busbar's own docs spell with a password and `plugin-pack` marks `x-busbar-secret`. That
#     GET is READ-ONLY scope while the matching PUT is FULL.
# Every one of them was a NEW projection added later, by someone who had not read the previous
# retraction. A fifth projection will be written the same way; this makes it fail the build instead.
#
# WHAT IT SCANS: `crates/busbar-core/src/**/*.rs` — the WHOLE ENGINE CRATE, minus test trees (named-
# navigated and exempt exactly the way structure-lint.sh / response-header-lint.sh /
# tracing-lint.sh treat them).
#
# THE SCAN ROOT USED TO BE `crates/busbar-core/src/admin/**` ALONE, and that was a COVERAGE CLAIM the lint
# could not back: an admin handler serializes whatever type it is handed, and nothing requires that
# type to be DECLARED under `admin/`. A view struct born in `hooks/`, `governance/` or `config/` and
# returned by an admin handler was invisible to this lint while being exactly the defect it exists
# to catch — and `hooks/wire.rs`'s `StatusReply` (the hook's echo of the RESOLVED bag, the third
# historical leak in the list above) is precisely such a type. The engine crate is the boundary that
# actually holds: an admin projection is BUILT here. The sibling wire/ABI crates (`busbar-api`,
# `plugin-abi`, `secret-ref`) define the ABI-level bag types themselves and are out of scope by
# construction — they have no admin surface and cannot serve an HTTP read.
#
# WHAT IT FLAGS, two mechanical shapes:
#   R1  a STRUCT FIELD named `settings` (or `*_settings`) declared as a raw bag type
#       (`serde_json::Map<…>` / `serde_json::Value`, optionally `Option<…>`) — an admin VIEW field.
#   R2  a JSON body member `"settings":` — a hand-built `json!` response member.
#
# THE ALLOWLIST is explicit, per-line and self-documenting: put
#     // settings-leak-lint: allow — <reason>
# on the line itself or the line immediately above. Use it ONLY for (a) an INBOUND request-body
# struct (a bag the operator is WRITING, never serialized back), (b) a response ENVELOPE member
# whose nested bags are already redacted by `service::redact_settings_bags`, or (c) a NON-PROJECTION
# engine type — an operator CONFIG struct (`HookCfg`, `StoreCfg`, … : the parsed `settings:` the
# operator wrote) or an INBOUND wire reply the engine consumes internally. Category (c) is what the
# widened scan root buys: such a type is only safe while nothing serializes it to a reader, so the
# marker is the place that claim is written down and reviewed. Adding a marker with any other reason
# is the bug this lint exists to catch, in a costume.
#
# Runs in CI (see .github/workflows/ci.yml, structure-lint job) alongside its sibling lints: no
# external deps, bash 3.2 + POSIX awk (macOS/Linux), and `--selftest` proves the scanner still catches
# a real leak before its verdict on the tree is trusted.
set -euo pipefail
cd "$(dirname "$0")/.."

note() { printf '  %s\n' "$1"; }
hdr()  { printf '\n== %s ==\n' "$1"; }

# ── THE SCANNER ────────────────────────────────────────────────────────────────────────────────────
# One awk pass per file. `prev_allow` carries the allow marker forward exactly one line, so the
# marker may sit above a multi-line-formatted field. Comment lines never arm a rule (a doc comment
# quoting `"settings":` is prose, not a projection).
SETTINGS_SCAN_AWK='
  FNR==1 { prev_allow=0 }
  {
    line = $0
    is_comment = (line ~ /^[[:space:]]*(\/\/|\*|\/\*)/)
    allow = (line ~ /settings-leak-lint:[[:space:]]*allow/) || prev_allow
    # Carry an allow marker forward across the COMMENT BLOCK it starts (a reason rarely fits on one
    # line) and no further: the first non-comment line consumes it, and the line after that is armed
    # again. So a marker covers exactly the one declaration it sits above.
    if (line ~ /settings-leak-lint:[[:space:]]*allow/)      prev_allow = 1
    else if (is_comment && prev_allow)                      prev_allow = 1
    else                                                    prev_allow = 0
    if (is_comment || allow) next

    # R1 — a raw settings BAG as a struct field type.
    if (line ~ /^[[:space:]]*(pub(\([a-z]+\))?[[:space:]]+)?[a-z_]*settings[[:space:]]*:[[:space:]]*(Option[[:space:]]*<[[:space:]]*)?(serde_json::)?(Map[[:space:]]*<|Value[[:space:]]*[,>]|Value[[:space:]]*$)/) {
      printf "%s:%d: admin view field carries a RAW settings bag — project settings_keys (admin::v1::service::settings_keys) or redact via service::redact_settings_bags\n", FILENAME, FNR
      next
    }
    # R2 — a hand-built JSON response member named `settings`.
    if (line ~ /"settings"[[:space:]]*:/) {
      printf "%s:%d: admin JSON body serializes a `settings` member — serve `settings_keys` instead (or redact the tree with service::redact_settings_bags and allowlist the envelope)\n", FILENAME, FNR
      next
    }
  }
'
scan_rule() { awk "$SETTINGS_SCAN_AWK" "$@"; }

# ── SELF-TEST — prove the scanner still catches a real leak before trusting its verdict ────────────
run_selftest() {
  hdr "settings-leak-lint SELF-TEST (the raw-bag scanner cannot be lied to)"
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local fail=0 pass=0

  # RED: every shape this lint exists to catch — the four historical leaks, transcribed.
  cat >"${tmp}/red.rs" <<'RED'
#[derive(Serialize)]
pub(crate) struct HookView {
    pub(crate) name: String,
    pub(crate) settings: serde_json::Map<String, serde_json::Value>,
}

#[derive(Serialize)]
pub(crate) struct HookReportedStatus {
    pub(crate) settings: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Serialize)]
pub(crate) struct ConfigSettingsView {
    pub(crate) settings: serde_json::Value,
}

fn hook_status() -> Response {
    ok_json(StatusCode::OK, &json!({
        "name": name,
        "reported": {"settings": r.settings, "settings_version": r.settings_version},
    }))
}
RED
  local hits n
  hits=$(scan_rule "${tmp}/red.rs")
  n=$(printf '%s\n' "$hits" | grep -c ':' || true)
  if [ "$n" -eq 4 ]; then
    pass=$((pass+1)); note "RED: all 4 leak shapes (Map field / Option<Map> field / Value field / json! member) flagged"
  else
    fail=1; note "RED FAILED: expected 4 hits, got ${n}:"; note "$hits"
  fi

  # GREEN: the SANCTIONED forms — the keys projection, the structural redaction, and the two
  # allowlisted categories (an inbound body, a redacted envelope). All must stay silent.
  cat >"${tmp}/green.rs" <<'GREEN'
#[derive(Serialize)]
pub(crate) struct HookView {
    pub(crate) settings_keys: Vec<String>,
}

#[derive(Serialize)]
pub(crate) struct HookReportedStatus {
    pub(crate) settings_keys: Option<Vec<String>>,
}

/// The PATCH body — INBOUND only.
#[derive(Deserialize)]
pub(crate) struct PatchSettingsReq {
    // settings-leak-lint: allow — inbound request body; never serialized back to a reader.
    settings: serde_json::Map<String, serde_json::Value>,
}

fn hook_status() -> Response {
    let mut settings = serde_json::to_value(&root).unwrap_or_default();
    crate::admin::v1::service::redact_settings_bags(&mut settings);
    ok_json(StatusCode::OK, &json!({
        "desired": {"settings_keys": settings_keys(&hook.settings), "settings_version": v},
        // settings-leak-lint: allow — response envelope; nested bags already redacted above.
        "settings": settings,
    }))
}

// A doc comment merely NAMING a "settings": member, or a settings: Map<…> field, must not arm the
// scanner: `pub(crate) settings: serde_json::Map<String, serde_json::Value>`.
GREEN
  hits=$(scan_rule "${tmp}/green.rs")
  if [ -z "$hits" ]; then
    pass=$((pass+1)); note "GREEN: settings_keys projections, the redaction helper, both allowlist categories and comment mentions all stay silent"
  else
    fail=1; note "GREEN FAILED: expected silence, got: $hits"
  fi

  # A marker must not be a blanket mute: an UNMARKED leak two lines below a marker is still caught.
  cat >"${tmp}/scope.rs" <<'SCOPE'
// settings-leak-lint: allow — this marker (and its continuation line, since a reason rarely
// fits on one line) covers the NEXT declaration only.
pub(crate) settings: serde_json::Value,
pub(crate) other: u8,
pub(crate) settings: serde_json::Map<String, serde_json::Value>,
SCOPE
  hits=$(scan_rule "${tmp}/scope.rs")
  n=$(printf '%s\n' "$hits" | grep -c ':' || true)
  if [ "$n" -eq 1 ]; then
    pass=$((pass+1)); note "SCOPE: an allow marker (incl. its comment continuation) covers exactly one declaration — a later unmarked leak is still flagged"
  else
    fail=1; note "SCOPE FAILED: expected 1 hit, got ${n}: $hits"
  fi

  note "self-test: ${pass}/3 fixture groups passed"
  if [ "$fail" -ne 0 ]; then
    note "settings-leak-lint SELF-TEST FAILED — the scanner would let a leak through"
    return 1
  fi
  note "ok"
  return 0
}

if [ "${1:-}" = "--selftest" ]; then run_selftest; exit $?; fi

hdr "no engine type reaching an admin read carries a raw operator settings bag"
# The WHOLE engine crate, not just `admin/**`: an admin handler serializes whatever type it is
# handed, and that type may be declared anywhere in the crate (see the scan-root note in the header).
CANDIDATES=()
# Core/bin split roots (step 3.7): the engine library and the thin binary are scanned together.
CORE="crates/busbar-core/src"
BIN="crates/busbar/src"
LLM="crates/busbar-llm/src"
# ── THE PLANE ROOTS, FOUND RATHER THAN SPELLED (see scripts/plane-roots.sh for the whole argument).
# 1.6.0's R-E makes the MCP and A2A planes plugin CRATES. They are 71 of the 238 files below and the
# scan floor is 100, so if they leave `$CORE` the count falls to 167, CLEARS THE FLOOR, and this
# lint goes on printing `ok` over a tree it no longer reads — and the raw settings bag this lint
# exists to catch is exactly the shape a plane's upstream credential handling reaches for. The
# floor catches a root that MOVED; only this catches a root that SPLIT.
# shellcheck source=scripts/plane-roots.sh
. "$(dirname "$0")/plane-roots.sh"
if ! plane_roots_resolve mcp a2a; then
  hdr "result"
  note "settings-leak-lint FAILED — PLANE ROOT UNRESOLVED"
  printf '%s' "$PLANE_ROOTS_ERR" | while IFS= read -r l; do note "$l"; done
  exit 1
fi
while IFS= read -r f; do CANDIDATES+=("$f"); done < <(find "$CORE" "$BIN" "$LLM" "$PLANE_ROOT_mcp" "$PLANE_ROOT_a2a" -name '*.rs' -not -path '*/tests/*' | sort -u)

# ── SCAN FLOOR — "for each file, assert no raw settings bag" is VACUOUSLY TRUE over zero files.
# Rename `crates/busbar`, move the engine, or mistype the root and this lint reports `ok` forever
# while nothing is scanned. The floor is not `> 0` (one file is as vacuous as none): it tracks the
# real tree (123 files when written) with slack for genuine consolidation.
SCAN_FLOOR=100
if [ "${#CANDIDATES[@]}" -lt "$SCAN_FLOOR" ]; then
  hdr "result"
  note "settings-leak-lint FAILED — SCAN ROOT EMPTY OR MOVED"
  note "found ${#CANDIDATES[@]} non-test .rs files under ${CORE}, expected >= ${SCAN_FLOOR}."
  note "This lint scanned (almost) nothing, so its verdict is meaningless — it is NOT a pass."
  note "If the engine crate legitimately moved, update the find root above AND this floor together."
  exit 1
fi
note "scan set: ${#CANDIDATES[@]} files under ${CORE} (floor ${SCAN_FLOOR})"

hits=""
for f in "${CANDIDATES[@]}"; do
  h=$(scan_rule "$f") || true
  [ -n "$h" ] && hits="${hits}${h}"$'\n'
done
hits="${hits%$'\n'}"

fail=0
if [ -n "$hits" ]; then
  while IFS= read -r h; do note "SETTINGS-LEAK: $h"; done <<<"$hits"
  fail=1
else
  note "ok"
fi

hdr "result"
if [ "$fail" -ne 0 ]; then
  note "settings-leak-lint FAILED"
  note "an admin projection must serve a settings bag's KEY NAMES, never its values:"
  note "  * a view field: \`settings_keys: Vec<String>\` filled by \`service::settings_keys(&cfg.settings)\`;"
  note "  * a serialized config tree: \`service::redact_settings_bags(&mut value)\` before it goes out."
  note "If (and ONLY if) the line is an INBOUND request body, a response ENVELOPE whose nested bags"
  note "are already redacted, or a NON-PROJECTION engine type (an operator config struct / an inbound"
  note "wire reply the engine only consumes), mark it: \`// settings-leak-lint: allow — <reason>\`."
  exit 1
fi
note "settings-leak-lint passed"
