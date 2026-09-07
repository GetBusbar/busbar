#!/usr/bin/env bash
# profile-lock — the RELEASE-PROFILE PARITY GATE.
#
# WHY THIS EXISTS. A ~20% throughput gap between two releases was traced mostly to a BUILD-CONFIG
# mismatch: a binary that was NOT built with the optimized release posture masqueraded as a code
# regression. Two independent guards now make that structurally impossible:
#   1. The BUILD-PROVENANCE STAMP (crates/busbar/build.rs → `busbar --build-info`) makes every binary
#      self-report profile / opt-level / debug-assertions / pgo. CI asserts a release build reports
#      the optimized values (see the build-provenance gate in ci.yml).
#   2. THIS SCRIPT locks the SOURCE OF those values: `[profile.release]` in the workspace Cargo.toml.
#      `lto` and the profile `debug-assertions` bit are NOT exposed to a build script (so build.rs
#      cannot bake them), which is exactly why they need a source-level lock. If someone weakens the
#      release profile — drops `lto = "fat"`, lowers `opt-level`, turns on `debug-assertions`, bumps
#      `codegen-units`, or removes `strip` — CI goes RED here, before any binary ships.
#
# Together: the stamp catches a binary built with the wrong profile; this catches the profile itself
# being weakened. Neither substitutes for the other.
#
# `--selftest` proves the checker still catches a weakened profile before its verdict on the tree is
# trusted (same discipline as cargo xtask gate <name> --selftest et al). No external deps; bash 3.2 + awk.
set -euo pipefail
cd "$(dirname "$0")/.."

# The REQUIRED [profile.release] settings — the optimized posture the shipped binary must be built
# with. Each is `key<TAB>expected-value`. `debug-assertions` is required ABSENT-or-false (see check).
REQUIRE_OPT_LEVEL=3
REQUIRE_LTO='"fat"'
REQUIRE_CODEGEN_UNITS=1
REQUIRE_STRIP=true

# Extract the raw body of the [profile.release] table (lines until the next top-level [section]).
# Prints nothing if the table is absent.
extract_release_profile() {
  awk '
    /^\[profile\.release\]/ { grab = 1; next }
    /^\[/ && grab { grab = 0 }
    grab { print }
  ' "$1"
}

# Read the value of `key = value` from a profile body (strips inline comments + surrounding space).
# Empty output = key absent.
profile_value() {
  local body="$1" key="$2"
  printf '%s\n' "$body" | awk -v k="$key" '
    {
      line = $0
      sub(/#.*$/, "", line)                 # strip inline comment
      if (line ~ "^[[:space:]]*" k "[[:space:]]*=") {
        sub("^[[:space:]]*" k "[[:space:]]*=[[:space:]]*", "", line)
        gsub(/[[:space:]]+$/, "", line)
        print line
        exit
      }
    }
  '
}

# The core verdict over one Cargo.toml. Returns 0 (locked) / 1 (weakened); prints every finding.
check_profile() {
  local manifest="$1" fail=0 body v
  body="$(extract_release_profile "$manifest")"
  if [ -z "$body" ]; then
    echo "  FAIL: [profile.release] table not found in $manifest"
    return 1
  fi

  v="$(profile_value "$body" opt-level)"
  if [ "$v" != "$REQUIRE_OPT_LEVEL" ]; then
    echo "  FAIL: opt-level = '${v:-<absent>}' (require $REQUIRE_OPT_LEVEL)"; fail=1
  else echo "  ok: opt-level = $v"; fi

  v="$(profile_value "$body" lto)"
  if [ "$v" != "$REQUIRE_LTO" ]; then
    echo "  FAIL: lto = '${v:-<absent>}' (require $REQUIRE_LTO — whole-program optimization)"; fail=1
  else echo "  ok: lto = $v"; fi

  v="$(profile_value "$body" codegen-units)"
  if [ "$v" != "$REQUIRE_CODEGEN_UNITS" ]; then
    echo "  FAIL: codegen-units = '${v:-<absent>}' (require $REQUIRE_CODEGEN_UNITS)"; fail=1
  else echo "  ok: codegen-units = $v"; fi

  v="$(profile_value "$body" strip)"
  if [ "$v" != "$REQUIRE_STRIP" ]; then
    echo "  FAIL: strip = '${v:-<absent>}' (require $REQUIRE_STRIP)"; fail=1
  else echo "  ok: strip = $v"; fi

  # debug-assertions must be OFF for a release build. Cargo's default for `release` is OFF, so the
  # key is normally ABSENT; the only way it is on is an explicit `debug-assertions = true`, which
  # must never ship (it changes hot-path codegen and would itself be a perf regression).
  v="$(profile_value "$body" debug-assertions)"
  if [ "$v" = "true" ]; then
    echo "  FAIL: debug-assertions = true (must be off/absent for the shipped profile)"; fail=1
  else echo "  ok: debug-assertions = ${v:-<absent, defaults off>}"; fi

  return $fail
}

# ── SELF-TEST: prove EVERY locked key still goes RED on its own, before trusting a GREEN. ─────────
# ONE weakened key per fixture, never a bundle. The bundled fixture this replaced weakened opt-level,
# lto, codegen-units AND debug-assertions at once and omitted strip entirely; check_profile reds on
# the first rule that fires, so the bundle proved nothing about the other four. Measured: replacing
# the codegen-units and strip comparisons with `if false` left that self-test PASSing, and the gate
# then reported "the release profile is the locked optimized posture" on a Cargo.toml carrying
# codegen-units = 256 and strip = false. A per-rule fixture is what makes a deleted rule visible.
selftest() {
  local tmp fails=0 got
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' RETURN

  local GOOD_OPT="opt-level = $REQUIRE_OPT_LEVEL"
  local GOOD_LTO="lto = $REQUIRE_LTO"
  local GOOD_CGU="codegen-units = $REQUIRE_CODEGEN_UNITS"
  local GOOD_STRIP="strip = $REQUIRE_STRIP"

  # expect_case <accept|reject> <label> [profile-body-line ...]
  expect_case() {
    local want="$1" label="$2"; shift 2
    { echo '[profile.release]'; [ $# -gt 0 ] && printf '%s\n' "$@"; } > "$tmp"
    if check_profile "$tmp" >/dev/null 2>&1; then got=accept; else got=reject; fi
    if [ "$got" = "$want" ]; then
      echo "  ok: $label -> $got"
    else
      echo "  SELFTEST FAILED: $label -> $got (expected $want)"
      fails=$((fails + 1))
    fi
  }

  echo "[selftest] the locked optimized posture must be ACCEPTED:"
  expect_case accept "the exact posture this repo ships" "$GOOD_OPT" "$GOOD_LTO" "$GOOD_CGU" "$GOOD_STRIP"

  echo "[selftest] every locked key must be proven to fire ON ITS OWN:"
  expect_case reject "opt-level lowered"          "opt-level = 1"     "$GOOD_LTO"   "$GOOD_CGU"          "$GOOD_STRIP"
  expect_case reject "opt-level absent"                               "$GOOD_LTO"   "$GOOD_CGU"          "$GOOD_STRIP"
  expect_case reject "lto dropped"                "$GOOD_OPT"         "lto = false" "$GOOD_CGU"          "$GOOD_STRIP"
  expect_case reject "lto absent"                 "$GOOD_OPT"                       "$GOOD_CGU"          "$GOOD_STRIP"
  expect_case reject "codegen-units raised"       "$GOOD_OPT"         "$GOOD_LTO"   "codegen-units = 16" "$GOOD_STRIP"
  expect_case reject "codegen-units absent"       "$GOOD_OPT"         "$GOOD_LTO"                        "$GOOD_STRIP"
  expect_case reject "strip removed"              "$GOOD_OPT"         "$GOOD_LTO"   "$GOOD_CGU"          "strip = false"
  expect_case reject "strip absent"               "$GOOD_OPT"         "$GOOD_LTO"   "$GOOD_CGU"
  expect_case reject "debug-assertions on"        "$GOOD_OPT"         "$GOOD_LTO"   "$GOOD_CGU"          "$GOOD_STRIP" "debug-assertions = true"

  # And the table missing entirely, which is how a bad merge deletes the whole posture at once.
  : > "$tmp"
  if check_profile "$tmp" >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: a Cargo.toml with no [profile.release] table -> accept (expected reject)"
    fails=$((fails + 1))
  else
    echo "  ok: [profile.release] absent entirely -> reject"
  fi

  if [ "$fails" -ne 0 ]; then
    echo "[selftest] FAILED: $fails case(s) did not hold. No profile-lock verdict means anything until they do." >&2
    return 1
  fi
  echo "[selftest] PASS"
}

if [ "${1:-}" = "--selftest" ]; then
  selftest
  exit $?
fi

echo "== profile-lock: [profile.release] in Cargo.toml =="
if check_profile Cargo.toml; then
  echo "profile-lock: PASS — the release profile is the locked optimized posture."
else
  echo "profile-lock: FAIL — the release profile was weakened. A non-optimized release is a perf" >&2
  echo "regression by construction; restore the locked settings or, if this is a deliberate and" >&2
  echo "reviewed change, update the REQUIRE_* values in scripts/profile-lock.sh in the same commit." >&2
  exit 1
fi
