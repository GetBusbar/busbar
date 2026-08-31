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
# trusted (same discipline as scripts/structure-lint.sh et al). No external deps; bash 3.2 + awk.
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

# ── SELF-TEST: prove the checker goes RED on a weakened profile before trusting its GREEN. ─────────
selftest() {
  local tmp rc
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' RETURN

  # A deliberately-weakened profile (the exact incident shape: LTO dropped, opt lowered,
  # debug-assertions on). The checker MUST reject it.
  cat > "$tmp" <<'EOF'
[profile.release]
opt-level = 1
lto = false
codegen-units = 16
debug-assertions = true
EOF
  echo "[selftest] a weakened [profile.release] must be REJECTED:"
  if check_profile "$tmp" >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: checker ACCEPTED a weakened profile (opt-level=1, lto=false, debug-assertions=true)"
    return 1
  fi
  echo "  ok: weakened profile rejected"

  # The exact optimized posture this repo ships. The checker MUST accept it.
  cat > "$tmp" <<EOF
[profile.release]
opt-level = $REQUIRE_OPT_LEVEL
lto = $REQUIRE_LTO
codegen-units = $REQUIRE_CODEGEN_UNITS
strip = $REQUIRE_STRIP
EOF
  echo "[selftest] the optimized posture must be ACCEPTED:"
  if ! check_profile "$tmp" >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: checker REJECTED the correct optimized profile"
    return 1
  fi
  echo "  ok: optimized profile accepted"
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
