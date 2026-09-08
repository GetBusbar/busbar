#!/usr/bin/env bash
# build-provenance-gate — assert a built busbar binary self-reports the EXPECTED optimization posture.
#
# WHY. The ~20% "regression" incident was a build-config mismatch that no test could see because no
# binary said out loud how it was built. crates/busbar/build.rs now bakes the posture into the binary
# and `busbar --build-info` prints it as one stable line:
#   profile=release opt-level=3 lto=... debug-assertions=false pgo=false target=... target-cpu=...
# This gate parses that line and asserts the fields that a shipped/optimized binary MUST have, so a
# release build that is secretly debug/non-PGO fails CI instead of shipping and being misdiagnosed.
#
# USAGE:
#   build-provenance-gate.sh <binary> <expect-profile> <expect-pgo>   # run the binary, assert
#   build-provenance-gate.sh --selftest
# <expect-profile> is release|debug; <expect-pgo> is true|false. For a release build the gate also
# pins opt-level=3, debug-assertions=false and the LTO posture (the optimized invariants); a debug
# build only pins the profile/pgo it was told to expect.
#
# THREE HOLES THIS GATE USED TO HAVE, AND WHY THE SHAPE BELOW IS WHAT IT IS.
#
#  1. THE STAMP WAS NOT EVIDENCE ABOUT THE BINARY. There was a `--line "<stamp>"` mode that asserted
#     a string handed in on the command line. Anything can write that string; a workflow step that
#     produced the line by any means other than running the binary would pass this gate green while
#     proving nothing about any bytes. `--line` IS GONE. The only way to get a verdict is to hand
#     the gate an executable, which it runs. (The one real caller, docker.yml, was already running
#     the binary into a temp file and then passing the file's contents back in — it now passes the
#     binary, which is what it always meant.) The literal-line assertion still exists, but only as
#     an INTERNAL helper the self-test drives over planted stamps.
#
#  2. `pgo=true` WAS SATISFIABLE BY AN ENV VAR. crates/busbar/build.rs used to stamp `pgo=true` from
#     EITHER `-Cprofile-use` in CARGO_ENCODED_RUSTFLAGS or a bare `BUSBAR_PGO=1`, so
#     `BUSBAR_PGO=1 cargo build --release` produced a binary that swore it was PGO-optimized and
#     satisfied every `... release true` assertion in the tree. The env arm is deleted; this gate's
#     self-test now READS crates/busbar/build.rs and refuses a source that consults an env var for
#     the pgo bit, so the hole cannot be reopened quietly.
#
#  3. `lto` WAS PRINTED AND NEVER ASSERTED. The stamp carried an lto field that no branch below ever
#     compared to anything. It is asserted now. Cargo exposes no lto value to a build script, so a
#     profile-governed build stamps the sentinel `(profile-table)`; on that value the gate resolves
#     `[profile.release] lto` out of the workspace Cargo.toml and requires the optimized posture.
#     An explicit `-Clto=<x>` flag stamps its own value and is asserted directly. Either way a
#     release binary whose LTO posture is not `fat` is now RED instead of silently narrated.
#
# `--selftest` proves every assertion goes RED on a mis-built stamp before its GREEN is trusted.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_RS="$ROOT/crates/busbar/build.rs"
WORKSPACE_MANIFEST="$ROOT/Cargo.toml"

# The LTO posture a release binary must have. `fat` is what [profile.release] pins and what
# scripts/profile-lock.sh locks; anything else is a weakened optimized build.
RELEASE_LTO="fat"

field() { printf '%s\n' "$1" | tr ' ' '\n' | awk -F= -v k="$2" '$1==k{print $2; exit}'; }

# Resolve `[profile.release] lto = "<x>"` out of a workspace manifest. Prints the value, or nothing
# if the table or the key is absent (which is itself a failure at the call site: an unresolvable
# profile-table sentinel is an unasserted lto, the exact hole this closes).
profile_table_lto() { # profile_table_lto <manifest>
  awk '
    /^\[/ { in_rel = ($0 ~ /^\[profile\.release\][[:space:]]*$/) }
    in_rel && /^[[:space:]]*lto[[:space:]]*=/ {
      line = $0
      sub(/^[^=]*=[[:space:]]*/, "", line)
      sub(/[[:space:]]*#.*$/, "", line)
      gsub(/["\x27[:space:]]/, "", line)
      print line; exit
    }
  ' "$1" 2>/dev/null
}

# THE PGO-PROVENANCE SOURCE RULE (hole 2). The pgo bit must be derived from cargo's account of the
# flags it passed (CARGO_ENCODED_RUSTFLAGS / -Cprofile-use), never from an env var the builder sets.
# Returns 0 when the build script is clean, 1 (with findings) when it consults an env PGO signal.
assert_pgo_provenance() { # assert_pgo_provenance <build.rs path>
  local src="$1"
  if [ ! -f "$src" ]; then
    echo "  FAIL: no build script at $src — the provenance stamp has no source to check"; return 1
  fi
  # Any read of a *_PGO env var, in any of the shapes a build script can spell it.
  if grep -Eq '(env::var|env!|option_env!|var_os)[^)]*[A-Z_]*PGO' "$src"; then
    echo "  FAIL: $src derives the pgo bit from an environment variable."
    echo "        An env var is the builder's account of what it meant to do; only"
    echo "        CARGO_ENCODED_RUSTFLAGS (-Cprofile-use) is evidence about the bytes."
    grep -nE '(env::var|env!|option_env!|var_os)[^)]*[A-Z_]*PGO' "$src" | sed 's/^/        /'
    return 1
  fi
  if ! grep -q 'profile-use' "$src"; then
    echo "  FAIL: $src never looks for -Cprofile-use — the pgo bit is not derived from the"
    echo "        flags cargo actually applied, so 'pgo=true' asserts nothing."
    return 1
  fi
  echo "  ok: $src derives pgo from -Cprofile-use in the applied rustflags, not from the environment"
  return 0
}

# Assert one stamp LINE against (expect_profile, expect_pgo). Prints findings; returns 0/1.
# INTERNAL: reachable from the CLI only through a real binary's --build-info, or from the self-test
# over a planted stamp. A caller-supplied literal is not evidence (see hole 1 in the header).
# The optional 4th argument is the manifest the `(profile-table)` lto sentinel resolves against;
# the self-test passes planted manifests to prove the resolution goes RED.
assert_line() {
  local line="$1" expect_profile="$2" expect_pgo="$3" manifest="${4:-$WORKSPACE_MANIFEST}" fail=0
  local profile opt da pgo lto
  profile="$(field "$line" profile)"
  opt="$(field "$line" opt-level)"
  da="$(field "$line" debug-assertions)"
  pgo="$(field "$line" pgo)"
  lto="$(field "$line" lto)"

  echo "  stamp: $line"

  if [ "$profile" != "$expect_profile" ]; then
    echo "  FAIL: profile = '${profile:-<absent>}' (expect $expect_profile)"; fail=1
  else echo "  ok: profile = $profile"; fi

  if [ "$pgo" != "$expect_pgo" ]; then
    echo "  FAIL: pgo = '${pgo:-<absent>}' (expect $expect_pgo)"; fail=1
  else echo "  ok: pgo = $pgo"; fi

  # Optimized invariants apply only to a release build.
  if [ "$expect_profile" = "release" ]; then
    if [ "$opt" != "3" ]; then
      echo "  FAIL: opt-level = '${opt:-<absent>}' (release must be 3)"; fail=1
    else echo "  ok: opt-level = $opt"; fi
    if [ "$da" != "false" ]; then
      echo "  FAIL: debug-assertions = '${da:-<absent>}' (release must be false)"; fail=1
    else echo "  ok: debug-assertions = $da"; fi

    # LTO (hole 3): the stamp printed this field and nothing ever compared it. Two shapes.
    case "$lto" in
      "")
        echo "  FAIL: lto = <absent> (the stamp must carry an lto field for a release build)"; fail=1
        ;;
      '(profile-table)')
        # Cargo exposes no lto value to a build script, so a profile-governed build stamps this
        # sentinel. Resolve the real value from the workspace manifest and assert THAT — a sentinel
        # accepted on its own is the unasserted field all over again.
        local table_lto
        table_lto="$(profile_table_lto "$manifest")"
        if [ -z "$table_lto" ]; then
          echo "  FAIL: lto = (profile-table) but [profile.release] lto is not set in $manifest,"
          echo "        so the sentinel resolves to nothing and the field asserts nothing."; fail=1
        elif [ "$table_lto" != "$RELEASE_LTO" ]; then
          echo "  FAIL: lto = (profile-table) -> [profile.release] lto = '$table_lto' (release must be $RELEASE_LTO)"; fail=1
        else
          echo "  ok: lto = (profile-table) -> [profile.release] lto = $table_lto"
        fi
        ;;
      *)
        # An explicit -Clto=<x> reached the compiler; the stamp carries its own value.
        if [ "$lto" != "$RELEASE_LTO" ]; then
          echo "  FAIL: lto = '$lto' (release must be $RELEASE_LTO)"; fail=1
        else echo "  ok: lto = $lto"; fi
        ;;
    esac
  fi

  return $fail
}

selftest() {
  echo "[selftest] a debug stamp claiming to be a release build must be REJECTED:"
  if assert_line "profile=debug opt-level=0 lto=(profile-table) debug-assertions=true pgo=false target=x target-cpu=default" release false >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: accepted a debug stamp as release"; return 1
  fi
  echo "  ok: rejected"

  echo "[selftest] a release stamp with debug-assertions=true must be REJECTED:"
  if assert_line "profile=release opt-level=3 lto=fat debug-assertions=true pgo=false target=x target-cpu=default" release false >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: accepted debug-assertions=true in a release build"; return 1
  fi
  echo "  ok: rejected"

  echo "[selftest] a release stamp with pgo=false must be REJECTED when pgo=true is required:"
  if assert_line "profile=release opt-level=3 lto=fat debug-assertions=false pgo=false target=x target-cpu=default" release true >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: accepted pgo=false when pgo=true required"; return 1
  fi
  echo "  ok: rejected"

  # ── HOLE 3: the lto field was printed and never asserted ──────────────────────────────────────
  echo "[selftest] a release stamp with an explicit weakened lto (thin) must be REJECTED:"
  if assert_line "profile=release opt-level=3 lto=thin debug-assertions=false pgo=false target=x target-cpu=default" release false >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: accepted lto=thin in a release build"; return 1
  fi
  echo "  ok: rejected"

  echo "[selftest] a release stamp with lto=off must be REJECTED:"
  if assert_line "profile=release opt-level=3 lto=off debug-assertions=false pgo=false target=x target-cpu=default" release false >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: accepted lto=off in a release build"; return 1
  fi
  echo "  ok: rejected"

  echo "[selftest] a release stamp with NO lto field must be REJECTED:"
  if assert_line "profile=release opt-level=3 debug-assertions=false pgo=false target=x target-cpu=default" release false >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: accepted a release stamp carrying no lto field"; return 1
  fi
  echo "  ok: rejected"

  # The `(profile-table)` sentinel must RESOLVE, not be waved through. Two planted manifests prove
  # both failure arms: a weakened table value, and a table with no lto key at all.
  local st_work weak_manifest silent_manifest fat_manifest
  st_work="$(mktemp -d)"
  weak_manifest="$st_work/weak.toml"
  silent_manifest="$st_work/silent.toml"
  fat_manifest="$st_work/fat.toml"
  printf '[profile.release]\nopt-level = 3\nlto = "thin"\n' > "$weak_manifest"
  printf '[profile.release]\nopt-level = 3\n' > "$silent_manifest"
  printf '[profile.release]\nopt-level = 3\nlto = "fat"   # comment\n' > "$fat_manifest"

  echo "[selftest] lto=(profile-table) resolving to a WEAKENED table value must be REJECTED:"
  if assert_line "profile=release opt-level=3 lto=(profile-table) debug-assertions=false pgo=false target=x target-cpu=default" release false "$weak_manifest" >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: accepted (profile-table) resolving to lto=thin"; rm -rf "$st_work"; return 1
  fi
  echo "  ok: rejected"

  echo "[selftest] lto=(profile-table) resolving to NOTHING must be REJECTED:"
  if assert_line "profile=release opt-level=3 lto=(profile-table) debug-assertions=false pgo=false target=x target-cpu=default" release false "$silent_manifest" >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: accepted (profile-table) against a manifest that pins no lto"; rm -rf "$st_work"; return 1
  fi
  echo "  ok: rejected"

  echo "[selftest] lto=(profile-table) resolving to fat must be ACCEPTED:"
  if ! assert_line "profile=release opt-level=3 lto=(profile-table) debug-assertions=false pgo=false target=x target-cpu=default" release false "$fat_manifest" >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: rejected (profile-table) resolving to lto=fat"; rm -rf "$st_work"; return 1
  fi
  echo "  ok: accepted"

  # ── HOLE 2: pgo=true was satisfiable by an env var alone ──────────────────────────────────────
  local planted_env planted_blind
  planted_env="$st_work/build-env.rs"
  planted_blind="$st_work/build-blind.rs"
  cat > "$planted_env" <<'PLANT'
fn main() {
    let pgo_env = std::env::var("BUSBAR_PGO").map(|v| v == "1").unwrap_or(false);
    let pgo_flag = flags.iter().any(|f| f.contains("profile-use"));
    println!("cargo:rustc-env=BUSBAR_BUILD_PGO={}", pgo_env || pgo_flag);
}
PLANT
  printf 'fn main() { println!("cargo:rustc-env=BUSBAR_BUILD_PGO=true"); }\n' > "$planted_blind"

  echo "[selftest] a build script that reads a *_PGO env var must be REJECTED:"
  if assert_pgo_provenance "$planted_env" >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: accepted a build script whose pgo bit an env var can set"; rm -rf "$st_work"; return 1
  fi
  echo "  ok: rejected"

  echo "[selftest] a build script that never looks at -Cprofile-use must be REJECTED:"
  if assert_pgo_provenance "$planted_blind" >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: accepted a build script that stamps pgo from nothing"; rm -rf "$st_work"; return 1
  fi
  echo "  ok: rejected"

  echo "[selftest] a missing build script must be REJECTED:"
  if assert_pgo_provenance "$st_work/does-not-exist.rs" >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: accepted an absent build script"; rm -rf "$st_work"; return 1
  fi
  echo "  ok: rejected"

  echo "[selftest] THIS TREE's crates/busbar/build.rs must be ACCEPTED (pgo from the rustflags):"
  if ! assert_pgo_provenance "$BUILD_RS"; then
    echo "  SELFTEST FAILED: $BUILD_RS does not derive pgo from the applied rustflags alone"; rm -rf "$st_work"; return 1
  fi

  rm -rf "$st_work"

  # ── HOLE 1: --line accepted a hand-written stamp as a verdict ─────────────────────────────────
  echo "[selftest] the removed --line mode must NOT be accepted as a CLI verdict:"
  if "$0" --line "profile=release opt-level=3 lto=fat debug-assertions=false pgo=true target=x target-cpu=default" release true >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: --line still turns a hand-written stamp into a PASS"; return 1
  fi
  echo "  ok: rejected"

  echo "[selftest] a non-executable subject must NOT be accepted as a CLI verdict:"
  if "$0" "$BUILD_RS" release false >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: accepted a subject that is not an executable"; return 1
  fi
  echo "  ok: rejected"

  # ── the GREEN side ───────────────────────────────────────────────────────────────────────────
  echo "[selftest] a correct optimized release stamp (pgo=false, dev CI) must be ACCEPTED:"
  if ! assert_line "profile=release opt-level=3 lto=(profile-table) debug-assertions=false pgo=false target=x target-cpu=default" release false >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: rejected a correct release stamp"; return 1
  fi
  echo "  ok: accepted"

  echo "[selftest] a correct PGO release stamp (pgo=true, release job) must be ACCEPTED:"
  if ! assert_line "profile=release opt-level=3 lto=fat debug-assertions=false pgo=true target=x target-cpu=default" release true >/dev/null 2>&1; then
    echo "  SELFTEST FAILED: rejected a correct PGO release stamp"; return 1
  fi
  echo "  ok: accepted"

  echo "[selftest] PASS"
}

if [ "${1:-}" = "--selftest" ]; then
  selftest; exit $?
fi

usage() {
  echo "usage: build-provenance-gate.sh <binary> <expect-profile> <expect-pgo>" >&2
  echo "       build-provenance-gate.sh --selftest" >&2
  echo "NOTE: the old --line <stamp> mode was REMOVED. A stamp handed in on the command line is" >&2
  echo "      not evidence about any binary; hand this gate the executable and it will run it." >&2
}

case "${1:-}" in
  --line)   echo "build-provenance-gate: --line was removed (a hand-written stamp is not evidence)." >&2; usage; exit 2 ;;
  ""|--help|-h) usage; exit 2 ;;
esac
[ "$#" -eq 3 ] || { usage; exit 2; }

BIN="$1"; EXPECT_PROFILE="$2"; EXPECT_PGO="$3"
[ -x "$BIN" ] || { echo "build-provenance-gate: '$BIN' is not an executable" >&2; exit 2; }
LINE="$("$BIN" --build-info)"

# The pgo bit is only worth asserting if its SOURCE cannot be set by the builder's environment.
if ! assert_pgo_provenance "$BUILD_RS"; then
  echo "build-provenance-gate: FAIL — the pgo field of the stamp is not derived from build evidence." >&2
  exit 1
fi

echo "== build-provenance-gate: expect profile=$EXPECT_PROFILE pgo=$EXPECT_PGO =="
if assert_line "$LINE" "$EXPECT_PROFILE" "$EXPECT_PGO"; then
  echo "build-provenance-gate: PASS"
else
  echo "build-provenance-gate: FAIL — the binary was NOT built with the expected optimized posture." >&2
  echo "A mis-built binary is exactly the ~20% 'regression' this stamp exists to prevent shipping." >&2
  exit 1
fi
