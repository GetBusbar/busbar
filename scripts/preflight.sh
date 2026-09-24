#!/usr/bin/env bash
# Pre-release gate. Mirrors .github/workflows/ci.yml EXACTLY so a tag can never ship red CI —
# in particular the config-specific dead-code that `-D warnings` rejects only under
# `--no-default-features` or on Windows (which a single default `cargo build` on a unix box
# silently passes). Run this before every `git tag vX.Y.Z`.
#
#   scripts/preflight.sh          # the CI mirror (fast)
#   scripts/preflight.sh --full   # + an external acceptance harness, if one is configured
#
# `--full` additionally runs an acceptance harness against the release binary. The harness is an
# EXTERNAL, optional tool — point `BUSBAR_ACCEPTANCE_HARNESS` at a directory holding an executable
# `run.sh` that takes the binary path as its first argument and writes its summary JSON to the path
# named by `$BUSBAR_KAT_OUT`. That path is per-run: the verdict is read back out of the file, so a
# fixed name would let one run inherit an earlier run's green summary.
# Unset, `--full` skips that step and everything else still runs.
#
# Exit 0 only if every mirrored job is green. Windows can't fully build on a mac (cross C
# toolchain), so it is a *type-check* best-effort here.
#
# EXIT CODES. 0 = every mirrored CI job ran here and was green ("safe to tag"). 1 = a job ran and was
# red. 3 = PROVISIONAL: nothing ran red, but at least one mirrored CI job could NOT be verified on
# this machine (cargo-deny not installed, the windows target absent, or the windows check failing
# for a reason that is not a recognised rustc diagnostic) -- each is named, and the verdict is NOT
# "safe to tag". These legs used to print a warning glyph, leave fail=0, and end on "PREFLIGHT
# GREEN -- safe to tag" with the Windows job -- the one this file exists for -- unverified.
#
#   scripts/preflight.sh --selftest   # prove the verdict logic on fixtures (no cargo, no tree)
set -uo pipefail
cd "$(dirname "$0")/.." || { echo "preflight: cannot cd to the repository root" >&2; exit 1; }
export RUSTFLAGS="-D warnings"   # same as CI env
fail=0

# ── SCRATCH FILES ARE PER-RUN, NOT FIXED PATHS IN /tmp ──
# Every log here used to be a constant name under /tmp. Two runs of this gate on one box shared
# them, and the acceptance summary was worse than a log: the verdict was READ back out of a fixed
# /tmp/kat.json that nothing required this run to have written, so a harness that exited 0 without
# producing a summary left the PREVIOUS run's green file in place and the step printed a tick.
TMPD="$(mktemp -d)" || { echo "preflight: cannot create a scratch directory" >&2; exit 1; }
trap 'rm -rf "$TMPD"' EXIT
step() { echo; echo "━━━ $1"; shift; if "$@"; then echo "  ✓"; else echo "  ✗ FAILED: $*"; fail=1; fi; }

# A mirrored CI job this machine could not verify. Not a red (nothing ran red) and never a green.
UNVERIFIED=""
unverified() {   # unverified <job> <why…>
  local job="$1"; shift
  echo "  ⚠ NOT VERIFIED LOCALLY: $*"
  echo "    → the '$job' CI job must be confirmed green before tagging."
  UNVERIFIED="${UNVERIFIED:+$UNVERIFIED; }$job"
}

have() { command -v "$1" >/dev/null 2>&1; }

# ── Security job: cargo-deny (advisories · licenses · sources · bans) ──
leg_cargo_deny() {
  echo; echo "━━━ cargo-deny"
  if have cargo-deny; then
    if cargo deny check >"$TMPD/deny.log" 2>&1; then echo "  ✓"; else
      echo "  ✗ cargo-deny failed:"; grep -iE "error|warning" "$TMPD/deny.log" | head -6; fail=1
    fi
  else
    unverified "security (cargo-deny)" "cargo-deny is not installed (cargo install cargo-deny)."
  fi
}

# Classify a finished `cargo check --target x86_64-pc-windows-msvc` log: `red` for a REAL code
# error (a rustc diagnostic: `error[Ennnn]` or an unused/dead-code lint), `unverified` for anything
# else -- a cross C-toolchain gap (ring/libsqlite3 needing MSVC headers on a mac) is NOT our code,
# but neither is it a pass: the check did not complete, so it proved nothing.
classify_windows_log() {
  if grep -qiE "error\[E[0-9]|is never (used|constructed|read)" "$1"; then echo red; else echo unverified; fi
}

# ── Job 3: windows build · test (best-effort locally) ──
# Catches cfg(unix)-only items left dead on Windows (e.g. a const used only inside #[cfg(unix)]).
leg_windows() {
  echo; echo "━━━ windows check (x86_64-pc-windows-msvc)"
  if rustup target list --installed 2>/dev/null | grep -q x86_64-pc-windows-msvc; then
    if cargo check --workspace --target x86_64-pc-windows-msvc >"$TMPD/win.log" 2>&1; then
      echo "  ✓ windows type-check clean"
    elif [ "$(classify_windows_log "$TMPD/win.log")" = red ]; then
      echo "  ✗ windows has a REAL code error:"; grep -iE "error\[E[0-9]|is never (used|constructed|read)|-->" "$TMPD/win.log" | grep -v check-cfg | head -6; fail=1
    else
      unverified "windows build · test" "the windows check could not complete locally (not a recognised rustc diagnostic -- e.g. a cross C-toolchain gap building ring/sqlite)."
    fi
  else
    unverified "windows build · test" "the windows target is not installed (rustup target add x86_64-pc-windows-msvc)."
  fi
}

verdict() {
  echo
  if [ "$fail" -ne 0 ]; then echo "❌ PREFLIGHT FAILED — fix before tagging."; return 1; fi
  if [ -n "$UNVERIFIED" ]; then
    echo "⚠ PREFLIGHT PROVISIONAL — nothing ran red, but these mirrored CI jobs were NOT verified here:"
    echo "    $UNVERIFIED"
    echo "  Not safe to tag on this result alone: confirm those jobs green in CI."
    return 3
  fi
  echo "✅ PREFLIGHT GREEN — safe to tag."
  return 0
}

# ── --selftest: the verdict logic, on fixtures. No cargo, no working-tree check. ──
run_selftest() {
  local bad=0 out rc
  expect() {   # expect <label> <want-rc> <rc> <out> [<must-not-contain>]
    if [ "$3" -ne "$2" ] || { [ -n "${5:-}" ] && printf '%s' "$4" | grep -qF "$5"; }; then
      echo "  BAD — $1 (rc $3, want $2)"; printf '%s\n' "$4" | sed 's/^/      /'; bad=$((bad + 1))
    else
      echo "  ok  — $1"
    fi
  }
  echo "preflight.sh selftest"
  out="$(fail=0; UNVERIFIED=""; verdict)"; rc=$?
  expect "every job verified and green -> exit 0, safe to tag" 0 "$rc" "$out"
  out="$(fail=1; UNVERIFIED=""; verdict)"; rc=$?
  expect "a red job -> exit 1" 1 "$rc" "$out" "PREFLIGHT GREEN"
  out="$(fail=0; UNVERIFIED="windows build · test"; verdict)"; rc=$?
  expect "an unverified job -> exit 3, never GREEN" 3 "$rc" "$out" "PREFLIGHT GREEN"
  out="$(fail=0; UNVERIFIED=""; have() { return 1; }; leg_cargo_deny; verdict)"; rc=$?
  expect "cargo-deny absent -> not green" 3 "$rc" "$out" "PREFLIGHT GREEN"
  printf 'error[E0425]: cannot find value `X` in this scope\n' >"$TMPD/w-red.log"
  printf 'error: linking with `link.exe` failed: exit status: 1\nerror: could not compile `busbar` (bin "busbar")\n' >"$TMPD/w-other.log"
  [ "$(classify_windows_log "$TMPD/w-red.log")" = red ] && echo "  ok  — a rustc diagnostic on windows is red" \
    || { echo "  BAD — a rustc diagnostic on windows was not red"; bad=$((bad + 1)); }
  [ "$(classify_windows_log "$TMPD/w-other.log")" = unverified ] && echo "  ok  — any other windows failure is unverified, not a pass" \
    || { echo "  BAD — a non-diagnostic windows failure was classified as a pass"; bad=$((bad + 1)); }
  if [ "$bad" -ne 0 ]; then echo "preflight.sh selftest: RED — $bad case(s)"; return 1; fi
  echo "preflight.sh selftest: GREEN"
}
if [ "${1:-}" = "--selftest" ]; then run_selftest; exit $?; fi

echo "▶ Pre-release gate — mirroring CI (RUSTFLAGS=$RUSTFLAGS)"

# ── Working tree must be COMMITTED ──
# CI checks the committed tree, not your working copy. A local `cargo fmt` that reformats a file
# but is never committed passes this gate yet fails CI. Fail loudly if anything is uncommitted.
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
  echo "  ✗ uncommitted changes — CI tests the COMMITTED tree, so commit first (a stray"
  echo "    'cargo fmt' edit that is never committed is exactly how red CI slips through):"
  git status --short | head; fail=1
fi

# ── Job 1: fmt · structure · clippy · build · test (default features) ──
step "fmt --all --check"                 cargo fmt --all -- --check

# A SUB-GATE THAT IS NOT THERE IS A FAILURE, NOT A SKIP. These were `[ -x … ] && step …`, so
# deleting either script, renaming it, or losing its +x bit (a fresh clone through a tar that drops
# the mode bit will do it) removed the check from the gate in total silence — preflight printed
# "PREFLIGHT GREEN -- safe to tag" having never run the compile fence that CI blocks the merge on.
require_step() {   # require_step <path> <label> <cmd…>
  local path="$1" label="$2"; shift 2
  if [ -x "$path" ]; then
    step "$label" "$@"
  else
    echo; echo "━━━ $label"
    echo "  ✗ FAILED: $path is missing or not executable — this gate is part of CI and cannot be skipped"
    fail=1
  fi
}
# structure-lint has no script left to require: it is `cargo xtask gate structure-lint`, and a
# registry gate that is missing exits 2 with the registry's own "no such gate" message rather than
# vanishing the way an un-executable script did. `require_step` still guards the shell gates below.
step "structure-lint"                    cargo xtask gate structure-lint
# The config-mutation compile fence: a transaction body that reaches a store or
# awaits must NOT type-check. The script inverts the verdict, so a clean build there fails here.
require_step scripts/txn-fence.sh "txn compile fence" ./scripts/txn-fence.sh
step "clippy (default, all-targets)"     cargo clippy --workspace --all-targets --locked -- -D warnings
step "build (default)"                   cargo build --workspace --locked
step "test (default)"                    cargo test --workspace --locked

# ── Job 2: no-default-features · clippy · build · test ──
# This is the job that catches feature-gated dead code (e.g. a getter only read by an
# optional auth link, a test helper behind a feature). --all-targets so TEST code is linted too.
step "clippy (no-default, all-targets)"  cargo clippy --no-default-features --all-targets --locked -- -D warnings
step "build (no-default)"                cargo build --no-default-features --locked
step "test (no-default)"                 cargo test --no-default-features --locked

leg_cargo_deny

# ── Local artifact audit (optional, machine-local) ──
# A developer machine carries things a published tree must not: credential material, personal paths,
# editor leftovers. Point BUSBAR_LOCAL_AUDIT at an executable that audits for them and it runs here.
# Unset or missing = skipped with a note, so an ordinary clone is never blocked by a tool it has no
# reason to have.
echo; echo "━━━ local dev artifacts"
_scrub="${BUSBAR_LOCAL_AUDIT:-}"
if [ -x "$_scrub" ]; then
  if "$_scrub" . >"$TMPD/scrub.log" 2>&1; then echo "  ✓"; else
    echo "  ✗ FAILED:"; grep -vE '^==|^clean' "$TMPD/scrub.log" | head -8; fail=1
  fi
else
  echo "  ⚠ BUSBAR_LOCAL_AUDIT not set or not executable — skipped"
fi

leg_windows

# ── Optional: deeper release gate (acceptance harness) ──
if [ "${1:-}" = "--full" ]; then
  H="${BUSBAR_ACCEPTANCE_HARNESS:-}"
  if [ -n "$H" ] && [ -x "$H/run.sh" ]; then
    # NOTE: pass the binary as an ABSOLUTE path — run.sh cd's into its own dir before reading $1, so a
    # path relative to this repo root (e.g. target/release/busbar) would resolve under the harness dir
    # and the binary would never launch (a silent, always-red --full harness step).
    #
    # THE SUMMARY MUST BE WRITTEN BY THIS RUN. The verdict is read back out of a file, so the file
    # is created fresh per run, removed before the harness starts, and required to be non-empty
    # afterwards. Against a fixed /tmp/kat.json none of that held: a harness that exited 0 without
    # writing a summary — wrong output path, an early return, a suite that silently ran nothing —
    # left the PREVIOUS run's green summary sitting there and this step printed a tick over it.
    # BUSBAR_KAT_OUT names the path for a harness that honours it; the pre-delete and the non-empty
    # check make a harness that ignores it fail rather than inherit a stale verdict.
    KAT="$TMPD/kat.json"; export KAT
    step "acceptance harness" bash -c "rm -f \"\$KAT\" && cargo build --release --locked && env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u GEMINI_API_KEY -u COHERE_API_KEY BUSBAR_KAT_OUT=\"\$KAT\" $H/run.sh \"\$PWD/target/release/busbar\" >/dev/null 2>&1 && { [ -s \"\$KAT\" ] || { echo 'the harness wrote no summary to \$BUSBAR_KAT_OUT'; exit 1; }; } && python3 -c 'import json,os;d=json.load(open(os.environ[\"KAT\"]));s=d[\"summary\"];exit(0 if s[\"fail\"]==0 else 1)'"
  elif [ -n "$H" ]; then
    echo; echo "  ⚠ BUSBAR_ACCEPTANCE_HARNESS=$H has no executable run.sh — skipping."
  else
    echo; echo "  ⚠ BUSBAR_ACCEPTANCE_HARNESS is unset — skipping the acceptance harness."
  fi
fi

verdict; exit $?
