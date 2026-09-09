#!/usr/bin/env bash
# release-key-guard.sh - make a missing plugin release key fail the BUILD, not the USER.
#
# WHY THIS FILE EXISTS.
#
# `option_env!("BUSBAR_RELEASE_PUBKEY")` (crates/plugin-sign) is a COMPILE-time read that resolves
# to `None` when the variable is absent from the compiler's environment. There is no build error,
# no warning, and no runtime complaint. The binary compiles, links, passes every test, uploads,
# and is downloaded -- and the first person to learn anything is wrong is an operator installing a
# correctly-signed first-party plugin and being told the binary "embeds no busbar release key".
#
# That is not hypothetical. busbar-aarch64-unknown-linux-gnu shipped with NO embedded key in
# 1.5.1, 1.5.2 AND 1.5.3 (#52): its matrix leg built on an x86_64 runner, so
# `taiki-e/upload-rust-binary-action` cross-compiled it inside a `cross` DOCKER CONTAINER, and
# `cross` forwards only a fixed allowlist of environment variables into that container. There is no
# `Cross.toml` in this repo to extend the allowlist, so the `BUSBAR_RELEASE_PUBKEY` on the step's
# `env:` block never reached the compiler. Three releases, five builds a release, always green.
#
# #52's own fix (a native ARM runner, see .github/workflows/release.yml) repairs THAT leg. THIS
# script is what makes the CLASS of defect unrepeatable, and it matters more than the one fix,
# because it holds for a target that has not been invented yet.
#
# TWO HALVES, BOTH NEEDED:
#
#   require                     asserted BEFORE anything is compiled. The input side. It cannot see
#                               a compiler that read the variable and then dropped it.
#   assert-embedded <archive>   asserted AFTER packaging, against the SHIPPED BYTES. The output
#                               side. It is the check that would have gone red on the real 1.5.3
#                               aarch64 tarball, and it cannot run until an artifact exists.
#
# Usage:
#   scripts/release-key-guard.sh require
#   scripts/release-key-guard.sh assert-embedded busbar-<target>.tar.gz
#   scripts/release-key-guard.sh --selftest      # prove both halves discriminate, offline
#
# Reads BUSBAR_RELEASE_PUBKEY from the environment. In CI that is the org variable
# BUSBAR_RELEASE_PUBKEY (visibility: all) -- the PUBLIC half; the private half is the
# BUSBAR_SIGN_KEY secret each plugin repo signs with.
set -euo pipefail

MODE="${1:-}"

# ── THE KEY ITSELF ──────────────────────────────────────────────────────────────────────────────
# 64 hex characters, an ed25519 public key. Asserting the SHAPE and not merely non-emptiness is
# deliberate: `BUSBAR_RELEASE_PUBKEY: ${{ vars.MISSPELLED }}` expands to the empty string, and a
# truncated or whitespace-padded value would embed and then fail every verification at runtime,
# which is the same user-visible outcome as embedding nothing.
key_is_valid() {
  printf '%s' "${BUSBAR_RELEASE_PUBKEY:-}" | grep -Eq '^[0-9a-fA-F]{64}$'
}

# ── --selftest ──────────────────────────────────────────────────────────────────────────────────
#
# THIS GUARD IS RELIED ON BY TWO OTHER CHECKS AND WAS ITSELF UNEXERCISED.
#
# platform-checks' `pubkey:<target>` row runs `assert-embedded` against every published archive and
# reports the verdict as its own — deliberately, so the build-time and publish-time halves are one
# assertion and not two copies of it. release-stage.yml calls `require` before a compiler starts.
# So a guard that had quietly stopped discriminating would take BOTH of those green with it, and
# the failure it exists to catch is invisible by construction: a missing key produces a binary that
# compiles, links, tests and ships.
#
# Every case below is one where a broken guard says the comfortable thing:
#
#   * `hits` empty — a python that could not run — takes the `-eq 0` branch, so an archive nobody
#     could search must not report as searched. (`[ "" -eq 0 ]` is a bash ERROR under `set -e`,
#     which is why the code says `${hits:-0}`; the case pins the intent, not the spelling.)
#   * a key that is present but truncated, padded, or the wrong length embeds and then fails every
#     verification at runtime, which is the same user-visible outcome as embedding nothing.
#   * `assert-embedded` with no usable key would search for an empty needle, and an empty needle is
#     found in every binary — the exact shape verify-artifact.py's tarball row already refuses.
#
# Offline, seconds, no release: the archives are built here out of two byte strings.
if [ "${MODE}" = "--selftest" ]; then
  st_bad=0
  ok()   { printf '  [ok]     %s\n' "$1"; }
  nope() { printf '  [FAILED] %s\n' "$1"; st_bad=1; }
  st_tmp="$(mktemp -d "${TMPDIR:-/tmp}/relkeyguard-selftest-XXXXXX")"
  # shellcheck disable=SC2064
  trap "rm -rf '$st_tmp'" EXIT
  self="$0"
  GOOD_KEY="$(printf 'a%.0s' $(seq 1 63))b"

  echo "release-key-guard selftest"

  # `require`, both directions and every near-miss. A near-miss is the interesting half: the
  # variable being SET is not the property, the value being a real key is.
  if BUSBAR_RELEASE_PUBKEY="$GOOD_KEY" "$self" require >/dev/null 2>&1; then
    ok "require accepts a well-formed 64-hex key"
  else
    nope "require REJECTED a well-formed key — the guard would stop every release"
  fi
  for bad_label in "unset:" "empty:" "short:abc123" "long:${GOOD_KEY}ff" "padded: ${GOOD_KEY} " "nonhex:${GOOD_KEY%??}zz"; do
    label="${bad_label%%:*}"; val="${bad_label#*:}"
    if [ "$label" = "unset" ]; then
      if (unset BUSBAR_RELEASE_PUBKEY; "$self" require >/dev/null 2>&1); then
        nope "require accepted an UNSET key"
      else
        ok "require refuses an unset key"
      fi
      continue
    fi
    if BUSBAR_RELEASE_PUBKEY="$val" "$self" require >/dev/null 2>&1; then
      nope "require accepted the ${label} case ('${val}') — it would embed and then fail every verification at runtime"
    else
      ok "require refuses the ${label} case"
    fi
  done

  # `assert-embedded`, against real archives built here. The tar carries the key verbatim, exactly
  # as `option_env!`'s `&'static str` puts it in the binary's read-only data; the other does not.
  mkdir -p "$st_tmp/with" "$st_tmp/without"
  printf 'ELF-ish padding %s more padding\n' "$GOOD_KEY" > "$st_tmp/with/busbar"
  printf 'ELF-ish padding and no key at all here\n'       > "$st_tmp/without/busbar"
  (cd "$st_tmp/with"    && tar -czf "$st_tmp/with.tar.gz" busbar)
  (cd "$st_tmp/without" && tar -czf "$st_tmp/without.tar.gz" busbar)

  if BUSBAR_RELEASE_PUBKEY="$GOOD_KEY" "$self" assert-embedded "$st_tmp/with.tar.gz" >/dev/null 2>&1; then
    ok "assert-embedded passes an archive that really carries the key"
  else
    nope "assert-embedded REJECTED an archive containing the key — every release would be red"
  fi
  if BUSBAR_RELEASE_PUBKEY="$GOOD_KEY" "$self" assert-embedded "$st_tmp/without.tar.gz" >/dev/null 2>&1; then
    nope "assert-embedded PASSED a keyless archive — this is #52 walking through the check written to catch it"
  else
    ok "assert-embedded refuses a keyless archive (the 1.5.3 aarch64 shape)"
  fi
  # A key that is merely SIMILAR must not match. The search is for the exact 64 bytes.
  if BUSBAR_RELEASE_PUBKEY="${GOOD_KEY%b}c" "$self" assert-embedded "$st_tmp/with.tar.gz" >/dev/null 2>&1; then
    nope "assert-embedded matched an archive carrying a DIFFERENT key"
  else
    ok "an archive carrying a different key does not satisfy this key"
  fi
  # No usable key: the search would be for an empty needle, which every binary contains.
  if (unset BUSBAR_RELEASE_PUBKEY; "$self" assert-embedded "$st_tmp/without.tar.gz" >/dev/null 2>&1); then
    nope "assert-embedded ran with NO key to look for — an empty needle is found in every binary"
  else
    ok "assert-embedded refuses to run without a key rather than searching for nothing"
  fi
  if BUSBAR_RELEASE_PUBKEY="$GOOD_KEY" "$self" assert-embedded "$st_tmp/there-is-no-archive.tar.gz" >/dev/null 2>&1; then
    nope "assert-embedded passed on an archive that does not exist"
  else
    ok "an archive that is not there is a failure, not an empty search"
  fi
  # An unknown mode must not look like a pass: a typo'd invocation in a workflow would otherwise
  # switch the guard off silently.
  if "$self" verify-please >/dev/null 2>&1; then
    nope "an unrecognised mode exited 0 — a typo in a workflow would switch this guard off"
  else
    ok "an unrecognised mode is a usage error, not a pass"
  fi

  echo
  if [ "$st_bad" = 0 ]; then
    echo "release-key-guard selftest: both halves discriminate"
    exit 0
  fi
  echo "release-key-guard selftest: FAILED"
  exit 1
fi

case "$MODE" in
  require)
    if ! key_is_valid; then
      cat >&2 <<EOF
[release-key-guard] ##########################################################################
[release-key-guard] # REFUSING TO BUILD A RELEASE BINARY WITHOUT BUSBAR_RELEASE_PUBKEY.
[release-key-guard] #
[release-key-guard] # It must be 64 hex characters (the ed25519 PUBLIC half). Got:
[release-key-guard] #   '${BUSBAR_RELEASE_PUBKEY:-<unset>}'
[release-key-guard] #
[release-key-guard] # Without it this artifact would compile, link, pass its tests and ship, and
[release-key-guard] # every correctly-signed first-party plugin would be refused on this platform
[release-key-guard] # with "this build embeds no busbar release key". That is exactly what
[release-key-guard] # busbar-aarch64-unknown-linux-gnu did in 1.5.1, 1.5.2 and 1.5.3 (#52).
[release-key-guard] #
[release-key-guard] # In CI the value is the org variable BUSBAR_RELEASE_PUBKEY (visibility: all).
[release-key-guard] ##########################################################################
EOF
      exit 1
    fi
    echo "[release-key-guard] BUSBAR_RELEASE_PUBKEY present and well-formed (${BUSBAR_RELEASE_PUBKEY:0:12}…)"
    ;;

  assert-embedded)
    ARCHIVE="${2:?usage: release-key-guard.sh assert-embedded <archive>}"
    # The input side must already hold, or "not embedded" is ambiguous between "the build dropped
    # it" and "there was nothing to embed".
    key_is_valid || {
      echo "[release-key-guard] assert-embedded needs a well-formed BUSBAR_RELEASE_PUBKEY to look for" >&2
      exit 1
    }
    [ -f "$ARCHIVE" ] || { echo "[release-key-guard] no such archive: $ARCHIVE" >&2; exit 1; }

    # `option_env!` yields a `&'static str`, so the 64-char hex key is present in the binary's
    # read-only data VERBATIM. Grepping the shipped archive for it is therefore an exact,
    # byte-level assertion about the artifact a user downloads -- not a proxy for it. This is the
    # form the #52 defect was confirmed in: zero occurrences in the ARM tarball, present in the
    # other four. `-a` because the archive is binary; `-c` so the count goes in the log.
    #
    # Done in python rather than `tar | grep -a` because this runs on the WINDOWS leg too, where
    # `unzip` is not guaranteed and `grep -a` semantics differ. python3 is on every GitHub runner
    # (`python` under that name on Windows), and reading the members as bytes makes the search
    # unambiguous regardless of platform.
    PY=python3
    command -v python3 >/dev/null 2>&1 || PY=python
    hits="$("$PY" - "$ARCHIVE" "$BUSBAR_RELEASE_PUBKEY" <<'PYEOF'
import sys, tarfile, zipfile
archive, key = sys.argv[1], sys.argv[2].encode()
def members():
    if archive.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            for n in zf.namelist():
                yield zf.read(n)
    else:
        with tarfile.open(archive, "r:*") as tf:
            for m in tf.getmembers():
                if m.isfile():
                    f = tf.extractfile(m)
                    if f is not None:
                        yield f.read()
print(sum(blob.count(key) for blob in members()))
PYEOF
)"

    if [ "${hits:-0}" -eq 0 ]; then
      cat >&2 <<EOF
[release-key-guard] ##########################################################################
[release-key-guard] # THE SHIPPED ARTIFACT DOES NOT CONTAIN THE RELEASE PUBLIC KEY.
[release-key-guard] #   archive: $ARCHIVE
[release-key-guard] #
[release-key-guard] # BUSBAR_RELEASE_PUBKEY was set correctly for this job, so the build read it
[release-key-guard] # and DROPPED it -- the signature of a compiler that ran in an environment the
[release-key-guard] # variable did not reach (a \`cross\` container, a sandboxed builder, a second
[release-key-guard] # build step with its own \`env:\` block). Shipping this would refuse every
[release-key-guard] # correctly-signed first-party plugin on this platform. Refusing.
[release-key-guard] ##########################################################################
EOF
      exit 1
    fi
    echo "[release-key-guard] $ARCHIVE embeds the release public key ($hits occurrence(s))"
    ;;

  *)
    echo "usage: release-key-guard.sh require | assert-embedded <archive>" >&2
    exit 2
    ;;
esac
