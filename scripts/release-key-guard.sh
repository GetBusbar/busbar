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
