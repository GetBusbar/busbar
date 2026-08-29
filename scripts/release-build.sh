#!/usr/bin/env bash
# release-build.sh - THE build. One script, every target, no second path.
#
# WHY THIS FILE EXISTS.
#
# Through 1.5.3 the release matrix had TWO build steps. Host-native targets went through
# scripts/pgo-build.sh; cross targets went through upload-rust-binary-action. Both carried
# `BUSBAR_RELEASE_PUBKEY` in their own `env:` block, both were green, and
# busbar-aarch64-unknown-linux-gnu shipped with no embedded key in 1.5.1, 1.5.2 and 1.5.3 -- so on
# ARM Linux every correctly-signed first-party plugin was refused. Two build steps means two places
# a property has to be right, and a property established on one path is UNPROVEN on the other,
# silently and permanently.
#
# Owner, 2026-08-08: "should just be 1 build pipeline that takes what its building: arm, windows,
# mac, but it does the same thing for each no way for 1 to be different".
#
# So there is one build step in .github/workflows/build-artifact.yml and it runs this script. Every
# target's difference is a FIELD in .github/release-targets.json read below -- never a different
# step, never an `if:`, never a second action. The env block that carries the release public key is
# written once and applies to all five targets because there is only one step for it to be on.
#
# FAIL-CLOSED ON THE KEY, FOR EVERY TARGET, IN ONE PLACE. The check below is the build-time half of
# the fix; scripts/verify-artifact.py's `release_pubkey` and `first_party_plugin` rows are the
# output-side half that proves it actually landed in the bytes. Both are needed: this one cannot
# see a compiler that read the variable and dropped it, and that one cannot run until an artifact
# exists.
#
# Usage:
#   scripts/release-build.sh <target-triple> [--out-dir DIR] [--evidence-dir DIR]
#
# Produces, under --out-dir (default: the repo root):
#   busbar-<target>.<archive>        the release asset, exactly as users download it
# and under --evidence-dir (default: ./build-evidence):
#   artifact.sha256                  the SHA-256 of that archive, which verify-artifact.py binds to
#                                    the bytes it downloads from the release
#   busbar.pgo-verified              pgo-build.sh's proof marker, for targets that declare pgo
#
# Requires: cargo, python3 (archiving and manifest reading; present on every GitHub runner), and
# for pgo targets everything scripts/pgo-build.sh requires.
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET="${1:?usage: release-build.sh <target-triple> [--out-dir DIR] [--evidence-dir DIR]}"
shift
OUT_DIR="$(pwd)"
EVIDENCE_DIR="$(pwd)/build-evidence"
while [ $# -gt 0 ]; do
  case "$1" in
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --evidence-dir) EVIDENCE_DIR="$2"; shift 2 ;;
    *) echo "release-build.sh: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

# `python3` is the name on Linux and macOS runners; Windows runners expose `python`. Resolving it
# once here is the only concession this script makes to the platform it runs on, and it is a name
# lookup rather than a behaviour difference.
PY=python3
command -v python3 >/dev/null 2>&1 || PY=python
command -v "$PY" >/dev/null 2>&1 || { echo "release-build.sh: no python interpreter on PATH" >&2; exit 1; }

MANIFEST=.github/release-targets.json
# Every per-target difference arrives here, as data, from the one file that declares the platforms.
# A target that is not in the manifest cannot be built: an artifact nothing declares is an artifact
# nothing verifies.
eval "$("$PY" - "$TARGET" <<'PY'
import json, shlex, sys
spec = json.load(open(".github/release-targets.json"))
want = sys.argv[1]
for t in spec["targets"]:
    if t["target"] == want:
        for k in ("pgo", "archive", "exe"):
            print("SPEC_%s=%s" % (k.upper(), shlex.quote(str(t[k]).lower() if k == "pgo" else str(t[k]))))
        break
else:
    sys.exit("release-build.sh: target %r is not declared in .github/release-targets.json. Add it "
             "there -- that file is what the build matrix, the verify matrix and the asset list are "
             "all derived from, so a target added anywhere else is built and never verified." % want)
PY
)"

ARCHIVE="busbar-${TARGET}.${SPEC_ARCHIVE}"

# ── THE KEY, ASSERTED BEFORE ANYTHING IS COMPILED, FOR EVERY TARGET ─────────────────────────────
# `option_env!("BUSBAR_RELEASE_PUBKEY")` (crates/plugin-sign) is a COMPILE-time read that resolves
# to `None` when the variable is absent. There is no build error, no warning, and no runtime
# complaint until an operator installs a signed plugin and is told the binary "embeds no busbar
# release key". Refusing to start the build is the only moment at which that is loud.
if ! printf '%s' "${BUSBAR_RELEASE_PUBKEY:-}" | grep -Eq '^[0-9a-fA-F]{64}$'; then
  cat >&2 <<EOF
[release-build] ############################################################
[release-build] # REFUSING TO BUILD $TARGET WITHOUT BUSBAR_RELEASE_PUBKEY.
[release-build] #
[release-build] # It must be 64 hex characters (the ed25519 PUBLIC half; the private half is the
[release-build] # BUSBAR_SIGN_KEY secret each plugin repo signs with). Got: '${BUSBAR_RELEASE_PUBKEY:-<unset>}'
[release-build] #
[release-build] # Without it this artifact would compile, link, pass its tests and ship, and every
[release-build] # correctly-signed first-party plugin would be refused on this platform with
[release-build] # "this build embeds no busbar release key". That is exactly what
[release-build] # busbar-aarch64-unknown-linux-gnu did in 1.5.1, 1.5.2 and 1.5.3.
[release-build] #
[release-build] # In CI the value is the org variable BUSBAR_RELEASE_PUBKEY (visibility: all).
[release-build] ############################################################
EOF
  exit 1
fi
echo "[release-build] target=$TARGET pgo=$SPEC_PGO archive=$SPEC_ARCHIVE key=${BUSBAR_RELEASE_PUBKEY:0:12}…"

mkdir -p "$EVIDENCE_DIR" "$OUT_DIR"
rm -f "$EVIDENCE_DIR/artifact.sha256" "$EVIDENCE_DIR/busbar.pgo-verified"

# ── THE BUILD ───────────────────────────────────────────────────────────────────────────────────
# `pgo` is a PARAMETER to this one step, not a second code path: both arms produce the same binary
# at a path this script then packages identically, and both inherit the same environment, the same
# key assertion above and the same evidence below. Every target now runs on a NATIVE runner, so the
# reason the cross targets could not train a profile is gone; the one target that still declares
# pgo:false says why, in .github/release-targets.json, next to the flag.
if [ "$SPEC_PGO" = "true" ]; then
  PGO_TARGET="$TARGET" scripts/pgo-build.sh
  BIN="target/pgo/${TARGET}/release/${SPEC_EXE}"
  MARKER="target/pgo/${TARGET}/release/busbar.pgo-verified"
  # pgo-build.sh writes the marker ONLY after a non-empty merged profile fed a successful
  # -Cprofile-use build, so a missing marker after a zero exit is a script contract violation, not
  # a build variation. verify-artifact.py's `pgo_applied` row re-asserts its contents against the
  # shipped digest; this copy is what carries it there.
  [ -s "$MARKER" ] || { echo "[release-build] pgo-build.sh exited 0 without writing $MARKER" >&2; exit 1; }
  cp "$MARKER" "$EVIDENCE_DIR/busbar.pgo-verified"
else
  # Flags kept byte-identical to the ones pgo-build.sh's optimised phase passes, minus the profile:
  # the two arms must differ in PGO and in nothing else, or "same build" is a claim rather than a
  # fact. (No `--locked`: pgo-build.sh does not pass it either, and the lockfile freshness gate is
  # `gate`'s job, upstream of this one.)
  #
  # That parity includes the BOLT prerequisite: Linux targets link with --emit-relocs, same case
  # and same flag as pgo-build.sh (see the comment at its EMIT_RELOCS definition — llvm-bolt on
  # aarch64 emits a segfaulting binary when the input carries no relocations; harmless on x86_64;
  # not a flag ld64/link.exe know, hence the Linux gate). Today's only non-PGO target is Windows,
  # so this case is empty in practice — it exists so a Linux target that ever declares pgo:false
  # cannot silently lose the relocations the BOLT pass refuses to run without.
  EMIT_RELOCS=""
  case "$TARGET" in
    *-linux-*) EMIT_RELOCS="-Clink-arg=-Wl,--emit-relocs" ;;
  esac
  RUSTFLAGS="${EMIT_RELOCS}" cargo build --release -p busbar --target "$TARGET"
  BIN="target/${TARGET}/release/${SPEC_EXE}"
fi
[ -f "$BIN" ] || { echo "[release-build] the build produced no binary at $BIN" >&2; exit 1; }

# ── PACKAGE ─────────────────────────────────────────────────────────────────────────────────────
# One archiver, parameterised by the declared extension, rather than tar here and a zip action
# there. The archive contains exactly one member under exactly the declared name, which is what
# verify-artifact.py's `archive_shape` row asserts and what the documented
# `tar -xzf busbar-<target>.tar.gz && ./busbar` depends on.
"$PY" - "$BIN" "$OUT_DIR/$ARCHIVE" "$SPEC_EXE" "$SPEC_ARCHIVE" "$EVIDENCE_DIR/artifact.sha256" <<'PY'
import hashlib, os, sys, tarfile, zipfile
src, out, member, kind, digest_out = sys.argv[1:6]
if os.path.exists(out):
    os.remove(out)
if kind == "zip":
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(src, arcname=member)
else:
    with tarfile.open(out, "w:gz") as tf:
        info = tf.gettarinfo(src, arcname=member)
        # Normalise ownership and mode so the archive is a function of the bytes, not of whichever
        # runner account happened to build it -- and so the extracted binary is executable for the
        # user who downloads it, which the documented quickstart depends on.
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mode = 0o755
        with open(src, "rb") as fh:
            tf.addfile(info, fh)
h = hashlib.sha256()
with open(out, "rb") as fh:
    for chunk in iter(lambda: fh.read(1 << 20), b""):
        h.update(chunk)
open(digest_out, "w").write(h.hexdigest() + "  " + os.path.basename(out) + "\n")
print("[release-build] %s (%d bytes) sha256=%s" % (out, os.path.getsize(out), h.hexdigest()))
PY

echo "[release-build] evidence in $EVIDENCE_DIR:"
ls -l "$EVIDENCE_DIR"
echo "$OUT_DIR/$ARCHIVE"
