#!/usr/bin/env bash
# plugin-publish.sh - the publish step of a first-party plugin release (SECURITY-FIRST-PLAN C1/C12-a).
#
# A release's build emits UNSIGNED tarballs (`busbar-plugin-pack pack --allow-unsigned`), each with
# its manifest's canonical bytes (`busbar-plugin-pack canonical`). The owner signs those bytes
# offline on the hardware key (scripts/plugin-sign-offline.sh), which yields a signatures file:
#
#   <asset>\t<sha256 of the canonical bytes>\t<128-hex ed25519 signature>
#
# This step inserts each signature and REFUSES the whole release unless every one of these holds:
#   * every unsigned tarball has exactly one row, and every row names a tarball;
#   * the row's canonical sha256 is the tarball's (the owner signed THESE bytes, not others);
#   * `busbar-plugin-pack attach` verifies the signature against a first-party key in the list the
#     packer was built with (BUSBAR_RELEASE_PUBKEY, the list the 1.6.0 engine embeds), and the
#     signed tarball passes busbar's structural validation.
# Only then are the signed tarballs and their SHA256SUMS written to <out-dir>; publishing them is the
# caller's next step. Nothing is written on a refusal.
#
# Usage:
#   scripts/plugin-publish.sh <unsigned-dir> <signatures.tsv> <out-dir>
# PACK (default target/release/busbar-plugin-pack) is the packer built from this tree.
set -euo pipefail

usage="usage: plugin-publish.sh <unsigned-dir> <signatures.tsv> <out-dir>"
IN_DIR="${1:?$usage}"; SIGS="${2:?$usage}"; OUT_DIR="${3:?$usage}"
PACK="${PACK:-target/release/busbar-plugin-pack}"

sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
die() { echo "plugin-publish: REFUSED: $*" >&2; exit 1; }

[ -x "$PACK" ] || die "no packer at $PACK (cargo build --release -p busbar-plugin-loader --features pack --bin busbar-plugin-pack)"
[ -d "$IN_DIR" ] || die "no such directory: $IN_DIR"
[ -f "$SIGS" ] || die "no signatures file: $SIGS"
if [ -e "$OUT_DIR" ] && [ -n "$(ls -A "$OUT_DIR")" ]; then die "$OUT_DIR is not empty"; fi

# Every row well-formed, and no asset named twice.
awk -F'\t' 'NF != 3 || $2 !~ /^[0-9a-f]{64}$/ || $3 !~ /^[0-9a-f]{128}$/ { print "line " NR ": not <asset>\\t<sha256>\\t<signature>"; bad = 1 }
            seen[$1]++ { print "line " NR ": " $1 " is named twice"; bad = 1 }
            END { exit bad }' "$SIGS" >&2 || die "the signatures file is malformed"

stage="$(mktemp -d "${TMPDIR:-/tmp}/plugin-publish-XXXXXX")"
trap 'rm -rf "$stage"' EXIT
shopt -s nullglob
n=0
for tgz in "$IN_DIR"/*.tar.gz; do
  asset="$(basename "$tgz")"
  row="$(awk -F'\t' -v a="$asset" '$1 == a' "$SIGS")"
  [ -n "$row" ] || die "$asset has no signature row"
  want_sha="$(printf '%s' "$row" | cut -f2)"; sig="$(printf '%s' "$row" | cut -f3)"
  "$PACK" canonical "$tgz" >"$stage/$asset.canonical" || die "$asset: cannot read its manifest"
  got_sha="$(sha256 "$stage/$asset.canonical")"
  [ "$got_sha" = "$want_sha" ] || die "$asset: the owner signed canonical bytes $want_sha, this tarball's are $got_sha"
  "$PACK" attach --in "$tgz" --signature "$sig" --out "$stage/$asset" || die "$asset: the signature does not attach"
  "$PACK" verify "$stage/$asset" >/dev/null || die "$asset: the signed tarball does not verify"
  n=$((n + 1))
done
[ "$n" -gt 0 ] || die "no unsigned tarballs in $IN_DIR"
rows="$(grep -c . "$SIGS")"
[ "$rows" = "$n" ] || die "the signatures file has $rows row(s) for $n tarball(s): a row names no tarball"

mkdir -p "$OUT_DIR"
for f in "$stage"/*.tar.gz; do
  mv "$f" "$OUT_DIR/"
  printf '%s  %s\n' "$(sha256 "$OUT_DIR/$(basename "$f")")" "$(basename "$f")" >>"$OUT_DIR/SHA256SUMS"
done
echo "plugin-publish: $n first-party tarball(s) signed and verified -> $OUT_DIR"
