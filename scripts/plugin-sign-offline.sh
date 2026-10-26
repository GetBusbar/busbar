#!/usr/bin/env bash
# plugin-sign-offline.sh - the OWNER's half of a first-party plugin release (PLUGIN-KEY-CEREMONY.md).
#
# Signs every `<asset>.canonical` file a release emitted (the manifest's canonical bytes, printed by
# `busbar-plugin-pack canonical`) with the hardware-held first-party key, checks each signature
# against that key's public half, and writes the signatures file the publish step
# (scripts/plugin-publish.sh) consumes:
#
#   <asset>\t<sha256 of the canonical bytes>\t<128-hex ed25519 signature>
#
# Nothing here reaches a network, and no private key leaves the token.
#
# Usage:
#   scripts/plugin-sign-offline.sh <canonical-dir> <public-key.pem> <signatures.tsv>
#
# The signer is one command run per file with $IN (the canonical bytes) and $OUT (where it writes
# the RAW 64-byte signature). The default drives a YubiKey PIV Ed25519 key in slot 9c through
# yubico-piv-tool; override it with PLUGIN_SIGN_CMD (the ceremony's dry run proves whichever is
# used). Every signature is verified with OpenSSL against <public-key.pem> before it is written,
# so a signer that produced anything else is caught here, not at publish.
set -euo pipefail

CANON_DIR="${1:?usage: plugin-sign-offline.sh <canonical-dir> <public-key.pem> <signatures.tsv>}"
PUB="${2:?usage: plugin-sign-offline.sh <canonical-dir> <public-key.pem> <signatures.tsv>}"
OUT_TSV="${3:?usage: plugin-sign-offline.sh <canonical-dir> <public-key.pem> <signatures.tsv>}"
: "${PLUGIN_SIGN_CMD:=yubico-piv-tool -a verify-pin -a sign -s 9c -A ED25519 -i \"\$IN\" -o \"\$OUT\"}"

sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

[ -d "$CANON_DIR" ] || { echo "no such directory: $CANON_DIR" >&2; exit 1; }
[ -f "$PUB" ] || { echo "no such public key: $PUB" >&2; exit 1; }
[ -e "$OUT_TSV" ] && { echo "refusing to overwrite $OUT_TSV" >&2; exit 1; }
openssl pkey -pubin -in "$PUB" -noout -text 2>/dev/null | grep -q ED25519 \
  || { echo "$PUB is not an Ed25519 public key" >&2; exit 1; }

work="$(mktemp -d "${TMPDIR:-/tmp}/plugin-sign-XXXXXX")"
trap 'rm -rf "$work"' EXIT
n=0
shopt -s nullglob
for IN in "$CANON_DIR"/*.canonical; do
  asset="$(basename "$IN" .canonical)"
  OUT="$work/$asset.sig"
  echo "signing $asset (touch the key when it blinks)"
  IN="$IN" OUT="$OUT" bash -c "$PLUGIN_SIGN_CMD"
  [ "$(wc -c <"$OUT" | tr -d ' ')" = 64 ] || { echo "$asset: the signer did not write a 64-byte signature" >&2; exit 1; }
  openssl pkeyutl -verify -pubin -inkey "$PUB" -rawin -in "$IN" -sigfile "$OUT" >/dev/null \
    || { echo "$asset: the signature does NOT verify against $PUB" >&2; exit 1; }
  printf '%s\t%s\t%s\n' "$asset" "$(sha256 "$IN")" "$(od -An -v -tx1 "$OUT" | tr -d ' \n')" >>"$work/out.tsv"
  n=$((n + 1))
done
[ "$n" -gt 0 ] || { echo "no *.canonical files in $CANON_DIR" >&2; exit 1; }
mv "$work/out.tsv" "$OUT_TSV"
echo "signed and verified $n manifest(s) -> $OUT_TSV"
