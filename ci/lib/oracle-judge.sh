# shellcheck shell=bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Sourced (bash). The signed oracle judge for a plain shell CI job.
#
# oracle_judge_stage: find the judge the protected pin ci/native-oracle.json names for this
# host's architecture, refuse it unless its sha256 is the pin's and its Ed25519 signature
# (over "<filename>\n<sha256>\n") verifies with the pin's release key, and that key is the
# one bin/oracle trusts. Then export the environment bin/oracle requires of a CI run
# (BUSBAR_ORACLE_RELEASE_REPO/_REF/_SHA256_LINUX_*/_CRATE/_BIN and BUSBAR_ORACLE_JUDGE_PATH).
# bin/oracle re-hashes the judge on every use against the exported digest.
#
# Where the bytes come from: ORACLE_JUDGE_FILE if set (a downloaded release asset), else
# the image-baked copy every CI worker carries at
# /srv/busbar-native-tools/oracle/<sha256>/busbar-oracle (infra worker-oracle-image.sh).
# Either way the bytes are judged only by the pin, never by where they were found.
# This job never builds, fetches or signs a replacement judge.

oracle_refuse() {
  echo "refused: core-oracle: $*" >&2
  exit 1
}

oracle_judge_stage() {
  local root="${1:?oracle_judge_stage <checkout>}" pin arch row file want got sig key work trusted
  pin="$root/ci/native-oracle.json"
  [ -f "$pin" ] || oracle_refuse "no judge pin at ci/native-oracle.json"
  command -v jq >/dev/null 2>&1 || oracle_refuse "jq is required to read the judge pin"
  command -v openssl >/dev/null 2>&1 || oracle_refuse "openssl is required to verify the judge signature"
  [ "$(jq -r .schema "$pin")" = busbar.native-oracle-pin/1 ] && [ "$(jq -r .bin "$pin")" = busbar-oracle ] \
    || oracle_refuse "ci/native-oracle.json is not a busbar.native-oracle-pin/1 pin for busbar-oracle"
  [ "$(uname -s)" = Linux ] || oracle_refuse "the signed judge is published for Linux only (this host is $(uname -s))"
  arch="$(uname -m)"; [ "$arch" = arm64 ] && arch=aarch64
  row="$(jq -c --arg a "$arch" '.platforms[$a] // empty' "$pin")"
  [ -n "$row" ] || oracle_refuse "the judge pin names no judge for $arch"
  want="$(jq -r .sha256 <<<"$row")"
  [[ "$want" =~ ^[0-9a-f]{64}$ ]] || oracle_refuse "the judge pin's $arch sha256 is not 64 hex"
  file="${ORACLE_JUDGE_FILE:-/srv/busbar-native-tools/oracle/$want/busbar-oracle}"
  [ -f "$file" ] && [ ! -L "$file" ] \
    || oracle_refuse "no judge at $file (the CI worker image bakes the pinned judge there; set ORACLE_JUDGE_FILE to a downloaded $(jq -r .filename <<<"$row"))"
  got="$(sha256sum -- "$file" | cut -c1-64)"
  [ "$got" = "$want" ] || oracle_refuse "the judge at $file has sha256 $got, the pin says $want"
  # The pin's release key must be the key bin/oracle trusts (its ORACLE_RELEASE_KEY_PEMS).
  key="$(jq -r .release_key_pem "$pin")"
  trusted="$(printf '%s\n' "$key" | sed -n '2p')"
  if [ -z "$trusted" ] || ! grep -qxF -- "$trusted" "$root/bin/oracle"; then
    oracle_refuse "the judge pin's release key is not a key bin/oracle trusts"
  fi
  work="$(mktemp -d)"
  printf '%s\n' "$key" >"$work/release-key.pem"
  printf '%s\n%s\n' "$(jq -r .filename <<<"$row")" "$got" >"$work/message"
  sig="$(jq -r .signature <<<"$row")"
  printf '%s' "$sig" | base64 -d >"$work/signature" 2>/dev/null || { rm -rf "$work"; oracle_refuse "the judge pin's $arch signature is not base64"; }
  if ! openssl pkeyutl -verify -pubin -inkey "$work/release-key.pem" -rawin \
      -in "$work/message" -sigfile "$work/signature" >/dev/null 2>&1; then
    rm -rf "$work"
    oracle_refuse "the judge signature does not verify with the pinned release key"
  fi
  rm -rf "$work"
  [ -x "$file" ] || oracle_refuse "the judge at $file is not executable"
  "$file" --help >/dev/null 2>&1 || oracle_refuse "the judge at $file does not start on this host"
  export BUSBAR_ORACLE_RELEASE_REPO BUSBAR_ORACLE_RELEASE_REF BUSBAR_ORACLE_CRATE BUSBAR_ORACLE_BIN
  export BUSBAR_ORACLE_SHA256_LINUX_X86_64 BUSBAR_ORACLE_SHA256_LINUX_AARCH64 BUSBAR_ORACLE_JUDGE_PATH
  BUSBAR_ORACLE_RELEASE_REPO="$(jq -r .repository "$pin")"
  BUSBAR_ORACLE_RELEASE_REF="$(jq -r .source "$pin")"
  BUSBAR_ORACLE_CRATE="$(jq -r .crate "$pin")"
  BUSBAR_ORACLE_BIN="$(jq -r .bin "$pin")"
  BUSBAR_ORACLE_SHA256_LINUX_X86_64="$(jq -r .platforms.x86_64.sha256 "$pin")"
  BUSBAR_ORACLE_SHA256_LINUX_AARCH64="$(jq -r .platforms.aarch64.sha256 "$pin")"
  BUSBAR_ORACLE_JUDGE_PATH="$file"
  echo "core-oracle: judge $BUSBAR_ORACLE_RELEASE_REF ($arch) sha256 $got, signature verified with the pinned release key"
}
