#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Trusted native-controller entrypoint. All identities/digests MUST originate in
# its independently frozen source plan, never plugin code or a candidate receipt.
# Git locations may be bare repositories or working trees. No network lookup.
set -euo pipefail
[ "$#" = 6 ] || { echo 'usage: cohort-pin-check.sh PRODUCT_GIT PRODUCT_SHA SDK_GIT SDK_SHA LOCK_SHA256 PLUGIN_ROOT' >&2; exit 2; }
product_git=$1 product=$2 sdk_git=$3 sdk=$4 lock_digest=$5 plugin=$6
fail() { echo "::error::cohort-pin-check: $*" >&2; exit 1; }
for sha in "$product" "$sdk"; do
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || fail 'product and SDK must be full immutable commit SHAs'
done
[[ "$lock_digest" =~ ^[0-9a-f]{64}$ ]] || fail 'controller lock digest must be a full SHA256'
[ "$(git -C "$product_git" cat-file -t "$product")" = commit ] || fail 'product source must be a commit'
[ "$(git -C "$sdk_git" cat-file -t "$sdk")" = commit ] || fail 'SDK source must be a commit'
[ "$(awk '{print $1; exit}' "$plugin/.busbar-ref")" = "$sdk" ] || fail 'plugin SDK pin differs from controller plan'
regular_blob() {
  local entry
  entry="$(git -C "$1" ls-tree "$2" -- "$3")"
  [[ "$entry" = '100644 blob '* || "$entry" = '100755 blob '* ]] || fail "source path is not a regular blob: $3"
}
regular_blob "$product_git" "$product" dist/default/Cargo.lock
regular_blob "$sdk_git" "$sdk" scripts/fleet/pin-check.sh
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
# Read committed objects, not potentially edited or symlinked checkout paths.
git -C "$product_git" show "$product:dist/default/Cargo.lock" > "$tmp/Cargo.lock"
git -C "$sdk_git" show "$sdk:scripts/fleet/pin-check.sh" > "$tmp/pin-check.sh"
actual_digest="$(shasum -a 256 "$tmp/Cargo.lock" | awk '{print $1}')"
[ "$actual_digest" = "$lock_digest" ] || fail 'product lock digest differs from controller plan'
echo "cohort-pin-check: product=$product sdk=$sdk lock_sha256=$actual_digest"
# The SDK's unmodified validator still checks every SDK, workflow and framer ref.
PIN_CHECK_BUSBAR_LOCK="$tmp/Cargo.lock" bash "$tmp/pin-check.sh" "$plugin"
