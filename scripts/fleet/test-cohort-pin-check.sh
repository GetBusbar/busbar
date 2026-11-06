#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p "$tmp/sdk/scripts/fleet" "$tmp/product/dist/default" "$tmp/plugin/.github/workflows"
cp "$here/pin-check.sh" "$tmp/sdk/scripts/fleet/pin-check.sh"
framer=0123456789abcdef0123456789abcdef01234567
other=89abcdef0123456789abcdef0123456789abcdef
for repo in sdk product; do git -C "$tmp/$repo" init -q; done
commit() {
  git -C "$1" add .
  git -C "$1" -c user.name=fixture -c user.email=fixture@example.invalid commit-tree "$(git -C "$1" write-tree)" -m fixture
}
sdk="$(commit "$tmp/sdk")"
printf '[[package]]\nname = "busbar-transport-http"\nsource = "git+https://github.com/GetBusbar/busbar-transport-http?rev=%s#%s"\n' "$framer" "$framer" > "$tmp/product/dist/default/Cargo.lock"
product="$(commit "$tmp/product")"
digest="$(shasum -a 256 "$tmp/product/dist/default/Cargo.lock" | awk '{print $1}')"
printf '%s 1.6.0\n' "$sdk" > "$tmp/plugin/.busbar-ref"
printf '[dependencies]\nbusbar-contract = { git = "https://github.com/GetBusbar/busbar", rev = "%s" }\n' "$sdk" > "$tmp/plugin/Cargo.toml"
printf 'jobs:\n  ci:\n    uses: GetBusbar/busbar/.github/workflows/plugin-ci.yml@%s\n' "$sdk" > "$tmp/plugin/.github/workflows/ci.yml"
printf '[[package]]\nname = "busbar-contract"\nsource = "git+https://github.com/GetBusbar/busbar?rev=%s#%s"\n' "$sdk" "$sdk" > "$tmp/plugin/Cargo.lock"
cat "$tmp/product/dist/default/Cargo.lock" >> "$tmp/plugin/Cargo.lock"
run() { bash "$here/cohort-pin-check.sh" "$tmp/product" "$product" "$tmp/sdk" "$sdk" "$digest" "$tmp/plugin"; }
expect() {
  local want=$1 label=$2 needle=${3:-} result status=0
  result="$(run 2>&1)" || status=$?
  if [ "$want" = pass ]; then [ "$status" = 0 ] || { echo "$result"; exit 1; }
  else [ "$status" != 0 ] && [[ "$result" = *"$needle"* ]] || { echo "FAIL $label: $result"; exit 1; }; fi
  echo "PASS $label"
}
expect pass 'exact SDK + separately frozen product lock passes'
printf 'untrusted worktree bytes\n' > "$tmp/product/dist/default/Cargo.lock"
expect pass 'edited product checkout cannot replace committed lock'
old=$digest; digest=$(printf '%064d' 0); expect fail 'wrong controller lock digest' 'digest differs'; digest=$old
old=$product; product=dev; expect fail 'moving product ref refused' 'immutable commit'; product=$old
old=$product; product=$(git -C "$tmp/product" rev-parse "$product^{tree}"); expect fail 'tree ID refused' 'must be a commit'; product=$old
printf '%s 1.6.0\n' "$other" > "$tmp/plugin/.busbar-ref"
expect fail 'plugin cannot select another SDK' 'differs from controller'; printf '%s 1.6.0\n' "$sdk" > "$tmp/plugin/.busbar-ref"
sed -i.bak "s/$framer/$other/g" "$tmp/plugin/Cargo.lock"
expect fail 'wrong framer remains refused' 'not the rev'; mv "$tmp/plugin/Cargo.lock.bak" "$tmp/plugin/Cargo.lock"
sed -i.bak "s/$sdk/$other/g" "$tmp/plugin/.github/workflows/ci.yml"
expect fail 'wrong workflow remains refused' 'not the pin'; mv "$tmp/plugin/.github/workflows/ci.yml.bak" "$tmp/plugin/.github/workflows/ci.yml"
rm "$tmp/product/dist/default/Cargo.lock"
ln -s /tmp/untrusted "$tmp/product/dist/default/Cargo.lock"
product="$(commit "$tmp/product")"
expect fail 'committed symlink lock refused' 'not a regular blob'
