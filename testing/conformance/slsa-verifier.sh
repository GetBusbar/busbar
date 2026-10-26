#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Suite `slsa-verifier` (testing/conformance/suites.tsv): SLSA build provenance v1.0 for DEV builds,
# judged by the official slsa-verifier (`verify-artifact`), pinned release asset, sha256-checked.
#
# WHAT IS VERIFIED: the binaries and provenance that `slsa-dev-provenance` (slsa-github-generator's
# generic generator, keyless Sigstore under GitHub's OIDC identity) PUBLISHED for the latest dev
# build on the public rolling release `dev-provenance` of GetBusbar/busbar. No token: a public
# release. Assets (names fixed by the publisher):
#     busbar-linux-x86_64-<sha>   busbar-linux-aarch64-<sha>   busbar-linux-<sha>.intoto.jsonl
# slsa-verifier accepts provenance only from its trusted builders (the slsa-github-generator reusable
# workflows, signed through GitHub OIDC), so nothing a ModernCI check signs could be judged here.
#
# THE THREE LEGS (pass only when all three hold):
#   CONTROL           slsa-verifier's own published v2.7.1 release binary verifies against its own
#                     published provenance (a third-party artifact the same tool must accept);
#   NEGATIVE CONTROL  the subject binary with one byte appended is REFUSED, for the right reason (the
#                     hash is not a provenance subject), and the real binary is REFUSED for the wrong
#                     branch (`main`);
#   SUBJECT           every published busbar binary verifies with
#                     `--source-uri github.com/GetBusbar/busbar --source-branch dev`, and the commit
#                     the verifier reports as built equals the <sha> the assets are named for.
# No release / no assets yet is `not-run` (armed=false), never a pass. A verifier run that errors for
# any other reason, or a leg that does not hold, is `fail`.
#
# Test hook: BUSBAR_DEV_PROVENANCE_DIR=<dir holding the three assets> skips the download.
set -uo pipefail

: "${CONFORMANCE_OUT:?}"
SV_TAG=v2.7.1
SV_BASE="https://github.com/slsa-framework/slsa-verifier/releases/download/$SV_TAG"
REL_API="https://api.github.com/repos/GetBusbar/busbar/releases/tags/dev-provenance"
REL_DL="https://github.com/GetBusbar/busbar/releases/download/dev-provenance"
SRC=github.com/GetBusbar/busbar
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
say() { printf 'slsa-verifier: %s\n' "$*" >&2; }

verdict() { # <status> <armed true|false> <reason>
  python3 -I - "$CONFORMANCE_OUT/verdict.json" "$1" "$2" "$3" <<'PY'
import json, sys
out, status, armed, reason = sys.argv[1:5]
json.dump({"suite": "slsa-verifier", "status": status, "armed": armed == "true",
           "standard": "SLSA provenance (v1.0)",
           "plan": "slsa-verifier verify-artifact on the published dev build binaries vs their provenance",
           "spec_version": "slsa-verifier v2.7.1", "reason": reason}, open(out, "w"), indent=1)
PY
}
fail() { say "FAIL: $*"; verdict fail true "$*"; exit 0; }
notrun() { say "not-run: $*"; verdict not-run false "$*"; exit 0; }

sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
fetch() { # <url> <sha256> <dest>
  curl -fsSL --retry 3 -o "$3" "$1" || return 1
  [ "$(sha256 "$3")" = "$2" ] || { say "sha256 mismatch for $1"; return 1; }
}

# --- the tool: pinned release asset -----------------------------------------------------------
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)  plat=linux-amd64;  svsha=946dbec729094195e88ef78e1734324a27869f03e2c6bd2f61cbc06bd5350339 ;;
  Linux-aarch64) plat=linux-arm64;  svsha=5d3b2349ede7bfec19e7a21569f18b9f7410145ad12e9584b175370669e14061 ;;
  Darwin-x86_64) plat=darwin-amd64; svsha=4baf25415727821f847a38bccedc86c3e5b17cbfc2eb534cd554feb6c856d6f1 ;;
  Darwin-arm64)  plat=darwin-arm64; svsha=39abfcf5f1d690c3e889ce3d2d6a8b87711424d83368511868d414e8f8bcb05c ;;
  *) fail "no pinned slsa-verifier for $(uname -s)-$(uname -m)" ;;
esac
SV="$W/tool/slsa-verifier"; mkdir -p "$W/tool"
fetch "$SV_BASE/slsa-verifier-$plat" "$svsha" "$SV" || fail "could not fetch the pinned slsa-verifier $SV_TAG ($plat)"
chmod +x "$SV"

# --- CONTROL: the tool's own published artifact + provenance (always runs) ----------------------
mkdir -p "$W/ctl"
fetch "$SV_BASE/slsa-verifier-linux-amd64" 946dbec729094195e88ef78e1734324a27869f03e2c6bd2f61cbc06bd5350339 "$W/ctl/slsa-verifier-linux-amd64" \
  && fetch "$SV_BASE/slsa-verifier-linux-amd64.intoto.jsonl" b567f5ed9a08d0cbddffc169c4ad2d4101abc6b29f9a4c81893a801e432df1f4 "$W/ctl/slsa-verifier-linux-amd64.intoto.jsonl" \
  || fail "control inputs could not be fetched"
"$SV" verify-artifact "$W/ctl/slsa-verifier-linux-amd64" --provenance-path "$W/ctl/slsa-verifier-linux-amd64.intoto.jsonl" \
  --source-uri github.com/slsa-framework/slsa-verifier --source-tag "$SV_TAG" >"$W/ctl.log" 2>&1 \
  || { sed 's/^/  /' "$W/ctl.log" >&2; fail "CONTROL: slsa-verifier $SV_TAG refused its own published release artifact"; }
say "control ok: slsa-verifier-linux-amd64 $SV_TAG verified"

# --- the subject's inputs: the public rolling release --------------------------------------------
A="$W/asset"; mkdir -p "$A"
if [ -n "${BUSBAR_DEV_PROVENANCE_DIR:-}" ]; then
  cp "$BUSBAR_DEV_PROVENANCE_DIR"/* "$A"/ || notrun "BUSBAR_DEV_PROVENANCE_DIR unreadable"
else
  curl -fsSL --retry 3 -o "$W/rel.json" "$REL_API" 2>/dev/null \
    || notrun "no public 'dev-provenance' release on GetBusbar/busbar (or the GitHub API was unreachable): nothing to verify yet"
  python3 -I - "$W/rel.json" >"$W/assets.txt" <<'PY' || notrun "dev-provenance release is unreadable"
import json, sys
for a in json.load(open(sys.argv[1])).get("assets", []):
    print(a["name"])
PY
  while read -r n; do
    case "$n" in busbar-linux-*) curl -fsSL --retry 3 -o "$A/$n" "$REL_DL/$n" || fail "download of $n failed" ;; esac
  done <"$W/assets.txt"
fi
prov="$(ls "$A"/busbar-linux-*.intoto.jsonl 2>/dev/null | head -n1)"
[ -n "$prov" ] || notrun "the dev-provenance release holds no busbar-linux-<sha>.intoto.jsonl"
sha="$(basename "$prov" .intoto.jsonl)"; sha="${sha#busbar-linux-}"
bins=(); for arch in x86_64 aarch64; do [ -f "$A/busbar-linux-$arch-$sha" ] && bins+=("$A/busbar-linux-$arch-$sha"); done
[ "${#bins[@]}" -gt 0 ] || notrun "the dev-provenance release holds provenance for $sha but none of its binaries"
[ "${#bins[@]}" = 2 ] || fail "SUBJECT: the dev-provenance release holds only ${#bins[@]} of the two binaries (x86_64, aarch64) for $sha"
head="$(git ls-remote "https://$SRC" refs/heads/dev 2>/dev/null | cut -c1-40)"
say "subject: provenance for $sha (dev head: ${head:-unknown}); ${#bins[@]} binaries"

# --- NEGATIVE CONTROL: must be refused, for the stated reason -----------------------------------
b0="${bins[0]}"; n0="$(basename "$b0")"
mkdir -p "$W/tam"; cp "$b0" "$W/tam/$n0"; printf x >>"$W/tam/$n0"
if "$SV" verify-artifact "$W/tam/$n0" --provenance-path "$prov" --source-uri "$SRC" --source-branch dev >"$W/neg1.log" 2>&1; then
  fail "NEGATIVE CONTROL: a tampered busbar binary was ACCEPTED"
fi
grep -q 'does not match provenance subject' "$W/neg1.log" \
  || { sed 's/^/  /' "$W/neg1.log" >&2; fail "NEGATIVE CONTROL: the tampered binary was refused, but not for a hash mismatch"; }
if "$SV" verify-artifact "$b0" --provenance-path "$prov" --source-uri "$SRC" --source-branch main >"$W/neg2.log" 2>&1; then
  fail "NEGATIVE CONTROL: provenance was ACCEPTED for source branch main"
fi
grep -q "expected branch 'main'" "$W/neg2.log" \
  || { sed 's/^/  /' "$W/neg2.log" >&2; fail "NEGATIVE CONTROL: the wrong branch was refused, but not for the branch"; }
say "negative control ok: tampered binary and wrong branch refused"

# --- SUBJECT --------------------------------------------------------------------------------------
for b in "${bins[@]}"; do
  n="$(basename "$b")"
  "$SV" verify-artifact "$b" --provenance-path "$prov" --source-uri "$SRC" --source-branch dev >"$W/subj.log" 2>&1 \
    || { sed 's/^/  /' "$W/subj.log" >&2; fail "SUBJECT: slsa-verifier refused $n: $(grep -m1 FAILED "$W/subj.log" | cut -c1-300)"; }
  built="$(sed -n 's/.* at commit \([0-9a-f]\{40\}\).*/\1/p' "$W/subj.log" | head -n1)"
  [ "$built" = "$sha" ] || fail "SUBJECT: $n verified, but the build commit is '${built:-unreadable}', not $sha"
  say "subject ok: $n"
done
note="provenance for dev commit $sha, ${#bins[@]} binaries verified"
[ -n "$head" ] && [ "$head" != "$sha" ] && note="$note; dev head is now $head (its build is not published yet)"
verdict pass true "$note"
