#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# rotate-golden.sh — POINT THE SHADOW ORACLE AT THE RELEASE THAT JUST SHIPPED.
#
#   testing/shadow-oracle/rotate-golden.sh <version> [--dry-run]
#   testing/shadow-oracle/rotate-golden.sh --selftest
#
# WHY THIS IS A STANDING PROCEDURE AND NOT A ONE-OFF
# --------------------------------------------------
# The oracle's whole claim is "this build behaves like the last SHIPPED one". That claim decays the
# moment a release ships: on the day v1.6.0 is tagged, every run still compares HEAD against 1.5.5,
# so a 1.6.0→1.6.1 regression is invisible behind the 1.5.5→1.6.0 differences the register already
# forgives. Worse, the register is CUMULATIVE — every entry in accepted-differences.json is a
# permanent blindfold over the surface it names, and nobody removes one, because removing an entry
# looks like weakening a gate rather than what it is: the difference has SHIPPED, so it is no longer
# a difference.
#
# Two invariants, and this script is what makes them true rather than remembered:
#
#   THE GOLDEN IS ALWAYS THE LAST SHIPPED BINARY.
#   THE REGISTER IS ALWAYS THIS RELEASE'S NAMED DIFFERENCES.
#
# WHAT IT DOES, in order, and why the order is the order
# -----------------------------------------------------
#   1. Reads the PUBLISHED release assets' sha256 digests from the GitHub release BY TAG, read-only
#      (`gh release view <tag> --json assets`). The digests come from GitHub's own record of the
#      uploaded bytes, not from a local build and not from a file anyone here can edit.
#   2. REFUSES if any required digest is missing — the four platform archives and the openapi
#      document. A pin file with a hole in it is not a pin file: fetch-golden.sh's own rule is that
#      an absent pin is RED, never permission to skip the check, and this is the same rule one level
#      up. A release that has not finished uploading is not a release to rotate onto.
#   3. Appends the rows to golden-digests.tsv. This happens BEFORE the recording, deliberately:
#      golden-digests.tsv is IN the harness_rev file set (harness-rev.sh), so recording first would
#      stamp the golden with a revision that stops existing one line later, and diff-cells.py would
#      then refuse the very recording this script just made.
#   4. Records the new golden from the FETCHED, digest-verified binary via the existing
#      `record.sh --plane all`, into a scratch part, and lands it through merge-recordings.py — the
#      merge/replace path — so the golden's provenance is asserted BY SHA (version + binary_sha256 +
#      host_triple) rather than by the path someone happened to type.
#   5. Archives the outgoing register under testing/shadow-oracle/golden/<old-version>/ and resets
#      accepted-differences.json to an EMPTY register for the next cycle. The archive is why the
#      reset is not a loss: what 1.6.0 accepted about 1.5.5 stays readable forever, beside the
#      recording it was about.
#   6. Re-stamps harness_rev: recomputes it over the final tree and asserts the new golden's
#      meta.json carries exactly that, re-writing it (with the old one kept in harness_rev_history)
#      if anything in the harness set moved during the run.
#
# WHAT IT DELIBERATELY DOES NOT DO. It does not rewrite the version literals in ci.yml, qa-gate.yml
# or verify-1.6.0-done.sh. Those are the workflow graph and the done claim; a sed across them from
# inside a data-rotation script is how a release procedure silently becomes a workflow edit. They
# are GREPPED and PRINTED at the end as the remaining, reviewable, one-line changes.
#
# `--dry-run` prints the whole plan and touches nothing. `--selftest` drives the refusals over fake
# release JSON, so the rules are proven to fire on a laptop with no release in existence.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "${here}/../.." && pwd)"
# shellcheck source=harness-rev.sh
source "${here}/harness-rev.sh"

REPO_SLUG="${BUSBAR_ORACLE_REPO:-GetBusbar/busbar}"
DIGESTS="${here}/golden-digests.tsv"
REGISTER="${here}/accepted-differences.json"
GOLDEN_ROOT="${here}/golden"
SCRATCH="${repo}/target/oracle/rotate"

VERSION="" DRY=0 SELFTEST=0 RELEASE_JSON=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)      DRY=1; shift ;;
    --selftest)     SELFTEST=1; shift ;;
    --release-json) RELEASE_JSON="$2"; shift 2 ;;   # selftest / offline hook; see read_assets
    -h|--help)      sed -n '5,50p' "$0"; exit 0 ;;
    -*)             echo "rotate-golden: unknown arg: $1" >&2; exit 2 ;;
    *)              [ -z "$VERSION" ] || { echo "rotate-golden: two versions given ($VERSION, $1)" >&2; exit 2; }
                    VERSION="$1"; shift ;;
  esac
done

say()  { printf '%s\n' "$*"; }
plan() { printf '  %s\n' "$*"; }
die()  { printf 'rotate-golden: %s\n' "$*" >&2; exit 1; }

# ── THE ASSET SET ────────────────────────────────────────────────────────────────────────────────
# REQUIRED is the set whose absence is a refusal: the four platform archives the oracle can record a
# golden FROM (one per triple fetch-golden.sh knows), plus the openapi document enumerate-cells.py
# reads. ALSO_PIN is pinned when present and NAMED when absent — the Windows zip records no golden
# (there is no Windows oracle host) and the SBOM is not read by the harness at all, so their absence
# is a fact to report, not a reason to refuse a rotation.
REQUIRED_TRIPLES="aarch64-apple-darwin aarch64-unknown-linux-gnu x86_64-apple-darwin x86_64-unknown-linux-gnu"

required_assets() {  # required_assets <version>
  local t
  for t in $REQUIRED_TRIPLES; do printf 'busbar-%s.tar.gz\n' "$t"; done
  printf 'busbar-openapi-v%s.json\n' "$1"
}
also_pin_assets() {  # also_pin_assets <version>
  printf 'busbar-x86_64-pc-windows-msvc.zip\n'
  printf 'busbar-v%s.cdx.json\n' "$1"
}

# ── READING THE RELEASE ──────────────────────────────────────────────────────────────────────────
# READ-ONLY, and by TAG. `gh release view --json assets` returns GitHub's own `digest` field
# ("sha256:<hex>") for every uploaded asset — the hash of the bytes GitHub serves, computed by
# GitHub. That is the only digest worth pinning: one computed here from a download would pin
# whatever the network handed this machine, which is precisely the substitution the pin file exists
# to refuse.
read_assets() {  # -> TSV: name<TAB>sha256 ; empty output means "no release / no assets"
  local tag="$1" json
  if [ -n "$RELEASE_JSON" ]; then
    json="$(cat "$RELEASE_JSON")"
  else
    command -v gh >/dev/null 2>&1 || die "gh is not installed; it is the only read path to the published release's digests"
    json="$(gh release view "$tag" --repo "$REPO_SLUG" --json assets,isDraft 2>/dev/null)" || json=""
  fi
  [ -n "$json" ] || return 0
  printf '%s' "$json" | python3 -c '
import json, sys
try:
    doc = json.load(sys.stdin)
except Exception:
    sys.exit(0)
# A DRAFT IS NOT A PUBLISHED RELEASE. Its assets are re-uploadable in place, so a digest read from
# one pins bytes that can still change under the same name — the exact substitution the pin file
# exists to refuse. Emitted as a row rather than a separate query so one read answers both.
if doc.get("isDraft"):
    print("!draft\t-")
for a in (doc.get("assets") or []):
    name = a.get("name") or ""
    dig = (a.get("digest") or "")
    if dig.startswith("sha256:"):
        dig = dig[len("sha256:"):]
    else:
        dig = ""
    print(f"{name}\t{dig}")
'
}

pinned_versions() {  # every version already carrying rows in golden-digests.tsv, newest last
  grep -v '^#' "$DIGESTS" | awk -F'\t' 'NF>=3 && $1!="" {print $1}' | sort -u -V
}

# ── THE PLAN ─────────────────────────────────────────────────────────────────────────────────────
# Computed identically for --dry-run and for the real run, so what a reviewer reads in the dry run
# is what executes. Sets: NEW_ROWS, MISSING, PRESENT_OPTIONAL, MISSING_OPTIONAL, OLD_VERSION.
build_plan() {  # build_plan <version> ; returns non-zero (and fills MISSING) on any missing digest
  local ver="$1" assets name want got
  assets="$(read_assets "v${ver}")"
  NEW_ROWS=""; MISSING=""; PRESENT_OPTIONAL=""; MISSING_OPTIONAL=""; IS_DRAFT=0
  if printf '%s\n' "$assets" | grep -q '^!draft	'; then IS_DRAFT=1; fi
  if [ -z "$assets" ]; then
    MISSING="$(required_assets "$ver" | tr '\n' ' ')"
    return 1
  fi
  for name in $(required_assets "$ver"); do
    got="$(printf '%s\n' "$assets" | awk -F'\t' -v n="$name" '$1==n {print $2; exit}')"
    if [ -z "$got" ]; then MISSING="${MISSING}${name} "; else NEW_ROWS="${NEW_ROWS}${ver}	${name}	${got}
"; fi
  done
  for name in $(also_pin_assets "$ver"); do
    got="$(printf '%s\n' "$assets" | awk -F'\t' -v n="$name" '$1==n {print $2; exit}')"
    if [ -z "$got" ]; then MISSING_OPTIONAL="${MISSING_OPTIONAL}${name} "
    else PRESENT_OPTIONAL="${PRESENT_OPTIONAL}${name} "; NEW_ROWS="${NEW_ROWS}${ver}	${name}	${got}
"; fi
  done
  [ "$IS_DRAFT" -eq 0 ] && [ -z "$MISSING" ]
}

# ── SELFTEST ─────────────────────────────────────────────────────────────────────────────────────
# Every refusal, driven over FAKE release JSON, so the rules are proven on a laptop where no such
# release exists. A rotation script whose refusals have never fired is a rotation script that will
# append a hole into the pin file on the one day it matters.
if [ "$SELFTEST" -eq 1 ]; then
  fails=0
  fx="${SCRATCH}/selftest"
  rm -rf "$fx"; mkdir -p "$fx"

  mk_json() {  # mk_json <file> <name:digest>...
    local out="$1"; shift
    { printf '{"assets":['
      local first=1 pair
      for pair in "$@"; do
        [ "$first" -eq 1 ] || printf ','
        first=0
        printf '{"name":"%s","digest":"sha256:%s"}' "${pair%%:*}" "${pair#*:}"
      done
      printf ']}'
    } >"$out"
  }
  D=0000000000000000000000000000000000000000000000000000000000000000
  mk_json "$fx/full.json" \
    "busbar-aarch64-apple-darwin.tar.gz:${D}" \
    "busbar-aarch64-unknown-linux-gnu.tar.gz:${D}" \
    "busbar-x86_64-apple-darwin.tar.gz:${D}" \
    "busbar-x86_64-unknown-linux-gnu.tar.gz:${D}" \
    "busbar-x86_64-pc-windows-msvc.zip:${D}" \
    "busbar-openapi-v9.9.9.json:${D}"
  # One required archive short: the exact shape of a release still uploading.
  mk_json "$fx/short.json" \
    "busbar-aarch64-apple-darwin.tar.gz:${D}" \
    "busbar-x86_64-apple-darwin.tar.gz:${D}" \
    "busbar-x86_64-unknown-linux-gnu.tar.gz:${D}" \
    "busbar-openapi-v9.9.9.json:${D}"
  # An asset present but with NO digest — GitHub has the row, not the bytes' hash.
  printf '{"assets":[{"name":"busbar-openapi-v9.9.9.json","digest":""}]}\n' >"$fx/nodigest.json"
  printf '{"assets":[]}\n' >"$fx/empty.json"
  # A COMPLETE set of assets on a release that is still a DRAFT. This is the case that is not
  # hypothetical: under the qa/main split the draft is filled with every asset on `qa` and only
  # published by the promote on `main`, so "all six digests are there" is TRUE for hours before the
  # bytes are final. Pinning then would pin a name whose contents can still be replaced.
  python3 -c '
import json,sys
doc = json.load(open(sys.argv[1])); doc["isDraft"] = True
json.dump(doc, open(sys.argv[2], "w"))
' "$fx/full.json" "$fx/draft.json"

  case_run() {  # case_run <label> <want-rc> <why> -- <argv...>
    local label="$1" want="$2" why="$3"; shift 4
    local out rc
    out="$(bash "$0" "$@" 2>&1)"; rc=$?
    if [ "$rc" = "$want" ]; then
      printf '  [ok]     %-52s -> rc=%s\n           %s\n' "$label" "$rc" "$why"
    else
      printf '  [FAILED] %-52s -> rc=%s (want %s)\n           %s\n%s\n' "$label" "$rc" "$want" "$why" "$out"
      fails=$((fails+1))
    fi
  }

  printf '== rotate-golden SELF-TEST (every refusal, on fake release JSON) ==\n'
  case_run "a complete release plans cleanly (dry run)"   0 "the happy path must still be reachable, or the refusals prove nothing" \
    -- 9.9.9 --dry-run --release-json "$fx/full.json"
  case_run "a release missing a platform archive"          1 "a pin file with a hole in it is not a pin file — fetch-golden.sh's own rule, one level up" \
    -- 9.9.9 --dry-run --release-json "$fx/short.json"
  case_run "an asset GitHub has no digest for"             1 "an unhashed asset would be pinned to the empty string, which matches nothing and refuses everything" \
    -- 9.9.9 --dry-run --release-json "$fx/nodigest.json"
  case_run "a release with no assets at all"               1 "a tag that exists with nothing published is not a release to rotate onto" \
    -- 9.9.9 --dry-run --release-json "$fx/empty.json"
  case_run "a COMPLETE set of assets on a DRAFT release"    1 "a draft's assets are re-uploadable in place; the digest would pin a name, not the bytes" \
    -- 9.9.9 --dry-run --release-json "$fx/draft.json"
  case_run "no version given"                            2 "the version is the whole argument; defaulting it would rotate onto something nobody named" \
    -- --dry-run --release-json "$fx/full.json"
  case_run "a version already pinned in golden-digests"    1 "re-appending rows for a pinned version would give one asset two digests and make the pin ambiguous" \
    -- 1.5.5 --dry-run --release-json "$fx/full.json"
  case_run "a version that is not X.Y.Z"                   2 "the version names a tag, a cache directory and every row's key; a malformed one poisons all three" \
    -- 1.6 --dry-run --release-json "$fx/full.json"

  # THE DRY RUN CHANGES NOTHING, proven by digest rather than asserted in prose.
  before="$(sha256_of "$DIGESTS")"
  bash "$0" 9.9.9 --dry-run --release-json "$fx/full.json" >/dev/null 2>&1
  after="$(sha256_of "$DIGESTS")"
  if [ "$before" = "$after" ]; then
    printf '  [ok]     --dry-run left golden-digests.tsv byte-identical\n'
  else
    printf '  [FAILED] --dry-run MODIFIED golden-digests.tsv\n'; fails=$((fails+1))
  fi

  # And the plan a clean release produces actually names the rows it would write — a "plan" that
  # printed nothing would pass every case above.
  outp="$(bash "$0" 9.9.9 --dry-run --release-json "$fx/full.json" 2>&1)"
  n="$(printf '%s\n' "$outp" | grep -c '^  9\.9\.9	busbar-')"
  if [ "$n" -ge 6 ]; then
    printf '  [ok]     the plan names all %s rows it would append\n' "$n"
  else
    printf '  [FAILED] the plan named only %s rows (want >= 6) — an empty plan passes every refusal case\n' "$n"; fails=$((fails+1))
  fi

  if [ "$fails" -eq 0 ]; then printf '\nrotate-golden selftest: GREEN\n'; exit 0; fi
  printf '\nrotate-golden selftest: RED (%s failure(s))\n' "$fails"; exit 1
fi

# ── ARGUMENT RULES ───────────────────────────────────────────────────────────────────────────────
[ -n "$VERSION" ] || { echo "usage: $0 <version> [--dry-run] | $0 --selftest" >&2; exit 2; }
VERSION="${VERSION#v}"
case "$VERSION" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "rotate-golden: '$VERSION' is not an X.Y.Z version. It keys every row in golden-digests.tsv, the cache directory and the tag; a malformed one poisons all three." >&2; exit 2 ;;
esac
TAG="v${VERSION}"

OLD_VERSION="$(pinned_versions | tail -1)"
[ -n "$OLD_VERSION" ] || die "golden-digests.tsv pins no version at all — refusing to rotate off an empty pin file"
if pinned_versions | grep -qx "$VERSION"; then
  die "${VERSION} already has rows in golden-digests.tsv. Re-appending would give one asset two digests, and \`pinned()\` takes the first — an ambiguous pin is a pin that can be chosen."
fi

say "== rotate the shadow-oracle golden: ${OLD_VERSION} -> ${VERSION} =="
say "   the golden is always the last shipped binary; the register is always this release's named differences"
say ""

if ! build_plan "$VERSION"; then
  if [ "${IS_DRAFT:-0}" -eq 1 ]; then
    say "REFUSED. ${TAG} is still a DRAFT release."
    say ""
    say "A draft's assets are re-uploadable in place, so a digest read from one pins bytes that can"
    say "still change under the same name — the substitution the pin file exists to refuse. Under the"
    say "qa/main split the draft is BUILT ON qa and only PUBLISHED by the promote on main, so the"
    say "right moment for this script is after the tag is pushed and the draft is published, never"
    say "during the qa soak. Nothing was changed."
    [ -n "$MISSING" ] && { say ""; say "(it is also missing a digest for: ${MISSING})"; }
    exit 1
  fi
  say "REFUSED. The published ${TAG} release does not carry a digest for:"
  for m in $MISSING; do plan "$m"; done
  say ""
  say "A missing digest is not permission to pin fewer assets: fetch-golden.sh treats an absent pin"
  say "as RED rather than as a check to skip, and this is that rule one level up. Either the release"
  say "has not finished uploading, or ${TAG} does not exist yet. Nothing was changed."
  exit 1
fi

say "PLAN"
say ""
say "1. append to testing/shadow-oracle/golden-digests.tsv:"
printf '%s' "$NEW_ROWS" | while IFS= read -r r; do [ -n "$r" ] && plan "$r"; done
[ -n "$MISSING_OPTIONAL" ] && plan "(not published, so not pinned: ${MISSING_OPTIONAL})"
say ""
say "2. fetch ${TAG} by that pin and record the new golden:"
plan "testing/shadow-oracle/fetch-golden.sh --version ${VERSION}"
plan "testing/shadow-oracle/record.sh --bin <cache>/${VERSION}/busbar --plane all --out ${SCRATCH#"${repo}/"}/${VERSION}/part"
plan "testing/shadow-oracle/merge-recordings.py --out golden/${VERSION} <part>   (identity by version+binary_sha256+host_triple)"
say ""
say "3. archive the outgoing register and reset it:"
plan "cp accepted-differences.json golden/${OLD_VERSION}/accepted-differences.json"
plan "accepted-differences.json <- empty register (the ${OLD_VERSION} differences have SHIPPED; they are not differences any more)"
say ""
say "4. re-stamp harness_rev over the final tree and assert the new golden carries it"
say ""

if [ "$DRY" -eq 1 ]; then
  say "--dry-run: nothing was changed."
  exit 0
fi

# ── 1. THE PINS, FIRST ───────────────────────────────────────────────────────────────────────────
# Before the recording, because golden-digests.tsv is in the harness_rev file set: recording first
# would stamp meta.json with a revision that stops existing one line later.
{
  printf '# Pinned from `gh release view %s --repo %s --json assets` on %s.\n' \
    "$TAG" "$REPO_SLUG" "$(date -u +%Y-%m-%d)"
  printf '# Rotated from %s by testing/shadow-oracle/rotate-golden.sh. The digests are GitHub'"'"'s own\n' "$OLD_VERSION"
  printf '# record of the uploaded bytes, never a hash of a local download.\n'
  printf '%s' "$NEW_ROWS"
} >>"$DIGESTS"
say "appended $(printf '%s' "$NEW_ROWS" | grep -c .) row(s) to golden-digests.tsv"

# ── 2. FETCH AND RECORD ──────────────────────────────────────────────────────────────────────────
bash "${here}/fetch-golden.sh" --version "$VERSION" || die "fetch-golden.sh refused ${VERSION} (see above). The pins are appended; fix the release or revert that hunk."
CACHE_ROOT="${BUSBAR_ORACLE_CACHE:-$HOME/.cache/busbar-oracle}"
BIN="${CACHE_ROOT}/${VERSION}/busbar"
[ -x "$BIN" ] || die "no fetched binary at ${BIN}"

PART="${SCRATCH}/${VERSION}/part"
rm -rf "$PART"; mkdir -p "$PART"
say "recording the new golden from ${BIN} (--plane all) — this is the long step"
bash "${here}/record.sh" --bin "$BIN" --plane all --out "$PART" || die "record.sh failed; the golden was not replaced"

NEW_GOLDEN="${GOLDEN_ROOT}/${VERSION}"
rm -rf "$NEW_GOLDEN"; mkdir -p "$NEW_GOLDEN"
python3 "${here}/merge-recordings.py" --out "$NEW_GOLDEN" "$PART" \
  || die "merge-recordings.py refused the recording (identity is version+binary_sha256+host_triple). The golden was not replaced."
say "landed golden/${VERSION} through the merge path (provenance asserted by sha, not by path)"

# ── 3. ARCHIVE AND RESET THE REGISTER ────────────────────────────────────────────────────────────
mkdir -p "${GOLDEN_ROOT}/${OLD_VERSION}"
cp "$REGISTER" "${GOLDEN_ROOT}/${OLD_VERSION}/accepted-differences.json"
say "archived the ${OLD_VERSION} register under golden/${OLD_VERSION}/accepted-differences.json"

python3 - "$REGISTER" "$OLD_VERSION" "$VERSION" <<'PY'
import json, sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
doc = json.load(open(path))
# The _comment block is the register's RULES (what a kind means, what the differ refuses, what the
# changelog gate owes). Those do not change at a rotation; only the entries do. Keeping them is what
# makes the empty register self-explaining to whoever writes the first entry of the next cycle.
comment = doc.get("_comment", [])
comment = [c for c in comment if not c.startswith("ROTATED:")]
comment.insert(0, f"ROTATED: the golden is now the published {new}. Every entry accepted against "
                  f"{old} has SHIPPED and is therefore no longer a difference; the outgoing register "
                  f"is archived verbatim at testing/shadow-oracle/golden/{old}/accepted-differences.json. "
                  f"This register holds only differences between HEAD and the published {new}.")
json.dump({"_comment": comment, "accepted": []}, open(path, "w"), indent=2)
open(path, "a").write("\n")
PY
say "reset accepted-differences.json to an empty register for the ${VERSION} cycle"

# ── 4. RE-STAMP harness_rev ──────────────────────────────────────────────────────────────────────
# The recording was made after step 1, so its meta.json should already carry the final revision.
# ASSERTED rather than assumed: anything in the harness set that moved during the run (a fixture
# regenerated by record.sh, a concurrent edit) makes the golden claim a revision the tree no longer
# has, and diff-cells.py refuses that skew — loudly here, at rotation time, rather than on the next
# CI run against a golden nobody can explain.
FINAL_REV="$(harness_rev)"
python3 - "${NEW_GOLDEN}/meta.json" "$FINAL_REV" <<'PY'
import json, sys
path, want = sys.argv[1], sys.argv[2]
meta = json.load(open(path))
have = meta.get("harness_rev")
if have == want:
    print(f"harness_rev {want[:16]} — the golden carries the final revision")
else:
    hist = meta.setdefault("harness_rev_history", [])
    if have and have not in hist:
        hist.append(have)
    meta["harness_rev"] = want
    note = meta.get("harness_rev_note") or ""
    meta["harness_rev_note"] = ("re-stamped by rotate-golden.sh: the harness set moved during the "
                               "rotation. " + note).strip()
    json.dump(meta, open(path, "w"), indent=2)
    print(f"harness_rev RE-STAMPED {str(have)[:16]} -> {want[:16]} (previous kept in harness_rev_history)")
PY

say ""
say "== rotation complete: the golden is the published ${VERSION} =="
say ""
say "REMAINING, BY HAND — this script does not sed the workflow graph or the done claim."
say "Every site below still names ${OLD_VERSION}; each is a one-line, reviewable change:"
grep -rn -- "${OLD_VERSION}" \
  "${repo}/.github/workflows/ci.yml" \
  "${repo}/.github/workflows/qa-gate.yml" \
  "${repo}/scripts/verify-1.6.0-done.sh" \
  "${here}/fetch-golden.sh" 2>/dev/null | sed 's/^/  /' || say "  (none found)"
