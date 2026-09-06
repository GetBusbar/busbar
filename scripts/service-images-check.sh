#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# scripts/service-images-check.sh — every `image:` in .github/workflows/ is the digest
# testing/fleet-fixtures/service-images.tsv pins. docs/design/store-qa-cycle.md §2.1.
#
# THE DRIFT THIS EXISTS TO STOP, measured before it was written. The service containers busbar's
# durable stores need were provisioned in FIVE places: ci.yml's `check` job, ci.yml's `coverage` job,
# release-stage.yml's `gate` job, plugin-ci.yml's `build-test-signoff` job, and
# scripts/release-check.sh. The four workflows agreed on a digest. release-check.sh — the script the
# QA GATE runs — used floating tags. So the gate that decides a release was not pinned to the bytes
# CI was pinned to, and nothing anywhere said so.
#
# GitHub Actions cannot read a file into a `services:` block, so the workflows must keep literal
# `image:` lines; the pin therefore cannot be enforced by construction and has to be enforced by a
# lint. That is this file. A digest bump now lands in ONE commit — edit the table, edit the workflow
# lines — and this lint is what proves the fan-out was complete rather than three-quarters complete.
#
# WHAT IS CHECKED
#   * every `image:` value in .github/workflows/ that names a container image resolves to a row in
#     the table, with the SAME digest. A digest that is in a workflow and not in the table is red;
#     so is one that is in the table under a different image reference.
#   * no `image:` value carries a FLOATING tag (a `name:tag` with no `@sha256:`). This is the
#     specific hole release-check.sh had, and it is invisible: a floating tag is a perfectly
#     well-formed workflow that silently changes what it proved between two runs of the same commit.
#   * every digest in the table has the shape `sha256:` + 64 hex.
#   * every row in the table is USED by at least one workflow. An unused pin is a pin nobody bumps,
#     and it is how the table starts lying.
#   * a DISCOVERY FLOOR. A scanner that finds nothing passes everything, so finding fewer than
#     MIN_IMAGE_LINES image lines is red on its own terms — the same fails-closed shape
#     scripts/full-gate.sh uses on its own discovery.
#
# HOW IT DECIDES. Through testing/fleet-fixtures/lib.sh + verdict.sh, the same ledger-and-verdict
# inversion as every other gate in this tree: each check appends exactly ONE row and NEVER controls
# flow, so no check can mask another; an owed id with no row is DID NOT RUN, red in its own column;
# and ZERO ROWS IS RED — a lint that passes because it scanned nothing is the exact
# green-having-checked-nothing failure the audit named.
#
# USAGE
#   scripts/service-images-check.sh              # the gate
#   scripts/service-images-check.sh --selftest   # prove the lint fires, on planted fixtures
#
#   SERVICE_IMAGES_TSV=<file>  WORKFLOW_DIR=<dir>   override both inputs (used by --selftest)
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "${here}/.." && pwd)"

IMAGES="${SERVICE_IMAGES_TSV:-${repo}/testing/fleet-fixtures/service-images.tsv}"
WORKFLOW_DIR="${WORKFLOW_DIR:-${repo}/.github/workflows}"
# Nine `image:` lines exist today across ci.yml (2), plugin-ci.yml (6) and release-stage.yml (2) —
# ten. The floor is set below that on purpose: it must catch a scanner that broke, not fail every
# time somebody legitimately deletes a service. A floor of 1 would not catch anything.
MIN_IMAGE_LINES="${MIN_IMAGE_LINES:-6}"

say() { printf '%s\n' "$*"; }

# The extractor, used by the gate AND by --selftest, so the self-test cannot pass against a parser
# the real path does not use. Emits one TSV line per image reference found:
#   <workflow-basename>:<line-no> <TAB> <image-ref-without-digest> <TAB> <digest-or-'FLOATING'>
extract_images() {  # extract_images <workflow-dir>
  python3 - "$1" <<'PY'
import os, re, sys

wf_dir = sys.argv[1]
# The KEY must be exactly `image:` at the start of the (stripped) line. `promote-image:`,
# `stage-image:` and `bundle_image:` are JOB and INPUT names, not image references, and an earlier
# shape of this scanner that grepped for the substring `image:` reported all three plus a line of
# prose from verify-deploy.yml that happens to read `(image: ${IMG})`. A lint with four false
# positives is a lint somebody adds an allowlist to, and the allowlist is where the real one hides.
KEY = re.compile(r"^image:\s*(.+?)\s*$")
# A pinned reference: <name>[:tag]@sha256:<64 hex>. The name may carry a registry host and path.
PINNED = re.compile(r"([A-Za-z0-9][A-Za-z0-9._/-]*(?::[A-Za-z0-9._-]+)?)@(sha256:[0-9a-f]{64})")
# A floating reference: a quoted <name>:<tag> with no digest. Quoted, because an unquoted bare word
# in a `${{ }}` ternary is an expression fragment, not an image.
FLOATING = re.compile(r"'([A-Za-z0-9][A-Za-z0-9._/-]*:[A-Za-z0-9._-]+)'")

for name in sorted(os.listdir(wf_dir)):
    if not name.endswith((".yml", ".yaml")):
        continue
    path = os.path.join(wf_dir, name)
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            m = KEY.match(line.strip())
            if not m:
                continue
            value = m.group(1)
            found = PINNED.findall(value)
            for ref, digest in found:
                print(f"{name}:{n}\t{ref}\t{digest}")
            # A value that mentions an image WITHOUT a digest is the floating-tag case, and it is
            # reported even when the same line also carries a pinned one (plugin-ci.yml's ternaries
            # put a pinned image and an empty fallback on one line; a THIRD, unpinned literal
            # sneaking in beside them is exactly what would otherwise be invisible).
            pinned_names = {r for r, _ in found}
            for ref in FLOATING.findall(value):
                if ref in pinned_names or f"{ref}@" in value:
                    continue
                print(f"{name}:{n}\t{ref}\tFLOATING")
            if not found and not FLOATING.search(value) and "${{" not in value and value not in ("", "''"):
                print(f"{name}:{n}\t{value}\tFLOATING")
PY
}

run_check() {  # run_check -> exit status of verdict.sh
  local work="${repo}/.qa-work/service-images-check"
  rm -rf "$work"; mkdir -p "$work"
  export LEDGER="${work}/ledger.tsv"; : >"$LEDGER"
  export GATE_NAME="service image pins"
  # shellcheck source=../testing/fleet-fixtures/lib.sh
  source "${repo}/testing/fleet-fixtures/lib.sh"

  local owed=""
  owe() { owed="${owed} $1"; }

  # ── the table itself ──────────────────────────────────────────────────────────────────────────
  owe "images|table-readable"
  if [ -s "$IMAGES" ]; then
    record "images|table-readable" PASS "the pinned image table is present" "$IMAGES"
  else
    record "images|table-readable" FAIL "the pinned image table is missing or empty" "$IMAGES"
    GATE_NAME="service image pins" EXPECTED_IDS="$owed" LEDGER="$LEDGER" bash "${repo}/testing/fleet-fixtures/verdict.sh"
    return $?
  fi

  local bad_shape
  bad_shape="$(awk -F'\t' '/^[[:space:]]*#/{next} NF>=3 && $3 !~ /^sha256:[0-9a-f]{64}$/ {printf "%s ", $1}' "$IMAGES")"
  owe "images|table-digest-shape"
  if [ -z "$bad_shape" ]; then
    record "images|table-digest-shape" PASS "every table row is pinned by a well-formed sha256 digest" \
      "$(awk -F'\t' '/^[[:space:]]*#/{next} NF>=3{n++} END{print n+0}' "$IMAGES") row(s)"
  else
    record "images|table-digest-shape" FAIL "a table row is not pinned by a well-formed sha256 digest" "rows: ${bad_shape}"
  fi

  # ── the workflows ─────────────────────────────────────────────────────────────────────────────
  local found; found="$(extract_images "$WORKFLOW_DIR")"
  local n_found; n_found="$(printf '%s' "$found" | grep -c . || true)"

  # A SCANNER THAT FINDS NOTHING PASSES EVERYTHING. This row is the floor, and it is owed like any
  # other, so a scanner that silently stopped matching is red rather than quietly perfect.
  owe "images|discovery-floor"
  if [ "$n_found" -ge "$MIN_IMAGE_LINES" ]; then
    record "images|discovery-floor" PASS "the scanner found ${n_found} image reference(s)" "floor is ${MIN_IMAGE_LINES}"
  else
    record "images|discovery-floor" FAIL "the scanner found only ${n_found} image reference(s)" \
      "floor is ${MIN_IMAGE_LINES}; a lint that scans nothing passes everything, so this is red on its own terms"
  fi

  local seen_refs="" loc ref digest want_digest
  while IFS=$'\t' read -r loc ref digest; do
    [ -n "$loc" ] || continue
    local id="images|${loc}"
    owe "$id"
    if [ "$digest" = "FLOATING" ]; then
      record "$id" FAIL "a workflow image is on a FLOATING tag" \
        "${ref} at ${loc} carries no @sha256: — it can change what it proved between two runs of the same commit. Pin it to the digest in $(basename "$IMAGES")."
      continue
    fi
    want_digest="$(awk -F'\t' -v r="$ref" '/^[[:space:]]*#/{next} NF>=3 && $2 == r {print $3; exit}' "$IMAGES")"
    if [ -z "$want_digest" ]; then
      record "$id" FAIL "a workflow image has no row in the pinned table" \
        "${ref} at ${loc} is not named in $(basename "$IMAGES"); add a row rather than pinning it in one workflow only"
    elif [ "$want_digest" != "$digest" ]; then
      record "$id" FAIL "a workflow image's digest disagrees with the pinned table" \
        "${ref} at ${loc} is ${digest}; the table pins ${want_digest}. One of the two was bumped and the other was not."
    else
      record "$id" PASS "${ref} at ${loc} matches the pin" "$digest"
      seen_refs="${seen_refs}${ref} "
    fi
  done <<<"$found"

  # ── every pin is USED ─────────────────────────────────────────────────────────────────────────
  # An unused pin is a pin nobody bumps. It is also how a table starts describing a world that no
  # longer exists while still reading as authoritative.
  local unused="" r
  while IFS= read -r r; do
    [ -n "$r" ] || continue
    case " ${seen_refs} " in *" $r "*) ;; *) unused="${unused}${r} " ;; esac
  done <<<"$(awk -F'\t' '/^[[:space:]]*#/{next} NF>=2{print $2}' "$IMAGES")"
  owe "images|every-pin-used"
  if [ -z "$unused" ]; then
    record "images|every-pin-used" PASS "every pinned image is referenced by at least one workflow" ""
  else
    record "images|every-pin-used" FAIL "a pinned image is referenced by no workflow" \
      "unused: ${unused}— delete the row or wire the service, but do not leave a pin nobody bumps"
  fi

  GATE_NAME="service image pins" EXPECTED_IDS="$owed" LEDGER="$LEDGER" \
    bash "${repo}/testing/fleet-fixtures/verdict.sh"
}

# ── --selftest: every rule proven RED on a planted fixture ───────────────────────────────────────
# A lint nobody has watched fail is a guess. Each case below plants the exact defect the rule exists
# for and asserts the REAL gate (run_check above, through the REAL verdict.sh) goes red — never a
# re-implementation of the rule.
run_selftest() {
  local work="${repo}/.qa-work/service-images-selftest"
  rm -rf "$work"; mkdir -p "$work/wf"
  local failures=0
  local pin_pg="sha256:95206741a5b214807675e14165369d05b93a9cf692223b616d07cca227e74b0b"
  local pin_vk="sha256:495e4fecdc98ee48a20b207726caa5ab6451e0fac3642a9be10d9e70b3068df6"

  local tbl="$work/table.tsv"
  {
    printf '# service\timage\tdigest\tready_probe\tport\tlocal_port\tready_secs\n'
    printf 'postgres\tpostgres:16\t%s\tpg_isready -U busbar\t5432\t15432\t60\n' "$pin_pg"
    printf 'valkey\tvalkey/valkey:8\t%s\tvalkey-cli ping\t6379\t16379\t60\n' "$pin_vk"
  } >"$tbl"

  write_wf() {  # write_wf <postgres-image-value> <valkey-image-value>
    cat >"$work/wf/fixture.yml" <<EOF
jobs:
  check:
    services:
      postgres:
        image: $1
      valkey:
        image: $2
      # A JOB NAME, not an image reference — the scanner must not see this.
  promote-image:
    steps:
      - run: echo "running image label (image: \${IMG})"
EOF
  }

  probe() {  # probe <label> <expect-green|expect-red>
    local label="$1" expect="$2" rc
    SERVICE_IMAGES_TSV="$tbl" WORKFLOW_DIR="$work/wf" MIN_IMAGE_LINES=2 \
      bash "$0" >"$work/${label}.log" 2>&1
    rc=$?
    if [ "$expect" = "expect-green" ] && [ "$rc" -ne 0 ]; then
      say "  MISS: ${label} should have been GREEN, exit ${rc} (see $work/${label}.log)"
      failures=$((failures + 1))
    elif [ "$expect" = "expect-red" ] && [ "$rc" -eq 0 ]; then
      say "  MISS: ${label} should have been RED, exit 0 — the rule did not fire"
      failures=$((failures + 1))
    else
      say "  ok: ${label}"
    fi
  }

  say "== service-images-check SELF-TEST (every rule proven RED on a planted fixture) =="

  # GREEN baseline first: a lint that is red on everything proves nothing when it is red on a defect.
  write_wf "postgres:16@${pin_pg}" "valkey/valkey:8@${pin_vk}"
  probe "green-baseline (both workflow pins match the table)" expect-green

  # RED 1: a digest bumped in the workflow and not in the table — the fan-out-incomplete case that is
  # the whole reason this lint exists.
  write_wf "postgres:16@sha256:0000000000000000000000000000000000000000000000000000000000000000" "valkey/valkey:8@${pin_vk}"
  probe "red: workflow digest disagrees with the table" expect-red

  # RED 2: a FLOATING tag — release-check.sh's actual hole, reproduced.
  write_wf "postgres:16" "valkey/valkey:8@${pin_vk}"
  probe "red: workflow image on a floating tag" expect-red

  # RED 3: an image with no row at all in the table.
  write_wf "postgres:16@${pin_pg}" "mysql:8@sha256:b3b90af2a6552ae30c266fdb7d5dd55f3afb72404bb78d37fe8a23eb857fd3fb"
  probe "red: workflow image absent from the pinned table" expect-red

  # RED 4: a table row nobody uses — the pin that stops being bumped.
  write_wf "postgres:16@${pin_pg}" "postgres:16@${pin_pg}"
  probe "red: a pinned image referenced by no workflow" expect-red

  # RED 5: THE DISCOVERY FLOOR. An empty workflow directory must be red, not vacuously perfect. This
  # is the same "zero rows is red" property verdict.sh enforces, one level up: a scanner that found
  # nothing has proven nothing.
  rm -f "$work/wf/fixture.yml"
  cat >"$work/wf/fixture.yml" <<'EOF'
jobs:
  check:
    steps:
      - run: echo no services here
EOF
  probe "red: a scan that found no image at all (discovery floor)" expect-red

  # RED 6: a table whose own digest is malformed.
  write_wf "postgres:16@${pin_pg}" "valkey/valkey:8@${pin_vk}"
  printf 'mysql\tmysql:8\tlatest\tmysqladmin ping\t3306\t13306\t120\n' >>"$tbl"
  probe "red: a table row that is not pinned by a sha256 digest" expect-red

  # RED 7: ZERO ROWS IS RED, against the REAL verdict.sh on a genuinely empty ledger. Every gate in
  # this tree owes this proof; a gate that cannot demonstrate it has not adopted the inversion, only
  # its shape.
  : >"$work/empty.tsv"
  if GATE_NAME="service image pins" EXPECTED_IDS="images|table-readable" LEDGER="$work/empty.tsv" \
      bash "${repo}/testing/fleet-fixtures/verdict.sh" >/dev/null 2>&1; then
    say "  MISS: a ledger with zero rows was accepted as a verdict"
    failures=$((failures + 1))
  else
    say "  ok: zero rows is red (vacuous run), never a silent pass"
  fi

  if [ "$failures" -ne 0 ]; then
    say ""
    say "service-images-check self-test: RED — ${failures} expectation(s) did not hold. No verdict from this lint means anything until they do."
    return 1
  fi
  say ""
  say "service-images-check self-test: PASS."
  return 0
}

case "${1:-}" in
  --selftest) run_selftest ;;
  --help|-h) sed -n '2,${/^[^#]/q;p;}' "$0" | sed 's/^# \{0,1\}//' ;;
  "") run_check ;;
  *) printf 'unknown arg: %s\n' "$1" >&2; exit 2 ;;
esac
