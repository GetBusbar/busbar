#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Shared provenance helpers for the shadow oracle. A golden or candidate recording only proves
# anything about busbar if we also know two things about how it was made:
#
#   harness_rev    which revision of the FILES THAT DECIDE WHAT GETS RECORDED AND HOW IT IS
#                  COMPARED produced it: cells.json, every *.py beside this file, oracle-config.sh,
#                  record.sh, renormalize.sh, everything under scripts/, fixtures/*.json, the two
#                  digest pins (golden-digests.tsv, plugin-digests.tsv), the comparison register
#                  (accepted-differences.json, owed-baseline.txt) and testing/fleet-fixtures/lib.sh
#                  (record.sh and all 20 drivers source it) — names as well as bytes.
#                  `harness_rev_files` prints that list, repo-relative.
#                  This is the SAME file list ci.yml hashes for its shadow-oracle cache key —
#                  computed here, in one place, so record.sh, diff-cells.py and ci.yml can never
#                  quietly drift onto different definitions of "the harness changed".
#   binary_sha256  which exact binary file produced it (sha256 of the file's bytes).
#
# Usable two ways:
#   source testing/shadow-oracle/harness-rev.sh    # then call harness_rev / binary_sha256 / host_triple
#   bash testing/shadow-oracle/harness-rev.sh       # prints "harness_rev <hash>" (ci.yml, humans)
set -uo pipefail
_hr_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

_hr_sha256_stdin() {  # read bytes on stdin, print the hex digest
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1
  else shasum -a 256 | cut -d' ' -f1; fi
}

sha256_of() {  # sha256_of <file> -> hex digest
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

binary_sha256() { sha256_of "$1"; }  # binary_sha256 <path-to-busbar-binary>

_hr_files() {  # print, one per line, every file whose contents decide what gets recorded and how
  # it is compared — absolute paths, in LC_ALL=C order. ONE list: harness_rev() hashes it,
  # harness_rev_files prints it for humans, and land.sh asks it whether a set of picked commits
  # touched the harness at all. Two lists would drift, and a drifted list is the whole bug class.
  #
  # WHOLE DIRECTORIES, NOT A HAND-KEPT LIST OF NAMES. The old globs named `normalize.py`,
  # `capture*.py`, `build-request.py` and `scripts/*.sh` one by one, so apply-mutation.py (which
  # rewrites the config a mutation cell is recorded against) and scripts/apply-deferred-decisions.py
  # (which supplies the decisions a migrated corpus config is validated with) could change without
  # moving the rev — CI would then restore a golden recorded under different config-shaping code and
  # diff-cells' skew guard would see nothing to complain about. `*.py` and `scripts/*` close that by
  # construction: a new helper is covered the day it lands, not the day someone remembers.
  #
  # The two digest pins are in the set for the same reason: a re-pinned golden binary or plugin is a
  # different harness even though no code changed.
  #
  # FOUR FILES WERE MISSING, AND EACH OF THEM DECIDES A RECORDING:
  #   ../fleet-fixtures/lib.sh      record.sh sources it and so does every one of the 20 drivers.
  #                                 It supplies `record`, the ledger row writer — the function that
  #                                 turns a cell's outcome into the PASS/FAIL the golden ledger
  #                                 carries and diff-cells reads to decide what is OWED. It lives
  #                                 outside this directory, which is the only reason it was never in
  #                                 the set; a change to it changes every cell in every recording
  #                                 while the rev sat still and the skew guard stayed quiet.
  #   renormalize.sh                rewrites the normalized cells of an EXISTING recording in place.
  #                                 A recording it has touched is not the recording record.sh made,
  #                                 and nothing else in the set can see that it ran.
  #   accepted-differences.json     the register of divergences the differ FORGIVES. Recording and
  #                                 comparison are the two halves of "how this golden was made and
  #                                 read"; a widened waiver changes the verdict on identical bytes.
  #   owed-baseline.txt             the set of ids the golden must not stop owing. It is the floor
  #                                 the replay is measured against, so it decides the verdict too.
  #
  # NAMES ARE HASHED ALONGSIDE THE BYTES. Concatenated contents alone cannot see a file being added
  # or removed (an empty new fixture, a deleted script) — and both change what gets recorded.
  # LC_ALL=C fixes the glob order, or the same tree hashes differently under a different locale.
  #   FOUR MORE DECIDE THE VERDICT, NOT THE RECORDING, AND WERE OUTSIDE THE SET. The rule this file
  #   states is "what gets recorded AND HOW IT IS COMPARED" — it is that second half that puts
  #   accepted-differences.json and owed-baseline.txt in the set, since neither is executed while
  #   recording and both change the verdict on identical bytes. By the same argument:
  #     replay.sh                 the comparison DRIVER: the owed-baseline regression check, the
  #                               golden-binary provenance gate and the skew plumbing all live here,
  #                               so an edit to it gives the same two recordings a different verdict.
  #     ../fleet-fixtures/verdict.sh
  #                               its own header: "This is the ONLY place the gate decides anything."
  #                               lib.sh was in the set for WRITING a ledger row; the file that turns
  #                               those rows into red or green was not.
  #     accepted-gaps.json        the register that forgives an owed-baseline regression with an
  #                               owner and a rationale — the same shape, and the same power, as
  #                               accepted-differences.json beside it.
  #     harness-rev.sh            the definition of the set itself. Dropping a file from the list
  #                               moved the hash only because that file's bytes left it; changing how
  #                               the list is built or hashed did not move it at all.
  #   rigs-baseline.json is deliberately NOT here: it is the sign-off floor of the SEPARATE plane-rigs
  #   gate (rigs-ledger.sh), which has its own verdict and never reads an LLM-plane recording.
  local d="$_hr_here" f
  (
    LC_ALL=C
    for f in "$d/cells.json" "$d"/*.py "$d/oracle-config.sh" "$d/record.sh" "$d/renormalize.sh" \
             "$d/replay.sh" "$d/harness-rev.sh" \
             "$d"/scripts/* "$d"/fixtures/*.json "$d/golden-digests.tsv" "$d/plugin-digests.tsv" \
             "$d/accepted-differences.json" "$d/accepted-gaps.json" "$d/owed-baseline.txt" \
             "$d/../fleet-fixtures/lib.sh" "$d/../fleet-fixtures/verdict.sh"; do
      [ -f "$f" ] || continue
      printf '%s\n' "$f"
    done
  )
}

_hr_repo() { (cd "$_hr_here/../.." && pwd); }

harness_rev_files() {  # the same set, as repo-relative paths (ci.yml's cache key, land.sh, humans)
  local repo; repo="$(_hr_repo)" || return 1
  _hr_files | while IFS= read -r f; do
    printf '%s\n' "$( (cd "$(dirname "$f")" && pwd) )/$(basename "$f")"
  done | sed "s|^${repo}/||"
}

harness_rev() {  # sha256 over the exact file set ci.yml's shadow-oracle cache key hashes
  local f repo; repo="$(_hr_repo)"
  (
    LC_ALL=C
    _hr_files | while IFS= read -r f; do
      # the REPO-RELATIVE name, so a file outside testing/shadow-oracle (fleet-fixtures/lib.sh) has
      # a stable name in the hash rather than a `../` that depends on where the set is rooted
      printf '%s\n' "$( (cd "$(dirname "$f")" && pwd) )/$(basename "$f")" | sed "s|^${repo}/||"
      cat "$f"
    done
  ) | _hr_sha256_stdin
}

host_triple() {  # the running machine's target triple, as busbar release assets name it
  case "$(uname -sm)" in
    "Darwin arm64") echo aarch64-apple-darwin ;;
    "Darwin x86_64") echo x86_64-apple-darwin ;;
    "Linux aarch64"|"Linux arm64") echo aarch64-unknown-linux-gnu ;;
    "Linux x86_64") echo x86_64-unknown-linux-gnu ;;
    *) echo "unknown-$(uname -sm | tr ' ' '-')" ;;
  esac
}

# Run directly (not sourced): print the harness revision, e.g. for ci.yml's cache key or a human
# checking whether their tree still matches a cached golden.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  # `--files`: the repo-relative file list, one per line — the SAME set the hash above is taken over,
  # so a caller asking "did this change touch the harness?" and the rev itself can never answer
  # differently. No caller asks today: land.sh diffs against the one committed golden and has no skew
  # flag to earn, so this exists for humans and for whatever next needs the set rather than the hash.
  if [ "${1:-}" = "--files" ]; then harness_rev_files; else echo "harness_rev $(harness_rev)"; fi
fi
