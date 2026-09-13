#!/usr/bin/env bash
# `bash -n` and `shellcheck -x` over every script that keeps the runner fleet alive.
#
#   ./scripts/ci-runners-lint.sh
#
# WHY THIS IS A SCRIPT AND NOT A LINE IN A RUNBOOK. These scripts are the thing that brings CI back
# when CI is down, so they are the one place where "it has a syntax error" is discovered at exactly
# the moment nobody can afford to discover it. `shellcheck -x` follows the `source=` directive into
# ci-runners-lib.sh, so a helper renamed in the library is caught here rather than at 03:00 by an
# unset variable in a top-up loop.
#
# EVERY SUPPRESSION IN THESE FILES IS INLINE AND CARRIES ITS REASON. There is no config file and no
# blanket exclude list, because a blanket exclude is how a real finding gets to hide behind a
# deliberate one. The two that recur: SC2086 on `--instance-ids $LIST` (AWS wants separate argv
# entries, so the word-splitting is the point) and SC2016 on `'$Latest'` (EC2's literal
# launch-template version alias) and on JMESPath backticks.
#
# scripts/ci-runner-bootstrap.sh is deliberately NOT in this list. It is a user-data TEMPLATE, not a
# script that runs here: it carries `__PLACEHOLDER__` tokens that ci-runners-up.sh substitutes, its
# "unused" variables are consumed by the here-docs it writes out on the box, and its one SC2086 is
# an intentional split of SCCACHE_ENV. It is also gzipped into a 16384-byte user-data budget, so
# every suppression comment added to it is bytes spent against the cap that broke the fleet once
# already. Lint it by hand when it changes; do not add it here.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v shellcheck >/dev/null || {
  echo "shellcheck is not installed: brew install shellcheck" >&2
  exit 2
}

rc=0
for f in "$HERE"/ci-runners-lib.sh "$HERE"/ci-runners-up.sh "$HERE"/ci-runners-register.sh \
         "$HERE"/ci-runners-reconcile.sh "$HERE"/ci-runners-down.sh "$HERE"/ci-runners-ssh.sh \
         "$HERE"/ci-runners-lint.sh "$HERE"/ci-runners-selftest.sh "$HERE"/ci-remote-lib.sh; do
  printf '%-34s ' "$(basename "$f")"
  if bash -n "$f" 2>/dev/null; then printf 'bash -n: OK   '; else printf 'bash -n: FAIL '; rc=1; fi
  if shellcheck -x "$f"; then
    echo 'shellcheck: CLEAN'
  else
    echo 'shellcheck: FINDINGS (above)'
    rc=1
  fi
done
exit "$rc"
