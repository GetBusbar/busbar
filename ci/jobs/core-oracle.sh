#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# core-oracle: the assembled product replays the 1.5.5 recording with the same answers.
#
#   ci/jobs/core-oracle.sh shard   one of N shards (GitLab `parallel: N`, CI_NODE_INDEX of
#                                  CI_NODE_TOTAL): bin/oracle ci-run records this shard's cells
#                                  from the candidate and replays them --strict against
#                                  testing/shadow-oracle/golden/1.5.5. Red on any difference the
#                                  owner did not sign (accepted-differences.json), on a shard that
#                                  did not select every cell it owns, and on a replay that judged
#                                  nothing.
#   ci/jobs/core-oracle.sh merge   one verdict from the N shard reports (bin/oracle shard-merge):
#                                  green only for shards 1..N, each once, each green, together
#                                  every cell of cells.json.
#
# The judge is the signed busbar-oracle the protected pin ci/native-oracle.json names
# (ci/lib/oracle-judge.sh). The golden is the tree BUSBAR_GOLDEN_1_5_5_TREE names (the
# pipeline configuration, never the candidate); bin/oracle reads it from the object database
# and refuses a candidate whose golden/1.5.5 is any other tree, and golden-guard holds it
# add-only against ORACLE_BASE_SHA. Nothing here edits the golden or accepts a difference.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=ci/lib/oracle-judge.sh
. "$root/ci/lib/oracle-judge.sh"

mode="${1:-}"
out="$root/oracle-shards"

# Forge-only sources: GetBusbar repositories and the reviewed upstream forks come from the
# canonical forge (scripts/architecture/native_sources.py UPSTREAM_FORKS); any other github.com
# Git URL is rewritten to an unroutable host so a stray fetch fails loudly. Git applies the
# longest matching insteadOf. Cargo uses the git CLI so the same mapping reaches its git deps.
forge_sources() {
  local server="${CI_SERVER_URL:-https://github.com}" n=0 pair
  server="${server%/}"
  add() { export "GIT_CONFIG_KEY_$n=$1" "GIT_CONFIG_VALUE_$n=$2"; n=$((n + 1)); }
  if [ -n "${CI_JOB_TOKEN:-}" ]; then
    add "http.$server/.extraheader" "Authorization: Basic $(printf 'gitlab-ci-token:%s' "$CI_JOB_TOKEN" | base64 | tr -d '\n')"
  fi
  add "url.$server/GetBusbar/.insteadOf" "https://github.com/GetBusbar/"
  for pair in MattJackson/aws-lc-sys:aws-lc-sys MattJackson/jobserver-rs:jobserver-rs \
      MattJackson/rust-stringprep:rust-stringprep MattJackson/dunce:dunce MattJackson/fs_extra:fs_extra \
      MattJackson/h2:h2 MattJackson/tungstenite-rs:tungstenite-rs headroomlabs-ai/headroom:headroom; do
    add "url.$server/GetBusbar/upstream-forks/${pair#*:}.insteadOf" "https://github.com/${pair%%:*}"
  done
  add "url.https://public-replica-refused.invalid/.insteadOf" "https://github.com/"
  export GIT_CONFIG_COUNT="$n" GIT_TERMINAL_PROMPT=0 CARGO_NET_GIT_FETCH_WITH_CLI=true
}

golden_pinned() {
  local want="${BUSBAR_GOLDEN_1_5_5_TREE:-}" got
  [[ "$want" =~ ^[0-9a-f]{40}$ ]] || oracle_refuse "the pipeline configuration names no 40-hex BUSBAR_GOLDEN_1_5_5_TREE"
  got="$(git rev-parse -q --verify "HEAD:testing/shadow-oracle/golden/1.5.5" 2>/dev/null)" || got="<none>"
  [ "$got" = "$want" ] \
    || oracle_refuse "the candidate's testing/shadow-oracle/golden/1.5.5 is tree $got, the configuration pins $want (the golden is never edited here)"
}

# The add-only base: the merge request's diff base, else the push's previous head. API and
# schedule pipelines have none; the exact tree pin above still holds the golden.
oracle_base() {
  local base="${CI_MERGE_REQUEST_DIFF_BASE_SHA:-${CI_COMMIT_BEFORE_SHA:-}}"
  case "$base" in ""|0000000000000000000000000000000000000000) base="" ;; esac
  printf '%s' "$base"
}

case "$mode" in
  shard)
    k="${CI_NODE_INDEX:-}" n="${CI_NODE_TOTAL:-}"
    [[ "$k" =~ ^[0-9]+$ && "$n" =~ ^[0-9]+$ ]] && [ "$n" -gt 1 ] && [ "$k" -ge 1 ] && [ "$k" -le "$n" ] \
      || oracle_refuse "a shard needs CI_NODE_INDEX in 1..CI_NODE_TOTAL with CI_NODE_TOTAL > 1 (got '${k}' of '${n}')"
    golden_pinned
    forge_sources
    oracle_judge_stage "$root"
    ORACLE_BASE_SHA="$(oracle_base)"; export ORACLE_BASE_SHA
    # bin/oracle names a shard i/N with i from 0.
    export ORACLE_SHARD="$((k - 1))/$n"
    unset MODERNCI_SHARD MODERNCI_SHARD_INDEX MODERNCI_SHARD_COUNT
    echo "core-oracle: shard $k of $n, add-only base ${ORACLE_BASE_SHA:-none}, golden tree $BUSBAR_GOLDEN_1_5_5_TREE"
    bin/oracle shard-cover "$n"
    rc=0
    bin/oracle ci-run || rc=$?
    rm -rf "$out"; mkdir -p "$out/$k"
    if [ -d target/oracle/reports/dev ]; then cp -R target/oracle/reports/dev/. "$out/$k/"; fi
    [ -f "$out/$k/shard.tsv" ] || printf '%s\t%s\t%s\n' "$k" "$n" "$([ "$rc" -ne 0 ] && echo "$rc" || echo 1)" >"$out/$k/shard.tsv"
    [ "$rc" -eq 0 ] || echo "refused: core-oracle: shard $k of $n is red (bin/oracle ci-run exit $rc); the differing cells are listed above and in $out/$k" >&2
    exit "$rc"
    ;;
  merge)
    n="${ORACLE_SHARDS:-}"
    [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -gt 1 ] || oracle_refuse "ORACLE_SHARDS must name the shard count"
    dirs=()
    for k in $(seq 1 "$n"); do
      [ -d "$out/$k" ] || oracle_refuse "no report from shard $k of $n (its job did not run or kept no artifact)"
      dirs+=("$out/$k")
    done
    extra="$(find "$out" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
    [ "$extra" = "$n" ] || oracle_refuse "$extra shard reports for $n shards"
    for d in "${dirs[@]}"; do echo "core-oracle: $(basename "$d"): $(tr '\t' ' ' <"$d/shard.tsv")"; done
    bin/oracle shard-cover "$n"
    bin/oracle shard-merge "${dirs[@]}" || oracle_refuse "the shards do not give one green verdict over every cell"
    ;;
  *)
    echo "usage: ci/jobs/core-oracle.sh shard|merge" >&2
    exit 2
    ;;
esac
