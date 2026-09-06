#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# testing/fleet-fixtures/store-services.sh — the one-command way to stand the durable-store backends
# up on a laptop, and the namespace machinery the shadow oracle needs to record two binaries against
# them at once. See docs/design/store-qa-cycle.md, "Local docker for developers and unattended
# agents" and "Namespacing — the concurrency hazard the oracle creates".
#
# THE GAP THIS CLOSES. busbar has FOUR published durable stores (sqlite, postgres, mysql, valkey) and
# three of them need a server. Every provisioner of that server lived inside CI — four workflows and
# scripts/release-check.sh — so a developer, or an unattended agent, had no way at all to run
# testing/fleet-fixtures/probe-store.sh or testing/shadow-oracle/scripts/store-persist.sh against
# anything but sqlite. A check nobody can run on a laptop is a check nobody exercises against a real
# artifact before trusting it (testing/fleet-fixtures/lib.sh says this about the probes themselves;
# it is just as true of the fixtures the probes need).
#
# WHY NOT A COMPOSE FILE. There is no docker compose file anywhere in this repository, and adding one
# would make a FIFTH source of truth for the image pins the whole point of service-images.tsv is to
# collapse into one. scripts/release-check.sh already proves `docker run -d --rm` plus a `docker exec`
# readiness probe is sufficient; this file is that pattern, made reusable and pointed at the pinned
# digests instead of floating tags.
#
# USAGE
#   store-services.sh up   [postgres|mysql|valkey|all]   stand them up, PROVE readiness, exit 0
#   store-services.sh down [postgres|mysql|valkey|all]   remove them; safe when nothing is up
#   store-services.sh url  <service>                     print the base DSN on stdout, NOTHING else
#   store-services.sh ns   <service> <token>             create a per-run namespace, print ITS DSN
#   store-services.sh ns-drop  <service> <token>         drop that namespace; idempotent
#   store-services.sh ns-sweep <service>                 drop every leaked busbar_oracle_* namespace
#   store-services.sh status                             one line per service: up / down
#   store-services.sh --selftest                         prove this script's own rules, no docker
#
# PORTS — OFFSET, ON PURPOSE, TWICE OVER
#   15432 / 13306 / 16379, read from service-images.tsv, exactly the offsets release-check.sh uses.
#   They avoid a developer's OWN postgres on 5432 (the thing that makes a local run destructive), and
#   they are nowhere near the shadow oracle's own 487xx/488xx band (record.sh's 48811/48812/48781,
#   48813 for script cells, 48821/48822 for boot cells, and store-persist.sh's 48831/48832/48791).
#   Those two bands are disjoint and MUST STAY disjoint; --selftest asserts it rather than trusting it.
#
# READINESS IS PROVEN, NEVER SLEPT ON
#   pg_isready / mysqladmin ping / valkey-cli ping INSIDE the container, capped at the seconds
#   service-images.tsv pins (mysql's is 120, not 60: MySQL 8's first boot initialises the datadir and
#   restarts once). A poll that decides WHETHER THE TEST CAN BEGIN is not a retry; exceeding a cap is
#   a red that names the service and dumps `docker logs`, never a silent skip and never a re-run.
#
# NAMESPACES — THE CONCURRENCY HAZARD THE ORACLE CREATES
#   The shadow-oracle job records the golden AND the candidate in the same job against the same
#   services. Postgres and mysql are shared, non-reset databases, so two recordings writing the same
#   tables make each other's failure — and, worse, the candidate could READ THE GOLDEN'S ROWS and
#   appear to persist when it did not. `ns` hands each recording its own database (postgres, mysql) or
#   its own logical db index (valkey), created before record.sh starts and dropped after it exits. A
#   killed run leaks at most one empty database; `ns-sweep` removes the leaks.
#
#   valkey's teardown is FLUSHDB on that index. Never FLUSHALL: one recording must not be able to
#   erase another's.
#
# CREDENTIALS
#   `busbar:busbar` against a throwaway container is not a credential and is not treated as one. What
#   IS enforced: `url` and `ns` print to STDOUT for command substitution and log nothing, `set -x` is
#   never used on any path here, and no DSN is ever written to a file this repository tracks.
#
# CONTAINER NAMES. `busbar-store-qa-<svc>`, optionally suffixed by $BUSBAR_STORE_QA_TAG. The design
# doc sketches a `-$$` suffix under an EXIT trap; that shape belongs to a caller that owns the whole
# lifecycle in ONE process (release-check.sh does exactly that). It cannot be this script's default,
# because `up` and `down` are separate processes BY THE DOC'S OWN CLI — an EXIT trap in `up` would
# reap the container the moment `up` returned, and a `$$` name would be unfindable from `down`. So the
# name is stable, `--rm` still does the reaping, and $BUSBAR_STORE_QA_TAG is there for a caller that
# genuinely needs two sets at once. `down all` additionally sweeps every `busbar-store-qa-*`
# container, so a tagged or `$$`-suffixed leak from any caller is still removable by one command.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "${here}/../.." && pwd)"
IMAGES="${SERVICE_IMAGES_TSV:-${here}/service-images.tsv}"

# The three services this script can stand up. vault/wiremock/openldap are pinned in the same file
# (so the workflow-image lint is total) but are provisioned by other rigs; naming them here would
# claim a readiness contract this script does not implement.
STORE_SERVICES="postgres mysql valkey"

say() { printf '%s\n' "$*"; }
die() { printf 'store-services: %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,${/^[^#]/q;p;}' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

# ── the pinned image table ───────────────────────────────────────────────────────────────────────
# One reader, used by every verb AND by --selftest, so the self-test cannot pass against a parser the
# real path does not use.
tsv_field() {  # tsv_field <service> <1-based column>
  awk -F'\t' -v s="$1" -v c="$2" '
    /^[[:space:]]*#/ { next } NF < 7 { next }
    $1 == s { print $c; found = 1; exit }
    END { exit !found }
  ' "$IMAGES"
}

svc_image()  { tsv_field "$1" 2; }
svc_digest() { tsv_field "$1" 3; }
svc_probe()  { tsv_field "$1" 4; }
svc_port()   { tsv_field "$1" 5; }
svc_lport()  { tsv_field "$1" 6; }
svc_secs()   { tsv_field "$1" 7; }

svc_ref() {  # the fully pinned reference: image@digest, never a floating tag
  local img dig
  img="$(svc_image "$1")" || return 1
  dig="$(svc_digest "$1")" || return 1
  printf '%s@%s' "$img" "$dig"
}

container() { printf 'busbar-store-qa-%s%s' "$1" "${BUSBAR_STORE_QA_TAG:+-${BUSBAR_STORE_QA_TAG}}"; }

assert_known() {
  case " ${STORE_SERVICES} " in
    *" $1 "*) ;;
    *) die "unknown service '$1'. This script stands up: ${STORE_SERVICES}. (vault/wiremock/openldap are pinned in $(basename "$IMAGES") but provisioned by other rigs.)" ;;
  esac
  svc_image "$1" >/dev/null || die "service '$1' has no row in ${IMAGES}"
}

expand() {  # expand <arg> -> the service list
  case "${1:-all}" in
    all|"") printf '%s' "$STORE_SERVICES" ;;
    *) assert_known "$1"; printf '%s' "$1" ;;
  esac
}

need_docker() {
  command -v docker >/dev/null 2>&1 \
    || die "docker is not on PATH. This is the one dependency; there is no way to prove a store
persists across a process death without a server to persist into. On a host without docker the
oracle's store cells record a NAMED GAP (SKIP), never a pass — see docs/design/store-qa-cycle.md."
}

# A TOKEN GOES INTO DDL, SO IT IS VALIDATED, NOT TRUSTED. The token is a recording's output-directory
# basename plus a pid — but "the caller only ever passes something safe" is precisely the assumption
# that makes an injection. Anything outside [A-Za-z0-9_] is refused by name.
assert_token() {
  case "$1" in
    ""|*[!A-Za-z0-9_]*) die "namespace token '$1' is not [A-Za-z0-9_]+. It is interpolated into DDL; an unvalidated token is an injection, not an inconvenience." ;;
  esac
  [ "${#1}" -le 40 ] || die "namespace token '$1' is longer than 40 characters (postgres truncates identifiers at 63; the busbar_oracle_ prefix leaves 40)."
}

ns_db() { printf 'busbar_oracle_%s' "$1"; }

# valkey has no databases, only 16 numbered logical indexes. Index 0 is the BASE url's index, so a
# namespace never lands on it: a run that fell back to 0 would silently share with `url`'s callers,
# which is the exact interference the namespace exists to prevent.
ns_index() {
  local n
  n="$(printf '%s' "$1" | cksum | awk '{print ($1 % 15) + 1}')"
  printf '%s' "$n"
}

# ── verbs ────────────────────────────────────────────────────────────────────────────────────────
do_up() {
  need_docker
  local svc name ref lport secs probe waited
  for svc in $(expand "${1:-all}"); do
    name="$(container "$svc")"
    ref="$(svc_ref "$svc")"
    lport="$(svc_lport "$svc")"
    secs="$(svc_secs "$svc")"
    probe="$(svc_probe "$svc")"
    if docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null | grep -q true; then
      say "  ${svc}: already up as ${name} on 127.0.0.1:${lport}"
      continue
    fi
    say "  ${svc}: docker run ${ref} -> 127.0.0.1:${lport}"
    case "$svc" in
      postgres)
        docker run -d --rm --name "$name" \
          -e POSTGRES_USER=busbar -e POSTGRES_PASSWORD=busbar -e POSTGRES_DB=busbar_store_qa \
          -p "${lport}:$(svc_port "$svc")" "$ref" >/dev/null || die "docker run failed for ${svc}" ;;
      mysql)
        docker run -d --rm --name "$name" \
          -e MYSQL_ROOT_PASSWORD=busbar -e MYSQL_USER=busbar -e MYSQL_PASSWORD=busbar \
          -e MYSQL_DATABASE=busbar_store_qa \
          -p "${lport}:$(svc_port "$svc")" "$ref" >/dev/null || die "docker run failed for ${svc}" ;;
      valkey)
        docker run -d --rm --name "$name" \
          -p "${lport}:$(svc_port "$svc")" "$ref" >/dev/null || die "docker run failed for ${svc}" ;;
    esac
    # READINESS IS PROVEN. The probe runs inside the container and its cap comes from the pinned
    # table, so mysql's 120 s datadir initialisation is a fact in a file rather than a number
    # somebody remembered. Exceeding the cap dumps the container's own logs and is RED.
    say "  ${svc}: waiting for readiness (${probe}), cap ${secs}s"
    waited=0
    # shellcheck disable=SC2086  # $probe is a pinned command line from the table, split on purpose
    until docker exec "$name" $probe >/dev/null 2>&1; do
      waited=$((waited + 1))
      if [ "$waited" -ge "$secs" ]; then
        docker logs "$name" >&2 2>/dev/null || true
        die "${svc} did not become ready within ${secs}s. A service that did not come up is a HARD RED on any promotion branch or PR: a store that could not be tested has not been tested."
      fi
      sleep 1
    done
    say "  ${svc}: ready after ${waited}s"
  done
}

do_down() {
  command -v docker >/dev/null 2>&1 || { say "docker is not on PATH; nothing to bring down."; return 0; }
  local svc name
  for svc in $(expand "${1:-all}"); do
    name="$(container "$svc")"
    docker rm -f "$name" >/dev/null 2>&1 && say "  ${svc}: removed ${name}" || say "  ${svc}: nothing to remove"
  done
  # THE THIRD TEARDOWN LAYER. A container that SURVIVED and answers the next run's probe with
  # someone else's data is the failure that matters, so `down all` sweeps every container this file's
  # naming scheme could have produced — including a $BUSBAR_STORE_QA_TAG or `-$$` suffixed one left
  # by a caller that died before its own trap fired.
  if [ "${1:-all}" = "all" ]; then
    docker ps -aq --filter 'name=^busbar-store-qa-' 2>/dev/null | while read -r cid; do
      [ -n "$cid" ] || continue
      docker rm -f "$cid" >/dev/null 2>&1 && say "  swept leaked container ${cid}"
    done
  fi
}

do_url() {  # STDOUT IS THE DSN AND NOTHING ELSE — this is consumed by command substitution
  local svc="$1"
  assert_known "$svc"
  local lport; lport="$(svc_lport "$svc")"
  case "$svc" in
    postgres) printf 'postgres://busbar:busbar@127.0.0.1:%s/busbar_store_qa\n' "$lport" ;;
    mysql)    printf 'mysql://busbar:busbar@127.0.0.1:%s/busbar_store_qa\n' "$lport" ;;
    valkey)   printf 'redis://127.0.0.1:%s/0\n' "$lport" ;;
  esac
}

do_ns() {
  local svc="$1" token="$2"
  assert_known "$svc"; assert_token "$token"
  local lport db; lport="$(svc_lport "$svc")"; db="$(ns_db "$token")"
  case "$svc" in
    postgres)
      need_docker
      docker exec "$(container "$svc")" psql -U busbar -d busbar_store_qa -v ON_ERROR_STOP=1 \
        -c "CREATE DATABASE ${db}" >/dev/null 2>&1 \
        || die "could not create namespace database ${db} on postgres"
      printf 'postgres://busbar:busbar@127.0.0.1:%s/%s\n' "$lport" "$db" ;;
    mysql)
      need_docker
      docker exec "$(container "$svc")" mysql -ubusbar -pbusbar \
        -e "CREATE DATABASE IF NOT EXISTS ${db}" >/dev/null 2>&1 \
        || die "could not create namespace database ${db} on mysql"
      printf 'mysql://busbar:busbar@127.0.0.1:%s/%s\n' "$lport" "$db" ;;
    valkey)
      printf 'redis://127.0.0.1:%s/%s\n' "$lport" "$(ns_index "$token")" ;;
  esac
}

do_ns_drop() {
  local svc="$1" token="$2"
  assert_known "$svc"; assert_token "$token"
  need_docker
  local db; db="$(ns_db "$token")"
  case "$svc" in
    postgres) docker exec "$(container "$svc")" psql -U busbar -d busbar_store_qa \
                -c "DROP DATABASE IF EXISTS ${db}" >/dev/null 2>&1 || true ;;
    mysql)    docker exec "$(container "$svc")" mysql -ubusbar -pbusbar \
                -e "DROP DATABASE IF EXISTS ${db}" >/dev/null 2>&1 || true ;;
    # FLUSHDB on THIS index, never FLUSHALL: one recording must not be able to erase another's.
    valkey)   docker exec "$(container "$svc")" valkey-cli -n "$(ns_index "$token")" FLUSHDB >/dev/null 2>&1 || true ;;
  esac
  say "  ${svc}: namespace ${token} dropped"
}

do_ns_sweep() {
  local svc="$1"
  assert_known "$svc"; need_docker
  case "$svc" in
    postgres)
      docker exec "$(container "$svc")" psql -U busbar -d busbar_store_qa -At \
        -c "SELECT datname FROM pg_database WHERE datname LIKE 'busbar\\_oracle\\_%'" 2>/dev/null \
      | while read -r db; do
          [ -n "$db" ] || continue
          docker exec "$(container "$svc")" psql -U busbar -d busbar_store_qa \
            -c "DROP DATABASE IF EXISTS ${db}" >/dev/null 2>&1 && say "  swept ${db}"
        done ;;
    mysql)
      docker exec "$(container "$svc")" mysql -ubusbar -pbusbar -N -B \
        -e "SELECT schema_name FROM information_schema.schemata WHERE schema_name LIKE 'busbar\\_oracle\\_%'" 2>/dev/null \
      | while read -r db; do
          [ -n "$db" ] || continue
          docker exec "$(container "$svc")" mysql -ubusbar -pbusbar \
            -e "DROP DATABASE IF EXISTS ${db}" >/dev/null 2>&1 && say "  swept ${db}"
        done ;;
    valkey) say "  valkey namespaces are logical db indexes; nothing accumulates to sweep." ;;
  esac
}

do_status() {
  local svc name state
  for svc in $STORE_SERVICES; do
    name="$(container "$svc")"
    if command -v docker >/dev/null 2>&1 \
       && docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null | grep -q true; then
      state="up   127.0.0.1:$(svc_lport "$svc")  $(svc_ref "$svc")"
    else
      state="down"
    fi
    printf '%-10s %s\n' "$svc" "$state"
  done
}

# ── --selftest ───────────────────────────────────────────────────────────────────────────────────
# NO DOCKER. Everything below is a property of the TABLE and of this script's own rules, and every
# one of them is a way this fixture could go quietly wrong: a port band that drifted into the
# oracle's, a floating tag that crept back in, a namespace token that reaches DDL unvalidated, two
# services sharing a host port. Decided through the SAME ledger-and-verdict inversion every gate in
# this tree uses (testing/fleet-fixtures/lib.sh + verdict.sh) — every check records exactly one row
# and NOTHING controls flow, so no check can mask another, an owed row that never appeared is DID NOT
# RUN, and ZERO ROWS IS RED.
run_selftest() {
  local work="${repo}/.qa-work/store-services-selftest"
  rm -rf "$work"; mkdir -p "$work"
  export LEDGER="${work}/ledger.tsv"; : >"$LEDGER"
  export GATE_NAME="store service fixtures"
  # shellcheck source=./lib.sh
  source "${here}/lib.sh"

  local owed=""
  owe() { owed="${owed} $1"; }

  # 1. Every service this script claims to stand up has a complete row.
  local svc missing=""
  for svc in $STORE_SERVICES; do
    svc_ref "$svc" >/dev/null 2>&1 || missing="${missing}${svc} "
  done
  owe "fixtures|table-complete"
  if [ -z "$missing" ]; then
    record "fixtures|table-complete" PASS "every store service has a pinned row" "$(printf '%s' "$STORE_SERVICES")"
  else
    record "fixtures|table-complete" FAIL "a store service has no row in service-images.tsv" "missing: ${missing}"
  fi

  # 2. EVERY row is pinned by digest. A floating tag in this file would re-open the exact hole the
  #    file exists to close (release-check.sh's `postgres:16`), and it would do it invisibly.
  local unpinned
  unpinned="$(awk -F'\t' '/^[[:space:]]*#/ {next} NF>=3 && $3 !~ /^sha256:[0-9a-f]{64}$/ {print $1}' "$IMAGES" | tr '\n' ' ')"
  owe "fixtures|every-row-digest-pinned"
  if [ -z "$unpinned" ]; then
    record "fixtures|every-row-digest-pinned" PASS "every row carries a sha256: digest" \
      "$(awk -F'\t' '/^[[:space:]]*#/{next} NF>=3{n++} END{print n+0}' "$IMAGES") row(s)"
  else
    record "fixtures|every-row-digest-pinned" FAIL "a row is not pinned by digest" "unpinned: ${unpinned}"
  fi

  # 3. THE TWO PORT BANDS ARE DISJOINT. The oracle derives its ports in 48781–48899; every
  #    local_port here must sit outside it, and outside the default ports a developer's own servers
  #    use. This is the check that stops a well-meaning "just use 5432" from eating somebody's data.
  local bad_ports=""
  while IFS= read -r p; do
    [ -n "$p" ] && [ "$p" != "-" ] || continue
    if [ "$p" -ge 48700 ] && [ "$p" -le 48999 ]; then bad_ports="${bad_ports}${p} "; fi
    case "$p" in 5432|3306|6379|8200) bad_ports="${bad_ports}${p} " ;; esac
  done <<<"$(awk -F'\t' '/^[[:space:]]*#/{next} NF>=6{print $6}' "$IMAGES")"
  owe "fixtures|port-bands-disjoint"
  if [ -z "$bad_ports" ]; then
    record "fixtures|port-bands-disjoint" PASS "no local port collides with the oracle band or a default" \
      "15432/13306/16379/18200, oracle band 48700-48999 untouched"
  else
    record "fixtures|port-bands-disjoint" FAIL "a local port sits in the oracle band or on a service default" "offending: ${bad_ports}"
  fi

  # 4. No two services publish on the same host port.
  local dupes
  dupes="$(awk -F'\t' '/^[[:space:]]*#/{next} NF>=6 && $6 != "-" {print $6}' "$IMAGES" | sort | uniq -d | tr '\n' ' ')"
  owe "fixtures|local-ports-unique"
  if [ -z "$dupes" ]; then
    record "fixtures|local-ports-unique" PASS "every local port is claimed by exactly one service" ""
  else
    record "fixtures|local-ports-unique" FAIL "two services publish on the same host port" "duplicated: ${dupes}"
  fi

  # 5. mysql's readiness cap is the measured 120 s, not the 60 s everything else gets. This has a row
  #    of its own because "make them all 60" is the plausible tidy-up that reintroduces a flake nobody
  #    can reproduce: MySQL 8's first boot initialises the datadir and restarts once.
  owe "fixtures|mysql-cap-120"
  if [ "$(svc_secs mysql)" = "120" ]; then
    record "fixtures|mysql-cap-120" PASS "mysql's readiness cap is 120s (first-boot datadir init)" ""
  else
    record "fixtures|mysql-cap-120" FAIL "mysql's readiness cap is not 120s" "found: $(svc_secs mysql)"
  fi

  # 6. RED-PROOF: an unknown service is refused, not silently treated as 'all'.
  owe "fixtures|unknown-service-refused"
  if ( assert_known "definitely-not-a-service" ) >/dev/null 2>&1; then
    record "fixtures|unknown-service-refused" FAIL "an unknown service name was ACCEPTED" \
      "assert_known returned 0 for a name with no row"
  else
    record "fixtures|unknown-service-refused" PASS "an unknown service name is refused by name" ""
  fi

  # 7. RED-PROOF: a namespace token that could reach DDL as SQL is refused. Runs the REAL
  #    assert_token, not a re-implementation of its regex.
  local injected=0 t
  for t in 'a; DROP DATABASE busbar_store_qa' 'a-b' '' 'a$(id)' "a'b"; do
    if ( assert_token "$t" ) >/dev/null 2>&1; then injected=$((injected + 1)); fi
  done
  owe "fixtures|ddl-token-validated"
  if [ "$injected" -eq 0 ]; then
    record "fixtures|ddl-token-validated" PASS "every unsafe namespace token is refused" "5 fixtures, 0 accepted"
  else
    record "fixtures|ddl-token-validated" FAIL "an unsafe namespace token was accepted into DDL" "${injected} of 5 fixtures accepted"
  fi
  owe "fixtures|ddl-token-accepts-real"
  if ( assert_token "goldenstore_41277" ) >/dev/null 2>&1; then
    record "fixtures|ddl-token-accepts-real" PASS "a real recording token is accepted" "goldenstore_41277"
  else
    record "fixtures|ddl-token-accepts-real" FAIL "a legitimate recording token was refused" \
      "the validator is too strict to be usable, which makes callers route around it"
  fi

  # 8. A valkey namespace NEVER lands on index 0 — index 0 is what `url` hands out, so a namespace
  #    that fell back to it would silently share with the very callers it exists to isolate.
  local zero=0 i
  for i in a b c d e f g h golden candidate goldenstore_1 goldenstore_2 cand_991 x1 x2 x3; do
    [ "$(ns_index "$i")" = "0" ] && zero=$((zero + 1))
  done
  owe "fixtures|valkey-ns-never-zero"
  if [ "$zero" -eq 0 ]; then
    record "fixtures|valkey-ns-never-zero" PASS "no namespace token maps to valkey db index 0" "16 tokens"
  else
    record "fixtures|valkey-ns-never-zero" FAIL "a namespace token mapped to index 0, which \`url\` also hands out" "${zero} of 16"
  fi

  # 9. `url` prints ONE line and nothing else — it is consumed by command substitution, and a helpful
  #    banner on stdout would be pasted into a DSN.
  local lines
  lines="$(do_url postgres | wc -l | tr -d ' ')"
  owe "fixtures|url-is-one-line"
  if [ "$lines" = "1" ] && do_url postgres | grep -q '^postgres://busbar:busbar@127\.0\.0\.1:15432/'; then
    record "fixtures|url-is-one-line" PASS "url prints exactly the DSN, one line" "$(do_url postgres | sed 's/busbar:busbar/REDACTED/')"
  else
    record "fixtures|url-is-one-line" FAIL "url did not print exactly one DSN line" "${lines} line(s)"
  fi

  # 10. `down` is safe with nothing up and safe with no docker at all — the doc's own contract, and
  #     the difference between a fixture an agent can call unattended and one it must guard.
  owe "fixtures|down-is-idempotent"
  if ( PATH="/nonexistent" do_down all ) >/dev/null 2>&1; then
    record "fixtures|down-is-idempotent" PASS "down exits 0 with nothing up and no docker on PATH" ""
  else
    record "fixtures|down-is-idempotent" FAIL "down did not exit 0 when there was nothing to do" \
      "an unattended caller cannot use a teardown that fails when it succeeds"
  fi

  # 11. Every image: line in .github/workflows/ is covered by this table. The dedicated lint
  #     (scripts/service-images-check.sh) is the gate; this row is the fixture's own smoke test that
  #     the table it publishes is the one CI actually uses.
  owe "fixtures|lint-agrees"
  if bash "${repo}/scripts/service-images-check.sh" >/dev/null 2>&1; then
    record "fixtures|lint-agrees" PASS "scripts/service-images-check.sh is green against this table" ""
  else
    record "fixtures|lint-agrees" FAIL "the workflow-image lint is red against this table" \
      "run scripts/service-images-check.sh for the rows"
  fi

  GATE_NAME="store service fixtures" EXPECTED_IDS="$owed" LEDGER="$LEDGER" \
    bash "${here}/verdict.sh"
}

case "${1:-}" in
  up)       shift; do_up "${1:-all}" ;;
  down)     shift; do_down "${1:-all}" ;;
  url)      shift; [ $# -ge 1 ] || usage 2; do_url "$1" ;;
  ns)       shift; [ $# -ge 2 ] || usage 2; do_ns "$1" "$2" ;;
  ns-drop)  shift; [ $# -ge 2 ] || usage 2; do_ns_drop "$1" "$2" ;;
  ns-sweep) shift; [ $# -ge 1 ] || usage 2; do_ns_sweep "$1" ;;
  status)   do_status ;;
  --selftest) run_selftest ;;
  --help|-h|"") usage 0 ;;
  *) printf 'unknown verb: %s\n' "$1" >&2; usage 2 ;;
esac
