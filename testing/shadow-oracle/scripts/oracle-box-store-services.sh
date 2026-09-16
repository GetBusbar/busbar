#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# ORACLE-BOX STORE-SERVICE PROVISIONING RECIPE.
#
# WHY THIS EXISTS. Three of the shadow-oracle's store-persist cells --
#   plugins.store-persist|store-postgres, |store-mysql, |store-valkey --
# boot a PUBLISHED first-party store plugin (postgres v1.0.6, mysql v1.0.6, valkey v1.0.7) as the
# binary's `store:` and drive a REAL double boot against a LIVE network backend (see
# store-persist.sh: validate -> boot -> mint -> spend -> KILL -> boot again -> read the key and its
# usage back). store-persist.sh gates each cell on one env var carrying the backend's connection
# URL (the same map cells/__init__.py's STORE_FIXTURE_ENV enumerate-cells.py uses to decide the
# cell's skip condition):
#     store-postgres -> BUSBAR_TEST_POSTGRES_URL
#     store-mysql    -> BUSBAR_TEST_MYSQL_URL
#     store-valkey   -> VALKEY_URL
# With none of those set the recorder SKIPs the cell (needs_fixture) and the ledger shows a named
# gap instead of the PASS the pinned golden/1.5.5 carries -- so a candidate record on a box with no
# live backend can never reproduce the golden's three store PASS rows. This script brings the three
# backends up on the box via docker, exports the three URL vars in the EXACT scheme/port each
# plugin's driver expects, and waits until each is actually reachable, so a candidate record on the
# box records these three cells PASS and matches the golden.
#
# store-sqlite needs nothing here: its fixture is a path in the cell's own work dir, so it records
# from the tree alone and is not gated.
#
# USAGE
#   source testing/shadow-oracle/scripts/oracle-box-store-services.sh up
#       bring the three containers up, wait for readiness, and EXPORT the three URL vars INTO THE
#       CURRENT SHELL (source it -- a child process cannot export back into the recorder's shell).
#   testing/shadow-oracle/scripts/oracle-box-store-services.sh up
#       same, but run (not sourced): brings the containers up, waits, and writes the three export
#       lines to $ORACLE_STORE_ENV_FILE (default ./oracle-store-services.env) for the caller to
#       `source` before invoking record.sh. Also prints them to stdout.
#   ... down            stop and REMOVE the three containers and their volumes (a clean slate for
#                       the next full record run -- see IDEMPOTENCY below).
#   ... env             print the three export lines for the current settings without touching docker.
#   ... wait            (re)run only the readiness probes against already-running containers.
#
# IDEMPOTENCY. Each record run mints a fresh key (a new random id) and expects requests==1 on the
# read-back, so re-running the recorder against the SAME live DB is harmless for the numbers. But
# `down` removes the volumes so a full re-record starts from an empty schema every time (the
# plugins run their own migrations on first boot); prefer `down` then `up` between full runs on a
# shared box rather than leaving state to accumulate.
#
# SCOPE. This script only provisions services and exports vars. It does NOT run the recorder and it
# does NOT fetch or install the store plugins (fetch-plugin.sh does that from plugin-digests.tsv at
# record time). It touches nothing under the busbar source tree.
set -uo pipefail

# --- knobs (override in the environment before sourcing/running) --------------------------------
PG_PORT="${ORACLE_PG_PORT:-5432}"
MY_PORT="${ORACLE_MY_PORT:-3306}"
VK_PORT="${ORACLE_VK_PORT:-6379}"
DB_USER="${ORACLE_STORE_USER:-busbar}"
DB_PASS="${ORACLE_STORE_PASS:-busbar}"
DB_NAME="${ORACLE_STORE_DB:-busbar}"
# Pinned images: a byte-parity harness must not let a floating `latest` change the backend under it
# between the golden recording and a candidate run.
PG_IMAGE="${ORACLE_PG_IMAGE:-postgres:16}"
MY_IMAGE="${ORACLE_MY_IMAGE:-mysql:8.0}"
VK_IMAGE="${ORACLE_VK_IMAGE:-valkey/valkey:8}"
PG_NAME="${ORACLE_PG_NAME:-oracle-store-postgres}"
MY_NAME="${ORACLE_MY_NAME:-oracle-store-mysql}"
VK_NAME="${ORACLE_VK_NAME:-oracle-store-valkey}"
READY_TIMEOUT="${ORACLE_STORE_READY_TIMEOUT:-90}"   # seconds to wait per backend
ENV_FILE="${ORACLE_STORE_ENV_FILE:-oracle-store-services.env}"

# The connection URLs, in each driver's OWN scheme:
#   postgres/mysql: sqlx URLs (postgres://, mysql://) with host:port and a database name.
#   valkey:         the redis crate's own URL scheme is `redis://` (migrate.rs: "redis:// is the
#                   driver's own URL scheme, not a busbar name"); /0 selects the default logical db.
PG_URL="postgres://${DB_USER}:${DB_PASS}@127.0.0.1:${PG_PORT}/${DB_NAME}"
MY_URL="mysql://${DB_USER}:${DB_PASS}@127.0.0.1:${MY_PORT}/${DB_NAME}"
VK_URL="redis://127.0.0.1:${VK_PORT}/0"

# Detect `source`d vs executed so `up` can export into the caller's shell when sourced.
_sourced=0
if [ "${BASH_SOURCE[0]:-$0}" != "$0" ]; then _sourced=1; fi

_log() { printf '[oracle-store] %s\n' "$*" >&2; }
_die() { _log "ERROR: $*"; if [ "$_sourced" = 1 ]; then return 1; else exit 1; fi; }

_need_docker() { command -v docker >/dev/null 2>&1 || _die "docker not found on PATH"; }

_up_containers() {
  _need_docker || return 1
  _log "starting postgres (${PG_IMAGE}) on :${PG_PORT}"
  docker run -d --rm --name "$PG_NAME" \
    -e POSTGRES_USER="$DB_USER" -e POSTGRES_PASSWORD="$DB_PASS" -e POSTGRES_DB="$DB_NAME" \
    -p "127.0.0.1:${PG_PORT}:5432" "$PG_IMAGE" >/dev/null \
    || _log "postgres container may already be running ($PG_NAME)"
  _log "starting mysql (${MY_IMAGE}) on :${MY_PORT}"
  # A dedicated non-root user/db is created from these env vars; the plugin connects as that user.
  docker run -d --rm --name "$MY_NAME" \
    -e MYSQL_RANDOM_ROOT_PASSWORD=yes \
    -e MYSQL_USER="$DB_USER" -e MYSQL_PASSWORD="$DB_PASS" -e MYSQL_DATABASE="$DB_NAME" \
    -p "127.0.0.1:${MY_PORT}:3306" "$MY_IMAGE" >/dev/null \
    || _log "mysql container may already be running ($MY_NAME)"
  _log "starting valkey (${VK_IMAGE}) on :${VK_PORT}"
  docker run -d --rm --name "$VK_NAME" \
    -p "127.0.0.1:${VK_PORT}:6379" "$VK_IMAGE" >/dev/null \
    || _log "valkey container may already be running ($VK_NAME)"
}

_wait_ready() {
  _need_docker || return 1
  local deadline=$(( $(date +%s) + READY_TIMEOUT ))

  _log "waiting for postgres ..."
  until docker exec "$PG_NAME" pg_isready -U "$DB_USER" -d "$DB_NAME" -h 127.0.0.1 >/dev/null 2>&1; do
    [ "$(date +%s)" -lt "$deadline" ] || { _die "postgres not ready within ${READY_TIMEOUT}s"; return 1; }
    sleep 1
  done
  _log "postgres ready"

  _log "waiting for mysql ..."
  # `mysqladmin ping` answers before the user grants are loaded, so probe with an actual query as
  # the dedicated user against the dedicated db -- the exact credential the plugin will use.
  until docker exec "$MY_NAME" mysql -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" -e 'SELECT 1' >/dev/null 2>&1; do
    [ "$(date +%s)" -lt "$deadline" ] || { _die "mysql not ready within ${READY_TIMEOUT}s"; return 1; }
    sleep 1
  done
  _log "mysql ready"

  _log "waiting for valkey ..."
  until [ "$(docker exec "$VK_NAME" valkey-cli ping 2>/dev/null || docker exec "$VK_NAME" redis-cli ping 2>/dev/null)" = "PONG" ]; do
    [ "$(date +%s)" -lt "$deadline" ] || { _die "valkey not ready within ${READY_TIMEOUT}s"; return 1; }
    sleep 1
  done
  _log "valkey ready"
}

_print_env() {
  printf 'export BUSBAR_TEST_POSTGRES_URL=%q\n' "$PG_URL"
  printf 'export BUSBAR_TEST_MYSQL_URL=%q\n' "$MY_URL"
  printf 'export VALKEY_URL=%q\n' "$VK_URL"
}

_export_env() {
  export BUSBAR_TEST_POSTGRES_URL="$PG_URL"
  export BUSBAR_TEST_MYSQL_URL="$MY_URL"
  export VALKEY_URL="$VK_URL"
}

_down_containers() {
  _need_docker || return 1
  # --rm containers vanish on stop; -v also clears the anonymous data volumes for a clean slate.
  docker rm -f -v "$PG_NAME" "$MY_NAME" "$VK_NAME" >/dev/null 2>&1 || true
  _log "stopped and removed store containers"
}

cmd="${1:-up}"
case "$cmd" in
  up)
    _up_containers && _wait_ready || _die "failed to bring store services up"
    if [ "$_sourced" = 1 ]; then
      _export_env
      _log "exported BUSBAR_TEST_POSTGRES_URL / BUSBAR_TEST_MYSQL_URL / VALKEY_URL into this shell"
    else
      _print_env | tee "$ENV_FILE"
      _log "wrote export lines to ${ENV_FILE}; \`source ${ENV_FILE}\` before running record.sh"
    fi
    ;;
  down)  _down_containers ;;
  env)   _print_env ;;
  wait)  _wait_ready ;;
  *)     _die "unknown command '$cmd' (use: up | down | env | wait)" ;;
esac
