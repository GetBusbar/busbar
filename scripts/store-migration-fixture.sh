#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# THE #33 STORE MIGRATION FIXTURES (BUSBAR-1.6.0.md l.1096-1103, M5 l.1526): rows WRITTEN BY THE
# PINNED, PUBLISHED v1.5.5 BINARY through the published 1.5-line store plugin, for each store
# backend, so each store plugin's own `migrate()` is proven against what 1.5.5 really wrote and
# reads it back byte-identically. A fixture is never hand-written and never produced by a crate's
# own example: only the two published artifacts write it, each verified against its pinned digest
# before it runs.
#
#   scripts/store-migration-fixture.sh record <backend> <out-dir>
#       backend: sqlite | postgres | mysql | valkey
#       Downloads busbar v1.5.5 for this host (digest: testing/shadow-oracle/golden-digests.tsv, the
#       archive AND the extracted binary) and the 1.5-line store plugin (digest:
#       testing/shadow-oracle/plugin-digests.tsv), boots 1.5.5 over a local stand-in upstream,
#       drives the fixed request script below, stops it gracefully (its final flush), and dumps the
#       backend. Network backends need their service reachable at the URL named by
#       MIGRATION_FIXTURE_POSTGRES_URL / _MYSQL_URL / _VALKEY_URL (a throwaway database: it is
#       written to), and the matching client (psql+pg_dump / mysql+mysqldump / valkey-cli or
#       redis-cli) on PATH, or MIGRATION_FIXTURE_DOCKER=<container> to run the client in it (then
#       MIGRATION_FIXTURE_CLIENT_URL is the URL as the container reaches the service, when it differs).
#       Writes <out-dir>/{dump file, rows.json, readback/*.json, MANIFEST.tsv}.
#
#   scripts/store-migration-fixture.sh check <fixture-dir>
#       The CI half: refuses a missing fixture, a missing or malformed MANIFEST, a binary digest
#       other than the pinned 1.5.5 binary's for the recorded triple, a plugin digest other than
#       the pinned 1.5-line asset's, and any file whose digest no longer matches its MANIFEST row.
#
# rows.json is the backend's own usage tables as 1.5.5 left them, read with the backend's client
# (one JSON object per table, rows ordered by every column), so a store's migrate test compares
# what its 1.6.0 read returns with exactly what was written. readback/ holds 1.5.5's own admin
# answers about those rows (the fleet read and each key's read), the customer-visible half.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
GOLDEN_DIGESTS="$repo/testing/shadow-oracle/golden-digests.tsv"
PLUGIN_DIGESTS="$repo/testing/shadow-oracle/plugin-digests.tsv"
RELEASE_VERSION="1.5.5"

die() { echo "store-migration-fixture: $*" >&2; exit 1; }

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

host_triple() {
  local arch os
  case "$(uname -m)" in arm64|aarch64) arch=aarch64 ;; x86_64|amd64) arch=x86_64 ;; *) die "no pinned 1.5.5 build for $(uname -m)" ;; esac
  case "$(uname -s)" in Darwin) os=apple-darwin ;; Linux) os=unknown-linux-gnu ;; *) die "no pinned 1.5.5 build for $(uname -s)" ;; esac
  echo "${arch}-${os}"
}

# pinned <file> <col1> <col2> -> the digest of the row whose first two columns match, or nothing.
pinned() { awk -F'\t' -v a="$2" -v b="$3" '$0 !~ /^#/ && $1 == a && $2 == b { print $NF; exit }' "$1"; }

# The 1.5-line store plugin per backend: <digest-table repo> <tag> <github repo>.
plugin_of() {
  case "$1" in
    sqlite)   echo "store-sqlite v1.0.6 busbar-store-sqlite" ;;
    postgres) echo "store-postgres v1.0.6 busbar-store-postgres" ;;
    mysql)    echo "store-mysql v1.0.6 busbar-store-mysql" ;;
    valkey)   echo "store-valkey v1.0.7 busbar-store-valkey" ;;
    *) die "unknown backend '$1' (sqlite | postgres | mysql | valkey)" ;;
  esac
}

fetch() {  # fetch <url> <dest> <sha256>
  curl -fsSL --retry 3 -o "$2" "$1" || die "download failed: $1"
  local got; got="$(sha256 "$2")"
  [ "$got" = "$3" ] || die "digest mismatch for $1: got $got, pinned $3"
}

# ── record ──────────────────────────────────────────────────────────────────────────────────────

record() {
  local backend="$1" out="$2"
  [ -n "$out" ] || die "record needs <backend> <out-dir>"
  command -v jq >/dev/null || die "jq is required"
  command -v python3 >/dev/null || die "python3 is required (the stand-in upstream)"
  mkdir -p "$out/readback"
  out="$(cd "$out" && pwd)"
  work="$(mktemp -d)"
  pids=()
  trap 'for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; [ -n "${MIGRATION_FIXTURE_KEEP:-}" ] || rm -rf "$work"' EXIT

  # 1. THE PUBLISHED BINARY, verified twice: the archive and the binary inside it.
  local triple asset archive_sha bin_sha
  triple="$(host_triple)"
  asset="busbar-${triple}.tar.gz"
  archive_sha="$(pinned "$GOLDEN_DIGESTS" "$RELEASE_VERSION" "$asset")"
  bin_sha="$(pinned "$GOLDEN_DIGESTS" "$RELEASE_VERSION" "busbar-${triple}")"
  [ -n "$archive_sha" ] || die "golden-digests.tsv pins no $asset"
  [ -n "$bin_sha" ] || die "golden-digests.tsv pins no extracted busbar-${triple}; record on a host whose binary is pinned"
  fetch "https://github.com/GetBusbar/busbar/releases/download/v${RELEASE_VERSION}/${asset}" "$work/busbar.tgz" "$archive_sha"
  mkdir -p "$work/bin"
  tar -xzf "$work/busbar.tgz" -C "$work/bin"
  local bin; bin="$(find "$work/bin" -type f -name busbar | head -1)"
  [ -n "$bin" ] || die "no busbar binary in $asset"
  [ "$(sha256 "$bin")" = "$bin_sha" ] || die "the extracted 1.5.5 binary's digest is not the pinned busbar-${triple}"
  chmod +x "$bin"

  # 2. THE PUBLISHED 1.5-LINE STORE PLUGIN, verified.
  local ptable ptag prepo passet psha
  read -r ptable ptag prepo <<<"$(plugin_of "$backend")"
  passet="$(awk -F'\t' -v r="$ptable" -v t="$triple" '$0 !~ /^#/ && $1 == r && $3 ~ ("-" t "\\.tar\\.gz$") { print $3; exit }' "$PLUGIN_DIGESTS")"
  [ -n "$passet" ] || die "plugin-digests.tsv pins no $ptable asset for $triple"
  psha="$(awk -F'\t' -v a="$passet" '$3 == a { print $4; exit }' "$PLUGIN_DIGESTS")"
  mkdir -p "$work/plugins"
  fetch "https://github.com/GetBusbar/${prepo}/releases/download/${ptag}/${passet}" "$work/plugins/$passet" "$psha"
  local alias_; alias_="$(tar -xzOf "$work/plugins/$passet" manifest.json | jq -r .alias)"

  # 3. THE BACKEND the plugin writes to.
  local settings dump
  case "$backend" in
    sqlite)   settings="{ db_path: \"$work/governance.db\" }"; dump="governance.db" ;;
    postgres) settings="{ url: \"${MIGRATION_FIXTURE_POSTGRES_URL:?a throwaway postgres database URL}\" }"; dump="dump.sql" ;;
    mysql)    settings="{ url: \"${MIGRATION_FIXTURE_MYSQL_URL:?a throwaway mysql database URL}\" }"; dump="dump.sql" ;;
    valkey)   settings="{ url: \"${MIGRATION_FIXTURE_VALKEY_URL:?a throwaway valkey URL}\" }"; dump="keys.json" ;;
  esac

  # 4. THE STAND-IN UPSTREAM: an OpenAI-shaped chat endpoint with fixed usage. A model whose name
  #    ends in `-down` is answered 503, so 1.5.5 records its refund path too.
  local lp=47831 ap=47832 mp=47791
  cat >"$work/upstream.py" <<'PY'
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        model = body.get("model", "")
        if model.endswith("-down"):
            self.send_response(503); self.send_header("content-type", "application/json")
            out = b'{"error":{"message":"down","type":"server_error"}}'
            self.send_header("content-length", str(len(out))); self.end_headers(); self.wfile.write(out); return
        cached = 4 if "cache" in model else 0
        out = json.dumps({"id": "chatcmpl-fixture", "object": "chat.completion", "created": 0,
            "model": model, "choices": [{"index": 0, "message": {"role": "assistant", "content": "pong"},
            "finish_reason": "stop"}], "usage": {"prompt_tokens": 11, "completion_tokens": 7,
            "total_tokens": 18, "prompt_tokens_details": {"cached_tokens": cached}}}).encode()
        self.send_response(200); self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out))); self.end_headers(); self.wfile.write(out)
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
  python3 -I "$work/upstream.py" "$mp" >"$work/upstream.log" 2>&1 & pids+=($!)

  "$bin" --generate-signing-key >"$work/signing.key" 2>/dev/null
  cat >"$work/providers.yaml" <<YAML
fixture-openai:
  protocol: openai
  base_url: "http://127.0.0.1:${mp}"
YAML
  cat >"$work/config.yaml" <<YAML
listen: "127.0.0.1:${lp}"
admin_listen: "127.0.0.1:${ap}"
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { env: BUSBAR_ADMIN_TOKEN }
auth:
  chain: [keys]
  signing_key: { file: "${work}/signing.key" }
  admin_auth: [admin-tokens]
plugins:
  enabled: true
  dir: "${work}/plugins"
store:
  module: ${alias_}
  settings: ${settings}
groups:
  fixture:
    limits:
      - { budget: 1000000, per: day }
providers:
  fixture-openai:
    api_key: { env: FIXTURE_UPSTREAM_KEY }
models:
  m-chat:
    provider: fixture-openai
  m-cache:
    provider: fixture-openai
  m-chat-down:
    provider: fixture-openai
per_request_fee: 3
rate_card:
  m-chat: { input_utok: 100000, output_utok: 200000 }
  m-cache: { input_utok: 100000, output_utok: 200000, cache_read_utok: 10000 }
  m-chat-down: { input_utok: 100000, output_utok: 200000 }
advanced:
  usage_flush_interval_ms: 3600000
YAML
  local admin=fixture-admin-token bpid
  boot() {
    ( exec env BUSBAR_CONFIG="$work/config.yaml" BUSBAR_PROVIDERS="$work/providers.yaml" \
        FIXTURE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN="$admin" RUST_LOG=warn "$bin" ) >>"$work/busbar.log" 2>&1 &
    bpid=$!; pids+=($bpid)
    local n=0
    until curl -fsS -m 2 "http://127.0.0.1:${lp}/healthz" >/dev/null 2>&1; do
      n=$((n+1)); [ $n -lt 600 ] || die "1.5.5 did not come up: $(tail -c 800 "$work/busbar.log")"; sleep 0.1
    done
  }
  boot

  # 5. THE FIXED REQUEST SCRIPT: two keys (one in a budget group, one not), three models (plain,
  #    cache-read, upstream down), so the fixture holds every usage column 1.5.5 wrote.
  mint() {
    curl -fsS -m 10 -X POST "http://127.0.0.1:${ap}/api/v1/admin/keys" -H "Authorization: Bearer $admin" \
      -H 'Content-Type: application/json' -d "$1"
  }
  local k1 k2
  k1="$(mint '{"name":"fixture-grouped","group":"fixture"}')"
  k2="$(mint '{"name":"fixture-ungrouped"}')"
  chat() {  # chat <token> <model>
    curl -sS -m 20 -o /dev/null -w '%{http_code}\n' -X POST "http://127.0.0.1:${lp}/v1/chat/completions" \
      -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
      -d "{\"model\":\"$2\",\"messages\":[{\"role\":\"user\",\"content\":\"ping\"}]}"
  }
  local t1 t2 statuses=""
  t1="$(jq -r .token <<<"$k1")"; t2="$(jq -r .token <<<"$k2")"
  for m in m-chat m-chat m-cache m-chat-down; do statuses+="$(chat "$t1" "$m") "; done
  for m in m-chat m-cache; do statuses+="$(chat "$t2" "$m") "; done
  # 6. THE GRACEFUL STOP (1.5.5's final flush writes everything it counted), then 1.5.5 BOOTS AGAIN
  #    over the same store and answers what it reads back: the readback is 1.5.5's own reading of
  #    the rows it wrote, never of counters it still held in memory. Then it stops for the dump.
  stop() { kill "$1"; wait "$1" 2>/dev/null || true; }
  stop "$bpid"
  boot
  i=0
  until [ "$(curl -fsS -m 5 -H "Authorization: Bearer $admin" "http://127.0.0.1:${ap}/api/v1/admin/usage" | jq '.total.requests')" -ge 5 ] 2>/dev/null; do
    i=$((i+1)); [ $i -lt 100 ] || die "1.5.5 read back fewer than the 5 served requests after its restart"
    sleep 0.1
  done
  curl -fsS -m 5 -H "Authorization: Bearer $admin" "http://127.0.0.1:${ap}/api/v1/admin/usage" | jq -S 'del(.as_of)' >"$out/readback/usage.json"
  for k in "$k1" "$k2"; do
    local id; id="$(jq -r .id <<<"$k")"
    curl -fsS -m 5 -H "Authorization: Bearer $admin" "http://127.0.0.1:${ap}/api/v1/admin/keys/${id}/usage" | jq -S 'del(.as_of)' >"$out/readback/key-$(jq -r .name <<<"$k").json"
  done
  stop "$bpid"

  # 7. THE DUMP, by the backend's own client.
  client() { if [ -n "${MIGRATION_FIXTURE_DOCKER:-}" ]; then docker exec -i "$MIGRATION_FIXTURE_DOCKER" "$@"; else "$@"; fi; }
  case "$backend" in
    sqlite)
      # 1.5.5's store keeps sqlite in WAL mode: fold the log into the main file (a checkpoint moves
      # pages, it writes no row), so the fixture is one self-contained database.
      python3 -I -c 'import sqlite3, sys; db = sqlite3.connect(sys.argv[1]); db.execute("PRAGMA wal_checkpoint(TRUNCATE)"); db.close()' "$work/governance.db"
      cp "$work/governance.db" "$out/$dump"
      python3 -I - "$out/$dump" >"$out/rows.json" <<'PY'
import json, sqlite3, sys
db = sqlite3.connect(sys.argv[1])
tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
out = {}
for t in tables:
    cur = db.execute(f'SELECT * FROM "{t}"')
    cols = [d[0] for d in cur.description]
    rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    rows.sort(key=lambda r: json.dumps(r, sort_keys=True))
    out[t] = rows
print(json.dumps(out, indent=1, sort_keys=True))
PY
      ;;
    postgres)
      local pg="${MIGRATION_FIXTURE_CLIENT_URL:-$MIGRATION_FIXTURE_POSTGRES_URL}"
      # `\restrict`/`\unrestrict` are psql meta-commands carrying a random key (pg_dump 16.10+):
      # dropped, so the dump is plain SQL any client executes and the same rows dump the same bytes.
      client pg_dump --no-owner --no-privileges --no-comments --inserts --column-inserts "$pg" \
        | grep -v -E '^\\(un)?restrict ' >"$out/$dump"
      # One table at a time, so each table's rows are ordered by their own text.
      {
        echo "{"
        local first=1 t
        for t in $(client psql -At "$pg" -c "SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY table_name"); do
          [ $first = 1 ] || echo ","
          first=0
          printf '"%s": ' "$t"
          client psql -At "$pg" -c "SELECT coalesce(json_agg(x ORDER BY x::text), '[]'::json) FROM \"$t\" x"
        done
        echo "}"
      } | jq -S . >"$out/rows.json"
      ;;
    mysql)
      local u="${MIGRATION_FIXTURE_CLIENT_URL:-$MIGRATION_FIXTURE_MYSQL_URL}"
      # mysql://user:pass@host:port/db
      local my_user my_pass my_host my_port my_db rest
      rest="${u#mysql://}"; my_user="${rest%%:*}"; rest="${rest#*:}"; my_pass="${rest%%@*}"; rest="${rest#*@}"
      my_host="${rest%%:*}"; rest="${rest#*:}"; my_port="${rest%%/*}"; my_db="${rest#*/}"
      client mysqldump --skip-comments --skip-dump-date --skip-extended-insert --complete-insert -h "$my_host" -P "$my_port" -u "$my_user" "-p$my_pass" "$my_db" >"$out/$dump"
      {
        echo "{"
        local first=1 t
        for t in $(client mysql -N -h "$my_host" -P "$my_port" -u "$my_user" "-p$my_pass" "$my_db" -e "SHOW TABLES"); do
          [ $first = 1 ] || echo ","
          first=0
          printf '"%s": ' "$t"
          local cols
          cols="$(client mysql -N -h "$my_host" -P "$my_port" -u "$my_user" "-p$my_pass" "$my_db" -e \
            "SELECT GROUP_CONCAT(CONCAT('''', column_name, ''', \`', column_name, '\`') ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='$t'")"
          client mysql -N -h "$my_host" -P "$my_port" -u "$my_user" "-p$my_pass" "$my_db" -e \
            "SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT($cols)), JSON_ARRAY()) FROM \`$t\`" | jq -c 'sort_by(tostring)'
        done
        echo "}"
      } | jq -S . >"$out/rows.json"
      ;;
    valkey)
      local cli; cli="$(command -v valkey-cli || command -v redis-cli || echo valkey-cli)"
      python3 -I - "$MIGRATION_FIXTURE_VALKEY_URL" "${MIGRATION_FIXTURE_DOCKER:-}" "$cli" >"$out/$dump" <<'PY'
import json, subprocess, sys
url, container, cli = sys.argv[1], sys.argv[2], sys.argv[3]
def run(*args):
    cmd = ([ "docker", "exec", "-i", container ] if container else []) + [cli, "-u", url, "--no-raw"] + list(args)
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
def raw(*args):
    cmd = ([ "docker", "exec", "-i", container ] if container else []) + [cli, "-u", url, "--raw"] + list(args)
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout.splitlines()
out = {}
for key in sorted(raw("--scan")):
    kind = raw("TYPE", key)[0]
    if kind == "string": value = raw("GET", key)[0] if raw("GET", key) else ""
    elif kind == "hash":
        f = raw("HGETALL", key); value = dict(sorted(zip(f[0::2], f[1::2])))
    elif kind == "set": value = sorted(raw("SMEMBERS", key))
    elif kind == "zset":
        f = raw("ZRANGE", key, "0", "-1", "WITHSCORES"); value = [[m, s] for m, s in zip(f[0::2], f[1::2])]
    elif kind == "list": value = raw("LRANGE", key, "0", "-1")
    else: value = None
    ttl = int(raw("PTTL", key)[0])
    out[key] = {"type": kind, "value": value, "has_ttl": ttl >= 0}
print(json.dumps(out, indent=1, sort_keys=True))
PY
      cp "$out/$dump" "$out/rows.json"
      ;;
  esac

  # 8. THE MANIFEST: what wrote it, and the digest of every file it names.
  {
    printf '# what\tvalue\n'
    printf 'busbar\tv%s %s %s\n' "$RELEASE_VERSION" "busbar-${triple}" "$bin_sha"
    printf 'plugin\t%s %s %s\n' "$ptag" "$passet" "$psha"
    printf 'backend\t%s\n' "$backend"
    printf 'recorder\t%s\n' "$(git -C "$repo" hash-object "$0")"
    printf 'requests\t%s\n' "$statuses"
    ( cd "$out" && find . -type f ! -name MANIFEST.tsv | LC_ALL=C sort | while read -r f; do printf 'file\t%s %s\n' "${f#./}" "$(sha256 "$f")"; done )
  } >"$out/MANIFEST.tsv"
  echo "recorded $backend fixture into $out ($(awk 'END{print NR}' "$out/MANIFEST.tsv") manifest rows; request statuses: $statuses)"
}

# ── check ───────────────────────────────────────────────────────────────────────────────────────

check() {
  local dir="$1"
  [ -d "$dir" ] || die "no fixture at $dir: every store backend owes one (#33, M5)"
  local m="$dir/MANIFEST.tsv"
  [ -f "$m" ] || die "$dir has no MANIFEST.tsv"
  local busbar plugin
  busbar="$(awk -F'\t' '$1 == "busbar" { print $2 }' "$m")"
  plugin="$(awk -F'\t' '$1 == "plugin" { print $2 }' "$m")"
  [ -n "$busbar" ] && [ -n "$plugin" ] || die "$m names no busbar or no plugin row"
  local ver name bsha
  read -r ver name bsha <<<"$busbar"
  [ "$ver" = "v$RELEASE_VERSION" ] || die "$m: written by $ver, not the pinned v$RELEASE_VERSION"
  [ "$(pinned "$GOLDEN_DIGESTS" "$RELEASE_VERSION" "$name")" = "$bsha" ] || die "$m: binary $name $bsha is not the pinned v$RELEASE_VERSION binary"
  local ptag passet psha
  read -r ptag passet psha <<<"$plugin"
  [ "$(awk -F'\t' -v a="$passet" '$3 == a { print $2 "\t" $4; exit }' "$PLUGIN_DIGESTS")" = "$(printf '%s\t%s' "$ptag" "$psha")" ] \
    || die "$m: plugin $passet ($ptag) $psha is not a pinned 1.5-line release asset"
  local files=0 f sha
  while IFS=$'\t' read -r what value; do
    [ "$what" = file ] || continue
    read -r f sha <<<"$value"
    [ -f "$dir/$f" ] || die "$m names $f, which is missing"
    [ "$(sha256 "$dir/$f")" = "$sha" ] || die "$dir/$f does not match its MANIFEST digest"
    files=$((files+1))
  done <"$m"
  [ "$files" -ge 2 ] || die "$m names $files files: a fixture is a dump and its rows at least"
  echo "fixture $dir: written by v$RELEASE_VERSION ($name) through $passet; $files files match"
}

case "${1:-}" in
  record) record "${2:-}" "${3:-}" ;;
  check) check "${2:-}" ;;
  *) die "usage: $0 record <sqlite|postgres|mysql|valkey> <out-dir> | check <fixture-dir>" ;;
esac
