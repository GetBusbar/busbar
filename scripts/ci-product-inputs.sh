#!/usr/bin/env bash
# Build ordinary tests' real product inputs from the normal, immutable fleet pins.
# stdout is the generated environment file; build output goes to stderr.
set -eo pipefail
root=$(git rev-parse --show-toplevel)
pins="$root/scripts/ci-product-pins.json"
[ -f "$pins" ] || { echo "missing normal fleet pins: $pins" >&2; exit 1; }
target="$root/target"
work="${MODERNCI_CACHE_DIR:-$target}/ci-product-inputs/$(git rev-parse HEAD)"
mkdir -p "$work"
envfile="$work/environment.sh"
: > "$envfile"
case "$(uname -s)" in Darwin) suffix=dylib ;; Linux) suffix=so ;; *) echo 'unsupported native product-test platform' >&2; exit 1 ;; esac
digest() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi; }
emit() { printf 'export %s=%q\n' "$1" "$2" >> "$envfile"; }
build_product() {
  local repo="$1" variables="$2" row sha source manifest package image libname meta variable
  local -a features
  row=$(jq -ce --arg repo "$repo" '.products[] | select(.repo == $repo)' "$pins")
  sha=$(jq -er '.commit | select(test("^[0-9a-f]{40}$"))' <<< "$row")
  package=$(jq -er '.package' <<< "$row")
  source="$work/sources/$repo-$sha"
  if [ ! -d "$source/.git" ]; then
    mkdir -p "$source"
    git -C "$source" init -q >&2
    git -C "$source" fetch --depth 1 "$(jq -er .url <<< "$row")" "$sha" >&2
    git -C "$source" checkout --detach FETCH_HEAD >&2
  fi
  [ "$(git -C "$source" rev-parse HEAD)" = "$sha" ]
  [ -z "$(git -C "$source" status --porcelain)" ]
  [ "$(digest "$source/Cargo.lock" | cut -d' ' -f1)" = "$(jq -er '.lock_sha256' <<< "$row")" ]
  manifest="$source/Cargo.toml"
  meta=$(cargo +1.98.0 metadata --manifest-path "$manifest" --locked --format-version 1)
  features=()
  if jq -e --arg p "$package" '.packages[] | select(.name == $p) | .features | has("dropped-in")' <<< "$meta" >/dev/null; then features=(--features dropped-in); fi
  cargo +1.98.0 build --manifest-path "$manifest" --locked -p "$package" --lib "${features[@]}" --target-dir "$target" >&2
  libname=$(jq -er --arg p "$package" '.packages[] | select(.name == $p) | .targets[] | select(.kind | index("cdylib")) | .name' <<< "$meta")
  image="$target/debug/lib$libname.$suffix"
  [ -f "$image" ]
  for variable in $variables; do emit "$variable" "$image"; done
  if [[ "$repo" = busbar-export-* && "$repo" != busbar-export-prometheus ]]; then
    local kind alias out declares prefix
    kind=$(jq -er '.kind' <<< "$row"); alias=$(jq -er '.alias' <<< "$row")
    declares=$(jq -er '.declares' <<< "$row")
    [ -f "$source/$declares" ]
    out="$work/$repo.tar.gz"
    env -u BUSBAR_SIGN_KEY "$target/debug/busbar-plugin-pack" pack --lib "$image" --name "$repo" --alias "$alias" --kind "$kind" --publisher busbar --license Apache-2.0 --declares-file "$source/$declares" --allow-unsigned --out "$out" >&2
    mkdir -p "$work/$repo"
    tar -xzf "$out" -C "$work/$repo" manifest.json
    prefix="BUSBAR_TEST_EXPORT_$(printf %s "${repo#busbar-export-}" | tr '[:lower:]' '[:upper:]')"
    emit "${prefix}_MANIFEST" "$work/$repo/manifest.json"
    emit "${prefix}_DECLARES" "$source/$declares"
  fi
}
cargo +1.98.0 build --locked -p busbar-plugin-loader --features pack --bin busbar-plugin-pack --target-dir "$target" >&2
while IFS='|' read -r repo variables; do build_product "$repo" "$variables"; done <<'PRODUCTS'
busbar-store-memory|BUSBAR_TEST_MEMORY_STORE_CDYLIB BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN
busbar-store-sqlite|BUSBAR_TEST_SQLITE_CDYLIB BUSBAR_BOOTSTRAP_TEST_STORE_PLUGIN
busbar-store-mysql|BUSBAR_TEST_MYSQL_CDYLIB
busbar-secret-env|BUSBAR_TEST_SECRET_ENV_CDYLIB BUSBAR_BOOTSTRAP_TEST_SECRET_PLUGIN
busbar-secret-vault|BUSBAR_TEST_VAULT_CDYLIB
busbar-transport-tcp|BUSBAR_TEST_TCP_CDYLIB
busbar-transport-http|BUSBAR_TEST_HTTP_CDYLIB
busbar-transport-ws|BUSBAR_TEST_WS_CDYLIB
busbar-plane-a2a|BUSBAR_TEST_A2A_CDYLIB
busbar-plane-mcp|BUSBAR_TEST_MCP_CDYLIB
busbar-plane-decisions|BUSBAR_TEST_DECISIONS_CDYLIB
busbar-plane-llm|BUSBAR_GOVERNANCE_TEST_PLANE_PLUGIN
busbar-auth-oidc|BUSBAR_TEST_OIDC_CDYLIB BUSBAR_AUTH_TEST_OIDC_PLUGIN
busbar-auth-ldap|BUSBAR_TEST_LDAP_PLUGIN
busbar-auth-webhook-signature|BUSBAR_AUTH_WEBHOOK_SIGNATURE_TEST_PLUGIN
busbar-hook-ranking|BUSBAR_TEST_RANKING_CDYLIB
busbar-hook-webrequest|BUSBAR_TEST_WEBREQUEST_CDYLIB
busbar-export-file|BUSBAR_TEST_EXPORT_FILE_CDYLIB
busbar-export-webhook|BUSBAR_TEST_EXPORT_WEBHOOK_CDYLIB
busbar-export-otlp|BUSBAR_TEST_EXPORT_OTLP_CDYLIB BUSBAR_TEST_OTLP_CDYLIB
busbar-export-prometheus|BUSBAR_TEST_EXPORT_PROMETHEUS_CDYLIB BUSBAR_TEST_PROMETHEUS_CDYLIB
PRODUCTS
emit BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS '{}'
printf '%s\n' "$envfile"
