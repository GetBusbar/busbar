#!/usr/bin/env bash
# Shared trainer configuration, sourced by the build and its CLI regression.
write_run_configs() {
  local run_port="$1" run_mock_port="$2"
  cat > "$WORK/config.yaml" <<YAML
listen: "127.0.0.1:$run_port"
admin_listen: "127.0.0.1:$((run_port + 1))"
store: {module: memory}
# 1.5.3 grammar. Two keys moved and the old spellings are now fail-closed boot refusals, which is
# how this script broke the 1.5.3 Docker build: PGO is mandatory, the instrumented binary refused
# its own training config, and the release could not produce an image. The trainer must be written
# in the grammar of the binary it trains.
#   observability.emit_server_timing -> advanced.response_headers.server_timing (block DELETED)
#   auth.upstream_credentials        -> pools.upstream_credentials (all-pools default)
advanced:
  response_headers:
    server_timing: true
# Signed-key front door. Production traffic is governed - Bearer bbk_* tokens through the keys
# arm, group admission, per-principal reqlog chains - and with the old empty chain NONE of that
# trained: ed25519 verify, the governance admit/charge, and the governed reqlog branch were laid
# out as cold code (the old "Bearer pgo-token" header was extracted and never verified). The
# trainer mints one throwaway key per run against its own admin listener (the store is
# in-memory, so the binding row only exists inside this process - exactly right for a trainer).
identity-providers:
  admin-tokens: { module: admin-tokens, token: { env: PGO_ADMIN_TOKEN } }
auth:
  chain: [keys]
  admin_auth: [admin-tokens]
  signing_key: { env: PGO_SIGNING_KEY }
# Effectively-unbounded caps: the point is to run the admission check-and-charge path hot, not
# to exercise 429s (the refusal sliver in phase 2 covers the reject arms, lightly).
groups:
  bench:
    limits:
      - { requests: 100000000, per: minute }
      - { concurrent: 4096 }
providers:
  mock:
    api_key: { env: PGO_MOCK_KEY }
models:
  gpt-4o-mini:
    provider: mock
    max_concurrent: 512
    max_requests: -1
pools:
  upstream_credentials: own
  bench-pool:
    members:
      - model: gpt-4o-mini
YAML
  cat > "$WORK/providers.yaml" <<YAML
mock:
  protocol: openai
  base_url: http://127.0.0.1:$run_mock_port
  error_map: {}
YAML
}

