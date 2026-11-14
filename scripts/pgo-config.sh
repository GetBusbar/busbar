#!/usr/bin/env bash
# Shared trainer configuration, sourced by the build and its CLI regression.
#
# THE UPSTREAM IS THE BENCHMARK'S MOCK. The trainer points every provider at the GetBusbar/benchmarking
# `mock` (one hyper server that answers all six wire protocols by path), so the profile trains the
# same egress codecs the published benchmark measures. The providers and models mirror the benchmark's
# busbar manifest (gateways/busbar/{config,providers}.gen.yaml.tmpl): one provider and one model per
# egress dialect, named `mock-<dialect>` / `gpt-4o-mini[-<dialect>]`. Keep them in step when that
# manifest grows a dialect, or the new codec trains cold.
#
# The config stays in THIS tree, beside the binary it configures, on purpose: the 1.5.3 Docker build
# broke because a trainer written in an older grammar was refused by the binary it trained. The
# trainer's `--validate` step names that failure, and keeping the grammar here keeps it reviewable in
# the same change that moves a key.
#
# The one list of trained egress dialects (provider suffix, protocol, model suffix), read by
# pgo-build.sh's grid as well as by the config below.
PGO_EGRESS_DIALECTS="openai responses anthropic gemini cohere bedrock"

pgo_model_for() { # pgo_model_for <egress dialect> -> the trained model routed to that provider
  case "$1" in
    openai) printf 'gpt-4o-mini' ;;
    *)      printf 'gpt-4o-mini-%s' "$1" ;;
  esac
}

write_run_configs() {
  local run_port="$1" run_mock_port="$2" d
  {
    cat <<YAML
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
  # The training provider is this one loopback mock; keep the private-address guard on.
  allow_destinations: ["127.0.0.1"]
  response_headers:
    server_timing: true
# Signed-key front door. Production traffic is governed - Bearer bbk_* tokens through the keys
# arm, group admission, per-principal reqlog chains - and with an empty chain NONE of that trains.
# The trainer mints one throwaway key per run against its own admin listener (the store is
# in-memory, so the binding row only exists inside this process - exactly right for a trainer).
identity-providers:
  admin-tokens: { module: admin-tokens, token: { env: PGO_ADMIN_TOKEN } }
auth:
  chain: [keys]
  admin_auth: [admin-tokens]
  signing_key: { env: PGO_SIGNING_KEY }
# Effectively-unbounded caps: the point is to run the admission check-and-charge path hot, not
# to exercise 429s (the refusal sliver covers the reject arms, lightly).
groups:
  bench:
    limits:
      - { requests: 100000000, per: minute }
      - { concurrent: 4096 }
providers:
YAML
    for d in $PGO_EGRESS_DIALECTS; do
      if [ "$d" = bedrock ]; then
        printf '  mock-%s:\n    api_key: { env: PGO_BEDROCK_KEY }\n' "$d"
      else
        printf '  mock-%s:\n    api_key: { env: PGO_MOCK_KEY }\n' "$d"
      fi
    done
    printf 'models:\n'
    for d in $PGO_EGRESS_DIALECTS; do
      printf '  %s:\n    provider: mock-%s\n    max_concurrent: 512\n    max_requests: -1\n' "$(pgo_model_for "$d")" "$d"
    done
    cat <<YAML
pools:
  upstream_credentials: own
  bench-pool:
    members:
      - model: gpt-4o-mini
YAML
  } > "$WORK/config.yaml"
  : > "$WORK/providers.yaml"
  for d in $PGO_EGRESS_DIALECTS; do
    printf 'mock-%s:\n  protocol: %s\n  base_url: http://127.0.0.1:%s\n' "$d" "$d" "$run_mock_port" >> "$WORK/providers.yaml"
  done
}
