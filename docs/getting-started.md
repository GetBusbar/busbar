# Getting started

Install Busbar, point it at one provider and send the first request. This page follows the
"Run it" section of the [README](../README.md); change them together.

## Install and run

One binary and one YAML file. No interpreter, no database, no sidecar.

```bash
curl -fsSL https://getbusbar.com/install.sh | sh      # busbar + providers.yaml into ./

cat > config.yaml <<'EOF'
store: { module: memory }
providers:
  anthropic: { api_key: { env: ANTHROPIC_KEY } }   # the NAME of the env var, never the key
models:
  claude: { provider: anthropic, upstream_model: claude-sonnet-4-5 }
pools:
  fast:
    members:
      - { model: claude, weight: 1 }
EOF

export ANTHROPIC_KEY=sk-ant-...
BUSBAR_CONFIG=./config.yaml ./busbar &

curl -s localhost:8080/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model":"fast","messages":[{"role":"user","content":"Hello!"}]}'
```

Or run the container, which ships a bootable default configuration:

```bash
docker run --rm -p 8080:8080 -e ANTHROPIC_KEY -e BUSBAR_ADMIN_TOKEN getbusbar/busbar
```

Every configuration names its Store; there is no default. `memory` is compiled in and ephemeral, so
keys, usage counters, ledgers, the audit trail and rate-card history reset on restart, and one
warning at boot says so. For durable state, name a durable Store plugin; see
[configuration](configuration.md) and [plugins](plugins.md).

## Check a configuration before you boot

`busbar --validate` checks the selected configuration and provider catalog, plugin declarations and
local artifacts, and built-in `env:` and `file:` secret references. It starts no server, opens no
Store and makes no network calls. A pass checks those operator inputs only; it does not promise
that boot, plugin readiness or a backend will succeed. After startup, `GET /readyz` reports
readiness and `GET /livez` liveness; see [operations](operations.md#health--readiness).

## Platforms

Linux (x86_64 and 64-bit ARM), macOS (Apple silicon and x86_64), Windows (x86_64 only) and
container images. On ARM Linux there are two builds; the table in
[operations](operations.md) says which instruction-set level each needs.

## Next steps

- [Configuration](configuration.md) and [config at a glance](config-at-a-glance.md).
- [Architecture](architecture.md): how a request flows through Busbar.
- [Operations](operations.md): listeners, TLS, health, shutdown and backup.
- [Verify a release](verify.md) before you run it in production.
- Upgrading from 1.5.5: [the migration guide](migration-1.6.md).
