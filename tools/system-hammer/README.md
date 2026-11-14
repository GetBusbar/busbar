# busbar-system-hammer

A dev load tool that drives the WHOLE gateway: the real `busbar` binary, its real plugins, every
plane and plugin kind, against in-process mock upstreams. It reports per scenario: rps, latency
(p50/p90/p99/p999) under load, added latency (gateway minus mock at c=1), gateway CPU µs per
request, RSS idle/steady/peak/post-load, throughput drift across the load window, and errors by
status. It is a report, not a gate.

It is one of the two dev perf tools (owner decision 121): `busbar-plugin-bench` measures one plugin
alone; this measures the product. The onthebench engine stays the source of the website numbers.

## Run

From this directory (it is its own Cargo workspace, outside the product lock):

```sh
cargo run -p busbar-system-hammer --release -- --bin <path/to/busbar> --suite default
cargo run -p busbar-system-hammer --release -- --bin <busbar> --scenario llm-openai-openai --long
cargo run -p busbar-system-hammer --release -- --list
cargo run -p busbar-system-hammer --release -- selftest --concurrency 128
```

- `--suite default` (per commit, short windows: 1 s warmup, 3 s load, 1 s settle), `full` (adds
  the 72-case dialect matrix, h2c/open-loop and the webhook export), `prove`, `stores`, `planes`.
- `--long`: 5 s warmup, 60 s load, 30 s post-load settle, 10 s idle.
- `--plugins-dir <dir>`: tarballs for scenarios that load dynamic plugins (sqlite, postgres,
  valkey, mysql stores, vault, webrequest). They load under `plugins.trust.allow_unsigned`, so
  unsigned dev packs (`busbar-plugin-pack pack --allow-unsigned`) work. Without the tarball the
  scenario is reported `SKIPPED`, never silently dropped.
- Store scenarios start their database with `docker run` (published on a random loopback port)
  and remove it afterwards.
- `--busbar-sha <sha>`: the source commit when the binary's `--build-info` cannot say (local
  builds print `source-commit=unverified`).

Each run prints a plain-text table and writes `hammer-<time>-<version>-<sha>.json` and `.txt`
under `--out` (default `./hammer-reports`): git sha, `--build-info` (incl. `pgo=`), binary sha256,
host (CPU model, cores, load average), the driver ceiling, and every case with its per-second
throughput windows.

## Pieces

| module | what |
|---|---|
| `driver` | HTTP/1.1 keep-alive and h2c clients; closed loop (N in flight) and open loop (fixed rate, latency from the scheduled start, no coordinated omission); warmup; HDR histograms; per-second windows; errors by status |
| `mock` | one hyper server (h1 + h2c) on its own runtime: the six LLM dialects whole/streamed/tool-call (shapes of the oracle mock that `tests/upgrade` vendors), MCP server, A2A agent (JWS-signed card), OAuth/OIDC IdP token endpoint, Vault KV v2, OTLP and webhook sinks, webrequest sidecar, decisions (jev/nanojev), streams session mint |
| `gateway` | boots the binary (work dir, `config.yaml`, `providers.yaml`, `signing.key`, admin token), waits for `/healthz`; the shape of the upgrade harness's `Gateway::boot`, to be replaced by it when that lands |
| `procstat` | process CPU time and RSS on Linux (`/proc`) and macOS (`proc_pidinfo`) |
| `scenario` | the data files: `scenarios/*.yaml` (config + setup + cases, or an `llm_matrix`), `scenarios/suites.yaml` |

## Scenario files

```yaml
name: plane-mcp            # = file name
group: planes
config: |                  # busbar 1.6 config; {LISTEN} {ADMIN} {MOCK} {WORK} ... are filled in
  ...
config_1_5: |              # optional: the 1.5.x grammar; without it a 1.5 binary SKIPs
providers: |               # providers.yaml
plugins: [busbar-store-sqlite]   # dynamic plugin tarballs needed from --plugins-dir
docker: [{ var: PG_PORT, image: "postgres:16", port: 5432, ... }]
setup:                     # mint_key, audience_token, http (save fields), rsa_service_account, sleep_ms
  - mint_key: { as: KEY, group: bench }
cases:                     # each measured separately against the same booted gateway
  - name: tools/call
    shape: { closed: 32 }  # or { open: 500, connections: 64 }
    proto: h1              # or h2c
    requests: [{ path: /mcp, headers: {...}, body: '...', contains: "ping: hammer", weight: 1 }]
    direct: { listener: mock, path: /mcp, body: '...' }    # the upstream request, for added latency
    background: { shape: {...}, requests: [...] }          # e.g. admin ops under load
llm_matrix:                # generated LLM cases: ingress x egress x stream x pad x tools
  - { ingress: [openai, anthropic], egress: [openai], stream: [false, true], key: "{KEY}" }
```

## Known gaps

- Inbound OIDC/JWT (`busbar-auth-oidc`) needs an `https` JWKS; the mock is plaintext, so the auth
  scenario covers OAuth client credentials and JWT bearer on the egress side instead.
- `request-log-webhook` only dials `https` public hosts: `export-webhook` (suite `full`) measures the sink on the request path but nothing is delivered to the mock.
- `stub-plugins` is the core floor (open auth, memory store, no hooks/exports, instant upstream,
  plus `/healthz`): core's neutral stub plane refuses every data op today.
- The driver and mocks share the host with the gateway; every report carries the driver ceiling
  (echo) and the hammer's own CPU per request so a driver-bound number is visible.
