# Getting Started with Busbar

Busbar is your AI control plane: a single self-hosted, self-contained Rust binary (no runtime, no interpreter, no sidecar) that sits between your application and your AI providers. Point any SDK at it (OpenAI, Anthropic, Gemini, Cohere, Bedrock, or the OpenAI Responses API) and Busbar routes each request to the provider (or pool of providers) you configured, translating between wire protocols when the ingress and egress differ.

It does the same job as LiteLLM or OpenRouter (one API in front of every model and provider) and goes further: it speaks six provider protocols natively (so any vendor's SDK can point at it, not just OpenAI-shaped ones), ships as one binary with no Python runtime and no third party in your data path, and gives you per-(pool, lane) circuit breaking with in-flight failover. You run it in your own infra and it holds your keys.

This guide takes you from zero to a working request in about five minutes.

<svg viewBox="0 0 820 300" role="img" aria-label="The Busbar request path: a client SDK using OpenAI, Anthropic, or Gemini ingress sends to Busbar on port 8080, which authenticates the caller, routes by model name to a pool, translates through its intermediate representation when the ingress and egress protocols differ, and picks a lane by weighted smooth round-robin with per-lane circuit breaking before calling the provider (Anthropic, OpenAI, Bedrock, and others). When a lane's breaker is open the in-flight request fails over to a sibling member of the pool." style="width:100%;height:auto;max-width:820px;font-family:ui-sans-serif,system-ui,sans-serif;">
  <defs>
    <marker id="gs-flow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="#a3e635"/>
    </marker>
    <marker id="gs-fail" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="#94a3b8"/>
    </marker>
  </defs>
  <rect x="0" y="0" width="820" height="300" fill="#111a2e"/>
  <!-- primary request flow -->
  <g stroke="#a3e635" stroke-width="2.5">
    <line x1="168" y1="150" x2="206" y2="150" marker-end="url(#gs-flow)"/>
    <line x1="612" y1="150" x2="650" y2="150" marker-end="url(#gs-flow)"/>
  </g>
  <!-- client -->
  <rect x="16" y="110" width="150" height="80" rx="12" fill="#1a2740" stroke="#2c3a52"/>
  <text x="91" y="142" text-anchor="middle" fill="#e6edf7" font-size="14" font-weight="700">Client SDK</text>
  <text x="91" y="161" text-anchor="middle" fill="#94a3b8" font-size="10">OpenAI / Anthropic /</text>
  <text x="91" y="175" text-anchor="middle" fill="#94a3b8" font-size="10">Gemini ingress</text>
  <!-- provider -->
  <rect x="652" y="110" width="152" height="80" rx="12" fill="#1a2740" stroke="#2c3a52"/>
  <text x="728" y="142" text-anchor="middle" fill="#e6edf7" font-size="14" font-weight="700">Provider</text>
  <text x="728" y="161" text-anchor="middle" fill="#94a3b8" font-size="10">Anthropic / OpenAI /</text>
  <text x="728" y="175" text-anchor="middle" fill="#94a3b8" font-size="10">Bedrock ...</text>
  <!-- busbar core -->
  <rect x="208" y="28" width="404" height="244" rx="14" fill="#a3e635" fill-opacity="0.05" stroke="#a3e635" stroke-opacity="0.5" stroke-width="2"/>
  <text x="410" y="53" text-anchor="middle" fill="#ffffff" font-size="15" font-weight="700">Busbar  :8080</text>
  <!-- internal pipeline -->
  <g>
    <circle cx="244" cy="74" r="7" fill="#a3e635"/><text x="244" y="78" text-anchor="middle" fill="#1a2e05" font-size="9" font-weight="700">1</text>
    <text x="262" y="78" fill="#e6edf7" font-size="11.5">Authenticate the caller</text>
    <circle cx="244" cy="102" r="7" fill="#a3e635"/><text x="244" y="106" text-anchor="middle" fill="#1a2e05" font-size="9" font-weight="700">2</text>
    <text x="262" y="106" fill="#e6edf7" font-size="11.5">Route by model name to a pool</text>
    <circle cx="244" cy="130" r="7" fill="#a3e635"/><text x="244" y="134" text-anchor="middle" fill="#1a2e05" font-size="9" font-weight="700">3</text>
    <text x="262" y="134" fill="#e6edf7" font-size="11.5">IR translate<tspan fill="#94a3b8"> if ingress != egress</tspan></text>
    <circle cx="244" cy="158" r="7" fill="#a3e635"/><text x="244" y="162" text-anchor="middle" fill="#1a2e05" font-size="9" font-weight="700">4</text>
    <text x="262" y="162" fill="#e6edf7" font-size="11.5">Pick a lane<tspan fill="#94a3b8"> via weighted SWRR + breaker</tspan></text>
  </g>
  <!-- pool lanes with failover -->
  <text x="232" y="192" fill="#94a3b8" font-size="10" font-weight="600">pool</text>
  <path d="M373,198 C373,174 455,174 455,198" fill="none" stroke="#94a3b8" stroke-width="1.6" stroke-dasharray="4 3" marker-end="url(#gs-fail)"/>
  <text x="414" y="171" text-anchor="middle" fill="#94a3b8" font-size="9.5">failover</text>
  <rect x="248" y="198" width="150" height="54" rx="10" fill="#1a2740" stroke="#f87171" stroke-opacity="0.55" stroke-width="1.5"/>
  <text x="323" y="221" text-anchor="middle" fill="#e6edf7" font-size="11.5" font-weight="700">claude-sonnet-4-5</text>
  <circle cx="278" cy="238" r="3.5" fill="#f87171"/>
  <text x="333" y="241" text-anchor="middle" fill="#fca5a5" font-size="10">breaker open</text>
  <rect x="430" y="198" width="150" height="54" rx="10" fill="#1a2740" stroke="#2c3a52"/>
  <text x="505" y="221" text-anchor="middle" fill="#e6edf7" font-size="11.5" font-weight="700">gpt-4o</text>
  <text x="505" y="241" text-anchor="middle" fill="#94a3b8" font-size="10">sibling member</text>
</svg>

---

## What you need

- An API key for at least one supported provider (Anthropic, OpenAI, Gemini, Cohere, or AWS Bedrock credentials)
- The Busbar binary (see below)
- `curl` or any LLM SDK

---

## Step 1: Get the binary

**One-line install** (macOS / Linux). It detects your platform, downloads the latest release binary *and* the provider catalog into the current directory, and prints the next steps:

```bash
curl -fsSL https://getbusbar.com/install.sh | sh
```

Drops `busbar` and `providers.yaml` where you run it (no sudo). To install onto your PATH instead: `curl -fsSL https://getbusbar.com/install.sh | sudo env BUSBAR_INSTALL_DIR=/usr/local/bin sh`.

**Or download manually**: grab the archive for your platform from the [latest release](https://github.com/GetBusbar/busbar/releases/latest) (Linux `x86_64`/`aarch64`, macOS Intel/Apple Silicon, Windows `x86_64`), plus the provider catalog from [getbusbar.com/providers.yaml](https://getbusbar.com/providers.yaml). The binary is self-contained (no runtime, no virtualenv, no dependencies):

**Which 64-bit ARM Linux build do I need?** There are two, of equal standing — they are the same
release, built for two CPU generations:

| Your hardware | Download this |
| --- | --- |
| Any cloud ARM (AWS Graviton, Ampere, Google Axion), Raspberry Pi 5, Apple Silicon running Linux, anything 2016+ | `busbar-aarch64-unknown-linux-gnu.tar.gz` (the default) |
| Raspberry Pi 4 / Pi 400 / CM4, or other older ARMv8.0 boards (Cortex-A72/A53 class) | `busbar-aarch64-unknown-linux-gnu-armv8.0.tar.gz` |

The default build requires ARMv8.1 or newer so it can use the CPU's native atomic instructions —
measurably faster under concurrency, and every ARM server or desktop chip made since 2016 has
them. The `-armv8.0` build is the same binary recipe without that requirement, so it runs on the
Raspberry Pi 4 generation. If you pick wrong in the fast direction nothing breaks; if you run the
default build on a Pi 4 it stops immediately with an "illegal instruction" error — switch to the
`-armv8.0` download. Not sure what you have? `busbar --build-info` on the running binary prints
`target-features=+lse` for the default build and `target-features=default` for the compat one.

```bash
tar -xzf busbar-*.tar.gz   # extracts the `busbar` binary
chmod +x busbar
./busbar --version
```

**Or use Docker**: a tiny `FROM scratch` image (the static binary plus the provider catalog, amd64 + arm64, see the image-size badge on the [repo](https://github.com/GetBusbar/busbar) for the current compressed size), cosign-signed with build provenance:

```bash
docker run -d -p 8080:8080 \
  -e ANTHROPIC_KEY \
  -v "$PWD/config.yaml:/etc/busbar/config.yaml:ro" \
  getbusbar/busbar
```

The provider catalog ships inside the image at `/etc/busbar/providers.yaml`, so you only mount `config.yaml` (written in [Step 2](#step-2-write-a-minimal-config)). Pin an exact version (`getbusbar/busbar:1.5.3`) or ride `latest`. **On 64-bit ARM the same two-build choice applies as for the binary** (see the table above): the multi-arch image's `linux/arm64` entry is the default (ARMv8.1+) build, right for every cloud ARM host and the Raspberry Pi 5 — and for Raspberry Pi 4-class boards there is a first-class compat image under the `armv8.0` tag: `getbusbar/busbar:armv8.0` (or pin `getbusbar/busbar:X.Y.Z-armv8.0`). **If you want keys/usage/ledgers/audit to survive a restart, "a writable volume" is not the whole recipe** — see [Durable store: giving persistence a writable volume](#durable-store-giving-persistence-a-writable-volume) below for the complete four-key config plus the plugin tarball.

The `:ro` on that mount is deliberate, and it has one consequence worth knowing up front: Busbar keeps admin-API config changes in an overlay file written next to `config.yaml`, so a read-only config directory means there is nowhere to persist them. Busbar starts and serves traffic normally, logs a warning saying so, and refuses admin-API config mutations rather than applying a change that would silently revert on the next restart. That is the right default for a container you deploy from a file you version-control. If you want to drive this Busbar through the admin API instead, give the overlay a writable path:

```bash
docker run -d -p 8080:8080 \
  -e ANTHROPIC_KEY \
  -v "$PWD/config.yaml:/etc/busbar/config.yaml:ro" \
  -v busbar-data:/var/lib/busbar \
  getbusbar/busbar
```

with `config.overlay.file: /var/lib/busbar/busbar-overlay.json` in your `config.yaml`. Or set `config.locked: true` to declare the read-only posture deliberately and silence the warning.

**Or build from source** (requires Rust 1.97+):

```bash
cargo build --release      # binary at target/release/busbar
```

---

## Step 2: Write a minimal config

Prefer clicking to typing? The [config builder](https://getbusbar.com/build/) generates this file: pick your models, copy the YAML, come back for Step 3.

Busbar reads two YAML files:

- `providers.yaml`: the shipped provider catalog (protocol, `base_url`, error maps). You almost never edit this. The one-line installer fetches it for you, or grab it from [getbusbar.com/providers.yaml](https://getbusbar.com/providers.yaml).
- `config.yaml`, your deployment: which providers to activate, their key env-var names, your models, and optionally pools.

**Important: keys are never written into config.** `api_key: { env: VAR }` is a secret REFERENCE naming the *environment variable* that holds a provider's key; Busbar resolves it at startup (a `{ file: /path }` reference or a secret plugin work the same way). (Separately, `${VAR}` tokens elsewhere in `config.yaml` are expanded from the environment at load time.)

**An unset referenced variable STOPS Busbar.** A provider `api_key` reference that does not resolve refuses boot under `BUSBAR-8020`, naming the provider and the reference (never the value): Busbar will not start a lane that could only ever answer 401. `--validate` catches the same thing before you deploy — it resolves every `env:` and `file:` reference and exits `1` naming the first one that fails — so run it with the same environment the deployment will have. If an upstream genuinely takes no credential (a local ollama or vLLM), say so with `api_key: none`.

### Minimal `config.yaml` (one provider, one model, no auth)

This is the smallest config that boots and serves requests. Use it on a local machine to try Busbar quickly.

<!-- doc-check: config -->
```yaml
# config.yaml (dev/minimal, no client auth gate)
providers:
  anthropic:
    api_key: { env: ANTHROPIC_KEY }   # the NAME of the env var to read the key from, NOT the key itself

models:
  claude-sonnet-4-5:
    provider: anthropic
```

`provider` is the only required field on a model. `max_concurrent` (a per-lane concurrency limiter) is optional and defaults to unbounded; add it only when you want to cap in-flight requests to a model.

The key itself is never in this file. `api_key: { env: ANTHROPIC_KEY` } tells Busbar "read this provider's key from the `$ANTHROPIC_KEY` environment variable at startup", so you set the real secret in your environment ([Step 3](#step-3-set-environment-variables-and-run)), and `config.yaml` stays safe to commit and share.

Save this as `config.yaml` in your working directory.

`providers.yaml` must also be present. The one-line installer fetches it for you. If you built from source it lives in the repo root; otherwise grab it from [getbusbar.com/providers.yaml](https://getbusbar.com/providers.yaml).

### What the fields mean

| Field | What it does |
|---|---|
| `providers.<name>.api_key` | A secret reference to this provider's API key (`{ env: VAR }` / `{ file: /path }` / a secret plugin) |
| `models.<name>.provider` | Which provider entry in the `providers` block this model calls |
| `models.<name>.max_concurrent` | Optional per-lane concurrency limiter: max simultaneous in-flight requests to this model. Omit for unbounded (the default); set a value ≥ 1 to cap. |

`providers` and `models` are the only required sections. `listen` defaults to `0.0.0.0:8080`. `auth` defaults to an empty chain (`chain: []`), an open relay, when omitted, fine for local dev, not for production.

---

## Step 3: Set environment variables and run

```bash
# the actual secret, this is what `api_key: { env: ANTHROPIC_KEY` } in config.yaml points at
export ANTHROPIC_KEY=sk-ant-...

BUSBAR_CONFIG=./config.yaml ./busbar
```

Busbar logs a startup event per listener indicating the listen address (`busbar listening`, with the bound address as a field) — on unix you'll see one line per data-plane worker, all on the same port. It accepts requests immediately: Prometheus/TSC calibration is deferred to a background thread, so it never blocks the hot path at boot.

**Check liveness:**

```bash
curl -s http://localhost:8080/healthz
# → ok
```

`/healthz` is always unauthenticated and returns `200 ok` when at least one lane is ready, `503 no usable lanes` when every lane's circuit breaker is open. It is side-effect-free and never steals a recovery probe.

---

## Step 4: Send a request

### Via curl: Anthropic-format ingress

The model name goes in the URL path: `POST /<model-name>/v1/messages`. Busbar resolves `<model-name>` against your configured pools first, then your models, and routes the request to the matching lane.

```bash
curl -s http://localhost:8080/claude-sonnet-4-5/v1/messages \
  -H "Content-Type: application/json" \
  -d '{
    "max_tokens": 256,
    "messages": [{"role": "user", "content": "What is a busbar?"}]
  }' | jq .
```

You get back a standard Anthropic Messages response. Because both ingress and egress are Anthropic here, Busbar relays it as a native same-protocol passthrough. Routing keys off the name in the URL, not the `model` field in the body.

### Via curl, OpenAI-format ingress

The model name goes in the request body: `POST /v1/chat/completions`. This works with any OpenAI SDK or tool that targets `http://localhost:8080` as the base URL.

```bash
curl -s http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet-4-5",
    "messages": [{"role": "user", "content": "What is a busbar?"}]
  }' | jq .
```

Busbar translates the request from OpenAI format to Anthropic format on the way out, and the response from Anthropic format back to OpenAI format on the way in, through its intermediate representation, transparently. Your client receives a standard `chat.completion` object, with the answer in `choices[0].message.content`.

### Via the OpenAI Python SDK

```python
from openai import OpenAI

client = OpenAI(
    api_key="unused",          # no client auth gate in the minimal config
    base_url="http://localhost:8080",
)

response = client.chat.completions.create(
    model="claude-sonnet-4-5",     # busbar model name, not OpenAI's
    messages=[{"role": "user", "content": "What is a busbar?"}],
)
print(response.choices[0].message.content)
```

The OpenAI SDK has no idea it's talking to an Anthropic backend. Swap `model="claude-sonnet-4-5"` to any model or pool name you configured; no other change required.

### Via the Anthropic Python SDK

```python
import anthropic

client = anthropic.Anthropic(
    api_key="unused",
    base_url="http://localhost:8080",
)

message = client.messages.create(
    model="claude-sonnet-4-5",     # the model name from your config
    max_tokens=256,
    messages=[{"role": "user", "content": "What is a busbar?"}],
)
print(message.content[0].text)
```

The Anthropic SDK sends `x-api-key`; Busbar accepts it on the `/v1/messages` routes.

---

## Step 5: Add a second provider and a pool

Once the single-provider setup is working, extend the config to introduce a pool. A pool is a named group of models with weighted load balancing, per-member circuit breaking, and automatic failover.

<!-- doc-check: config -->
```yaml
# config.yaml, two providers, two models, one pool, with client auth
identity-providers:
  admin-tokens: { module: admin-tokens, token: { env: BUSBAR_ADMIN_TOKEN } }

auth:
  chain:
    - keys                                 # callers present minted signed keys
  signing_key: { env: BUSBAR_SIGNING_KEY } # required with `keys`; `busbar --generate-signing-key`
  admin_auth: [admin-tokens]           # a bare PROVIDER NAME (defined above)

providers:
  anthropic:
    api_key: { env: ANTHROPIC_KEY }
  openai:
    api_key: { env: OPENAI_KEY }

models:
  claude-sonnet-4-5:
    provider: anthropic
    max_concurrent: 20
  gpt-4o:
    provider: openai
    max_concurrent: 20

pools:
  smart:
    members:
      - model: claude-sonnet-4-5
        weight: 2
      - model: gpt-4o
        weight: 1
```

Generate the signing key `auth.signing_key` points at (busbar no longer auto-generates one), set the additional environment variables, restart Busbar, and mint a caller key (shown once):

```bash
# Prints the secret (64 hex chars) to stdout, guidance to stderr; capture just the secret:
export BUSBAR_SIGNING_KEY=$(./busbar --generate-signing-key)

export ANTHROPIC_KEY=sk-ant-...
export OPENAI_KEY=sk-...
export BUSBAR_ADMIN_TOKEN=your-admin-token

BUSBAR_CONFIG=./config.yaml ./busbar

# Mint a signed key for your app (expires in 90 days by default):
BUSBAR_CLIENT_TOKEN=$(curl -s -X POST http://127.0.0.1:8081/api/v1/admin/keys \
  -H "Authorization: Bearer $BUSBAR_ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"quickstart"}' | jq -r .token)
```

Now call the pool by name. Both ingress styles work against a pool:

```bash
# OpenAI ingress, model field selects the pool
curl -s http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $BUSBAR_CLIENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model": "smart", "messages": [{"role": "user", "content": "Hello!"}]}'

# Anthropic ingress, pool name in the URL path
curl -s http://localhost:8080/smart/v1/messages \
  -H "Authorization: Bearer $BUSBAR_CLIENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"max_tokens": 256, "messages": [{"role": "user", "content": "Hello!"}]}'
```

With `weight: 2` on `claude-sonnet-4-5` and `weight: 1` on `gpt-4o`, Busbar distributes via smooth weighted round-robin, roughly two of every three requests go to Claude and one to GPT-4o. If `claude-sonnet-4-5`'s breaker trips (on upstream 5xx, 429, timeout, or network errors), Busbar fails the request over to `gpt-4o`, provided the failure happens before the first byte of the response reaches your client. After the first byte, in-flight failover is no longer possible.

### What "cross-protocol" means here

`claude-sonnet-4-5` speaks Anthropic; `gpt-4o` speaks OpenAI. A client using OpenAI-format ingress (`/v1/chat/completions`) is making an OpenAI request. When Busbar routes that request to `claude-sonnet-4-5`, it translates the request from OpenAI to Anthropic format, and the response back, through its intermediate representation: every modelled field arrives in the other protocol's native shape, and what has no place to go is dropped at the seam rather than forwarded in a shape either end would reject. What that does and does not cover, including what is still lost in 1.6.0, is defined in [Protocols and translation](https://getbusbar.com/docs/protocols/#what-lossless-means-here). When it routes to `gpt-4o`, it passes through natively, byte-for-byte. Your client never needs to know.

---

## Checking health and stats

**Liveness** (always unauthenticated):

```bash
curl -s http://localhost:8080/healthz
```

Returns `200 ok` if any lane is ready, `503 no usable lanes` otherwise.

**Per-lane topology** (`/stats`):

```bash
curl -s http://localhost:8080/stats \
  -H "Authorization: Bearer $BUSBAR_CLIENT_TOKEN" | jq .
```

`/stats` goes through the auth middleware, so with a non-empty `auth.chain` it requires a valid key; under `chain: []` it is open. It returns a per-lane snapshot: `model`, `provider`, `max_concurrent`, `inflight`, `free_slots`, `ok`/`err`/`client_fault` counts, `usable`, `dead`, `dead_reason`, `cooldown_remaining_s`, `streak`, and `budget`. A key restricted to specific `allowed_pools` only sees the pools and lanes it can reach.

**Prometheus metrics** (`/metrics`) are opt-in. Add an `export:` instance with `module: prometheus` and a required `settings.buffer_seconds` retention window first, otherwise the route is not mounted:

```bash
curl -s http://localhost:8080/metrics \
  -H "Authorization: Bearer $BUSBAR_CLIENT_TOKEN"
```

Prometheus scrape exposition. Like `/stats`, `/metrics` is subject to the auth middleware (it is *not* auth-exempt, telemetry is a fingerprinting surface), so it requires a key with a non-empty chain and is open under `chain: []`. Key metrics: `busbar_requests_total`, `busbar_upstream_failures_total`, `busbar_breaker_trips_total`, `busbar_request_duration_seconds`, `busbar_translations_total`.

---

## Common setup variations

### Durable store: giving persistence a writable volume

**The default store is in-memory.** With no `store:` block, keys, usage counters, ledgers and the
audit trail all live in RAM and are gone on restart — Busbar logs one WARN at boot saying so. The
admin-API config overlay (Step 1's `busbar-overlay.json`) is a *separate* thing and persists on its
own writable path; it does not make keys/usage/ledgers durable.

A durable store ships as a **signed plugin**, not code baked into the binary or the Docker image —
`sqlite`, `postgres`, `mysql` and `valkey` are each a separate release from their own repo
(`GetBusbar/store-sqlite`, `GetBusbar/store-postgres`, `GetBusbar/store-mysql`,
`GetBusbar/store-valkey` — the full list, with each plugin's alias and crate name, is
[`plugins.yaml`](../plugins.yaml) at the repo root). "Give it a writable volume" is necessary but
not sufficient; the complete recipe has **four** parts:

1. **`plugins.enabled: true`** — the plugin subsystem's master switch. Default is `false`, and with
   it off a tarball sitting in the plugins directory is inert: `store.module: sqlite` refuses boot
   rather than silently falling back to memory (see the refusal table below).
2. **An ABSOLUTE `plugins.dir`.** The default, `plugins`, is a *relative* string — in the `FROM
   scratch` image (no `WORKDIR`, so the process's cwd is `/`) that resolves to `/plugins`, which is
   almost never where you meant to mount the volume. Set it explicitly to an absolute path, e.g.
   `/etc/busbar/plugins`.
3. **`store.module` + `store.settings`** naming the plugin and its own config, e.g. for sqlite:
   `store.module: sqlite` with `store.settings.db_path: /var/lib/busbar/governance.db` — and
   `db_path`'s directory must already exist on a writable volume (the plugin does not create it).
4. **The signed plugin tarball actually in `plugins.dir`.** Two ways to get it there:
   - **Mount it yourself**: download the release asset and bind-mount (or bake into a derived
     image) the `.tar.gz` into `plugins.dir`. `plugins.dir` itself only needs to be *readable* for
     this path.
   - **`plugins.fetch`**: let Busbar download it at boot. One entry, `{ github: "org/repo@tag" }`,
     resolves to the exact GitHub release-asset URL
     `https://github.com/{org}/{repo}/releases/download/{tag}/{repo}.tar.gz` — for sqlite that is
     `https://github.com/GetBusbar/store-sqlite/releases/download/v1.0.0/store-sqlite.tar.gz`
     (pin whatever tag you actually want; `v1.0.0` here is illustrative). Because this path
     *writes* the downloaded tarball into `plugins.dir`, that directory must be **writable**, not
     merely mounted — a read-only `plugins.dir` fails the download, not just the load.

Put together, a config that persists across restarts:

```yaml
plugins:
  enabled: true
  dir: /etc/busbar/plugins          # ABSOLUTE — the default ("plugins") resolves to /plugins in the image
  fetch:
    - github: "GetBusbar/store-sqlite@v1.0.0"   # or omit `fetch` and mount the tarball yourself

store:
  module: sqlite
  settings:
    db_path: /var/lib/busbar/governance.db      # directory must exist on the volume below
```

```bash
docker run -d -p 8080:8080 \
  -e ANTHROPIC_KEY -e BUSBAR_ADMIN_TOKEN \
  -v "$PWD/config.yaml:/etc/busbar/config.yaml:ro" \
  -v busbar-plugins:/etc/busbar/plugins \
  -v busbar-data:/var/lib/busbar \
  getbusbar/busbar
```

See [`docker/docker-compose.yml`](../docker/docker-compose.yml) for the same thing wired end to
end, and [`docs/plugins.md`](plugins.md) for the full plugin-subsystem reference (trust,
anti-downgrade floors, `busbar --list-plugins`).

#### What the log says when it is wrong

Every message below is copied verbatim from the code that emits it — nothing here is paraphrased.

| Symptom | Exact message | Source |
| --- | --- | --- |
| `plugins.enabled` is still `false` (the default) | `store.module: 'sqlite' requires the plugin subsystem, but plugins.enabled is false (the default). Set plugins.enabled: true and place the signed 'sqlite' store plugin tarball in the plugins directory ('plugins'), or set store.module: memory.` | `crates/busbar-core/src/preflight.rs`; reproduced verbatim by golden cell `boot.refusal__BOOT-130__boot` |
| `plugins.enabled: true` but no plugin named `sqlite` is actually in `plugins.dir` (wrong path, relative `plugins.dir` resolving somewhere unexpected, or the tarball never landed) | `no plugin matching store.module: 'sqlite' is installed in '<dir>' (plugins ARE enabled; loadable: [<names>]). Two things to check: is the plugin subsystem enabled? (it is) — and is the signed tarball actually IN the folder? Add it to plugins.fetch or drop the signed tarball in the directory, or set store.module: memory.` | `crates/busbar-core/src/preflight.rs`; same wording (auth-plugin variant) verified live by golden cell `boot.refusal__BOOT-137c__boot` |
| `db_path`'s directory does not exist on the mounted volume | `store 'busbar-store-sqlite-plugin' plugin load failed: plugin 'busbar-store-sqlite-plugin' open failed: unable to open database file: <path>` | `crates/busbar-core/src/preflight.rs` (store plugin open, called from `main.rs`); verified live by golden cell `boot.refusal__BOOT-171__boot` |
| The tarball is signed but built against an ABI this binary no longer speaks (too old or too new) | `manifest abi_version <n> is not supported for kind '<kind>' by this binary (supported range v<floor>..=v<max>)` | `crates/plugin-sign/src/lib.rs` (`verify_and_load`'s ABI-range check; covered by `crates/plugin-sign/src/tests/lib_tests.rs`) |

### auth: none (local dev, open relay)

Omit the `auth` block entirely, or set `chain: []`. No `Authorization` header required. Do not use in production.

### auth: passthrough (forward your own key)

```yaml
identity-providers:
  admin-tokens: { module: admin-tokens, token: { env: BUSBAR_ADMIN_TOKEN } }

auth:
  chain: []
```

The caller's own token (`Authorization: Bearer`, `x-api-key`, or `x-goog-api-key`) is forwarded directly to the upstream provider. Use this when each caller has their own provider key and you want Busbar purely for routing and protocol translation, not credential management.

Note: with `passthrough` Busbar forwards the caller's credential and holds no upstream keys; a caller with a bad key can hard-down a lane for everyone (30 minutes), so use it deliberately.

### Bedrock egress (Busbar signs requests with SigV4)

Add a Bedrock provider. The key env var holds `ACCESS_KEY_ID:SECRET_ACCESS_KEY` (or with an optional third segment `:SESSION_TOKEN`):

```yaml
providers:
  bedrock:
    api_key: { env: AWS_BEDROCK_CREDS }

models:
  claude-bedrock:
    provider: bedrock
    max_concurrent: 10
```

```bash
export AWS_BEDROCK_CREDS="AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

Busbar signs each outbound request with SigV4 (region parsed from the host); your clients call Busbar normally with a Busbar token. OpenAI-format clients can reach Bedrock backends this way with no SDK changes.

**Bedrock ingress** (acting as a Bedrock endpoint for native AWS SDK clients) has two tracks:

- **Open/passthrough** (`auth.chain: []`, optionally with `pools.upstream_credentials: passthrough`): Busbar does not verify the inbound SigV4 signature. The credential is forwarded upstream (passthrough) or ignored (plain `chain: []`).
- **With keys** (`auth.chain: [keys]`): Busbar verifies the inbound SigV4 signature natively (`crates/busbar/src/auth/mod.rs` `verify_bedrock_sigv4`). Mint a virtual key with `"issue_aws_credential": true` via `POST /api/v1/admin/keys`; the response includes `aws_access_key_id` + `aws_secret_access_key` (shown once). Configure your Bedrock SDK with those credentials: Busbar verifies the signature, then enforces the key's group limits and pool ACL. No `passthrough` required.

### Injecting `max_tokens` for cross-protocol calls

If you route OpenAI-format requests to an Anthropic backend, Anthropic's API requires a `max_tokens` field that OpenAI clients often omit. Busbar injects a default only on cross-protocol translation to a backend that requires `max_tokens` (Anthropic Messages) when the source omitted it. The default is 4096 unless you override it per model:

```yaml
models:
  claude-sonnet-4-5:
    provider: anthropic
    max_concurrent: 20
    default_max_tokens: 8192
```

A caller-supplied `max_tokens` is always preserved; this only applies when the field is absent and the egress requires it. It has no effect on same-protocol passthrough.

---

## Production checklist

Before taking Busbar out of dev mode:

- [ ] Set `auth.chain: [keys]` and mint a signed key per caller (keys expire; default 90 days)
- [ ] Enable inbound TLS: add a `tls` block (`cert` + `key` secret references) so the client-to-Busbar hop is encrypted, and, for zero-trust deployments, set `client_ca` to require client certs (mTLS). See [`docs/operations.md#inbound-tls--mutual-tls-mtls`](operations.md#inbound-tls--mutual-tls-mtls)
- [ ] Consider setting `max_concurrent` on models where you want to cap in-flight load to your provider tier (optional; omitted = unbounded)
- [ ] Set `max_requests` to `-1` (unlimited lifetime budget) or a finite positive budget per model
- [ ] Run `busbar --validate` (in CI and before every deploy/reload): parses and validates both YAML files with no server and no network. It resolves every `env:`/`file:` secret reference, so give the job the same secrets the deployment has. Exit `0` = valid, `1` = errors. See [`operations.md#validating-configuration-busbar---validate`](operations.md#validating-configuration-busbar---validate)
- [ ] Verify `/healthz` returns `200` and `/stats` shows all lanes `usable: true` before routing production traffic
- [ ] Consider `health.mode: dead` on providers you care about (re-probes tripped lanes so they recover faster after an outage clears)
- [ ] Set `RUST_LOG=info` (the default); increase to `debug` only temporarily for diagnostics

---

## What's next

- **Deploy it**: running Busbar for real. Process configuration, TLS termination, the two-listener model, and running multiple instances ([`docs/operations.md`](operations.md))
- **Full config reference**: every field, default, and validation rule ([`docs/configuration.md`](configuration.md))
- **Pools, breakers, and failover**: weighting, breaker tuning, session affinity, context-length failover, and exhaustion policies ([`docs/configuration.md#pools`](configuration.md#pools))
- **Running in production**: TLS termination, systemd, Docker, `/stats` monitoring, and breaker diagnosis ([`docs/operations.md`](operations.md))
- **Governance**: signed expiring keys, group limits, and the `/admin` API ([`docs/operations.md`](operations.md))
- **Architecture**: how the IR works, the six-protocol model, and why `f64` instead of `f32` ([`docs/architecture.md`](architecture.md))