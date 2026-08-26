<p align="center">
  <img src="assets/busbar-logo.png" alt="Busbar" width="96" height="96">
</p>

<h1 align="center">Busbar</h1>

<p align="center">
  <strong>The self-hosted execution boundary for AI systems.</strong><br>
  Control where AI can go, what it may use, what authority it receives,
  what it may cost, and what evidence is retained—before it acts.
</p>

<p align="center">
<a href="https://github.com/GetBusbar/busbar/actions/workflows/ci.yml"><img src="https://github.com/GetBusbar/busbar/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="https://codecov.io/gh/GetBusbar/busbar"><img src="https://codecov.io/gh/GetBusbar/busbar/branch/main/graph/badge.svg" alt="Coverage"></a>
<a href="https://github.com/GetBusbar/busbar/releases"><img src="https://img.shields.io/github/v/release/GetBusbar/busbar?include_prereleases" alt="Release"></a>
<a href="https://hub.docker.com/r/getbusbar/busbar"><img src="https://img.shields.io/docker/image-size/getbusbar/busbar?sort=semver&label=image" alt="Image size"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache 2.0"></a>
</p>

Busbar sits between AI applications and the destinations they can reach:

```text
Applications and agents → Busbar → Models, MCP tools, and A2A agents
```

For traffic routed through Busbar, operators can verify, govern, route,
and record model calls, tool use, and agent delegation before they reach
approved destinations.

Busbar is a self-hosted, customer-operated static Rust binary. It keeps
provider credentials at the boundary, preserves supported native SDK
workflows, and puts policy, budgets, routing, resilience, and execution
evidence in one enforcement point.

> **What this README demonstrates today:** Busbar's model execution
> plane—native provider protocols, credential boundary, routing,
> budgets, resilience, and audit evidence. MCP tool governance and A2A
> agent trust use the same execution-boundary model.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme/matrix-dark.svg">
  <img src="assets/readme/matrix-light.svg" alt="Six by six matrix of ingress protocol against upstream protocol. All 36 pairs served. The same-protocol diagonal is forwarded byte for byte.">
</picture>

Six model wire protocols, first class on both sides: OpenAI, OpenAI
Responses, Anthropic, Gemini, Cohere, and Bedrock Converse.

Same-protocol routes are byte-for-byte identical to calling the provider
directly, because Busbar forwards the original request bytes rather than
re-serializing them. Cross-protocol routes translate modelled fields into
the target provider's native shape.

Self-hosted, always. No hosted service, no signup, and nothing phones
home. Provider credentials stay in your infrastructure, at the
enforcement boundary.

---

## Built for the governed hot path

An enforcement boundary only works if teams can deploy it on every
governed request path. Busbar is designed to make the decision in the
path without becoming the bottleneck.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme/perf-dark.svg">
  <img src="assets/readme/perf-light.svg" alt="73 microseconds added latency p50, 65.1 microseconds of gateway CPU per request, 67,837 requests per second sustained with zero failures.">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme/memory-dark.svg">
  <img src="assets/readme/memory-light.svg" alt="Resident set size flat at 7.3 MiB idle, 22.4 MiB under sustained load, returning to 16.1 MiB when the load stops.">
</picture>

*Busbar 1.5.1, AWS m7g.4xlarge (Graviton3), 4-core pin, measured 2026-08-03. Same-protocol OpenAI cell. Across all 36 cells idle stayed between 7.32 and 7.42 MiB.*

---

## A boundary, not just a proxy

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/readme/field-dark.svg">
  <img src="assets/readme/field-light.svg" alt="Wire protocol pairs served, idle resident memory and container image size, comparing Busbar with LiteLLM, Kong and Portkey.">
</picture>

| | Busbar | LiteLLM&nbsp;Py | LiteLLM&nbsp;Rust | Kong | Portkey |
|---|---|---|---|---|---|
| Wire protocol pairs served, of 36 | **36** | 8 | 1 | 4 | 8 |
| Added latency p99, µs | **82** | 8,221 | 106 | 389 | 3,720 |
| CPU per request at c=8, µs | **65** | 6,775 | 89 | 210 | 1,486 |
| Requests/sec, zero failures | **67,837** | 170 | 48,354 | 22,418 | 855 |
| Time to first token p50, µs | **129** | 9,088 | 181 | 105,907 | 27,908 |
| Idle resident memory | **7.3 MiB** | 1,080 MiB | 253 MiB | 403 MiB | 124 MiB |

| | Container image | Install |
|---|---|---|
| Busbar | **5.74 MiB**, 3 layers | one **12.39 MiB** binary, no runtime |
| LiteLLM | 360.77 MiB, 21 layers | **558 MiB** across 107 packages |

Measured 2026-08-03 on an m7g.4xlarge pinned to 4 cores. Image sizes are compressed registry layers for `getbusbar/busbar:latest` and `ghcr.io/berriai/litellm:main-latest`, linux/amd64.

Busbar overlaps with AI gateways on protocol support, routing, and
resilience. Its direction is broader: it is the customer-operated
enforcement point for AI execution, beginning with model traffic and
extending to governed tool and agent access.

Three things we will say against ourselves:

- **LiteLLM's provider catalogue is far larger than ours**, and that is a real reason to pick it. The coverage row counts ingress-to-upstream *wire protocol* pairs, not providers.
- **LiteLLM Rust is early beta** with a deliberately narrow surface, and its overhead is the same class as ours. The difference there is scope, not speed.
- **Kong is a general API gateway** with an LLM plugin bolted on. That is why its streaming row reads 106 ms and ours reads 129 µs.

Every cell is published with its own verdict and reason at [onthebench.ai](https://onthebench.ai). The harness is open source, so you can disagree with it in public. &nbsp; [Busbar vs LiteLLM](https://getbusbar.com/docs/vs-litellm/)

---

## Put the boundary in the path

Your application already speaks one of these protocols. Change the base
URL and key; Busbar becomes the point where model destinations,
credentials, routing, budgets, and execution evidence are controlled.

```diff
- client = OpenAI(api_key=OPENAI_KEY)
+ client = OpenAI(api_key=BUSBAR_TOKEN, base_url="http://localhost:8080/v1")

  # "fast" is a pool you define in config: 80% Claude, 20% GPT, Bedrock on failover
  client.chat.completions.create(model="fast", messages=[{"role": "user", "content": "Hi"}])
```

That request left as OpenAI, may have been served by Anthropic, and came back as OpenAI. If Anthropic had failed before the first byte, Busbar would have moved to the next lane without your client noticing.

<details>
<summary><strong>The same swap in the other five SDKs</strong></summary>

```python
# Anthropic: the SDK appends /v1/messages, so the pool name goes in the base URL
import anthropic
client = anthropic.Anthropic(api_key="busbar-token", base_url="http://localhost:8080/fast")
client.messages.create(model="ignored", max_tokens=1024, messages=[{"role": "user", "content": "Hi"}])

# OpenAI Responses: same client as above, same base URL
client.responses.create(model="fast", input="Hi")

# Gemini
from google import genai
from google.genai import types
client = genai.Client(api_key="busbar-token",
                      http_options=types.HttpOptions(base_url="http://localhost:8080"))
client.models.generate_content(model="fast", contents="Hi")

# Cohere v2
import cohere
client = cohere.ClientV2(api_key="busbar-token", base_url="http://localhost:8080")
client.chat(model="fast", messages=[{"role": "user", "content": "Hi"}])

# Bedrock Converse: a SigV4 boto3 client, load balanced across non-Bedrock backends
import boto3
client = boto3.client("bedrock-runtime", region_name="us-east-1",
                      endpoint_url="http://localhost:8080")
client.converse(modelId="fast", messages=[{"role": "user", "content": [{"text": "Hi"}]}])
```

Every one of these was run against Busbar 1.5.3 while writing this file. Full route and auth reference: [Protocols](https://getbusbar.com/docs/protocols/).

</details>

---

## Model routing and resilience

Model routing is one execution-plane capability. A pool is a weighted
group of lanes that share a circuit breaker; a lane that fails before
the first byte is replaced mid-request, and the breaker attributes the
fault so a bad key benches one lane instead of tripping a healthy one.

```yaml
providers:
  anthropic:       { api_key: { env: ANTHROPIC_KEY } }
  openai:          { api_key: { env: OPENAI_KEY } }
  bedrock:         { api_key: { env: AWS_KEYPAIR } }   # ACCESS_KEY_ID:SECRET_ACCESS_KEY

models:
  claude:      { provider: anthropic, upstream_model: claude-sonnet-4-5, max_concurrent: 40 }
  gpt:         { provider: openai,    upstream_model: gpt-4o,            max_concurrent: 40 }
  claude-aws:  { provider: bedrock,   upstream_model: "anthropic.claude-3-5-sonnet-20241022-v2:0" }

pools:
  fast:
    members:
      - { model: claude,     weight: 8 }   # 80 percent of traffic
      - { model: gpt,        weight: 2 }   # 20 percent
      - { model: claude-aws, weight: 1 }   # same model, other cloud, picks up load when the others trip
    breaker:
      trip: { mode: consecutive, consecutive_n: 3 }
      base_cooldown_secs: 15
    failover:
      timeout_secs: 20
      max_hops: 2
```

Your client never sees the hop, because the hop happens before the first byte reaches it, even on a streaming request. Once that first byte is out Busbar does not switch providers under your client: it records the fault against that lane and ends the stream with an error event, and the client retries. The state machine, the fault classes and the recovery probe are in [Reliability](https://getbusbar.com/docs/reliability/).

---

## Run it

One binary and one YAML file. No interpreter, no database, no sidecar.

```bash
curl -fsSL https://getbusbar.com/install.sh | sh      # busbar + providers.yaml into ./

cat > config.yaml <<'EOF'
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

Or the container, which ships a bootable default config, so one line is the whole thing:

```bash
docker run --rm -p 8080:8080 -e ANTHROPIC_KEY -e BUSBAR_ADMIN_TOKEN getbusbar/busbar
```

`busbar --validate` parses your config and every provider reference and exits non-zero on anything wrong, with no server, no network and no state, so it belongs in CI. Full walkthrough: [Getting started](https://getbusbar.com/docs/getting-started/).

---

## Kubernetes

One container, no sidecar, nothing to run beside it. The image is 5.74 MiB compressed and the process idles at 7.3 MiB, both stamped in the comparison below, so it fits a 32Mi request and a 128Mi limit with room to spare.

```bash
helm repo add busbar https://getbusbar.github.io/helm-charts
helm install busbar busbar/busbar -f my-values.yaml
```

<details>
<summary><strong>Plain Deployment, Service and ConfigMap, without Helm</strong></summary>

```yaml
apiVersion: v1
kind: ConfigMap
metadata: { name: busbar-config }
data:
  config.yaml: |
    listen: "0.0.0.0:8080"
    config: { locked: true }          # GitOps: config changes ship as a new ConfigMap
    providers:
      anthropic: { api_key: { env: ANTHROPIC_KEY } }
      openai:    { api_key: { env: OPENAI_KEY } }
    models:
      claude: { provider: anthropic, upstream_model: claude-sonnet-4-5, max_concurrent: 20 }
      gpt:    { provider: openai,    upstream_model: gpt-4o,            max_concurrent: 20 }
    pools:
      fast:
        members:
          - { model: claude, weight: 8 }
          - { model: gpt,    weight: 2 }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: busbar }
spec:
  replicas: 2
  selector: { matchLabels: { app: busbar } }
  template:
    metadata: { labels: { app: busbar } }
    spec:
      containers:
        - name: busbar
          image: getbusbar/busbar:1.5.3
          env:
            - { name: BUSBAR_CONFIG, value: /etc/busbar/config.yaml }
          envFrom:
            - secretRef: { name: busbar-keys }     # ANTHROPIC_KEY, OPENAI_KEY
          ports: [ { name: http, containerPort: 8080 } ]
          readinessProbe: { httpGet: { path: /healthz, port: http } }
          livenessProbe:  { httpGet: { path: /healthz, port: http } }
          resources:
            requests: { cpu: 100m, memory: 32Mi }
            limits:   { memory: 128Mi }
          securityContext:
            runAsNonRoot: true
            runAsUser: 65532
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities: { drop: [ ALL ] }
          volumeMounts:
            - { name: config, mountPath: /etc/busbar, readOnly: true }
      volumes:
        - name: config
          configMap: { name: busbar-config }
---
apiVersion: v1
kind: Service
metadata: { name: busbar }
spec:
  selector: { app: busbar }
  ports: [ { name: http, port: 80, targetPort: http } ]
```

`config: { locked: true }` is what lets the root filesystem be read-only: a mutable config needs a writable overlay path and Busbar refuses to boot without one. This Service is cluster-internal and the data plane has no auth chain, so turn on virtual keys before you expose it ([Governance](https://getbusbar.com/docs/guides/governance/)).

</details>

---

## What Busbar governs

Busbar's model execution plane includes native protocol support,
provider credentials at the boundary, virtual keys, group budgets and
spend tracking, weighted routing, per-lane concurrency caps,
fault-attributed circuit breaking, in-flight failover, native TLS and
mTLS, Prometheus and OTLP telemetry, and per-request audit webhooks.

The broader execution-boundary model spans three planes:

- **Model control:** Native model traffic, routing, budgets, provider
  credentials, resilience, and execution evidence.
- **Tool governance:** Caller grants, approved schemas, budget
  enforcement, and drift quarantine for MCP tools.
- **Agent trust:** Verification, pinning, re-verification, egress
  control, and target-bound credentials for A2A agents.

The SemVer-protected contract is the runtime: the data-plane HTTP
surface and supported wire-protocol contracts do not break inside a
major version. `config.yaml` is an operator artifact outside that
freeze; changes ship with `busbar --migrate-config` and a loud
fail-closed boot rather than silent behavior changes.

Single Rust binary, MSRV 1.97, Apache-2.0. Docs at
[getbusbar.com](https://getbusbar.com), contributor documentation in
[`docs/`](docs/).
