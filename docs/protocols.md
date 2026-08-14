# Wire protocols and cross-protocol translation

Busbar just **listens**. Your client decides which protocol it speaks: OpenAI, Anthropic, Gemini, Bedrock, Cohere, or Responses, by which URL it calls, and Busbar accepts it. It implements all six protocols as both **ingress** (what your client speaks *to* Busbar) and **egress** (what Busbar speaks to your backend). When the two differ, Busbar translates through one internal format rich enough to hold every protocol's features, in both directions. Your client code never changes: it speaks its own native protocol and gets its own native responses back. Same-protocol routes are byte-for-byte identical to calling the provider directly; cross-protocol, read [what "lossless" means here](#what-lossless-means-here) before you rely on the word, because that section also lists what does not cross in 1.6.0.

This document covers:

1. [One protocol in, any backend out](#one-protocol-in-any-backend-out)
1. [What "point any SDK at one URL" means in practice](#what-point-any-sdk-at-one-url-means)
2. [The six protocols](#the-six-protocols), ingress route, auth carrier, SDK wiring, notes
3. [Body-model vs path-model ingress](#body-model-vs-path-model-ingress)
4. [Cross-protocol translation](#cross-protocol-translation)
5. [What survives translation and what does not](#what-survives-translation-and-what-does-not)
6. [Worked example: OpenAI SDK calling Anthropic Claude](#worked-example-openai-sdk-calling-anthropic-claude)
7. [Worked example: Anthropic SDK calling a Gemini backend](#worked-example-anthropic-sdk-calling-a-gemini-backend)

---

## One protocol in, any backend out

<svg viewBox="0 0 760 400" role="img" aria-label="Any of six client protocols enters Busbar, is translated through a superset intermediate representation, and reaches any of six backend protocols, in both directions." style="width:100%;height:auto;max-width:760px;font-family:ui-sans-serif,system-ui,sans-serif;">
  <defs>
    <marker id="ir-both" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="#94a3b8"/>
    </marker>
  </defs>
  <rect x="0" y="0" width="760" height="400" fill="#ffffff"/>
  <text x="102" y="26" text-anchor="middle" fill="#64748b" font-size="12" font-weight="700" letter-spacing="0.04em">CLIENT SPEAKS</text>
  <text x="658" y="26" text-anchor="middle" fill="#64748b" font-size="12" font-weight="700" letter-spacing="0.04em">BACKEND SPEAKS</text>
  <!-- spokes (drawn first, under the chips) -->
  <g stroke="#cbd5e1" stroke-width="1.5" marker-start="url(#ir-both)" marker-end="url(#ir-both)">
    <line x1="184" y1="62"  x2="296" y2="200"/>
    <line x1="184" y1="120" x2="296" y2="200"/>
    <line x1="184" y1="178" x2="296" y2="200"/>
    <line x1="184" y1="236" x2="296" y2="200"/>
    <line x1="184" y1="294" x2="296" y2="200"/>
    <line x1="184" y1="352" x2="296" y2="200"/>
    <line x1="464" y1="200" x2="576" y2="62"/>
    <line x1="464" y1="200" x2="576" y2="120"/>
    <line x1="464" y1="200" x2="576" y2="178"/>
    <line x1="464" y1="200" x2="576" y2="236"/>
    <line x1="464" y1="200" x2="576" y2="294"/>
    <line x1="464" y1="200" x2="576" y2="352"/>
  </g>
  <!-- hub -->
  <rect x="300" y="152" width="160" height="96" rx="16" fill="#0f172a" stroke="#a3e635" stroke-width="2.5"/>
  <text x="380" y="196" text-anchor="middle" fill="#ffffff" font-size="16" font-weight="700">Superset IR</text>
  <text x="380" y="216" text-anchor="middle" fill="#a3e635" font-size="10.5" letter-spacing="0.02em">both ways, natively</text>
  <!-- protocol chips -->
  <g font-size="13" font-weight="600" fill="#0f172a">
    <g>
      <rect x="24"  y="40"  width="160" height="44" rx="10" fill="#f8fafc" stroke="#e2e8f0"/><text x="104" y="66"  text-anchor="middle">OpenAI</text>
      <rect x="24"  y="98"  width="160" height="44" rx="10" fill="#f8fafc" stroke="#e2e8f0"/><text x="104" y="124" text-anchor="middle">Anthropic</text>
      <rect x="24"  y="156" width="160" height="44" rx="10" fill="#f8fafc" stroke="#e2e8f0"/><text x="104" y="182" text-anchor="middle">Gemini</text>
      <rect x="24"  y="214" width="160" height="44" rx="10" fill="#f8fafc" stroke="#e2e8f0"/><text x="104" y="240" text-anchor="middle">Bedrock</text>
      <rect x="24"  y="272" width="160" height="44" rx="10" fill="#f8fafc" stroke="#e2e8f0"/><text x="104" y="298" text-anchor="middle">Cohere</text>
      <rect x="24"  y="330" width="160" height="44" rx="10" fill="#f8fafc" stroke="#e2e8f0"/><text x="104" y="356" text-anchor="middle">Responses</text>
    </g>
    <g>
      <rect x="576" y="40"  width="160" height="44" rx="10" fill="#f8fafc" stroke="#e2e8f0"/><text x="656" y="66"  text-anchor="middle">OpenAI</text>
      <rect x="576" y="98"  width="160" height="44" rx="10" fill="#f8fafc" stroke="#e2e8f0"/><text x="656" y="124" text-anchor="middle">Anthropic</text>
      <rect x="576" y="156" width="160" height="44" rx="10" fill="#f8fafc" stroke="#e2e8f0"/><text x="656" y="182" text-anchor="middle">Gemini</text>
      <rect x="576" y="214" width="160" height="44" rx="10" fill="#f8fafc" stroke="#e2e8f0"/><text x="656" y="240" text-anchor="middle">Bedrock</text>
      <rect x="576" y="272" width="160" height="44" rx="10" fill="#f8fafc" stroke="#e2e8f0"/><text x="656" y="298" text-anchor="middle">Cohere</text>
      <rect x="576" y="330" width="160" height="44" rx="10" fill="#f8fafc" stroke="#e2e8f0"/><text x="656" y="356" text-anchor="middle">Responses</text>
    </g>
  </g>
</svg>

Each request Busbar receives speaks **one** protocol, the one the client chose. You can pick *any* of the six on the way in, but a single request is exactly one of them. The important part: a pool has **no fixed input protocol**. It's just a routing target. So different clients can reach the *same* pool, each in its own protocol, and Busbar fans each request out to whichever backend in the pool serves it, translating both ways when they differ.

Say you define a pool `fast` backed by Claude Opus (an `anthropic` backend) and GPT (an `openai` backend). Each of these clients can hit it natively, with no extra configuration:

| Your client speaks | It calls | Names `fast` via | Gets back |
|---|---|---|---|
| OpenAI | `POST /v1/chat/completions` | body `{"model": "fast"}` | an OpenAI response |
| Anthropic | `POST /fast/v1/messages` | URL path | an Anthropic response |
| Gemini | `POST /v1beta/models/fast:generateContent` | URL path | a Gemini response |
| Bedrock | `POST /model/fast/converse` | URL path | a Bedrock response |
| Cohere | `POST /v2/chat` | body `{"model": "fast"}` | a Cohere response |
| Responses | `POST /v1/responses` | body `{"model": "fast"}` | a Responses reply |

Client 1 makes an **OpenAI** request to `fast`; client 2 makes a **Bedrock** request to the *same* `fast`. Each request carries one input protocol, its own, and gets its response back in that same protocol: the OpenAI client gets an OpenAI body even when Claude (Anthropic) answered. You never declare an "input protocol" on a pool; Busbar listens on all six and accepts whatever each client speaks.

**One protocol in (any of the six), any backend out.** The client picks the protocol; you pick the backends.

---

## What "point any SDK at one URL" means

Every major LLM provider ships (or is compatible with) a client SDK. Those SDKs are tightly coupled to a specific base URL and a specific wire protocol: the OpenAI Python SDK always speaks the OpenAI Chat Completions protocol; the Anthropic SDK always speaks the Anthropic Messages protocol; the Google Gen AI SDK always speaks the Gemini protocol.

Every registered SDK talks to Busbar by changing exactly two things:

- **`base_url`**: point it at Busbar instead of the vendor.
- **API key**: give it a Busbar client token (or your vendor key in `passthrough` mode) instead of the vendor key.

Nothing else changes in your application code. The SDK still calls the same method (`chat.completions.create`, `messages.create`, whatever). The body it constructs is valid for its native protocol. Busbar accepts it, resolves the model/pool, and forwards: translating to the lane's protocol if necessary.

**How ingress protocol identification actually works** (`proto::detect::protocol_id`): mostly path-determined, with a small, deliberate header-first exception for auth-carrier ambiguity. The URL path is authoritative for every route this doc lists below, but a request carrying one of a few protocol-specific auth headers (`anthropic-version`/`anthropic-beta`, `x-goog-api-key`, or bare `x-api-key`, or an AWS SigV4 `Authorization` header) is routed by that header FIRST, before the path is even consulted. This exists specifically so a curl user who copies Anthropic's docs (which often omit `anthropic-version` in the simplest examples) still lands on the right protocol via `x-api-key` alone. It also means: **`x-api-key`, `x-goog-api-key`, `anthropic-version`/`anthropic-beta`, and an AWS SigV4 `Authorization` header are NOT interchangeable "any carrier reaches any protocol" tokens**. Sending one of these headers on a request whose BODY and PATH are for a *different* protocol routes to the header's protocol, not the path's, and typically 404s once that protocol's own operation resolver doesn't recognize the path. Stick to each protocol's own native auth carrier (or a bearer token, which never forces a specific protocol) and this never comes up in practice. No body-sniffing and no true content-negotiation either way: identification only ever looks at the path and this small, fixed set of headers.

---

## The six protocols

### `anthropic`, Anthropic Messages API

**Ingress routes:**

```
POST /{name}/v1/messages
POST /{provider}/{model}/v1/messages
```

`{name}` resolves first against your configured pools, then against your configured models. The two-segment form (`{provider}/{model}`) is an ad-hoc direct route that bypasses pool configuration and hits a specific provider+model pair directly: useful for debugging or for models you don't need to pool.

**Auth carrier (ingress):** `Authorization: Bearer <token>` or `x-api-key: <token>`. Both are accepted; bearer takes precedence. (Busbar's token-extraction precedence is `Authorization: Bearer`, then `x-api-key`, then `x-goog-api-key`: the same single Busbar token validates identically through any of those carriers.)

**Auth header (egress to Anthropic backend):** `x-api-key: <key>` (Anthropic's native carrier) by default, or `Authorization: Bearer <key>` if the provider's `auth` field is set to `bearer`. The shipped Anthropic catalog entry sets no `auth` field, so it uses the native `x-api-key`.

**Upstream path:** `POST /v1/messages`

**Key property:** Anthropic is the only protocol that **requires** `max_tokens` on every request (its writer is the only one whose `requires_max_tokens()` returns `true`). On a cross-protocol hop where the source omitted it (OpenAI, Gemini, Cohere, Responses, and Bedrock do not require it), Busbar injects the lane's `default_max_tokens` setting, or `4096` if none is configured. A caller-supplied value is always preserved verbatim.

**SDK wiring (Python):**

```python
import anthropic

client = anthropic.Anthropic(
    api_key="your-busbar-token",
    base_url="http://busbar:8080/my-pool",   # ← {name} is the pool or model
)

message = client.messages.create(
    model="ignored",   # busbar overwrites this with the selected lane's model
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello"}],
)
```

The Anthropic SDK appends `/v1/messages` to `base_url`, producing `POST /my-pool/v1/messages`: exactly the ingress route Busbar registers for `anthropic`.

**Note on streaming:** Anthropic ingress receives SSE (`text/event-stream`) from Busbar, regardless of which backend served the response. If the backend is Anthropic, the SSE frames pass through byte-for-byte. If it is any other protocol, Busbar re-frames the translated IR events as Anthropic SSE.

---

### `openai`: OpenAI Chat Completions

**Ingress route:**

```
POST /v1/chat/completions
```

**Auth carrier (ingress):** `Authorization: Bearer <token>`.

**Auth header (egress):** `Authorization: Bearer <key>`.

**Upstream path:** `POST /v1/chat/completions`

**Model selection:** The `"model"` field in the request body names the model or pool. Busbar reads it, resolves it against your configured pools and models, and rewrites it to the upstream model name before forwarding.

**SDK wiring (Python):**

```python
from openai import OpenAI

client = OpenAI(
    api_key="your-busbar-token",
    base_url="http://busbar:8080",
)

response = client.chat.completions.create(
    model="my-pool",     # a busbar pool or model name
    messages=[{"role": "user", "content": "Hello"}],
)
```

The OpenAI SDK appends `/v1/chat/completions` to `base_url`. Busbar resolves `"my-pool"` against pool configuration, picks a lane by SWRR, translates if the lane speaks a different protocol, and returns the response in OpenAI Chat Completions format.

**Streaming:** `stream: true` in the body. Busbar emits SSE with the `data: [DONE]` terminator the OpenAI SDK expects. Each chunk carries a stable `id`, `created`, and `model` field: replayed from the synthesis anchor so the chunk shape is indistinguishable from native OpenAI responses.

---

### `responses`, OpenAI Responses API

**Ingress route:**

```
POST /v1/responses
```

**Auth carrier (ingress):** `Authorization: Bearer <token>`.

**Auth header (egress):** `Authorization: Bearer <key>`.

**Upstream path:** `POST /v1/responses`

**Model selection:** Same as `openai`: the `"model"` field in the body.

This protocol is the newer OpenAI surface (as distinct from the older Chat Completions shape). Busbar handles it identically to `openai` in terms of routing and auth; the reader/writer pair is specialized to the Responses API's wire format.

---

### `cohere`, Cohere Chat API (v2)

**Ingress route:**

```
POST /v2/chat
```

**Auth carrier (ingress):** `Authorization: Bearer <token>`.

**Auth header (egress):** `Authorization: Bearer <key>`.

**Upstream path:** `POST /v2/chat`

**Model selection:** The `"model"` field in the request body.

**SDK wiring (Python):** Use the Cohere v2 client, which issues `POST /v2/chat`:

```python
import cohere

co = cohere.ClientV2(
    api_key="your-busbar-token",
    base_url="http://busbar:8080",
)

response = co.chat(
    model="my-pool",
    messages=[{"role": "user", "content": "Hello"}],
)
```

Busbar resolves the pool, translates if needed, and returns a Cohere-shaped response.

---

### `gemini`: Google Gemini / Gen AI

**Ingress routes:**

```
POST /v1/models/{model}:generateContent
POST /v1/models/{model}:streamGenerateContent
POST /v1beta/models/{model}:generateContent
POST /v1beta/models/{model}:streamGenerateContent
```

Both the stable `/v1/` and the beta `/v1beta/` path prefixes are accepted, served through the same fallback dispatch as every other body-model/path-model protocol (see the note on ingress identification above). Anything under `/v1/models/` or `/v1beta/models/` other than a bare `GET` (which lists models) resolves to Gemini. The Google `google-generativeai` and `google-genai` SDKs use either surface depending on the version and the method called; Busbar accepts both so you do not need to know which one your SDK version issues.

**Auth carrier (ingress):** `x-goog-api-key: <token>` (the header the Gemini SDK sends). Busbar also accepts `Authorization: Bearer` on this route (any of Busbar's carriers validate the same token). With a non-empty `auth.chain`, the value is verified as a Busbar key: not forwarded to Google.

**Auth header (egress to Gemini backend):** `x-goog-api-key: <key>`.

**Upstream path:** `/v1beta/models/{model}:generateContent` (non-stream) or `/v1beta/models/{model}:streamGenerateContent?alt=sse` (stream).

**Model selection (path-model):** The model is in the URL path: not in the body. The segment after `/models/` and before the `:action` suffix is the model identifier. See [Body-model vs path-model ingress](#body-model-vs-path-model-ingress) for how Busbar handles this.

**Streaming formats:** Gemini supports two streaming framing modes:
- **SSE (`?alt=sse`)**: standard `text/event-stream`. This is what Busbar uses on the egress path. On ingress, Busbar accepts both.
- **JSON-array framing**: the default when `?alt=sse` is absent, which is what the `google-generativeai` SDK uses by default. Busbar detects the absence of `?alt=sse` on a streaming ingress request, sets a router-internal shim key (`__busbar_gemini_json_array`), and re-frames the translated response as a JSON array rather than SSE: so the SDK receives what it expects.

**SDK wiring (Python):**

```python
import google.generativeai as genai

genai.configure(
    api_key="your-busbar-token",
    client_options={"api_endpoint": "http://busbar:8080"},
)

model = genai.GenerativeModel("my-pool")   # pool or model name
response = model.generate_content("Hello")
```

---

### `bedrock`: AWS Bedrock Converse API

**Ingress routes:**

```
POST /model/{model_id}/converse
POST /model/{model_id}/converse-stream
```

**Auth carrier (ingress):** AWS SDKs sign requests with SigV4 (`Authorization: AWS4-HMAC-SHA256 ...`). Busbar supports two tracks for Bedrock ingress depending on the auth chain.

**Track A: Open/passthrough (`auth.chain: []`, with `pools.upstream_credentials: passthrough` or without):** Busbar does not verify the inbound SigV4 signature. Bearer-style carriers (`Authorization: Bearer`, `x-api-key`, `x-goog-api-key`) are the only tokens Busbar's auth middleware reads in these modes. The SigV4 header is forwarded upstream to the Bedrock backend (`pools.upstream_credentials: passthrough`) or ignored entirely (plain `chain: []`). Use this when you want AWS SDK clients to target Busbar as a transparent Bedrock proxy with pooling and failover but without per-key governance controls.

**Track B: With keys (`auth.chain: [keys]`):** Busbar verifies the inbound SigV4 signature natively (`crates/busbar/src/auth/mod.rs` `verify_bedrock_sigv4`). An operator mints a virtual key with `"issue_aws_credential": true` via `POST /api/v1/admin/keys`; the response returns an `aws_access_key_id` + `aws_secret_access_key` alongside the signed token (both shown once, never again). The Bedrock SDK authenticates with that credential pair, Busbar verifies the signature and body integrity (`x-amz-content-sha256`), then attaches the same `GovCtx` a bearer request would, so the key's group limits and pool ACL all apply. No passthrough is required.

**Auth header (egress to Bedrock backend):** Per-request AWS SigV4, computed by Busbar using the credential the lane's `api_key` reference resolves to. The key format is `ACCESS_KEY_ID:SECRET_ACCESS_KEY` (or `ACCESS_KEY_ID:SECRET_ACCESS_KEY:SESSION_TOKEN` for temporary credentials): Busbar splits on up to three colon-separated parts. The region is parsed from the Bedrock `base_url` hostname.

**Upstream paths:** `POST /model/{model}/converse` (non-stream) and `POST /model/{model}/converse-stream` (stream).

**Model selection (path-model):** The model is `{model_id}` in the ingress URL path.

**Wire format:** Bedrock uses a binary `application/vnd.amazon.eventstream` framing for streaming, with real CRC32 checksums. Busbar decodes these frames on the egress path (when a Bedrock backend is the upstream) and re-encodes translated events as valid binary eventstream frames for Bedrock-ingress clients. Non-stream responses use JSON.

**SDK wiring (Python):**

```python
import boto3

bedrock = boto3.client(
    "bedrock-runtime",
    region_name="us-east-1",
    endpoint_url="http://busbar:8080",
)

response = bedrock.converse(
    modelId="my-pool",     # busbar pool or model name
    messages=[{"role": "user", "content": [{"text": "Hello"}]}],
)
```

---

## Operations: more than chat

Since 1.2, chat is one of six operations. Embeddings, moderations, image generation, audio (transcription, speech-to-English translation, and text-to-speech), and rerank all run through the same translation layer, in both directions, errors and usage totals included. A client speaking one protocol can call any operation on a backend speaking another, wherever both sides support it.

There is nothing to configure. A lane or pool serves whichever operations its protocol supports; you call the operation's surface instead of the chat surface, with the same model or pool name.

### Support matrix

| Operation | openai | anthropic | gemini | bedrock | cohere | responses |
|---|---|---|---|---|---|---|
| Chat | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Embeddings | ✓ | n/a | ✓ | ✓ | ✓ | n/a |
| Moderations | ✓ | n/a | n/a | n/a | n/a | n/a |
| Image generation | ✓ | n/a | ✓ | ✓ | n/a | n/a |
| Audio (transcription and speech) | ✓ | n/a | ✓ | n/a | n/a | n/a |
| Rerank | n/a | n/a | n/a | ✓ | ✓ | n/a |

The matrix reads both ways: a checked cell means that protocol speaks the operation as a client dialect (ingress) and as a backend (egress). Any checked ingress can route to any checked egress on the same row; Busbar translates between them.

### Native surfaces per protocol

Each protocol keeps its own real wire surface for each operation, exactly as its SDK sends it:

| Protocol | Operation surfaces |
|---|---|
| openai | `/v1/embeddings`, `/v1/moderations`, `/v1/images/generations`, `/v1/audio/transcriptions` (and `/v1/audio/translations`), `/v1/audio/speech` |
| gemini | `:embedContent` (and `:batchEmbedContents`) for embeddings, `:predict` for images; audio rides `:generateContent`, split by body (`responseModalities: ["AUDIO"]` is text-to-speech, an inline audio part is transcription) |
| bedrock | Converse is chat; `/model/{id}/invoke` multiplexes by body (`textToImageParams` is image generation, `inputText` is embeddings, `query` + `documents` is rerank) |
| cohere | `/v2/embed`, `/v2/rerank` |

### Calling an operation a backend lacks

The `n/a` cells in the matrix are real gaps: some backends do not implement some operations. Calling one anyway (image generation against an Anthropic lane, for example) returns a clean, well-formed 404 in the caller's own protocol dialect. It never crashes, never leaks an upstream error shape, and never affects the lane's health for other traffic. In a pool, a backend without the operation is simply not a candidate for that request.

### Image edits and variations are a supported operation, unsupported sub-op

`/v1/images/edits` and `/v1/images/variations` route as `Operation::IMAGE`, same as
`/v1/images/generations`. But every egress writer in this release emits only
`/v1/images/generations`. A request naming an `image` to edit or vary (an edit/variation body, not a
plain generation) returns a 404 naming the operation and the model, distinct from the no-backend 404
above: the operation IS supported, this particular sub-op is not.

## Body-model vs path-model ingress

The six protocols split into two groups based on where the target model (or pool name) lives in the request:

### Body-model protocols: `openai`, `responses`, `cohere`

The `"model"` field is in the JSON body. Busbar reads it, resolves it, and begins the forwarding pipeline. The `"stream"` intent is also in the body (`"stream": true`).

These three protocols share one ingress implementation (`ingress::dispatch::operation_ingress`, reached via the single axum fallback route `ingress::protocol_dispatch`, described in the note on static routing above). The only difference between them is the protocol name and the shape of their native error envelopes.

### Path-model protocols: `gemini`, `bedrock`

The model and stream intent live in the URL, not the body:

- **Gemini:** `/v1beta/models/{model}:generateContent` (non-stream) vs `/v1beta/models/{model}:streamGenerateContent` (stream). The model and action are packed into the last path segment separated by `:`. Axum cannot split on `:` inside a single path segment, so the wildcard tail (`*rest`) is captured and split on the last colon in the handler.
- **Bedrock:** `/model/{model_id}/converse` vs `/model/{model_id}/converse-stream`. Busbar determines stream intent from which route matched.

Because the body does not carry `"model"` or `"stream"`, Busbar injects them into the parsed body before running the same pool-resolution and forwarding code as body-model protocols. This injection is internal: the upstream never sees it (the injected shim keys are stripped before the egress write).

### `anthropic`, routed by path, handled separately

Anthropic ingress takes its pool-or-model name from the URL (`{name}` in `/{name}/v1/messages`), so like the path-model protocols the model field in the Anthropic body does not drive routing. But it is handled by its own handlers rather than the shared body/path-model code: `ingress::named` for `/{name}/v1/messages` and `ingress::adhoc` for the two-segment ad-hoc form (`/{provider}/{model}/v1/messages`).

---

## Cross-protocol translation

When the ingress protocol and the selected lane's egress protocol differ, Busbar translates through a superset intermediate representation (IR). This is the single mechanism that makes "point any SDK at Busbar and reach any backend" work.

### The translation pipeline

**Request translation** (`forward::translate_request_cross_protocol`):

```
ingress.reader().read_request(body)   →   IrRequest   →   egress.writer().write_request(ir)
```

Steps, in order:

1. The ingress reader parses the request body into an `IrRequest`.
2. If the egress protocol requires `max_tokens` (only Anthropic returns `true` for `requires_max_tokens()`), and the IR has none, the lane's `default_max_tokens` is injected (falling back to `4096`).
3. Tool IDs the client echoes back in `tool_result` blocks are decoded from the ingress-native shape to the egress backend's original id, so the backend sees the id it actually issued. (The reverse remap, egress id to ingress-native, runs on the response side.)
4. The `extra` map: which holds unmodeled source-protocol fields like OpenAI's `logprobs` or `logit_bias`, is cleared before writing. This is the structural leak guard: OpenAI-only fields must not reach an Anthropic or Gemini backend, where they would be rejected or silently ignored.
5. The egress writer serializes the IR into the upstream protocol's wire format.
6. Router shim keys are stripped (the Gemini JSON-array flag, and `"stream"` for path-model egress where stream intent is in the URL).
7. The `"model"` field is rewritten to the selected lane's actual model identifier.

(When ingress and egress are the same protocol, steps 1 through 5 are skipped, only shim-key cleanup and model rewrite run.)

**Response translation** (non-streaming):

```
egress.reader().read_response(body)   →   IrResponse   →   ingress.writer().write_response(ir)
```

The upstream response is buffered (up to the configured `request_body_max_bytes`, 32 MiB by default), parsed, and re-serialized in the caller's protocol format. On a cross-protocol hop, the upstream-assigned `id` is stripped and the ingress writer mints a native-format ID; `model` and `created` are preserved as the synthesis anchor.

**Response translation (streaming):** `StreamTranslate` composes the reader and writer event-by-event:

```
while let Some(event) = egress.reader().read_response_events(frame, &mut state) {
    ingress.writer().write_response_event(event)  →  emitted to client
}
```

Busbar reassembles frames that arrive split across TCP chunks, threads per-request `StreamDecodeState` (necessary for protocols like OpenAI whose flat chunk stream requires block-boundary synthesis), and emits the correct framing for the ingress protocol: SSE for the five SSE protocols on ingress (with the `data: [DONE]` terminator for OpenAI), Gemini's JSON-array framing when `?alt=sse` was absent, or binary CRC32-valid eventstream frames for Bedrock-ingress clients.

### Same-protocol passthrough

When ingress and egress protocols match, the IR round-trip is still used (`StreamTranslate::new_same_proto` decodes each response frame through the reader into IR purely as a usage side-channel), but the translator re-emits the ORIGINAL frame bytes verbatim instead of re-serializing from IR. The bytes the client receives are the upstream's bytes; busbar never re-encodes them, and every field, annotation and vendor extension survives on the wire. That is not the same claim as "as cheap as native passthrough": each frame still pays a JSON decode to extract usage (the two token counts), and the decoded value is otherwise discarded. On the Anthropic same-protocol path this decode is elided for every frame except `message_start`/`message_delta`/`error`; every other same-protocol pair still decodes every frame. The request side is byte-for-byte only when the client named the lane's exact wire model. A pool-alias route rewrites the model and re-serializes (see the `claude-sonnet` example below).

A `busbar_translations_total{from, to}` Prometheus counter is incremented per cross-protocol hop and is not touched for same-protocol requests.

### Non-2xx cross-protocol responses

Upstream error responses (non-2xx) are **never** relayed verbatim on a cross-protocol hop. The upstream error is parsed, classified, and re-serialized as a native error envelope in the ingress protocol's shape. For example, a `429` from a Gemini backend reaching an OpenAI-ingress client is reshaped into an OpenAI-shaped error with `type: "rate_limit_error"`. The error kind mapping is deterministic (`401` → `authentication_error`, `403` → `permission_error`, `429` → `rate_limit_error`, `503` → `overloaded`, `504` → `timeout`, other 5xx → `api_error`, other 4xx → `invalid_request_error`); each ingress writer renders that kind into its own native envelope (e.g. OpenAI emits `authentication_error` with `code: "invalid_api_key"`).

Same-protocol error responses (`4xx`) are relayed verbatim.

---

## What survives translation and what does not

### What "lossless" means here

The claim busbar makes, in full, so you can check it rather than take it:

> **Same-protocol routes are byte-for-byte identical to calling the provider directly: busbar forwards your original bytes, it does not re-serialize them. Cross-protocol, every modelled field survives in the target's native shape, and what cannot cross is dropped deliberately: your client always gets a response its own SDK parses, and the backend always gets a request it accepts.**

The first sentence is unconditional and is the stronger of the two: see [Same-protocol note](#same-protocol-note). The second holds for everything the IR models, and [Fields the target protocol cannot express](#fields-the-target-protocol-cannot-express) names the constructs that have nowhere to go on the other side. As of 1.6.0 there is no third list: what was published here as [Known gaps](#closed-in-160) is closed, and every remaining drop emits a `warn!` naming the field.

Busbar's translation is **lossless** in a specific, testable sense: **neither end can tell the hop happened.**

- **The client is never confused.** It gets a response its own SDK parses cleanly, in its own protocol's shape, that never contradicts what it sent: no `finish_reason`/`stop_reason` outside its enum, no field in a shape its validator rejects, no identifier minted by a foreign vendor.
- **The backend never rejects the request.** What Busbar sends upstream is a valid request in the *backend's* protocol, never a foreign-shaped structured-output object, an off-enum image format, a non-alternating message sequence, or any field the backend 400s as malformed.

The reference is native-to-native: a translated exchange should behave exactly as if the client had spoken the backend's protocol directly. A difference counts as *loss* only if it trips one of those two tests, a client that can't parse what it got back, or a backend that rejects what it was sent. Field-level differences that trip neither test (e.g. an upstream `id` replaced with an ingress-native one) are not loss.

Where a construct genuinely has **no representation** in the target protocol: a rare, inherent limit, see [Fields the target protocol cannot express](#fields-the-target-protocol-cannot-express), Busbar degrades it to the closest valid native form **and emits a `warn!`**, never something either end would reject. The degradation is observable in logs; it is never silent and never yields an unparseable or malformed wire body.

### Closed in 1.6.0

This section used to be headed "Known gaps in 1.6.0" and published a table of measured defects. **That table is empty.** Every construct it named now either crosses correctly, or has no representation in the target protocol and degrades to the closest valid native form with a `warn!` — the second case is a design limit and lives in [Fields the target protocol cannot express](#fields-the-target-protocol-cannot-express), not here.

The table is kept as an inventory of what closed, because "we fixed it" is worth less than "here is the construct, here is where it crosses, here is the test that proves it".

| Construct | How it crosses now | Proven by |
|---|---|---|
| Non-image attachments: OpenAI `input_audio` / `file`, Responses `input_file`, Anthropic `document`, Bedrock `document` / `video`, Gemini non-image `inlineData` / `fileData`, Cohere tool-result `document` | `IrBlock::Media { kind: Document \| Audio \| Video, source, name, cache_control }`. Every reader populates it and every writer projects it into its own native slot (Gemini `inlineData`/`fileData` takes any mime; Bedrock has `document` and `video`; Anthropic and Responses have `document`/`input_file`; OpenAI Chat has `input_audio` and `file`). Where a target genuinely has no slot — Anthropic has no audio or video content block, Bedrock Converse has no audio block — the attachment is dropped with a `warn!` naming the kind, **never** as an empty text block, which is indistinguishable from having sent nothing | `openai_attachments_survive_the_ir_rather_than_becoming_empty_text`, `attachments_reach_gemini_as_inline_data`, `responses_input_file_survives_the_ir`, `bedrock_document_is_modelled_without_double_emitting`, `cohere_tool_result_document_is_not_stringified`, `gemini_non_image_inline_data_is_not_an_image_block` |
| Anthropic `search_result` blocks | The retrieved passages are entirely text by Anthropic's own schema, so they cross as a `Text` block carrying the passage plus a source/title header, with the provenance attached as an `IrCitation`. The raw block stays parked in the unmodeled-block sentinel, so an Anthropic→Anthropic hop still re-emits the original bytes verbatim | `anthropic_search_result_reaches_a_foreign_client` |
| Response citations out of a **Cohere** backend | The Cohere response reader reads `message.citations` through `read_cohere_citations` into `IrCitation` (neutral fields plus the byte-exact `raw` escape) | `cohere_response_citations_reach_a_foreign_client` |
| Streaming citation deltas toward OpenAI, Cohere **and Bedrock** clients | All three emit natively: OpenAI `choices[].delta.annotations`, Cohere `citation-start`, Bedrock `contentBlockDelta.delta.citation`. The Bedrock writer declares `max_citations_per_delta() == Some(1)` so a multi-citation delta is fanned out into one frame each rather than serialized as an array its union decoder rejects | `streamed_citations_reach_openai_and_cohere_clients`, `streamed_citations_reach_a_bedrock_client`, `bedrock_citation_omits_a_location_it_cannot_honestly_fill` |
| Usage **sub-buckets**, buffered **and streaming** | `IrUsageDetail { reasoning_tokens, cache_creation_5m_input_tokens, cache_creation_1h_input_tokens, search_units }`. Every field is a SLICE of a total in `IrUsage`, never an addition, so carrying a bucket can never change what busbar bills. Read from OpenAI `completion_tokens_details`, Responses `output_tokens_details`, Gemini `thoughtsTokenCount`, Anthropic `usage.cache_creation.ephemeral_{5m,1h}_input_tokens` and Cohere `billed_units.search_units` — on the terminal STREAM frame as well as the buffered body, so the same request no longer reports a breakdown at `stream: false` and a hard `0` at `stream: true` | `openai_reasoning_tokens_reach_the_ir`, `responses_reasoning_tokens_are_not_zeroed`, `gemini_thoughts_token_count_is_the_reasoning_sub_bucket`, `anthropic_cache_tier_split_survives_the_ir`, `cohere_search_units_reach_the_ir`, `streamed_usage_sub_buckets_are_not_zeroed`, `streamed_anthropic_cache_tiers_survive`, `streamed_cohere_search_units_survive` |
| Gemini `groundingMetadata` | A Google-Search-grounded answer puts its sources in `groundingMetadata` (`groundingChunks[]` + `groundingSupports[]`), not in the older `citationMetadata`. Both are now read into `IrCitation`s, so a grounded answer reaches an OpenAI, Anthropic or Cohere client with its provenance intact instead of as an unattributed paragraph. Sources with no support spans still cross (Google omits the spans on some replies) | `gemini_grounding_metadata_reaches_a_foreign_client`, `gemini_grounding_chunks_cross_without_support_spans` |
| Request knobs that ride the `extra` map | Still cleared at the seam — that is correct for a field with no analog — but **every** key is now named in one `warn!` before the clear, sorted and greppable, with `cachedContent` and `messages[].name` additionally getting their own line naming the specific consequence. No key leaves silently | `ir/variant.rs` `prepare_for_egress`; `cross_protocol_extra_tests.rs` |
| Cohere assistant `tool_plan` | Read as an `IrBlock::Thinking`, not prepended to the assistant turn, and re-emitted into Cohere's native `message.tool_plan` slot. The model's internal plan can no longer surface to the end user as the first paragraph of the answer | `cohere_tool_plan_is_reasoning_not_visible_text` |
| `tools[].strict` | First-class on `IrTool`, carried in both directions across the OpenAI Chat ↔ Responses pair (the two dialects that model it). The other four targets have no per-tool strict flag, so they drop it with a `warn!` naming the affected tools — see the cannot-express table below | `tool_strict_crosses_the_openai_responses_pair` |
| `messages[].name` | No protocol other than OpenAI Chat models a participant name, so this is a target-protocol limit (see the cannot-express table). Two things changed: it now survives a **same-protocol re-serialize** (a pool-alias route used to strip it from every message), and the cross-protocol drop emits a `warn!` naming it in the caller's own vocabulary | `openai_message_name_survives_a_same_protocol_reserialize` |
| Response-side provider metadata: Gemini `safetyRatings`, Bedrock guardrail `trace` | These genuinely cannot cross (see the cannot-express table) — a guardrail assessment is an AWS account artifact and a harm-category rating uses Google's own vocabulary, and no target protocol has a field of that shape. What changed is that the drop is now **signalled**: the cross-protocol response seam names the fields present in the upstream body before they are discarded | `proto::warn_untranslatable_response_metadata`, called from `translate_response_cross_protocol` |

**The standing rule this section now enforces:** a construct either crosses, or it is dropped with a `warn!` that names it. There is no third category. If you find one, it is a bug — please file it.

### Always preserved

These fields survive a cross-protocol hop because they are first-class in the IR:

| Field | IR representation |
|---|---|
| `system` prompt | `IrRequest.system` |
| Messages (user / assistant / tool turns) | `IrRequest.messages: Vec<IrMessage>` |
| Text blocks | `IrBlock::Text { text, cache_control, citations }` |
| Thinking / extended-thinking blocks | `IrBlock::Thinking { text, signature, redacted, cache_control }`. `redacted: true` means `text` holds opaque provider-encrypted bytes, not plaintext |
| Tool definitions | `IrRequest.tools`: `IrTool { name, description, input_schema }` |
| Tool-use and tool-result blocks | `IrBlock::ToolUse`, `IrBlock::ToolResult` |
| Image blocks | `IrBlock::Image { source: IrImageSource, cache_control }` (media type and data live in `IrImageSource::Base64 { media_type, data }`) |
| Document / audio / video attachments | `IrBlock::Media { kind: IrMediaKind, source: IrImageSource, name, cache_control }` — the same typed source carrier `Image` uses. Projected into each target's native slot; dropped with a `warn!` naming the kind only where the target has no slot at all (Anthropic and Bedrock have no audio block; Bedrock and OpenAI Chat have no video/document-audio pairing respectively) |
| Prompt-cache breakpoints (`cache_control`) | First-class on text, tool-use, tool-result, **thinking, and image** blocks: an Anthropic cache breakpoint survives a same-protocol re-serialize instead of vanishing |
| Structured output (`response_format` / `responseSchema`) | `IrRequest.response_format`, mapped into **each backend's native shape** (OpenAI `json_schema`, Cohere `json_object`, Gemini `responseMimeType`/`responseSchema`), never forwarded in a foreign shape the backend rejects |
| Stop reason (`finish_reason` / `stop_reason` / `finishReason`) | Normalized to a **valid member of each protocol's enum** on egress: an unknown/foreign reason degrades to that protocol's SDK-safe value rather than leaking an off-enum string the client can't parse |
| `max_tokens` | `IrRequest.max_tokens` |
| `temperature` | `IrRequest.temperature: f64` (not f32, no lossy round-trip) |
| `top_p`, `top_k` | `IrRequest.top_p`, `IrRequest.top_k` |
| `stop` sequences | `IrRequest.stop: Vec<String>` |
| `stream` flag | `IrRequest.stream` |
| `n` (multiple completions) | `IrRequest.n`, a first-class field written only by protocols that model it (OpenAI `n`, Gemini `candidateCount`); preserved across those hops, omitted where the target has no analog |
| `frequency_penalty`, `presence_penalty`, `seed` | First-class IR fields; survive cross-protocol hops (dropped with `warn!` where the target protocol has no analog) |
| Grounding/web-search citations | `IrCitation` (with `raw` escape hatch for byte-exact Anthropic re-emit), in **both** directions on **all six** protocols, streaming included: Anthropic `citations_delta`, Gemini `citationMetadata` **and `groundingMetadata`**, Cohere `message.citations` / `citation-start`, OpenAI and Responses `annotations`, Bedrock `citationsContent` / `contentBlockDelta.citation`. A citation whose location cannot be honestly expressed in the target (an Anthropic page number has no Bedrock character-offset equivalent) crosses with its title and quoted text and no location, rather than with a fabricated one |
| Serving model name | `IrResponse.model` (so pooled cross-protocol responses report which model served) |
| Token usage | `IrUsage` (input/output tokens plus cache-creation and cache-read, with input-usage backfill on streams that only report it at message start) |
| Usage **sub-buckets** | `IrUsageDetail { reasoning_tokens, cache_creation_5m_input_tokens, cache_creation_1h_input_tokens, search_units }` — attribution only, never added to a total, so carrying a bucket cannot change what busbar bills. Carried on the buffered **and** streaming paths |
| `tools[].strict` | `IrTool.strict`, across the OpenAI Chat ↔ Responses pair; dropped with a `warn!` naming the tools on the four targets that have no per-tool strict flag |

**Usage-token cross-protocol nuance (Anthropic/Bedrock → OpenAI/Gemini/Responses):** Anthropic and Bedrock responses carry a separate `cache_creation` token bucket that has no equivalent field in the OpenAI, Gemini, or Responses wire shapes. When such a response is translated to one of those protocols, the reported `prompt_tokens` / `input_tokens` total *includes* cache-creation tokens (so billing is complete), but the `cached_tokens` sub-field reflects only cache-read tokens, because the target wire shape has no cache-creation bucket to place them in. Billing is unaffected (all consumed tokens are counted); only the sub-field breakdown differs.

### Fields the target protocol cannot express

This is not loss in the sense defined above: lossless means neither end can tell the hop happened, and these are fields that have *no place to go* on the other side of the hop. Forwarding them anyway would make the backend reject the request, which is the one thing translation must never do. So they are dropped at the seam, deliberately. On a **same-protocol** route none of this applies: every one of these fields survives byte-for-byte (see [Same-protocol note](#same-protocol-note)).

The tables below were **measured, not asserted**: each field was sent through Busbar to a same-protocol and a cross-protocol backend against a capture mock, and the egress wire bodies were diffed. **That measurement was made against 1.2.0 and has not been re-run since**, so on 1.6.0 read these rows as the engine's documented intent rather than a fresh reading. A 1.6.0 re-measurement is outstanding; the rows will carry its version and date when it lands. The most recent audit of the translation path (1.6.0, by code read plus an executed read/write round trip per protocol) is what produced [Closed in 1.6.0](#closed-in-160) above.

Two things can happen to a field on a cross-protocol hop:

1. **Dropped at the seam.** The field is provider-specific with no IR representation. It rides the `extra` passthrough map (which is why it survives same-protocol) and `extra` is cleared before a cross-protocol write.
2. **Dropped by the target writer.** The field IS first-class in the IR, but the target protocol has no such knob (Anthropic has no `seed`; OpenAI has no `top_k`). Dropped with a `warn!` log.

| Sent by | Field | Cross-protocol fate | What changes |
|---|---|---|---|
| OpenAI | `logprobs`, `top_logprobs` | **carried to Gemini** (`responseLogprobs`/`logprobs`), and the response data comes back in the caller's shape, streaming included; dropped toward backends with no logprobs concept (Anthropic, Bedrock) | per-token probabilities work across the OpenAI/Gemini pair |
| OpenAI | `logit_bias` | dropped at seam | token steering unavailable (token IDs are tokenizer-specific anyway) |
| OpenAI | `store`, `metadata`, `service_tier` | dropped at seam | bookkeeping and tier hints only |
| OpenAI | `stream_options` | dropped at seam | usage-in-stream hint lost |
| OpenAI | `seed`, `frequency_penalty`, `presence_penalty` | IR-carried; dropped by targets without the knob (e.g. Anthropic) | sampling reproducibility/penalties unavailable on that backend |
| Anthropic | `top_k` | IR-carried; dropped by targets without the knob (e.g. OpenAI) | top-k sampling unavailable on that backend |
| Anthropic | `thinking.budget_tokens` | **carried when the target lane declares `reasoning: true`** (straight number copy to Gemini `thinkingBudget`; bucketized to OpenAI effort words) | thinking budgets cross protocols, gated by operator config |
| Anthropic | `metadata`, `service_tier` | dropped at seam | bookkeeping and tier hints only |
| Gemini | `safetySettings` | dropped at seam | the target backend applies its own safety defaults; Gemini harm categories mean nothing elsewhere |
| Gemini | `cachedContent` | dropped at seam | the cache reference only exists at Google; the full prompt is reprocessed |
| Gemini | `thinkingConfig.thinkingBudget` | **carried when the target lane declares `reasoning: true`** (number copy to Anthropic; effort word to OpenAI; `-1` dynamic projects as medium) | thinking budgets cross protocols, gated by operator config |
| Gemini | other unmodeled `generationConfig` sub-fields | dropped at seam | provider-specific generation tweaks lost (`responseSchema`/`responseMimeType` are NOT in this list; structured output is IR-mapped) |
| Gemini | `labels` | dropped at seam | billing labels lost |
| Cohere | `documents` | dropped at seam (with `warn!`) | RAG grounding gone; the backend answers from model knowledge alone |
| Cohere | `citation_options`, `safety_mode` | dropped at seam | citations and safety mode fall back to backend defaults |
| Bedrock | `guardrailConfig` | dropped at seam | guardrails are AWS account resources; no other backend can apply one |
| Bedrock | `additionalModelRequestFields`, `performanceConfig`, `promptVariables` | dropped at seam | model-specific escape hatches lost |
| Responses | `previous_response_id` | dropped at seam | conversation state lives at OpenAI; a foreign backend answers without that context |
| Responses | `reasoning.effort` | **carried when the target lane declares `reasoning: true`** (to Anthropic/Gemini thinking budgets via the effort table); dropped with a warn otherwise | reasoning strength crosses protocols, gated by operator config |
| Responses | `store`, `truncation`, `include`, `metadata` | dropped at seam | bookkeeping and OpenAI-side behaviors lost |
| OpenAI | `messages[].name` | dropped at seam (with `warn!`) | no other protocol frames a turn as anything but (role, content), so a multi-speaker transcript reaches the backend without its speaker labels. Survives a same-protocol route byte-for-byte, including a pool-alias re-serialize |
| OpenAI, Responses | `tools[].strict` | IR-carried; dropped with a `warn!` naming the tools by targets with no per-tool strict flag (Anthropic, Gemini, Bedrock, Cohere) | the model's tool arguments are no longer *guaranteed* to conform to the schema, so validate them on that route. Cohere's `strict_tools` is a request-level switch, not a per-tool one, so it is not an equivalent |
| Gemini | `safetyRatings` (response side) | dropped at the response seam (with `warn!`) | harm-category ratings use Google's own category and probability vocabulary; no target protocol has a field of that shape. `promptFeedback.blockReason` **is** mapped to a stop reason, so a blocked prompt still reads as blocked, and `groundingMetadata` **is** carried (as citations) |
| Bedrock | guardrail `trace` (response side) | dropped at the response seam (with `warn!`) | a guardrail assessment is an AWS account artifact with no cross-vendor shape. If the trace is compliance evidence, route to a same-protocol Bedrock lane, where the upstream body reaches the client verbatim |

Some fields that LOOK protocol-specific actually have an exact analog on the other side, so Busbar carries them instead of dropping them (measured, both directions): OpenAI `user` travels as Anthropic `metadata.user_id` (the same end-user identifier), OpenAI `parallel_tool_calls` travels as Anthropic `tool_choice.disable_parallel_tool_use` (the same switch, inverted), **the reasoning ask crosses all three protocols that model it** (`reasoning_effort` / `thinking.budget_tokens` / `thinkingBudget`, converted through a configurable effort table and gated by the per-lane `reasoning` capability flag; see the [configuration reference](https://getbusbar.com/docs/configuration/#cross-protocol-reasoning-reasoning)), and **logprobs cross the OpenAI/Gemini pair in full**: the ask (`logprobs`/`top_logprobs` ↔ `generationConfig.responseLogprobs`/`logprobs`) travels one way and the per-token data (`choices[].logprobs.content[]` ↔ `candidates[].logprobsResult`) travels back, buffered and streaming. Cohere's logprobs stay same-protocol-only: its wire shape carries bare token IDs under Cohere's own tokenizer, which cannot honestly fill another protocol's token-string shape. A generic OpenAI `metadata` object still drops (Anthropic's metadata only holds `user_id`).

The rule of thumb that falls out of the table: **statefulness, grounding, and safety configuration do not cross protocols**, because they are references to machinery that only exists at one vendor. If your request depends on `safetySettings`, `guardrailConfig`, `documents`, or `previous_response_id`, route it to a same-protocol backend (pin the pool, or use `exclusions`/direct routing), where all of it survives byte-for-byte. Sampling periphery (`logit_bias`, `top_k`, `seed`) degrades gracefully: the request still works, that one knob just does not exist over there.

Also note: **protocol-specific identifiers** are replaced, not leaked. The upstream's `id` is swapped for an ingress-native minted ID on cross-protocol responses, so Anthropic `msg_...` IDs never appear in OpenAI-shaped responses. That is translation working, not loss.

### The `extra` map

Fields that the ingress reader encounters but does not model as first-class IR fields are stored in `IrRequest.extra` (a passthrough JSON map). On a same-protocol passthrough they reach the upstream unchanged. On a cross-protocol hop, `extra` is cleared in its entirety before the egress write (the same step that drops `logprobs` and `logit_bias`): intentionally, so source-protocol-specific fields never reach a backend that rejects unknown fields.

### Same-protocol note

On same-protocol routes, none of the above applies. The request body is forwarded byte-for-byte when the client named the lane's exact wire model (a pool-alias route rewrites the model and re-serializes instead); the response body is streamed byte-for-byte in every case. Every field, every annotation, every vendor extension survives on the wire, because busbar never re-encodes them. But the response side still decodes each frame into IR as a usage side-channel and discards the result; "byte-for-byte" describes what reaches the client, not how much work busbar does to get there. See "Same-protocol passthrough" above.

---

## Worked example: OpenAI SDK calling Anthropic Claude

**Scenario:** Your application uses the OpenAI Python SDK. You want to route requests to Claude through Busbar using the OpenAI Chat Completions wire format on ingress, while the backend speaks the Anthropic Messages protocol.

### 1. Configure Busbar

```yaml
# config.yaml
listen: "0.0.0.0:8080"

identity-providers:
  admin-tokens: { module: admin-tokens, token: { env: BUSBAR_ADMIN_TOKEN } }

auth:
  chain: [keys]        # callers present minted signed keys
  admin_auth: [admin-tokens]           # a bare PROVIDER NAME (defined above)

providers:
  anthropic:
    api_key: { env: ANTHROPIC_KEY }

models:
  claude-sonnet:
    provider: anthropic
    max_concurrent: 20
    default_max_tokens: 4096

pools:
  fast:
    members:
      - model: claude-sonnet
        weight: 1
```

```bash
export BUSBAR_ADMIN_TOKEN=my-admin-token
export ANTHROPIC_KEY=sk-ant-...
BUSBAR_PROVIDERS=./providers.yaml BUSBAR_CONFIG=./config.yaml ./busbar

# Mint a caller key (the signed token is shown once):
BUSBAR_TOKEN=$(curl -s -X POST http://127.0.0.1:8081/api/v1/admin/keys \
  -H "Authorization: Bearer $BUSBAR_ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"local-dev"}' | jq -r .token)
```

### 2. Call it with the OpenAI SDK

```python
import os
from openai import OpenAI

client = OpenAI(
    api_key=os.environ["BUSBAR_TOKEN"],   # your minted busbar key, not an OpenAI key
    base_url="http://localhost:8080",
)

response = client.chat.completions.create(
    model="fast",               # the busbar pool name
    messages=[
        {"role": "user", "content": "What is the capital of France?"},
    ],
)

print(response.choices[0].message.content)
```

### What happens on the wire

1. The OpenAI SDK issues `POST http://localhost:8080/v1/chat/completions` with body:

   ```json
   {
     "model": "fast",
     "messages": [{"role": "user", "content": "What is the capital of France?"}]
   }
   ```

2. Busbar's auth middleware reads `Authorization: Bearer <token>`, verifies the signed key (signature + expiry + denylist), and admits the request.

3. The ingress dispatcher (`ingress::dispatch::operation_ingress`, reached via the single fallback route) reads `"model": "fast"` from the body, resolves `fast` against the pool table, and picks `claude-sonnet` via SWRR.

4. `claude-sonnet` maps to the `anthropic` provider (egress protocol `anthropic`). Ingress protocol is `openai`. They differ: translation runs.

5. `translate_request_cross_protocol`:
   - The OpenAI reader parses the body into an `IrRequest` with one user message and `stream: false`.
   - No `max_tokens` in the IR. Anthropic `requires_max_tokens()` returns `true`. The lane's `default_max_tokens: 4096` is injected → `IrRequest.max_tokens = Some(4096)`.
   - The Anthropic writer serializes to (with `"model"` rewritten to the lane's actual model):

     ```json
     {
       "model": "<lane model>",
       "max_tokens": 4096,
       "messages": [{"role": "user", "content": "What is the capital of France?"}]
     }
     ```

6. Busbar issues `POST https://api.anthropic.com/v1/messages` with `x-api-key: sk-ant-...` and the translated body.

7. Anthropic returns a Messages-format response:

   ```json
   {
     "id": "msg_01XFDUDYJgAACzvnptvVoYEL",
     "type": "message",
     "role": "assistant",
     "content": [{"type": "text", "text": "Paris."}],
     "model": "<anthropic model>",
     "stop_reason": "end_turn",
     "usage": {"input_tokens": 14, "output_tokens": 5}
   }
   ```

8. Response translation runs (`anthropic` → `openai`):
   - The upstream `id` (`msg_01XFD...`) is stripped; Busbar mints an OpenAI-format ID. `model` and `created` are preserved.
   - The Anthropic reader parses to an `IrResponse` carrying the text block, `stop_reason: "end_turn"`, and usage `{input: 14, output: 5}`.
   - The OpenAI writer serializes to a `chat.completion` object:

     ```json
     {
       "id": "chatcmpl-<busbar-minted>",
       "object": "chat.completion",
       "created": 1718000000,
       "model": "<anthropic model>",
       "choices": [{
         "index": 0,
         "message": {"role": "assistant", "content": "Paris."},
         "finish_reason": "stop"
       }],
       "usage": {"prompt_tokens": 14, "completion_tokens": 5, "total_tokens": 19}
     }
     ```

9. The OpenAI SDK receives a response it considers valid OpenAI Chat Completions output. `response.choices[0].message.content` is `"Paris."`. The SDK is unaware that Anthropic served it.

---

## Worked example: Anthropic SDK calling a Gemini backend

**Scenario:** Your application uses the Anthropic Python SDK. You want to route some requests to a Gemini backend (for cost or capability reasons) without changing any application code.

### 1. Configure Busbar

```yaml
providers:
  anthropic:
    api_key: { env: ANTHROPIC_KEY }
  gemini:
    api_key: { env: GEMINI_KEY }

models:
  claude-sonnet:
    provider: anthropic
    max_concurrent: 20
    default_max_tokens: 4096
  gemini-flash:
    provider: gemini
    max_concurrent: 30
    default_max_tokens: 4096

pools:
  smart:
    members:
      - model: claude-sonnet
        weight: 3
      - model: gemini-flash
        weight: 1
```

### 2. Call it with the Anthropic SDK

```python
import anthropic

client = anthropic.Anthropic(
    api_key="my-busbar-token",
    base_url="http://localhost:8080/smart",   # {name} = the pool
)

message = client.messages.create(
    model="ignored",   # overridden by busbar
    max_tokens=512,
    messages=[{"role": "user", "content": "Summarize the water cycle in two sentences."}],
)

print(message.content[0].text)
```

When SWRR selects the `gemini-flash` lane (roughly a quarter of the time at these weights), the request is an `anthropic`-ingress → `gemini`-egress translation:

- The Anthropic reader parses the body, including `max_tokens: 512` (caller-supplied, so no injection needed).
- The Gemini writer serializes to the Gemini `generateContent` shape, mapping the messages array and the user's `max_tokens` to Gemini's `generationConfig.maxOutputTokens`.
- Busbar constructs the upstream URL `POST <gemini base_url>/v1beta/models/<lane model>:generateContent` with `x-goog-api-key: <GEMINI_KEY>`.
- Gemini responds in its own format; the Gemini reader parses it; the Anthropic writer produces an Anthropic Messages response. The Anthropic SDK receives it and sees a valid `Message` object. `message.content[0].text` holds the response.

When SWRR selects the `claude-sonnet` lane (the rest of the time), the ingress and egress protocols are both `anthropic`, no translation. But this specific example passes `model="ignored"`, so busbar must rewrite the model field to the lane's wire model; that rewrite is exactly what takes the request OFF the byte-for-byte fast path, so the body is materialized and re-serialized with the model corrected and the `x-api-key` header injected. A request that already names the lane's exact wire model stays byte-for-byte.

The application code is identical in both cases.

---

## Protocol compatibility matrix

The IR is a superset every reader maps into and every writer maps out of, and the protocol registry constructs all six reader/writer pairs, so every ingress can target every egress.

| Ingress ↓ / Egress → | `anthropic` | `openai` | `gemini` | `bedrock` | `responses` | `cohere` |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| `anthropic` | passthrough | translated | translated | translated | translated | translated |
| `openai` | translated | passthrough | translated | translated | translated | translated |
| `gemini` | translated | translated | passthrough | translated | translated | translated |
| `bedrock` | translated | translated | translated | passthrough | translated | translated |
| `responses` | translated | translated | translated | translated | passthrough | translated |
| `cohere` | translated | translated | translated | translated | translated | passthrough |

"Passthrough" means the request and response bodies are forwarded byte-for-byte on the wire. Nothing is re-encoded before it reaches the client. It does NOT mean no IR round-trip: as "Same-protocol passthrough" above describes, the response side still decodes each frame through the IR as a usage side-channel; only the re-encode is skipped. "Translated" means the request and each response frame passes through the IR AND is re-serialized from it. Both paths produce valid wire output in the ingress protocol.

A heterogeneous pool (members spanning more than one egress protocol) emits a warning at startup. The warning is informational, the pool works, but tells you that some requests through it will translate and some will not, depending on which lane SWRR picks.

---

## Quick reference: routes and SDK swap

| Protocol | Ingress route(s) | SDK config, change `base_url` to | Auth header sent by SDK |
|---|---|---|---|
| `anthropic` | `POST /{name}/v1/messages` | `http://busbar:8080/<pool-or-model>` | `x-api-key` or `Authorization: Bearer` |
| `openai` | `POST /v1/chat/completions` | `http://busbar:8080` | `Authorization: Bearer` |
| `responses` | `POST /v1/responses` | `http://busbar:8080` | `Authorization: Bearer` |
| `cohere` | `POST /v2/chat` | `http://busbar:8080` | `Authorization: Bearer` |
| `gemini` | `POST /v1[beta]/models/{model}:generateContent[Stream]` | `http://busbar:8080` (via `api_endpoint`) | `x-goog-api-key` |
| `bedrock` | `POST /model/{model_id}/converse[-stream]` | `http://busbar:8080` (via `endpoint_url`) | SigV4, with keys: minted `aws_access_key_id`/`aws_secret_access_key` (verified by Busbar); open mode: `auth.chain: []` (+ `pools.upstream_credentials: passthrough` to forward creds) |