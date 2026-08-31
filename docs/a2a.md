# A2A

Busbar fronts your A2A agents and delegates to the ones you register, over all three of the specification's bindings — JSON-RPC, HTTP+JSON and gRPC — on the one listener. A caller authenticates against Busbar with an audience-bound token, sees only the agents its key grants it, submits work that becomes a durable task, and gets a task id back. Everything a model-plane request already got — the key, its grants, its budget, hooks and the audit chain — applies to an agent task unchanged.

This page is the operator's reference: what a deployment gets by turning it on, the complete configuration grammar and every boot refusal, how identity is established, the three bindings and their routes, the task lifecycle, push-notification delivery, what a tripped agent returns, and what the plane emits.

Cross-references: [MCP](/docs/mcp/) (the sibling plane, one vocabulary) · [Circuit breaker](/docs/circuit-breaker/) (the one FSM, on all three planes) · [Configuration](/docs/configuration/) · [Observability](/docs/observability/) · [Hooks](/docs/hooks/).

---

## What the plane is

The `agents:` section registers external A2A agents. Registering one turns on **two** directions, and they are gated separately.

**The receiving side** — Busbar *fronts* those agents. It serves its own agent card, an extended card that lists the agents a caller is entitled to, and the A2A operation surface on three bindings. A caller talks to Busbar; Busbar relays to the registered backend.

**The delegating side** — Busbar reaches out to a registered agent as a client, presenting a leased credential of its own, over the binding that agent's verified card declares.

### A deployment with no `agents:` block gains nothing

`A2aPlane::from_config` returns `None` when no agent is configured, and that is the whole gate: no registry, no re-verification, no route (`crates/busbar-a2a/src/a2a/plane.rs`). "Is the A2A plane running here?" is answered by the mounted surface rather than by a boolean an operator has to trust.

### And a delegating-only deployment mounts no route either

The receiving side additionally needs a top-level **`public_url:`**. `A2aPlane::admission()` answers `None` without one (`crates/busbar-a2a/src/a2a/plane.rs:301-307`), `receive::mount` then returns the router untouched (`crates/busbar-a2a/src/a2a/receive.rs:2393-2396`), and `appbuild` claims no path and binds no audience (`crates/busbar-core/src/appbuild.rs:1469-1487`). That is deliberate rather than an oversight: an operator may configure `agents:` for the delegating direction alone, and a deployment that only delegates fronts nothing — it has no resource for a token to be bound to and no metadata document to point a refused caller at. Refusing to boot would make the receiving side's requirement the whole plane's.

Concretely, with `agents:` but no `public_url:` you get none of `/a2a`, `/a2a/`, `/a2a/agents/{id}`, the REST routes, `/a2a/push`, `/lf.a2a.v1.A2AService/*`, `/.well-known/agent-card.json` or `/.well-known/oauth-protected-resource/a2a`. The relay, the credential leases, the registry and verify-on-call all still exist.

There is a second consequence worth knowing: the `a2a_inbound` credential kind is conferred **only** when the plane is audience-bound (`crates/busbar-a2a/src/a2a/receive.rs:53-62`), and `inbound::authorize` refuses the empty kind. So even if a route existed, nothing could be admitted through it.

---

## Configuration

### The `agents:` section

`agents:` is a sibling of `pools:` and `tools:`: a map whose keys are registrations, with the same two words reserved at the section level on every plane (`crates/busbar-a2a/src/a2a/config.rs:13-20`).

| Reserved section key | Type | Combine rule |
|---|---|---|
| `agents.hooks` | list of bare hook names | **ADDITIVE** — union with each agent's own `hooks:`, deduped by name |
| `agents.upstream_credentials` | `own` (`passthrough` refused) | **OVERRIDE** — an entry's own value replaces it |

Naming an agent `hooks` or `upstream_credentials` is refused at parse (`crates/busbar-core/src/plane/config.rs:278-287`, `:312-317`).

#### `agents.<name>` — one registered agent

`deny_unknown_fields`: a typo'd key fails boot rather than silently un-pinning an agent (`crates/busbar-a2a/src/a2a/config.rs:196`).

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `url` | string | **yes** | — | The agent's A2A endpoint. `http://` or `https://`. Never client-visible: callers reach it through Busbar. |
| `pin` | object | **yes** | — | The out-of-band trust root. Required even when it is `unpinned`. |
| `pin.mechanism` | `jws_issuer_key` \| `cert_spki` \| `mtls` \| `unpinned` | **yes** | — | |
| `pin.key` | string | required for the three rooted mechanisms; **refused** for `unpinned` | — | JWS verification key, or a certificate SPKI hash. |
| `pin.fingerprint` | string | no | absent | The approved canonical card fingerprint, where you already have one. Absent means "capture it at `connect` and let me approve it", which is the normal first registration. |
| `client_identity` | object | **required** when `pin.mechanism: mtls`; optional otherwise; **refused** on an `http://` URL | absent | The certificate Busbar PRESENTS to this endpoint. |
| `client_identity.cert` | `SecretRef` | yes (within the block) | — | PEM chain, leaf first. |
| `client_identity.key` | `SecretRef` | yes (within the block) | — | PEM private key (PKCS#8, PKCS#1 or SEC1). **There is deliberately no way to write PEM bytes here** — an inlined private key is a private key in every config dump, every `--validate` output, every admin GET and every version-history row. |
| `reverify_ttl` | `<n><s\|m\|h\|d>` | no | `5s` (`a2a/config.rs`) | The longest a verification may be reused on the delegation path before the card is re-fetched and re-verified. `0` = strict-live; a larger value is an explicit security downgrade. See [Tool and agent trust](/docs/tool-and-agent-trust/). |
| `recovery_backoff` | `<n><s\|m\|h\|d>` | no | `15m` (`a2a/config.rs:80`) | How long after a DRIFT a clean answer is disbelieved. The only half of the cadence that is ever held. |
| `protocol_version` | string | no | the release default | Pinned per registration because the well-known card path moved between versions, and a registration that follows whatever the upstream now claims has no pin at all. |
| `allow_private` | bool | no | `false` | Permits a plaintext `http://` endpoint and a loopback / link-local / RFC1918 / CGNAT address for this one agent. **Never** permits a cloud-metadata address, whatever it says. |
| `upstream_credentials` | `own` | no; **`passthrough` refused** | | |
| `upstream_credential` | object | no | absent | The leased outbound credential Busbar presents. See below. |
| `egress_scopes` | list of strings | no | `[]` | **Which fronted agents may delegate here.** Absent or empty ⇒ NONE may — reading an empty list as "everyone" would be a registration granting egress nobody wrote down. |
| `hooks` | list of bare names | no | `[]` | Adds to `agents.hooks:`. |

**`upstream_credential`** (`crates/busbar-a2a/src/a2a/creds.rs:238-250`), `deny_unknown_fields`, three fields and no more:

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `secret` | `SecretRef` | **yes** | — | A handle resolved at delegation time. Never the secret, never the caller's. |
| `placement` | `bearer` \| `{ header: <name> }` | no | `bearer` | `bearer` sends `Authorization: Bearer <secret>`; `header:` sends the named header carrying the secret verbatim, which is several vendors' `APIKey` scheme. It is an enum precisely so a secret cannot be placed in a query string, which lands in every access log on the path (`creds.rs:211-214`). |
| `lease_ttl_ms` | u64 milliseconds | **yes** | — | Must be > 0. |

`lease_ttl_ms` is enforced inside the lease type, not at call sites: the secret leaves a `Lease` by exactly one route, `header_for(agent_id, now_ms)`, which refuses `WrongAgent` if the lease was minted for a different agent and `Expired` if the TTL has elapsed (`crates/busbar-a2a/src/a2a/creds.rs:344-367`). A `Lease` prints `<redacted; present>` under `Debug`. Minting reads the agent id **off the egress grant** rather than as a sibling parameter, so "authorise against A, mint against B" is not expressible (`creds.rs:411-430`), and the grant type is producible only by the egress gate, so skipping the gate does not compile (`creds.rs:201-208`).

```yaml
public_url: https://gateway.example.com     # REQUIRED for the receiving side

agents:
  hooks: [pii-guard]                        # fires for every fronted agent

  planner:
    url: https://planner.vendor.example/a2a
    pin: { mechanism: jws_issuer_key, key: "MCowBQYDK2Vw…" }
    reverify_ttl: 5s
    recovery_backoff: 15m
    upstream_credential:
      secret: { env: PLANNER_API_KEY }
      placement: { header: X-API-Key }
      lease_ttl_ms: 30000
    egress_scopes: [triage]                 # only the fronted agent `triage` may delegate here
    hooks: [planner-audit]
```

### Boot refusals: the `agents:` section

`validate_agent` is called from **both** the config file's `Deserialize` and the admin write path, so the API refuses exactly what the file refuses (`crates/busbar-a2a/src/a2a/config.rs:315-322`). This was not always true, and the defect it fixed is instructive: the API used to persist a definition the file would have refused, then drop it at the next rebuild with a log line.

| Refusal | Condition | `a2a/config.rs` |
|---|---|---|
| `url:` must name the agent's A2A endpoint | empty | `326-328` |
| `url:` must be an http:// or https:// endpoint | any other scheme; checked at boot so it does not land on a delegation six hours later | `331-337` |
| rooted `pin.mechanism` with no `pin.key` | a pin with nothing to verify with is not a pin | `341-348` |
| `pin.mechanism: unpinned` carrying `pin.key` | key material never verified against reads to an operator as protection that does not exist | `349-355` |
| `pin.mechanism: mtls` with no `client_identity:` | `mtls` means the endpoint is served behind mutual TLS; a client with nothing to present is refused at the handshake with `CertificateRequired`, not at the pin — and it would fail six hours later on a re-verification tick rather than here | `361-368` |
| `client_identity:` on an `http://` URL | a client certificate is a TLS-handshake object and plaintext has no handshake to present it in | `372-377` |
| **`upstream_credentials: passthrough`** | at the section level *and* per entry | `303-305`, `383-385` |
| `upstream_credential.lease_ttl_ms: 0` | a lease that expires at the instant it is minted is a credential that can never be presented | `389-394` |
| `upstream_credential.placement.header:` empty | | `395-401` |
| `egress_scopes:` contains an empty name | an empty scope grants nothing and reads as though it grants something | `404-411` |
| `reverify_ttl:` / `recovery_backoff:` unparseable | | `413-419` |
| a `hooks:` entry that is not a bare name, or that reaches onto another section | | `plane/config.rs:180-201` |
| a `hooks:` entry naming a hook not defined in the top-level `hooks:` map | checked over the whole config in `resolve` | `config/mod.rs:4405-4414` |

**The `passthrough` refusal is the one to understand.** `passthrough` means "forward the CALLER's credential upstream". On the delegation plane that would hand a third-party vendor a working Busbar credential belonging to somebody else — the caller's key authenticated them *to Busbar* and authorised them against *Busbar's* scopes, and it means nothing anywhere else. **Busbar delegates as itself.** The word stays reserved on every plane so the vocabulary is learned once; the value is refused loudly, because accepting it and quietly doing something else is how an operator ends up believing a credential is being forwarded when it is not, or the reverse (`crates/busbar-a2a/src/a2a/config.rs:82-95`).

### There is no empty-`auth.chain` boot refusal on this plane

`config_validate`'s **rule set** has no `agents:` arm. The MCP plane refuses to start with `mcp:` present and an empty `auth.chain` (`crates/busbar-core/src/config_validate/mod.rs:945-956`); **A2A has no equivalent check**, and you should not read that as the plane serving anonymously. (`config_validate` does walk `agents:`, but only to collect secret references, exhaustively and with no `..` — `crates/busbar-core/src/config_validate/secret_refs.rs:345-389`.)

What enforces it instead is a runtime requirement stated in three places:

- **Governance is mandatory on the receiving path.** A request arriving with no governed key answers `governance_required()` ahead of the media-type and version gates and before any parse (`crates/busbar-a2a/src/a2a/receive.rs:745-748`), and a deployment with `app.governance` absent is refused again at the meter, before the work rather than after (`receive.rs:953-955`). The plane's whole admission story is an audience on a Busbar-minted token plus that key's `agent` scopes, and neither exists with governance off (`receive.rs:597-598`).
- **The credential kind is conferred only by an audience-bound mount**, and `inbound::authorize` refuses the empty kind (`receive.rs:53-62`).
- **An unknown agent id resolves to an empty grant list**, so the ordered gate refuses (`crates/busbar-a2a/src/a2a/inbound.rs:177-186`).

The practical difference from MCP: a misconfiguration here surfaces as every request being refused at runtime rather than as a process that will not start. Configure `auth.chain` before you turn the plane on.

### Failover pools: `pools:`

A pool in the one neutral top-level `pools:` map whose members are `agents:` registrations is an A2A failover pool — the pool's kind is **inferred from its members**, so the same grammar in core serves every plane and an operator learns the concept once (`crates/busbar-core/src/failover/mod.rs:113-118`). It tells Busbar that two registrations are **the same agent registered twice**, and the walk runs at the admission of every fresh submission (`crates/busbar-a2a/src/a2a/route.rs:167`).

It is **opt-in and declaring no A2A pool is exactly today's behaviour**.

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `members` | list of bare `agents:` names | yes, **≥ 2** | `[]` | ORDERED: the first is the primary, and its approved card fingerprint is the one every other member must match. |
| `repeatable` | list of operation names | no | `[]` | Operations safe to perform TWICE. |

```yaml
pools:
  planner:                        # kind = A2A, inferred from its `agents:` members
    members: [planner-eu, planner-us]
```

Boot refusals are identical to those for an MCP pool, from the same function (`crates/busbar-core/src/config/mod.rs:1585-1639`): fewer than two members; a member named twice; **a member that is an entry in `tools:` or `models:` rather than `agents:`** — no pool may straddle two planes (a pool's kind is inferred from its members, so they must all be the same kind), and the message names the section the entry really lives in; a member defined nowhere; an empty `repeatable:` entry.

**Interchangeability is checked, not asserted.** On this plane the pin the walk compares is the **approved canonical card fingerprint** (`crates/busbar-core/src/failover/mod.rs:180-186`). A request moves between two candidates only when those fingerprints agree; a candidate with nothing approved yet can never match, not even another unapproved one — two unknowns are not one fact. You are asserting only *"these names are the same deployment"*.

**A reroute is not a retry**, and the seam draws the line there. Before the first byte, the request never left Busbar and moving it duplicates nothing: that is the movement the rule allows by default. After a dispatch has gone out, moving it is a genuine repeat of work the backend may already have done, and the rule refuses it unless the operation is named in `repeatable:` (`crates/busbar-core/src/failover/mod.rs:60-80`). There is no `repeatable: all`.

Reroute never means Busbar found somewhere else to send a task on its own. It means the walk chose a different member of a pool you declared, whose fingerprint Busbar verified matches. There is no discovery, and no member you did not write down. It also applies to **fresh submissions only**: an accepted task lives at the member that accepted it, and a verb naming that task is refused rather than moved.

---

## The three bindings, and what is mounted

The A2A specification models three bindings as three interfaces of **one** agent (`supportedInterfaces[]`, not three agents), and Busbar mounts them that way. The plane declares three wire formats, ordered, with JSON-RPC canonical (`crates/busbar-core/src/plane/mod.rs:208-228`).

| Route | Method | Auth | What it is |
|---|---|---|---|
| `/.well-known/oauth-protected-resource/a2a` | GET | **none** | RFC 9728 metadata. |
| `/.well-known/agent-card.json` | GET | **none** | Busbar's own agent card. |
| `/a2a` and `/a2a/` | POST | key | The JSON-RPC binding, plane-scoped: the agent is resolved from the caller's catalogue. |
| `/a2a/agents/{agent_id}` | GET | key | One fronted agent's rewritten card. |
| `/a2a/agents/{agent_id}` | POST | key | The JSON-RPC binding, addressed to one agent. |
| `/a2a/message:send`, `/a2a/message:stream`, `/a2a/tasks`, `/a2a/tasks/{id}`, `/a2a/tasks/{id}` (verb), `/a2a/tasks/{id}/pushNotificationConfigs[/{config_id}]`, `/a2a/extendedAgentCard` | per row | key | The HTTP+JSON binding. |
| `/a2a/push` | POST | **none** (own token) | Busbar's own push-notification callback. See [Push notifications](#push-notifications). |
| `/lf.a2a.v1.A2AService/{method}` | POST | key | The gRPC binding. |

Mounted by `crates/busbar-a2a/src/a2a/receive.rs:2388-2486` and `crates/busbar-a2a/src/a2a/rest.rs:561-628`. `/a2a/` with a trailing slash is a second claim rather than a redirect, because `httpx` — which the official TCK's JSON-RPC client uses — resolves a base URL to it (`receive.rs:2447-2452`).

The gRPC binding is served at the path the vendored `a2a.proto`'s package and service name dictate and **cannot** be served under `/a2a`: a gRPC channel takes an authority, never a path prefix. Busbar therefore claims that path for the plane explicitly, because a claimed path is where the RFC 8707 audience is found — leaving it unclaimed would have admitted a token minted for any other resource (`crates/busbar-core/src/plane/mod.rs:296-311`, `appbuild.rs:1477-1486`).

**gRPC rides the existing listener.** `grpc::serve` is an ordinary axum handler over h2c prior-knowledge, not a `route_service`, so the route carries a normal route-table entry and there is no second socket to bind, no second TLS config and no second port to open in a firewall (`crates/busbar-a2a/src/a2a/grpc.rs:56-85`, `:123-128`). Busbar implements the generated service itself rather than adopting the SDK's server, because that would pull the SDK's own task store and give two answers to "what happened" (`grpc.rs:14-21`).

### The eleven operations

Both dialects are accepted and canonicalised to the v1.0 spelling (`crates/busbar-a2a/src/a2a/relay.rs:853-875`):

| v1.0 | v0.3 | HTTP+JSON row |
|---|---|---|
| `SendMessage` | `message/send` | `POST /message:send` |
| `SendStreamingMessage` | `message/stream` | `POST /message:stream` |
| `GetTask` | `tasks/get` | `GET /tasks/{id}` |
| `ListTasks` | `tasks/list` | `GET /tasks` |
| `CancelTask` | `tasks/cancel` | `POST /tasks/{id}:cancel` |
| `SubscribeToTask` | `tasks/resubscribe` | `POST /tasks/{id}:subscribe` |
| `CreateTaskPushNotificationConfig` | `tasks/pushNotificationConfig/set` | `POST /tasks/{taskId}/pushNotificationConfigs` |
| `GetTaskPushNotificationConfig` | `tasks/pushNotificationConfig/get` | `GET /tasks/{taskId}/pushNotificationConfigs/{id}` |
| `ListTaskPushNotificationConfigs` | `tasks/pushNotificationConfig/list` | `GET /tasks/{taskId}/pushNotificationConfigs` |
| `DeleteTaskPushNotificationConfig` | `tasks/pushNotificationConfig/delete` | `DELETE /tasks/{taskId}/pushNotificationConfigs/{id}` |
| `GetExtendedAgentCard` | `agent/getAuthenticatedExtendedCard` | `GET /extendedAgentCard` |

The REST table is at `crates/busbar-a2a/src/a2a/relay.rs:761-844`. There are **exactly two** `POST /tasks/{id}:<verb>` verbs — `cancel` and `subscribe` — and any other suffix, or none, is a `MethodNotFound`-class refusal whose message names the two that exist (`crates/busbar-a2a/src/a2a/rest.rs:101-102`, `:368-396`).

On the HTTP+JSON binding the request body **is** the JSON-RPC `params` verbatim and the success body **is** the `result` verbatim; `message:stream` and `tasks/{id}:subscribe` answer `text/event-stream` (`rest.rs:10-11`, `:45`).

### How Busbar picks a binding for a backend

From the registration's **cached, verified** card: `supportedInterfaces[].protocolBinding` in order, taking the first word Busbar speaks — which is the specification's own preference rule (`crates/busbar-a2a/src/a2a/relay.rs:650-673`). A card declaring no interfaces defaults to JSON-RPC. A card declaring interfaces Busbar speaks **none** of is refused **by name** at the hop rather than silently sent a JSON-RPC envelope by a peer that just said it does not speak one. There is no production "default binding" third answer.

What Busbar **publishes** is narrower than what it speaks. Its own card advertises every binding the plane serves, derived from the plane's wire-format list rather than hand-written, so the card cannot claim a binding the plane does not answer (`crates/busbar-a2a/src/a2a/serve.rs:191-197`). A *fronted agent's* rewritten card advertises **`JSONRPC` only**, because the only thing mounted at `/a2a/agents/{id}` is the JSON-RPC handler and there is no spelling of a gRPC address that means "this one fronted agent" (`serve.rs:216-234`).

### Two gRPC-specific limits, stated

- **The gRPC binding cannot be a courier.** It is a typed parse, so a proto field the SDK's conversions do not carry is a field dropped on this binding only. The JSON-RPC binding's verbatim property is untouched (`crates/busbar-a2a/src/a2a/grpc.rs:44-54`).
- **gRPC has no v0.3 protobuf**, so a request naming no version is a 1.0 request (`grpc.rs:110`). The version metadata key is `a2a-version`.
- Busbar's own card is narrowed by exactly one member — `capabilities.stateTransitionHistory` — before transcoding to a protobuf `AgentCard`, because the generated ProtoJSON type is `deny_unknown_fields` and the transcode used to fail with `INTERNAL` for every caller of the extended card (`grpc.rs:350`, `:370-381`). The card served over the two HTTP bindings is untouched.

---

## Authentication and identity

### The audience

The A2A plane's RFC 8707 resource indicator is **`<public_url>/a2a`**, derived rather than configured separately, because a caller reads the audience to ask for off the card Busbar served it — an independently configured audience is a confused-deputy gap that opens the first time somebody edits one of the two (`crates/busbar-a2a/src/a2a/serve.rs:285-287`, `crates/busbar-a2a/src/a2a/plane.rs:295-307`). The metadata document is at `<origin>/.well-known/oauth-protected-resource/a2a`.

The check is the same one the MCP plane uses and it lives in the same place: beside the **mount**, so every path behind the door inherits it, compared for **equality** and never as a prefix (`crates/busbar-core/src/plane/mod.rs:363-375`). Both `/a2a` and `/lf.a2a.v1.A2AService` are claimed for the plane, so the gRPC leg's tokens are audience-checked too. An opaque bearer — one with no readable claims — is refused, for the reason given in [the MCP guide](/docs/mcp/#what-busbar-issues-and-what-it-does-not): the honest answer to "I cannot tell whether this was minted for me" on a confused-deputy defence is refusal (`crates/busbar-core/src/auth/audience.rs:38-47`).

### The scheme Busbar advertises

Busbar's card advertises exactly one security scheme, **`busbarA2aInbound`**, on the `authorization` header with RFC 7235 scheme `Bearer` (`crates/busbar-a2a/src/a2a/serve.rs:98-101`, `:547`). It is published in the proto `oneof` spelling `{"httpAuthSecurityScheme": {…}}` and the requirement as `[{"schemes": {"busbarA2aInbound": {"list": []}}}]` (`serve.rs:555-589`); the OpenAPI spelling it replaced set no variant and left conformant clients unable to classify it. `bearerFormat` is deliberately absent.

Internally this is a **value** on the existing generalized credential type — `a2a_inbound` — not a new type, table or trait method (`crates/busbar-a2a/src/a2a/inbound.rs:19-25`, `:57`).

### What Busbar signs, and what it does not

**Busbar signs the agent cards it serves, and nothing else.** Both its own card and each rewritten fronted-agent card, with the signature attached **last** — after the rewrite and after the backend-leak check — because a signature over anything other than the published bytes is worthless (`crates/busbar-a2a/src/a2a/serve.rs:533-540`). The vendor's own `signatures` member is **dropped** during the rewrite: carrying a signature that cannot verify over a rewritten document is worse than carrying none (`serve.rs:456-457`).

The signing key is a **domain-separated subkey** derived from the token secret, not the token signing key itself: `SHA-256("busbar/subkey/v1" ‖ token_secret ‖ "a2a/agent-card-signing/v1")` (`crates/busbar-a2a/src/a2a/sign.rs:14-44`, `:65`, `:121`). A served card is largely vendor-authored bytes, so signing it with the credential-minting key would make card signing a signing oracle. The blast radius is stated both ways: a card-key compromise does not reach tokens, and a token-secret compromise takes the card key too. The `kid` is `busbar-a2a-card-{token_kid}`, so a rotation is visible to callers. Algorithm is Ed25519 / `EdDSA`.

A card with **no** signing key configured is served **unsigned** rather than refused; a card that has a key and fails to sign is refused (`serve.rs:59-63`).

**There is no message-level signing of outbound requests.** Nothing on this plane signs a relayed request body. An outbound hop carries a leased credential in a header and nothing else. The only other MAC Busbar mints here is the per-task push-back capability token, which authenticates a backend calling *in*.

### What Busbar verifies

A fetched card's JWS, against the operator's out-of-band issuer key. **The algorithm is decided by the key, never by the header**: `EdDSA` over Ed25519 and nothing else, and a **missing `alg` is refused rather than defaulted** (`crates/busbar-a2a/src/a2a/jws.rs:11-25`, `:249-252`). The issuer key must be supplied as a full SPKI wrapper so the key material itself names its algorithm. At most 8 signatures are considered. A verification answers *which* signature index and *which* `kid` verified, so an operator view can say so.

The order is verify-then-fingerprint, always. A failed verification is recorded as a *failed sighting*, which derives an error state and serves nothing — never as an absence of contact (`crates/busbar-a2a/src/a2a/verify.rs:11-23`). `VerifyRefusal` distinguishes, among others, `TransportPinNotObserved` from `TransportPinMismatch`: "we could not look" and "it matched" must stay apart (`verify.rs:49-90`).

**`unpinned` is registrable and never approvable** — there is no fingerprint to approve (`crates/busbar-a2a/src/a2a/pin.rs:90`, `:217`).

**There is no knob that slows detection or delays a demotion.** Only recovery is held (`recovery_backoff:`), and a test enumerates the knobs and fails if one grows a direction (`verify.rs`). The `reverify_ttl:` you set is the longest a verification may be reused on the delegation path; a stale card is re-verified **on the call**, single-flight and fail-closed, with no background job — see [Tool and agent trust](/docs/tool-and-agent-trust/).

---

## What a caller can see and call

One scope kind gates this plane, and it gates **both directions** (`crates/busbar-a2a/src/a2a/inbound.rs:64`, `crates/busbar-core/src/plane/mod.rs:156-162`):

| Scope kind | Grants |
|---|---|
| `agent` | "may this key invoke fronted agent X", and "may fronted agent Y delegate to registered agent X" |

```yaml
allowed_scopes:
  - { kind: agent, value: planner }
```

**Enumeration and invocation ask the same question of the same key** (`crates/busbar-a2a/src/a2a/inbound.rs:27-32`). There is one function that produces a dispatch — `inbound::authorize` — so there is no path to a backend that skipped the check (`inbound.rs:141-148`, `:155-213`). Its order is: credential kind → registration lookup → **one ordered gate** (identity, grant, agent trust state, registry generation).

### The two cards

**The public card** at `/.well-known/agent-card.json` is unauthenticated and therefore carries **no skills and no enumeration of fronted agents** — it cannot ask who is asking (`crates/busbar-a2a/src/a2a/serve.rs:611-621`).

**The extended card** (`GetExtendedAgentCard`, authenticated) is built from the caller's own catalogue and carries **one skill per entitled agent**: skill id = Busbar's `agent_id`, `tags: ["agent"]`, name and description from the vendor's cached card (`serve.rs:786-842`, `crates/busbar-a2a/src/a2a/registry.rs:496-504`). The backends' own `skills[]` are deliberately **not** republished, because upstream skill ids collide across vendors and duplicate ids are refused. Each entry is scanned against its own backend's host and silently dropped, with a warning logged, if it mentions it — the same backend-leak rule the card rewrite enforces.

### Resolving an agent at the plane endpoint

A `POST /a2a` names no agent, so Busbar resolves one from **this caller's catalogue** for the shape of work asked for (`crates/busbar-a2a/src/a2a/receive.rs:248-…`):

| Matches | Answer |
|---|---|
| exactly one | dispatch |
| **zero** | the *same* refusal an unauthorised caller gets — the endpoint is not an inventory oracle |
| more than one | `InvalidParams`, naming the ids, telling the caller to address `/a2a/agents/{id}` |

`registry::Excluded` enumerates why a registration was not a candidate: `NotTrusted(state)`, `NotInScope`, `CallerNotLive`, `NoEgressGrant`, `SkillNotDeclared(name)`, and a capability-not-declared arm (`crates/busbar-a2a/src/a2a/registry.rs:287-…`); `registry::explain` re-derives the reason for one registration for an operator view.

### Refusal statuses

`InboundRefusal::status()` (`crates/busbar-a2a/src/a2a/inbound.rs:96-103`):

| Refusal | Status |
|---|---|
| `WrongCredentialKind` | `401` |
| `KeyNotLive` | `401` |
| `NoSuchAgent` | `404` |
| `NotInScope` | `403` |
| `NotServing` (agent state) | `503` |

The 404/403 split is a deliberate, documented, bounded existence leak: the catalogue already tells an authorized caller which agents exist, and ids are operator-chosen rather than derived from anything sensitive (`inbound.rs:90-95`). For an **unknown** agent id the grant list is deliberately empty so the trust step refuses and the answer is `404`, preserving 404-before-403 (`inbound.rs:177-186`).

### The error vocabulary

Every refusal on this plane is a JSON-RPC error whose HTTP status is the one A2A §5.4 binds to it — kept, rather than flattened to `200` (`crates/busbar-a2a/src/a2a/rpcerror.rs:30-36`). `data` is a ProtoJSON **array**, carrying a `google.rpc.ErrorInfo` with `domain: "a2a-protocol.org"` and a `reason` re-derived from Busbar's own table.

| Error | Code | HTTP | gRPC | `reason` |
|---|---|---|---|---|
| `TaskNotFound` | `-32001` | 404 | `NotFound` | `TASK_NOT_FOUND` |
| `TaskNotCancelable` | `-32002` | 409 | `FailedPrecondition` | `TASK_NOT_CANCELABLE` |
| `UnsupportedOperation` | `-32004` | 400 | `Unimplemented` | `UNSUPPORTED_OPERATION` |
| `ContentTypeNotSupported` | `-32005` | 415 | `InvalidArgument` | `CONTENT_TYPE_NOT_SUPPORTED` |
| `InvalidAgentResponse` | `-32006` | 502 | `Internal` | `INVALID_AGENT_RESPONSE` |
| `ExtendedAgentCardNotConfigured` | `-32007` | 400 | `FailedPrecondition` | `EXTENDED_AGENT_CARD_NOT_CONFIGURED` |
| `VersionNotSupported` | `-32009` | 400 | `Unimplemented` | `VERSION_NOT_SUPPORTED` |
| `InvalidRequest` | `-32600` | 400 | `InvalidArgument` | — |
| `MethodNotFound` | `-32601` | 404 | `Unimplemented` | — |
| `InvalidParams` | `-32602` | 400 | `InvalidArgument` | — |
| `Internal` | `-32603` | 500 | `Internal` | — |
| `Parse` | `-32700` | 400 | `InvalidArgument` | — |

(`crates/busbar-a2a/src/a2a/rpcerror.rs:107-156`, `:212-260`.)

Two things an operator should know about this table. **`TaskNotFound` and `MethodNotFound` are constructed by no production call site on this plane** (`rpcerror.rs:52-60`): Busbar is content-blind on the receiving side, so those are the backend's words and Busbar carries the answer. And **Busbar's own admission refusals — a hook reject, a spent budget — are rendered as `UnsupportedOperation`** with the real reason in the message and the gate's own HTTP status where applicable (`receive.rs:931-947`, `:965-974`). `UnsupportedOperation` is this plane's binding for "Busbar will not do this for you"; a body in another plane's shape is a body the TCK rejects by schema.

A forbidden `Origin` answers `403` with an `UnsupportedOperation` body (`crates/busbar-a2a/src/a2a/words.rs:51-60`).

---

## Tasks

### States and legal transitions

Eight states (`crates/busbar-a2a/src/a2a/task.rs:76-108`): `submitted`, `working`, `input-required`, `auth-required`, `completed`, `failed`, `canceled`, `rejected`. The last four are terminal; `input-required` and `auth-required` are *interrupted* — paused awaiting the caller, consuming no compute, and the exact rows the durable store exists for.

`can_transition_to` is total over the pair rather than a set of guards at call sites, so the combination nobody thought about is refused by default (`task.rs:156-189`):

| From | Legal `to` |
|---|---|
| `submitted` | anything except itself |
| `working` | anything except itself and `submitted` — **never back to `submitted`** |
| `input-required` | `working`, `auth-required`, and the four terminals |
| `auth-required` | `working`, `input-required`, and the four terminals |
| any terminal | **nothing, including itself** |

A repeated `completed` is refused because it is the shape of a duplicate delivery, and honouring it would double-append provenance and billing (`task.rs:187`). An illegal move is `TaskError::IllegalTransition { from, to }`, and `updated_at` moves only on an accepted transition.

An unknown state token from the store **fails closed** (`task.rs:112-129`). A row written by a newer engine carrying a state this binary does not know is a row it cannot reason about — it cannot tell whether it is terminal (safe to compact) or interrupted (must be preserved and resumed) — and the cheap guess, "unknown means terminal", is the one that deletes a live task on a downgrade.

### Task ids

Minted at `crates/busbar-a2a/src/a2a/receive.rs:1201-1213` as `a2a-<agent_id>-<16 hex>`. The hex is a hash over the request body, the clock, a **process-wide monotonic counter** and the process id; the counter is the only ingredient that guarantees anything, and it was added after resume tests found two identical submissions replacing each other's rows (`receive.rs:2358-2380`). It is explicitly not a UUID. If the request carries no `contextId`, the context id is the task id. If the caller addressed an existing owned task, or a resumable one is found for the context, no new id is minted.

`a2a/idmap.rs` is the inverse map — Busbar's task id → the backend's — and it is **process-local and does not survive a restart** (`idmap.rs:28-37`). That is a stated limitation rather than an oversight: the durable home would be a new column on the store plugin's task row, i.e. an ABI change. Capacity 100 000, oldest-first eviction. Every lookup takes the principal and delegates the ownership boundary to the scoped read; there is deliberately no unscoped twin, because the id-only version was an IDOR on `GetTask` and `CancelTask`.

### Durability and boot

The task store writes through to the configured governance store on every append, and `submit` persists **before** the task is acknowledged (`crates/busbar-a2a/src/a2a/taskstore.rs:14-20`, `:241`). With `store: memory` nothing persists and the restore honestly reports zero.

At boot, `restore_from_store` walks the store's task rows (`taskstore.rs:191-239`):

- unparseable rows are counted as `unreadable` and logged at ERROR, never silently dropped;
- **terminal tasks are counted and deliberately not loaded** into the working set;
- active and interrupted tasks are loaded and their provenance chain is re-verified from the stored events;
- **a chain that fails to verify is still restored.** Refusing to restore it would turn a detection control into a deletion primitive: anyone who can corrupt one event could erase a task. The break is named loudly, counted, and the chain continues from the broken tail rather than being silently re-based onto it.

`Rehydrated` reports `active`, `terminal`, `unreadable` and `chain_breaks` separately, so a boot log line distinguishes "nothing to restore" from "I could not read what was there".

**Reads are scoped.** "No such task" and "not yours" answer the same refusal and render `403` — a distinguishable not-found would be an enumeration oracle (`taskstore.rs:30-35`, `:63-67`).

> **Retention is a mechanism with no wired sweep today.** `compact(before)` exists and calls the store's purge, but there is no production call site for it in the tree (`taskstore.rs:37-40`, `:590-600`). Terminal task rows accumulate in the durable store until something outside Busbar removes them. Plan for that in your store's own retention policy.

---

## Push notifications

A caller registers a push-notification config and expects a callback when its task moves. Busbar does **not** relay that config to the backend.

**The substitution.** Busbar registers *its own* callback with the backend — `<public_url>/a2a/push`, with a per-task capability token — and holds the caller's URL and credential itself (`crates/busbar-a2a/src/a2a/pushback.rs:27-42`, `:172-180`). The token is `<task-id>.<hex HMAC-SHA256(task_id)>` under a **process-local** 32-byte secret from `getrandom` (`pushback.rs:44-57`, `:98-122`). If `getrandom` fails the secret stays unset, the mint answers `None`, and Busbar registers **no** callback at all rather than one under a guessable key. **A restart invalidates every prior token.** Busbar registers a callback only while the task is non-terminal.

**Busbar's callback endpoint** (`POST /a2a/push`, `pushback.rs:259-347`) is unauthenticated by the key chain and authenticates itself against that token:

| Condition | Answer |
|---|---|
| no A2A plane | `404` |
| missing, unparseable or non-verifying token | `401`, with a message that says nothing about which |
| body over 64 KiB | `413` |
| token verified but the task row is gone | `401` — not `404`, so existence is never revealed |
| body not JSON | `400` |
| otherwise | `202` with an empty body |

The reported state goes through the **same** task-store transition and the same per-task chain as everything else; a re-report of the state already held is treated as a retry and not a transition; an unrecordable transition logs at INFO and still answers `202`, so a backend does not retry-loop. Refusals are `{"error":{"message":…}}` and deliberately not a JSON-RPC error body. **Nothing from the pushed body reaches the caller's webhook** — the onward delivery is composed from Busbar's own task row.

**The onward delivery** (`crates/busbar-a2a/src/a2a/pushdeliver.rs`) carries:

```json
{ "task": { "id": "a2a-planner-…", "contextId": "…", "kind": "task",
            "status": { "state": "completed", "timestamp": 1771027200 } } }
```

A `StreamResponse` nested under `"task"` — not a bare task and not a JSON-RPC envelope (`pushdeliver.rs:299-…`). The ids are always Busbar's, never the backend's.

**The SSRF guard runs at delivery, not only at registration** (`pushdeliver.rs:17-37`). Before every delivery the host is re-resolved through the plane's resolver, the full guard runs again over the fresh answer, and the socket goes to a just-passed pinned address with no second lookup. Where a pin from a previous delivery exists and the URL matches, the fresh answer must pass **and overlap the pin**; a fresh answer that is public but shares no address with the pin is `PinDrifted` and held for an operator, because a legitimate DNS change and a takeover look identical from here.

The guard itself (`crates/busbar-a2a/src/a2a/pushnotify.rs:53-75`) refuses:

- any scheme other than **https** — "there is no deployment in which another one is accepted";
- a missing host;
- an **obfuscated** host, refused on the host *string* before resolution (`2130706433`, `0x7f000001`, `127.1`, `017700000001`);
- an **empty** resolution — "checked nothing" must never read as "found nothing wrong";
- **any** resolved address that is internal: loopback, private, link-local, unique-local, CGNAT, unspecified, multicast, broadcast, or cloud metadata. There is no "prefer the public one".

**The callback credential is the caller's own**, presented as `Authorization: <scheme> <credentials>`, and it is attached only **after** the guard passes, so a refused destination can never see it (`pushdeliver.rs:102-121`, `:226-236`). It lives in a process-local map, never persisted, never logged, never echoed on a read verb — the store seam has no notion of a secret. The consequence, stated because it is operationally visible: **a credential does not survive a restart while the URL does, so Busbar keeps delivering without the header.**

**There is no retry loop.** Delivery is best-effort and a failure never touches the task (`pushdeliver.rs:49-54`). Success is HTTP `200..300`. Every attempt is chained to the task's own provenance under one of three kinds, and the split is deliberate so an operator is sent to the right place:

| Provenance kind | When |
|---|---|
| `task.push_delivered` | the receiver accepted it |
| `task.push_refused` | **nothing left the process** — Busbar's guard, DNS, or a bad URL |
| `task.push_failed` | it went out and the receiver failed it |

A `NoCallback` produces no record at all.

---

## What a tripped agent returns

The circuit breaker runs on all three planes. There is one FSM: a registered A2A agent is a cell on the same breaker a model lane sits on, keyed `agent:<agent-id>` with lane index 0 (`crates/busbar-core/src/store/planes.rs:22-30`, `:112-114`). See [circuit-breaker.md](/docs/circuit-breaker/) for the state machine.

**The breaker is consulted immediately after the demotion gate and before the socket** — trust first, then availability. One admission there covers all three bindings by construction, because the relay preamble sits beneath the transport axis (`crates/busbar-a2a/src/a2a/relay.rs:1462-1481`).

A tripped agent answers **HTTP `503`** with an exact **`Retry-After`** from the cell's own remaining cooldown, and a JSON-RPC `UnsupportedOperation` (`-32004`) body **carrying the task id**:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32004,
    "message": "agent `planner` is unavailable: its circuit breaker is open after repeated backend failures; busbar did not dispatch this request. Retry after 12s",
    "data": [
      { "@type": "type.googleapis.com/google.rpc.ErrorInfo",
        "domain": "a2a-protocol.org", "reason": "UNSUPPORTED_OPERATION" },
      { "@type": "type.googleapis.com/google.rpc.ResourceInfo",
        "resourceType": "a2a.busbar/task", "resourceName": "a2a-planner-…" }
    ]
  }
}
```

(`crates/busbar-a2a/src/a2a/receive.rs:1991-2028`; the `ResourceInfo` shape is `crates/busbar-a2a/src/a2a/rpcerror.rs:361-386`. The task id rides as a `google.rpc.ResourceInfo` rather than a `taskId` member of the error object, because JSON-RPC 2.0 §5 admits only `code`, `message` and `data`, and the TCK rejects the other shape by schema.)

**And the task state is `rejected`, not `failed`.** A2A has what MCP lacks: task state is first class, and the specification gives both words. `failed` means *we tried and it broke*. `rejected` means *we did not accept this work*, which is literally what a breaker refusing to start a call has done. The caller still gets a task id to poll and correlate — the row predates the hop, so the id resolves — and **the calling agent decides whether and when to retry.** Busbar does not invent a retry schedule on another agent's behalf.

**An addressed task is different.** A verb naming an existing task does *not* transition it: the task exists at exactly one backend, and a tripped backend must not end it. The verb gets the refusal and the row keeps its last-known state, readable from Busbar's own store (`receive.rs:1997-2006`). Either way it is `503` plus an exact `Retry-After`.

`503` is also what a *demoted* registration answers, from the trust axis rather than the availability axis, so a caller sees one answer for "this agent is not serving" whichever axis said so (`crates/busbar-a2a/src/a2a/relay.rs:397-410`).

### What records against the cell, and what deliberately does not

The relay is this plane's Stage-1 normalizer; Stage 2 is the one core classifier (`crates/busbar-a2a/src/a2a/relay.rs:1380-1435`):

| Hop outcome | Recorded as |
|---|---|
| an answer, of any kind | **success** |
| a well-formed A2A error from the backend | **success** — the backend was reachable and answered; a task-level failure from a backend that answered is the *work* failing, not the wire |
| transport error | network failure |
| an HTTP status | classified: 401/403 → hard down, 5xx/429 → transient, other 4xx → client fault (never a penalty) |
| body too large / not JSON / uncorrelated | server error — the backend answered 2xx and the answer was unusable |
| Busbar's own guard, a lease failure, an unframable operation | **nothing** — nothing reached the backend |
| a demotion | **nothing** — that is trust, not health |
| the breaker itself | **nothing** — the cell is already speaking |

**These cells refuse on a trip and nothing less**, exactly as the MCP cells do and for the same reason: `bench_below_trip_threshold: false` (`crates/busbar-core/src/store/planes.rs:81-99`). The predicate is **error rate ≥ 0.5 over at least 5 outcomes in a 30-second window**, cooldown 15 s escalating to 120 s (`crates/busbar-core/src/store/in_memory/mod.rs:563-574`, `:629-639`). There is no `breaker:` key under `agents:` and none on an agent pool; these planes run on the built-in defaults. An upstream's own `Retry-After` is honoured.

**A tripped agent that is a member of a `pools:` failover pool is not what produces the `rejected` task above.** For a FRESH submission the walk runs at admission, before any refusal is composed, and tries the next member whose approved card fingerprint matches the primary's (`crates/busbar-a2a/src/a2a/route.rs:82-219`); the caller gets that member's answer. Only an *exhausted* pool yields the `rejected` task, and then it names the **pool**, because the pool is the unit with nothing left (`crates/busbar-a2a/src/a2a/receive.rs:1497-1501`). A verb naming an **existing** task is unaffected either way: that task is pinned to the member that accepted it, so a tripped backend refuses the verb and the row keeps its last-known state.

### Anomaly-driven suspension

Separately from the breaker, a registration can be suspended on operator-configured thresholds over four signals (`crates/busbar-a2a/src/a2a/anomaly.rs:42-112`): `error_rate`, `terminal_failure_rate`, `latency_p95_ms`, `egress_budget_ratio`, each gated by a `min_observations` floor. **Every threshold is optional, and `None` means not configured and can never trip** — reading an absent threshold as zero would suspend every agent in the deployment on the day the feature shipped. A trip carries the signal, the observed value, the threshold and the observation window, for the audit row.

---

## Observability

The A2A plane emits on **its own pair of request families** — `busbar_plane_requests_total` and `busbar_plane_request_duration_seconds` (the `plane`-labelled counterparts of the model plane's `busbar_requests_total` / `busbar_request_duration_seconds`, kept separate so those stay byte-identical to 1.5.4) — and it labels its own requests **from inside**, because two of its three bindings are spoken at the same door and only the reader knows which one spoke (`crates/busbar-a2a/src/a2a/receive.rs:671-712`).

| Metric | Type | Labels | On this plane |
|---|---|---|---|
| `busbar_plane_requests_total` | counter | `plane`, `ingress_protocol`, `pool`, `outcome` | `plane="a2a"`; `ingress_protocol` is **`jsonrpc`, `http+json` or `grpc`** — the binding the request actually arrived on; `pool="unresolved"` |
| `busbar_plane_request_duration_seconds` | histogram | `plane`, `ingress_protocol`, `pool` | same |

That per-binding label is what makes a per-binding number readable from Busbar's own telemetry rather than only from a conformance suite's stdout (`crates/busbar-core/src/transport.rs:172-183`). `pool` is pinned to the `unresolved` sentinel because the routing target is client-supplied and an unbounded label value is a memory-exhaustion DoS one valid credential can drive.

A handled response is stamped so the plane's mount-level boundary does not count it a second time (`receive.rs:705-712`). **A refusal that reached no handler is still counted** — the audience-bound `401`, a `413`, a `404` — and on the gRPC binding, which has a door of its own, it is counted with the `grpc` label off the claim without any handler running (`crates/busbar-core/src/plane/observe.rs:51-70`).

**No metric family is defined inside the A2A tree.** There are no A2A-specific counters, histograms or gauges: the plane's only emission is the mounted-plane request pair above. Anomaly evaluation and provenance produce audit rows, chain events and log lines, not metrics.

**There is no `operation` metric label**, on this plane or any other. `invoke` / `catalogue` / `fetch` / `task` / `subscribe` / `control` are `OpShape::as_str()` values — a closed internal vocabulary for the *shape* of an exchange (`crates/busbar-core/src/operation.rs:174-183`). No metric family carries them (`crates/busbar-core/src/metrics.rs:147-153`).

The client leg lands on the shared upstream families, emitted on every plane: `busbar_upstream_attempts_total{pool,lane}` and `busbar_upstream_failures_total{pool,lane,disposition}` (`crates/busbar-core/src/telemetry.rs:788-830`).

---

## Governance

**Budgets are enforced before the work.** A submission is admitted through the shared governance ledger — the same `try_admit` the model plane uses — and a spent budget records an audit rejection and answers HTTP **429** with an `UnsupportedOperation` body reading "this key's budget is spent" (`crates/busbar-a2a/src/a2a/receive.rs:956-974`). A successful call records one metered event with resource `agent:<agent_id>` and provider `a2a`, so an existing cost dashboard groups agent traffic without knowing what A2A is (`receive.rs:1317-1322`).

**Locally-answered verbs are metered too.** `ListTasks` and the push-config verbs run *after* the meter: answering one for free would make it the one unmetered verb on the plane (`receive.rs:977-988`).

**Attribution differs by direction, and the difference is a type rather than a convention** (`crates/busbar-a2a/src/a2a/meter.rs:48-119`). On the *receiving* side the presenting key is billed and it covers downstream L2 MCP spend. On the *delegating* side the **initiating** key is billed — never a synthetic identity for the fronted agent — and it does not cover downstream L2 spend. `covers_callee_internal_spend` is **always false** on both arms, and it is a field rather than an omission so the claim is visible where the numbers are read: Busbar does not and cannot bill for what happens inside somebody else's agent.

**Hooks fire through the same seam as the MCP plane** — one hooks implementation, one projection, one verdict type (`crates/busbar-a2a/src/a2a/receive.rs:888-948`). `agents.hooks:` ∪ `agents.<agent>.hooks:`, keyed by agent, resolved once per config generation, and an agent with no attached hook costs one hash lookup that misses (`crates/busbar-core/src/state.rs:314-318`).

Placement is stated and load-bearing: **after** admission (the agent is what the attach is keyed on, so there is nothing to look up before it) and **before** the meter, the egress gate, the callback guard and the task row — everything after that line spends the caller's budget, leases Busbar's own credential, or mints durable state, and a refusal must cost none of them (`receive.rs:880-883`). It fires for **every verb**, not only `message/send`: a gate attached to an agent is a statement about that agent, and a plane that fired it for submissions but not for the task verbs would be a plane where the control's scope depends on which method a caller happened to use.

The projection is the `invoke` IR: the method name as the target, `params` as the arguments — so a message's `parts` are *inside* the projection a screening gate reads rather than summarised beside it. A rejection is audited and answered with the hook's clamped HTTP status and its own message.

**Two audit chains touch this plane, and they answer different questions.**

The **admin audit log** records one row per admitted call under action `agent.call` / resource `agent:<agent_id>`, plus rejections on the hook path, the budget path and the egress gate — three rejection sites, not two (`receive.rs:45`, `:919-924`, `:959-964`, `:1098-1103`, `:1326-1332`). The trust verbs record `a2a_agent.connect` and `a2a_agent.approve` against resource `a2a_agent:<name>` (`crates/busbar-core/src/plane/mod.rs:186-192`, `crates/busbar-core/src/admin/planeverbs.rs:115-133`).

The **per-task provenance chain** is one hash chain per task, over the core chain mechanism rather than a second implementation (`crates/busbar-a2a/src/a2a/provenance.rs:48-50`). Its event kinds are constants so tooling can branch on them: `task.submitted`, `task.working`, `task.interrupted`, `task.resumed`, `task.delegated`, `task.artifact`, `task.terminal`, `task.rehydrated`, plus the three push kinds. The digest covers `prev_hash | task_id | seq | ts | kind | context_id | principal | agent_id | state` and deliberately **excludes `request_id`** — a join key absent on the boot-rehydrate and retention paths, and a sometimes-absent field must not make an intact chain unverifiable (`provenance.rs:171-186`). Adding a new event *kind* is safe; adding a new digest *field* is not.

The claim is **tamper-evidence, not tamper-prevention**, and the boot verifier reports breaks while still restoring the rows.

**Egress is gated.** The delegating direction runs through the shared egress gate, whose grant is the only thing that can produce a credential lease (`crates/busbar-a2a/src/a2a/creds.rs:201-208`). Which fronted agents may delegate to a given registration is `egress_scopes:`, fail-closed on absent or empty.

---

## Operator surfaces

| Route | Scope | What it does |
|---|---|---|
| `POST /api/v1/admin/agents/{name}/connect` | mutation | **Reaches the network.** Fetches the agent's card, verifies it against the operator's root, records the observation, and audits whatever it found as `a2a_agent.connect`. It **grants nothing**. |
| `POST /api/v1/admin/agents/{name}/approve` | mutation | Body `{"fingerprint": "…"}` — the fingerprint `connect` reported, echoed back. |

Mounted at `crates/busbar-core/src/admin/v1/json/mod.rs:91-100`. **Without these the `agents:` surface is CRUD only, every registration stays `Pending`, and no sequence of operator actions can make a fronted agent serve** — `Pending` is the fail-closed floor its only constructor puts it in.

`approve` refuses if the observed fingerprint differs from the one you echoed, if the sighting is `Failed`, or if the registration is `unpinned` (there is no authenticity root, so there is nothing to approve). The `404` is answered **before** the body is parsed, so the error shape is not an existence oracle (`crates/busbar-a2a/src/a2a/verbs.rs:505-516`, `:600-…`). The write re-finds the registration **under the registry lock** rather than mutating a clone, because a config apply may have removed the row while the card was being fetched.

`connect` deliberately does not approve. Adopting what was seen is a separate, explicit operator act, precisely so a poisoned card cannot be adopted by the same call that fetched it (`crates/busbar-core/src/admin/planeverbs.rs:44-47`).

Both verbs answer the same `A2aTrustView`: `{name, state, pin_mechanism, fingerprint, pin_changed, added, changed, removed, observed_skills, failure}` (`crates/busbar-a2a/src/a2a/verbs.rs:361`).

> **`sync`, `operator_suspend` and `operator_resume` are implemented but not mounted** (`crates/busbar-a2a/src/a2a/verbs.rs:55-57`). Each needs its own admin verb and its own audit row. Today an operator suspends a registration by removing or editing it.

A registration that is missing from either the registry or config answers the same `404` — two answers a caller could tell apart would be an existence oracle (`crates/busbar-core/src/admin/planeverbs.rs:28-35`).

### The registry generation

The registry carries a monotonic generation, re-taken on **any** mutation, and it is what makes an in-flight request unable to outlive the approval it was admitted under: admission records the value, the gate immediately before the socket re-reads it, and a move is a refusal (`crates/busbar-a2a/src/a2a/plane.rs:62-73`). It is bumped for any mutation rather than only trust-relevant ones — deciding whether a particular change mattered means re-deriving the whole admission, and "did this specific change affect me" is the reasoning that lets a revocation slip through. Movement is refusal; the caller retries and is re-admitted under the new registry.

---

## Conformance

Busbar's A2A claims are gated by **two independent instruments plus a governance probe**, run from this repository (`.github/workflows/a2a-conformance.yml`):

- `testing/a2a-harness/` — an independent battery written from the published specification alone, with adversarial and hostile-peer coverage;
- `testing/a2a-tck/` — a wrapper around the publisher's own TCK at a pinned commit, covering all three transports across 36 modules;
- `testing/a2a-governance/` — budgets, quarantine, trust lifecycle. **Product policy, not protocol**, and it can never contribute to a conformance verdict: the harness raises if a governance test is ever registered inside it. A perfectly conformant agent that ignores every budget and quarantines nothing scores 100% on conformance.

The same two rules as the MCP battery apply: **control legs run always** (a battery that cannot judge a known-good peer cannot be trusted to judge Busbar) and **the subject leg is armed or red** (a disarmed leg renders as the same green tick as a leg that judged Busbar and passed).

The subject is booted **from the commit under test**, on loopback, by `scripts/a2a-subject/boot.sh` — not against a deployed URL, because that makes both verdicts unreadable. The script asks the OS for five free ports, generates the signing key with `busbar --generate-signing-key`, hands Busbar the same bytes through `auth.signing_key`, and signs one audience-correct token; Busbar's A2A mount refuses any credential whose audience is not exactly `<public_url>/a2a`, and an opaque API key is refused outright, so there is no "just use an API key" path.

```
scripts/a2a-subject/boot.sh --battery      # the independent battery, --role server
scripts/a2a-subject/boot.sh --tck          # the publisher's TCK
scripts/a2a-subject/boot.sh --supplement   # busbar-authored coverage of requirements the pinned
                                           # TCK declares but does not execute; reported separately
scripts/a2a-subject/boot.sh --probe        # boot + prove the plane boundary only
scripts/a2a-subject/boot.sh --selftest     # prove the arming rule and the boundary proof BITE
```

Arm it with `A2A_SUBJECT_BUSBAR_BIN` pointing at a binary built from your tree; `BUSBAR_A2A_ENDPOINT` is an optional extra leg for an already-deployed Busbar. Unarmed, the script **fails**.

The boundary proof presents five credentials to the booted process past any shim: no credential, no audience, a different audience and a flipped signature must each be `401`; the right audience must be admitted.

**Stated gaps, worth knowing before you read a number:**

- the **delegating direction is not exercised** — the battery still runs `--role server`;
- the **HTTP+JSON binding is not armed by the TCK**, so its requirements report as *untested* rather than failed. That is a gap in this harness and not in the card: Busbar's own card advertises all three bindings, because `servable_bindings()` is the plane's own wire-format list upper-cased (`crates/busbar-a2a/src/a2a/serve.rs:191-197`, `crates/busbar-core/src/plane/mod.rs:228`). A *fronted agent's* card is narrower and advertises `JSONRPC` only, because `/a2a/agents/{id}` mounts a JSON-RPC reader and nothing else (`serve.rs:225-227`);
- `PUSH-DELIVER-001/002/003` are **red and waived**, with the reason recorded in `testing/a2a-tck/WAIVERS.md`: the suite's receiver URL is literal `http://`, and Busbar refuses a plaintext webhook before it looks at the address. All three still run, still fail, and are still counted in the MUST row.

The verdict logic refuses an empty waiver pin outright and treats `NOT TESTED` requirements as reported-but-not-gated; `--selftest` exercises both directions of that with red and green fixtures.
