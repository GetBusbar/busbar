# A2A

Busbar fronts your A2A agents and delegates to the ones you register, over all three of the specification's bindings — JSON-RPC, HTTP+JSON and gRPC. A caller authenticates against Busbar with an audience-bound token, sees only the agents its key grants it, submits work that becomes a durable task, and gets a task id back. The key, its grants, its budget, hooks and the audit trail apply to an agent task as they do to a model request.

This page is the operator's reference: what a deployment gets by turning it on, the configuration grammar and its refusals, how identity is established, the three bindings and their routes, the task lifecycle, push-notification delivery, what a tripped agent returns, and what the plane emits.

The A2A plane is not code in this repository. It is the plane plugin built from GetBusbar/busbar-plane-a2a (crate `plane-a2a`), which the host links; this repository pins a revision of it in `Cargo.toml`. Plane code is cited below as `plane-a2a/src/<file>.rs` in GetBusbar/busbar-plane-a2a; host code as `crates/<crate>/src/<file>.rs`.

Cross-references: [MCP](/docs/mcp/) (the sibling plane, one vocabulary) · [Circuit breaker](/docs/circuit-breaker/) · [Configuration](/docs/configuration/) · [Observability](/docs/observability/) · [Hooks](/docs/hooks/).

---

## What the plane is

The `agents:` section registers external A2A agents. Registering one turns on **two** directions, and they are gated separately.

**The receiving side** — Busbar *fronts* those agents. It serves its own agent card, an extended card that lists the agents a caller is entitled to, and the A2A operation surface on three bindings. A caller talks to Busbar; Busbar relays to the registered backend.

**The delegating side** — Busbar reaches each registered agent as a client, at that agent's own `url`, over the binding its verified card declares, presenting busbar's own credential for it where one is configured.

### A deployment that registers no agent gains no route

An `agents:` section that registers no agent — absent, or carrying only its reserved section-level keys — states no route at all: no claim, no audience, no metadata document, and not busbar's public push callback. The plane's two trust verbs stay stated and answer every name `404`, because none is registered (`plane-a2a/src/door_statement.rs`, `agents_snapshot_spec`).

### And neither does a deployment with no `public_url:`

The receiving side additionally needs a top-level **`public_url:`**. Without a readable one the plane claims nothing: a plane with no public base has no audience a token could name and no metadata document to point a refused caller at (`agents_snapshot_spec`). An operator may configure `agents:` for the delegating direction alone; refusing to boot would make the receiving side's requirement the whole plane's.

Concretely, with `agents:` but no `public_url:` you get none of `/a2a`, `/a2a/`, `/a2a/agents/{agent_id}`, the HTTP+JSON routes, `/lf.a2a.v1.A2AService/*`, `/.well-known/agent-card.json` or `/.well-known/oauth-protected-resource/a2a`.

Busbar's own push callback has one further condition: Busbar registers its callback with a backend only when `public_url` is `https`. A task token in cleartext is refused, with no knob (`plane-a2a/src/mirror.rs`, `callback_url`).

---

## Configuration

### The `agents:` section

`agents:` is a sibling of `tools:` and the model plane's `pools:`: a map whose keys are registrations, with the same two words reserved at the section level on every plane (`plane-a2a/src/a2a/config.rs`).

| Reserved section key | Type | Combine rule |
|---|---|---|
| `agents.hooks` | list of bare hook names | **ADDITIVE** — union with each agent's own `hooks:`, deduped by name |
| `agents.upstream_credentials` | `own` (`passthrough` refused) | **OVERRIDE** — an entry's own value replaces it |

Naming an agent `hooks` or `upstream_credentials` is refused by the shared section parser.

#### `agents.<name>` — one registered agent

`deny_unknown_fields`: a typo'd key fails boot rather than silently un-pinning an agent.

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `url` | string | **yes** | — | The agent's A2A endpoint. `http://` or `https://`, with a host and **no userinfo** (a `user@` or `user:password@` is refused without being repeated; the credential belongs under `upstream_credential:`). Never client-visible: callers reach it through Busbar. |
| `pin` | object | **yes** | — | The out-of-band trust root. Required even when it is `unpinned`. A kernel-owned trust key: the kernel parses and judges it before the plane sees the section. |
| `pin.mechanism` | `jws_issuer_key` \| `cert_spki` \| `mtls` \| `unpinned` | **yes** | — | The first three are authenticity roots; `unpinned` is not. Under `cert_spki` and `mtls` the pinned key is the far end's key, which the connector holds every connection to the agent to. |
| `pin.key` | string | required for the three rooted mechanisms; refused for `unpinned` | — | JWS verification key, or a certificate SPKI hash. |
| `pin.fingerprint` | string | no | absent | A canonical card fingerprint you already have. It is intent, not an approval: the registration still serves nothing until an operator runs `approve`. Absent is the normal first registration: capture the fingerprint at `connect` and approve it. |
| `client_identity` | object | **required** when `pin.mechanism: mtls`; optional otherwise; **refused** on an `http://` URL | absent | The certificate Busbar PRESENTS to this endpoint. |
| `client_identity.cert` | `SecretRef` | yes (within the block) | — | PEM chain, leaf first. |
| `client_identity.key` | `SecretRef` | yes (within the block) | — | PEM private key (PKCS#8, PKCS#1 or SEC1). **There is deliberately no way to write PEM bytes here** — an inlined private key is a private key in every config dump, every `--validate` output and every admin GET. |
| `reverify_ttl` | `<n><s\|m\|h\|d>` | no | `5s` | The longest a verification may be reused on the delegation path before the card is re-fetched and re-verified. `0` = strict-live; a larger value is an explicit security downgrade. A kernel-owned trust key. See [Tool and agent trust](/docs/tool-and-agent-trust/). |
| `recovery_backoff` | `<n><s\|m\|h\|d>` | no | `15m` | How long after a DRIFT a clean answer is disbelieved. The only half of the cadence that is ever held. A kernel-owned trust key. |
| `protocol_version` | string | no | absent | **Accepted and read by nothing.** The key is kept so an older config still parses; the plane pins nothing on it, and fetches the card at both well-known paths, canonical first, whatever version it names. |
| `allow_private` | bool | no | `false` | Permits a plaintext `http://` endpoint and a loopback / link-local / RFC1918 / CGNAT address for this one agent. **Never** permits a cloud-metadata address, whatever it says. |
| `upstream_credentials` | `own` | no; **`passthrough` refused** | | |
| `upstream_credential` | object | no | absent | Busbar's own credential for this agent. See below. Absent ⇒ the agent is dialled with no credential. |
| `egress_scopes` | list of strings | no | `[]` | Judged for shape only (an empty name is refused) and **read by nothing**: no request is ever judged against this list. What gates a hop is the caller key's own `agent:<id>` grant for the agent it reaches. |
| `hooks` | list of bare names | no | `[]` | Adds to `agents.hooks:`. |

**`upstream_credential`** (`plane-a2a/src/a2a/creds.rs`), `deny_unknown_fields`, three fields and no more:

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `secret` | `SecretRef` | **yes** | — | A reference, never the secret, never the caller's. |
| `placement` | `bearer` \| `{ header: <name> }` | no | `bearer` | `bearer` sends `Authorization: Bearer <secret>`; `header:` sends the named header carrying the secret verbatim, which is several vendors' `APIKey` scheme. It is an enum precisely so a secret cannot be placed in a query string, which lands in every access log on the path. |
| `lease_ttl_ms` | u64 milliseconds | **yes** | — | Must be > 0: a lease that expires at the instant it is minted is a credential that can never be presented. |

The credential is **busbar's own**, never the caller's, and the plane never holds it: minting and presenting a lease is the host's (`creds.rs`). The plane's Statement lists `settings.*.upstream_credential.secret`, `settings.*.client_identity.cert` and `settings.*.client_identity.key` as the section's secret references, so `--validate` and boot resolve each one (`plane-a2a/src/door_statement.rs`, `SECRET_REFS`). A hop the host refuses because the agent's credential could not be leased is refused and logged as `BUSBAR-7013`. The door's public card fetch carries no credential.

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
    hooks: [planner-audit]
```

### Boot refusals: the `agents:` section

`validate_agent` is called both when the section is read from the config file and from the host's admin write path, so the API refuses exactly what the file refuses (`plane-a2a/src/a2a/config.rs`). The pin and the two cadence durations are kernel-owned trust keys and are judged by the kernel before the section reaches the validator.

| Refusal | Condition | Judged by |
|---|---|---|
| `url:` must name the agent's A2A endpoint | empty | `validate_agent` |
| `url:` must be an http:// or https:// endpoint | any other scheme, checked at boot rather than at the first delegation | `validate_agent` |
| `url:` carries a userinfo | `user@` or `user:password@` in the authority | `validate_agent` |
| rooted `pin.mechanism` with no `pin.key`; `unpinned` carrying `pin.key`; an unparseable `reverify_ttl:` / `recovery_backoff:` | | the kernel (trust keys) |
| `pin.mechanism: mtls` with no `client_identity:` | a client with nothing to present is refused at the handshake with `CertificateRequired`, not at the pin | `validate_agent` |
| `client_identity:` on an `http://` URL | plaintext has no handshake to present a certificate in | `validate_agent` |
| **`upstream_credentials: passthrough`** | per entry, and at the section level | `validate_agent`; the kernel for the section key |
| `upstream_credential.lease_ttl_ms: 0` | | `validate_agent` |
| `upstream_credential.placement.header:` empty | | `validate_agent` |
| `egress_scopes:` contains an empty name | an empty scope grants nothing and reads as though it grants something | `validate_agent` |
| a dotted `hooks:` reference | the kernel sees every section; the plane's validator sees only its own | the kernel |

**The `passthrough` refusal is the one to understand.** `passthrough` means "forward the CALLER's credential upstream". On the delegation plane that would hand a third-party vendor a working Busbar credential belonging to somebody else — the caller's key authenticated them *to Busbar* and authorised them against *Busbar's* scopes, and it means nothing anywhere else. **Busbar delegates as itself.** The word stays reserved on every plane so the vocabulary is learned once; the value is refused loudly (`REFUSE_PASSTHROUGH_SECTION`, `plane-a2a/src/a2a/config.rs`).

### Governance is required at runtime

The plane's admission is an audience on a Busbar-minted token plus that key's `agent` grants, and neither exists without governance and an `auth.chain`. A misconfiguration here surfaces as requests being refused at runtime rather than as a process that will not start. Configure `auth.chain` before you turn the plane on.

### Failover pools: `agents.pools`

A pool under the `agents:` section's reserved `pools` sub-key is an A2A failover pool; the top-level `pools:` map belongs to the model plane, and which plane a pool is on is where you wrote it. It tells Busbar that two registrations are **the same agent registered twice**. The host hands the section its own pools, each pool's members in declared order, the first the primary (`plane-a2a/src/door_statement.rs`, `read_agents_section`; `crates/busbar/src/root/door_steps.rs`, `DoorPools`).

It is **opt-in, and declaring no A2A pool is exactly today's behaviour**.

```yaml
agents:
  planner-eu: { url: https://eu.agents.example }
  planner-us: { url: https://us.agents.example }
  pools:
    planner:
      members: [planner-eu, planner-us]
```

**Interchangeability is checked, not asserted.** A fresh submission the walk places on a member whose approved card fingerprint is not the pool primary's is refused rather than relayed (`plane-a2a/src/agent_door.rs`), logged as `BUSBAR-7003`. You are asserting only *"these names are the same deployment"*.

Reroute never means Busbar found somewhere else to send a task on its own: there is no discovery, and no member you did not write down. It also applies to **fresh submissions only**: a request naming an existing task — or resuming an interrupted one under its `contextId` — goes to the member that holds it (`plane-a2a/src/task_hop.rs`, `holder`).

---

## The three bindings, and what is mounted

The A2A specification models three bindings as three interfaces of **one** agent, and Busbar mounts them that way. The plane declares three dialects, in order, with JSON-RPC first (`plane-a2a/src/door_statement.rs`, `DIALECTS`).

| Route | Method | Auth | What it is |
|---|---|---|---|
| `/.well-known/oauth-protected-resource/a2a` | GET | **none** | RFC 9728 metadata. |
| `/.well-known/agent-card.json` | GET | **none** | Busbar's own agent card. |
| `/a2a` and `/a2a/` | POST | key | The JSON-RPC binding, plane-scoped: the agent is resolved from the caller's catalogue. |
| `/a2a/agents/{agent_id}` | GET | key | One fronted agent's rewritten card. |
| `/a2a/agents/{agent_id}/.well-known/agent-card.json` | GET | key | The same card at the protocol's well-known path under the agent's endpoint. |
| `/a2a/agents/{agent_id}` (and `/a2a/agents/{agent_id}/`) | POST | key | The JSON-RPC binding, addressed to one agent. |
| `/a2a/message:send`, `/a2a/message:stream`, `/a2a/tasks`, `/a2a/tasks/{id}` (GET, and POST for the colon verbs), `/a2a/tasks/{id}/pushNotificationConfigs[/{config_id}]`, `/a2a/extendedAgentCard` | per row | key | The HTTP+JSON binding. |
| `/a2a/push` | POST | **none** (own token) | Busbar's own push-notification callback. See [Push notifications](#push-notifications). |
| `/lf.a2a.v1.A2AService/{method}` | POST | key | The gRPC binding. |

The route table is `ROUTES` in `plane-a2a/src/door_statement.rs`; the push callback is a public route on the data listener, declared among the plane's admin routes and served to an agent that holds no Busbar key (`ADMIN_VERBS`, `PUSH_ROUTE`). `/a2a/` with a trailing slash is a second claim rather than a redirect, and each configured agent's `/a2a/agents/<id>/` spelling is claimed exactly, because an A2A client joins relative calls to the card's `url` and arrives there (`agent_slash_claims`).

The gRPC binding is served at the path the vendored `a2a.proto`'s package and service name dictate and **cannot** be served under `/a2a`: a gRPC client is given an authority, never a path prefix. That path is claimed for the plane explicitly, so the gRPC leg's tokens are audience-checked too (`GRPC_MOUNT_PATH`, `plane-a2a/src/lib.rs`). The line is a transcoding: the call's protobuf request is composed into the v1.0 JSON-RPC request it is, served exactly as the JSON-RPC line serves its own, and the answer transcoded back (`plane-a2a/src/framed.rs`).

### The eleven operations

Both dialects are accepted. The method spelling decides the dialect: v0.3's are slash paths, v1.0's PascalCase (`plane-a2a/src/local.rs`, `Dialect::of_method`).

| v1.0 | v0.3 | HTTP+JSON row |
|---|---|---|
| `SendMessage` | `message/send` | `POST /message:send` |
| `SendStreamingMessage` | `message/stream` | `POST /message:stream` |
| `GetTask` | `tasks/get` | `GET /tasks/{id}` |
| `ListTasks` | `tasks/list` | `GET /tasks` |
| `CancelTask` | `tasks/cancel` | `POST /tasks/{id}:cancel` |
| `SubscribeToTask` | `tasks/resubscribe` | `POST /tasks/{id}:subscribe` |
| `CreateTaskPushNotificationConfig` | `tasks/pushNotificationConfig/set` | `POST /tasks/{id}/pushNotificationConfigs` |
| `GetTaskPushNotificationConfig` | `tasks/pushNotificationConfig/get` | `GET /tasks/{id}/pushNotificationConfigs/{config_id}` |
| `ListTaskPushNotificationConfigs` | `tasks/pushNotificationConfig/list` | `GET /tasks/{id}/pushNotificationConfigs` |
| `DeleteTaskPushNotificationConfig` | `tasks/pushNotificationConfig/delete` | `DELETE /tasks/{id}/pushNotificationConfigs/{config_id}` |
| `GetExtendedAgentCard` | `agent/getAuthenticatedExtendedCard` | `GET /extendedAgentCard` |

`ListTasks`, the four push-config verbs, and the refusals of `SubscribeToTask` are answered by Busbar itself from its own task records; every other method is relayed (`plane-a2a/src/local.rs`, `LOCAL_VERB_METHODS` in `lib.rs`).

On the HTTP lines a request that names no protocol version is a 0.3 request; on the gRPC line it is a 1.0 request, because there is no v0.3 protobuf. The version metadata key is `a2a-version` (`plane-a2a/src/framed.rs`, `DEFAULT_VERSION`).

### What Busbar publishes

Busbar's own card advertises every binding the plane serves at its mount — `JSONRPC`, `HTTP+JSON`, `GRPC` — and the gRPC entry's address is the authority of `public_url`. A *fronted agent's* rewritten card advertises **`JSONRPC` only**, because the only thing mounted at `/a2a/agents/{id}` is the JSON-RPC endpoint: an interface entry busbar cannot serve there is dropped, and a card that offers no binding busbar serves there is refused (`plane-a2a/src/served_card.rs`, `SERVABLE_BINDINGS`, `AGENT_ADDRESS_BINDINGS`). The rewrite sweeps every URL whose host is the backend's and refuses a card that still names the backend authority afterwards, so the backend endpoint is never published.

### A gRPC-specific limit, stated

The gRPC binding is a typed parse, so a proto field the SDK's conversions do not carry is a field dropped on this binding only. Busbar's own card is narrowed to what the protobuf `AgentCard` carries before it is transcoded for `GetExtendedAgentCard` (`framed.rs`, `narrowed_to_the_proto`); the card served over the two HTTP bindings is untouched.

---

## Authentication and identity

### The audience

The A2A plane's RFC 8707 resource indicator is **`<public_url>/a2a`**, derived rather than configured separately, so the audience a caller reads off the card and the one Busbar checks cannot be edited apart. The metadata document is at `<public_url>/.well-known/oauth-protected-resource/a2a` (`agents_snapshot_spec`). Both `/a2a` and `/lf.a2a.v1.A2AService` are claimed for the plane, so the gRPC leg's tokens are audience-checked too. An opaque bearer — one with no readable claims — is refused, for the reason given in [the MCP guide](/docs/mcp/#what-busbar-issues-and-what-it-does-not).

### The scheme Busbar advertises

Every card Busbar serves advertises exactly one security scheme, **`busbarA2aInbound`**, on the `authorization` header with RFC 7235 scheme `Bearer`, in the normative proto spelling. The backend's own security schemes describe how to reach the backend and are replaced. The credential kind an inbound caller presents is `a2a_inbound` (`plane-a2a/src/served_card.rs`).

### What Busbar signs, and what it does not

**Busbar signs the agent cards it serves.** Both its own card and each rewritten fronted-agent card are signed after the rewrite, over the published document. The vendor's own `signatures` member is **dropped** during the rewrite: a signature over a document busbar has changed would not verify.

The plane holds no signing key: it reaches the host's signing service, under the domain `a2a/agent-card-signing/v1`, with a `kid` prefixed `busbar-a2a-card-`, and the JWS header names `EdDSA` (`served_card.rs`, `sign_card`; `door_statement.rs`, `CARD_SIGNING_DOMAIN`, `CARD_KID_PREFIX`). A deployment with **no** signing key serves cards **unsigned**; a key that will not sign refuses the card, so a missing signature always means "no key".

**There is no message-level signing of outbound requests.** The only other signature Busbar makes on this plane is the per-task push-callback token, which authenticates a backend calling *in*.

### What Busbar verifies

A fetched card is verified against the operator's out-of-band root before its fingerprint is taken; a failed verification is recorded as a failed sighting, which derives an error state and serves nothing. **`unpinned` is registrable and never approvable** — there is no root, so there is nothing to approve. There is no knob that slows detection or delays a demotion; only recovery is held (`recovery_backoff:`). A stale card is re-verified **on the call** — see [Tool and agent trust](/docs/tool-and-agent-trust/).

---

## What a caller can see and call

One scope kind gates this plane (`plane-a2a/src/door_statement.rs`, `SCOPE`):

| Scope kind | Grants |
|---|---|
| `agent` | may this key reach fronted agent X |

```yaml
allowed_scopes:
  - { kind: agent, value: planner }
```

### The two cards

**The public card** at `/.well-known/agent-card.json` is unauthenticated and therefore carries **no enumeration of fronted agents** — it cannot ask who is asking.

**The extended card** (`GetExtendedAgentCard`, authenticated) is built from the caller's own catalogue. On `POST /a2a` it names no agent and is billed against the plane pool (see [Governance](#governance)).

### Resolving an agent at the plane endpoint

A `POST /a2a` names no agent, so Busbar resolves one from **this caller's grants**: exactly one reachable entry is dispatched to; several are refused, naming them, telling the caller to address `/a2a/agents/{id}`.

### The error vocabulary

Every refusal on this plane is a JSON-RPC error whose HTTP status is the one A2A §5.4 binds to it, rather than `200`. `data` is a ProtoJSON **array** carrying a `google.rpc.ErrorInfo` with `domain: "a2a-protocol.org"` and the specification's `reason` token for the A2A-specific codes (`plane-a2a/src/lib.rs`, `ERRORS`; `plane-a2a/src/task_identity.rs`, `status_of_code`). On the gRPC line the error ends the call with a status and the `ErrorInfo` in its details.

| Error | Code | HTTP | `reason` |
|---|---|---|---|
| `TaskNotFound` | `-32001` | 404 | `TASK_NOT_FOUND` |
| `TaskNotCancelable` | `-32002` | 409 | `TASK_NOT_CANCELABLE` |
| `PushNotificationNotSupported` | `-32003` | 400 | `PUSH_NOTIFICATION_NOT_SUPPORTED` |
| `UnsupportedOperation` | `-32004` | 400 | `UNSUPPORTED_OPERATION` |
| `ContentTypeNotSupported` | `-32005` | 415 | `CONTENT_TYPE_NOT_SUPPORTED` |
| `InvalidAgentResponse` | `-32006` | 502 | `INVALID_AGENT_RESPONSE` |
| `ExtendedAgentCardNotConfigured` | `-32007` | 400 | `EXTENDED_AGENT_CARD_NOT_CONFIGURED` |
| `ExtensionSupportRequired` | `-32008` | 400 | `EXTENSION_SUPPORT_REQUIRED` |
| `VersionNotSupported` | `-32009` | 400 | `VERSION_NOT_SUPPORTED` |
| `InvalidRequest` | `-32600` | 400 | — |
| `MethodNotFound` | `-32601` | 404 | — |
| `InvalidParams` | `-32602` | 400 | — |
| `Internal` | `-32603` | 500 | — |
| `Parse` | `-32700` | 400 | — |

`TaskNotFound` is Busbar's own word for a task this caller does not hold: every local verb, and every relayed request addressed to a task (a task verb, or a message whose `taskId` names one), answers `404`, `-32001`, "no task with that id is open for this caller", and relays nothing (`plane-a2a/src/local.rs`, `NO_SUCH_TASK`; `plane-a2a/src/task_hop.rs`). Another caller's task, a retired one and one that never existed read alike, so the refusal is no existence oracle. A `CancelTask` of a task Busbar holds as terminal answers `409`, `-32002`, from Busbar's own row. Busbar's own refusals of work it will not do for you are rendered as `UnsupportedOperation` with the reason in the message.

---

## Tasks

### States and legal transitions

Eight states (`plane-a2a/src/a2a/task.rs`): `submitted`, `working`, `input-required`, `auth-required`, `completed`, `failed`, `canceled`, `rejected`. The last four are terminal; `input-required` and `auth-required` are *interrupted* — paused awaiting the caller, and the rows the durable store exists for.

`can_transition_to` is total over the pair rather than a set of guards at call sites, so the combination nobody thought about is refused by default:

| From | Legal `to` |
|---|---|
| `submitted` | anything except itself |
| `working` | anything except itself and `submitted` — **never back to `submitted`** |
| `input-required` | `working`, `auth-required`, and the four terminals |
| `auth-required` | `working`, `input-required`, and the four terminals |
| any terminal | **nothing, including itself** |

A repeated `completed` is refused because it is the shape of a duplicate delivery. An unknown state token from the store **fails closed**: a row this binary cannot classify as terminal or interrupted is refused rather than guessed at, because "unknown means terminal" is the guess that deletes a live task on a downgrade.

### Task ids

A fresh task's id is minted as **`a2a-<agent>-<16 hex>`**, the hex being eight bytes from the kernel's random service; `<agent>` is the agent the caller addressed, not the pool member the walk placed it on (`plane-a2a/src/task_identity.rs`, `mint`; `plane-a2a/src/task_hop.rs`, `open`). If the request names no `contextId`, the context id is the task id. No new id is minted when the request names a task the caller holds (in its `params`, or its message's `taskId`), or when its `contextId` names one of the caller's interrupted tasks on that agent — the newest such task moves back to `working` instead.

The agent's answer leaves under Busbar's identity: the far end's own task id is read first, then Busbar's id and context are written over the payload, its status message and its history, and `referenceTaskIds` Busbar knows are rewritten too (`rewrite_identity`). A later request naming Busbar's id is sent on with the far end's id spliced in, every other byte as the caller wrote it (`translate_request`).

That map from Busbar's task id to the far end's is **plane memory, keyed by caller, and a restart forgets it** (`plane-a2a/src/agent_door.rs`, `backends`). Every lookup goes through the caller's own scoped read, so an id only translates for a task that caller holds.

### Durability and restore

Tasks are host records, never a store of the plane's own: one `task` record per task, keyed `<caller>/<task>` where `<caller>` is the kernel's opaque per-principal reference, a hash-chained `task_event` record per change, and a `push_config` record per task (`plane-a2a/src/tasks.rs`, `plane-a2a/src/records.rs`). A key under another caller's prefix is one this caller can never name, which is how a foreign task reads exactly as a missing one. Every write of a task first claims the next sequence of its chain, so concurrent writers cannot interleave.

A fresh task is submitted and its dispatch recorded before the hop; a task that cannot be recorded refuses the request `503`, `-32603`, "the task could not be recorded".

When the plane's instance opens it restores (`tasks::restore`):

- unreadable rows are counted, never silently skipped (`BUSBAR-7024`); a store that cannot be listed at all is `BUSBAR-7025`;
- **terminal tasks are counted and their chains not read back**;
- each in-flight task's chain is read back through the host, which verifies it;
- **a chain the host reports broken is still held.** A break is named (`BUSBAR-2030`), never a deletion: refusing to restore it would let anyone able to corrupt one event erase a task.

Serving does not wait on the restore: each task is read from its own record when a request names it.

### Retention

**There is a retention sweep, and it touches only settled tasks** (`plane-a2a/src/tasks.rs`, `retention_sweep`). Its rule:

- a terminal task stays readable for **300 seconds** after its last change (`TERMINAL_TTL_SECS`); past that a read answers it as not found, and the sweep tombstones its `task` record, its event chain and its push config;
- at most **4096** terminal tasks are kept (`MAX_RETAINED`); past that the oldest go first, whatever their age;
- **an active task — working or interrupted — is never touched**, however long it has been idle. Live tasks are bounded at admission by the kernel instead.

The sweep **runs from a submission**, in the same record writes that open a fresh task, and never from a read, a callback or a timer. Each submission retires at most **32** settled tasks (`SWEEP_BUDGET`); the rest wait for the next. A sweep that fails retires nothing and fails no submission (`plane-a2a/src/task_hop.rs`). These are constants: there is no configuration key for the window, the cap or the budget.

---

## Push notifications

A caller registers a push-notification config — with the push-config verbs, or inline on a message — and expects a callback when its task moves. Busbar holds exactly **one config per task**; registering a second with a different id is refused until the first is deleted (`plane-a2a/src/local.rs`).

**What Busbar stores.** The config is a `push_config` host record: the callback URL, the A2A version it was registered under (which decides the notification's shape), and, if the caller gave one, its `authentication` credential as a sealed field. A read verb answers `id` and `url` only and never echoes the credential. Because the record is durable, **the URL and the caller's credential both survive a restart**: each delivery reads the task's config record and takes the credential from it (`plane-a2a/src/push_door.rs`, `queue_moved`). Between a config naming a credential and the task ending (its terminal delivery settling) or the config being deleted, the plane also holds it in memory. The credential type has no `Display` and a redacted `Debug`, and it never reaches a log line or an error text (`plane-a2a/src/push.rs`, `PushCredential`).

A config's `authentication` must name a `scheme` (an HTTP authentication scheme token such as `Bearer`), or `schemes[0]`; its `credentials` must be bytes an HTTP header can carry. A config `token` is refused with `UnsupportedOperation`: there is no header or body member a delivery would put it in.

**The callback floor.** A callback URL is judged when it is registered and again on every delivery attempt, by the host's destination judge — the one check every outbound connection passes — with private reach refused whatever the deployment's private-address setting. The words a refused callback gets (`local::judge_callback`):

- a scheme other than **https** — "a callback carries task metadata off-box and must be https";
- a URL with no host, or one carrying a userinfo, is malformed;
- an alternate IPv4 encoding of the host is refused;
- a host that resolves to no addresses — "nothing was checked, so nothing is allowed";
- an internal or metadata address.

**Busbar's own callback at the agent.** Busbar does not hand the caller's URL or credential to the backend. When a caller creates, reads, lists or deletes a push config for a task Busbar holds as live and whose agent has named it, Busbar mirrors that onto the agent: a create registers busbar's own callback, `<public_url>/a2a/push`, under config id `busbar-<agent's task id>`, with `authentication: {scheme: Bearer, credentials: <token>}`; a delete removes it; a read that does not find busbar's registration re-arms it (`plane-a2a/src/mirror.rs`). The mirror is best effort, never changes the caller's answer, and bills nothing. It is skipped when `public_url` is not `https`.

**The callback token.** The token is `<task-id>.<64 lower-case hex>`: the first 32 bytes of the host signing service's signature over the domain `busbar-a2a-push-token\0` followed by the task id. The plane never holds the key; it verifies a presented token by asking the host to sign again and comparing in constant time. Which caller each token's task belongs to is plane memory, so **a restart refuses every earlier token**. At most 4096 tokens are held per instance; past that no token is minted, and Busbar registers no callback of its own for that task (`plane-a2a/src/push.rs`, `Tokens`, `MAX_TOKENS`).

**Busbar's callback endpoint** (`POST /a2a/push`, `plane-a2a/src/push_serve.rs`) takes no Busbar key. The backend presents the token as `Authorization: Bearer <token>`. In order, each step a refusal that costs nothing further:

| Condition | Answer |
|---|---|
| no token, a token this instance did not mint, or one whose signature does not verify | `401` |
| the task's push-volume budget is spent: more than **60** pushes in its fixed **60-second** window | `429`, `Retry-After: 60` |
| body over **64 KiB** | `413` |
| the task is gone, past its retention window, or has ENDED | `401` — the same sentence, so existence is never revealed |
| body not JSON | `400` |
| otherwise | `202` with an empty body |

Every `401` carries the one sentence "this endpoint is addressed by the push token busbar registered with the agent". Refusals are `{"error":{"message":…}}`, not a JSON-RPC error body.

**The token's lifetime is the task's.** It is a capability for one task, not a one-time nonce: a backend reports `working`, then `input-required`, then `completed` with the same token. The report that moves the task to a terminal state is the last one it authorises: the token is forgotten once that answer is final, and it is also forgotten whenever the task ends any other way (a relayed answer, a cancel). An active task's token is never retired for idling.

**What a push records.** The reported state goes through the same transition table as every other observation of the task. A push that reports no state this build can read, or the state the task already holds, is `202` and moves nothing. A move the table refuses — an older state replayed after a newer one, anything after a terminal — is `202` and records nothing, so the backend does not retry-loop. **Nothing from the pushed body reaches the caller's webhook**: the onward delivery is composed from Busbar's own task row.

**The onward delivery** (`plane-a2a/src/push.rs`, `notification_body`) is shaped by the version the callback was registered under, always with Busbar's ids:

```json
{ "task": { "id": "a2a-planner-…", "contextId": "…",
            "status": { "state": "TASK_STATE_COMPLETED", "timestamp": "2026-02-14T00:00:00Z" } } }
```

That is v1.0 (and a config written before the version was kept): a `StreamResponse` with the task under `"task"`, the ProtoJSON state token and no `kind`. A v0.3 callback gets the `Task` object itself, `"kind": "task"` and the lower-case state word. `status.timestamp` is RFC 3339.

**Delivery.** Each task's notifications are queued in order, at most **64** per task; past that the oldest not-yet-attempted one is dropped and counted. One due notification is attempted per lifecycle tick, the tasks served in turn. Each attempt re-runs the destination judge, dials only the addresses that judgement admitted, attaches the caller's credential as `Authorization: <scheme> <credentials>` **only after** the judge has passed, and is bounded at **10 seconds** (`push_door.rs`). A delivery makes **at most three attempts**: the second waits 250 ms and the third 500 ms, each moved by up to 20% either way, and only a transport error, a `5xx` or a `429` is retried. A refused destination or any other `4xx` ends it at once. Success is a `2xx`. Delivery is best-effort: a failure never touches the task.

**Which certificates a delivery trusts.** A delivery verifies the webhook's certificate chain and name against the public roots. An operator whose callers' webhooks sit under a private CA writes that CA, as PEM, in the plane's own `agent_push:` section, beside `agents:`:

```yaml
agent_push:
  ca: |
    -----BEGIN CERTIFICATE-----
    …
    -----END CERTIFICATE-----
```

The CA is trusted **on top of** the public roots, never instead of them, and chain and name verification stay on: it is the connector's per-connection operator CA, reached through the push need's `trust_from` (`owned.agent_push.ca`, `plane-a2a/src/door_statement.rs`, `PUSH_TRUST_FROM`). The section is optional. Its one key is `ca`; any other key, a non-mapping section, or a `ca` that is not non-empty text refuses the configuration (`read_push_section`), and a `ca` the host cannot use as a trust anchor refuses the boot.

Every attempt's outcome is chained to the task's own provenance under one of three kinds, filed on a later relayed answer of the same caller:

| Provenance kind | When |
|---|---|
| `task.push_delivered` | the receiver answered `2xx` |
| `task.push_refused` | **nothing left the process** — the destination judge refused it, or the request could not be framed |
| `task.push_failed` | it went out and the receiver failed it, or the transport did |

---

## What a tripped agent returns

The circuit breaker runs on every plane, and a registered A2A agent is a cell on the same breaker a model lane sits on. See [Circuit breaker](/docs/circuit-breaker/) for the state machine.

**These cells refuse on a trip and nothing less.** The plane declares `bench_below_trip_threshold: false` (its `declares.json` in GetBusbar/busbar-plane-a2a): one transient failure below the trip threshold never benches an agent's cell. An upstream's own `Retry-After` is still honoured. A failover pool's `breaker:` block, where its `agents.pools` entry states one, is read for an A2A pool exactly as for any other (`crates/busbar/src/root/door_steps.rs`, `DoorPools::breaker`); otherwise the built-in defaults apply.

A tripped agent answers **HTTP `503`** with a `Retry-After` and a JSON-RPC error. **A fresh submission the open breaker refused before the socket is opened and ended `rejected`, not `failed`**, and the refusal names its task id as a `google.rpc.ResourceInfo` in `error.data` (`resourceType: "a2a.busbar/task"`, `plane-a2a/src/task_identity.rs`, `about_task`). The task id rides there rather than as a `taskId` member of the error object, because JSON-RPC 2.0 §5 admits only `code`, `message` and `data`. `failed` means *we tried and it broke*; `rejected` means *we did not accept this work*, which is what a breaker refusing to start a call has done. The calling agent decides whether and when to retry.

**An addressed task is different.** A verb naming an existing task does not end it: that task exists at exactly one backend, and the row keeps its last-known state.

For a member of an `agents.pools` failover pool, a fresh submission is placed by the pool's walk, so a tripped member is not by itself what produces a `rejected` task.

---

## Observability

**Plane-defined metric families.** The plane's Statement declares two counters, both about the push channel (`plane-a2a/src/door_statement.rs`, `FAMILIES`):

| Metric | Type | Meaning |
|---|---|---|
| `busbar_a2a_push_notifications_dropped_total` | counter | push notifications dropped, oldest first, from a full per-task queue |
| `busbar_a2a_push_outcomes_unfiled_total` | counter | push delivery outcomes dropped unfiled from a full book of owed outcomes (at most 4096 are held) |

Requests on the plane are counted by the host's shared plane request families, labelled with the binding the request arrived on; see [Observability](/docs/observability/). The plane's counter lane words are its three dialect names.

**Diagnostics.** The plane raises exactly ten catalogue codes, and its `declares.json` states exactly those (`plane-a2a/src/diagnostics.rs`, `DIAGNOSTICS`):

| Code | Slug |
|---|---|
| `BUSBAR-2030` | `a2a-task-chain-verify-failed` |
| `BUSBAR-7003` | `a2a-pool-not-interchangeable` |
| `BUSBAR-7013` | `a2a-outbound-cred-unleased` |
| `BUSBAR-7018` | `a2a-relayed-stream-refused` |
| `BUSBAR-7020` | `a2a-relayed-outcome-unrecorded` |
| `BUSBAR-7021` | `a2a-relayed-submission-failed` |
| `BUSBAR-7023` | `a2a-failure-unrecorded` |
| `BUSBAR-7024` | `a2a-task-rows-unreadable` |
| `BUSBAR-7025` | `a2a-task-state-unread` |
| `BUSBAR-7104` | `plane-sse-frame-not-utf8` |

The other `BUSBAR-70xx`/`71xx` codes the plane's predecessor registered are never raised by the plane. The plane's `dev` catalogue holds them as reserved (never declared, never reissued to another meaning); the generated A2A diagnostics page still lists them until this build's pin of the plane includes that change. See the A2A diagnostics catalogue for each code's action.

---

## Governance

**Every admitted unit leaves an audit row**, action `agent.call`, resource `agent:<agent_id>`: `applied` when the unit was served (its hop left the plane, or the plane answered it), rejected when it was refused after its admission — a gate, a budget, a breaker, a hop that never left (`plane-a2a/src/door_statement.rs`, `AUDIT_ACTION`, `audit_write`).

**Billing.** The plane reports units and never a price: a hop's moved bytes, and a fee unit, `per_request`, reported `1` once the unit is served, so a unit refused before that has its fee refunded (`BILLABLE_CLASSES`). Verbs Busbar answers itself (`ListTasks`, the push-config verbs) are metered against the agent they named. `GetExtendedAgentCard` on `POST /a2a` names *no* agent, so its row names the **plane pool**, spelled as this plane's config section, `agents` (`PLANE_POOL_RESOURCE`); that cannot collide with a member row, because members are keyed with an `agent:` prefix. The task store records no charge: a charge, an audit row, a breaker verdict and an outbound credential are the kernel's (`plane-a2a/src/records.rs`).

**Hooks** attach as `agents.hooks:` ∪ `agents.<agent>.hooks:`. The plane's tail declares its hooks gated: an agent's gates screen the projected `{tool, arguments}` — the method as the target, `params` as the arguments — first, fail-closed, a veto answered at the hook's own status; then its rewrites apply (`door_statement.rs`, `TAIL`).

**The per-task provenance chain** is one hash chain per task, kept and verified by the host. Each event carries `ts`, `kind`, `context_id`, `principal`, `agent_id` and `state`, each length-prefixed so no byte can cross a field boundary unseen; the host frames the previous hash, the chain's scope and the sequence ahead of them. `request_id` is not chained (`plane-a2a/src/tasks.rs`, `suffix`). Event kinds include `task.submitted`, `task.delegated`, `task.artifact`, the state moves, and the three push kinds above. The claim is **tamper-evidence, not tamper-prevention**: the restore reports breaks while still holding the rows.

**Egress is gated by the caller's grant.** A hop reaches an agent only when the caller's key holds the `agent:<id>` grant for that agent; Busbar does not spend its own credential on behalf of a caller that is not itself authorised for the backend agent. `egress_scopes:` is not read.

---

## Operator surfaces

| Route | What it does |
|---|---|
| `POST /api/v1/admin/agents/{name}/connect` | **Reaches the network.** Fetches the agent's card, verifies it against the operator's root, records it as the agent's card records, and reports the fingerprint. It **approves nothing**. A card that could not be authenticated is still a `200`, with the reason in `failure` and the state `error`. Audited as `connect`. |
| `POST /api/v1/admin/agents/{name}/approve` | Body `{"fingerprint": "…"}` — the fingerprint `connect` reported, echoed back. The card is re-fetched and re-verified, and an approval naming any other fingerprint is refused. Audited as `approve`. |

Both are served by the plane on the kernel's admin mount (`plane-a2a/src/door_statement.rs`, `ADMIN_VERBS`, `ADMIN_OPENAPI`). Without them every registration stays pending and no fronted agent can serve.

`connect` deliberately does not approve: adopting what was seen is a separate, explicit operator act, so a poisoned card cannot be adopted by the same call that fetched it. `unpinned` cannot be approved.

Both verbs answer the same `A2aTrustView`: `{name, state, pin_mechanism, fingerprint, pin_changed, added, changed, removed, observed_skills, failure}`, where `state` is `pending`, `approved`, `quarantined`, `suspended` or `error`, derived on every read. The approved card and its skills are host records (`card`, `card_approval`), so a restart keeps what drift is judged against (`plane-a2a/src/records.rs`).

---

## Conformance

Busbar's A2A claims are gated by two independent instruments, run against a Busbar booted from the commit under test:

- `testing/a2a-harness/` — an independent battery written from the published specification;
- `testing/a2a-tck/` — a wrapper around the publisher's own TCK at a pinned commit.

The same two rules as the MCP battery apply: **control legs run always** (a battery that cannot judge a known-good peer cannot be trusted to judge Busbar) and **the subject leg is armed or red** (a disarmed leg renders as the same green tick as a leg that judged Busbar and passed).

The subject is booted on loopback by `scripts/a2a-subject/boot.sh` — not against a deployed URL, because that makes both verdicts unreadable. The script asks the OS for five free ports, generates the signing key with `busbar --generate-signing-key`, hands Busbar the same bytes through `auth.signing_key`, and signs one audience-correct token; Busbar's A2A mount refuses any credential whose audience is not exactly `<public_url>/a2a`, and an opaque API key is refused outright, so there is no "just use an API key" path.

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
- the **HTTP+JSON binding is not driven by the TCK** in this rig, so its requirements report as *untested* rather than failed. That is a gap in the rig and not in the card: Busbar's own card advertises all three bindings. A *fronted agent's* card advertises `JSONRPC` only, because `/a2a/agents/{id}` mounts a JSON-RPC endpoint and nothing else;
- `PUSH-DELIVER-001/002/003` are **red and waived**, with the reason recorded in `testing/a2a-tck/WAIVERS.md`: the suite's receiver URL is literal `http://`, and Busbar refuses a plaintext webhook before it looks at the address. All three still run, still fail, and are still counted.
