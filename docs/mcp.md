# MCP

Busbar is an MCP server, and a governed gateway in front of the MCP tool servers you already run. An agent connects to Busbar exactly as it connects to any OAuth 2.1 protected resource: with no credential first, which earns a `401` carrying the discovery document's URL; it follows that to your identity provider, comes back with a token, and from there every tool call rides the machinery a model request already rides — the caller's key, its grants, its budget, hooks, the audit chain, and the circuit breaker.

This page is the operator's reference for the plane: what a deployment gets by turning it on, the complete configuration grammar and every boot refusal, how identity is established, how a caller's grants decide what it can see and call, the two transports, what a tripped upstream returns, and what the plane emits.

The plane is built in its own repository, GetBusbar/busbar-plane-mcp, and pinned into this build as a git dependency. Source paths on this page written as a bare file name (`tools_config.rs`, `call.rs`, ...) are in that repository's `plane-mcp/src/` unless another repository is named; paths starting `crates/` are in this repository.

Cross-references: [Circuit breaker](/docs/circuit-breaker/) (the one FSM, on all three planes) · [Configuration](/docs/configuration/) (field reference) · [Observability](/docs/observability/) (the metric families) · [Hooks](/docs/hooks/) (attaching your own logic) · [Operations](/docs/operations/) (running it).

---

## What the plane is

Busbar sits on both sides of MCP at once, and the two directions are configured by two different sections.

**Busbar as the MCP server** is the `mcp:` block. Its presence mounts an MCP endpoint, an RFC 9728 protected-resource metadata document, and nothing else. On the stateless revision Busbar answers `server/discover`, `tools/list`, `tools/call`, `prompts/list`, `prompts/get`, `resources/list`, `resources/templates/list`, `resources/read`, `completion/complete`, the SEP-2663 task methods (`tasks/get`, `tasks/update`, `tasks/cancel`) and `subscriptions/listen` (`codec.rs`). A session-revision client opens with `initialize`, and its session dispatches `tools/list`, `tools/call`, `prompts/list`, `prompts/get`, `resources/list`, `resources/templates/list`, `resources/read` and `completion/complete`, answers `ping`, and answers `resources/subscribe`, `resources/unsubscribe` and `logging/setLevel` from the session's own state (`adapt.rs`). Anything else answers JSON-RPC `-32601`.

**Busbar as an MCP client** is the `tools:` section. Each entry registers one upstream tool server: where it is, what authenticity root it is pinned to, which of its tools you have approved, and what credential Busbar spends to reach it.

The two are independent. `mcp:` with no `tools:` is a correctly configured MCP server with an empty catalogue. `tools:` with no `mcp:` registers upstreams that nothing inbound can reach — no route is mounted, so nothing can call them over MCP.

### A deployment with no `mcp:` block gains nothing

This is a property of the boot path rather than a claim about defaults: a plane whose section is not configured is not mounted (the `law7-unconfigured-*` black-box cases hold this for each plane). With no `mcp:`:

- no ingress route and no metadata route exist in the route table, so a `POST /mcp` is an ordinary unclaimed path that falls through to the residual LLM plane;
- no MCP claim is mounted, so the RFC 8707 audience check bound to the MCP mount never runs;
- nothing inbound can reach a `tools:` registration, because nothing inbound is mounted.

There is **no background job to switch off**: an upstream is re-verified lazily, on the `tools/call` path (verify-on-call — see [Tool and agent trust](/docs/tool-and-agent-trust/)), so a registration nothing calls is never reached. An absent `mcp:` block closes the inbound door, and with no inbound call there is nothing to trigger an outbound fetch. If you want no traffic to a registration at all, remove the registration.

A plane exists because it is configured, not because its name appears in a path.

---

## Configuration

### The `mcp:` block

`deny_unknown_fields`: a typo'd key fails boot (`endpoint.rs`).

| Key | Type | Required | Default | What it is |
|---|---|---|---|---|
| `canonical_uri` | string | **yes** | — | The RFC 8707 resource indicator: the absolute URI naming this deployment's MCP endpoint. It is the exact `aud` every inbound token must carry. Its path **must be `/mcp`**; any other path refuses boot. |
| `authorization_servers` | list of strings | **yes**, non-empty | `[]` (refused) | RFC 9728 `authorization_servers`: the issuer identifiers permitted to mint tokens for this resource. This list is the entire content of the answer a credential-less client came for. |
| `scopes_supported` | list of strings | no | `[]` | RFC 9728 `scopes_supported`. **Advisory metadata only** — authorization is decided by the caller's grant, never by this list. |
| `allowed_origins` | list of strings | no | `[]` | Browser origins accepted on the ingress, for the `2026-07-28` `Origin` MUST. Empty means no browser origin is accepted; a request carrying no `Origin` (every non-browser client) is unaffected. |

The **mount path is fixed at `/mcp`**; it is not configurable. The plane's inbound paths are compile-time claims, and `/mcp` (with its discovery document) is the one it claims. `canonical_uri` chooses the scheme, host and port the audience names, and its path must be `/mcp` (a trailing slash is accepted and mounts at the same place). A `canonical_uri` naming any other path, including a nested one such as `https://gateway.example.com/api/mcp` or a differently cased one such as `/MCP`, is a boot refusal, so the path a client posts to and the identifier its token is bound to cannot drift apart.

```yaml
mcp:
  canonical_uri: https://gateway.example.com/mcp
  authorization_servers:
    - https://login.example.com
  scopes_supported: [mcp.tools.read, mcp.tools.call]
  allowed_origins: []
```

That mounts the plane's served routes (`door.rs`, `ROUTES`; the claims are in `tool_claims.rs`) — `GET` and `DELETE` are separate entries sharing one row here because they share one answer:

| Route | Auth | What it is |
|---|---|---|
| `GET /.well-known/oauth-protected-resource/mcp` | **none** | RFC 9728 §3.1 metadata. The one open route on this plane — every caller who needs it is by definition one that has no token yet. |
| `POST /mcp` | key | The endpoint. JSON-RPC 2.0. |
| `GET /mcp`, `DELETE /mcp` | key | The session revisions (2025-11-25, 2025-06-18): a GET naming `Mcp-Session-Id` opens that session's event stream, a DELETE naming it ends it; a session another key presents is `404`. A GET accepting `text/event-stream` with no session and no `MCP-Protocol-Version` opens the 2024-11-05 event stream. Any other GET or DELETE is `405`. Behind the key so an anonymous caller gets the `401` challenge instead of a description of the surface. |
| `POST /mcp/tasks/run` | key | A task's continuation (SEP-2663), nested by the unit that created the task: it runs under the principal its work handle recorded, and only once. |

The metadata path is the well-known prefix with the resource's path appended **after** it, per RFC 9728's path-insertion rule (`endpoint.rs`). Getting that backwards 404s every compliant client's discovery. The document Busbar renders carries `resource` always, `authorization_servers` and `scopes_supported` when non-empty, and `bearer_methods_supported: ["header"]`, with `Cache-Control: public, max-age=3600` (`crates/busbar-kernel/src/ingress/protocol.rs`). `bearer_methods_supported` is not configurable: Busbar accepts a bearer in the `Authorization` header and nowhere else, on every plane.

### Boot refusals: the `mcp:` block

Every one of these stops the process. An MCP plane that is half-configured is worse than one that is absent, because it answers.

| Refusal | Condition | Source |
|---|---|---|
| `mcp.canonical_uri is required` | absent or empty | `endpoint.rs` |
| `… is not an absolute http(s) URI` | not `http://` / `https://` with a non-empty authority | `endpoint.rs` |
| `… carries a query or fragment` | a `?` or `#` in the **path**, or a `#` in the **origin**. A `?` inside the authority is not tested by this arm — `split_absolute` cuts at the first `/`, so it lands in the origin, and `https://gateway.example.com?x/mcp` boots with that whole string as the audience and `/mcp` as the mount | `endpoint.rs` |
| `… has no path` | path is empty or `/` — mounting at `/` would claim every path in the deployment | `endpoint.rs` |
| `… but the MCP endpoint is served only at` `` `/mcp` `` | the path is anything but `/mcp`, trailing slashes aside | `endpoint.rs` |
| `mcp.authorization_servers must list at least one issuer` | empty list | `endpoint.rs` |
| `… entry is not an absolute http(s) URI` | any entry | `endpoint.rs` |
| **`` `mcp:` is configured but auth.chain is empty ``** | `mcp:` present and `auth.chain` absent or `[]` | `crates/busbar-kernel/src/config_validate/mod.rs` |

**The empty-`auth.chain` refusal is the one to understand.** With an empty chain the auth middleware admits with no principal at all. The plane's entire authorization model is that a caller sees and may call only what its key's grant permits — and a request that carries no key is never *narrowed* by one, so the grant predicate answers `true` for every `(kind, value)` pair it is asked. That is not "no access", it is wildcard access to every registered server and every approved tool, for anyone who can reach the port. The second half is transitive: the outbound credential Busbar spends is bound to the inbound principal's grant, and with no inbound principal there is nothing to bind to, so Busbar spends its own upstream credentials on behalf of an anonymous caller. Both properties go vacuous at once and neither failure is visible from outside — the deployment answers every request perfectly. Close the chain (`auth: { chain: [keys] }`, or an IdP auth plugin), or drop the `mcp:` block.

This refusal is MCP-only. There is no equivalent check for `agents:` — see [A2A](/docs/a2a/).

### The `tools:` section

`tools:` is a sibling of `pools:` and `agents:`: a map whose keys are registrations, with two words reserved at the section level on every plane (`RESERVED_SECTION_KEYS`, `crates/busbar-contract/src/section.rs`). The section's `pools` sub-key is lifted out the same way and holds the plane's failover pools (see [Failover pools](#failover-pools-toolspools)).

| Reserved section key | Type | Combine rule |
|---|---|---|
| `tools.hooks` | list of bare hook names | **ADDITIVE** — union with each server's own `hooks:`, deduped in declaration order (`tools_config.rs`) |
| `tools.upstream_credentials` | `own` \| `passthrough` | **OVERRIDE** — an entry's own value replaces it (`tools_config.rs`) |

Naming a server `hooks` or `upstream_credentials` is refused at parse with a message naming the reservation, and the refusal for a reserved key holding a *mapping* fires **before** the typed lifts so you read "that name is reserved" rather than "expected a sequence" (`split_section`, `crates/busbar-contract/src/section.rs`).

#### `tools.<server>` — one registered upstream

`deny_unknown_fields`: a typo'd key fails boot rather than silently un-pinning a server (`tools_config.rs`).

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `pin` | object | **yes** | — | The out-of-band trust root. Required even when it is `unpinned`. |
| `pin.mechanism` | `pinned_pubkey` \| `cert_spki` \| `mtls` \| `unpinned` | **yes** | — | A pin whose mechanism is inferred is a pin whose meaning changes when the inference changes. |
| `pin.key` | string | required for the three rooted mechanisms; **refused** for `unpinned` | — | Issuer public key, or certificate SPKI hash. For `cert_spki` and `mtls` the key is the SHA-256 of the server certificate's whole SubjectPublicKeyInfo, written `sha256/<base64>` (canonical, standard base64 with padding); the plain `<base64>` is accepted as an alias. Anything that is not one 32-byte digest in either spelling is refused when the registration is sealed (the configuration is not loaded). |
| `transport` | `streamable_http` \| `stdio` | no | `streamable_http` | See [Transports](#transports). |
| `url` | string | **yes** for `streamable_http`; **refused** for `stdio` | `""` | `http://` or `https://`. |
| `command` | string | **yes** for `stdio`; **refused** otherwise | — | ABSOLUTE path of the binary Busbar spawns. |
| `args` | list of strings | no; **refused** on non-stdio | `[]` | The child's argv, verbatim. Never split on spaces. |
| `env` | map of name → string \| secret ref | no; **refused** on non-stdio | `{}` | The child's WHOLE environment. |
| `cwd` | string | no; **refused** on non-stdio | Busbar's own | Absolute. |
| `verify_ttl` | `<n><s\|m\|h\|d>` | no | `5s` (`tools_config.rs`) | The longest an observation of this upstream's tool list may be reused on the `tools/call` path before it is re-fetched and re-verified. `0` = strict-live (re-verify every call); a larger value is an explicit security downgrade. Renamed from `refresh_ttl` in 1.6.0 — see [Tool and agent trust](/docs/tool-and-agent-trust/). |
| `timeout` | `<n><s\|m\|h\|d>` | no | `30s` (the core's default for a tool-server registration, `DEFAULT_ENTRY_TIMEOUT_MS` in `crates/busbar-contract/src/section.rs`) | Wall-clock budget for one outbound leg (the tool call; separately, the tool-list fetch and the RFC 8693 exchange). `0` is refused. |
| `tools_allow` | map of tool name → object | no | `{}` | The approved tools. A map, not a list, because every tool needs a slot for its approved schema hash. |
| `prompts_allow` | map of prompt name → object | no | `{}` | |
| `resources_allow` | map of URI → object | no | `{}` | |
| `resource_templates_allow` | map of URI template → object | no | `{}` | RFC 6570 **level 1 only**. |
| `aud` | absolute http(s) URI | required when `token_exchange:` is set; **refused** on `stdio` | — | The RFC 8707 resource indicator for the OUTBOUND token. Not Busbar's own audience — that is `mcp.canonical_uri`. |
| `grants` | object of three booleans | no | all `false` | `sampling`, `elicitation`, `roots` — which asks this upstream may put to your callers. A granted ask is relayed to the caller; Busbar answers none itself. |
| `allow_private` | bool | no; **refused** on `stdio` | `false` | Permits a private / loopback / CGNAT address for this one server. Never permits cloud-metadata addresses. |
| `token_exchange` | object | no; **refused** on `stdio` | absent | RFC 8693 exchange. Absent ⇒ no credential is sent at all. |
| `max_input_required_rounds` | u32 | no | `3` (`tools_config.rs`) | Cap on the rounds of an UPSTREAM's asks Busbar relays to its caller, per dispatch. `0` means never. |
| `max_caller_ask_rounds` | u32 | no | `3` (`tools_config.rs`) | Cap on rounds Busbar asks ITS OWN CALLER for. `0` is an operator kill switch for every `ask_caller` on this server. |
| `sampling_bounds` | object | no | see below | Input-side bounds on a relayed `sampling/createMessage` ask. An ask past any bound is refused by name (`sampling_bound_exceeded`), never relayed. |
| `upstream_credentials` | `own` \| `passthrough` | no; **refused** on `stdio` | section value, else engine default | |
| `hooks` | list of bare names | no | `[]` | Adds to `tools.hooks:`. |

**`tools_allow.<tool>`** (`tools_config.rs`):

| Key | Type | Default | Notes |
|---|---|---|---|
| `schema_hash` | string | absent | The APPROVED digest. **An empty value object means "allowed, no hash approved yet", which is `pending` and does not serve.** |
| `description` | string | absent | The OPERATOR's description, published in the catalogue. Markup-normalised on the way out. Never an input to a routing decision. |
| `input_schema` | JSON | absent | Echoed verbatim as `inputSchema`. Absent publishes `{"type":"object"}`. |
| `output_schema` | JSON | absent | Published as `outputSchema`. Busbar does not validate an upstream's `structuredContent` against it: the upstream's result reaches the caller as the upstream sent it, and the caller judges it against the published schema. Absent publishes none — Busbar never invents one. |
| `publish_as` | string | absent | Overrides the default published wire name `<server>_<tool>`. This is the value `tools/list` emits, the value `tools/call` dispatches on, **and the value an `mcp_tool:` grant must name** — so setting it changes who can call the tool. |
| `ask_caller` | list of rounds | `[]` | What Busbar asks its own caller for, synchronously (SEP-2322), before dispatching. |
| `task_support` | `none` \| `optional` \| `required` | `none` | SEP-2663. `required` refuses a client that did not declare the tasks extension with `-32021` before the handler runs. |
| `task_ask_caller` | list of rounds | `[]` | The same ask, from INSIDE a task. Requires `task_support` other than `none`. |

One round of `ask_caller` is a map from a server-assigned key to `{method, params?}`. `method` is one of `elicitation/create`, `sampling/createMessage`, `roots/list`. **`params` is cloned verbatim onto the wire — there is no templating and no substitution**, structurally, so an upstream's value can never flow into a demand Busbar makes in its own name (`tools_config.rs`).

**`sampling_bounds`** (`tools_config.rs`): `max_messages` (default `64`; `0` refused), `max_prompt_bytes` (system prompt plus every message's content, default `65536`; `0` refused), `max_stop_sequences` (default `8`), `max_stop_sequence_bytes` (default `64`), `temperature_min_milli` / `temperature_max_milli` (thousandths, default `0` / `2000`; min above max is refused), and `max_input_response_bytes` (the caller's reply to an ask, with the `requestState` it carries, default `1048576`; `0` refused).

**`prompts_allow.<name>`**: `description`, `template` (text form), `messages` (typed form: `role` ∈ `user`\|`assistant`, default `user`; content `text` / `image` / `audio` / `resource`), `ask_caller`. `template:` and `messages:` are alternatives — declaring both is refused.

**`resources_allow.<uri>`**: `name`, `description`, `mime_type`, `text`, `blob` (base64). `text:` and `blob:` are alternatives — declaring both is refused, and a `blob` that does not decode is refused at boot.

**`resource_templates_allow.<template>`**: `name`, `description`, `mime_type`, `text`. There is deliberately no `blob:`.

**`token_exchange`**: `token_url` (must be `https`, or `http` only on a registration that also sets `allow_private: true`), `subject_token` (a `SecretRef` — Busbar's OWN token, never the caller's), `subject_token_type` (default `urn:ietf:params:oauth:token-type:access_token`). There is deliberately **no `scope:`** — the requested scope is derived from the inbound caller's own grant at dispatch time, because a configured scope list would be a second statement of what a caller may reach and the wider one would win (`tools_config.rs`; the derivation is `tool_scope.rs`).

```yaml
tools:
  hooks: [pii-guard]                       # fires for every registered server

  acme:
    url: https://tools.acme.example/mcp
    pin: { mechanism: cert_spki, key: "sha256/…" }   # canonical; the plain base64 alias is accepted too
    verify_ttl: 5s
    timeout: 30s
    aud: https://tools.acme.example/mcp
    token_exchange:
      token_url: https://login.example.com/oauth2/token
      subject_token: { env: BUSBAR_SUBJECT_TOKEN }
    tools_allow:
      search_code:
        schema_hash: "sha256:…"            # approved: this one serves
        description: Search the code index.
      send_email: {}                       # allowed, nothing approved: pending, does NOT serve
    hooks: [acme-audit]                    # ADDS to tools.hooks
```

### Boot refusals: the `tools:` section

All of these are checked by `validate_server` / `validate_endpoint`, which is called from **both** the config file's `Deserialize` and the admin write path, so the API refuses exactly what the file refuses (`tools_config.rs`).

| Refusal | Condition | `tools_config.rs` |
|---|---|---|
| server id may not contain `_` | the id is the first half of the `<server>_<tool>` routing key; with a separator inside it two different `(server, tool)` pairs render the same key and one `mcp_tool` grant silently names both. **Tool names may contain `_`** — only the id may not | `1202-1212` |
| `command:` / `args:` / `env:` / `cwd:` on a network registration | those describe a child process | `1062-1076` |
| `url:` missing / not http(s) on a network registration | | `1077-1087` |
| `url:` present on `transport: stdio` | the registration named two different servers | `1091-1096` |
| `command:` missing on `transport: stdio` | there is no default and Busbar will not guess one | `1097-1107` |
| `command:` not an absolute path | a bare name is resolved through `PATH`, so whoever controls Busbar's environment chooses the binary. Checked with `Path::is_absolute`, which is platform-correct (a drive-relative `\foo` on Windows is refused for the same reason) | `1123-1129` |
| `cwd:` not absolute | | `1130-1137` |
| `env:` name empty, or containing `=` or NUL | not a variable an exec can carry | `1138-1149` |
| `token_exchange:` on `stdio` | a pipe has no header block to carry a bearer. Refused rather than silently dropped | `1154-1160` |
| `aud:` on `stdio` | stdio mints no outbound token | `1161-1166` |
| `upstream_credentials:` on `stdio` | stdio makes no network hop | `1167-1172` |
| `allow_private:` on `stdio` | there is no address for it to widen | `1175-1180` |
| rooted `pin.mechanism` with no `pin.key` | a pin with nothing to verify with is not a pin | `1218-1225` |
| `pin.mechanism: unpinned` carrying `pin.key` | key material never verified against reads as protection that does not exist | `1226-1232` |
| `verify_ttl:` unparseable | parsed at boot so it lands on the operator, not on a silent fallback later | `tools_config.rs` |
| `timeout:` unparseable, or `0` | zero would refuse every call before it was sent. There is deliberately no spelling for "unlimited" | `1246-1256` |
| `task_ask_caller:` with `task_support` absent or `none` | the ask could never be emitted | `1324-1331` |
| `publish_as:` empty, or with leading/trailing whitespace | it is compared byte-for-byte against a `tools/call` name and against an `mcp_tool:` grant | `1337-1354` |
| empty `tools_allow` / `prompts_allow` name key, empty `resources_allow` URI key | | `1550-1555`, `1361-1363` |
| `prompts_allow.<n>` declares both `template:` and `messages:` | two alternative spellings of one prompt | `1559-1566` |
| `messages[i].role` not `user` or `assistant` | | `1571-1577` |
| base64 that does not decode (`image.data`, `audio.data`, `resource.blob`, `resources_allow.<uri>.blob`) | | `1607-1618` |
| `resources_allow.<uri>` declares both `text:` and `blob:` | | `1365-1372` |
| a resource template using anything above RFC 6570 level 1 (`+ # / ? & *`), an unbalanced brace, an empty `{}`, a duplicated parameter, or no parameter at all | a matcher that accepted level-3 syntax with level-1 semantics would resolve some URIs to the wrong template — content served under an approval nobody gave | `1629-1684` |
| `resource_templates_allow.<t>.text:` substitutes none of the template's parameters | a concrete resource behind a URI wildcard | `1382-1393` |
| `token_exchange.token_url:` not https (and not `http` + `allow_private`) | it receives Busbar's own subject token | `1401-1409` |
| `token_exchange:` beside `upstream_credentials: passthrough` | one says Busbar mints the credential, the other says the caller supplies it | `1413-1422` |
| `token_exchange:` with no `aud:` | without a resource indicator the issued token is spendable at any backend the AS serves | `1426-1432` |
| `aud:` not an absolute http(s) URI | | `1435-1442` |
| a `hooks:` entry that is not a bare name, or that reaches onto another section (`pools.x`, `agents.y`) | | `crates/busbar-kernel/src/config/plane_sections.rs` |

Two more refusals run over the **whole** effective registry (file base + admin overlay), in `config::resolve`:

- **Published-name uniqueness.** Two tools that would both be published as one wire name refuse boot, naming both claimants. The check compares every published name against every other, *including* an override against another server's default — the collision a naive overrides-only check misses (`validate_published_names`, `tools_config.rs`). A collision is refused rather than resolved, because the published name is what an `mcp_tool:` grant names, so resolving it would silently move an authorization decision.
- **Dangling hook references.** A hook a `tools:` entry names must exist in the one top-level `hooks:` map (`crates/busbar-kernel/src/config/mod.rs`). A dropped reference is an operator believing a control is attached that is not.

### Failover pools: `tools.pools`

An MCP registration is one destination. A pool under the `tools:` section's reserved `pools` sub-key is how you tell Busbar that two registrations are **the same server deployed twice**: one image in two regions, a hosted instance beside a self-hosted twin. The top-level `pools:` map belongs to the model plane; a plane's failover pools are written under that plane's own section, and which plane a pool is on is where you wrote it (`crates/busbar-kernel/src/config/mod.rs`). That declaration is what the kernel's selection walk needs in order to send a request the breaker would otherwise refuse to the other member instead; a `tools/call` whose server is a pool member routes over the pool (`tool_door.rs`).

It is **opt-in and declaring no MCP pool is exactly the unpooled behaviour**: one registration, one destination, nothing to reason about (`crates/busbar-kernel/src/config/pools.rs`).

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `members` | list of bare `tools:` names | yes, **2 to 8** | `[]` | ORDERED: the first is the primary, and its approved fingerprint is the one every other member must match. |
| `repeatable` | list of operation names | no | `[]` | Operations safe to perform TWICE. |
| `breaker` | object | no | the breaker defaults | The pool's breaker block, with the same keys and validation as a top-level `pools:` entry's `breaker:`. |

`deny_unknown_fields` — a typo'd key must fail boot, not silently un-declare a safety rule (`crates/busbar-kernel/src/config/pools.rs`). There is no `repeatable: all`.

```yaml
# `key:` is `sha256/<base64>` (canonical) or the plain `<base64>` alias of the same digest.
tools:
  search-eu: { url: https://eu.search.example/mcp, pin: { mechanism: cert_spki, key: "sha256/…" } }
  search-us: { url: https://us.search.example/mcp, pin: { mechanism: cert_spki, key: "sha256/…" } }
  pools:
    search:
      members: [search-eu, search-us]
      repeatable: [search_code]    # reads may be performed twice. Default: none.
```

Boot refusals, all in `crates/busbar-kernel/src/config/mod.rs` (`check_failover_pool`):

| Refusal | Condition |
|---|---|
| a failover pool needs at least TWO members | `members.len() < 2` — a one-member pool has nowhere to fail over to |
| members exceeds the supported maximum of 8 per failover pool | the breaker's per-member lane table is fixed at process start |
| `<pool>` is also the id of a `tools:` registration | a pool's name shares the breaker keyspace with registration ids on its plane |
| `<member>` is named twice | a repeated member would be tried twice against the same upstream, which is a retry wearing a failover's clothes |
| `<member>` is an entry in another top-level section | **no pool may straddle two planes**; the message names the section the entry really lives in rather than sending you hunting for a typo you did not make |
| `<member>` is not defined in the top-level `tools:` map | |
| `repeatable:` holds an empty entry | an empty entry names nothing |

**Naming two servers in a pool is not what makes them interchangeable.** When the walk picks another member, that member's own tool is admitted as its own (its grants, its trust state, its argument guard) and is interchangeable only when its approved digest is the primary's; a member with no such twin is declined and the walk moves on (`tool_door.rs`). Same image in two regions ⇒ same schemas ⇒ same digest ⇒ provably interchangeable. Two different vendors' `search` tools ⇒ different digests ⇒ declined. You are asserting only *"these names are the same deployment"*, and that claim is checked before a single request moves.

**A reroute is not a retry**, and the seam draws the line there. When the primary's breaker is Open the request never left Busbar, so sending it to an equivalent deployment duplicates nothing: that movement is the one the rule allows by default. Once a call has gone out, moving it is a genuine repeat of work the upstream may already have done, and the rule refuses it unless the operation is named in `repeatable:` (`crates/busbar-kernel/src/config/pools.rs`). `send_email` is not repeated. `charge_card` is not repeated. There is no switch that turns the rule off wholesale. The two rules compose: **repeat a call only when the digests match AND the operation is declared safe to repeat.**

Reroute never means Busbar found somewhere else to send a call on its own. It means the selection walk chose a different member of a pool you declared, whose fingerprint Busbar verified matches. There is no discovery, and no member you did not write down.

---

## Authentication and identity

### The discovery loop

An MCP client arrives with no credential. It gets `401` with an RFC 6750 `WWW-Authenticate: Bearer` challenge carrying a `resource_metadata` parameter — the **absolute** URL of this deployment's protected-resource document, because a client with no credential also has no reason to trust its own reconstruction of your origin (`endpoint.rs`, `crates/busbar-kernel/src/auth/challenge.rs`). It reads that document, finds `authorization_servers`, does ordinary OAuth against your IdP, and comes back with a token.

The challenge distinguishes two cases and clients branch on the difference. No credential presented at all earns a **bare** challenge with no `error` parameter — RFC 6750 §3.1 is explicit that this case omits it, because the bare challenge means *authenticate* — while a credential that was presented and failed earns `error="invalid_token"`. They are not collapsed (`crates/busbar-kernel/src/auth/challenge.rs`, `crates/busbar-kernel/src/auth/mod.rs`). A principal that authenticates but carries no grant on this resource gets `insufficient_scope`.

### What Busbar issues, and what it does not

**With `mcp:` alone, Busbar issues nothing.** It is an OAuth 2.1 *resource server*. The tokens are minted by your existing IdP (Okta, Entra, Auth0) and nothing in the MCP plane mints one.

Two consequences that bite operators:

- **A Busbar virtual key does not work on the MCP endpoint.** Busbar's own signed `bbk_…` tokens carry an optional audience claim, and the verifier enforces the plane boundary in both directions: a token with no audience is admissible only on the plain data plane, and a token presented on an audience-checked ingress must carry exactly that audience. A key minted through `SigningKey::mint` carries `aud: None`, so it is refused here with an audience mismatch. There is no release surface that mints an audience-bound `bbk_` token: `mint_for_audience` is compiled only under `cfg(any(test, feature = "test-support"))` (`crates/busbar-kernel/src/governance/signing.rs`).
- **An opaque bearer is refused.** An IdP that issues opaque reference tokens presents a credential with no readable claims, so Busbar cannot establish that it was minted for Busbar. The honest answer to "I cannot tell" on a confused-deputy defence is refusal (`crates/busbar-kernel/src/auth/audience.rs`). Until token introspection exists, an IdP that issues opaque tokens cannot serve this plane — and you find that out from a clear refusal rather than from an audience check that silently was not happening.

If you do not have an IdP you can register clients in, the separate **`oauth_as:` block** makes Busbar an authorization server as well, serving pre-registration, Client ID Metadata Documents and dynamic client registration, and issuing RFC 9068 `at+jwt` access tokens whose `aud` is one of Busbar's own protected resources (`crates/busbar-kernel/src/oauth_as/`). That is a different plane with its own configuration and is out of scope here.

### The audience check

This is the load-bearing one, and it is the difference between a gateway and an open relay. Without it, a token an agent legitimately obtained for some *other* resource — a token your IdP happily issued, for a service that has nothing to do with Busbar — is spendable here against Busbar's pools, budget and upstream credentials.

Busbar compares the token's `aud` for **equality** against `mcp.canonical_uri`, and refuses anything else including a token that carries no audience at all. Never prefix, never suffix, never case-insensitively: a resource indicator is an opaque identifier, and treating it as a namespace is how `https://gw.example.com/mcp` starts admitting tokens minted for `https://gw.example.com/mcp-staging` (`crates/busbar-kernel/src/plane/mod.rs`, `crates/busbar-kernel/src/auth/audience.rs`). RFC 7519's single-string and array forms of `aud` are both accepted.

The check lives beside the **mount**, not in a handler, so every path behind that door inherits it and a route added later cannot forget it (`crates/busbar-kernel/src/plane/mod.rs`). For a token Busbar did not mint, core makes its own determination *before* the auth chain runs, and only ever to refuse: an unverified `aud` read is sound here precisely because the result can only narrow what is admitted, never widen it (`crates/busbar-kernel/src/auth/audience.rs`).

`canonical_uri` is operator-configured rather than derived from the request's `Host`. Deriving it from the request would let a caller choose its own audience by sending a header, which turns the defence into a formality.

### `Origin` and DNS rebinding

`2026-07-28` makes `Origin` validation a MUST. Busbar refuses a request carrying an `Origin` that is not in `mcp.allowed_origins` with `403`; a request carrying no `Origin` — which is every non-browser client — is unaffected, and loopback is admitted unconditionally by the shared rule (`endpoint.rs`, `door.rs`). The threat is a page on an attacker's origin resolving a name to Busbar's loopback address and driving the tool plane with the user's ambient credentials.

---

## What a caller can see and call

**Which tools a caller can see is decided by the caller's key scopes and by nothing else.** There is no hook on the catalogue path, no filter verb, no tag convention (`catalogue.rs`). Two scope kinds gate this plane (`door.rs`):

| Scope kind | Grants | Named as |
|---|---|---|
| `mcp_server` | may this caller reach this upstream at all | the `tools:` registration id |
| `mcp_tool` | may it reach this capability | the **published wire name** — `<server>_<tool>` by default, or the `publish_as:` override |

**Both must pass, for every capability** — a tool, a prompt, a resource and a template alike. A key scoped to one tool on a server must not acquire the rest by having been let through the door (`catalogue.rs`).

```yaml
# on the virtual key
allowed_scopes:
  - { kind: mcp_server, value: acme }
  - { kind: mcp_tool,   value: acme_search_code }
```

### Listed and served are two different answers

The **listing** (`tools/list`, `prompts/list`, `resources/list`, `resources/templates/list`) asks the two grants, and deliberately not the approval: a tool with no approved hash is *listed*, so the approval queue is visible. Only a tool whose server's live sighting is quarantined is hidden, and that verdict is asked after the grants, never in place of them (`catalogue.rs`). What a listed but unapproved tool does not get is a dispatch.

The **dispatch** (`tools/call`) is admitted in order — the name and its length (at most 256 bytes), the tool, the grants, the kernel's trust verdict, the mirrored headers, the tasks gate and the answers to Busbar's own asks — and then the call's arguments are judged by the argument guard (`call.rs`). It refuses a call with:

| Meaning | Status | Audit reason |
|---|---|---|
| no such published name, or an item the kernel never sighted | `404` | `unknown_tool` |
| this caller is not granted the server or the tool. **Rendered with the same words as an unknown tool** — a caller learns only that there is nothing there for it | `404` | `not_granted` |
| registered, but no schema hash approved: pending | `403` | `not_approved` |
| the server has not been verified yet | `403` | `pending` |
| the upstream offers an approved tool at a different digest, or the server is quarantined | `403` | `quarantined` |
| any other distrust | `403` | `not_serving` |
| an argument names a URL or host the argument guard refuses (`argguard.rs`) | `403`, `-32000` | `tool_argument_refused` |

A server the live re-fetch could not reach is not a refusal: the call fails as an upstream failure, a tool error naming why Busbar could not verify it (`upstream_failed`). A quarantine is `403` and not `404` on purpose: the tool exists and this caller may see it — what changed is the upstream.

The catalogue is built once per config generation from that generation's `tools:` section, so an approval is visible from the generation that carries it and from no earlier one (`catalogue.rs`, `tool_door.rs`).

### Routing binds identity, never description

A catalogue entry is keyed on `(server-id, published name, schema-hash)`. The description is the **operator's**, carried for display, markup-normalised on the way out, and never an input to a routing decision (`tools_config.rs`, `catalogue.rs`). Publishing the operator's text rather than the upstream's is what keeps an upstream from rewriting the instructions a model reads. `outputSchema` follows the same rule: it is the operator's approved schema, published as approved. Busbar does not validate an upstream's `structuredContent` against it or replace a result that does not match; the upstream's result reaches the caller as it came, and the caller judges it (THE DESIGN Law 11).

Descriptions, prompt templates and resource contents (the text Busbar serves from its own section) are markup-normalised: `<IMPORTANT>`, `<system>` and HTML-like tags are stripped before the text re-enters model context (`sanitize.rs`). A tool's result is not: it is the upstream's data and reaches the caller as the upstream sent it (THE DESIGN Law 11); markup policy on results is a response-rewrite hook. **This is a floor, not a claim that injection is handled.** "now call `transfer_funds`" carries no markup and survives unchanged, by design — there is nothing to strip. Semantic injection is a hook residual and a model-alignment problem; Busbar reduces the markup-shaped attack surface of its own text.

---

## Transports

A transport is not a wire format. Every MCP transport carries the same JSON-RPC 2.0 message shape, which is why the plane needs no superset IR.

### Inbound: streamable HTTP

MCP is one dialect with dated revisions, and the plane speaks four of them, inbound and outbound (`revision.rs`, in GetBusbar/busbar-plane-mcp):

| Revision | Opened by | Sessions | `MCP-Protocol-Version` header | Carried as |
|---|---|---|---|---|
| `2026-07-28` | nothing: every request is whole | none | required | `POST /mcp` only |
| `2025-11-25` | `initialize` | yes | required | `POST /mcp`, plus the session's `GET` stream and `DELETE` |
| `2025-06-18` | `initialize` | yes | required | `POST /mcp`, plus the session's `GET` stream and `DELETE` |
| `2024-11-05` | `initialize` | yes | none | an event stream (`GET /mcp`) whose first event names the address messages are POSTed to |

`2025-03-26` is not implemented: it is the only revision that allows batched bodies, and a client that asks for it in `initialize` is answered with `2025-11-25`, the latest session revision, which the spec's negotiation rule permits. A client naming a session revision Busbar implements gets that revision back. Session streams of `2025-11-25` and `2025-06-18` resume after `Last-Event-ID`.

**The stateless revision (`2026-07-28`, SEP-2243/SEP-2575):**

- **No `initialize` handshake and no protocol session.** Every request is self-describing, carrying its protocol version and the client's capabilities in `params._meta`.
- **The server-to-client channel is a method**: `subscriptions/listen` is an ordinary POST whose response is a long-lived stream of notifications (`subscribe.rs`). A principal admitted through `auth.role_bindings` keeps its subscription for as long as a binding still grants it: removing the binding, or narrowing it to no pools, ends the stream with `identity_not_live` on the next frame, and a changed pool or group applies from that frame on.
- **`Mcp-Method` mirrors the body's `method` on every request**, and `Mcp-Name` mirrors the target name on `tools/call`, `resources/read` and `prompts/get`. Both are required. A header that disagrees with the body is `400` with `-32020`, because a proxy routing on the header while the server executes the body is a request-smuggling primitive.
- **`MCP-Protocol-Version` must equal the body `_meta` protocol version** — same `-32020` on mismatch. A `_meta` that is absent or incomplete is a *different* failure and answers `-32602` with `400`: that is a defect in the request's own params, not two readings of one request disagreeing.

An unsupported protocol version answers `-32022`.

**The session revisions:** sessions are bound to the caller's key and bounded per owner in count and bytes (`door_sessions.rs`, `tool_sessions.rs`). A session request whose `MCP-Protocol-Version` disagrees with its session's revision is `400`. On an ungoverned chain every caller is one owner, so a session isolates nothing; the first `2024-11-05` stream on such an instance reports that once, as a warning.

### Inbound: `busbar --mcp-stdio`

For an MCP host that runs Busbar as a child process (Claude Desktop-class), `busbar --mcp-stdio` serves the MCP plane on Busbar's own stdin and stdout, newline-delimited JSON-RPC, and **binds no listener at all** — a child that opened ports would be a network server its supervisor never asked for. The plane states the flag (`tool_meta.rs`); the root serves the plane's line-carrier claim on the process's own stdin and stdout (`crates/busbar/src/main.rs`, `crates/busbar/src/root/serve.rs`), and each line is its own unit (`line.rs`, `door_line.rs`).

The **same boot** runs: config load, plugin preflight, governance and the flusher. Every line read from stdin is fed to the same serve sequence the HTTP endpoint runs, with the same envelope rules and the same dispatch, so a request the HTTP plane would refuse is refused here with the same code and the same sentence (`line.rs`). The mirrored routing headers are synthesised from the body — a pipe has no header block and no intermediary — so a body defect stays a body defect rather than being converted into a header defect.

**Governance is bound once, at boot, for the whole session.** A stdio caller presents no per-request bearer, so `BUSBAR_MCP_STDIO_CREDENTIAL` carries the same credential the HTTP plane accepts, judged by the same sequence: the RFC 8707 audience pre-filter against `mcp.canonical_uri`, then the configured auth chain, then the one identity resolution the HTTP middleware itself calls (end to end in `crates/busbar/tests/mcp_stdio_serve.rs`). A credential the HTTP door would refuse is refused here; one it would admit binds the session to the same principal, the same budgets, the same audit attribution and the same hooks. **A configured chain with no credential, or a refused one, is a refusal to serve** — nonzero exit, a sentence on stderr — exactly as the HTTP door answers `401`.

The credential rides an environment variable and not a flag, because argv is world-readable on most platforms and an MCP host's `env` block already has exactly this shape.

The identity is **frozen for the life of the session**: a key revoked mid-session keeps being honoured until the process ends. The party able to end the session is the party that started it, and killing the child *is* the revocation — which no network peer can say of an HTTP stream.

Because stdout is the MCP channel, logging goes to stderr in this mode (`crates/busbar/src/main.rs`).

`--mcp-stdio` requires the `mcp:` block. Two live asks and one round cap are transport-local belts: a 30-second timeout on one live ask, and a cap of 8 live MRTR rounds per request on top of the operator's own `max_caller_ask_rounds` (`line.rs`).

### Outbound: `transport: streamable_http`

The default, and the only network transport. The leg carries a credential selected under the **inbound caller's** grant. Busbar sends an upstream the stateless `2026-07-28` request first; only when the upstream refuses it does the client open a session with `initialize` (latest session revision first), and an upstream that refuses `initialize` too is reached on the `2024-11-05` event stream. An upstream that answers in the stateless revision is remembered as such and never renegotiated (`revision.rs`, `client/negotiate.rs`, `door_sessions.rs`, `door_legacy.rs`).

### Outbound: `transport: stdio`

Busbar spawns a local MCP server that has no URL — a filesystem, database or git server. The SSRF guard is the defence on the HTTP wire and has nothing to say about a child process, so `validate_endpoint` stands in its place, at boot, where the operator who wrote it is standing (`tools_config.rs`). The spawn itself is the host's (`crates/busbar-core-connector/src/hostio.rs`, `crates/busbar-core-connector/src/program.rs`). Four decisions, each fail-closed:

1. **No shell, ever.** The program goes to `Command::new` and the arguments through `.args()`. There is no `sh -c`, no string split on spaces, and therefore no metacharacter with meaning. An operator who wants a shell writes `/bin/sh` as the program.
2. **The program is an absolute path**, refused at boot otherwise. A bare name is resolved through `PATH`, which would make the binary that actually runs a property of the environment Busbar was started in rather than of the file you wrote.
3. **The environment is not inherited.** `env_clear()` runs first and only the named `env:` entries are put back. Busbar's own process environment holds provider API keys, store credentials and admin tokens; handing that set to an operator-configured child would make every stdio registration a credential-exfiltration primitive, silently. A value that is itself a secret is written as a secret reference. It is **resolved when the registration loads** (boot, and every config apply) and held in Busbar's own records, never in the config snapshot. A spawn — the first tool call, or a restart after the child exits — uses the held value and resolves nothing, because a secret source can block for its whole deadline and a spawn is serving a request. Busbar re-resolves held values off the request path every 60 seconds; this interval is fixed and there is no setting for it. **A rotated secret reaches the first NEW child after the next refresh**, so at most 60 seconds after the rotation, or at the next config apply. A running child keeps the environment it was spawned with. A reference that stops resolving at a refresh refuses every spawn after it; Busbar never hands a child a stale value (`crates/busbar-core-connector/src/spawn_env.rs`).
4. **The arguments come from config only.** Nothing on the dispatch path can add to, reorder or substitute into them — a tool call's `arguments` reach the child as JSON on its stdin, which is data, and never as argv.

> **Windows operators must name more variables than unix ones, and the reason is the OS.** On unix an empty environment is a working environment. On Windows the process environment is load-bearing for the platform itself (`SystemRoot`, `windir` during DLL resolution and Winsock init) and interpreter-based children want `PATH`, `TEMP`/`TMP` and often `APPDATA`. An `env_clear()`ed child on Windows can fail to start, or start and fail on its first socket. The posture is not relaxed — it is the same secret on both platforms — so a Windows `env:` block is explicit about the platform variables the child needs. This is reasoned rather than observed; see the note in [operations.md](/docs/operations/).

**The child is long-lived, not a fire-and-forget spawn.** One child runs per registration; it is spawned on the first call that needs it, and every later call leases the same running process, its messages correlated by JSON-RPC id. Each spawn is a new *generation*, and the plane runs the MCP `initialize` handshake once per generation before it sends that child a call. A child that ends ends every call leased on it, and the next call spawns it anew. A registration that is removed or whose program changes takes no new lease, and its child is killed once its last lease closes (`crates/busbar-core-connector/src/program.rs`; `tool_program.rs`, `door_program.rs`).

**The restart policy is a circuit breaker, not a retry loop.** A child that crashes on startup will crash on every startup, so an unbounded restart loop against a broken binary is a fork bomb with a config file behind it. Exponential backoff from the crash count, capped, and a trip that stops restarting entirely past a threshold inside a window, until the registration is declared anew. The supervisor is the stdio transport's (`supervisor.rs`, in GetBusbar/busbar-transport-stdio):

| Knob | Value | Configurable |
|---|---|---|
| first backoff after a crash | 100 ms | no |
| backoff ceiling | 30 s | no |
| ends that stop the restarts | 5 | no |
| the window they are counted over | 60 s | no |

A successful start **does not clear the crash history** — a child that crashes, restarts, serves one call and crashes again is crash-looping, and clearing the window on every successful start is how a breaker is written that never trips. The history ages out by time. The supervisor outlives the child, deliberately: it is keyed by the registration's supervision key, which the host keeps while the registration's program is unchanged across config applies, so supervision resets only when the registration is new — never for a sibling registration running the same program, and never for a changed secret value under an unchanged registration (`supervisor.rs`, in GetBusbar/busbar-transport-stdio).

Defaults are chosen to make a crash-looping child visible within seconds rather than to maximise availability: an MCP server that will not start is a configuration error, and hiding it behind retries delays the fix.

---

## The trust lifecycle: pins, hashes, drift and quarantine

Tool identity on this plane is `(server, tool, schema-hash)`. Two things have to be approved before a tool serves: the server's **pin** (its authenticity root) and the tool's **schema hash**.

A registration with no authenticity root (`pin.mechanism: unpinned`) is registrable and **approves nothing**: the approval is an authenticity root plus, per tool, the approved digest, and a registration with no root has no approval to match (`trust.rs`). A tool with an empty `tools_allow` value object is `pending` and does not dispatch.

**The rug-pull defence needs a live observation, and verify-on-call supplies it on the call path.** Comparing an approved digest against the digest the operator wrote in config is comparing intent with itself and is structurally incapable of noticing an upstream changing its schema underneath (`trust.rs`). So on each `tools/call`, before the trust gate, Busbar re-fetches the server's live tool list if its last fetch is older than `verify_ttl` (a `transport: stdio` server's list is fetched from its own child) and re-hashes each tool **from the definition the upstream sent** — name, description and input schema — never adopting a digest the upstream supplied, which would be the rug-pull with an extra step (`tool_door.rs`, `trust.rs`). The sighting is stamped on the kernel's trust book, and the kernel's verdict decides the call (`crates/busbar-kernel/src/trust/`). A fetch that fails is the `error` state, which serves nothing: the call is not dispatched and fails as an upstream failure (**fail-closed**). The full model is in [Tool and agent trust](/docs/tool-and-agent-trust/).

The plane runs no background re-fetch: a stale server is re-verified on the call that names it, and within `verify_ttl` the last sighting is reused. `verify_ttl` (default `5s`, `0` = every call) is the per-server knob — there is deliberately no key that delays a quarantine, and no per-server "skip if it failed last time", either of which would be a window an upstream could open for itself by misbehaving.

**A quarantine survives a restart.** What is written to the store is not "this server is quarantined" but "a live observation of this server disagreed with the approval, at this time" — an observation replayed at boot, with the derivation running unchanged on top of it. The demotion rows are host-held records and the trust state they feed is the kernel's (`tool_records.rs`, `crates/busbar-kernel/src/trust/demotion.rs`). A server with no record replays as nothing at all and falls back to the declarative approval, exactly as before: the absence of a row is not a demotion. The record is cleared by the first observation that agrees with the approval again — the record is written on the call path, so the first call after a fix clears it. A restart does not silently re-open it: `tools/list` does not itself re-verify, so the persisted demotion keeps a drifted tool un-advertised until an operator works it.

> **Stated gap.** Drift has two axes and the fetch path observes one of them. The **capability** axis (digests over name, description and input schema) is fully observed. The **identity** axis is not: an MCP hop through the host connector presents no certificate key the plane could compare a `cert_spki`/`mtls` pin against, so the trust view reports `pin_changed: false` and a certificate rotation is invisible to it (`trust.rs`).

### Operator surfaces

| Route | Scope | What it does |
|---|---|---|
| `POST /api/v1/admin/tools/{name}/connect` | mutation | **Reaches the network.** Fetches the upstream's live tool list, re-hashes it, records the observation, and audits whatever it found. It does **not** approve anything — adopting what was seen is a separate, explicit act, precisely so a poisoned capability list cannot be adopted by the same call that fetched it. |
| `GET /api/v1/admin/tools/{name}/changes` | read | The trust view, computed from the last observation. Contacts nothing; safe to poll. |
| `GET /api/v1/admin/tools/{name}/health` | read | Can Busbar use this server right now, and if not, why. Contacts nothing. |

The plane states these verbs and their OpenAPI fragment (`door.rs`, `ADMIN_OPENAPI`); the admin API mounts them (`crates/busbar-core-admin/src/v1/json/mod.rs`) and the shared sequence is `crates/busbar-core-admin/src/planeverbs.rs`. `connect` is audited; the two reads are not. A registration missing from either the catalogue or config answers the same `404` — two answers a caller could tell apart would be an existence oracle.

**There is no `/tools/{name}/approve` verb.** Approval on this plane is the definition itself: write the observed digest into `tools_allow.<tool>.schema_hash` in config, or `PUT` the definition through the generic `tools` section CRUD. (The A2A plane has an `approve` verb because a card fingerprint has no config slot the operator fills in advance.)

---

## What a tripped upstream returns

The circuit breaker runs on all three planes. There is one FSM and no second state machine: an MCP tool server is a cell on the same breaker a model lane sits on, keyed `tool:<server-id>` (`crates/busbar-kernel/src/store/vocab.rs`). Closed → Open → HalfOpen, the same two-stage disposition pipeline, the same exponential cooldown, the same single-flight half-open recovery probe. See [circuit-breaker.md](/docs/circuit-breaker/) for the state machine itself.

**The breaker is consulted before any socket.** The plane states the called server as its unit's route, and the kernel's plane driver walks that route through the breaker cells before every attempt — the same walk the LLM plane's lanes take (`crates/busbar-kernel/src/plane_driver/far_end.rs`). A tripped server is a refusal the caller sees now, not a dispatch.

A tripped server answers:

- HTTP **`503 Service Unavailable`**
- a **`Retry-After`** header, in seconds, populated from the cell's own remaining cooldown — an exact number rather than a guess
- a JSON-RPC **error** with code **`-32030`**, and structured `data`:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32030,
    "message": "MCP server `acme` is unavailable: its circuit breaker is open after repeated failures; busbar did not dispatch this call. Retry after 12s.",
    "data": { "reason": "upstream_unavailable", "server": "acme", "retry_after_ms": 12000 }
  }
}
```

(`tool_door.rs`.) When the call *was* dispatched and the server did not answer within its `timeout:`, the same `503` and `-32030` say so instead: "it did not answer this call within the server's timeout; busbar dispatched it and stopped waiting".

**It is an error, never a tool result with `isError: true`.** MCP's `isError` means *the tool ran and it failed*. A tripped breaker means *the call never happened*. Returning the second as the first tells the calling model that a tool executed and reported a failure, and the model then reasons from a lie and may report that false result onward as fact. `-32030` sits in JSON-RPC 2.0 §5.1's implementation-defined `-32000..-32099` band because each reserved code is wrong for a specific reason: `-32603` says Busbar broke (it did not), `-32601` says the tool does not exist (it does), `-32602` blames the caller (`codec.rs`).

**These cells refuse on a trip and nothing less.** The plane declares `bench_below_trip_threshold: false` in its `declares.json` breaker fact — the one field it does not take from the LLM defaults (`crates/busbar-kernel-breaker/src/cfg.rs`). On an LLM pool, a sub-threshold failure arms a short cooldown meaning "prefer a sibling for a while", and failover is what keeps the caller served while it lasts. On a single MCP registration with no pool there is no sibling, so the same cooldown would mean "refuse *every* caller of this server for the next 15–120 seconds" after one transient blip, on a cell whose own trip predicate had just declined to trip. So the predicate is the published one and nothing weaker: **error rate ≥ 0.5 over at least 5 outcomes in a 30-second window**, cooldown 15 s escalating to 120 s (`crates/busbar-kernel-breaker/src/cfg.rs`). An upstream's own `Retry-After` is still honoured, for as long as the upstream asked for — that is the upstream's backpressure, not Busbar inventing an outage.

**A tripped server that is a member of a `tools.pools` failover pool is not what produces the `503` above.** The walk runs before any refusal is composed and tries the next member whose approved digest matches the primary's (`tool_door.rs`); the caller gets that member's answer. The `503` is what remains when the walk found no member its breaker admits, with the `Retry-After` the kernel's walk reports (`tool_door.rs`). An unpooled registration has no twin to select, so for it the `503` is the whole story.

**Timeouts are a bound the upstream cannot lengthen by choosing to be slow.** `timeout:` is per server, default 30 s, and there is deliberately no spelling for "unlimited": a leg that cannot time out holds a concurrency slot for as long as the upstream chooses. A registration that writes no `timeout:` is held to the 30 s default by the kernel's walk itself, the same bound a written one sets (`crates/busbar/src/root/door_steps.rs`, `DoorPools`); a call it cuts is answered with the `503`/`-32030` above, in words that say the call was dispatched and the server's timeout ran out. The 30 s default is the tool plane's alone: a registration on another plane, such as an A2A agent, that writes no `timeout:` is bounded by its pool's whole budget (120 s by default), not 30 s.

### Other refusals on this plane

| Code | Status | When |
|---|---|---|
| `-32000` | varies | A governance refusal: well-formed request, method exists, server declined by policy (`codec.rs`). |
| `-32020` | `400` | A mirrored routing header disagrees with the body (`codec.rs`, `checks.rs`). |
| `-32021` | `400` | The caller did not declare a client capability a `task_support: required` tool needs; `data.requiredCapabilities` names it. The status is fixed by the spec, not chosen (`call.rs`). |
| `-32022` | `400` | Unsupported protocol version; `data` carries `requested` and `supported` (`checks.rs`). |
| `-32030` | `503` | The upstream's breaker is open. |
| `-32601` | `404` | Unknown method — never a `200` carrying an error object. |
| `-32602` | `400` | Structurally wrong params, including an absent or incomplete `params._meta`. |

---

## Observability

The MCP plane emits on **its own pair of request families** — `busbar_plane_requests_total` and `busbar_plane_request_duration_seconds`, which carry a `plane` label — from a layer on the mount rather than a call in the handler (`crates/busbar-kernel/src/ingress/observe.rs`). These are kept separate from the model plane's `busbar_requests_total` / `busbar_request_duration_seconds` precisely so those stay byte-identical to 1.5.4 (no `plane` label).

| Metric | Type | Labels | On this plane |
|---|---|---|---|
| `busbar_plane_requests_total` | counter | `plane`, `ingress_protocol`, `pool`, `outcome` | `plane="mcp"`, `ingress_protocol="jsonrpc"`, `pool="unresolved"` |
| `busbar_plane_request_duration_seconds` | histogram | `plane`, `ingress_protocol`, `pool` | same |

`pool` reads `unresolved` because the door counts the request **before** its routing target is resolved, and handing the door a caller-supplied tool name would be an unbounded label — one valid credential could mint a new time series per distinct tool name, which is the memory-exhaustion DoS the sentinel exists to close (`crates/busbar-kernel/src/ingress/observe.rs`). Narrowing it to the configured server name is future work and belongs where the target is resolved.

`sum by (plane) (rate(busbar_plane_requests_total[5m]))` answers "which mounted plane is this traffic on". Existing model-plane panels over `busbar_requests_total` keep working unchanged; to span all planes in one query, sum `busbar_requests_total` and `busbar_plane_requests_total` together.

**A refusal issued before any handler runs is counted too.** The audience-bound `401`, an oversized-body `413`, a `404` — all of them reach no handler, and counting them here is the case an operator most needs to see and the one a handler-level emit could never reach (`crates/busbar-kernel/src/ingress/observe.rs`).

The client leg lands on the shared upstream families, which are emitted on every plane rather than only the model one (`crates/busbar-kernel/src/telemetry.rs`): `busbar_upstream_attempts_total{pool,lane}`, `busbar_upstream_failures_total{pool,lane,disposition}`. Both labels are operator-configured and therefore bounded.

**There is no `operation` metric label, on this plane or any other.** `OpShape::as_str()` — `invoke`, `catalogue`, `fetch`, `task`, `subscribe`, `control` — is a closed internal vocabulary describing the *shape* of an exchange (`crates/busbar-contract/src/operation.rs`). `Operation::name()` is a different thing: the word the wire calls a verb (`crates/busbar-contract/src/operation.rs`). No metric family carries either (`crates/busbar-kernel/src/telemetry.rs`). See [observability.md](/docs/observability/) for the full metric table.

Metrics are opt-in: with no `module: prometheus` instance under `export:`, Busbar installs no recorder and mounts no `/metrics`.

---

## Governance

Everything a model-plane request already got applies to a tool call unchanged.

**Budgets and metering.** A tool call is admitted against the caller's key through the same kernel admission the LLM path uses, so a tool call and a model call land in the same budget window; a budget refusal names the budget and carries `Retry-After` (`tool_door.rs`). The plane reports and the kernel writes: the plane declares two meter classes, `tool_calls` (flat, one per answered call) and `bytes` (the length of the answer), and reports them once a server has answered a relayed `tools/call`. A call whose upstream never answered reports neither class, because nothing was measured (`tool_meta.rs`). Governance disabled ⇒ no key, no budget, nothing charged — the same posture the LLM path takes.

**Hooks.** `tools.hooks:` ∪ `tools.<server>.hooks:` attach to the **dispatch** path — never the catalogue. What a caller may *see* is decided by grants and nothing else; a hook decides what a caller may *do*. A hook sees a `tools/call` as one turn of tool arguments (the `{tool, arguments}` body, and for a content-granted hook the arguments as a `user` turn); a request-stage rewrite is applied before the call is projected, and a veto is answered with reason `hook_rejected` and the name of the hook that vetoed it (`tool_door.rs`).

**Audit.** Refusals and outcomes are audited through the one core chain; the plane's audit resource kind is `mcp_server` and its action words are prefixed with it (`door.rs`).

**The per-call log.** Every inbound `tools/call` terminal is written as one hash-chained record, per caller, as a host-held record the plane appends and reads back through the host's record seam (`tool_records.rs`, `record.rs`). It is deliberately **not** the admin audit ring: an admin mutation is operator-rate and a tool call is request-rate, and sharing one bounded ring means a busy afternoon of tool calls evicts every admin row from it — silently, because a ring that pruned looks identical to a ring that was never written to.

What is written: every `tools/call` terminal — the dispatched result, every refusal (admission, dispatch-time re-validation, header mismatch, the tasks gate, the caller-ask gate, the budget, the egress gate, the upstream's own refusal), and the creation of an asynchronous task. What is **not** written: `prompts/get` and `resources/read` (the record's `tool` field is the tool routing key, and inventing a value for a prompt would put a name there no `mcp_tool:` grant can name); the round structure of a multi-round exchange (one inbound request, one record); and the task's own later upstream leg (`tool_records.rs`).

The claim is **tamper-evidence, not tamper-prevention.** A chain detects an altered, reordered, inserted or removed record after the fact; it does not stop one, and a host compromised at the moment of writing can rewrite a whole chain consistently and it will verify. Prevention means shipping the records off-box. A chain break is *reported*, never repaired by deleting the record — deleting a record whose chain does not verify would turn a detection control into a deletion primitive.

**Upstream credentials are bound to the inbound caller.** The plane never holds the outbound credential: it names the scheme, and the kernel's auth binding adds the credential when it sends, under the *inbound* caller's grant — that binding is the confused-deputy defence for the client direction (`call.rs`, `tool_records.rs`). A `passthrough` registration is lent the caller's own credential. The RFC 8693 exchange asks for a scope **derived, never configured** (`tool_scope.rs`) — a configured static list would be a second place the authority is written down.

**An upstream's ask is relayed to the caller; Busbar answers nothing on the caller's behalf.** A server-initiated ask arrives as an `input_required` result of a call Busbar made. `grants.{sampling,elicitation,roots}` decides whether that server may put the ask to your callers at all — every kind the ask names must be granted, or the call is refused (`ask_ungranted`). A granted ask reaches the caller with the upstream's `inputRequests` exactly as sent, under Busbar's own sealed `requestState`, which nests the upstream's state and binds it to that caller, that call (tool and arguments) and the server that asked. The caller's retry is a new request with its own admission: the state is checked and spent once, the call goes back to that same server and no other, and the caller's `inputResponses` and the upstream's own state are handed to it verbatim. Busbar only declares a capability upstream that both the grant and the caller declare. A result that still carries an ask after the relay decision is refused (`ask_not_proxied`). Busbar's own `ask_caller:` rounds are resolved first, as before (`call.rs`, `ask.rs`).

The same rule holds where there is no request waiting to carry the ask back. **Inside a task** (SEP-2663), an upstream's ask parks the task `input_required` with the upstream's `inputRequests` verbatim, under Busbar's sealed state (bound to the caller, the tool and the server that asked, nesting the upstream's own); `tasks/get` shows the asks and `tasks/update` answers them. Once every key is answered the task continues as a new unit: the call goes back to that same server with the caller's answers and the upstream's state, verbatim, and the state is spent once. The answers never become tool arguments (`door_tasks.rs`). **From a `transport: stdio` child**, a `sampling/createMessage`, `elicitation/create` or `roots/list` request the child sends while it serves a call goes to the caller of that call: across HTTP it comes back as an `input_required` result whose `inputRequests` carry the child's requests verbatim (keyed by the child's request ids), correlated with a work handle; on `busbar --mcp-stdio` it is sent to the caller as a live request on the pipe. The caller's answer is written to the child under the child's own request id, and the call the child still owes is read on. A retry must answer every request the child made (`ask_unanswered` otherwise, and the state stays unspent); a spent or forged state is refused. A request over stdio names no call it serves, so calls to a stdio server that holds any of these grants reach its child ONE AT A TIME, in arrival order: a call waits its turn behind the one the child is serving (within its own `timeout:`; past it, it is answered as an upstream failure and never sent), and a call whose ask went to its caller keeps its place until the caller's retry or the ask's state lapses. The child's ask is the caller's of the call it is serving, never another's; one raised while no call is open is refused on the child's input with `-32001` (`ask_unattributed`). An ungranted ask is refused on the child's input with `-32001` (`ask_ungranted`), as is one past `max_input_required_rounds`; `ping` is still answered by Busbar, because it is keepalive, not an ask (`client/peer.rs`, `door_program.rs`).

---

## Conformance

Busbar's MCP conformance is checked by two batteries, both driven from this repository by `scripts/mcp-conformance.sh`:

- the **official suite** at a pinned version, against a pinned third-party SDK (the control leg) and against a Busbar binary built from the commit under test (the subject leg);
- an **in-house adversarial/seam battery** in `testing/mcp-conformance/`, likewise control and subject.

Two rules make the numbers mean something. **Control legs run always** — a battery that cannot judge a known-good third-party peer cannot be trusted to judge Busbar, and a red control is a finding about the harness, never about Busbar. **Subject legs are armed or red** — a disarmed subject leg proves the suite works and proves nothing about Busbar, and it renders as the same green tick as a leg that judged Busbar and passed, so "not armed, so not run" is a failure. Once armed, a run producing fewer than the revision's full required scenario set fails: set equality, never a floor, because a floor of 30 is satisfied by any 30 of 37. No workflow under `.github/workflows/` invokes the script on `dev`; run it yourself.

To run it, arm the subject leg with `MCP_SUBJECT_BUSBAR_BIN` pointing at a binary built from your tree and invoke `scripts/mcp-conformance.sh --official-subject` or `--battery-subject` (`--official-control` and `--battery-control` run the control legs); `--selftest` proves the anti-vacuity assertions still bite before any verdict is trusted. The plane's own repository also runs a plugin conformance test (`plane-mcp-plugin/tests/conformance.rs`, in GetBusbar/busbar-plane-mcp).
