# MCP

Busbar is an MCP server, and a governed gateway in front of the MCP tool servers you already run. An agent connects to Busbar exactly as it connects to any OAuth 2.1 protected resource: with no credential first, which earns a `401` carrying the discovery document's URL; it follows that to your identity provider, comes back with a token, and from there every tool call rides the machinery a model request already rides — the caller's key, its grants, its budget, hooks, the audit chain, and the circuit breaker.

This page is the operator's reference for the plane: what a deployment gets by turning it on, the complete configuration grammar and every boot refusal, how identity is established, how a caller's grants decide what it can see and call, the two transports, what a tripped upstream returns, and what the plane emits.

Cross-references: [Circuit breaker](/docs/circuit-breaker/) (the one FSM, on all three planes) · [Configuration](/docs/configuration/) (field reference) · [Observability](/docs/observability/) (the metric families) · [Hooks](/docs/hooks/) (attaching your own logic) · [Operations](/docs/operations/) (running it).

---

## What the plane is

Busbar sits on both sides of MCP at once, and the two directions are configured by two different sections.

**Busbar as the MCP server** is the `mcp:` block. Its presence mounts an MCP endpoint, an RFC 9728 protected-resource metadata document, and nothing else. Busbar answers `server/discover`, `tools/list`, `tools/call`, `prompts/list`, `prompts/get`, `resources/list`, `resources/templates/list`, `resources/read`, `completion/complete`, the SEP-2663 task methods (`tasks/get`, `tasks/update`, `tasks/cancel`) and `subscriptions/listen` (`crates/busbar-core/src/mcp/method.rs:67-89`). Anything else answers `404` with JSON-RPC `-32601`.

**Busbar as an MCP client** is the `tools:` section. Each entry registers one upstream tool server: where it is, what authenticity root it is pinned to, which of its tools you have approved, and what credential Busbar spends to reach it.

The two are independent. `mcp:` with no `tools:` is a correctly configured MCP server with an empty catalogue. `tools:` with no `mcp:` registers upstreams that nothing inbound can reach — no route is mounted, so nothing can call them over MCP.

### A deployment with no `mcp:` block gains nothing

This is a property of the boot path rather than a claim about defaults. `App::planes` mounts the MCP plane only when `cfg.mcp` is `Some` (`crates/busbar-core/src/appbuild.rs:1460-1468`), and the router mounts the two MCP paths inside `match mcp { None => router, Some(resource) => … }` (`crates/busbar-core/src/router.rs:430-469`). With no `mcp:`:

- no ingress route and no metadata route exist in the route table, so a `POST /mcp` is an ordinary unclaimed path that falls through to the residual LLM plane;
- `PlaneDispatch` claims no path for MCP, so `admission_for` answers `None` and the RFC 8707 audience check costs one `Option` test;
- nothing inbound can reach a `tools:` registration, because nothing inbound is mounted.

**One thing an absent `mcp:` block does NOT switch off: the outbound sweep.** The tool-list refresh job is keyed on the *registry*, not on the plane. `spawn_refresh_job` returns `None` only when the catalogue is empty (`crates/busbar-core/src/mcp/connect.rs:708-710`), the catalogue is built unconditionally from `tools:` (`crates/busbar-core/src/appbuild.rs:1500`), and the spawn is unconditional (`crates/busbar/src/main.rs:922`). So a deployment that writes `tools:` and no `mcp:` block still reaches those upstreams on their `refresh_ttl:` — outbound, and on the sweep's own clock. If you want no traffic to a registration at all, remove the registration; an absent `mcp:` block only closes the door in one direction.

A plane exists because it is configured, not because its name appears in a path (`crates/busbar-core/src/plane/mod.rs:505-509`).

---

## Configuration

### The `mcp:` block

`deny_unknown_fields`: a typo'd key fails boot (`crates/busbar-core/src/mcp/mod.rs:221`).

| Key | Type | Required | Default | What it is |
|---|---|---|---|---|
| `canonical_uri` | string | **yes** | — | The RFC 8707 resource indicator: the absolute URI naming this deployment's MCP endpoint. It is the exact `aud` every inbound token must carry, **and** the path the endpoint mounts at. |
| `authorization_servers` | list of strings | **yes**, non-empty | `[]` (refused) | RFC 9728 `authorization_servers`: the issuer identifiers permitted to mint tokens for this resource. This list is the entire content of the answer a credential-less client came for. |
| `scopes_supported` | list of strings | no | `[]` | RFC 9728 `scopes_supported`. **Advisory metadata only** — authorization is decided by the caller's grant, never by this list (`crates/busbar-core/src/mcp/mod.rs:240-243`). |
| `allowed_origins` | list of strings | no | `[]` | Browser origins accepted on the ingress, for the `2026-07-28` `Origin` MUST. Empty means no browser origin is accepted; a request carrying no `Origin` (every non-browser client) is unaffected. |

The **mount path is derived** from `canonical_uri`, never configured separately, so the path a client posts to and the identifier its token is bound to cannot drift apart (`crates/busbar-core/src/mcp/mod.rs:230-232`). `https://gateway.example.com/mcp` mounts at `/mcp`.

```yaml
mcp:
  canonical_uri: https://gateway.example.com/mcp
  authorization_servers:
    - https://login.example.com
  scopes_supported: [mcp.tools.read, mcp.tools.call]
  allowed_origins: []
```

That mounts four route entries over two paths (`crates/busbar-core/src/router.rs:430-469`) — `GET` and `DELETE` are separate entries sharing one row here because they share one answer:

| Route | Auth | What it is |
|---|---|---|
| `GET /.well-known/oauth-protected-resource/mcp` | **none** | RFC 9728 §3.1 metadata. The one open route on this plane — every caller who needs it is by definition one that has no token yet. |
| `POST /mcp` | key | The endpoint. JSON-RPC 2.0. |
| `GET /mcp`, `DELETE /mcp` | key | `405`. This revision has no GET stream and no sessions. Behind the key so an anonymous caller gets the `401` challenge instead of a description of the surface. |

The metadata path is the well-known prefix with the resource's path appended **after** it, per RFC 9728's path-insertion rule (`crates/busbar-core/src/mcp/mod.rs:266-272`). Getting that backwards 404s every compliant client's discovery. The document Busbar renders carries `resource` always, `authorization_servers` and `scopes_supported` when non-empty, and `bearer_methods_supported: ["header"]`, with `Cache-Control: public, max-age=3600` (`crates/busbar-core/src/ingress/protocol.rs:344-372`). `bearer_methods_supported` is not configurable: Busbar accepts a bearer in the `Authorization` header and nowhere else, on every plane.

### Boot refusals: the `mcp:` block

Every one of these stops the process. An MCP plane that is half-configured is worse than one that is absent, because it answers.

| Refusal | Condition | `crates/busbar-core/src/…` |
|---|---|---|
| `mcp.canonical_uri is required` | absent or empty | `mcp/mod.rs:351-354` |
| `… is not an absolute http(s) URI` | not `http://` / `https://` with a non-empty authority | `mcp/mod.rs:355-356`, `mcp/mod.rs:448-461` |
| `… carries a query or fragment` | a `?` or `#` in the **path**, or a `#` in the **origin**. A `?` inside the authority is not tested by this arm — `split_absolute` cuts at the first `/`, so it lands in the origin, and `https://gateway.example.com?x/mcp` boots with that whole string as the audience and `/mcp` as the mount (`mcp/mod.rs:448-460`) | `mcp/mod.rs:357-359` |
| `… has no path` | path is empty or `/` — mounting at `/` would claim every path in the deployment | `mcp/mod.rs:360-363` |
| `mcp.authorization_servers must list at least one issuer` | empty list | `mcp/mod.rs:364-366` |
| `… entry is not an absolute http(s) URI` | any entry | `mcp/mod.rs:367-371` |
| **`mcp: is configured but auth.chain is empty`** | `mcp:` present and `auth.chain` absent or `[]` | `config_validate/mod.rs:945-956` |

**The empty-`auth.chain` refusal is the one to understand.** With an empty chain the auth middleware admits with no principal at all. The plane's entire authorization model is that a caller sees and may call only what its key's grant permits — and a request that carries no key is never *narrowed* by one, so the grant predicate answers `true` for every `(kind, value)` pair it is asked. That is not "no access", it is wildcard access to every registered server and every approved tool, for anyone who can reach the port. The second half is transitive: `upstream::authorise` binds the outbound credential Busbar spends to the inbound principal's grant, and with no inbound principal there is nothing to bind to, so Busbar spends its own upstream credentials on behalf of an anonymous caller. Both properties go vacuous at once and neither failure is visible from outside — the deployment answers every request perfectly. Close the chain (`auth: { chain: [keys] }`, or an IdP auth plugin), or drop the `mcp:` block.

This refusal is MCP-only. There is no equivalent check for `agents:` — see [A2A](/docs/a2a/).

### The `tools:` section

`tools:` is a sibling of `pools:` and `agents:`: a map whose keys are registrations, with two words reserved at the section level on every plane (`crates/busbar-core/src/plane/config.rs:84-89`).

| Reserved section key | Type | Combine rule |
|---|---|---|
| `tools.hooks` | list of bare hook names | **ADDITIVE** — union with each server's own `hooks:`, deduped in declaration order (`crates/busbar-core/src/mcp/config.rs:962-972`) |
| `tools.upstream_credentials` | `own` \| `passthrough` | **OVERRIDE** — an entry's own value replaces it (`crates/busbar-core/src/mcp/config.rs:974-983`) |

Naming a server `hooks` or `upstream_credentials` is refused at parse with a message naming the reservation, and the refusal for a reserved key holding a *mapping* fires **before** the typed lifts so you read "that name is reserved" rather than "expected a sequence" (`crates/busbar-core/src/plane/config.rs:278-287`, `:335-341`).

#### `tools.<server>` — one registered upstream

`deny_unknown_fields`: a typo'd key fails boot rather than silently un-pinning a server (`crates/busbar-core/src/mcp/config.rs:654`).

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `pin` | object | **yes** | — | The out-of-band trust root. Required even when it is `unpinned`. |
| `pin.mechanism` | `pinned_pubkey` \| `cert_spki` \| `mtls` \| `unpinned` | **yes** | — | A pin whose mechanism is inferred is a pin whose meaning changes when the inference changes. |
| `pin.key` | string | required for the three rooted mechanisms; **refused** for `unpinned` | — | Issuer public key, or certificate SPKI hash. |
| `transport` | `streamable_http` \| `stdio` | no | `streamable_http` | See [Transports](#transports). |
| `url` | string | **yes** for `streamable_http`; **refused** for `stdio` | `""` | `http://` or `https://`. |
| `command` | string | **yes** for `stdio`; **refused** otherwise | — | ABSOLUTE path of the binary Busbar spawns. |
| `args` | list of strings | no; **refused** on non-stdio | `[]` | The child's argv, verbatim. Never split on spaces. |
| `env` | map of name → string \| secret ref | no; **refused** on non-stdio | `{}` | The child's WHOLE environment. |
| `cwd` | string | no; **refused** on non-stdio | Busbar's own | Absolute. |
| `refresh_ttl` | `<n><s\|m\|h\|d>` | no | `6h` (`mcp/config.rs:646`) | How long an observation of this upstream's tool list stays fresh. |
| `timeout` | `<n><s\|m\|h\|d>` | no | `30s` (`mcp/upstream.rs:72`) | Wall-clock budget for one outbound leg (the tool call; separately, the RFC 8693 exchange). `0` is refused. |
| `tools_allow` | map of tool name → object | no | `{}` | The approved tools. A map, not a list, because every tool needs a slot for its approved schema hash. |
| `prompts_allow` | map of prompt name → object | no | `{}` | |
| `resources_allow` | map of URI → object | no | `{}` | |
| `resource_templates_allow` | map of URI template → object | no | `{}` | RFC 6570 **level 1 only**. |
| `aud` | absolute http(s) URI | required when `token_exchange:` is set; **refused** on `stdio` | — | The RFC 8707 resource indicator for the OUTBOUND token. Not Busbar's own audience — that is `mcp.canonical_uri`. |
| `grants` | object of three booleans | no | all `false` | `sampling`, `elicitation`, `roots` — what this upstream may ask Busbar for. |
| `roots` | list of `{uri, name?}` | no | `[]` | `file://` only. The satisfier behind `grants.roots`. |
| `sampling` | object | no | absent | The satisfier behind `grants.sampling`. All three fields required. |
| `allow_private` | bool | no; **refused** on `stdio` | `false` | Permits a private / loopback / CGNAT address for this one server. Never permits cloud-metadata addresses. |
| `token_exchange` | object | no; **refused** on `stdio` | absent | RFC 8693 exchange. Absent ⇒ no credential is sent at all. |
| `max_input_required_rounds` | u32 | no | `3` (`mcp/config.rs:623`) | Cap on rounds Busbar will satisfy an UPSTREAM's `input_required` for, per dispatch. `0` means never. |
| `max_caller_ask_rounds` | u32 | no | `3` (`mcp/config.rs:633`) | Cap on rounds Busbar asks ITS OWN CALLER for. `0` is an operator kill switch for every `ask_caller` on this server. |
| `upstream_credentials` | `own` \| `passthrough` | no; **refused** on `stdio` | section value, else engine default | |
| `hooks` | list of bare names | no | `[]` | Adds to `tools.hooks:`. |

**`tools_allow.<tool>`** (`crates/busbar-core/src/mcp/config.rs:182-269`):

| Key | Type | Default | Notes |
|---|---|---|---|
| `schema_hash` | string | absent | The APPROVED digest. **An empty value object means "allowed, no hash approved yet", which is `pending` and does not serve.** |
| `description` | string | absent | The OPERATOR's description, published in the catalogue. Markup-normalised on the way out. Never an input to a routing decision. |
| `input_schema` | JSON | absent | Echoed verbatim as `inputSchema`. Absent publishes `{"type":"object"}`. |
| `output_schema` | JSON | absent | Published as `outputSchema`, **and enforced**: an upstream's `structuredContent` is validated against it and a violation is reported as a tool failure. Absent means no promise and no validation — Busbar never invents one. |
| `publish_as` | string | absent | Overrides the default published wire name `<server>_<tool>`. This is the value `tools/list` emits, the value `tools/call` dispatches on, **and the value an `mcp_tool:` grant must name** — so setting it changes who can call the tool. |
| `ask_caller` | list of rounds | `[]` | What Busbar asks its own caller for, synchronously (SEP-2322), before dispatching. |
| `task_support` | `none` \| `optional` \| `required` | `none` | SEP-2663. `required` refuses a client that did not declare the tasks extension with `-32021` before the handler runs. |
| `task_ask_caller` | list of rounds | `[]` | The same ask, from INSIDE a task. Requires `task_support` other than `none`. |

One round of `ask_caller` is a map from a server-assigned key to `{method, params?}`. `method` is one of `elicitation/create`, `sampling/createMessage`, `roots/list`. **`params` is cloned verbatim onto the wire — there is no templating and no substitution**, structurally, so an upstream's value can never flow into a demand Busbar makes in its own name (`crates/busbar-core/src/mcp/config.rs:362-397`).

**`prompts_allow.<name>`**: `description`, `template` (text form), `messages` (typed form: `role` ∈ `user`\|`assistant`, default `user`; content `text` / `image` / `audio` / `resource`), `ask_caller`. `template:` and `messages:` are alternatives — declaring both is refused.

**`resources_allow.<uri>`**: `name`, `description`, `mime_type`, `text`, `blob` (base64). `text:` and `blob:` are alternatives — declaring both is refused, and a `blob` that does not decode is refused at boot.

**`resource_templates_allow.<template>`**: `name`, `description`, `mime_type`, `text`. There is deliberately no `blob:`.

**`sampling`** (all three REQUIRED, all three refused at zero): `model` (a pool or model on Busbar's own catalogue, dispatched under the inbound caller's grant — never the upstream's `modelPreferences`), `max_tokens` (a ceiling; an ask above it is clamped, not refused), `max_requests_per_minute` (per-upstream, deployment-wide, spent before any model leg is entered).

**`token_exchange`**: `token_url` (must be `https`, or `http` only on a registration that also sets `allow_private: true`), `subject_token` (a `SecretRef` — Busbar's OWN token, never the caller's), `subject_token_type` (default `urn:ietf:params:oauth:token-type:access_token`). There is deliberately **no `scope:`** — the requested scope is derived from the inbound caller's own grant at dispatch time, because a configured scope list would be a second statement of what a caller may reach and the wider one would win (`crates/busbar-core/src/mcp/config.rs:812-822`; the derivation is `mcp/client/egress.rs:361-375`).

```yaml
tools:
  hooks: [pii-guard]                       # fires for every registered server

  acme:
    url: https://tools.acme.example/mcp
    pin: { mechanism: cert_spki, key: "sha256/…" }
    refresh_ttl: 6h
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

All of these are checked by `validate_server` / `validate_endpoint`, which is called from **both** the config file's `Deserialize` and the admin write path, so the API refuses exactly what the file refuses (`crates/busbar-core/src/mcp/config.rs:1010-1016`).

| Refusal | Condition | `mcp/config.rs` |
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
| `refresh_ttl:` unparseable | parsed at boot so it lands on the operator, not on a silent fallback six hours later | `1237-1239` |
| `timeout:` unparseable, or `0` | zero would refuse every call before it was sent. There is deliberately no spelling for "unlimited" | `1246-1256` |
| `roots[n].uri` not a non-empty `file://` URI | MCP roots are filesystem roots | `1263-1272` |
| `roots:` declared with `grants.roots: false` | the gate runs before the satisfier, so the list would never be disclosed | `1273-1279` |
| `sampling:` with `grants.sampling: false` | unreachable policy | `1287-1294` |
| `sampling.model:` empty | | `1295-1301` |
| `sampling.max_tokens: 0` / `max_requests_per_minute: 0` | the grant withheld wearing a budget's clothes. An operator who means "off" deletes the grant | `1302-1315` |
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
| a `hooks:` entry that is not a bare name, or that reaches onto another section (`pools.x`, `agents.y`) | | `plane/config.rs:180-201` |

Two more refusals run over the **whole** effective registry (file base + admin overlay), in `config::resolve`:

- **Published-name uniqueness.** Two tools that would both be published as one wire name refuse boot, naming both claimants. The check compares every published name against every other, *including* an override against another server's default — the collision a naive overrides-only check misses (`crates/busbar-core/src/mcp/config.rs:1486-1546`, called from `config/mod.rs:4498`). A collision is refused rather than resolved, because the published name is what an `mcp_tool:` grant names, so resolving it would silently move an authorization decision.
- **Dangling hook references.** A hook a `tools:` entry names must exist in the one top-level `hooks:` map (`crates/busbar-core/src/config/mod.rs:4477-4486`). A dropped reference is an operator believing a control is attached that is not.

### Failover pools: `tool_pools:`

An MCP registration is one destination. `tool_pools:` is how you tell Busbar that two registrations are **the same server deployed twice** — one image in two regions, a hosted instance beside a self-hosted twin. That declaration is what the selection walk needs in order to send a request the breaker would otherwise refuse to the other member instead, and the walk runs on every `tools/call` (`crates/busbar-core/src/mcp/reroute.rs:259`).

It is **opt-in and the absent section is exactly today's behaviour**: one registration, one destination, nothing to reason about (`crates/busbar-core/src/failover/mod.rs:119-127`).

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `members` | list of bare `tools:` names | yes, **≥ 2** | `[]` | ORDERED: the first is the primary, and its approved fingerprint is the one every other member must match. |
| `repeatable` | list of operation names | no | `[]` | Operations safe to perform TWICE. |

`deny_unknown_fields` — a typo'd key must fail boot, not silently un-declare a safety rule (`crates/busbar-core/src/failover/mod.rs:135`). There is no `breaker:` key on a tool pool and no `repeatable: all`.

```yaml
tools:
  search-eu: { url: https://eu.search.example/mcp, pin: { mechanism: cert_spki, key: "sha256/…" } }
  search-us: { url: https://us.search.example/mcp, pin: { mechanism: cert_spki, key: "sha256/…" } }

tool_pools:
  search:
    members: [search-eu, search-us]
    repeatable: [search_code]      # reads may be performed twice. Default: none.
```

Boot refusals, all in `crates/busbar-core/src/config/mod.rs:1585-1639`:

| Refusal | Condition |
|---|---|
| a failover pool needs at least TWO members | `members.len() < 2` — a one-member pool has nowhere to fail over to |
| `<member>` is named twice | a repeated member would be tried twice against the same upstream, which is a retry wearing a failover's clothes |
| `<member>` is an entry in the top-level `agents:` section, not `tools:` | **no pool may straddle two planes.** The section a pool is written in *is* which plane it is on, and the message names the section the entry really lives in rather than sending you hunting for a typo you did not make |
| `<member>` is not defined in the top-level `tools:` map | |
| `repeatable:` holds an empty entry | an empty entry names nothing |

**Naming two servers in a pool is not what makes them interchangeable.** The walk compares the approved schema digest Busbar already computed for each candidate and moves a request only when they agree; a candidate whose digest differs, or that has nothing approved yet, is refused with both digests named (`crates/busbar-core/src/failover/mod.rs:33-57`, `:168-186`). Same image in two regions ⇒ same schemas ⇒ same digest ⇒ provably interchangeable. Two different vendors' `search` tools ⇒ different digests ⇒ refused. You are asserting only *"these names are the same deployment"*, and that claim is checked before a single request moves.

**A reroute is not a retry**, and the seam draws the line there. When the primary's breaker is Open the request never left Busbar, so sending it to an equivalent deployment duplicates nothing: that movement is the one the rule allows by default. Once a call has gone out, moving it is a genuine repeat of work the upstream may already have done, and the rule refuses it unless the operation is named in `repeatable:` (`crates/busbar-core/src/failover/mod.rs:60-80`). `send_email` is not repeated. `charge_card` is not repeated. There is no switch that turns the rule off wholesale. The two rules compose: **repeat a call only when the digests match AND the operation is declared safe to repeat.**

Reroute never means Busbar found somewhere else to send a call on its own. It means the selection walk chose a different member of a pool you declared, whose fingerprint Busbar verified matches. There is no discovery, and no member you did not write down.

---

## Authentication and identity

### The discovery loop

An MCP client arrives with no credential. It gets `401` with an RFC 6750 `WWW-Authenticate: Bearer` challenge carrying a `resource_metadata` parameter — the **absolute** URL of this deployment's protected-resource document, because a client with no credential also has no reason to trust its own reconstruction of your origin (`crates/busbar-core/src/mcp/mod.rs:271-273`, `crates/busbar-core/src/auth/challenge.rs:73-91`). It reads that document, finds `authorization_servers`, does ordinary OAuth against your IdP, and comes back with a token.

The challenge distinguishes two cases and clients branch on the difference. No credential presented at all earns a **bare** challenge with no `error` parameter — RFC 6750 §3.1 is explicit that this case omits it, because the bare challenge means *authenticate* — while a credential that was presented and failed earns `error="invalid_token"`. They are not collapsed (`crates/busbar-core/src/auth/challenge.rs:38-61`, `crates/busbar-core/src/auth/mod.rs:1650-1668`). A principal that authenticates but carries no grant on this resource gets `insufficient_scope`.

### What Busbar issues, and what it does not

**With `mcp:` alone, Busbar issues nothing.** It is an OAuth 2.1 *resource server*. The tokens are minted by your existing IdP (Okta, Entra, Auth0) and nothing in the MCP plane mints one.

Two consequences that bite operators:

- **A Busbar virtual key does not work on the MCP endpoint.** Busbar's own signed `bbk_…` tokens carry an optional audience claim, and the verifier enforces the plane boundary in both directions: a token with no audience is admissible only on the plain data plane, and a token presented on an audience-checked ingress must carry exactly that audience (`crates/busbar-core/src/governance/signing.rs:306-320`). Every key minted through the admin API or `/auth/token` is minted with `aud: None` (`crates/busbar-core/src/governance/signing.rs:194`), so it is refused here with an audience mismatch. There is no surface today that mints an audience-bound `bbk_` token: `mint_for_audience` is `#[cfg(test)]` and therefore is not in a release build at all (`governance/signing.rs:207-209`).
- **An opaque bearer is refused.** An IdP that issues opaque reference tokens presents a credential with no readable claims, so Busbar cannot establish that it was minted for Busbar. The honest answer to "I cannot tell" on a confused-deputy defence is refusal (`crates/busbar-core/src/auth/audience.rs:38-47`, `mod.rs:1618-1625`). Until token introspection exists, an IdP that issues opaque tokens cannot serve this plane — and you find that out from a clear refusal rather than from an audience check that silently was not happening.

If you do not have an IdP you can register clients in, the separate **`oauth_as:` block** makes Busbar an authorization server as well, serving pre-registration, Client ID Metadata Documents and dynamic client registration, and issuing RFC 9068 `at+jwt` access tokens whose `aud` is one of Busbar's own protected resources (`crates/busbar-core/src/oauth_as/mod.rs:1-70`, `oauth_as/plane.rs:119-149`). That is a different plane with its own configuration and is out of scope here.

### The audience check

This is the load-bearing one, and it is the difference between a gateway and an open relay. Without it, a token an agent legitimately obtained for some *other* resource — a token your IdP happily issued, for a service that has nothing to do with Busbar — is spendable here against Busbar's pools, budget and upstream credentials.

Busbar compares the token's `aud` for **equality** against `mcp.canonical_uri`, and refuses anything else including a token that carries no audience at all. Never prefix, never suffix, never case-insensitively: a resource indicator is an opaque identifier, and treating it as a namespace is how `https://gw.example.com/mcp` starts admitting tokens minted for `https://gw.example.com/mcp-staging` (`crates/busbar-core/src/plane/mod.rs:366-369`, `crates/busbar-core/src/auth/audience.rs:70-108`). RFC 7519's single-string and array forms of `aud` are both accepted.

The check lives beside the **mount**, not in a handler, so every path behind that door inherits it and a route added later cannot forget it (`crates/busbar-core/src/plane/mod.rs:357-362`). For a token Busbar did not mint, core makes its own determination *before* the auth chain runs, and only ever to refuse: an unverified `aud` read is sound here precisely because the result can only narrow what is admitted, never widen it (`crates/busbar-core/src/auth/audience.rs:24-36`).

`canonical_uri` is operator-configured rather than derived from the request's `Host`. Deriving it from the request would let a caller choose its own audience by sending a header, which turns the defence into a formality.

### `Origin` and DNS rebinding

`2026-07-28` makes `Origin` validation a MUST. Busbar refuses a request carrying an `Origin` that is not in `mcp.allowed_origins` with `403`; a request carrying no `Origin` — which is every non-browser client — is unaffected, and loopback is admitted unconditionally by the shared rule (`crates/busbar-core/src/mcp/mod.rs:244-252`, `crates/busbar-core/src/mcp/mod.rs:416-429`). The threat is a page on an attacker's origin resolving a name to Busbar's loopback address and driving the tool plane with the user's ambient credentials.

---

## What a caller can see and call

**Which tools a caller can see is decided by the caller's key scopes and by nothing else.** There is no hook on the catalogue path, no filter verb, no tag convention (`crates/busbar-core/src/mcp/catalogue.rs:25-30`). Two scope kinds gate this plane (`crates/busbar-core/src/plane/mod.rs:156-162`):

| Scope kind | Grants | Named as |
|---|---|---|
| `mcp_server` | may this caller reach this upstream at all | the `tools:` registration id |
| `mcp_tool` | may it reach this capability | the **published wire name** — `<server>_<tool>` by default, or the `publish_as:` override |

**Both must pass, for every capability** — a tool, a prompt, a resource and a template alike. A key scoped to one tool on a server must not acquire the rest by having been let through the door (`crates/busbar-core/src/mcp/catalogue.rs:1141-1167`).

```yaml
# on the virtual key
allowed_scopes:
  - { kind: mcp_server, value: acme }
  - { kind: mcp_tool,   value: acme_search_code }
```

### Listed and served are two different answers

The **listing** (`tools/list`, `prompts/list`, `resources/list`, `resources/templates/list`) asks identity and grant, and deliberately not the artifact step: a tool with no approved hash and a server with no locked pin both *appear*, so the approval queue is visible (`crates/busbar-core/src/mcp/catalogue.rs:1169-1180`, `:467-471`). What they do not get is a dispatch.

The **dispatch** (`tools/call`) asks the full ordered gate — identity, grants, the trust artifact comparison, and the catalogue generation — in `Catalogue::resolve` (`crates/busbar-core/src/mcp/catalogue.rs:749-810`). It refuses a call with:

| Refusal | Meaning | Status | Audit reason |
|---|---|---|---|
| `UnknownTool` | no such published name | `404` | `unknown_tool` |
| `NotGranted` / `IdentityNotLive` | this caller may not see it, or the principal is no longer live. **Both render to the caller with the same words as `UnknownTool`** — a caller learns only that there is nothing there for it | `404` / `401` | `not_granted` / `identity_not_live` |
| `NotApproved` | registered, but no schema hash approved: pending | `403` | `not_approved` |
| `NotPinned` | the server has no locked identity pin | `403` | `not_pinned` |
| `Quarantined` | the upstream's current tool list no longer matches what was approved | `403` | `quarantined` |
| `GenerationMoved` | the registry changed between admission and dispatch | `409` | `generation_moved` |

Statuses: `crates/busbar-core/src/mcp/method.rs:2034-2047`; wording: `mcp/catalogue.rs:404-435`; audit words: `mcp/catalogue.rs:449-462`. A quarantine is `403` and not `404` on purpose: the tool exists and this caller may see it — what changed is the upstream.

`GenerationMoved` is the swap guard. The catalogue is an immutable snapshot carrying a monotonic generation, taken fresh on every config apply *including one that changes nothing about `tools:`*; a call admitted under generation N is refused under N+1 (`crates/busbar-core/src/mcp/catalogue.rs:8-23`). An in-flight call cannot outlive the approval it was admitted under. Retry.

### Routing binds identity, never description

A catalogue entry is keyed on `(server-id, published name, schema-hash)`. The description is the **operator's**, carried for display, markup-normalised on the way out, and read by no decision anywhere in the module (`crates/busbar-core/src/mcp/catalogue.rs:74-80`). Publishing the operator's text rather than the upstream's is what keeps an upstream from rewriting the instructions a model reads. `outputSchema` follows the same rule and goes one step further: publishing a schema makes conforming structured results a MUST for the server that published it, and on this wire that server is Busbar — so Busbar validates what the upstream returned against the approved schema and reports a violation as a tool failure (`crates/busbar-core/src/mcp/config.rs:200-222`).

Descriptions, prompt templates, resource contents and tool outputs are all markup-normalised: `<IMPORTANT>`, `<system>` and HTML-like tags are stripped before the text re-enters model context (`crates/busbar-core/src/mcp/sanitize.rs:1-16`). **This is a floor, not a claim that injection is handled.** "now call `transfer_funds`" carries no markup and survives unchanged, by design — there is nothing to strip. Semantic injection is a hook residual and a model-alignment problem; Busbar reduces the markup-shaped attack surface (`mcp/sanitize.rs:17-25`).

---

## Transports

A transport is not a wire format. Every MCP transport carries the same JSON-RPC 2.0 message shape, which is why the plane has one `ingress_protocol` label and no superset IR (`crates/busbar-core/src/plane/mod.rs:42-44`, `:207`).

### Inbound: streamable HTTP

`POST` to the mount path. This is the `2026-07-28` stateless shape (SEP-2243/SEP-2575), and it is a breaking redesign rather than an increment (`crates/busbar-core/src/mcp/mod.rs:44-65`):

- **No `initialize` handshake and no protocol sessions.** Every request is self-describing, carrying its protocol version and the client's capabilities in `params._meta`. There is no `Mcp-Session-Id` to mint, honour or invalidate.
- **The GET stream is gone**, and with it resumability. `GET` and `DELETE` answer `405`. The server-to-client channel moved onto a method: `subscriptions/listen` is an ordinary POST whose response is a long-lived stream of notifications (`crates/busbar-core/src/mcp/subscribe.rs:1-21`).
- **`Mcp-Method` mirrors the body's `method` on every request**, and `Mcp-Name` mirrors the target name on `tools/call`, `resources/read` and `prompts/get`. Both are required. A header that disagrees with the body is `400` with `-32020`, because a proxy routing on the header while the server executes the body is a request-smuggling primitive.
- **`MCP-Protocol-Version` must equal the body `_meta` protocol version** — same `-32020` on mismatch. A `_meta` that is absent or incomplete is a *different* failure and answers `-32602` with `400`: that is a defect in the request's own params, not two readings of one request disagreeing.

The revision Busbar implements is `2026-07-28`, and it is the only one (`crates/busbar-core/src/mcp/envelope.rs:61-67`). An unsupported protocol version answers `-32022`.

### Inbound: `busbar --mcp-stdio`

For an MCP host that runs Busbar as a child process (Claude Desktop-class), `busbar --mcp-stdio` serves the MCP plane on Busbar's own stdin and stdout, newline-delimited JSON-RPC, and **binds no listener at all** — a child that opened ports would be a network server its supervisor never asked for (`crates/busbar/src/main.rs:934-951`).

The **same boot** runs: config load, plugin preflight, governance, the flusher and the refresh jobs. Every line read from stdin is fed to the same serve sequence the HTTP endpoint runs, with the same envelope rules and the same dispatch, so a request the HTTP plane would refuse is refused here with the same code and the same sentence (`crates/busbar-core/src/mcp/stdio_serve.rs:7-15`). The mirrored routing headers are synthesised from the body — a pipe has no header block and no intermediary — so a body defect stays a body defect rather than being converted into a header defect.

**Governance is bound once, at boot, for the whole session.** A stdio caller presents no per-request bearer, so `BUSBAR_MCP_STDIO_CREDENTIAL` carries the same credential the HTTP plane accepts, judged by the same sequence: the RFC 8707 audience pre-filter against `mcp.canonical_uri`, then the configured auth chain, then the one identity resolution the HTTP middleware itself calls (`crates/busbar-core/src/mcp/stdio_serve.rs:29-47`, `:108-111`). A credential the HTTP door would refuse is refused here; one it would admit binds the session to the same principal, the same budgets, the same audit attribution and the same hooks. **A configured chain with no credential, or a refused one, is a refusal to serve** — nonzero exit, a sentence on stderr — exactly as the HTTP door answers `401`.

The credential rides an environment variable and not a flag, because argv is world-readable on most platforms and an MCP host's `env` block already has exactly this shape.

The identity is **frozen for the life of the session**: a key revoked mid-session keeps being honoured until the process ends. The party able to end the session is the party that started it, and killing the child *is* the revocation — which no network peer can say of an HTTP stream.

Because stdout is the MCP channel, logging moves to stderr in this mode (`crates/busbar/src/main.rs:723-727`).

`--mcp-stdio` requires the `mcp:` block. Two live asks and one round cap are transport-local belts: a 30-second timeout on one live ask, and a cap of 8 live MRTR rounds per request on top of the operator's own `max_caller_ask_rounds` (`crates/busbar-core/src/mcp/stdio_serve.rs:109-118`).

### Outbound: `transport: streamable_http`

The default, and the only network transport. The leg is SSRF-checked, address-pinned and connection-pooled, and it carries a credential selected under the **inbound caller's** grant.

### Outbound: `transport: stdio`

Busbar spawns a local MCP server that has no URL — a filesystem, database or git server. The SSRF guard is the defence on the HTTP wire and has nothing to say about a child process, so `validate_endpoint` stands in its place, at boot, where the operator who wrote it is standing (`crates/busbar-core/src/mcp/config.rs:1046-1057`). Four decisions, each fail-closed (`crates/busbar-core/src/mcp/client/stdio.rs:15-49`):

1. **No shell, ever.** The program goes to `Command::new` and the arguments through `.args()`. There is no `sh -c`, no string split on spaces, and therefore no metacharacter with meaning. An operator who wants a shell writes `/bin/sh` as the program.
2. **The program is an absolute path**, refused at boot otherwise. A bare name is resolved through `PATH`, which would make the binary that actually runs a property of the environment Busbar was started in rather than of the file you wrote.
3. **The environment is not inherited.** `env_clear()` runs first and only the named `env:` entries are put back. Busbar's own process environment holds provider API keys, store credentials and admin tokens; handing that set to an operator-configured child would make every stdio registration a credential-exfiltration primitive, silently. A value that is itself a secret is written as a secret reference and is **resolved at spawn, never earlier**, so the snapshot never holds plaintext and rotating the secret needs no restart (`crates/busbar-core/src/mcp/config.rs:896-926`).
4. **The arguments come from config only.** Nothing on the dispatch path can add to, reorder or substitute into them — a tool call's `arguments` reach the child as JSON on its stdin, which is data, and never as argv.

> **Windows operators must name more variables than unix ones, and the reason is the OS.** On unix an empty environment is a working environment. On Windows the process environment is load-bearing for the platform itself (`SystemRoot`, `windir` during DLL resolution and Winsock init) and interpreter-based children want `PATH`, `TEMP`/`TMP` and often `APPDATA`. An `env_clear()`ed child on Windows can fail to start, or start and fail on its first socket. The posture is not relaxed — it is the same secret on both platforms — so a Windows `env:` block is explicit about the platform variables the child needs. This is reasoned rather than observed; see the note in [operations.md](/docs/operations/).

**The child has a lifecycle, not a fire-and-forget spawn.** `Spawning → Ready → Draining → Dead`, with a crash from any state landing in `Dead` (`crates/busbar-core/src/mcp/client/stdio.rs:55-71`). A dispatch is sent only in `Ready`: a write to a pipe whose reader has not started is a write that succeeds and is lost.

**The restart policy is a circuit breaker, not a retry loop.** A child that crashes on startup will crash on every startup, so an unbounded restart loop against a broken binary is a fork bomb with a config file behind it. Exponential backoff from the crash count, capped, and a quarantine that stops restarting entirely past a threshold inside a window (`crates/busbar-core/src/mcp/client/stdio.rs:150-158`):

| Knob | Value | Configurable |
|---|---|---|
| first backoff after a crash | 100 ms | no |
| backoff ceiling | 30 s | no |
| crashes that quarantine the child | 5 | no |
| the window they are counted over | 60 s | no |

A successful start **does not clear the crash history** — a child that crashes, restarts, serves one call and crashes again is crash-looping, and clearing the window on every successful start is how a breaker is written that never trips. The history ages out by time (`crates/busbar-core/src/mcp/client/stdio.rs:220-230`). The supervisor outlives the child, deliberately: a quarantine that lived on the child would be forgotten the moment the child was dropped, which is the moment it is always reached.

Defaults are chosen to make a crash-looping child visible within seconds rather than to maximise availability: an MCP server that will not start is a configuration error, and hiding it behind retries delays the fix.

---

## The trust lifecycle: pins, hashes, drift and quarantine

Tool identity on this plane is `(server, tool, schema-hash)`. Two things have to be approved before a tool serves: the server's **pin** (its authenticity root) and the tool's **schema hash**.

A registration with no authenticity root (`pin.mechanism: unpinned`) is registrable and **never approvable** — it is enforced by what is constructible rather than by a check a later edit could relax (`crates/busbar-core/src/mcp/catalogue.rs:70-74`). A tool with an empty `tools_allow` value object is `pending` and does not dispatch.

**The rug-pull defence needs a live observation, and that is what the refresh job supplies.** Comparing an approved digest against the digest the operator wrote in config is comparing intent with itself and is structurally incapable of noticing an upstream changing its schema underneath (`crates/busbar-core/src/mcp/connect.rs:7-14`). So Busbar fetches each registered server's live tool list on its own `refresh_ttl:` and re-hashes it **from the bytes the upstream sent** — never adopting a digest the upstream supplied, which would be the rug-pull with an extra step. A refresh that fails is recorded as a failure, not dropped: a server Busbar could not reach must never present as trusted.

The sweep job ticks every 30 seconds and is not configurable (`crates/busbar-core/src/trust/sweep.rs:49-56`). That constant only decides how finely the job notices that a per-registration TTL elapsed; the cadence you control is `refresh_ttl:`. There is deliberately no key that slows detection, none that delays a quarantine, and no per-server "skip if it failed last time" — every one of those would be a window an upstream could open for itself by misbehaving.

An upstream's own `notifications/tools/list_changed` can only ever bring a refresh **forward**, and its contents are never read: an attacker-controlled trigger may not choose the moment freely and may not choose the content at all (`crates/busbar-core/src/mcp/connect.rs:26-30`).

**A quarantine survives a restart.** What is written to the store is not "this server is quarantined" but "a live observation of this server disagreed with the approval, at this time" — an observation replayed at boot, with the derivation running unchanged on top of it (`crates/busbar-core/src/mcp/demotion.rs:22-35`). A server with no record replays as nothing at all and falls back to the declarative approval, exactly as before: the absence of a row is not a demotion. The record is cleared by the first observation that agrees with the approval again — fix the upstream, the sweep looks, the row goes. A restart does not clear it, which is the whole point.

> **Stated gap.** Drift has two axes and the refresh path observes one of them. The **capability** axis (digests over name, description and input schema) is fully observed. The **identity** axis is not: the shared HTTP client does not surface the peer's certificate SPKI to that layer, so a certificate rotation is invisible to the refresh path. It is invisible; it is not silently reported as verified (`crates/busbar-core/src/mcp/connect.rs:32-41`).

### Operator surfaces

| Route | Scope | What it does |
|---|---|---|
| `POST /api/v1/admin/tools/{name}/connect` | mutation | **Reaches the network.** Fetches the upstream's live tool list, re-hashes it, records the observation, and audits whatever it found. It does **not** approve anything — adopting what was seen is a separate, explicit act, precisely so a poisoned capability list cannot be adopted by the same call that fetched it. |
| `GET /api/v1/admin/tools/{name}/changes` | read | The trust view, computed from the last observation. Contacts nothing; safe to poll. |
| `GET /api/v1/admin/tools/{name}/health` | read | Can Busbar use this server right now, and if not, why. Contacts nothing. |

Mounted at `crates/busbar-core/src/admin/v1/json/mod.rs:82-90`; the shared sequence is `crates/busbar-core/src/admin/planeverbs.rs`. A registration missing from either the catalogue or config answers the same `404` — two answers a caller could tell apart would be an existence oracle (`admin/planeverbs.rs:28-35`).

**There is no `/tools/{name}/approve` verb.** Approval on this plane is the definition itself: write the observed digest into `tools_allow.<tool>.schema_hash` in config, or `PUT` the definition through the generic `tools` section CRUD. (The A2A plane has an `approve` verb because a card fingerprint has no config slot the operator fills in advance.)

---

## What a tripped upstream returns

The circuit breaker runs on all three planes. There is one FSM and no second state machine: an MCP tool server is a cell on the same breaker a model lane sits on, keyed `tool:<server-id>` with lane index 0 (`crates/busbar-core/src/store/planes.rs:22-30`, `:107-109`). Closed → Open → HalfOpen, the same two-stage disposition pipeline, the same exponential cooldown, the same single-flight half-open recovery probe. See [circuit-breaker.md](/docs/circuit-breaker/) for the state machine itself.

**The breaker is consulted before any socket**, immediately after the authorization gate and before the dispatch loop — the same position the LLM walk consults it before a lane (`crates/busbar-core/src/mcp/method.rs:1410-1431`). The task-creating path consults it at the same position and **before the task row is minted**, because a tripped server must be a refusal the caller sees now, not a task id for work Busbar already knows it will not dispatch (`crates/busbar-core/src/mcp/method.rs:1735-1754`).

A tripped server answers:

- HTTP **`503 Service Unavailable`**
- a **`Retry-After`** header, in seconds, populated from the cell's own remaining cooldown — an exact number rather than a guess, floored at 1 (`crates/busbar-core/src/store/planes.rs:220-224`)
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

(`crates/busbar-core/src/mcp/method.rs:2071-2109`.)

**It is an error, never a tool result with `isError: true`.** MCP's `isError` means *the tool ran and it failed*. A tripped breaker means *the call never happened*. Returning the second as the first tells the calling model that a tool executed and reported a failure, and the model then reasons from a lie and may report that false result onward as fact. `-32030` sits in JSON-RPC 2.0 §5.1's implementation-defined `-32000..-32099` band because each reserved code is wrong for a specific reason: `-32603` says Busbar broke (it did not), `-32601` says the tool does not exist (it does), `-32602` blames the caller (`crates/busbar-core/src/mcp/method.rs:2065-2075`).

**These cells refuse on a trip and nothing less.** The MCP cell is built with `bench_below_trip_threshold: false` — the one field it does not take from the LLM defaults (`crates/busbar-core/src/store/planes.rs:81-98`). On an LLM pool, a sub-threshold failure arms a short cooldown meaning "prefer a sibling for a while", and failover is what keeps the caller served while it lasts. On a single MCP registration with no pool there is no sibling, so the same cooldown would mean "refuse *every* caller of this server for the next 15–120 seconds" after one transient blip, on a cell whose own trip predicate had just declined to trip. So the predicate is the published one and nothing weaker: **error rate ≥ 0.5 over at least 5 outcomes in a 30-second window**, cooldown 15 s escalating to 120 s (`crates/busbar-core/src/store/in_memory/mod.rs:563-574`, `:629-639`). An upstream's own `Retry-After` is still honoured, for as long as the upstream asked for — that is the upstream's backpressure, not Busbar inventing an outage.

**A tripped server that is a member of a `tool_pools:` pool is not what produces the `503` above.** The walk runs before any refusal is composed and tries the next member whose approved digest matches the primary's (`crates/busbar-core/src/mcp/reroute.rs:235-379`); the caller gets that member's answer. The `503` is what remains when the pool is *exhausted* — every interchangeable member tripped — and then it names the **pool**, not one server, with a `Retry-After` set from the soonest member cooldown to expire (`crates/busbar-core/src/mcp/method.rs:2142-2167`). An unpooled registration has no twin to select, so for it the `503` is the whole story.

**Timeouts are a bound the upstream cannot lengthen by choosing to be slow.** `timeout:` is per server, default 30 s, and there is deliberately no spelling for "unlimited": a leg that cannot time out holds a concurrency slot for as long as the upstream chooses (`crates/busbar-core/src/mcp/config.rs:706-727`).

### Other refusals on this plane

| Code | Status | When |
|---|---|---|
| `-32000` | varies | A governance refusal: well-formed request, method exists, server declined by policy (`mcp/method.rs:2056-2062`). |
| `-32020` | `400` | A mirrored routing header disagrees with the body (`mcp/envelope.rs:134`). |
| `-32021` | `400` | The caller did not declare a client capability a `task_support: required` tool needs; `data.requiredCapabilities` names it. The status is fixed by the spec, not chosen (`mcp/method.rs:268-282`, `:2294-2303`). |
| `-32022` | `400` | Unsupported protocol version; `data` carries `requested` and `supported` (`mcp/envelope.rs:136-139`). |
| `-32030` | `503` | The upstream's breaker is open. |
| `-32601` | `404` | Unknown method — never a `200` carrying an error object. |
| `-32602` | `400` | Structurally wrong params, including an absent or incomplete `params._meta`. |

---

## Observability

The MCP plane emits on **its own pair of request families** — `busbar_plane_requests_total` and `busbar_plane_request_duration_seconds`, which carry a `plane` label — from a layer on the mount rather than a call in the handler (`crates/busbar-core/src/plane/observe.rs:104-153`). These are kept separate from the model plane's `busbar_requests_total` / `busbar_request_duration_seconds` precisely so those stay byte-identical to 1.5.4 (no `plane` label).

| Metric | Type | Labels | On this plane |
|---|---|---|---|
| `busbar_plane_requests_total` | counter | `plane`, `ingress_protocol`, `pool`, `outcome` | `plane="mcp"`, `ingress_protocol="jsonrpc"`, `pool="unresolved"` |
| `busbar_plane_request_duration_seconds` | histogram | `plane`, `ingress_protocol`, `pool` | same |

`pool` reads `unresolved` because the door counts the request **before** its routing target is resolved, and handing the door a caller-supplied tool name would be an unbounded label — one valid credential could mint a new time series per distinct tool name, which is the memory-exhaustion DoS the sentinel exists to close (`crates/busbar-core/src/plane/observe.rs:140-151`). Narrowing it to the configured server name is future work and belongs where the target is resolved.

`sum by (plane) (rate(busbar_plane_requests_total[5m]))` answers "which mounted plane is this traffic on". Existing model-plane panels over `busbar_requests_total` keep working unchanged; to span all planes in one query, sum `busbar_requests_total` and `busbar_plane_requests_total` together.

**A refusal issued before any handler runs is counted too.** The audience-bound `401`, an oversized-body `413`, a `404` — all of them reach no handler, and counting them here is the case an operator most needs to see and the one a handler-level emit could never reach (`crates/busbar-core/src/plane/observe.rs:51-65`).

The client leg lands on the shared upstream families, which are emitted on every plane rather than only the model one (`crates/busbar-core/src/telemetry.rs:788-815`): `busbar_upstream_attempts_total{pool,lane}`, `busbar_upstream_failures_total{pool,lane,disposition}`. Both labels are operator-configured and therefore bounded.

**There is no `operation` metric label, on this plane or any other.** `OpShape::as_str()` — `invoke`, `catalogue`, `fetch`, `task`, `subscribe`, `control` — is a closed internal vocabulary describing the *shape* of an exchange (`crates/busbar-core/src/operation.rs:174-183`). `Operation::name()` is a different thing: the word the wire calls a verb (`operation.rs:286-290`). Its one operator-visible appearance today is the `op` field on the **LLM** proxy engine's tracing span, where the values are the seven LLM verbs (`crates/busbar-core/src/proxy/engine/mod.rs:124`). No metric family carries it (`crates/busbar-core/src/metrics.rs:147-153`), and there is no `paths:` configuration key in the tree. See [observability.md](/docs/observability/) for the full metric table.

Metrics are opt-in: with no `module: prometheus` instance under `export:`, Busbar installs no recorder and mounts no `/metrics`.

---

## Governance

Everything a model-plane request already got applies to a tool call unchanged.

**Budgets and metering.** Every dispatch round is charged against the caller's key through the same admission the LLM path uses, on the same clock, so a tool call and a model call land in the same budget window rather than in two windows that happen to be close (`crates/busbar-core/src/mcp/method.rs:1940-1976`). One metered, attributed event per round: `model` carries the published tool name and `provider` carries `mcp`, so an existing cost dashboard groups MCP traffic without knowing what MCP is. Governance disabled ⇒ no key, no budget, nothing charged — the same posture the LLM path takes.

The per-upstream sampling budget is separate and additional: `sampling.max_requests_per_minute` caps how often *this upstream* may induce a completion, across every caller, spent before any model leg is entered (`crates/busbar-core/src/mcp/config.rs:598-615`).

**Hooks.** `tools.hooks:` ∪ `tools.<server>.hooks:` is resolved once per config generation into a per-server gate list and fired on the **dispatch** path — never the catalogue (`crates/busbar-core/src/state.rs:303-313`, `crates/busbar-core/src/mcp/method.rs:1324-1340`). What a caller may *see* is decided by grants and nothing else; a hook decides what a caller may *do*. The gate fires **before** the task path, the egress gate and the dispatch loop, so a refusal costs no durable task row, no token exchange and no socket. A `kind: gate` hook sees the `invoke` IR — the published tool name and the call's arguments — and can reject the call. A server with no attached hook has no entry in the map, so the firing site costs one hash lookup that misses.

**Audit.** Refusals and outcomes are audited through the one core chain; the plane's audit resource kind is `mcp_server` and its action words are prefixed with it (`crates/busbar-core/src/plane/mod.rs:186-192`).

**The per-call log.** Every inbound `tools/call` that reaches dispatch is written as one hash-chained record to the configured governance store, per caller, and read back at boot (`crates/busbar-core/src/mcp/calllog.rs:1-18`). It is deliberately **not** the admin audit ring: an admin mutation is operator-rate and a tool call is request-rate, and sharing one bounded ring means a busy afternoon of tool calls evicts every admin row from it — silently, because a ring that pruned looks identical to a ring that was never written to.

What is written: every `tools/call` terminal — the dispatched result, every refusal (admission, dispatch-time re-validation, header mismatch, the tasks gate, the caller-ask gate, the budget, the egress gate, the upstream's own refusal), and the creation of an asynchronous task. What is **not** written: `prompts/get` and `resources/read` (the record's `tool` field is the tool routing key, and inventing a value for a prompt would put a name there no `mcp_tool:` grant can name); the round structure of a multi-round exchange (one inbound request, one record); and the task's own later upstream leg (`crates/busbar-core/src/mcp/calllog.rs:65-90`).

The claim is **tamper-evidence, not tamper-prevention.** A chain detects an altered, reordered, inserted or removed record after the fact; it does not stop one, and a host compromised at the moment of writing can rewrite a whole chain consistently and it will verify. Prevention means shipping the records off-box. A chain break found at boot is *reported* while the row is still *restored* — refusing to restore a record whose chain does not verify would turn a detection control into a deletion primitive.

`store: memory` implements none of these methods, so nothing persists and the restore reports zero. That zero is the truth being reported, not a bug.

**Upstream credentials are bound to the inbound caller.** `upstream::authorise` selects the credential Busbar spends under the *inbound* caller's grant — that binding is the confused-deputy defence for the client direction, and it is what the whole plane's authorization model rests on (`crates/busbar-core/src/mcp/mod.rs:80-88`). The RFC 8693 exchange asks for a scope **derived from the caller's own `mcp_tool` grants on that server**, intersected with the server, sorted and deduped (`crates/busbar-core/src/mcp/client/egress.rs:361-375`) — never a configured static list, which would be a second place the authority is written down.

**What an upstream may ask for, it must be granted AND satisfied.** A server-initiated ask arrives as an `input_required` result of a call Busbar made; `grants.{sampling,elicitation,roots}` admits it and the matching `sampling:` / `roots:` block answers it. Neither implies the other: a grant with no satisfier is refused as unsatisfiable naming the missing key, and a satisfier behind a closed grant refuses boot as unreachable. Grants are consulted on **every** retry, because there is no handshake to consult them once and a revocation has to bite on the next retry (`crates/busbar-core/src/mcp/config.rs:521-528`).

**An upstream's ask never reaches Busbar's caller.** It terminates at Busbar: either satisfied under the grant the operator gave that server, or the call fails. Proxying one would ask the caller to grant, on the upstream's behalf, authority Busbar has just declined to spend. The asks Busbar *does* make of its own caller are the operator-authored `ask_caller:` rounds and nothing else — there is no `From` between the two types, none constructible, and the module that composes a caller-facing ask is scanned at test time for so much as the *name* of the modules an upstream's values live in (`crates/busbar-core/src/mcp/mod.rs:90-115`).

---

## Conformance

Busbar's MCP claims are gated in CI by two batteries, both run from this repository so that a red blocks the release it is about (`.github/workflows/mcp-conformance.yml`, driven by `scripts/mcp-conformance.sh`):

- the **official suite** at a pinned version, against a pinned third-party SDK (the control leg) and against a Busbar binary built from the commit under test (the subject leg);
- an **in-house adversarial/seam battery** in `testing/mcp-conformance/`, likewise control and subject.

Two rules make the numbers mean something. **Control legs run always** — a battery that cannot judge a known-good third-party peer cannot be trusted to judge Busbar, and a red control is a finding about the harness, never about Busbar. **Subject legs are armed or red** — a disarmed subject leg proves the suite works and proves nothing about Busbar, and it renders as the same green tick as a leg that judged Busbar and passed, so "not armed, so not run" is a failure. Once armed, a run producing fewer than the revision's full required scenario set fails: set equality, never a floor, because a floor of 30 is satisfied by any 30 of 37.

To run it locally, arm the subject leg with `MCP_SUBJECT_BUSBAR_BIN` pointing at a binary built from your tree and invoke `scripts/mcp-conformance.sh --official-subject` or `--battery-subject`; `--selftest` proves the anti-vacuity assertions still bite before any verdict is trusted.
