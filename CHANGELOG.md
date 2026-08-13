# Changelog

All notable changes to Busbar are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Attachments cross protocols now: documents, audio and video reach the backend instead of being
  destroyed.** Until this release the IR modelled `Text / Thinking / ToolUse / ToolResult / Image /
  Json` and nothing else, so on a **cross-protocol** route an OpenAI caller's `input_audio` or
  `file` part, an Anthropic `document`, a Bedrock `document`/`video` and a Responses `input_file`
  were all converted to an **empty text block, with no warning**. The user's audio never reached the
  model, the model answered "transcribe what?", and nothing in the logs said why — even though
  Gemini would have accepted the audio natively as `inlineData` and Bedrock has a `document` block
  of its own.

  The IR now has a first-class attachment block, and every reader fills it and every writer projects
  it into its dialect's native slot:

  | dialect | reads | writes |
  |---|---|---|
  | OpenAI Chat | `input_audio`, `file` (`file_data`/`filename`/`file_id`) | same |
  | Responses | `input_file` (`file_data`/`file_url`/`file_id`/`filename`) | same |
  | Anthropic | `document` (base64/text/url/file_id/content sources, `title`) | same |
  | Bedrock | `document`, `video` (inline bytes and `s3Location`) | same |
  | Gemini | `inlineData`/`fileData` of any mime type | same |
  | Cohere | tool-result `document` parts | same |

  **Where a target genuinely cannot express an attachment it is now dropped deliberately and
  logged, naming the construct** — Anthropic has no audio or video content block, Converse has no
  audio block, OpenAI Chat has no video part. A `warn!` says which attachment went and why. It is
  never replaced by an empty text block again, because an empty block is indistinguishable, to the
  model and to you, from the caller having attached nothing at all.

  **Deliberately NOT widened: attachment bytes, mime types and filenames are not disclosed to
  content hooks or sidecars.** They contribute no item to the hook-visible projection, which is the
  same decision `ir/facts.rs` records for image provenance. Widening it would be a real disclosure
  change and it will be made on its own terms, in its own release note, not as a side effect of the
  IR gaining a variant.

- **Usage sub-buckets survive the hop, so a bill can be reconciled line by line.** Totals were
  always right; the ATTRIBUTION was not. `reasoning_tokens` arrived at a client as a hard `0` from
  any cross-protocol reasoning call — which reads as "this model did no thinking" rather than "the
  number was not carried". Now carried: OpenAI `completion_tokens_details.reasoning_tokens`,
  Responses `output_tokens_details.reasoning_tokens`, Gemini `usageMetadata.thoughtsTokenCount`,
  Anthropic's **5-minute vs 1-hour cache-creation tier split** (the two tiers are priced
  differently, so collapsing them made a cache-write line item impossible to reconcile), and Cohere
  `billed_units.search_units` (a separately billed unit that no token field could hold, so its loss
  was invisible in a total that reconciled perfectly). Every one is a SLICE of a total, never an
  addition — what busbar bills is unchanged.

- **`qa/field-inventory.json` + a field-coverage gate.** 412 request/response fields across the six
  chat dialects, enumerated from vendored schemas in `qa/field-schemas/` (each with a source URL and
  a retrieval date) rather than from busbar's own readers, which are the thing under test.
  `crates/busbar/tests/field_coverage.rs` fails the build for any field that is neither `carried`
  — **naming a test that fails if it stops being carried** — nor `waived` with a dated reason. The
  unbacked remainder is pinned in `qa/field-coverage.missing` and is the visible work queue.
  Regenerate with `scripts/field-inventory.py --write`.

### Fixed

- **A non-image attachment no longer reaches Anthropic as an `image` and gets the request
  rejected.** The Gemini reader mapped **every** `inlineData` onto an image block regardless of mime
  type, and the Anthropic writer emitted `media_type` verbatim and unvalidated — so a Gemini→
  Anthropic hop carrying an `audio/mp3` clip sent
  `{"type":"image","source":{"type":"base64","media_type":"audio/mp3"}}` upstream, which Anthropic
  rejects (it accepts only `image/{jpeg,png,gif,webp}`). The Gemini reader now routes on the mime
  prefix, and the Anthropic writer validates the media type and drops with a `warn!` rather than
  sending a block the backend will refuse — the pattern the Bedrock writer already applied to its
  own `ImageFormat` union.

- **Cohere's `tool_plan` is no longer shown to the user as the answer's first paragraph.** The
  model's INTERNAL pre-tool-call plan was read into a leading visible text block, so on every
  cross-protocol hop it was rendered to the end user as content the model never intended to show —
  content injection, not loss. It now travels in the IR's reasoning carrier, which also lets the
  Cohere writer put it back in its native `message.tool_plan` slot instead of merging it into
  `content`. Streaming and non-streaming agree.

- **A Cohere tool-result `document` keeps its structure instead of becoming a JSON string.** It was
  serialized into the tool message's text, so the model saw escaped JSON syntax
  (`{"document":{"data":…}}`) where a document should have been. It is now carried structurally and
  re-emitted as a native `document` part.

- **Grounding citations survive out of a Cohere backend, and survive streaming.** The Cohere reader
  never read `message.citations` while the Cohere writer emitted them, so a citation INTO Cohere
  worked and a citation OUT of Cohere vanished — a customer running Cohere RAG behind an
  Anthropic-dialect client got an ungrounded answer with the sources stripped. Separately, streamed
  citations were suppressed on the OpenAI and Cohere egress writers, so the **same request against
  the same backend returned sources at `stream:false` and no sources at `stream:true`**, with
  nothing in the request to explain the difference. Both dialects now emit their native streamed
  citation frame (`delta.annotations`, `citation-start`).

- **Unmodeled request fields dropped at the cross-protocol seam are now named in the log.** `extra`
  was cleared wholesale with exactly two keys warning about themselves; the other ~40 — OpenAI
  `logit_bias`/`store`/`service_tier`/`stream_options`, Anthropic `metadata`/`container`/
  `mcp_servers`, Gemini `safetySettings`/`labels`, Bedrock `guardrailConfig`/`promptVariables`,
  Cohere `citation_options`/`safety_mode`, Responses `previous_response_id`/`truncation`/`include`
  and more — went silently. Most are correctly untranslatable; the silence was the defect. One
  `warn!` now names the exact key set of the request being cleared.

- **The `__busbar_anthropic_unmodeled_blocks` marker can no longer reach the Anthropic wire.** The
  Anthropic writer consumed the positional stash but did not remove it before the trailing `extra`
  overlay, so it could be emitted as a top-level body key — a latent 400 and a tell that names the
  proxy. The OpenAI writer already skipped its equivalent; this was the one writer that did not.

- **A read → write round-trip test now exists, per protocol.** `same_proto_fidelity_tests` covers
  the byte-verbatim short-circuit, which by construction cannot lose anything because it never calls
  a reader or a writer. `roundtrip_fidelity_tests` drives the parts that CAN lose and asserts an
  EXACT set of accepted divergences, failing both when a new one appears and when a listed one
  disappears — so the allow-list stays a reviewed inventory rather than a stale comment.

- **Busbar can front a local MCP server that has no URL — `transport: stdio`.** Most of the MCP
  server estate is not on a network: a filesystem server, a database server, a git server, the
  reference servers the SDKs ship. They are programs an agent LAUNCHES, and they speak JSON-RPC on
  their own stdin and stdout. Busbar now launches them too, so the same governance every other
  upstream gets — the caller's grant, the catalogue filter, the schema pin, the budget charge, the
  per-call log — applies to them as well:

  ```yaml
  tools:
    filesystem:
      transport: stdio
      command: /usr/local/bin/mcp-server-filesystem   # absolute, always
      args: ["--root", "/srv/shared"]
      env:
        LOG_LEVEL: info
        UPSTREAM_KEY: { env: FS_SERVER_KEY }          # a reference, never a pasted secret
      pin: { mechanism: unpinned }
      tools_allow: { read_file: {} }
  ```

  A stdio registration takes `command:`, `args:`, `env:` and `cwd:` instead of `url:`, and Busbar
  refuses at boot — not at the first tool call — if you mix the two, or if `command:` is anything
  other than an absolute path.

  **What Busbar does to keep a spawned process from being a hole in your gateway.** There is no
  shell: the program is executed directly and the arguments are a list, so no character in either
  has a second meaning. The path must be absolute, because a bare name is resolved through `PATH`
  and would let whoever controls Busbar's environment choose the binary that runs instead of you.
  **The child does NOT inherit Busbar's environment** — it is spawned with a cleared one and exactly
  the variables you named, because Busbar's own environment holds your provider API keys, your store
  credentials and your admin tokens, and handing that set to a configured child would make every
  stdio registration a way to read them. A tool call's arguments reach the child as JSON on its
  stdin and never as command-line arguments.

  **A child that will not start does not become a fork bomb.** Busbar supervises the process: it
  restarts a crashed child with an exponential backoff, and after five crashes in a minute it stops
  restarting and refuses calls to that server with a message saying so. Fixing the `command:` and
  re-applying the config is what re-arms it; nothing re-arms itself on a timer. Editing `command:`,
  `args:`, `env:` or `cwd:` retires the running child and starts the new one, and deleting the
  registration stops its process rather than leaving it running unreachable.

  Busbar being LAUNCHED as a child itself — serving MCP on its own stdin to one agent — is
  deliberately not supported, and `qa/method-coverage.status` records why: every control Busbar
  exists to apply is scoped to a long-lived multi-tenant listener, so a Busbar inside one client's
  own process would be a governance gateway with the governance switched off.

- **Busbar can be an MCP server, and agents log into it exactly as they log into anything else.**
  Add an `mcp:` block naming your endpoint's canonical URI and your identity provider, and Busbar
  mounts an MCP endpoint plus the OAuth 2.1 discovery surface that lets an agent find its way in with
  no prior configuration: it connects with no credential, receives a `401` whose
  `WWW-Authenticate` header points at an RFC 9728 protected-resource metadata document, follows that
  to your IdP, does ordinary OAuth, and comes back with a token. Busbar then checks the token's
  audience is Busbar itself (RFC 8707) before anything else happens, which is what stops a token
  your IdP legitimately issued for some other service being spent against Busbar's pools and budget.
  Tokens are minted by your existing IdP; Busbar issues none.

  Without an `mcp:` block nothing changes: no endpoint, no metadata document, no new routes.

  The endpoint speaks MCP revision `2026-07-28` (the stateless streamable-HTTP revision: no
  handshake, no sessions, no resumable stream) and enforces its transport rules: mirrored
  `Mcp-Method` / `Mcp-Name` headers must agree with the request body, `GET` and `DELETE` answer
  `405`, an unknown method answers `404`, an unlisted browser `Origin` answers `403`, and a request
  whose `params._meta` omits its protocol version or its client capabilities answers `400` with
  `-32602` rather than having either inferred for it.

- **Busbar serves A2A over gRPC, and its agent card says so.** The A2A specification defines three
  bindings of one agent, and this release arms the third. It serves the gRPC binding at
  `/lf.a2a.v1.A2AService/*`, on the same listener as everything else (cleartext HTTP/2:
  no second port, no second TLS configuration, no second address to firewall), and the card served
  at `/.well-known/agent-card.json` advertises `protocolBinding: "GRPC"` beside `"JSONRPC"` and
  `"HTTP+JSON"` so a conformant client can select it. A gRPC interface publishes an AUTHORITY rather
  than a URL, because that is what a gRPC channel is opened against.

  It is the same endpoint, not a second one. A gRPC call goes through the same audience check, the
  same per-key authorisation, the same catalogue, the same durable task store, the same budget and
  the same audit chain as the JSON-RPC call beside it: there is one admission path and one task
  store, so "what happened" has one answer whichever binding a caller used. The protobuf types and
  the service definition are the A2A project's own, generated from the `a2a.proto` it publishes.

  It is published on the plane's OWN card only. A fronted agent's card advertises `JSONRPC` alone,
  for the same reason it does not advertise HTTP+JSON: a gRPC channel is dialled at an authority and
  the agent is resolved from the caller's catalogue there, so a per-agent card claiming gRPC would
  send a client somewhere that answers a different question.

  Nothing changes for a deployment that does not front agents: without an `agents:` block and a
  `public_url` there is no A2A plane and no gRPC route.

- **The MCP tool surface answers, in both directions.** `server/discover`, `tools/list`,
  `tools/call`, `prompts/list`, `prompts/get`, `resources/list`, `resources/templates/list`,
  `resources/read` and `completion/complete`
  are served, and Busbar calls OUT to the upstream MCP servers you register under
  `tools:`, so Busbar is a governed gateway in front of your tool estate, not only an endpoint that
  speaks the protocol.

  What a caller SEES and what it may CALL are one decision, taken from that caller's own key
  grants: two callers holding two different grants get two different catalogues from the same
  deployment, and a caller whose grant reaches nothing gets an empty catalogue rather than an error.
  A call is admitted on the snapshot it arrived on and re-validated against the live one before it
  is dispatched, so a tool you de-approve stops being callable on the next request rather than at
  the end of a session. The credential Busbar spends upstream is selected under the INBOUND
  caller's grant, so Busbar cannot be talked into spending an authority the caller does not hold.
  Descriptions, prompt templates and tool output are markup-normalised on the way through, because
  each of them re-enters a model's context.

  Every list result carries this revision's caching hints, and both values are deliberate:
  `cacheScope: private`, because a catalogue computed under a caller's grant must never be served
  by a shared cache to a caller who holds none of it, and `ttlMs: 0`, because a stateless server has
  no channel to invalidate a stale catalogue over and any freshness window would be a promise it
  could not keep.

  A prompt registered with `{placeholder}` spellings now has them SUBSTITUTED from the arguments a
  client sends on `prompts/get`; before, the arguments were ignored and the caller received the
  template unchanged. Substitution happens BEFORE the markup strip, so a value supplied on the
  request is normalised exactly as the operator's own template is. An argument value ends up in a
  model's context and is the more attacker-controlled of the two. A placeholder you supply no value
  for is left visible rather than emptied, so a missing argument stays legible instead of producing
  a prompt that reads as complete and means something else.

  `completion/complete` answers, with an empty completion set: Busbar's registry declares no value
  sets for prompt arguments, so there are no suggestions to give, and "none" is a complete answer
  where `404` would wrongly say Busbar does not speak completion at all.

  **An MCP deployment may not have an anonymous front door.** An `mcp:` block together with an
  empty `auth.chain` is now a configuration error and Busbar will not start: a request that carries
  no key is never narrowed by one, so it would run with wildcard grants over every registered
  server and every approved tool, and there would be no inbound grant to bind Busbar's outbound
  credentials to. Close the data-plane chain, or drop the `mcp:` block.

- **Every MCP tool call is now written to a tamper-evident, per-caller durable record.** Point
  Busbar at a durable store (`store: sqlite`/`postgres`/`valkey`/`mysql`) and each inbound
  `tools/call` appends one row to that caller's own hash-linked chain: who called, which tool, under
  which approved schema digest and which registry generation, whether it went out, and (when it did
  not) a stable refusal token you can group on. Refusals are recorded as deliberately as successes:
  the record an auditor asks for first is the one where somebody asked for something they could not
  have. Each row links to the previous row for the same caller, so an altered, reordered, inserted or
  removed row is detectable afterwards. Chains are read back and VERIFIED at boot, and any break is
  logged at `ERROR` naming the caller and the position, while the rows stay restored. Refusing to
  restore an unverifiable chain would let anyone who can write to your store delete a caller's whole
  history by corrupting one byte.

  Read the claim precisely: this is tamper-EVIDENCE, not tamper-prevention. It detects after the
  fact; it does not stop a write, and a host compromised at the moment of writing can rewrite a whole
  chain consistently. Verification today happens at boot; there is no on-demand verify endpoint, so
  between two restarts a tamper is undetected. And there is no retention window for these records
  yet. A busy deployment's call log grows until you prune it yourself.

  With the default `store: memory` nothing is persisted and nothing is claimed: the log keeps chain
  positions in RAM, the boot restore reports zero, and that zero is the truth being reported.

- **Busbar's A2A endpoint now speaks the HTTP+JSON binding as well as JSON-RPC, and the agent card
  says so.** A2A defines the same agent as several bindings of one endpoint, and a client picks one
  from the card. Busbar previously advertised and served only JSON-RPC, so a client built against the
  REST binding could not reach it at all. The same endpoint now also answers `POST /message:send`,
  `POST /message:stream`, `GET /tasks`, `GET /tasks/{id}`, `POST /tasks/{id}:cancel`,
  `POST /tasks/{id}:subscribe`, the `pushNotificationConfigs` collection and `GET /extendedAgentCard`,
  and the `HTTP+JSON` interface is published on the card busbar serves for itself. Errors come back
  in the REST binding's own representation: the HTTP status in `error.code`, the canonical status
  name, and the structured `details` a conformant client reads.

  These paths hang off the plane's own endpoint, and the card busbar serves for an individual fronted
  agent still advertises `JSONRPC` alone — because that per-agent address answers the JSON-RPC
  envelope and nothing else. Busbar advertises what it serves at the address it is advertising, never
  what it serves somewhere else; a card entry sending a conformant client to an address that does not
  answer that binding is worse than no entry.

  Nothing about a request changes except how it is spelled. Both bindings run one admission, one
  budget check, one outbound-credential decision, one callback guard and one audit record, and both
  require the same audience-bound credential. A binding is a way of writing a request down, never a
  way around what busbar does with it.

  Agent traffic on `/metrics` gains a second value for the dialect label: `http+json` beside
  `jsonrpc`. Existing agent-plane series are unchanged and JSON-RPC traffic keeps reading `jsonrpc`.
- **Hooks fire on MCP tool calls and on A2A submissions.** `tools.hooks:` /
  `tools.<server>.hooks:` and `agents.hooks:` / `agents.<agent>.hooks:` have parsed and validated
  since 1.5.3 and did nothing: the grammar was there, the firing site was not. Now the same
  `hooks:` definitions you attach to a pool attach to a registered MCP server and to a registered
  A2A agent, with the same additive combine, and a `kind: gate` hook can **reject** a `tools/call`
  or a `message/send` before anything is dispatched.

  A hook receives the ordinary hook wire, projected from the request's IR rather than from a chat
  body: `pool` names the container (a pool, an MCP server, an A2A agent), `ingress_protocol` names
  the dialect, and — behind the same `prompt:` grant as always — `messages` carries the real
  payload: an MCP tool call's `arguments`, an A2A submission's `params` (a message's `parts`
  included). A gate written for the model plane screens a tool call with no change.

  `candidates` is empty on both planes, because these protocols route to the one registered upstream
  the caller's grant already selected: only `reject` applies, an `order`/`restrict` reply is ignored
  (logged at `debug`), and a gate that fails applies its own `on_error` exactly as it does on a pool.

  The gate runs on the DISPATCH path, never the catalogue — what a caller may SEE stays a question
  answered by its key grants alone. On MCP it runs after any `ask_caller` answers are merged, so a
  screen sees the arguments that would actually reach the upstream, and before the outbound
  credential is leased; on A2A before the meter, the egress gate and the task row. A refusal
  therefore costs no token exchange, no durable state and no hop, and it is recorded: the MCP
  per-call log carries the new reason token `hook_rejected`, distinct from `not_granted`.

  Deployments that attach no hook are unchanged and pay one hash lookup that misses.
- **A quarantined MCP upstream stays quarantined across a restart.** When the unattended sweep finds
  a registered upstream serving a tool list that disagrees with what you approved, it demotes it —
  and now writes that observation to your durable store. On the next boot the demotion is restored
  before the listener is bound, so a restarted Busbar refuses the upstream and stops advertising its
  tools instead of handing it its approval back until the next sweep.

  The record is cleared by the first observation that finds the upstream serving what you approved,
  which is how your remedy takes effect: fix the upstream, let the sweep look, and it serves again.
  Nothing else clears it — in particular a restart does not, and an upstream that goes unreachable
  cannot buy its approval back by going dark.

  A registration nobody has ever observed is untouched: with no record, it dispatches against the
  hash you wrote in config exactly as it always has. "We have never looked" and "it moved" are
  different facts, and a deployment that never runs a refresh keeps serving unchanged.

  With `store: memory` this is process-local as before: the demotion holds for the life of the
  process, and a restart re-opens the upstream for at most one sweep interval before the sweep
  re-establishes it.

- **An approval for a confirm-once tool can now be redeemed once per DEPLOYMENT, not once per node.**
  When you gate a tool behind `ask_caller:`, the sealed `requestState` Busbar mints is single-use.
  That record of "this one was already redeemed" now lives in your durable store, which closes two
  holes: a restart no longer hands back an approval that had already been spent, and — the one that
  matters at scale — two nodes sharing a signing key no longer redeem the same approval once each.
  Nodes share the key so that one exchange can span requests different nodes serve, which means they
  share the seal; without a shared ledger, a single operator confirmation executed a money-moving
  tool once per node, and the second redemption needed nothing more than a load balancer.

  With `store: memory` this remains what it was: single-use per node, for the life of the process.
  If the shared ledger cannot be reached, the redemption is REFUSED — a ledger that cannot say
  whether an approval was already spent must not be read as saying it was not.

### Changed

- **The embedded OAuth 2.1 authorization server moved to `oauth-as` 0.9.1, which is a security
  release published under a patch number.** Nothing an operator writes changes: the `oauth_as:`
  config block, the paths the plane mounts, the consent screen and the tokens it issues are all
  what they were. What changed is underneath, and four of the five items below are fixes rather
  than renames:

  - **A revoked refresh-token family can no longer be resurrected by an issuance already in
    flight.** In 0.9.0, detecting a stolen refresh token revoked the family, but a token being
    signed across an `await` could land behind the revocation and leave a live access token; the
    same held for authorization-code replay. 0.9.1 makes a revocation record a durable barrier and
    refuses the writes that would undo it. Busbar's exposure to the original defect was small
    rather than zero — the window scales with signing latency, and busbar signs locally and eagerly
    through `ring` — but it was never nil, and it is closed now.
  - **`acr_values` can no longer break a `WWW-Authenticate` header.** The RFC 9470 step-up
    challenge escaped `"` and `\` in the authentication-context classes it echoes, which is not
    enough: a CR or an LF has no legal spelling inside an RFC 9110 §5.6.4 `quoted-string` at all,
    and was being emitted verbatim out of a client-supplied query parameter. Control characters are
    now dropped, and the auth scheme is filtered to the `tchar` set for the same reason.
  - **`acr_values` can no longer be used as an allocation amplifier.** It is one unauthenticated
    parameter carrying a space-delimited list, one heap allocation per segment, at two bytes a
    segment. It is now capped at 16 classes and REFUSED rather than truncated past that.
  - **The RFC 7592 registration-management endpoint checks the credential before parsing the
    body**, so an anonymous caller can no longer buy a full JSON parse per request, and its
    bodyless error responses no longer claim a `Content-Type` they have no body for.

  One change is visible on the wire without being a defect: **the discovery document no longer
  advertises `introspection_endpoint`.** It used to be emitted unconditionally, defaulting to
  `{issuer}/introspect` — a path busbar has never mounted, so the RFC 8414 document named an
  endpoint that answered 404. It is now published only where the host sets it, and busbar does not.

  The library also renamed the seam busbar wires: what it now calls an APPROVAL (a per-request
  prompt, answered once) is distinguished from a CONSENT (a persisted, withdrawable grant). Busbar
  has only the first and stores none of the second, so the change is a rename in
  `crates/busbar/src/oauth_as/`, with no behaviour attached. The dependency tree is unchanged: the
  lockfile moves one version and one checksum and nothing else.

- **The documentation now states exactly what "lossless" covers, and what it does not cover yet.**
  An audit of the translation path (code read plus an executed read/write round trip per protocol,
  against the 1.6.0 tree) found the word doing more work than the engine earns on a cross-protocol
  hop, so the claim has been narrowed to what is checkable. Same-protocol routes are byte-for-byte
  identical to calling the provider directly, and that is now stated as the stronger claim it is:
  those routes never enter the IR at all, on the request side or the non-stream response side.
  Cross-protocol, every modelled field arrives in the target's native shape, and
  [Known gaps in 1.6.0](https://getbusbar.com/docs/protocols/#known-gaps-in-160) lists what does not
  cross: non-image attachments, citations coming from a Cohere backend, streaming citation deltas,
  usage sub-buckets such as `reasoning_tokens`, and the response-side safety and guardrail metadata. Two
  in-repo statements were wrong rather than merely vague and are corrected: `extra` never survives a
  cross-protocol hop for any writer (it is cleared unconditionally at the seam), and same-protocol
  routes do not "use the IR path".

- **Hooks now fire on the normalized IR — the same representation the request that goes upstream is
  built from.** Busbar had two answers to "what is the text in this request": the one every protocol
  reader produces, and a second one the hook seam re-derived from the raw ingress body with its own
  content flattening and its own per-dialect branching. They could disagree, and the disagreement is
  security-shaped rather than untidy: a PII/DLP gate wired as a `prompt: ro` hook screened the first
  view while the provider received a request built from the second — **so a screening hook could
  pass a request whose real payload it never saw.** One instance of that class had already shipped
  and been fixed inside a single hook. The second implementation is now deleted, so that class of bug
  cannot recur.

  This is operator-visible, and each change below applies at `prompt: ro` and `prompt: rw` alike.

  - **The system prompt reaches a hook in `system`, on every protocol.** A client that sends it as an
    in-band `{role: "system"}` turn no longer has it arrive as an ordinary message. Consequently
    **`message_count` is one lower** than the client's array length for such a body, and the
    `messages` projection is aligned with the normalized turns rather than with the wire array.
    A hook that guarded for an in-band system turn (Headroom carries such a guard) keeps working —
    the guard simply never fires again. A hook keying a heuristic off `message_count` sees the lower
    number. Media-only turns still keep their entry, so a hook never sees fewer turns than the
    provider does.
  - **A top-level `system` key on a dialect that does not define one is no longer projected as a
    system prompt.** It was being shown to hooks as one while the provider never received it as one.
  - **A conversation turn that omits its role is projected with the role that dialect defines for the
    omission** (rather than as an empty string). A hook that switches on role — "screen user turns
    strictly, trust assistant turns" is the common shape — no longer takes its default arm on
    caller-supplied input.
  - **An OpenAI `refusal` content part is now projected** and counts toward `total_chars`. A
    guardrail could not previously screen a replayed refusal.
  - **Tool-call ARGUMENTS are now projected**, attributed to the turn that made the call. They are
    the most attacker-influenceable field in an agent request and went upstream verbatim while the
    projection showed a gate nothing at all for that turn. Tool results were already projected and
    still are. This is a widening of an already opt-in, `full`-scope-gated grant, in the same spirit
    as the reasoning-text widening: if your hook logs or forwards the projection verbatim, it now
    carries tool arguments too.
  - **A request body Busbar cannot read is rejected with a 400 rather than forwarded.** Five protocol
    readers hard-reject a turn whose role they do not recognise; such a body used to be forwarded
    upstream while the hook was told the role was an empty string. That is the fail-open shape, and
    the rejection is unconditional rather than keyed on whether a content hook happens to be
    configured.
  - **An out-of-range `max_tokens` is reported as absent rather than saturated.** The value a hook
    sees is now the cap that actually governs the request.
  - **A Bedrock Converse caller's `inferenceConfig.maxTokens` now reaches the `max_tokens` signal.**
    This is a straight fix: the old projection read `max_tokens`, found nothing on that dialect, and
    reported no cap — so a routing policy keyed on the size signal was blind to a Bedrock caller's
    cap in exactly the way every Responses request used to be.
  - **A Responses `reasoning` item carrying only an opaque `encrypted_content` blob projects the
    `[busbar:redacted_reasoning]` marker**, as the Anthropic and Bedrock redacted shapes already did.
    Provider ciphertext still never reaches a hook, on any of the three shapes.

  `docs/hooks.md` said hooks fire on the normalized IR before they did. That sentence is now true.

- **`limits.hook_content_max_bytes` bounds what a content-granted hook is shown** (default 65536;
  `0` disables the ceiling). Over-cap content is omitted WHOLE — never truncated mid-value, because a
  guardrail that screens half a payload and passes it is worse than one that refuses — and the hook
  receives a present-but-empty content projection while the size fields still report the real totals,
  so an omission is stated in the payload rather than hidden. `busbar_hook_content_truncated_total`
  counts it. This bounds the tool-argument and tool-result widening above, which on an agent request
  is limited by neither a context window nor a token count.

- **The `operation` label reads `invoke`, not `tool_call`.** The operation that carries "a caller
  names a target, hands it arguments, and gets content or an error back" now also carries A2A
  `message/send`, so it is no longer named after one protocol's method. The same string is the
  `paths:` configuration key for that operation, so a `paths:` entry keyed `tool_call` must be
  re-keyed to `invoke`. The five operations that arrive alongside it (`catalogue`, `fetch`, `task`,
  `subscribe` and `control`) publish those names as their label and their key.

- **BREAKING (metrics): `busbar_requests_total` and `busbar_request_duration_seconds` gained a
  `plane` label, and the model plane's existing series carry it too.** The values are `llm`, `mcp`
  and `a2a`. If you group or join on the full label set of either family (a recording rule, a
  `group_left`, a panel legend built from `{{...}}`), those series are NEW series after this
  upgrade, so counters restart from zero at the changeover and a `rate()` window spanning the
  restart will read low once. Queries that only aggregate (`sum(rate(busbar_requests_total[5m]))`)
  are unaffected. To keep an existing panel exactly as it was, add `plane="llm"` to its selector;
  that matches precisely the traffic the panel used to describe, because before this release those
  two families described nothing else.

  We added the label to the model plane rather than only to the new planes on purpose. A label
  present on some series of a family and absent from others cannot be grouped by: `sum by (plane)`
  would bucket every model-plane series under the empty string, and an operator would have to know
  that the blank bucket means "LLM", which is a footnote, not a dashboard. One breaking change,
  once, buys `sum by (plane) (rate(busbar_requests_total[5m]))` meaning what it says.

### Removed

- **The MCP stdio child-process supervisor has been deleted, and `transport: stdio` says so
  plainly.** Busbar carried a complete, tested supervisor for local stdio MCP servers (spawn, reap,
  a `spawning → ready → draining → dead` lifecycle, capped restart backoff and a
  five-crashes-in-a-window circuit breaker) that **nothing could ever call**: there is no dispatch
  path for a stdio upstream, and `transport: stdio` has always been refused at config validation. It
  is removed rather than wired, because unreachable code that reads as a shipped resilience feature
  is worse than an absent one: it is the kind of thing that ends up in a security questionnaire
  answer. The MCP design commits to no stdio build for this release. All three transports are
  DESIGNED, the transport baseline at ship is explicitly still open, and the owner rulings that
  override earlier sections say nothing about it.

  Nothing an operator can configure changes: `transport: stdio` was refused before and is refused
  now, with a message that no longer implies a supervisor exists somewhere waiting to be switched
  on. The `process` feature was dropped from Busbar's async runtime along with it, so Busbar's
  release binary can no longer spawn a child process at all, which is also what stops an
  unreachable supervisor being re-introduced quietly, since doing so now fails to compile.

### Fixed

- **The A2A gRPC binding could not serve Busbar's own extended Agent Card — it answered
  `INTERNAL` to every caller.** `GetExtendedAgentCard` was mounted and written, and the call failed
  inside the protobuf transcode: Busbar's card declares `capabilities.stateTransitionHistory` — an
  A2A v0.3 member, and one the specification's own sample card in section 8.5 declares — while
  `a2a.proto`'s `AgentCapabilities`, which the specification makes normative, has no such field. The
  generated ProtoJSON type rejects unknown members, so the member did not get dropped: the whole
  card failed to render. A gRPC client asking Busbar what it may reach got `grpc-status 13` and no
  card.

  The gRPC answer now carries the card minus the members a protobuf `AgentCard` has no field for,
  from a named list rather than by ignoring whatever fails to parse. **The card served over JSON-RPC
  and HTTP+JSON is unchanged** and still carries every member it did: this is not Busbar reshaping
  the document A2A clients read, it is the one binding whose wire format cannot represent a member
  carrying the rest of the card instead of nothing.

  It was invisible to the official A2A TCK by construction — `CARD-EXT-002` skips itself once a card
  is configured, and `CORE-CAP-003` only passes for a server that does *not* implement the verb — so
  a Busbar that answered this perfectly and one that answered `INTERNAL` produced identical suite
  output. It was found by a new in-tree test that drives the real mounted service path over h2c.

- **MCP and A2A traffic was invisible on `/metrics`. It is now on the same series as model
  traffic.** `busbar_requests_total` and `busbar_request_duration_seconds` were emitted from the
  model plane's ingress and nowhere else, so a tool call and an agent task produced no sample at
  all: not an under-labelled one, none. An operator watching a dashboard saw model traffic and had
  no signal that the tool or agent plane was refusing or timing out every request. Both planes now
  emit the same two families, with the same `outcome` vocabulary (`ok` / `client_error` /
  `exhausted` / `error`) and the same label keys, distinguished by the new `plane` label. A refusal
  issued before the handler runs (a `401` on an audience-bound MCP endpoint, for instance) is
  counted too, because the emission happens at the plane's door rather than inside its handler.

  The `pool` label reads `unresolved` on both new planes for now: it names the routing target a
  request resolved to, and neither plane's door resolves one. Narrowing it to the configured tool
  server / agent is a follow-up and will not change the series shape.

- **`busbar --validate` now checks every secret reference in the config, including the ones it used
  to walk straight past.** 1.5.3 made `--validate` resolve `env:` and `file:` references and exit 1
  when one could not resolve, but the set of references it knew about was a hand-written list of
  config paths, and `identity-providers.<name>.browser_login.client_secret` was not on it. A config
  whose OAuth confidential-client secret named an unset variable was reported as `ok: config valid`
  and then failed every hosted login at runtime. Every secret reference on the typed config surface
  is enumerated now, and each is named by its full config path in the error. If your `--validate` job
  goes red on an identity provider after this upgrade, the credential it names genuinely could not be
  resolved in that environment; that is the answer 1.5.3 intended to give you.

## [1.5.3], 2026-08-08

This release reshapes the config file, so give yourself a few minutes for the upgrade.
`busbar --migrate-config <config.yaml>` does most of it for you and tells you what it changed. Busbar will
not start on the old spellings, which is deliberate: a config that quietly means something different is
worse than one that stops and says so.

Every breaking change below is a config change. If you would rather see the finished shape than a list of
edits, [config at a glance](docs/config-at-a-glance.md) is one annotated file with
every section on a single page, and [the 1.5 migration guide](docs/migration-1.5.md) walks the path from
1.4.

### Breaking changes

- **`busbar --validate` now resolves `env:` and `file:` secret references, and exits 1 when one of
  them cannot be resolved.** It previously checked only that the reference was well formed and exited
  0, so a config naming an unset variable reported "ok: config valid". A CI job that runs `--validate`
  without production secrets in its environment will now go red: give that job the environment
  variables and files your config names, or point it at a config whose references resolve there. Boot
  is unchanged, an unresolvable reference still logs a warning and Busbar still serves. See
  [the operations guide](docs/operations.md#validating-configuration-busbar---validate).
- **The Redis-protocol store plugin is now Valkey.** Change `store.module: redis` to `valkey` and
  install the `busbar-store-valkey` artifact. Your connection URL does not change. Re-pin any plugin
  version pin under the new name, and delete the old plugin file from your plugin directory.
- **Hooks are defined once by name and attached by name.** Inline hook definitions and
  `global_hooks:` no longer load: define each hook under the top-level `hooks:` block and list its name
  under `pools.hooks:` (every pool) or under one pool. Stage names are now `request`, `candidate`,
  `routing` and `response`; the old `route`, `attempt` and `completion` fail at startup. A pool may not be
  named `hooks`. A hand-written hook with no stage list now fires at all four stages rather than once per
  request; set `phase: [request]` for the old behaviour. See [the hooks guide](docs/hooks.md).
- **Identity providers are defined once by name and referenced by name.** Define each under the
  top-level `identity-providers:` block; `auth.chain:` and `auth.admin_auth:` are lists of those names. The
  `auth.methods:` block is gone and its contents belong on the provider, `auth.role_bindings:` is keyed by
  provider name, and an unstated admin trust ceiling is now the most restrictive one. A ceiling can only be
  raised in the config file, never through the admin API.
- **Export sinks are named, and `observability:` is gone.** Write `export:` as
  `<your-name>: {module, settings}` rather than keyed by type, which lets you run two sinks of one kind,
  for example one request log to your own store and one to a SIEM. `generic-webhook` is now part of
  `request-log-webhook`. Move `observability.otlp_url` to an export sink using the `otlp` module. See
  [the observability guide](docs/observability.md).
- **Response headers are off by default.** Everything Busbar used to add to a response, timing
  and route headers included, must be enabled under `advanced.response_headers`.
  `observability.emit_server_timing` no longer exists. Enable what your dashboards and clients read.
- **`admin_insecure` is now `admin_require_mtls`, with the meaning reversed** and safe by
  default. A network-exposed admin listener with no client CA still refuses to start; the waiver is now
  `admin_require_mtls: false`.
- **Upstream credentials are configured per pool.** `auth.upstream_credentials` moves to
  `pools.upstream_credentials`, and any pool can override it.

### Added

- Identity providers and export sinks can be managed through the admin API, as hooks already were. See
  [the admin API reference](docs/admin-api.md).
- Config changes made through the admin API now survive a restart out of the box. Set `config.locked: true`
  to make the file the only way to change configuration.
- Plugins can serve their own HTTP endpoints.
- A plugin's own log lines now reach your log sink. Store, auth, hook and secret plugins previously had
  their logging discarded or written straight to stderr, so lines like a failed token-signature check or
  an ambiguous directory match never appeared. They now arrive through Busbar's logging with their level
  and structured fields intact, named by plugin, and are filtered by `RUST_LOG` like everything else.
  Existing signed plugin artifacts keep loading unchanged.
- A guide to pointing Busbar at a local inference server (Ollama, LM Studio, llama.cpp, vLLM): what to
  put in your own `providers.yaml`, how local members mix with hosted ones in a pool, and what changes
  when Busbar runs in Docker. See [the providers guide](docs/providers.md).

### Changed

- Operational settings that were environment variables are now config keys: `BUSBAR_PROVIDERS`,
  `BUSBAR_CONFIG_OVERLAY`, `BUSBAR_WORKER_THREADS`, `BUSBAR_UPSTREAM_HTTP1_ONLY` and
  `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE`. Each still works for one more release, and the config key wins if
  you set both. `BUSBAR_CONFIG` is unchanged.
- The `persist` field on admin config calls is ignored: durability is now a property of the deployment.
- The admin hooks API calls the field `module` rather than `plugin`, matching the config file. `plugin` is
  still accepted.
- Every durable store now answers the same way for the same request, where the answer used to depend on
  which store you had deployed. Deleting a key that never existed is an error rather than a silent
  success, deleting one already deleted stays a success, revoking an already-revoked credential is a
  success while revoking an unknown one is an error, and an audit write that lands on an occupied
  position is a success only if the record is identical and an error if it differs. Tooling that read a
  lenient backend's silent success as confirmation should be checked.

### Fixed

- Admin reads returned the raw values of a module's settings, including credentials such as a client secret
  or a store password. They now return only the setting names.
- Deleting or rotating a key could return an error while the key went on working, and flushing the
  authentication cache could return success without revoking anything.
- An admin deletion of a user's self-serve key survived only until that user's next login, which
  silently recreated the deleted credential and put every token minted before the deletion back into
  service. The deletion now stands.
- Rotating a user's self-serve key and then changing their group's pools left the user holding two
  valid keys at once, each metering and enforcing budget separately, so spend was counted against two
  buckets and neither reflected the real total.
- A hook that could not reach its own dependency had no way to say so, so it read as "no opinion" and
  a gate configured with `on_error: reject` admitted the request instead of refusing it. A hook can now
  report the failure and `on_error` applies. See [the hooks guide](docs/hooks.md).
- Busbar sent an empty `client_secret` when exchanging a code for a public identity-provider client.
  An identity provider is entitled to read an empty secret as a wrong one and answer `invalid_client`,
  so browser login against a public client could fail outright. The parameter is now omitted when
  there is no secret; a confidential client is unaffected.
- The SSRF guard on an OTLP export sink checked only the literal text of the collector endpoint, so
  `https://169.254.169.254/v1/traces` was blocked while a hostname resolving to that same cloud
  metadata address was allowed through. Span data carries key ids, pool names and governance
  decisions, so the endpoint is now resolved and every resulting address is checked. A collector whose
  DNS is briefly unavailable is not treated as a rejection. See
  [the observability guide](docs/observability.md).
- Budget accounting could allow spend it should have blocked: an exhausted lifetime budget on a group with
  an email-shaped name reset to zero on restart, deleting one principal could reclaim another's budget, and
  deleted groups left budget entries behind that no admin call could see.
- Admin config writes could report success without taking effect. An unknown field was accepted then
  dropped at reload, `config.locked` was not enforced on two endpoints, and a write with nowhere to persist
  returned success.
- An identity provider's `max_admin_scope` was ignored, leaving it read-only even when you granted more.
- `busbar --migrate-config` could change or drop what you wrote: a hook attached with a single value rather
  than a list migrated to a pool with no hooks and still passed `--validate`, so a compliance gate could
  vanish silently; an unrecognized budget period became a lifetime cap; a yearly budget carried onto a
  monthly window unrescaled, a twelve-fold increase; and a provider used on both planes could lose one
  plane's settings.
- Busbar could refuse to start in a writable directory when the config file was named with no directory
  path.
- The request-log file export could grow without bound if the destination stalled, and every webhook export
  shared one queue limit, so a slow sink could consume capacity you had capped elsewhere.
- A hook whose settings referenced a secret reported a settings mismatch on every check, forever.
- `advanced.worker_threads: 0` was silently ignored instead of reported.

## [1.5.2], 2026-08-02

### Breaking changes

- **`auth.chain: [keys]` with no way to mint an admin token now refuses to start.** It previously
  booted as a silent open relay admitting anonymous requests. Give `auth.admin_auth` an `admin-tokens`
  entry with a `token:`, or an admin module granting `mint` or `full`, or set an explicit `admin_auth: []`
  for development. See [the 1.5 migration guide](docs/migration-1.5.md).

### Changed

- Setting an admin token no longer forces data-plane requests to carry a virtual key, so `chain: []` plus
  an admin token is now an open relay with a protected admin API.

## [1.5.1], 2026-08-02

### Breaking changes

- **Busbar no longer generates a signing key at boot.** If `auth.chain` names the built-in `keys`
  verifier, `auth.signing_key` is required and startup fails without it. Generate one with
  `busbar --generate-signing-key` and point `auth.signing_key` at a file or environment variable. It is
  fleet-shared, so generate once and distribute to every node; rotating it revokes every outstanding key.
  1.5.0 wrote this file itself beside your config, which boot-looped on a read-only mount.

### Added

- `/stats` and `/metrics` report why a lane cannot take a request (at capacity, breaker open, dead, budget
  exhausted), when it might recover, and how many requests are parked. See
  [the observability guide](docs/observability.md).
- `on_exhausted: { queue: { max_ms } }` holds a request for a bounded wait when every pool member is at
  capacity, then dispatches it or falls through to `reject`.

### Changed

- A pool whose members are all at `max_concurrent` now spills or sheds per `on_exhausted` instead of
  queueing to the failover deadline, so a burst against a small pool with a cloud overflow pool spills
  immediately rather than serializing.
- `busbar_lane_at_capacity` is replaced by `busbar_lane_available`. Update dashboards that use it.

### Fixed

- `on_exhausted: least_bad` returned a 503 when the best member was at capacity even though a sibling had a
  free slot.
- `Retry-After` on an exhaustion 503 always said one second under saturation, rather than the real cooldown.
- `limits.max_inbound_concurrent` queued excess requests behind the cap instead of shedding them, so
  clients got no backpressure.

## [1.5.0], 2026-08-01

The config, identity and cost release. The config file changed shape and every 1.4.x virtual key stops
working, so plan the migration and the key rotation together. The data-plane HTTP surface is unaffected: an
application posting to `/v1/chat/completions` gets a byte-identical response after the upgrade.

### Breaking changes

- **The config file changed shape and a 1.x config refuses to start.** Run
  `busbar --migrate-config <old.yaml> > config.yaml`, review every WARNING and TODO it prints, then run
  `busbar --validate`. Read every `allowed_pools: []` carefully: its meaning flipped from all pools to no
  pools.
- **Every 1.4.x virtual key stops working and must be re-minted** through
  `POST /api/v1/admin/keys`, with the new tokens rolled out to callers. Keys are now signed tokens that
  expire (90 days by default) and can be revoked fleet-wide, where a 1.x key was a bearer secret that never
  expired.
- **A durable store is dropped and recreated on first open.** Usage history resets with it.
- **Limits moved off keys and onto groups.** `rpm_limit`, `tpm_limit`, `max_budget_cents` and
  `budget_period` are gone from minting, from `PATCH /keys/{id}` and from key metadata; a key resolves to a
  group and the group carries the limits. The per-key `busbar_key_budget_remaining_cents` gauge is gone
  with them, so use the bucket gauges.
- **The `governance:` block is gone.** `store`, `rate_card`, `per_request_fee`, `groups` and
  `advanced` are top-level, and the admin token is a secret reference on the `admin-tokens` module.
  `governance.enabled` and `governance.budget_on_store_error` no longer exist. Handled by
  `--migrate-config`.
- **Static token auth is gone.** The `tokens` module and `auth.client_tokens` are removed;
  data-plane auth is the built-in `keys` verifier or an identity provider.
- **The top-level `hooks:` registry is gone,** with the hook `global:` and `default:` flags. A
  hook instance is referenced inline in a pool's `hooks:` list or in `global_hooks:`. (Reversed in 1.5.3,
  which restores a named `hooks:` definition map.)
- **`cost_per_mtok` on pool members and `governance.price_per_1k_tokens_cents` are gone.**
  `rate_card:` is the only cost source; `--migrate-config` synthesizes entries and flags them for review.
- **Config aliases are gone, one canonical name each.** `window_s` becomes `window_secs`, `n`
  becomes `consecutive_n`, `deadline_secs` becomes `timeout_secs`, `cap` becomes `max_hops`,
  `otlp_endpoint` becomes `otlp_url`, a member's `target` becomes `model`, `api_key_env` becomes
  `api_key: { env: ... }`, and `auth.mode` becomes `auth.chain` plus `auth.upstream_credentials`.

### Added

- **`groups:` is the one place limits live:** a named tree where requests, tokens, budget and concurrency
  all use one shape. Admission checks every group up the chain and a rejection names the bucket that
  blocked it. A user is just a leaf group under their team. See
  [the configuration guide](docs/configuration.md).
- A limit can carry `pool: <name>`, so a team's spend splits across model tiers and exhausting the frontier
  budget stops only frontier traffic.
- A pool-scoped budget can declare `on_exhaust: downgrade` with `downgrade_to: <pool>`, so running out
  routes to a cheaper pool instead of refusing the request.
- Groups are editable live over the admin API with no restart, past accrual survives the edit, and
  per-group usage is readable at `GET /api/v1/admin/groups/{name}/usage`.
- `POST /api/v1/admin/keys` can auto-provision a personal group under a parent, and the new `mint` admin
  scope lets a portal issue keys without full admin rights. `limits.max_keys_per_principal` caps how many
  keys one principal may hold.
- `rate_card:` is the only source of cost, priced per model and tier. Omit it and everything prices at
  zero; include it and it must be complete, with a missing model failing startup with a paste-ready stub.
- Every secret in the config is a reference: `{ env: VAR }`, `{ file: /path }`, or a secret plugin for a
  vault or cloud secret manager.
- **Durable stores are plugins.** SQLite, Postgres and Valkey ship as signed tarballs you install and name
  in `store.module`; the compiled-in `memory` store is still the zero-setup default. See
  [the plugins guide](docs/plugins.md).
- Store, secret, identity and hook plugins share one signed artifact format and trust model. Unsigned,
  tampered or unknown-publisher plugins are skipped and never loaded; `trust.allow_unsigned` and
  `trust.allow_third_party` are opt-ins that default to off, and `plugins.min_versions` sets
  anti-downgrade floors.
- Identity providers are plugins: name one in `auth.chain` and it loads at boot, and one that cannot load
  is a hard startup failure rather than a silently open front door. The bundled `oidc` module is the first.
- Hooks are signed plugins loaded in process. Two ship with this release: `busbar-headroom-hook` compresses
  prompts before dispatch, and `busbar-webrequest-hook` forwards to an HTTPS sidecar you run yourself. The
  socket and webhook transports remain as built-in hook modules.
- Plugins can be listed, installed, removed, hot-reloaded and rolled back over the admin API with the same
  trust checks boot applies. Changing the store module still needs a restart.
- `GET`/`PUT /api/v1/admin/config/settings` covers every config section, and `POST /api/v1/admin/restart`
  applies the settings that need a restart (listeners, TLS, store backend) without shell access.
- Admin config changes persist to a Busbar-owned overlay file and your `config.yaml` is never written.
  `DELETE /api/v1/admin/overlay/{section}` reverts one section back to the file.
- `busbar --validate` covers the whole new surface with paste-ready fixes, and `busbar --list-plugins`
  prints the plugin inventory without loading plugin code.
- Spend, budget-remaining and token metrics are labelled by group and window, and key labels set at mint
  time echo onto per-key series, so a dashboard can sum by team.

### Changed

- The SemVer contract is now stated explicitly: the frozen surface is the data-plane HTTP surface and the
  wire protocols. `config.yaml` is an operator artifact outside that freeze and may change between
  releases, always with a migration path and a loud failure on an outdated config. The admin API carries
  its own version.
- Spend is derived, not stored. The store keeps a token ledger and money is computed at read time from the
  current rate card, so correcting a rate is a config edit and a reload with no re-billing.
- `PATCH /keys/{id}` takes `enabled` and `group` only; the 1.4.x cap fields are rejected.
- A hook granted `prompt: ro` or `prompt: rw` now also sees reasoning and thinking text, which it could not
  see before even though that text reached the provider in full. Nothing to configure, but review any path
  where your hook forwards or logs that projection. Opaque redacted reasoning is still never plaintext.

### Fixed

- An exhausted budget could be spent again: a request straddling a window boundary could rewind a live
  budget cell and zero its totals, a store error while loading budgets at boot started with empty counters,
  and a large enough ledger overflowed the derived total to a negative number that read as free.
- A caller could escape the `requests` limit by hammering failing requests, because the refund on a non-2xx
  outcome also refunded the admission slot.
- An identity provider could hand a caller a principal id shaped like a real key or group and take over
  that budget bucket.
- A typo in a security-relevant config key was silently ignored, so `client_c:` for `client_ca:` disabled
  mTLS without complaint. Unknown fields now fail startup.
- Concurrent budget flushes could double-count spend against a shared store, the Valkey store wrote
  duplicate audit entries, and store errors could include the connection password.
- An environment variable interpolated into the config could splice extra structure into it, for example
  widening an allowlist.

## [1.4.1], 2026-07-20

### Changed

- The repository moved to [`github.com/GetBusbar/busbar`](https://github.com/GetBusbar/busbar); older links
  redirect. Verify release artifacts with `--repo GetBusbar/busbar`. The Docker Hub image is unchanged.

### Added

- Every tagged release attaches the admin API's OpenAPI document, so you can generate a client or diff the
  API surface without running the gateway.

## [1.4.0], 2026-07-19

### Added

- **Google Vertex AI, Azure OpenAI and Oracle OCI Generative AI, all as configuration rather than code.**
  See [the providers guide](docs/providers.md).
- Two new ways to authenticate outward to a provider: `auth: jwt-bearer` (a signed assertion, which a
  Google service-account JSON satisfies directly) and `auth: oauth-client-credentials`. Both refresh in the
  background before expiry.
- `path_base`, `token_url` and `scope` provider fields, which is what lets the above reach non-standard
  provider URLs without new code.

### Changed

- **The default worker-thread count is one per available core** rather than a cap of four, so throughput
  scales with the machine. It reads the node's core count and cannot see a CPU bandwidth quota, so on a
  Kubernetes pod with a CPU limit it oversubscribes: **pin `BUSBAR_WORKER_THREADS` to your CPU limit
  there**, or to `1` or `2` in a footprint-sensitive sidecar.
- **Memory now falls back toward idle after a burst instead of staying at the peak:** a soak that plateaus
  around 1.2 GB drops to roughly 250 MB within 30 seconds of the load stopping. Windows builds keep the
  system allocator and do not get this.
- A cross-protocol stream whose backend reports usage in a trailing chunk now folds it into the terminal
  frame, so a non-OpenAI client receives real token counts instead of zeros. A Gemini JSON-array client on
  such a stream now receives one extra trailing element carrying that usage.

### Fixed

- **Budgets shared across several nodes no longer clobber each other:** the usage flush writes the delta
  since the last flush rather than an absolute value, so nodes sharing one store sum to the true total.
- The Valkey store's key deletion and credential writes are now atomic, so a partial failure cannot orphan
  an upstream credential behind a deleted key. It also gains reconnect and `rediss://` TLS.
- The token endpoint an OAuth provider posts its client secret to was checked less strictly than the
  provider base URL, so a typo could send the secret to a cloud metadata address. Both self-minting clients
  now also refuse redirects and carry timeouts.
- Health probes were not re-spawned on config reload, so reloaded lanes went unprobed and each reload
  leaked probe tasks.
- A `scope:` configured on a `jwt-bearer` provider was ignored, and a mid-stream transport error billed the
  tokens accumulated before the cut.
- A Cohere backend's pre-tool-call reasoning was dropped on any hop to another protocol, a raw-string tool
  argument was JSON-encoded twice by two writers, and an aborted Gemini JSON-array stream emitted two
  trailing error elements.
- `busbar --validate` reported false errors on a config templating its URLs from environment variables, and
  missed a model whose `context_max` conflicted across pools, so a clean validate could still fail at
  startup.
- A config still carrying the removed `auth.mode:` key now fails with a hint naming its replacement.

## [1.3.3], 2026-07-16

### Added

- `busbar --validate` checks a config file without booting or binding a socket, the `nginx -t` workflow,
  and runs in CI without the runtime environment present.

### Changed

- `BUSBAR_WORKER_THREADS` caps the worker pool, which lowers memory on many-core hosts.

### Fixed

- A slow fire-and-forget hook could grow in-flight work without bound; those spawns are now capped and
  over-cap notifications dropped and counted.
- An unreadable config overlay file was overwritten rather than refused, which could silently discard
  persisted admin state.
- A queued request rewrite that could not be re-applied on failover forwarded the original un-rewritten
  body; the request is now rejected.
- The outbound guard now also blocks the Azure and Oracle Cloud metadata addresses, and the host Busbar
  signs for can no longer differ from the host it dials.

## [1.3.2], 2026-07-14

Maintenance release: CI fixes and dependency bumps only, no change in behaviour.

## [1.3.1], 2026-07-14

Maintenance release: no change in behaviour.

## [1.3.0], 2026-07-13

The API release: anything you could previously do only by editing YAML and restarting, you can now do over
an authenticated, audited API. Hooks and policies are configured differently, so **existing configs need a
one-time update**: see the [1.2.x to 1.3 migration guide](docs/migration-1.3.md). An old-form key reports a
startup error naming exactly what to write instead.

### Breaking changes

- **The management API moved under `/api/v1/admin/`.** The key endpoints at `/admin/keys*` are
  now `/api/v1/admin/keys*`; scripts calling the old paths need a one-line URL update.
- **A network-exposed admin listener refuses to start without client-certificate mTLS.** Set
  `admin_tls.client_ca_file`, keep admin on loopback, or waive it with `admin_insecure: true` if a mesh
  terminates mTLS for you.
- **The inline `policy:` block and transport-named `route:` values.** A pool's `route:` now takes
  a hook name or a built-in policy name (`weighted`, `cheapest`, `fastest`, `least_busy`, `usage`). Each
  removed key reports a startup error with its exact replacement.
- **The embedded Rhai script routing policy (`route: script`),** deprecated in 1.2.1, is gone.
  A compiled hook over a socket or an HTTP webhook does the same job with real process isolation.

### Added

- **The admin API is a full config plane:** read the running config, apply a validated change atomically,
  roll back to a previous version, register hooks, adjust pools, budgets and rate limits. Drive Busbar from
  Terraform, Ansible or CI with no SSH and no restarts. See [the admin API reference](docs/admin-api.md).
- **The admin API is on its own listener, always,** with its own TLS and optional client-certificate mTLS,
  so the control plane binds and is firewalled independently of public traffic. It defaults to loopback.
- Admin credentials are scoped (read-only, hooks-register, full) rather than one shared token, every
  mutation is audited against whoever made it, and the admin auth chain is live-mutable with a guard
  refusing a change that would lock the caller out.
- **Gates, taps and the restrict verb.** A gate can reject a request or restrict which pool members may
  serve it, which is how data residency or a BAA-only lane is expressed without teaching the router about
  compliance. A tap observes and can never delay or fail a request. A request's hooks fire at once, so
  added latency is the slowest hook, not the sum. See [the hooks guide](docs/hooks.md).
- **The rewrite verb:** a trusted gate can replace the request body before dispatch, for context
  compression or redaction, across every protocol at once. A malformed or slow rewrite proceeds with the
  original body, so a broken compressor cannot corrupt a request.
- Hooks are defined once under `hooks:` and referenced by name in a pool's `hooks:` list or in
  `global_hooks:`. One list carries both the ranking strategy and any gates.
- Hook settings can be pushed to a running hook over the admin API, committing only when the hook
  acknowledges, and a restarted hook gets its current settings before any traffic. Its observed settings
  and metrics are readable at `GET /api/v1/admin/hooks/{name}/status`.
- **Per-model and per-key metering at `GET /api/v1/admin/usage`,** reporting the raw token split in daily
  buckets with spend derived at read time, so a consumer with negotiated pricing can reconstruct cost.
- **Authentication is a chain of modules,** each identifying the caller, rejecting, or passing to the next.
  Token auth is the first module and is removable. `group_map:` maps identity-provider groups to admin
  scope and data-plane access in one place, with per-module caps bounding what any module may assert.
- API-applied changes persist to a Busbar-owned overlay file; your hand-written `config.yaml` is never
  touched, so "who set this" is always answerable.
- `POST /api/v1/admin/config/reload` applies your config files atomically. Lane health is carried across by
  model identity rather than list position, so reordering or adding a model never resets what Busbar has
  learned, and that state now survives a restart. `--safe-mode` boots from your base config alone when an
  API-applied change is the problem.

### Changed

### Removed

## [1.2.1], 2026-07-11

### Added

- **A routing hook can run as a compiled binary on a local Unix socket** rather than over HTTP, deciding in
  roughly 8 microseconds. Same wire contract as the webhook. You run the hook process; Busbar connects
  lazily and reconnects across restarts, and requests keep flowing on the pool's fallback if you kill it.
- **A hook can reject a request outright,** and the caller gets an error in its own dialect. With the
  prompt payload below, this is the content-screening primitive: a hook that sees content can stop a
  request before it leaves your network.
- Two per-pool opt-ins extend the hook payload, both off by default: `policy.send_prompt` adds the prompt
  content so a trusted hook can screen for PII, and `policy.send_user` adds caller identity so a hook can
  route by who is asking. The caller's own credential is never in the payload. Each candidate also carries
  the `tags` you declared on it.

### Changed

- **The default hook deadline is 1 ms,** down from 150, because a co-located socket hook decides in about 8
  microseconds. Raise `policy.timeout_ms` if your hook does I/O; on timeout the decision falls back per
  `on_error` and the request proceeds either way.

### Deprecated

- `route: script` (the embedded Rhai interpreter) works behind a build flag but warns at startup. Migrate
  to a compiled socket hook or an HTTP webhook. Removed in 1.3.0.

## [1.2.0], 2026-07-10

Busbar now carries more than chat. Embeddings, moderations, image generation, audio and rerank all
translate across protocols the way chat already did, so a client in one dialect can reach a backend in
another and get its answer back in its own dialect, errors included. Chat itself is byte-for-byte
unchanged.

### Added

- **Embeddings**, routable to OpenAI, Amazon Bedrock, Cohere or Google Gemini from any dialect, with
  vectors, usage accounting and errors surviving the hop.
- **Moderations**, **image generation** (OpenAI, Gemini, Bedrock), **audio** transcription and speech
  (OpenAI, Gemini), and **rerank** (Cohere and Bedrock), all cross-protocol. A backend that lacks an
  operation answers with a clean 404 in the caller's dialect rather than a crash or malformed body.
- **`attempt_timeout_ms` catches a provider that fails by hanging,** where the connection opens and headers
  never arrive, silently eating the whole failover budget on one member. Set it on a model and override per
  pool member. It covers connect and headers only, so it never cuts off a stream that has started.
- Per-token log probabilities cross the OpenAI and Gemini seam both ways, buffered and streaming.
- The reasoning and thinking budget translates between the protocols that model it, **gated by an operator
  flag:** set `reasoning: true` on a model to declare the backend accepts thinking parameters. Without it
  the ask is dropped with a warning, so a non-reasoning model can never fail because of translation.
- An end-user identifier and the parallel-tool-calls switch now translate between OpenAI and Anthropic.

### Changed

- **Busbar is licensed under the Apache License 2.0** from this release onward: permissive,
  commercial-friendly, with an explicit patent grant.
- Error envelopes come back in the caller's own dialect, and usage accounting survives a cross-protocol
  round trip on every operation, not just chat.

### Fixed

- A Gemini backend's streamed reasoning was concatenated into the visible reply for every client in another
  dialect.

## [1.1.1], 2026-07-09

### Added

- **`GET /v1/models` and `GET /v1beta/models`** list every routable name in the caller's dialect. This is
  the first call SDKs and self-hosted UIs make to build a model picker, and it previously returned 404. A
  key restricted by `allowed_pools` sees only what it may reach.

### Fixed

- `/metrics` was empty until the first request arrived, so a freshly booted gateway exposed nothing to
  Prometheus, and direct model lanes with no pool were missing their health gauge.
- `/stats` output and lane ordering are now stable across restarts, so scrapes and dashboards are
  reproducible.

## [1.1.0], 2026-06-30

### Added

- **`upstream_model` separates a model's config key from the id sent on the wire,** which lets the same
  model sit behind two providers in one failover pool, for example Claude via both Anthropic and Bedrock.
  Contributed by [@lguzzon](https://github.com/lguzzon).

## [1.0.1], 2026-06-30

A hardened maintenance release, functionally identical to 1.0.0.

### Added

- Releases ship a CycloneDX SBOM and a build-provenance attestation, so an artifact can be verified with
  `gh attestation verify <file> --repo GetBusbar/busbar`. Dependencies are checked against the RustSec
  advisory database on every change and weekly.

## [1.0.0], 2026-06-21

First stable release. The HTTP API, configuration schema and wire-protocol contracts are stable under
Semantic Versioning from here: no breaking change without a major version bump.

### Changed

- **Migration from rc.7:** `governance.rate_sweep_interval` must now be at least `1`; rc.7 silently
  disabled the sweep on `0`. No other change for a default deployment.
- Structured output, stop reasons, image sources and redacted reasoning survive a cross-protocol hop intact
  rather than passing through as opaque blobs.

### Fixed

- Two Bedrock request shapes returned a 400 on a valid request, Anthropic cache markers were dropped on
  thinking and image blocks, and a streaming refusal could lose content.
- Billing corrections: sub-cent attribution, cancelled mid-stream requests, and no token billing for a
  stream aborted during translation.
- A client could hold a connection open indefinitely by trickling request headers on either listener.

## [1.0.0-rc.7], 2026-06-20

Every request now takes one code path with billing metered from it, and the config surface is cleaned up to
freeze a 1.0 contract. Same-protocol traffic stays byte-exact and just as fast.

### Breaking changes

- **`auth.token` is removed,** and `auth:`, `governance:` and `security:` reject unknown keys, so
  a stale or typo'd security key is a loud startup error rather than a silent default.

### Added

- **A `limits:` block puts every operational limit under operator control** rather than hardcoding it:
  upstream timeout, request body maximum, idle connections per host, hard-down cooldown, upstream error
  body cap, TLS handshake timeout, honored `Retry-After` ceiling, default `max_tokens`, and a new
  `max_inbound_concurrent`. Each defaults to its previous value, so nothing changes unless you set it.
- Grounding and web-search citations survive a cross-protocol hop, streaming and buffered.
- `observability.emit_server_timing` (default off) emits the `Server-Timing: busbar` response header.

### Changed

- **Migration from rc.6.** If `auth.token:` was your only credential, move its value into
  `auth.client_tokens: [...]` or the gateway refuses to start. Fix any typo'd or stale key under `auth:`,
  `governance:` or `security:`, now hard startup errors. Update any script parsing the admin API error
  shape, now the same `{"error":{"message","type"}}` envelope as the proxy endpoints. Prefer the renamed
  keys: `window_s` to `window_secs`, breaker `trip.n` to `consecutive_n`, `failover.cap` to `max_hops`,
  `failover.deadline_secs` to `timeout_secs`; the old names still work, but do not set both spellings.
- **Cache-hit requests on Anthropic and Bedrock backends now bill more than in rc.6,** because their cache
  tokens were previously not counted at all.
- Same-protocol traffic takes the same path as cross-protocol, with a short-circuit that re-emits the
  original bytes when nothing changed. Net effect is a fidelity improvement: most protocols now forward a
  same-protocol request byte for byte, where the old path re-serialized and reordered JSON keys.

### Removed

### Fixed

- Streamed Responses requests reported zero tokens, so they were never billed.
- A Bedrock image sourced from S3 leaked its location as a corrupt payload when translated, and an internal
  redacted-reasoning marker could reach a client wire or be injected by one.
- A Gemini chunk carrying several citations produced one array event that crashed native Anthropic SDKs,
  and a corrupt Bedrock event prelude spliced raw bytes into the client stream.
- Admin key endpoints echoed a fragment of the request body, which carries the key secret, in a parse
  error.
- `observability.max_inflight_webhook_deliveries: 0` silently dropped every delivery; it is floored at 1.

## [1.0.0-rc.6], 2026-06-19

### Added

- **`Server-Timing: busbar;dur=<ms>` reports Busbar's own added latency on every response,** readable in
  browser developer tools or any APM tool against your real traffic.
- Provider-native features survive a cross-protocol hop instead of being silently dropped: sampling
  controls, structured output, reasoning and thinking blocks both ways, Anthropic cache markers against
  their Bedrock equivalent, cache-read token accounting, and Cohere image input. Where a target genuinely
  has no equivalent, the parameter is dropped with a warning rather than in silence.

### Changed

- **Cross-protocol translation of a large payload is roughly twice as fast** (about 186 to 84 microseconds
  on a 32 KB body); small requests are unchanged at the per-request floor of about 33 microseconds. Full
  methodology at [getbusbar.com/benchmark](https://getbusbar.com/benchmark).
- The JSON serializer formats some floats differently, for example `1e26` rather than `1e+26`. This is
  numerically lossless; only an exact string comparison on an exotic numeric passthrough field would notice.

### Fixed

- **A small deeply-nested request body could crash the whole process,** killing every in-flight request for
  every tenant. Bodies nested past 128 levels are now rejected before any value is constructed.
- Temperature clamped to a provider's native range is now reported with a warning rather than silently,
  `top_k` spelling is preserved to Bedrock, `max_completion_tokens` is preserved for OpenAI reasoning
  models, and `max_tokens: 0` is filtered uniformly.
- `busbar_breaker_trips_total` counted some trips twice and others not at all.
- A JSON error is logged as a sanitized breadcrumb rather than the raw library message, which can embed
  fragments of the request body.

## [1.0.0-rc.5], 2026-06-17

### Added

- **Pluggable routing policies.** A pool can declare `route:` to order its members, feeding the existing
  failover loop so a policy can never strand a request. Built in: `weighted` (the default, unchanged),
  `cheapest`, `fastest`, `least_busy`, and `usage`, which steers away from members approaching a provider
  rate limit. Operator-defined logic runs over a `webhook` transport in any language, honoring a per-pool
  `timeout_ms` and falling back per `on_error`, so it can never fail the client request. A pool that omits
  `route:` pays nothing for any of this.
- **Native inbound TLS and optional mutual TLS,** without a reverse proxy. Add a `tls:` block with
  `cert_file` and `key_file`, plus `client_ca_file` to require a client certificate, enforced at the
  handshake before any HTTP or token processing. Omitting `tls:` leaves the plain HTTP path unchanged.
- Four Prometheus gauges refreshed at scrape time, not on the request path: per-key spend, per-key budget
  remaining, per-key tokens, and per-lane circuit-breaker state. Every label comes from your configuration.

### Fixed

- **A pool member set to `weight: 0` still received traffic** carrying an existing session-affinity
  stickiness, so an operator draining a lane could not actually drain it.
- Each incoming TLS handshake has a ten-second cap, so a client cannot park a connection before
  authenticating, and a routing webhook's response is capped at 64 KiB.
- A TLS certificate, key or CA that fails to load aborts startup naming the file; key material is never
  logged.
- The outbound guard now also blocks the Oracle Cloud metadata address.

## [1.0.0-rc.4], 2026-06-16

### Fixed

- **A lane that tripped could be benched permanently or have its recovery probe stolen.** A clean stream
  end no longer records a spurious breaker failure, mid-stream error paths no longer double-record, and a
  failed recovery probe releases its permit instead of benching the lane for good.
- An upstream `Retry-After` is honored as the breaker cooldown floor.
- A large same-protocol response undercounted tokens, because usage past a scan cap was dropped.
- Outbound request guards closed a backslash-based bypass and a redirect vector on the telemetry exporter.

## [1.0.0-rc.3], 2026-06-10

### Breaking changes

- **`/metrics` is no longer unconditionally open.** It goes through the same authentication check
  as `/stats`, because the exposition discloses your lane and pool topology and error rates. Only
  `/healthz` stays open. Update any Prometheus scrape config that assumed otherwise.

### Added

- **Every wire protocol is now first-class ingress.** Previously clients could speak only Anthropic or
  OpenAI; now Responses, Cohere, Gemini and Bedrock clients can point their SDK's base URL at Busbar
  unmodified, with errors in the caller's native shape. See [the protocols guide](docs/protocols.md).

### Changed

### Fixed

- Streamed assistant text from a Cohere backend was silently dropped on the read path.
- A Gemini response filtered for safety returned a spurious 500 instead of decoding normally, and an
  OpenAI stream with a usage-only trailing chunk produced a spurious extra event.
- A model named `admin` was reachable at the operator admin surface, making it unreachable to clients and
  bypassing per-model governance. That name is now rejected at config validation.
- A host with a trailing dot, such as `127.0.0.1.`, slipped past the outbound metadata and IP checks and
  resolved to an internal target.
- An Anthropic upstream request could carry two credential headers at once, a shape no native client
  produces.

## [1.0.0-rc.2], 2026-06-04

### Changed

- **Cold start is roughly 30 times faster, about 206 ms down to 6 ms,** so Busbar serves `/healthz` in
  single-digit milliseconds, which is what a container readiness probe needs. In exchange, `/metrics`
  renders empty for a moment after start and the few requests in that window are not counted.

## [1.0.0-rc.1], 2026-06-03

First release candidate for 1.0: feature-complete and API-stable, with the remaining work being operational
validation rather than features. The release binary shrank from about 12 MB to 7.4 MB with a faster hot
path.

## [0.17.4], 2026-06-03

### Fixed

- **An OpenAI-format request omitting `max_tokens` failed on every call against an Anthropic-backed lane,**
  because Anthropic requires the field and OpenAI does not. Busbar now injects one at the translation
  boundary when the target protocol requires it, and a caller-supplied value is always preserved. The new
  per-model `default_max_tokens` sets what gets injected, defaulting to 4096.

## [0.17.3], 2026-05-31

### Fixed

- **Request bodies are now capped at 32 MiB.** They were effectively unbounded, so a multi-gigabyte body
  could exhaust memory, most easily with authentication disabled.
- Token comparison is now proof against a compiler optimization that could reintroduce a timing signal.

## [0.17.2], 2026-05-31

### Fixed

- **A `health:` block written under a provider in `config.yaml` was silently ignored,** exactly as the
  shipped example documents it, so health probing never started for it.

## [0.17.1], 2026-05-31

### Fixed

- **A single upstream 5xx could bench a single-member route for the full cooldown with no active
  recovery,** because probing fired only for fully tripped lanes.
- Reasoning content from an OpenAI-dialect backend was dropped when translated to Anthropic.
- `--help`, `--version` and every startup misconfiguration print a clean error rather than a panic.

## [0.17.0], 2026-05-31

### Changed

- **Logs are now always emitted to stderr,** with the level from `RUST_LOG`. Previously every span and
  warning was dropped unless telemetry export was configured.

### Fixed

- **Three hostile inputs could panic a worker:** a malformed `Authorization` header, an unbalanced brace in
  an upstream body, and an API key containing a control character.
- **A long-running lane spuriously tripped its breaker** on clean recent traffic once old errors aged out.
- Concurrent selections could corrupt the weighted round-robin state and bias distribution across members.
- Session affinity used a randomly seeded hash, so sticky routing did not survive a restart, and cooldown
  jitter only ever lengthened cooldowns.
- Passthrough auth dropped the caller's own token and silently fell back to the lane's static key.
- Degraded routing skipped cross-protocol translation, so it was wrong whenever the chosen lane spoke a
  different protocol.
- The per-key rate-limit map never evicted stale windows, an unbounded memory leak. `/stats` reported
  in-flight requests as always zero, and admin usage double-counted some responses.

## [0.16.2], 2026-05-31

### Fixed

- **The admin token was compared with a non-constant-time comparison,** a timing side channel that could
  let an attacker recover it byte by byte.
- Virtual-key generation now refuses to mint rather than falling back to a predictable, time-derived secret
  if the operating system random source is unavailable.

## [0.16.1], 2026-05-31

### Added

- `error_map` can match a provider's structured error type, not just its numeric code, which is what some
  providers surface. `/stats` reports each lane's client-fault counter alongside its success and error
  counts.

## [0.16.0], 2026-05-31

### Added

- **A lane shared by several pools now carries independent circuit-breaker state per pool,** so one pool's
  traffic tripping a lane no longer benches it for every other pool. A successful health probe recovers the
  lane everywhere, since it tests the one shared upstream. This supersedes the 0.15.0 note deferring it.

## [0.15.0], 2026-05-31

### Added

- **Active health checks.** A provider's `health.mode` can be `none` (passive only, the default), `dead`
  (re-probe only tripped lanes so a recovered upstream is picked up promptly), or `active` (probe every
  lane so a silently dead upstream trips before real traffic hits it).
- **A pool's `breaker:` block now takes effect.** It was parsed then ignored, with the breaker using a
  hardcoded rule. `failover.exclusions` are likewise now enforced, and `affinity.header_name` is honored.

### Fixed

- **A tripped lane never came back.** Its recovery probe could succeed without ever closing the breaker, so
  any lane that tripped once became permanently dead.

## [0.14.0], 2026-05-31

This changelog begins at 0.14.0; earlier history is not recorded here.

### Added

- **Cohere is now a supported wire protocol** at `/v2/chat`, including streaming, with system prompts
  preserved across a cross-protocol hop.
- **Azure OpenAI** is reachable through a per-provider `auth: api-key` style, shipped as a template in
  `providers.yaml`.

### Fixed

- A pool landing on a member in another protocol returned a response with no `model` field.
- Token accounting was not charged on the buffered cross-protocol path, so per-key token limits never
  enforced there.
- The `max_requests` lifetime cap was never enforced and per-lane success counts always read zero.

## [Early development]

Project scaffolding for the open-source release. The project is licensed under the Apache License 2.0 as of
1.2.0.
