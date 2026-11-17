# Busbar Threat Model

This document scopes what Busbar 1.6.0 defends against, so a security reviewer gets a map instead of
"read the whole tree." It states the trust boundaries, the assets Busbar guards, the threats we
design against, and where the relevant mechanisms live. 1.6.0 is in active development. Source
mechanisms, approved requirements and final deployment qualification are separate: the presence
of code or tests does not establish that the final composition passed CI or release qualification.
**Release gate** denotes a required protection whose implementation or qualification is pending.
The [security posture](docs/security/1.6.0-security-posture.md) pins the source used for the
trust, audit, storage and TLS corrections below; other subsystem descriptions need their own
release-candidate check.

Report anything this model misses per [SECURITY.md](SECURITY.md).

## System in one paragraph

Busbar is a single binary that sits between your applications and the services they call: LLM
providers first, and in 1.6.0 also MCP tool servers, A2A agents, decision services and streaming
endpoints. The binary is a thin **kernel** (crates `busbar-kernel*`, `busbar-contract`,
`busbar-core-connector`, `busbar-core-admin`, `busbar-core-oauth2`) that hosts **plugins** of seven
kinds: store, secret, auth, hook, export, **plane** (a family of protocols: llm, mcp, a2a, decisions,
streaming) and **transport** (how bytes move). Every plugin, whether compiled into the binary or
dropped into the plugins directory, talks to the kernel over the same `repr(C)` memory ABI and is
loaded and validated by the same code (`crates/plugin-loader/src/dispatch/load.rs`). The kernel holds
the credentials, enforces authentication, routing, failover, rate and budget governance and TLS, and
owns every outbound connection through one connector. Busbar has **no hosted tier**; it dials only
destinations your configuration names (providers, tool servers, agents, identity providers, hook and
export endpoints, store backends, plugin fetch URLs). Governance state lives in the store you
configure: a `store:` block selects an available Store plugin. Linked plugins depend on the
assembled distribution; core does not guarantee that a memory Store is compiled in
(`crates/busbar-kernel/src/tests/central2_missing_plugin_tests.rs`). A Store's declared durability
determines restart survival. An ephemeral Store loses keys, usage, configuration mutations and
audit history with the process; a successful write does not make it crash-durable
(`crates/busbar-kernel/src/persistence/journal/runtime.rs`).

## Trust boundaries

1. **Client → data listener.** Untrusted or semi-trusted callers send requests to the data listener:
   LLM inference, and when configured the MCP, A2A, decisions and streaming planes, the OAuth2
   authorization server, and plugin routes. Everything in a request body or header is
   attacker-controlled.
2. **Kernel → remote counterparty.** Busbar makes credential-bearing calls to providers, MCP tool
   servers, A2A agents and other configured upstreams. Their responses, and their advertised tool
   lists and agent cards, are semi-trusted: a hostile upstream must not escalate into Busbar or
   change what callers are allowed to invoke.
3. **Kernel → network (the connector).** Every outbound connection, from any plane, transport or
   plugin that follows the ABI, is dialled by the kernel's connector after the destination guard has
   judged the name and every address it resolved to.
4. **Operator → admin listener.** Config, virtual keys, trust approvals, plugin rollback and hooks
   are managed through a **separate admin listener** (its own socket, loopback by default). Crossing
   it requires admin authentication and, when exposed off-loopback, mutual TLS.
5. **Operator → configuration and secrets.** `config.yaml`, `providers.yaml` and the secret sources
   they reference (`{ env: }`, `{ file: }`, a secret plugin) are trusted operator input, but Busbar
   still validates them so a typo does not become a vulnerability.
6. **Kernel ↔ plugin (new in 1.6.0).** A plugin is native code in Busbar's process. Compiled-in
   plugins are trusted by the build; dropped-in plugins cross a signature and version check before
   they load. Inside the process the ABI is a contract, not a wall (see T9 and T10).
7. **Distribution.** The Busbar binary, its images and the plugin tarballs an operator downloads or
   lets Busbar fetch.

## Assets

- **Provider and upstream credentials** (API keys, AWS SigV4 secrets, OAuth client secrets and
  service-account keys, credentials for tool servers, agents, stores and export endpoints).
- **Recoverable credentials Busbar mints** (signed-request secrets kept so Busbar can sign on a
  caller's behalf). Newly minted recoverable credentials are sealed with AES-256-GCM before
  storage, under a key derived from `auth.signing_key`. Minting refuses without a signing key
  (`crates/busbar-kernel/src/governance/at_rest.rs`, `identity_runtime.rs`). Legacy `v1:plain:`
  reads remain supported; the new-write protection does not prove existing rows or backups were
  migrated. Protect the signing key separately from store access. See T10.
- **The token-signing key** (`auth.signing_key`). Virtual keys are Ed25519-signed `bbk_` tokens
  (`crates/busbar-kernel/src/governance/signing.rs`); whoever holds this key can mint them.
- **The deployment keyset**, used for audit page stamps and checkpoint signatures. The production
  binding obtains it through the configured Store's identity owner and confirms its Bootstrap
  record (`crates/busbar/src/root/keyset.rs`, `bind_key`, `bind_split`). The current production
  path chooses `LiveSigner::SameAsBootstrap`; a delegated signer type alone does not establish
  a node-bound certificate or remote key custody. The durability builder does not open the legacy
  `data_dir` (`crates/busbar/src/root/durability/mod.rs`). Protect key custody separately from
  audit storage; control of both permits history to be re-signed.
- **Admin credentials** (admin tokens, the admin-plane mTLS client certificates).
- **Trust approvals** (the tool and agent fingerprints an operator approved; see T11).
- **Plugin verification authorities**: named release roots embedded at build time and the scoped
  publisher keys the operator configures (`crates/plugin-loader/src/sign.rs`). Release roots,
  delegated release keys, audit keys and TLS trust anchors have separate roles.
- **Backend identity** (which upstream served a request; leaking it is a fingerprinting aid).
- **Availability** (the gateway and its circuit-breaker state).

## Threats and mitigations

### T1: SSRF via a configured or request-derived destination (boundaries 2, 3, 5)
A `base_url`, `path`, `path_base`, OAuth `token_url`, tool-server or agent URL, export endpoint or
plugin fetch URL that reaches cloud metadata or an internal address would send credential-bearing
traffic there. **Mitigation, two layers:**
- **At load**, a denylist blocks cloud-metadata hosts (`ssrf_blocked_host`,
  `crates/busbar-kernel-egress/src/trust/net.rs`), after normalizing the authority the way a
  connecting client would: backslash to slash, userinfo stripped, percent-decoding, trailing dot,
  whitespace and control characters, IDNA, and alternate IPv4 spellings (decimal, hex, octal,
  IPv4-mapped IPv6) (`crates/busbar-contract/src/net.rs`). `path` and `path_base` must begin with
  `/` and the composed URL is re-checked; `token_url` gets the same guard and must be https for
  public hosts (`crates/busbar-kernel/src/config_validate/mod.rs`).
- **At connect**, the destination guard in the connector judges every dial whatever dialled it
  (`crates/busbar-core-connector/src/guard.rs`): the name before resolution, then **every** address
  it resolved to; one refused address refuses the whole answer, and the connector dials exactly the
  address it judged (`crates/busbar-core-connector/src/process.rs`), so a DNS-rebinding answer cannot
  slip an internal address past the check. Cloud metadata and IPv6 link-local are refused in every
  egress class unless an IP or CIDR allowlist entry names them; private addresses are refused for
  provider dials and request-derived destinations while `block_private_addresses` holds.
- The connector never follows a redirect (test `an_answer_naming_another_place_is_handed_up_and_never_dialled`,
  `crates/busbar-core-connector/src/tests/connector_tests.rs`).

**Limit:** an export plugin's webhook URL that the guard refuses disables that exporter with a
diagnostic rather than refusing boot. Plugin fetch allows plain `http` to loopback and private hosts.

### T2: Front-door authentication bypass (boundary 1)
**Mitigation:** the auth chain fails **closed**: a request no auth method accepts is denied
(`crates/busbar-kernel-identity/src/chain.rs`). Empty or absent credentials are rejected before any
lookup. Virtual keys are Ed25519-signed tokens checked by signature, expiry, revocation and
generation (`crates/busbar-kernel/src/governance/signing.rs`); plane tokens are audience-bound.
Admin token comparison is constant-time over SHA-256 digests, folding both carriers without a
short-circuit (`busbar-auth-admin-tokens` plugin). SigV4 ingress compares the signature in constant
time and answers an unknown access-key-id with a dummy secret, so it is indistinguishable from a bad
signature (`busbar-auth-sigv4` plugin; `crates/busbar/src/root/credentials.rs`). Refusals are
reason-agnostic: missing, wrong and disabled credentials get the same answer
(`crates/busbar-kernel/src/auth/mod.rs`, `unauthorized_response`).

**Limit:** a config with no `auth:` block is refused at validation (BUSBAR-8014,
`crates/busbar-kernel/src/config_validate/mod.rs`). Only an explicitly empty chain
(`auth: { chain: [] }`, the operator's open-relay acknowledgement) runs an open relay for the LLM
plane and for claims a plane marks open (for example A2A discovery). Nothing writes that block
for the operator: the one-time 1.5.5 upgrade reports a missing `auth:` block as an action item
with the refusal's remedy and writes nothing (`crates/busbar-migrate/src/migrate_1_6.rs`). It is
bannered on stderr, logged at ERROR at every boot (`crates/busbar-kernel/src/appbuild.rs`) and
named as `open_relay` in the `node.boot` audit event. The MCP plane refuses to boot behind an
empty chain (`crates/busbar/tests/mcp_open_front_door.rs`).

**Unauthenticated by design:** `/healthz` on both listeners; `/.well-known/oauth-protected-resource`;
`/auth/token`, whose handler runs the auth chain itself; and, when `oauth_as:` is configured, the
OAuth2 authorization server's metadata, JWKS, authorize, token, dynamic registration and PAR
endpoints, which authenticate clients themselves (`crates/busbar-core-oauth2/src/routes.rs`).
Dynamic client registration is always on while the authorization server is on.

### T3: Credential leakage (boundaries 1, 2, 6)
A key must never reach a client, a log, or the wrong host. **Mitigation:** secrets are held as
`Secret<T>`, whose `Debug` and `Display` print `[REDACTED]`
(`crates/busbar-contract/src/redacted.rs`); the per-attempt type carrying a provider key and the
credential and virtual-key records have hand-written redacting `Debug` impls
(`crates/busbar-kernel/src/plane_driver/route_input.rs`, `crates/busbar-contract/src/records.rs`).
OAuth mint failures report the status and at most 200 characters of the token endpoint's reply,
never the assertion or secret (`busbar-auth-oauth` plugin). Credential-type headers from the caller
are stripped before any plane sees the request (`crates/busbar-contract/src/abi/host/conn/connector.rs`,
`NEVER_KEPT`), so a caller's credential is never relayed upstream. On cross-dialect routes upstream
errors are re-enveloped, not relayed (`crates/busbar-plane-llm/src/exchange/reply/failure.rs`).

**Limits:** on same-dialect LLM routes, and on the decisions plane, caller headers other than
credential headers and Busbar's governed set are forwarded upstream so Busbar stays transparent
(`crates/busbar-plane-llm/src/exchange/attempt.rs`); a same-dialect client error is relayed
verbatim. Plugins receive the credentials they are configured with as plaintext (see T10).

### T4: Outbound-signing correctness (boundary 2)
A mis-signed AWS request is a functional and trust failure. **Mitigation:** the SigV4 signer
(`busbar-auth-sigv4` plugin) signs the wire target the LLM plane sends, and the end-to-end test
recomputes the signature from the bytes the upstream actually received, the way AWS does, and
asserts it matches (`crates/busbar/tests/sigv4_both_ways.rs`,
`sigv4_is_verified_inbound_and_signed_outbound`). **Limit:** that test covers a Bedrock model id
containing `:` and no query string; it is not a general fuzz of path encodings.

### T5: Admin-plane exposure (boundary 4)
The control plane must not be reachable from the data port and must not be silently exposed.
**Mitigation:** admin routes, and plugin routes declared at admin level, are mounted only on the
admin listener (`crates/busbar/src/main.rs`, `crates/busbar-kernel/src/router.rs`). Boot is refused
when the admin listener binds anything but loopback or `localhost` without `admin_tls.client_ca`,
unless `admin_require_mtls: false` is set explicitly; the retired `admin_insecure` key is refused and
the first-boot migration rewrites it (`crates/busbar-kernel/src/config/mod.rs`, `config/migrate.rs`). A hostname is treated as exposed without resolving
it. The admin scope a request needs is derived from method and path only, never the body
(`crates/busbar-kernel-scope/src/lib.rs`, `admin_required_scope`): `GET` and `HEAD` need read-only,
every other method outside two named dry-run paths needs full.

**Limit:** the OAuth2 authorization server's consent screen (`GET`/`POST` on its consent path)
requires an admin credential but is mounted on the **data** listener
(`crates/busbar-core-oauth2/src/routes.rs`), so the admin listener's mTLS requirement does not cover
it.

### T6: Routing confusion, breaker-state leakage and over-spend (boundary 1, availability)
A request must not be mis-routed, and one caller's failures must not corrupt another's routing.
**Mitigation:** circuit-breaker cells are per (pool, destination)
(`crates/busbar-kernel-breaker/src/lib.rs`); a hostile `Retry-After` is clamped (default ceiling
86,400 s, `crates/busbar-kernel/src/config/limits.rs`) with saturating arithmetic
(`crates/busbar-kernel-breaker/src/cell.rs`). The request budget is a compare-and-swap loop. Money
is never stored: spend is derived from metered usage times the rate card and checked against the cap
under the same held locks as the charge (`crates/busbar-kernel/src/governance/state.rs`,
`try_admit`).

**Limits:** a clamped `Retry-After` can still park a destination for up to the ceiling. Only an
already-exhausted budget is refused and no estimate is reserved, so concurrent in-flight requests
can each overshoot a cap by up to one request (more for streams). **Rewrite failure has distinct outcomes.** An optional
transform failure can retain the original content; `on_error: reject` converts a transform
failure to refusal. A returned rewrite that cannot be projected onto the protocol is refused,
not silently replaced by the original body. A not-applicable transform or content omitted from
the hook's view is a separate case: it does not establish that redaction occurred
(`crates/busbar-kernel/src/hooks/mod.rs`, `plane_driver/gated.rs`). Mandatory redaction must
select rejection on failure and cover every content path it intends to protect.

### T7: Denial of service (boundaries 1, 2, availability)
**Mitigation:** every buffering site is bounded: the inbound body limit
(`crates/busbar-kernel/src/router.rs`); the SigV4 pre-auth buffer (413 at the cap,
`crates/busbar-kernel/src/auth/mod.rs`); upstream error reads (256 KiB,
`crates/busbar-kernel/src/plane_driver/far_end.rs`); the cross-protocol translate buffer (32 MiB,
500 on overflow, `crates/busbar-kernel-egress/src/upstream.rs`); stream reassembly (16 MiB,
`crates/busbar-plane-llm/src/codec/`); the usage-tap buffer; the A2A card fetch (512 KiB, 10 s);
plugin fetch (256 MiB). No request-path regex; JSON depth is capped at 128; the runtime client does
no decompression. Tap fan-out is semaphore-capped and drops on saturation
(`crates/busbar-kernel/src/hooks/taps.rs`); export deliveries pass a per-instance admission gate.
Timeouts bound connect and overall duration (`upstream_request_timeout_secs`, default 300 s).
**Limit:** a per-attempt time-to-first-byte bound applies only where a pool member sets
`attempt_timeout_ms`; otherwise the first byte is bounded by the remaining overall budget.

The Hyper HTTP listener has an absolute 30-second first-complete-header deadline after
plaintext IO becomes available, including protocol detection. After the first request,
HTTP/2 connections close after 30 seconds with no active handler or unfinished request/response
body. Control frames cannot extend either deadline. Owned deadline closure drops transport IO
directly, including when writes block. Normal shutdown and read-drain share a 30-second total
budget; admission capacity follows actual IO through that drain. These policies do not change
plugin-framed session upgrades or datagram lifetimes.

**Remaining active-stall limitation (#102):** HTTP/2 keepalive uses a 30-second interval and
10-second acknowledgement timeout, but the library initiates protocol shutdown rather than a
guaranteed hard socket close. An active peer that stops reading can block GOAWAY and retain its
connection slot indefinitely. No hard active-stall or per-stream incomplete-header bound is
claimed; a live request exempts its connection from the zero-active timer.

### T8: Supply-chain tampering (boundary 7)
A backdoored binary, image or plugin must be detectable. **Mitigation in this tree:** release artifacts are signed by the release pipeline, never by a GitHub workflow or a CI-held key (a source
rule, `crates/busbar-contract/tests/source_rules/workflows.rs`, prevents GitHub Actions from returning);
dropped-in plugins are signature-checked before they load (see the plugin threat below).
Dependency checks use `deny.toml` through internal CI. GitHub is a public source mirror only.


**Release availability:** the 1.6.0 provenance producer and verifier are implemented, but production signing and publication are not activated. No published 1.6.0 attestation bundle or production verification identity is claimed here. Verify each released binary, container and plugin using that artifact's published verification material; a signed plugin does not authenticate its host engine. See the [release verification guide](https://getbusbar.com/docs/deploy/binary/) for published releases and current development limitations.

### T9: Malicious or tampered plugin (boundary 6)
A plugin is native code in Busbar's process with the process's privileges, so a hostile plugin is a
code-execution foothold. **Mitigation:**
- **Off by default.** `plugins.enabled` defaults to `false`; with it off, nothing in the plugins
  directory is read, and a config that references a plugin that is not available refuses boot
  (`crates/busbar-kernel/src/config/mod.rs`, `crates/busbar/src/root/boot.rs`).
- **Authenticated provenance.** Busbar releases verify through the embedded root, a root-signed
  keys document and delegated release signatures. Configured publisher keys authenticate only
  the exact plugin names the operator permits. Multiple keys allow overlap, and explicit revoked
  keys cannot admit code. `allow_untrusted`, default false, permits unsigned or unknown-publisher
  code with an unverified audit/admin verdict. Invalid known-publisher signatures, altered bytes,
  out-of-scope names and authenticated revocations are hard refusals regardless of that flag
  (`crates/plugin-loader/src/sign.rs`). Signature provenance grants no runtime egress privilege.
- **Version floors.** `plugins.min_versions` requires trusted proof at or above an explicit floor.
  The current code also retains Busbar-specific automatic high-water and rollback handling
  (`crates/plugin-loader/src/sign.rs`, `crates/busbar/src/root/durability/plugin_floor.rs`).
  Its persisted state inherits Store durability. This is not evidence of equal automatic
  anti-rollback handling for every publisher. **Release gate:** publisher-neutral lifecycle and
  runtime permissions must be qualified for configured publishers as well as Busbar packages.
- **Root lifecycle.** Multiple named roots are accepted through build-time `BUSBAR_RELEASE_PUBKEY`.
  A root-signed keys document can rotate or revoke delegated release signers; it cannot install
  or revoke an embedded engine root. Root replacement needs an authenticated engine update.
  Planned old / overlapping / new-root builds and compromise recovery are described in
  [release trust](docs/design/release-trust.md#5-root-rotation). One-of-N overlap is not a
  multi-party threshold guarantee or recovery from a compromised old root.
- **The verified bytes are the bytes that run.** The loader stages only the verified bytes, in a
  sealed `memfd` on Linux or a freshly created 0600 file elsewhere (and on Linux if `memfd` fails),
  and never loads a pre-existing file (`crates/plugin-loader/src/stage.rs`).
- **Strict ABI admission.** A plugin built for another ABI version, newer or older, is refused; a
  1.5.5 JSON-contract plugin is refused with a message naming the rebuild. The door's magic, version,
  table slot count and size are checked before any call (`crates/plugin-loader/src/dispatch/load.rs`).
- **Plugin fetch** (`plugins.fetch`) runs only when plugins are enabled, never under `--validate`;
  it requires https for public hosts, refuses redirects and metadata hosts, caps the download, checks
  an optional sha256 pin before writing, and the result still passes the signature check above
  (`crates/plugin-loader/src/fetch.rs`).

**Limits:** compiled-in plugins are not signature-checked; they are first party by the choice of
whoever built the binary. Panics are caught at the boundary only for plugins built with the SDK's
door macros (`crates/busbar-contract/src/abi/sdk/boundary.rs`); the host cannot enforce that on a
hand-built library. "Plugins reach the network only through the kernel's connector" is enforced at
build time by a dependency gate for the plugins in this project, not at runtime: native code can
open its own sockets and files. There is no sandbox or process isolation for plugins in 1.6.0.

### T10: Credential custody in plugins (boundary 6)
A plugin that authenticates to something (a store, an identity provider, a webhook, a provider)
needs a credential, and a plugin may be code someone else wrote. **Mitigation in this tree:** a
setting a plugin declares secret is taken out of its settings and handed to the plugin's `open` call
as bytes that are wiped after the call (`crates/plugin-loader/src/boot.rs`); a settings value that
fails to decode is reported without quoting it. A central canary harness measures where a canary
credential crosses the ABI (`crates/busbar/tests/canary/`).

**At-rest protection is implemented separately from plugin isolation.** Newly minted
recoverable credentials are sealed before they are written to the configured store; a missing
at-rest key refuses the mint. The implementation retains a legacy plaintext read path, so
operators must account for pre-existing rows and backups when reviewing exposure.

**Native plugins remain trusted code.** Credential handles, redacted diagnostics, controlled
ABI projections and wiped temporary buffers reduce accidental exposure; they do not isolate
code sharing Busbar's address space. A malicious native plugin can access process memory,
environment variables and files. Signing establishes the publisher and artifact integrity,
not a sandbox. Apply T9's publisher admission controls and protect the host and its key material.

### T11: Tool and agent rug-pull (boundary 2; MCP and A2A planes)
A tool server or agent that changes the tool description, argument schema or card an operator
approved could redirect the model. **Mitigation:** verify-on-call. Before a `tools/call` or an agent
delegation is dispatched, the plane re-fetches the upstream's tool list or card when its last fetch
is older than `verify_ttl` / `reverify_ttl` (default 5 s), records what it saw on the kernel's trust
book, and the kernel decides: a first sighting is refused until approved on `/admin/trust`, a changed
fingerprint is quarantined, and a fetch that fails serves nothing
(`crates/busbar-kernel/src/trust/book.rs`, `judge`; `busbar-plane-mcp`, `tool_door.rs`,
`verify_on_call`; `busbar-plane-a2a`, `agent_door.rs`, `verify_agent_on_call`). A clock that moved
backwards counts as stale (`crates/busbar-kernel/src/trust/reverify.rs`). An A2A registration with
`pin.mechanism: unpinned` has no authenticity root and cannot be approved. See
[Tool and agent trust](docs/tool-and-agent-trust.md).

**Limits:** verification checks the advertised surface, not what the upstream does when called. The
MCP plane coalesces concurrent tool-list refreshes per server and catalogue generation within the process. This does not coordinate refreshes across nodes or detect malicious behavior hidden behind an unchanged advertised definition.

### T12: Audit-chain tampering and loss (boundary 5, store)
**Mechanism:** current runtime audit lines are hash-linked (`audit.v8`), with asynchronous signed
page stamps covering ranges. A link line has no individual signature; linked, staged, Store-applied
and stamp-covered are different states (`crates/busbar-kernel-audit/src/link.rs`, `stamp.rs`,
`crates/busbar/src/root/durability/audit.rs`, `notary.rs`). Older signed formats remain distinct.
The [link and stamp format](docs/audit-link-v1.md) describes the wire representation.
The notary's existence does not prove an outstanding tail has been signed or persisted.

**Limits:** the configured Store owns persistence. An ephemeral Store cannot retain the chain or
its keyset across restart. Store/journal verification and signature coverage are separate checks;
an audit read alone is not proof of complete signed coverage. Current read and recovery paths are
in `crates/busbar/src/root/durability/audit.rs`, `audit_page.rs` and `store_identity.rs`.
An attacker controlling both the signing authority and the chain can re-sign history; an
independent retained anchor is necessary to detect wholesale replacement.

**Release gates:** qualify durable audit from the operation through Store confirmation, retained
reads and external verification on the final composition, including failures and shutdown. The
approved delegated audit certificate v2 binds the containing node, chain sequence and predecessor;
verifiers must derive those values from the containing record, not a caller-supplied claim. Its
signature domain is `busbar.audit.notary_key.v2`, record digest domain
`busbar.audit.notary_key.record.v2`, and journal tag `audit.notary_key.v2`; existing `audit.v8`
unit bytes stay unchanged. At this document's source baseline, production still selects the
Bootstrap signer and does not activate that certificate path. Do not treat delegated signer
types, draft code or a configured Store as proof of this gate. The certificate authorizes audit
sealing only; it grants neither plugin admission nor TLS identity.

### T13: Transport downgrade or false TLS assurance (boundaries 1–4, 6)
**Mechanism:** core owns connection security. Need OPEN, STARTTLS and FETCH use a core-held
acceptance policy before pool reuse and DNS (`crates/busbar-core-connector/src/need/policy.rs`).
The instance's `insecure_transport` object accepts `plaintext`, `unverified_tls` or both and
requires a printable reason (`crates/busbar-kernel/src/config/min3.rs`). Neither a plugin kind
nor a loopback/Unix destination is an automatic exemption in this gate. Signature trust is
independent of transport policy.

**Limits:** this gate is not evidence that every runtime socket and carrier has passed the same
end-to-end check. `PinnedKeyVerifier` layers a pin over chain/name verification; it is not a
pin-only verifier (`crates/busbar-core-connector/src/tls/client.rs`). A listener with no TLS config
currently gets identity/plaintext connection security (`off_path/tls.rs`, `prepare`). A TLS-capable
adapter, valid TLS config and a crypto backend are not evidence that a live socket performed
the required handshake.

**Release gate:** every kind must verify TLS by default, with explicit, scoped and audited
acceptance where verified TLS is impossible; the approved pin-only option also needs
implementation and qualification. Qualify all ingress/egress paths, STARTTLS, datagrams, pool
reuse and failure paths on the assembled runtime. These requirements remain required for 1.6.0;
the limits above do not waive them.

## Explicitly out of scope

- The security of the **upstream providers**, tool servers and agents themselves, and what an
  approved tool or agent does when called.
- **Host / OS / kernel** compromise of the machine Busbar runs on, and an attacker who controls the
  configured store.
- Operators who deliberately configure Busbar insecurely (`admin_require_mtls: false` on an exposed
  admin listener, an empty auth chain in production,
  `allow_untrusted`): documented foot-guns behind explicit settings, warned at
  boot.
- Physical access and side channels beyond the constant-time comparisons noted above.
- A malicious plugin reading a credential out of Busbar's own process memory (T10's accepted
  residual; T9's controls decide which plugins load), and any plugin the operator chose to compile
  in or trust.
- Outside the credential chip's custody in 1.6.0: HashiCorp Vault raw-stream and transit use, SRTP
  keying material, and the Busbar release signing key.

## Validation

Unit, integration and plugin conformance suites provide evidence only for their exact assertions,
source revisions and executed configurations. A skipped pipeline, a test definition or an approved
design is not a passing result. Final release qualification must pin the assembled engine, SDK,
plugins, backend configuration and published artifacts, and resolve the release gates above.
Boundary or mitigation changes must update this document and the relevant CI evidence.
