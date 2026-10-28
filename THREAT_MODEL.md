# Busbar Threat Model

This document scopes what Busbar 1.6.0 defends against, so a security reviewer gets a map instead of
"read the whole tree." It states the trust boundaries, the assets Busbar guards, the threats we
design against, and, for each, where the mitigation lives in the code. Every mitigation named below
is implemented in this tree and covered by tests. Where a protection is designed but not yet built,
or is weaker than its name suggests, this document says so in a **Not built** or **Limit** line
rather than leaving it out.

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
configure: a `store:` block is required (`crates/busbar-kernel/src/config/sections.rs`), `memory` is
the only store compiled in, and `sqlite`, `postgres`, `valkey` and `mysql` are drop-in store plugins
that keep keys, usage and the audit chain in a backend you run.

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
  caller's behalf). **Limit:** stored in the configured store as plaintext behind a `v1:plain:` tag
  (`crates/busbar-kernel/src/governance/state.rs`, `crates/busbar-contract/src/records.rs`); only
  their `Debug` output is redacted. See T10.
- **The token-signing key** (`auth.signing_key`). Virtual keys are Ed25519-signed `bbk_` tokens
  (`crates/busbar-kernel/src/governance/signing.rs`); whoever holds this key can mint them.
- **The deployment keyset**, the Ed25519 key that signs the audit chain and ledger checkpoints. It is
  minted on first boot and kept in the store, cached under `data_dir` with mode 0600
  (`crates/busbar/src/root/keyset.rs`). Whoever controls the store controls this key.
- **Admin credentials** (admin tokens, the admin-plane mTLS client certificates).
- **Trust approvals** (the tool and agent fingerprints an operator approved; see T11).
- **The plugin trust root**: the release public key embedded in the binary at build time and the
  publisher keys the operator allowlists (`crates/plugin-loader/src/sign.rs`).
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

**Limit:** a config with no `auth:` block, like an explicitly empty chain, runs an open relay for
the LLM plane and for claims a plane marks open (for example A2A discovery). It is bannered on
stderr and logged at ERROR at every boot (`crates/busbar-kernel/src/appbuild.rs`). The MCP plane
refuses to boot behind an empty chain (`crates/busbar/tests/mcp_open_front_door.rs`).

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
`--migrate-config` rewrites it (`crates/busbar-kernel/src/config/mod.rs`, `config/migrate.rs`). A hostname is treated as exposed without resolving
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
`try_admit_estimated`).

**Limits:** a clamped `Retry-After` can still park a destination for up to the ceiling. Under the
default `admission: exact`, only an already-exhausted budget is refused and the estimate is not
reserved, so concurrent in-flight requests can each overshoot a cap by up to one request (more for
streams unless `cut-stream` is set). A request-stage hook **rewrite** that cannot be applied to the
body (it does not parse or cannot be spliced) is dropped and the original body goes upstream
(`crates/busbar-plane-llm/src/exchange/project.rs`, `apply_rewrite`): rewrites fail open. Do not rely
on a rewrite hook alone to remove content that must not leave; use a gate hook that refuses.

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

### T8: Supply-chain tampering (boundary 7)
A backdoored binary, image or plugin must be detectable. **Mitigation in this tree:** each `dev`
commit gets SLSA provenance from a trusted builder (`.github/workflows/slsa-dev-provenance.yml`);
plugin release tarballs get a build-provenance attestation (`.github/workflows/plugin-release.yml`);
dropped-in plugins are signature-checked before they load (see the plugin threat below). Dependencies are checked by
`cargo deny` on every change (`deny.toml`, `.ci/default.yaml`), and third-party GitHub Actions are
pinned by commit (`docs/ci/actions-pins.md`).

**Not built:** the 1.6.0 release publication step (`.ci/qa.yaml`) is not written yet, so this tree
does not yet produce the signed, attested release binaries and images. Until it lands nothing is
published from `main` (`RELEASE.md`). Release artifacts are published only from the build that was
judged; the version tag is an output of a green release, not an input. See the
[Security page](https://getbusbar.com/security/) for verification recipes of published releases.

### T9: Malicious or tampered plugin (boundary 6)
A plugin is native code in Busbar's process with the process's privileges, so a hostile plugin is a
code-execution foothold. **Mitigation:**
- **Off by default.** `plugins.enabled` defaults to `false`; with it off, nothing in the plugins
  directory is read, and a config that references a plugin that is not available refuses boot
  (`crates/busbar-kernel/src/config/mod.rs`, `crates/busbar/src/root/boot.rs`).
- **Signed.** Every dropped-in plugin's signed manifest is verified (`verify_strict`) against the
  Ed25519 release key embedded in the binary at build time (first party, no config) or a publisher
  key the operator allowlisted under `plugins.trust.publishers`; unsigned or third-party plugins
  load only with `allow_unsigned` / `allow_third_party`, both `false` by default
  (`crates/plugin-loader/src/sign.rs`). An untrusted plugin is logged and skipped, never loaded.
  Only a first-party plugin may claim a first-party egress class
  (`crates/plugin-loader/src/registry.rs`).
- **No replay of older builds.** `plugins.min_versions` floors any trusted plugin. A first-party
  plugin is also floored at the highest version this host has loaded (kept in `data_dir` and in the
  store); loading below it refuses boot unless an operator records a rollback through the audited
  `POST /api/v1/admin/plugins/rollback` (`crates/plugin-loader/src/highwater.rs`,
  `crates/busbar/src/root/durability/plugin_floor.rs`).
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

**Not built (designed, in review for 1.6.0):** the credential "chip". Under it a plugin would never
hold a credential as text: an SDK `Cred`/`Seal` type with no getter, no `Debug` and no serialization;
SDK recipes that perform each auth step (Postgres SCRAM, MySQL, LDAP bind, RESP `AUTH`, Basic and
Bearer, HMAC, SigV4, JWS) from a wiped buffer; refusal at boot and under `--validate` of a secret
reference at a plugin setting the plugin did not declare secret; credentials written in an `https`,
`rediss` or `ldaps` URL, or with `sslmode=require`, sent only on a connection the connector reports
secured; refusal by default of an auth method weaker than the server offers (Postgres cleartext or
MD5 where SCRAM is available, MySQL cleartext or old-password), and MySQL RSA full authentication
only with a key pin, TLS or a unix socket; recoverable credentials sealed in the store under a
dedicated at-rest key (`credentials.at_rest`, with a `previous` key for rotation); and a canary in
every plugin's conformance suite that fails on a leak. **None of these is in this tree.** Until they
land:
- Plugins receive their configured credentials as plaintext bytes.
- A `{ env: }` or `{ file: }` reference at a setting the plugin did **not** declare secret is
  resolved and its plaintext passed to the plugin in its settings.
- Recoverable credentials Busbar mints are stored as plaintext (see Assets).
- No store plugin in this project refuses a weaker auth method than its server offers.
- The canary harness records known leaks as expected and does not fail on them.

**Residual, accepted for 1.6.0 even once the chip lands.** Plugins run in Busbar's process. Native
code in the same address space can read memory, the environment and files, so a plugin that is
*malicious*, rather than careless, can recover a credential. The chip is designed to remove every
accidental path and every ABI path; it does not stop deliberate in-process access. The controls
against a malicious plugin are therefore T9's: plugins are off by default, every dropped-in plugin
is signature-verified, and third-party publishers must be allowlisted.

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
MCP plane does not coalesce concurrent re-fetches, so a burst against a stale server can fetch once
per call.

### T12: Audit-chain tampering (boundary 5, store)
**Mitigation:** the audit log is a hash chain whose records and ledger checkpoints are signed with
the deployment keyset (Ed25519, separate signature domains, `verify_strict`;
`crates/busbar-kernel-audit/`, `crates/busbar-kernel-ledger/src/checkpoint.rs`), verifiable through
`GET /api/v1/admin/verify`. Format: [audit-chain digest v4](docs/audit-chain-digest-v4.md).
**Limit:** the signing key lives in the same store as the chain, and the only anchor is the chain
itself, so the chain detects tampering by anyone who does not hold the store or the key; it does not
stop someone who holds both from re-signing history.

## Explicitly out of scope

- The security of the **upstream providers**, tool servers and agents themselves, and what an
  approved tool or agent does when called.
- **Host / OS / kernel** compromise of the machine Busbar runs on, and an attacker who controls the
  configured store.
- Operators who deliberately configure Busbar insecurely (`admin_require_mtls: false` on an exposed
  admin listener, an empty auth chain in production, `security.allow_all_metadata`,
  `allow_unsigned`, `allow_third_party`): documented foot-guns behind explicit settings, warned at
  boot.
- Physical access and side channels beyond the constant-time comparisons noted above.
- A malicious plugin reading a credential out of Busbar's own process memory (T10's accepted
  residual; T9's controls decide which plugins load), and any plugin the operator chose to compile
  in or trust.
- Outside the credential chip's custody in 1.6.0: HashiCorp Vault raw-stream and transit use, SRTP
  keying material, and the Busbar release signing key.

## Validation

The mitigations above are exercised by the unit and integration suites (about ten thousand tests
across `crates/`), per-plugin conformance suites, the protocol conformance suites under `testing/` (LLM, MCP, A2A,
WebSocket, voice, WebRTC), and a behavioural
oracle that compares 1.6.0 against the published 1.5.5 binary cell by cell. Boundary or mitigation
changes must keep those green and update this document.
