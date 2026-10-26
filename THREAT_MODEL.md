# Busbar Threat Model

This document scopes what Busbar defends against, so a security reviewer gets a map instead of
"read 40,000 lines of Rust." It states the trust boundaries, the assets Busbar guards, the threats
we design against, and — for each — where the mitigation lives in the code. Nothing here is
aspirational: every mitigation named below is implemented and covered by tests.

Report anything this model misses per [SECURITY.md](SECURITY.md).

## System in one paragraph

Busbar is a single static binary that sits between your applications and upstream LLM providers. It
speaks six wire protocols on both sides (OpenAI, Anthropic, Gemini, Bedrock, Cohere, Responses),
holds the provider credentials, and enforces routing, failover, rate/budget governance, and TLS. It
has **no hosted tier** and makes **no outbound calls except to the providers you configure** (and any
hook endpoints you point it at). Governance state is **in-memory by default**; the durable store is a
choice, and selecting `postgres` or `valkey` means virtual keys, usage, and the audit log live off-box
in a backend you run (a local SQLite file keeps state on the same host).

## Trust boundaries

1. **Client → data plane.** Untrusted or semi-trusted callers send inference requests to the data
   listener. Everything in a request body/header is attacker-controlled.
2. **Data plane → upstream provider.** Busbar makes signed, credential-bearing calls to provider
   endpoints named in `providers.yaml`. The provider response is semi-trusted (a compromised or
   hostile upstream must not be able to escalate into Busbar).
3. **Operator → admin/control plane.** Config, virtual keys, and hooks are managed through a
   **physically separate admin listener** (its own socket, loopback by default). Crossing this
   boundary requires admin authentication and, when exposed off-loopback, mutual TLS.
4. **Operator → configuration & secrets.** `config.yaml` / `providers.yaml` / environment variables
   are trusted operator input, but Busbar still validates them to prevent a typo from becoming a
   vulnerability (e.g. an SSRF-able base URL).

## Assets

- **Provider credentials** (API keys, AWS SigV4 secrets, OAuth client secrets / service-account keys).
- **Virtual-key secrets** (the `sk-bb-…` bearer tokens Busbar issues to callers).
- **Admin credentials** (the admin token and the admin-plane mTLS client certificates).
- **Backend identity** (which upstream served a request — leaking it is a fingerprinting aid).
- **Availability** (the gateway and its circuit-breaker state).

## Threats and mitigations

### T1 — SSRF via a config-controlled upstream (boundary 2, 4)
A `base_url` / `path` / `path_base` / OAuth `token_url` / hook `webhook:` URL that resolves to a
cloud-metadata endpoint would send credential-bearing traffic to IMDS. **Mitigation:** a load-time
SSRF denylist (`config_validate::ssrf_blocked_host`) blocks cloud-metadata/IMDS hosts, and normalizes
the authority the way the connecting stack does (backslash→slash, userinfo stripping,
percent-decoding, trailing-dot, and alternate IPv4 encodings: decimal/hex/octal `inet_aton`,
IPv4-mapped IPv6), so an obfuscated host can't slip past. `path`/`path_base` must begin with `/` (an
override can only extend the path, never re-home the authority), the composed URL is re-checked, and
`token_url` gets the same guard because it carries the client secret. A hook `webhook:` URL is
validated the same way at load (`observability::validate_routing_webhook_url`) so a gate or tap
endpoint cannot be pointed at IMDS. The runtime HTTP client also **refuses redirects**, so a
hostile upstream can't 30x-redirect vetted traffic to an internal address.

### T2 — Front-door authentication bypass (boundary 1)
**Mitigation:** the auth chain fails **closed** — an unmatched request is denied, not allowed; an
empty chain is a deliberate, loudly-bannered dev-mode opt-in. Client and admin token comparisons are
**constant-time** over fixed-length SHA-256 digests, and the allowlist fold is bitwise-OR (no
`.any()` short-circuit) so match position doesn't leak via timing. Empty/absent tokens are rejected
before any lookup (closing the `sha256("")` path). SigV4 ingress verifies the full signature
constant-time and rejects an unknown access-key-id indistinguishably from a bad signature (no
enumeration oracle).

### T3 — Credential leakage (boundary 1, 2)
A key must never reach a client, a log, or the wrong host. **Mitigation:** secret-bearing config types
have **manual redacting `Debug` impls**; the `Lane` that holds the plaintext key isn't `Debug` at all;
OAuth mint errors are truncated and never echo the assertion/secret; upstream error bodies are
re-enveloped (not relayed verbatim) on cross-protocol paths; and error surfaces are **reason-agnostic**
(missing vs. wrong vs. disabled credentials are indistinguishable to the caller). Egress headers are
server-synthesized — client headers are never forwarded upstream. The virtual-key secret is 256-bit
and stored **hashed** at rest.

### T4 — Outbound-signing correctness (boundary 2)
A mis-signed AWS request is a functional and trust failure. **Mitigation:** SigV4 is
**signed == sent** — the canonical URI is encoded once and reused for both the signature and the wire
path (so a reserved `:` in a Bedrock modelId signs and transmits identically), header canonicalization
preserves the exact bytes AWS expects, and the harness verifies the signature the way real AWS does
(a mis-encoded canonical path 403s in test).

### T5 — Admin-plane exposure (boundary 3)
The control plane must not be reachable from the data port, and must not be silently exposed. **Mitigation:**
admin routes are mounted **only** on the separate admin listener (the combined router is test-only);
a boot-guard **refuses to start** if the admin listener binds a non-loopback address without
`admin_tls.client_ca_file` (mTLS) unless `admin_insecure: true` is set explicitly; `bind_is_loopback`
fails closed on unresolvable hosts; and the admin auth scope defaults to `Full` (fail-closed) for any
unmatched path/method, derived from method+path only (never the body).

### T6 — Routing confusion & breaker-state leakage (boundary 1, availability)
A request must not be mis-routed across pools/models/providers, and one caller's failures must not
corrupt another's routing. **Mitigation:** per-(pool, lane) circuit-breaker cells; a hostile
`Retry-After` is treated only as a cooldown floor (clamped, `saturating_add`, cannot bypass the
breaker); budget spend is a compare-and-swap loop (no TOCTOU over-spend); refunds are gated so a
failure can't raise a budget above cap; and rewrite-on-failover fails **closed** (a request that can't
be re-shaped for the retried lane is rejected, never forwarded un-rewritten).

### T7 — Denial of service (boundary 1, 2, availability)
**Mitigation:** every buffering site is bounded (inbound body limit; capped SigV4 pre-auth buffer;
capped upstream error/relay reads; capped cross-protocol translate buffer with a 500 on overflow;
`MAX_BUF` streaming-reassembly abort; capped usage-tap buffer). No request-path regex (no ReDoS);
JSON depth-guarded; auto-decompression is **not** enabled (no decompression-bomb amplification).
Fan-out is bounded (tap/webhook spawns are semaphore-capped and drop-on-saturate). Timeouts bound
connect, per-attempt (time-to-headers), and overall duration, so no single request hangs unbounded.

### T8 — Supply-chain tampering (boundary 4, distribution)
A backdoored binary/image swapped onto the release page must be detectable. **Mitigation:** every
release ships a CycloneDX SBOM and a signed Sigstore build-provenance attestation (SLSA Build L2) for
the binaries and both container images, plus a cosign-signed GHCR image. Release artifacts are built
only from a signed version tag by a public workflow. See the
[Security page](https://getbusbar.com/security/) for verification recipes.

### T9 (Malicious dynamic plugin, boundary 4)
A dynamic store/auth/hook plugin is native code loaded with `dlopen`; it runs in-process with full
engine privileges, so a hostile or tampered plugin is a code-execution foothold. **Mitigation:** the
whole subsystem is **off by default** (`plugins.enabled: false`; with it off, a tarball dropped in
`plugins.dir` is inert). When enabled, every plugin's signed `manifest.json` is verified against the
ed25519 **release key embedded in the binary**: first-party (busbar-signed) plugins pass with zero
config, third-party keys must be allowlisted under `plugins.trust.publishers`, and loading anything
unsigned or third-party requires the explicit `allow_unsigned` / `allow_third_party` opt-ins (both
default `false`). `plugins.min_versions` floors block replaying an older signed build (first-party
versions are auto-floored at the running binary's version). The loader maps **only the verified bytes**
(`memfd_create` on Linux, a private staging file elsewhere); a pre-existing on-disk library is never
loaded, so the bytes that pass the signature check are the bytes that run. An untrusted plugin is
logged and skipped, never `dlopen`ed. This narrows but does not eliminate the risk: a plugin you
choose to trust and load is trusted code by definition (see out-of-scope below).

### T10 — Credential custody in plugins (boundary 4; the credential chip, 1.6.0)
A plugin that authenticates to something (a store, an identity provider, a webhook, a provider)
needs a credential, and a plugin is code someone else may have written. **Mitigation:** a plugin is
never handed a credential as text. The plugin SDK's `Cred` (and the `Seal` a recipe makes from it)
has no getter, no `Debug`, no `Display` and no `Serialize`; printing or serializing one does not
compile. The plugin asks the SDK's recipes ("the chip") to perform the auth step — a Postgres
password or SCRAM message, a MySQL handshake, an LDAP bind, a RESP `AUTH`, Basic/Bearer, HMAC,
AWS SigV4, JWS — and the SDK writes the result to the wire from a wiped buffer. A setting the
plugin declares secret is sealed as it is parsed, a URL's password is split off at parse, and no
settings error quotes a value. Further rules:
- **Declared fields only.** A secret reference (`{env:}`, `{secret:}`, `{file:}`) at a plugin
  setting the plugin has not declared secret is refused at boot and by `--validate`, naming the
  field and the plugin.
- **The operator's URL decides how a credential travels.** A credential written in an `https`,
  `rediss`, `ldaps` (…) URL, or with a TLS mode that refuses cleartext (`sslmode=require`, …), goes
  out only on a connection the host connector reports secured; otherwise nothing is sent.
- **No downgrade.** An auth method weaker than the server offers (Postgres cleartext or MD5 where
  SCRAM is available; MySQL cleartext or old-password) is refused unless the operator allows it in
  config, and the refusal is explained and audited. MySQL RSA full authentication needs an operator
  key pin, TLS or a unix socket.
- **At rest.** A recoverable credential busbar mints (a signed-request secret) is sealed under a
  dedicated at-rest key before any store sees it; a `previous` key keeps rotation from breaking
  stored credentials, and rows are re-wrapped under the current key.
- **Every plugin is tested for it.** Each plugin's conformance suite configures a canary credential
  and fails if any spelling of it (raw, percent-encoded, base64, hex) crosses back through an answer
  or a log record.

**Residual, accepted for 1.6.0 (owner ruling).** Plugins run in busbar's process, and the chip runs
inside each plugin. Native code in the same address space can read memory, so a plugin that is
*malicious* — rather than careless — can recover a credential it was configured with. The
mitigations above remove every accidental path (logs, errors, `Debug`, dumps, the store, the
wrong host) and every ABI path; they do not stop deliberate in-process memory access. The
controls against a malicious plugin are therefore the ones in T9: plugins are off by default, every
dropped-in plugin is signature-verified, and third-party publishers must be allowlisted. A plugin
linked into a custom build is **first party by the operator's choice** and is trusted as such.

## Explicitly out of scope

- The security of the **upstream providers** themselves.
- **Host / OS / kernel** compromise of the machine Busbar runs on.
- Operators who deliberately configure Busbar insecurely (`admin_insecure: true`, an empty auth
  chain in production, `security.allow_all_metadata`) — these are documented foot-guns, gated behind
  explicit flags, and warned at boot.
- Physical access and side-channels beyond the timing-safe comparisons noted above.
- A malicious plugin reading a credential out of busbar's own process memory (T10's accepted
  residual; T9's controls decide which plugins load).
- Not part of 1.6.0 at all: HashiCorp Vault raw-stream and transit use, SRTP keying material, and
  the busbar release signing key are outside the credential chip's custody.

## Validation

The mitigations above are exercised by the unit suite (2,000+ tests), an offline acceptance harness
(protocol-translation matrix, SigV4 signature verification, TLS/mTLS handshakes, boot-refusal,
governance), and a full-codebase security audit. Boundary or mitigation changes must keep those green.
