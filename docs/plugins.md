# Plugins

Busbar ships as one small self-contained binary, no runtime, no interpreter, no sidecar (see the
image-size badge on the repo), with nothing compiled in that you did not ask for: no SQLite built in
(add it as a signed plugin), no Postgres, no Valkey. The default deploy needs no plugins at all.
When you do need more, a durable store, a secret backend, auth or hook modules, you add exactly that
capability as a signed plugin tarball dropped into a directory. Lightweight by default, extend when
needed.

A plugin is a plugin: store, secret, auth, and hook plugins share ONE artifact format, ONE trust model, ONE
loader, and ONE inventory (`busbar --list-plugins`). The manifest `kind` field is the only
discriminator; it selects which C ABI the cdylib exports and which engine subsystem consumes it.
The engine itself never sees any of this machinery. It receives a `dyn Store` (or a `dyn SecretModule` /
`dyn AuthModule` / `dyn HookHandler`) trait object through the `busbar-api` contract, exactly as if
the backend had been compiled in. The engine cannot tell a dynamic plugin from a built-in, and the
crate boundaries enforce it: all plugin discovery, unpacking, verification, and loading lives in
the `plugin-*` crates, and the engine crate keeps `#![forbid(unsafe_code)]` with every FFI
`unsafe` isolated in `busbar-plugin-loader`.

- [What makes it a plugin](#what-makes-it-a-plugin)
- [The artifact](#the-artifact)
- [Enabling plugins](#enabling-plugins)
- [Building a store plugin](#building-a-store-plugin)
- [Secret plugins (`kind: secret`)](#secret-plugins-kind-secret)
- [Auth plugins (`kind: auth`)](#auth-plugins-kind-auth)
- [Hook plugins (`kind: hook`)](#hook-plugins-kind-hook)
- [Signing and packaging](#signing-and-packaging)
- [Fail-closed loading](#fail-closed-loading)
- [How plugins are secured](#how-plugins-are-secured)
- [Inspecting and validating](#inspecting-and-validating)

## What makes it a plugin

"A plugin is a plugin" above is a claim, and it is enforced mechanically rather than reviewed by
hand. The rule: **anything busbar calls a plugin must survive being made downloadable-only.** If it
shipped uninstalled tomorrow, core would still have to work: boot, serve, and answer. If core stops
working, then core assumed it always had that module, and that module is not a plugin; it is part of
the engine wearing a plugin's name.

`scripts/no-plugins-gate.sh` (CI job `no-plugins-gate`) is that rule, executable. It uses a config
that references zero plugins: only `keys` (the inline signed-key verifier), `weighted` (the inline
SWRR floor), and `store.module: memory` (the one store that is not a plugin). Against that config it
runs busbar two ways:

- **compiled out**: built `--no-default-features`, so the built-in plugin features
  (`auth-admin-tokens`, `hooks-ranking`) are not in the binary at all;
- **not installed**: built with default features, but `plugins.dir` holds zero artifacts, which
  catches core assuming some `dlopen`ed plugin is present on disk. The first axis cannot see this:
  a compiled-in feature is not a dlopened artifact.

Both axes must boot, serve `/healthz`, answer the admin plane (real reads *and* a real write), and
proxy a real request end-to-end to a real upstream. Every one of those is an assertion on an actual
response, never an inference from a successful compile. The gate additionally asserts that the two axes'
response codes are identical across the whole probed surface: removing the built-in plugins must
change nothing core serves.

What is *not* a violation: a config that names a plugin the binary does not have. That is a loud,
fail-closed boot error, and it is the compliance-by-compilation guarantee working as designed.
`auth.admin_auth: [admin-tokens]` on a `--no-default-features` binary refuses to boot rather than
silently disabling the admin API. The gate uses exactly that case as a self-test fixture it must
catch.

## The artifact

One plugin is one `.tar.gz` per (plugin, target) containing exactly two members:

- the cdylib (`.so` / `.dylib` / `.dll`) exporting the C ABI for its `kind`;
- `manifest.json`, the signed manifest.

```json
{
  "name": "busbar-store-valkey-plugin",
  "alias": "valkey",
  "kind": "store",
  "version": "1.5.0",
  "publisher": "busbar",
  "abi_version": 2,
  "sha256": "<64-hex sha256 of the cdylib bytes>",
  "signature": "<128-hex ed25519 signature over the canonical manifest>",
  "description": "busbar valkey store plugin",
  "homepage": "",
  "license": "Apache-2.0"
}
```

`host` (optional, absent above) declares which product this manifest was packaged for: `busbar`
(the engine, and the implicit default when the field is absent, so every manifest packed before this
field existed keeps loading unchanged) or a sibling product's own identity, e.g. `busbar-ui`.
`busbar` and a sibling product like `busbar-ui` deliberately reuse this exact manifest/signing/ABI
machinery, and their plugin `kind` strings overlap by name (`store`, `auth`, `secret`) even though
the payload contracts are incompatible. A busbar-ui `store` plugin persists tenants/deployments,
an engine `store` plugin persists keys/denylists. `host` is signed (covered by the manifest
signature, so it cannot be spoofed) and checked structurally at load time: the loader refuses to
load any manifest whose `host` is present and does not match this binary's own identity (`busbar`),
even if the manifest is validly signed. A foreign-host plugin never gets far enough to be
laundered through a loose trust posture.

The signature covers every field except `signature` itself (deterministic sorted-key JSON), and
`sha256` pins the manifest to the exact library bytes, so neither the manifest nor the library can
be altered or swapped independently. Identity comes from the signed manifest, never the filename:
you can name the tarball anything.

> **Cross-language verifiers: the signature is over a canonical *re-serialization*, not the
> manifest member's raw bytes as they appear in the tarball.** This works transparently as long as
> your verifier's JSON serializer escapes identically to Rust's `serde_json`, which is not the
> default in every language. The failure mode is dangerous: every manifest verifies correctly
> until one field happens to contain a character your serializer escapes differently, then
> signature verification fails with no indication that character encoding is the cause. If you are
> writing a non-Rust verifier (Go, Python, TypeScript, ...) that re-encodes the parsed manifest
> struct before hashing/verifying, you MUST reproduce `serde_json`'s exact escaping, specifically:
>
> - `<`, `>`, `&`: some JSON encoders (e.g. Go's `encoding/json` by default) escape these; `serde_json` does not.
> - U+2028 (LINE SEPARATOR), U+2029 (PARAGRAPH SEPARATOR): some encoders always escape these; `serde_json` does not.
> - `0x08` (backspace), `0x0C` (form feed): `serde_json` writes `\b` / `\f`; some encoders write `` / ``.
>
> The simplest way to avoid this class of bug entirely: canonicalize from the manifest member's
> **raw bytes as they appear in the tarball**, rather than parsing and re-serializing. A sibling
> product (busbar-ui) does exactly this, and its own test fixtures deliberately include an `&`,
> `<`, and `>` in a URL field to keep the case covered.

`name` is the canonical identity (`[a-z0-9-]+`, e.g. `busbar-store-valkey-plugin`); `alias` is the short
config name (`valkey`). `store.module:` accepts either. `kind` is `store`, `secret`, `auth`, or `hook`.
`version` is strict semver. `abi_version` declares which per-kind payload-schema generation the
cdylib was built against. It is set **per kind**: `store` and `auth` are at `2`, `secret` and
`hook` at `1` (auth was bumped 1→2 in 1.5.2 for the additive browser-login primitives). The loader
enforces a supported-version RANGE per kind, so a plugin built against an outdated (or too-new) ABI
is refused at load rather than mis-called. See `busbar-plugin-abi` for the authoritative versions.

## Enabling plugins

Plugins are OFF by default. The top-level `plugins:` block is the whole configuration surface:

```yaml
plugins:
  enabled: true          # master switch, default false: off = nothing in the dir ever loads
  dir: plugins           # where the tarballs live
  trust:
    publishers:          # third-party signing keys only; busbar's own key is embedded
      - name: acme
        public_key: "<64-hex ed25519 public key>"
    allow_unsigned: false
    allow_third_party: false
  min_versions:
    acme-store-dynamo: "2.0.0"

store:
  module: valkey          # alias or canonical name, resolved against the signed manifests
  settings: { url: "rediss://:password@valkey.internal:6380/0" }
```

With `enabled: false` (or the block absent) a tarball in the directory is inert: Busbar does not
read it, and referencing a plugin store (`store.module: valkey`) fails boot with an error naming
`plugins.enabled`. See [configuration.md](configuration.md#plugins) for the field reference.

## Building a store plugin

The kind-specific sections below carry the auth, secret, and hook build examples. A store plugin in
Rust is small. Implement the `busbar_api::Store` trait (or wrap an existing
implementation), adapt the JSON config Busbar passes at open, and let the SDK emit the C glue:

```rust
// Cargo.toml:
//   [lib]
//   crate-type = ["cdylib"]
//   [dependencies]
//   busbar-api = { .. }
//   busbar-plugin-sdk = { .. }
//   serde_json = "1"

use busbar_api::Store;

fn open(cfg: &str) -> Result<Box<dyn Store>, String> {
    // `cfg` is the store's own `settings` map, passed through verbatim as JSON.
    let v: serde_json::Value = serde_json::from_str(cfg).map_err(|e| e.to_string())?;
    let url = v.get("url").and_then(|x| x.as_str()).ok_or("missing url")?;
    Ok(Box::new(MyStore::connect(url)?))
}

busbar_plugin_sdk::export_store_plugin!(open);
```

`export_store_plugin!` emits the six kind-neutral extern-C symbols of the plugin ABI (`busbar_abi`,
`busbar_plugin_kind`, `busbar_open`, `busbar_call`, `busbar_free`, `busbar_close`). Every store
operation rides one `busbar_call` symbol as a
JSON-serialized `StoreRequest`/`StoreResponse` pair, so the symbol set never grows as the trait
does, and a plugin can equally be written in C, Go, or Zig against the same contract
(`busbar-plugin-abi` is the source of truth). The store sits off the request hot path
(write-behind), so JSON serialization never touches request latency.

Build per target:

```sh
cargo build --release -p my-store-plugin                      # host target
cargo build --release -p my-store-plugin --target aarch64-unknown-linux-gnu
```

## Secret plugins (`kind: secret`)

Every secret value in the config (provider `api_key`, `auth.signing_key`, the admin token, each
TLS `cert`/`key`/`client_ca`) is a secret **reference**, not a literal. The two built-in reference
forms (`{ env: VAR }` and `{ file: /path }`) need no plugin. A `kind: secret` plugin adds a third
form, `{ module: <secret-plugin>, settings: {...} }`, so a reference resolves from an external
secrets backend (a vault, a cloud secret manager) through the same signed-plugin trust pipeline.
This is the plugin you reach for when key material must never sit in an env var or an on-disk file.

A secret plugin implements `busbar_api::SecretModule` (`resolve(&self, settings: &Map<String,
Value>) -> SecretResult<Vec<u8>>`). Note it is `settings`, not a single `key`. `resolve` is
STATELESS per call: one module instance serves every reference naming it, each carrying its own
`settings` map (the `{ module: vault, settings: {...} }` shape above), not a value baked in at
`open` time. Busbar resolves every reference **once at boot** (and on each hot config-apply), before
the value crosses any other ABI, so a raw secret is never logged and never written back to the
overlay. Only the reference is persisted. An unresolvable reference is a fatal boot / config-apply
error naming the reference.

```rust
// crate-type = ["cdylib"]; deps: busbar-api, busbar-plugin-sdk, serde_json
use busbar_api::{SecretError, SecretModule, SecretResult};

struct MyVault { /* connection state built once at `open` */ }

impl SecretModule for MyVault {
    fn resolve(&self, settings: &serde_json::Map<String, serde_json::Value>) -> SecretResult<Vec<u8>> {
        let path = settings.get("path").and_then(|v| v.as_str())
            .ok_or_else(|| SecretError("missing `path` in secret reference settings".to_string()))?;
        self.fetch(path).map_err(|e| SecretError(e.to_string()))
    }
}

fn open(cfg: &str) -> Result<Box<dyn SecretModule>, String> {
    // `cfg` is the MODULE's own open-time `settings:` map (e.g. the vault address + auth), verbatim
    // JSON, and distinct from the per-REFERENCE `settings` `resolve` receives above.
    Ok(Box::new(MyVault::connect(cfg)?))
}
busbar_plugin_sdk::export_secret_plugin!(open);
```

A complete, compiling reference implementation (a fixed in-memory map, no network) lives at
`crates/secret-example-plugin` and is exercised end-to-end over the real C ABI by
`busbar-plugin-loader`'s `load_and_exercise_secret_example_plugin` test. This doc example is kept
honest against it, not written once and left to drift.

Reference it from any secret field, for example a provider credential pulled from a vault:

```yaml
providers:
  openai:
    api_key: { module: acme-vault, settings: { path: "kv/data/openai#api_key" } }
```

The MODULE's own open-time config (the vault address + auth) is delivered by a top-level `secrets:`
entry, keyed by the module name/alias, exactly as `store.settings` carries a store plugin's `open()`
config:

```yaml
secrets:
  acme-vault:
    settings: { addr: "https://vault.internal:8200", token: { env: VAULT_TOKEN } }
```

The first-party **`vault`** module (`busbar-hashicorp-vault-plugin`, released from
[`GetBusbar/hashicorp-vault`](https://github.com/GetBusbar/hashicorp-vault)) is exactly such a
plugin: the first-party HashiCorp Vault KV v2 backend (a same-repo `hashicorp-vault` crate for the
logic, `hashicorp-vault-plugin` for the thin cdylib adapter, mirroring the `busbar-auth-oidc` /
`busbar-auth-oidc-plugin` split). Open-time config is
`{ addr, token, ca_cert_pem?, timeout_secs? }`; auth is a pre-obtained `X-Vault-Token` only, Vault's
simplest and most universal scheme. AppRole/Kubernetes login flows are a natural future extension of
`busbar-hashicorp-vault` itself. Per-reference `settings` accepts the `#field` suffix shown above
(`path: "kv/data/openai#api_key"`) OR the equivalent two-key form `{ path: "kv/data/openai", field:
"api_key" }` for callers that would rather not embed `#` in one string; `field` wins if both are
given. `path` is the full Vault v1 API path INCLUDING the KV v2 `data/` segment (i.e. exactly what
`vault kv get`/the Vault UI show), read via `GET {addr}/v1/{path}` with `X-Vault-Token: <token>`. A
404 (no secret there), a 403 (bad token / missing policy), and a 5xx (Vault itself unhealthy) each
surface as a distinct, specific error, never collapsed into a generic failure.

> **Not the built-in `keys` identity provider.** A `kind: secret` plugin resolves *config secret
> references* (fetching key material from a backend). The built-in `keys` module in `auth.chain`
> is data-plane **virtual-key auth**. It verifies the Busbar-signed caller tokens minted through
> the Admin API. Different layers: one supplies secret VALUES to the config, the other
> AUTHENTICATES callers. See [configuration.md → environment interpolation](configuration.md#environment-interpolation)
> for the secret-reference shape (`{ env: VAR }` / `{ file: /path }` / `{ module: <secret-plugin>, settings: {...} }`)
> and [configuration.md → `auth`](configuration.md#auth) for the `keys` module.

## Auth plugins (`kind: auth`)

A `kind: auth` plugin is a first-class **identity provider**: it implements the same
`busbar_api::AuthModule` trait the built-in modules do (`name()` + `authenticate()` returning
`Identify(principal)` / `Reject` / `Pass`), and the engine loads it **in-process** at boot over the
signed hybrid ABI, exactly like a store or secret plugin, same trust posture, same loader. It runs
in the data-plane **`auth.chain`**: name it there and the engine resolves it against the plugins
directory, loads it, and boxes it into the chain.

```rust
// crate-type = ["cdylib"]; deps: busbar-api, busbar-plugin-sdk, serde_json
use busbar_api::{AuthModule, AuthOutcome, Principal};

struct MyIdp { /* … */ }
impl AuthModule for MyIdp {
    fn name(&self) -> &'static str { "myidp" }             // the RUNTIME module identity
    fn authenticate(&self, candidate: Option<&str>) -> AuthOutcome {
        match verify(candidate) {
            Some((id, groups)) => {
                let mut p = Principal::from_id(id);
                p.roles = groups;                            // roles/groups the IdP asserts
                AuthOutcome::Identify(p)
            }
            None => AuthOutcome::Pass,                        // not my credential, so defer
        }
    }
    fn cacheable(&self) -> bool { true }                     // per-call I/O ⇒ opt into the cred cache
}

fn open(cfg: &str) -> Result<Box<dyn AuthModule>, String> {
    // `cfg` is the chain entry's own `settings:` map, passed through verbatim as JSON.
    Ok(Box::new(MyIdp::from_config(cfg)?))
}
busbar_plugin_sdk::export_auth_plugin!(open);
```

An identity provider returns **identity only**: who the caller is (`id` + `roles`). Policy (which
pools, which group's limits, which admin scope) is resolved by Busbar from
`auth.role_bindings.<provider>` and capped by that provider's `max_admin_scope`, never asserted by
the plugin. As of 1.5.3 `<provider>` is the NAME you chose in the top-level `identity-providers:`
map (the definition key you also write in `auth.chain:`), which is what lets one plugin back two
providers with independent bindings and ceilings.

Like every configured plugin, an auth plugin that cannot load is a hard error and never silently
degrades. See [Fail-closed loading](#fail-closed-loading), below.

The first-party **`oidc`** module (`busbar-auth-oidc-plugin`, released from `GetBusbar/auth-oidc`)
is exactly such a plugin. See
[configuration.md](configuration.md#auth-plugins) for the `auth.chain: [oidc]` + `settings:` recipe
(including an Entra ID example, and the **app roles vs. security groups** gotcha that trips up most
first-time Entra setups).

### First-party auth plugins

Three first-party `kind: auth` plugins ship for busbar, each an independently-versioned repo:

| Plugin | Repo | Identity | Flow |
|--------|------|----------|------|
| **`oidc`** (`busbar-auth-oidc-plugin`) | `GetBusbar/auth-oidc` | `oidc:<sub>` from a verified id_token (RS256/ES256 JWKS, iss/aud/exp/nbf) | verify a held bearer, **or** browser/headless [token-exchange](token-exchange.md) |
| **`github`** (`busbar-auth-github-plugin`) | `GetBusbar/auth-github` | `github:<login>` + `github:org/<org>` groups | OAuth authorization-code (opaque token → core-executed `/user` + `/user/orgs` hops), via the [token-exchange](token-exchange.md) `GET` browser flow |
| **`ldap`** (`busbar-auth-ldap-plugin`) | `GetBusbar/auth-ldap` | `ldap:<dn>` + `memberOf` groups | credential form (username/password → the plugin's own LDAP/LDAPS bind), via the [token-exchange](token-exchange.md) credential flow |

GitHub is **not** OIDC (its access token is opaque, so there is nothing to verify offline): identity
comes from REST userinfo hops the core executes on the plugin's behalf. LDAP is a **credential**
method. It renders a username/password form and binds against the directory itself. All three are
login-capable (Auth ABI v2), so they can mint a self-serve key via `/auth/token`; a v1 verify-only
build still loads for chain use but a hosted-login (`browser_login`) method requires a v2 build.

## Hook plugins (`kind: hook`)

Hook plugins load over the same signed hybrid ABI as store, secret, and auth plugins. They are
in-process dlopen consumers: the hook `cdylib` exports the six kind-neutral C symbols
(`busbar_abi`, `busbar_plugin_kind`, `busbar_open`, `busbar_call`, `busbar_free`, `busbar_close`)
and the engine loads and calls it directly. Trust is signature-based, not process-based: the
manifest `kind` is cross-checked against `busbar_plugin_kind()` at load, and the signed `needs`
field caps what grants the plugin may receive. For process isolation of out-of-process logic, the
first-party `busbar-webrequest-hook` plugin forwards the decision to an HTTPS sidecar (1.5.0
retired the standalone built-in `socket`/`webhook` transports; a hook is now always a signed
plugin).

A hook plugin implements the SDK's `HookHandler` trait: one method per op, each receiving the op's
payload as the opaque projection `serde_json::Value` the engine built and returning the reply object
the engine parses through its existing fail-closed normalizers. Every method has a default, so a
trivial hook implements only the ops it cares about (a ranking gate implements just `decide`; a
compressor just `transform`); the rest degrade to the safe abstain/no-op replies the engine already
treats as fail-open. The SDK emits the ABI glue:

```rust
// crate-type = ["cdylib"]; deps: busbar-plugin-sdk, serde_json
use busbar_plugin_sdk::HookHandler;

struct MyGate { /* … */ }
impl HookHandler for MyGate {
    // `decide`: rank candidates / return a verdict. Return `{}` to abstain.
    fn decide(&self, payload: &serde_json::Value) -> serde_json::Value {
        let too_big = payload["request"]["total_chars"].as_u64().unwrap_or(0) > 100_000;
        if too_big {
            serde_json::json!({ "reject": { "status": 413, "message": "prompt too large" } })
        } else {
            serde_json::json!({})
        }
    }
    // Unimplemented ops (`transform`/`notify`/`configure`/`describe`/`status`) use the trait defaults.
}

fn open(cfg: &str) -> Result<Box<dyn HookHandler>, String> {
    // `cfg` is the hook instance's own `settings:` map, passed through verbatim as JSON.
    Ok(Box::new(MyGate::from_config(cfg)?))
}
busbar_plugin_sdk::export_hook_plugin!(open);
```

`export_hook_plugin!` emits the six extern-C hybrid ABI symbols. Every op rides the one `busbar_call`
as an op-discriminated JSON envelope: the `decide`/`transform`/`notify`/`configure`/`describe`/
`status` payload contract, one op per envelope. The engine translates each `HookHandler` method into a
`busbar_call` and parses the reply through the ONE `hooks::wire` fail-closed normalizer, so the
dlopen and out-of-process seams can never diverge on reject-precedence, the status clamp, or
restrict/rewrite parsing. A hook never sees `prompt`/`user` content it was not granted: the engine
projects those keys into `payload` only when BOTH the operator grant and the signed-manifest `needs`
allow it.

A hook is packed and signed like any other plugin (see [Signing and packaging](#signing-and-packaging)),
with one hook-specific addition: `--needs-prompt` / `--needs-user` declare the plugin's grant intent
in the signed manifest `needs` field. The core enforces the actual projection, so a plugin can never
self-grant above what it declares.

As with every plugin kind, a configured `kind: hook` module that cannot load fails closed. See
[Fail-closed loading](#fail-closed-loading), below.

**Shipped first-party hook plugins (1.5.0):**

- **Headroom** (`busbar-headroom-hook`): a `prompt: rw` gate that compresses context before
  dispatch, saving tokens and latency. Reports `chars_saved_total` via the `status` op.
- **Webrequest** (`busbar-webrequest-hook`): an HTTP-forwarder gate, the out-of-process isolation
  path for code you don't want in-process. Forwards the routing projection over HTTPS to an
  operator-run sidecar (any language). SSRF-guarded, signed by release CI.

Both are auto-trusted by the embedded release key; no `trust.publishers` entry is needed.

## Settings schema (`settings_schema`)

A plugin's manifest may carry `settings_schema`: a JSON Schema (draft 2020-12) document describing
the shape of its `settings:` block, embedded and signed alongside everything else. It powers `GET
/plugins/{name}/schema`. A UI can render an install/config form for a plugin **without ever
loading it**, because the schema comes from the signed manifest, not a runtime `describe` call
(store/secret/auth plugins have no such call). A `kind: hook` plugin's live `describe`
narrows this baseline when the plugin is loaded and answers; the manifest schema is what every kind
gets, including one that has never run.

Pass `--settings-schema-file <path.json>` to `busbar-plugin-pack pack`. The file is validated,
never generated, at pack time:

- `$schema` must be EXACTLY `"https://json-schema.org/draft/2020-12/schema"`. An older/missing draft
  is a hard pack-time error (busbar-ui's form renderer understands 2020-12 only).
- The document must otherwise be a syntactically valid JSON Schema.
- `--schema-derived` asserts (self-attested, not verified by this tool) that the file was generated
  by a build-time macro from the same Rust config struct `open()` parses, rather than hand-written.
  The assertion is copied verbatim into the manifest's `schema_derived` field. Consumers must not treat
  `schema_derived: true` alone as a verified guarantee: it is load-bearing only paired with a
  `trusted` verdict AND `publisher == "busbar"` (a self-declared `publisher` string is never, on its
  own, proof of anything). See `crates/plugin-loader/src/registry.rs`'s existing refusal to derive a
  trust label from it.

### `x-busbar-secret`: marking a field as a secret

`x-busbar-secret: true` on a property means the field's value is a **reference**, never a plain
value: busbar-ui composes one of

```json
{"env": "VAR_NAME"}
{"file": "/path/to/secret"}
{"module": "vault", "settings": {"...": "..."}}
```

(the exact shapes accepted by `SecretRef`, now in the standalone `busbar-secret-ref` crate), and
busbar core resolves the reference to a plain value BEFORE the plugin's `open()` ever sees it. A
bare string in a marked field is a config-authoring error, not a valid value.

Pack-time rules (hard errors, not warnings):

- A marked field must be `type: string`, optionally with `contentEncoding: "base64"` for a binary
  secret (a private key, certificate, or keytab represented as base64/PEM text. The referenced
  source, env var or file, must ALREADY be clean UTF-8 base64/PEM text; the engine does not decode
  binary on the way through, it fails resolution on non-UTF-8 source bytes).
- A marked field must be a DIRECT member of the schema's root `properties`, never nested, and never
  inside `items`/`prefixItems`/`oneOf`/`anyOf` (busbar's `resolve_settings()` only ever resolves
  top-level fields; a nested marker would silently never resolve). `$ref`/`$defs`/`allOf` are
  resolved before this check, so a struct-derived nested field can't evade it by hiding behind a
  `$ref`. A legitimately nested secret-bearing struct field (e.g. `tls: { key: String }`) must be
  flattened to a root property instead (`tls_key`, not `tls.key`). A variable-length list of secrets
  (`upstreams: [{api_key}, ...]`) has no supported shape in v1. Collapse it into one root secret
  reference whose resolved value is a blob the plugin parses itself, or (for a small/fixed count)
  model it as named root fields (`upstream_primary_api_key`, `upstream_backup_api_key`).
- An UNMARKED field whose name matches
  `password|secret|token|credential|passphrase|private_key|apikey|api_key` (case-insensitive, at any
  depth) is also a hard error. Mark it or rename it. This is the mitigation against a third-party
  author silently shipping a plaintext-credential text box with no marker at all.

### `x-busbar-ref`: referencing an engine object

`x-busbar-ref: "pool" | "group" | "model" | "provider"` on a field tells busbar-ui to render a
picker populated from the matching admin listing endpoint, instead of a free-text box, closing the
"typo'd reference only discovered at apply time" failure mode. This is a UI rendering hint ONLY:
there is deliberately no server-side (or pack-time) enforcement of the value, because
pool/group/model/provider names are runtime data scoped to a single busbar instance. No manifest
schema, and no single fleet member's `describe`, could ever enumerate the valid set for an entire
fleet at template-authoring time. A fleet template using `x-busbar-ref` is validated per-member, at
apply time, against that member's own admin API listing.

### `x-busbar-restart-required`: restart scoping

Whether a settings change needs a process restart to take effect is a property of the ENGINE's
binding lifecycle for that plugin `kind`, not something a plugin author has visibility into:
`store`/`secret` plugins bind once at process start (every field is restart-scoped by construction);
`hook`/`auth` plugin registries rebuild hot. The default is therefore DERIVED from `kind`, not
plugin-declared:

| kind     | default            |
|----------|--------------------|
| `store`  | restart-required   |
| `secret` | restart-required   |
| `hook`   | hot-appliable      |
| `auth`   | hot-appliable      |

A per-field `x-busbar-restart-required` overrides the kind default, but only in ONE direction
without qualification: `true` (more restart-cautious than the kind default) is always honored. The
safe direction to be wrong in is an unnecessary restart. `false` against a kind default of `true`
(claiming a `store`/`secret` field is hot-appliable) is honored ONLY when the manifest's trust
verdict is `trusted` AND `publisher == "busbar"`. That is the same trust+publisher gate
`schema_derived` uses, for the same reason: a third-party claim in the direction that could cause a silently-dropped
setting is not trusted; a claim in the fail-safe direction is.

## Signing and packaging

Generate a keypair once (the private half is your signing secret; the public half is what
operators allowlist):

```sh
busbar-plugin-pack keygen
# private (BUSBAR_SIGN_KEY, keep secret): 9f2c...
# public  (publishers allowlist / BUSBAR_RELEASE_PUBKEY): 4ab1...
```

Then sign and package in one step:

```sh
BUSBAR_SIGN_KEY=9f2c... busbar-plugin-pack pack \
    --lib target/release/libmy_store_plugin.so \
    --name acme-store-dynamo --alias dynamo --kind store \
    --version 1.0.0 --publisher acme \
    --license Apache-2.0 \
    --out acme-store-dynamo-1.0.0-x86_64-linux.tar.gz
```

The tool computes the `sha256` binding, signs the canonical manifest, self-checks the result
against the same structural validation Busbar runs at load, and writes the tarball. For local
development, `--allow-unsigned` (with no `BUSBAR_SIGN_KEY`) packages an unsigned tarball that
Busbar loads only under `plugins.trust.allow_unsigned: true`.

`--kind` selects the plugin kind (`store` / `secret` / `auth` / `hook`). A `kind: hook` pack adds
the grant-declaration flags `--needs-prompt <no|ro|rw>` and `--needs-user <no|ro>`, which stamp the
signed manifest `needs` field. The core enforces the actual projection, so a plugin can never
receive more than it declared.

Every first-party plugin is built and signed with the same `BUSBAR_SIGN_KEY` / publisher `busbar`
signing identity, but the *release* it ships from depends on the plugin:

- **Store plugins** (`busbar-store-sqlite`, `busbar-store-postgres`, `busbar-store-mysql`,
  `busbar-store-valkey-plugin`), the **auth plugin** (`busbar-auth-oidc`), and the **secret plugin**
  (`busbar-hashicorp-vault`) each live in their own standalone repo (`GetBusbar/store-sqlite`,
  `GetBusbar/store-postgres`, `GetBusbar/store-mysql`, `GetBusbar/store-valkey`,
  `GetBusbar/auth-oidc`, `GetBusbar/hashicorp-vault`) with its own CI and its own release workflow. Download the tarball for the backend you need from *that plugin's own*
  GitHub Release, not from busbar's.
- **Hook plugins** (`busbar-headroom`, `busbar-webrequest`) also live in their own repos
  (`GetBusbar/headroom-hook`, `GetBusbar/webrequest-hook`) with their own CI and release workflow,
  same as every other kind. Busbar's own release no longer builds or re-publishes any plugin
  tarball, hook or otherwise: download the tarball for the plugin you need from *that plugin's own*
  GitHub Release, not from busbar's.

Regardless of which repo's Release page a tarball comes from, release binaries embed the matching
public key, so every first-party plugin verifies with zero configuration. The signature is what
establishes first-party trust, not the hosting repo.

## Fail-closed loading

The guarantee is uniform across every plugin kind: a configured plugin that cannot load (a
missing or untrusted tarball, the wrong `kind`, a `dlopen`/ABI failure, or a reference to a plugin
while `plugins.enabled: false`) is a **hard boot / config-apply error**, named at the flag or file.
A dropped store, secret backend, identity provider, or security gate never silently disappears or
degrades to open. `busbar --validate` catches every one of these manifest-only, before boot, so a
clean validate means a clean load.

## How plugins are secured

Running third-party native code inside a gateway is the sharpest tool in this codebase, so the
design is fail-closed at every layer. The threat model, plainly: an attacker who can write to the
plugins directory, tamper with a tarball in transit, or push an artifact at the admin API must not
get code executed, and a compromised or replayed plugin must not load.

1. **Off by default.** `plugins.enabled` defaults to `false`. Nothing in the directory is read,
   let alone executed. Dropping a file somewhere is never enough.
2. **Signature trust, not location trust.** A plugin loads because its manifest signature verifies,
   not because of where the file sits. Busbar's release public key is embedded in the binary, so
   busbar-signed plugins are trusted with zero configuration. Third-party publishers must be
   explicitly allowlisted by key. Unsigned or unknown-publisher plugins are logged and skipped
   unless the operator sets the matching explicit opt-in (`allow_unsigned` / `allow_third_party`),
   and a skipped plugin is never `dlopen`ed: its initialization code never runs, not at boot, not
   from the admin catalog, not from `--list-plugins`.
3. **Anti-downgrade.** A validly-signed but OLD release is still a signed artifact an attacker can
   replay. First-party plugins are automatically floored at the running binary's version;
   `plugins.min_versions` pins floors for third-party plugins by manifest name. A floored plugin
   must prove, with a trusted signature over a version at or above the floor, that it meets it. No
   opt-in flag relaxes a floor.
4. **Structural fail-closed.** Before trust is even consulted, every tarball must unpack cleanly
   (bounded sizes, exactly two members, no path tricks), the manifest must be complete and
   well-formed, `sha256(lib)` must match, and the `abi_version` must be one this binary speaks.
   With plugins enabled, ANY invalid artifact in the directory aborts boot with the file and the
   exact reason named. There is no partial or degraded boot.
5. **Conflicts are hard errors.** No two loadable plugins may share a name or alias, and no alias
   may collide with another plugin's name. You cannot run the first-party `valkey` store and a
   third-party plugin that also claims `valkey`; boot stops and names both.
6. **Verified bytes are the loaded bytes.** The tarball is unpacked and verified fully in memory;
   the manifest never touches disk. On Linux the verified library bytes go into a `memfd` and are
   loaded from `/proc/self/fd/N`: zero disk files, no path for anyone to race or swap. On macOS
   and Windows the verified bytes are written to a fresh file inside a per-process private
   staging directory and loaded from there. On macOS that directory is created `0700` and the file
   `0600`. **On Windows it is neither**: mode bits do not exist there, so the staging directory and
   file are created with whatever the inherited ACL grants — in practice the per-user ACL on
   `%TEMP%`, which is narrower than a world-writable `/tmp` but is NOT the `0700` guarantee, and an
   operator running busbar as a user whose `%TEMP%` is shared does not get one. The properties that
   do NOT depend on mode bits hold on every platform: the file is regenerated from the verified
   bytes on every load, a pre-existing on-disk library is never loaded, and clean shutdown unloads
   the library and then removes the file. There is no time-of-check/time-of-use window between
   verification and load. The boot-time sweep of staging left by a **crashed** prior process is
   **unix-only**: it decides a prior pid is dead with `kill(pid, 0)`, and on Windows that liveness
   test is not implemented and reports every pid as alive, so the sweep removes nothing. A Windows
   deployment that crashes therefore accumulates one abandoned staging directory per crash under
   `%TEMP%`, to be cleared by the OS temp cleaner or by hand. This costs disk, not integrity —
   nothing on disk is ever trusted input, so an abandoned directory cannot be loaded from.
7. **The engine stays memory-safe.** The engine crate compiles under `forbid(unsafe_code)`; all
   FFI lives in `busbar-plugin-loader`. The loader also bounds every plugin response (a buggy or
   hostile plugin cannot force an unbounded allocation).
8. **The pre-flight gate is the boot gate.** `busbar --validate` runs the same
   consistency-policy-scan-resolution pipeline boot runs, so it cannot drift: if `--validate`
   passes, the plugin half of boot succeeds; if it fails, it names exactly what is wrong.

What signing does NOT do: a trusted plugin still runs with Busbar's privileges, exactly like a
compiled-in backend would. Signing answers "is this the artifact its publisher shipped, unmodified,
and current"; it does not sandbox the publisher. Allowlist publishers you would be willing to link
into the binary.

## Licensing a plugin

A license check is the plugin author's concern, not the gateway's. If a plugin needs one, put a `licenseKey` (or any
key it expects) in that plugin's `settings:`, and let the plugin validate it on `open`. The value
may be a `SecretRef`, in which case the core resolves it against the secret backend **before** the
settings cross the ABI, so a raw key never has to sit in plaintext config, is never logged, and is
never written back to the overlay (only the reference is persisted). An unresolvable ref fails the
load fail-closed. See
[ADR-0010](https://github.com/GetBusbar/busbar/blob/main/docs/adr/0010-plugin-licensing.md) for the
full model. The link is absolute because `docs/adr/` is a repository-only record and is not synced to
the published docs site, so a relative path resolves in a checkout and 404s for a reader on the web.

## Inspecting and validating

```sh
$ busbar --list-plugins
plugins dir: plugins (plugins.enabled: true)
FILE                               NAME                        ALIAS    KIND   VERSION   SIGNATURE                STATUS
busbar-store-valkey-1.5.0.tar.gz   busbar-store-valkey-plugin  valkey   store  1.5.0     first-party              LOADS (store.module: valkey)
busbar-store-sqlite-1.5.0.tar.gz   busbar-store-sqlite-plugin  sqlite   store  1.5.0     first-party              ready
acme-store-dynamo-1.0.0.tar.gz     acme-store-dynamo           dynamo   store  1.0.0     unknown-publisher        SKIPPED: publisher 'acme' is not in the allowlist; ...
old-valkey.tar.gz                  busbar-store-valkey-plugin  valkey   store  1.2.0     trusted (below floor)    REJECTED: ... (anti-downgrade)
broken.tar.gz                      -                           -        -      -         INVALID                  INVALID: manifest.json does not parse: ...
```

`--list-plugins` is manifest-only: it never loads plugin code, so it is safe to run against a
directory full of untrusted artifacts. `busbar --validate` is the gate: it validates
`config.yaml`, `providers.yaml`, and every plugin manifest (structure, signature and trust,
conflicts, ABI, version floors) with zero side effects, exiting 0 only when boot would succeed.

The admin API exposes the same manifest-only catalog (`GET /api/v1/admin/plugins?type=store`) and
can install or remove tarballs remotely through the identical trust gate; see
[admin-api.md](admin-api.md).
