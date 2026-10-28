// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin **manifest, signing input, structural validation, and trust evaluation** for busbar.
//!
//! A PLUGIN IS A PLUGIN: plugins of every kind share ONE manifest format and ONE trust
//! model, discriminated only by the manifest `kind` field. Every plugin ships as a signed tarball
//! containing exactly the cdylib and this manifest; identity comes from the SIGNED manifest, never
//! from the filename.
//!
//! The manifest carries:
//!
//! - **identity**: `name` (canonical, e.g. `busbar-store-valkey-plugin`), `alias` (the short config name,
//!   e.g. `valkey`), `kind` (`store` | `auth` | `hook` | `secret` | `export` | `plane` | `transport`), `version` (semver);
//! - **binding + compat**: `sha256` (of the library bytes, pinning the manifest to that exact
//!   binary) and `abi_version` (its `kind`'s one memory-ABI version, the only version fact admission reads);
//! - **authenticity**: `publisher` + `signature` over the *canonical whole manifest*;
//! - **display**: `description`, `homepage`, `license` (all signed, so they cannot be spoofed).
//!
//! The signature covers the entire manifest (every field except `signature` itself) via
//! [`canonical_manifest_bytes`], and the manifest pins the library by `sha256`, so **neither the
//! manifest nor the library can be altered or swapped independently**.
//!
//! ## Trust model
//!
//! - **First-party**: a manifest whose `publisher` is `busbar` verifies against one of the release
//!   public keys EMBEDDED in the binary ([`embedded_release_keys`], a list so a key can be rotated
//!   to the next one without a new binary) - trusted with ZERO configuration.
//! - **Revoked**: a library whose sha256 is on the compiled-in revocation list
//!   ([`REVOKED_DIGESTS`]) is refused whoever signed it, before any opt-in is consulted.
//!   First-party anti-downgrade is PER-PLUGIN: rollback pins (`first_party_floors`) and
//!   `plugins.min_versions` floors, both hard rejects. There is no automatic binary-version
//!   floor — first-party plugins version on independent lines (1.0.x/2.x under a 1.5.0 engine).
//! - **Third-party**: `plugins.trust.publishers` allowlists third-party signing keys. A valid
//!   signature from an allowlisted publisher is TRUSTED. `plugins.min_versions` pins per-plugin
//!   anti-downgrade floors (first- and third-party alike).
//! - **Everything else** (unsigned, tampered, unknown publisher) is UNTRUSTED and, by DEFAULT,
//!   rejected. The operator opts in per category via [`TrustPolicy::allow_unsigned`] and
//!   [`TrustPolicy::allow_third_party`].
//!
//! This MODULE is pure data + policy: no I/O, no engine state. Discovery, unpacking, and loading
//! live in this crate's other modules; the engine sees neither. [`sign`] exists for the release
//! pipeline / packaging tooling - OSS ships verification, not a signing service.
//!
//! ## Why NOT Sigstore keyless yet (1.5.0 spike outcome - deferred)
//!
//! A 1.5.0 spike of the `sigstore` crate (v0.14) found it cannot be adopted without regressing the
//! security gates: its tree carries `rsa 0.9.10` with RUSTSEC-2023-0071 (the Marvin RSA timing
//! sidechannel, "no safe upgrade available"), which `cargo deny check advisories` rejects, and it
//! roughly triples the dependency surface. When a mitigated release ships, the swap is localized to
//! [`evaluate`]'s signature check; the manifest shape and posture are primitive-independent.

// `SigningKey`/`VerifyingKey` are re-exported so external signing tooling can name them via this crate.
// No `Verifier` import: verification goes through the inherent `VerifyingKey::verify_strict`, not
// the permissive trait method — see `signature_ok`.
use ed25519_dalek::{Signature, Signer};
pub use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The reserved first-party publisher name. A manifest carrying this publisher verifies against the
/// EMBEDDED release keys ([`TrustPolicy::first_party_keys`]), never against `publishers` - an operator
/// cannot (and need not) allowlist a key named `busbar`.
pub const FIRST_PARTY_PUBLISHER: &str = "busbar";

/// The plugin kinds this binary understands. ONE plugin subsystem: `kind` only selects which kind's
/// table the door answers and which engine subsystem consumes it; discovery/trust/validation are
/// shared. Each kind's manifest `abi_version` is that kind's one version (`supported_abi`, THE DESIGN
/// §11.2). Every kind, `plane` and `transport` included, loads only through its door.
// One line, as it always was: the kind list is one statement, not seven.
#[rustfmt::skip]
pub const KNOWN_KINDS: &[&str] = &["store", "auth", "hook", "secret", "export", "plane", "transport"];

/// This binary's own host identity — the value [`Manifest::host`] must match (or omit) to load.
/// `busbar` names the OSS engine. A sibling product (e.g. `busbar-ui`) that reuses this exact
/// manifest/signing/ABI machinery stamps its own plugins `host: busbar-ui`; those manifests are
/// STRUCTURALLY VALID (same memory ABI, same signed-manifest shape, same `kind` vocabulary)
/// but semantically foreign — a `busbar-ui` `store` plugin persists tenants/deployments, not the
/// keys/denylists an engine `store` plugin implements. Same `kind` string, incompatible contracts,
/// so `host` is what disambiguates them structurally rather than trusting `kind` alone.
pub const HOST_IDENTITY: &str = "busbar";

/// One first-party ROOT key this build trusts: the id every refusal names, and the public key.
/// A root key vouches for keys documents ([`crate::release_trust`]); an ed25519 root key also
/// verifies a per-plugin `signature` directly (the pre-1.6.0 shape, kept for run keys and tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstPartyKey {
    /// The key's name (`busbar-plugins-root`), stated beside it in the key list. A bare-hex entry
    /// (a run key, a test key) is named `ed25519:<first 16 hex digits>` ([`FirstPartyKey::unnamed`]).
    pub id: String,
    /// The public key.
    pub key: ReleaseKey,
}

pub use crate::release_trust::ReleaseKey;

impl FirstPartyKey {
    /// An ed25519 key the list states no id for, named by its first 16 hex digits.
    pub fn unnamed(key: VerifyingKey) -> Self {
        let hex = hex::encode(key.as_bytes());
        FirstPartyKey {
            id: format!("ed25519:{}", &hex[..16]),
            key: ReleaseKey::Ed25519(key),
        }
    }
}

/// The build-time variable carrying the first-party key list ([`parse_release_keys`]).
pub const RELEASE_KEYS_ENV: &str = "BUSBAR_RELEASE_PUBKEY";

/// Parse a first-party ROOT key list: entries separated by `,`, each one of
///
/// * `<id>:p256:<130 hex>`: an ECDSA P-256 key, its 65-byte uncompressed SEC1 point;
/// * `<id>:ed25519:<64 hex>`: an ed25519 key;
/// * `<id>:<64 hex>`: an ed25519 key (the pre-1.6.0 spelling);
/// * `<64 hex>`: an unnamed ed25519 key ([`FirstPartyKey::unnamed`]; a run key).
///
/// Every entry must be a usable key; ids are valid plugin names (`[a-z0-9-]+`) and neither an id
/// nor a key may repeat. An empty list is refused: a list that names no key is a packaging bug,
/// not a choice.
///
/// # Errors
///
/// The first entry that is not a usable, unique key, naming it by position.
pub fn parse_release_keys(spec: &str) -> Result<Vec<FirstPartyKey>, String> {
    let mut keys: Vec<FirstPartyKey> = Vec::new();
    for (i, entry) in spec.split(',').map(str::trim).enumerate() {
        let n = i + 1;
        if entry.is_empty() {
            return Err(format!("{RELEASE_KEYS_ENV} entry {n} is empty"));
        }
        let parts: Vec<&str> = entry.split(':').map(str::trim).collect();
        let (id, key) = match parts.as_slice() {
            [hex_key] => (None, public_key_from_hex(hex_key).map(ReleaseKey::Ed25519)),
            [id, hex_key] => (
                Some(*id),
                public_key_from_hex(hex_key).map(ReleaseKey::Ed25519),
            ),
            [id, "ed25519", hex_key] => (
                Some(*id),
                public_key_from_hex(hex_key).map(ReleaseKey::Ed25519),
            ),
            [id, "p256", hex_key] => (Some(*id), ReleaseKey::p256_from_hex(hex_key)),
            [_, alg, _] => (
                None,
                Err(format!("algorithm '{alg}' is not one of ed25519, p256")),
            ),
            _ => (
                None,
                Err("is not <id>:<algorithm>:<hex>, <id>:<hex> or <hex>".to_string()),
            ),
        };
        let key = key.map_err(|e| format!("{RELEASE_KEYS_ENV} entry {n}: {e}"))?;
        let key = match (id, key) {
            (Some(id), _) if !valid_name(id) => {
                return Err(format!(
                    "{RELEASE_KEYS_ENV} entry {n}: key id '{id}' is not lowercase [a-z0-9-]+"
                ));
            }
            (Some(id), key) => FirstPartyKey {
                id: id.to_string(),
                key,
            },
            (None, ReleaseKey::Ed25519(k)) => FirstPartyKey::unnamed(k),
            (None, ReleaseKey::P256(_)) => {
                return Err(format!(
                    "{RELEASE_KEYS_ENV} entry {n}: a p256 key must be named"
                ));
            }
        };
        if let Some(dup) = keys.iter().find(|k| k.id == key.id || k.key == key.key) {
            return Err(format!(
                "{RELEASE_KEYS_ENV} entry {n} ('{}') repeats the id or key of '{}'",
                key.id, dup.id
            ));
        }
        keys.push(key);
    }
    Ok(keys)
}

/// The busbar first-party release keys embedded at BUILD time through `BUSBAR_RELEASE_PUBKEY`
/// ([`parse_release_keys`]). Empty in a build where it was not provided or does not parse: every
/// `publisher: busbar` plugin is then treated as unsigned (loadable only under `allow_unsigned`).
///
/// THE RELEASE KEYS. 1.6.0 trusts a LIST, held on hardware (the plugin key ceremony): the key that
/// signs today and the sealed next key, so a lost or compromised signing key is retired by
/// re-signing with the next one, with no new binary. The list is the `BUSBAR_RELEASE_PUBKEY`
/// repository variable, committed for local builds in `.cargo/config.toml` `[env]`; no private half
/// is ever in this tree or in CI. `scripts/release-key-guard.sh` refuses to build a release binary
/// without a well-formed list, and `scripts/release-gate/platform-checks.sh` fails the `pubkey` row
/// when the published artifact does not embed it.
/// (Owner ruling 2026-09-30, N3 / Q90: a statement of the contract, not a deferral.)
pub fn embedded_release_keys() -> Vec<FirstPartyKey> {
    // A malformed build-time list is a build/packaging bug; fail closed to "no first-party key"
    // rather than panic in the engine (the plugin then simply cannot verify as first-party).
    option_env!("BUSBAR_RELEASE_PUBKEY")
        .and_then(|spec| parse_release_keys(spec).ok())
        .unwrap_or_default()
}

/// THE REVOKED ARTIFACTS: `(sha256 of the library bytes, why)`. A library on this list is refused
/// whoever signed it and whatever the operator opted in to. Compiled in, so a revocation ships with
/// a binary; it is the answer to a signed plugin that must never load again (a key misuse, a
/// release pulled for a defect) while its signing key stays trusted for everything else.
pub const REVOKED_DIGESTS: &[(&str, &str)] = &[];

/// [`REVOKED_DIGESTS`] as the map [`TrustPolicy::revoked`] holds.
pub fn revoked_digests() -> BTreeMap<String, String> {
    REVOKED_DIGESTS
        .iter()
        .map(|(digest, why)| (digest.to_ascii_lowercase(), (*why).to_string()))
        .collect()
}

/// The signed manifest that travels inside every plugin tarball. Every field except `signature` is
/// covered by the signature (via [`canonical_manifest_bytes`]), so none can be altered undetected.
///
/// `deny_unknown_fields`: a manifest with fields this binary does not understand FAILS structural
/// validation (fail-closed) rather than silently dropping content the signature may cover.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Canonical plugin name, e.g. `busbar-store-valkey-plugin`. Lowercase `[a-z0-9-]+`.
    pub name: String,
    /// Short config alias, e.g. `valkey` - what `governance.store:` may reference. Lowercase
    /// `[a-z0-9-]+`. May equal `name`.
    pub alias: String,
    /// Plugin category (see [`KNOWN_KINDS`]). Selects the kind's door the cdylib exports and the
    /// engine subsystem that consumes it; everything else about the plugin machinery is shared.
    pub kind: String,
    /// The plugin's release version (semver, e.g. `1.5.0`).
    pub version: String,
    /// The publisher identity whose key signed this. `busbar` is reserved for first-party plugins
    /// (verified against the embedded release key); anything else resolves via
    /// `plugins.trust.publishers`.
    pub publisher: String,
    /// Which version of busbar's C plugin ABI (for this `kind`) the cdylib was built against.
    pub abi_version: u32,
    /// Lowercase hex SHA-256 of the library bytes - binds this manifest to that exact binary.
    pub sha256: String,
    /// Lowercase hex ed25519 signature over [`canonical_manifest_bytes`] (every field but this one).
    #[serde(default)]
    pub signature: String,
    /// One-line description (display only; signed).
    #[serde(default)]
    pub description: String,
    /// Homepage/website (display only; signed).
    #[serde(default)]
    pub homepage: String,
    /// SPDX license id (display only; signed).
    #[serde(default)]
    pub license: String,
    /// ADVISORY declared intent (`kind: hook` only): what caller content the plugin ASKS to receive
    /// (`needs.prompt`, `needs.user`). SIGNED (covered by the signature, so it cannot be spoofed) and
    /// surfaced to the admin at register/load so they know what a grant would expose. It is ADVISORY:
    /// the operator's config grant remains the ENFORCEMENT — the core projects `prompt`/`user` ONLY
    /// when BOTH the manifest declares the need AND the operator grants it (belt-and-suspenders). A
    /// plugin that never declares a need can never be handed content, even on a fat-fingered grant.
    /// Absent (`{}`) for non-hook kinds and for hooks that ask for nothing. Serde-default so older
    /// manifests (and every non-hook plugin) parse unchanged.
    #[serde(default)]
    pub needs: HookNeeds,
    /// The plugin's `settings` shape as a JSON Schema (2020-12) document, serialized to a string
    /// (kept as a string, not a nested `serde_json::Value`, so `canonical_manifest_bytes`'s
    /// sorted-key re-serialization can never reorder keys INSIDE the schema and silently change
    /// what was signed - the schema's own byte-for-byte text is what's covered). SIGNED, so an
    /// operator (or `GET /plugins/{name}/schema`) can trust it without ever loading the plugin -
    /// `GET /plugins` is manifest-only and never dlopens anything. Absent (`None`) for a plugin
    /// that hasn't been re-packed with a schema yet; serde-default so every existing manifest
    /// this session already produced still parses unchanged. A field marked `"x-busbar-secret":
    /// true` in the schema is validated by callers against a `oneOf` secret-reference shape
    /// (`{"env": "..."}` / `{"file": "..."}` / `{"module": "...", "key": "..."}`), never a bare
    /// string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings_schema: Option<String>,
    /// SELF-ATTESTED, not verified by `busbar-plugin-pack` (which only embeds a schema FILE it is
    /// handed — it never sees the plugin's Rust source, so it has no way to confirm derivation
    /// actually happened). Set by `--schema-derived`, an assertion the CALLER (the plugin's own
    /// `build.rs`/CI, using the `busbar-plugin-sdk` `schema_for!` macro) makes. SIGNED, so a false
    /// claim is attributable after the fact — but signing makes a lie ATTRIBUTABLE, not TRUE.
    /// Consumers (busbar-ui, `default`/`required` trust) must NOT treat this flag alone as a
    /// verified guarantee: it is load-bearing only when paired with `trust == "trusted"` AND
    /// `publisher == "busbar"` (busbar's own CI is the only pipeline where derivation is
    /// structurally enforced, a compile error rather than an assertion).
    /// `false` by default (serde-default so every existing manifest still parses).
    #[serde(default)]
    pub schema_derived: bool,
    /// Which product this manifest was packaged for: `busbar` (the OSS engine, and the IMPLICIT
    /// default when absent) or a sibling product's own identity (e.g. `busbar-ui`). SIGNED (covered
    /// by the signature, so it cannot be spoofed after packing) and checked STRUCTURALLY at load
    /// time (phase 1, [`validate_structure`]) against [`HOST_IDENTITY`] — not merely parsed and
    /// ignored. `None` means `busbar`, so every manifest packed before this field existed (none of
    /// them carry it) keeps parsing and loading exactly as before: this is additive, not a breaking
    /// change. A manifest that EXPLICITLY declares a `host` other than this binary's own is a hard
    /// structural reject, because the same `kind` string (`store`/`auth`/`secret`) can carry
    /// entirely incompatible payload contracts across host products — see [`HOST_IDENTITY`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// What the plugin DECLARES it will say to the host beyond its kind's answers (K9a, the export
    /// kind's host seams): the metric series it emits, the diagnostics it raises and the settings
    /// keys that name its destinations. SIGNED like every other field, so a grant the host makes on
    /// a declaration is made on what the publisher signed. Absent (empty) for every manifest packed
    /// before the section existed, and skipped when empty, so their canonical bytes — and therefore
    /// their signatures — are unchanged.
    #[serde(default, skip_serializing_if = "Declares::is_empty")]
    pub declares: Declares,
    /// THE STATEMENT, as its canonical rendering in lowercase hex
    /// ([`rendering`](busbar_contract::abi::mechanism::rendering)): rendered from the plugin's door
    /// by the pack tool and SIGNED with everything else, so every reader that must not open the
    /// plugin (`--validate`, `--list-plugins`) reads the plugin's facts from here, and the loader
    /// compares it with the door's own Statement byte for byte when it admits the plugin. Absent
    /// for a library with no door (a pre-1.6.0 artifact), and skipped when absent, so every
    /// manifest packed before it keeps its canonical bytes and its signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    /// The FORMER NAMES the plugin answers to beside `name` and `alias`: the manifest names its
    /// earlier releases carried (a 1.5.5 config names `busbar-webrequest`, the 1.6.0 plugin is
    /// `busbar-hook-webrequest`), so a configuration written for those releases loads unchanged.
    /// Each is a reference the registry resolves exactly as it resolves the alias, and each is held
    /// to the alias's rules (lowercase `[a-z0-9-]+`) and to phase 3's collision checks. SIGNED like
    /// every field; `busbar-plugin-pack --former-name` (repeatable) writes it from plugins.yaml's
    /// `former_names:`. Absent on every manifest packed before it existed, and skipped when empty,
    /// so their canonical bytes, and therefore their signatures, are unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub former_names: Vec<String>,
}

impl Manifest {
    /// The names config may reference this plugin by beside its canonical `name`: the alias, then
    /// each former name ([`Manifest::former_names`]).
    pub fn config_names(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.alias.as_str()).chain(self.former_names.iter().map(String::as_str))
    }

    /// Every identifier this plugin claims: its canonical `name`, then [`Manifest::config_names`].
    pub fn identities(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.name.as_str()).chain(self.config_names())
    }

    /// Whether config naming `word` names this plugin: its name, its alias or a former name.
    pub fn answers_to(&self, word: &str) -> bool {
        self.identities().any(|n| n == word)
    }

    /// The Statement rendering this manifest states ([`Manifest::statement`], hex-decoded); `None`
    /// when it states none.
    ///
    /// # Errors
    ///
    /// A `statement` that is not lowercase hex.
    pub fn stated_rendering(&self) -> Result<Option<Vec<u8>>, String> {
        self.statement
            .as_deref()
            .map(|h| {
                if h.bytes().any(|b| b.is_ascii_uppercase()) {
                    return Err("manifest statement is not lowercase hex".to_string());
                }
                hex::decode(h).map_err(|e| format!("manifest statement is not hex: {e}"))
            })
            .transpose()
    }

    /// The facts this manifest's Statement rendering carries, read back without opening the plugin
    /// ([`rendering::read`](busbar_contract::abi::mechanism::rendering::read)); `None` when it
    /// states none.
    ///
    /// # Errors
    ///
    /// A `statement` that is not lowercase hex, or not one whole Statement rendering.
    pub fn stated(
        &self,
    ) -> Result<Option<busbar_contract::abi::mechanism::rendering::Read>, String> {
        self.stated_rendering()?
            .map(|b| {
                busbar_contract::abi::mechanism::rendering::read(&b).map_err(|e| {
                    format!(
                        "manifest statement is not a Statement rendering: byte {} is not {}",
                        e.at, e.what
                    )
                })
            })
            .transpose()
    }
}

/// The declaration shapes a manifest's `declares` section carries, named here so a packer or a
/// host reaches them beside [`Manifest`].
pub use busbar_contract::abi::mechanism::observe::{DiagnosticDecl, SeriesDecl};

/// A manifest's `declares` section — the statements a plugin makes ABOUT ITSELF that the host
/// grants or refuses at open, never trusts as-is (the export ABI's minor, `EXPORT_ABI_MINOR`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Declares {
    /// The metric series the plugin emits (S1, the first-party metric namespace): granted to a
    /// first-party plugin only — see [`busbar_contract::abi::mechanism::observe::SeriesDecl`].
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub metrics: Vec<busbar_contract::abi::mechanism::observe::SeriesDecl>,
    /// The `BUSBAR-NNNN` diagnostics the plugin raises: registered into the host's catalogue
    /// for a first-party plugin — see [`busbar_contract::abi::mechanism::observe::DiagnosticDecl`].
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<busbar_contract::abi::mechanism::observe::DiagnosticDecl>,
    /// The SETTINGS KEYS that name a destination the host opens for the plugin (S4, the
    /// destination handle): the host resolves each against the operator's settings at open, and
    /// the plugin's host ops name the key, never a path.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub destinations: Vec<String>,
    /// How many archives the host's disk lane keeps when it rolls a declared destination over
    /// (THE DESIGN: `disk.append` rotation is declared per destination, `{path_key,
    /// rotate_size_key, keep}`), keyed by the destination's settings key; the host turns it into
    /// its rotation ([`busbar_contract::services::DiskRotate::declared`]). `0`: no archive — a due
    /// file is truncated in place, 1.5.5's request-log rollover. A destination not named here takes
    /// [`busbar_contract::services::DISK_ROTATE_UNDECLARED`]. Left off the wire when empty, so every
    /// manifest packed before the field existed keeps its canonical bytes.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub keep: BTreeMap<String, u32>,
    /// The EGRESS POLICY the host applies to every request the plugin asks it to admit or carry
    /// (K9e-2, export ABI minor 10) — see [`EgressPolicy`]. Granted to a first-party plugin only
    /// when it is not the default; the default is left off the wire, so every manifest packed
    /// before the field existed keeps its canonical bytes.
    #[serde(skip_serializing_if = "EgressPolicy::is_default")]
    pub egress: EgressPolicy,
    /// The plane's BREAKER FACTS (ARCHITECT Q4): how its members' breaker cells treat a transient
    /// failure that does not trip them — see [`BreakerDecl`]. Absent, the host's default posture
    /// holds; left off the wire when absent, so every manifest packed before the field existed
    /// keeps its canonical bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breaker: Option<BreakerDecl>,
    /// THE DISK NEED (THE DESIGN §11.11 R4, as the OWNER amended it 2026-10-13): the plugin's
    /// source reads the local disk. Stated by a `kind: secret` plugin ONLY (no other kind may claim
    /// the exception; [`validate_identity`] refuses it elsewhere): the host runs its `resolve` on the
    /// bounded disk lane at config time and refuses it on a request path. Left off the wire when
    /// false, so every manifest packed before the field existed keeps its canonical bytes.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub disk: bool,
    /// THE HOOK FACTS a `kind: hook` plugin states about itself (ARCHITECT ruling, status row 194,
    /// BUSBAR-1.6.0.md l.246: `declares` carries structured answers): see [`HookDecl`]. Absent, the
    /// hook is judged and served as every hook before the field existed (it may order); left off
    /// the wire when absent, so every manifest packed before the field existed keeps its canonical
    /// bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook: Option<HookDecl>,
}

/// A hook's declared FACTS (`declares.hook`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookDecl {
    /// Whether the hook's `decide` ever answers an order (PREFER). `false`: it always abstains, the
    /// conformance suite judges it on abstain-only and fails it if it orders, and the loader refuses
    /// an order it answers at run. Absent, `true`.
    #[serde(default = "HookDecl::orders_by_default")]
    pub orders: bool,
}

impl HookDecl {
    const fn orders_by_default() -> bool {
        true
    }
}

/// A plane's declared BREAKER FACTS (`declares.breaker`, ARCHITECT Q4): per-plane facts about the
/// breaker cells of its members, which the host reads and applies to that plane's cells alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreakerDecl {
    /// Whether a transient failure BELOW the trip threshold still benches the member's cell for a
    /// cooldown. `false`: a cell refuses only on a TRIP (the host's trip thresholds), an upstream
    /// `Retry-After` still honoured.
    pub bench_below_trip_threshold: bool,
}

/// The EGRESS POLICY the host applies to every request a sink asks it to admit or carry (K9e-2,
/// export ABI minor 10). A sink's manifest DECLARES one (`declares.egress`); absent, it is
/// [`EgressPolicy::OpenWeb`]. The host grants any other policy to a FIRST-PARTY sink only, and the
/// policy's rules are the host's — a sink names which, never what they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EgressPolicy {
    /// The open web (the request-log webhook's policy): `https://` only; loopback, link-local,
    /// private, CGNAT and cloud-metadata targets refused.
    #[default]
    OpenWeb,
    /// A telemetry COLLECTOR (the span exporter's policy): `https://`, or plaintext `http://` to a
    /// loopback collector only; link-local, private, CGNAT and cloud-metadata targets refused.
    Collector,
}

impl EgressPolicy {
    /// The policy's manifest spelling (`open-web` | `collector`).
    pub const fn as_token(self) -> &'static str {
        match self {
            EgressPolicy::OpenWeb => "open-web",
            EgressPolicy::Collector => "collector",
        }
    }

    /// Whether this is the default policy — what a manifest that declares none states.
    pub fn is_default(&self) -> bool {
        *self == EgressPolicy::OpenWeb
    }
}

impl Declares {
    /// THE ONE READER OF A DECLARES DOCUMENT (a plugin's `declares.json`; ARCHITECT ruling (b),
    /// 2026-10-07): pack's `--declares-file`, a linked export row's `DECLARES` and a linked plane
    /// door's `linked-declares` row all read through here, and nothing else deserializes declares
    /// bytes into [`Declares`] (`declares_reader_tests` scans the tree for one).
    ///
    /// A networked plugin's file states `needs` (the transport schemes its Statement's needs name)
    /// for the conformance suite (`the_declared_needs_are_the_statements`) and the fleet render (its
    /// conformance host). The needs belong to the Statement, so the section never carries them:
    /// `needs` is checked to be a list of scheme names and removed, and the rest is read with every
    /// other unknown key still refused. Which schemes it names is not this reader's to judge: core
    /// names no transport (Law 1), the suite holds the list to the Statement's, and boot resolves a
    /// Statement's need against the claims the linked and dropped-in transports make. A SIGNED
    /// manifest's `declares` is not a declares document: it is read with the manifest and refuses
    /// `needs`.
    ///
    /// # Errors
    /// The bytes are not JSON, `needs` is not a list of non-empty strings, or the rest is not a
    /// `declares` section (an unknown key, a malformed declaration).
    pub fn from_declares_json(bytes: &[u8]) -> Result<Declares, String> {
        let mut doc: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|e| format!("not a `declares` section: {e}"))?;
        if let Some(needs) = doc.as_object_mut().and_then(|m| m.remove("needs")) {
            let list = needs
                .as_array()
                .ok_or_else(|| format!("`needs` is not a list of transport schemes: {needs}"))?;
            for n in list {
                if !n.as_str().is_some_and(|s| !s.is_empty()) {
                    return Err(format!("`needs`: {n} is not a transport scheme"));
                }
            }
        }
        // The superseded contract-ABI range (THE DESIGN §2 l.237-240: a plugin declares its kind's
        // ABI version, never a range): a declares FILE may still state it until the fleet's
        // re-render strips it from every repo (the DECLARES gate accepts it until then), so it is
        // dropped here, never read and never carried into a manifest.
        if let Some(m) = doc.as_object_mut() {
            m.remove("contract_abi");
        }
        let read: Self =
            serde_json::from_value(doc).map_err(|e| format!("not a `declares` section: {e}"))?;
        // A retention is stated for a declared destination only.
        if let Some(key) = read.keep.keys().find(|k| !read.destinations.contains(k)) {
            return Err(format!(
                "not a `declares` section: `keep` names `{key}`, which is not a declared destination"
            ));
        }
        Ok(read)
    }

    /// Nothing declared — the section is left off the wire (and out of the signed bytes).
    pub fn is_empty(&self) -> bool {
        self.metrics.is_empty()
            && self.diagnostics.is_empty()
            && self.destinations.is_empty()
            && self.keep.is_empty()
            && self.egress.is_default()
            && self.breaker.is_none()
            && !self.disk
            && self.hook.is_none()
    }

    /// Whether the hook may answer an order: `declares.hook.orders`, `true` when not stated.
    #[must_use]
    pub fn hook_orders(&self) -> bool {
        self.hook.is_none_or(|h| h.orders)
    }
}

/// The advisory declared-intent block a `kind: hook` plugin's manifest may carry (`needs:`). Each
/// axis mirrors the operator grant ladder but is only a REQUEST — the operator grant enforces. Fields
/// serde-default to `no` so a manifest omitting `needs` (or omitting an axis) declares no need.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HookNeeds {
    /// Declared PROMPT need: `no` (default) | `ro` (asks to read prompt content) | `rw` (asks to
    /// read + rewrite). The core sends prompt content only when this is at/above the operator's
    /// grant intent AND the operator grants it.
    pub prompt: NeedLevel,
    /// Declared caller-IDENTITY need: `no` (default) | `ro` (asks for the key id/name + end-user).
    pub user: NeedLevel,
}

impl HookNeeds {
    /// Does the plugin declare ANY content need? Used to surface intent at register/load.
    pub fn declares_any(&self) -> bool {
        self.prompt != NeedLevel::No || self.user != NeedLevel::No
    }
}

/// One axis of a hook manifest's declared intent: the contract's (`busbar_contract::plugin_rows`),
/// the shape the kernel reads a row's needs in.
pub use busbar_contract::plugin_rows::NeedLevel;

/// How a plugin was permitted to load when it is NOT signed by a trusted key - the operator's
/// EXPLICIT opt-in (never a silent default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowReason {
    /// The artifact carries no valid signature (unsigned / tampered) and `allow_unsigned` is set.
    Unsigned,
    /// The artifact is VALIDLY signed but by a publisher NOT in the allowlist, and
    /// `allow_third_party` is set.
    ThirdParty,
}

/// The resolved trust policy: the embedded first-party key, the allowlisted third-party publisher
/// keys, the EXPLICIT opt-in flags, and the anti-downgrade floors. Built from `plugins.trust` +
/// `plugins.min_versions` config (plus the embedded release key and the binary's own version).
///
/// DEFAULT posture (both flags `false`): an untrusted plugin (unsigned OR signed by a
/// non-allowlisted publisher) is REJECTED - logged and skipped, never `dlopen`ed.
#[derive(Clone, Default)]
pub struct TrustPolicy {
    /// The embedded busbar release public keys ([`embedded_release_keys`]). Empty in a build with
    /// no embedded key: first-party plugins then cannot verify (they are treated as unsigned).
    pub first_party_keys: Vec<FirstPartyKey>,
    /// REVOKED library digests (`sha256` -> why; [`REVOKED_DIGESTS`]): refused whoever signed them,
    /// before any opt-in is consulted.
    pub revoked: BTreeMap<String, String>,
    /// The highest keys-document version this deployment has accepted
    /// ([`crate::release_trust`]): a sealed plugin carrying an older one is a rollback, refused
    /// whatever the opt-ins. `0`: none accepted yet. Armed by the registry build from the persisted
    /// marks ([`crate::HighWaterMarks::release_keys_floor`]).
    pub release_keys_floor: u64,
    /// The time (Unix seconds) keys-document and release-manifest expiry is judged at. `None`, the
    /// system clock; a test sets it.
    pub release_clock: Option<u64>,
    /// Whether keys-document and release-manifest EXPIRY is judged (TUF's semantics,
    /// `docs/design/release-trust.md`): `true` at install, fetch and update (an upload, its
    /// preview); `false`, the default, at boot for a plugin already installed, which never stops
    /// loading because time passed. Signatures, revocations and rollback are judged either way.
    pub release_enforce_expiry: bool,
    /// The running binary's version (`CARGO_PKG_VERSION`). Informational (error text/telemetry)
    /// only: it is NOT a floor. First-party plugins version on their own independent lines
    /// (1.0.x stores/auth/hooks under a 1.5.0 engine), so the pre-release
    /// automatic "plugin >= binary version" floor would have rejected every correctly-signed
    /// current first-party release and was removed before 1.5.0 shipped.
    pub binary_version: String,
    /// PER-PLUGIN first-party anti-downgrade OVERRIDES: the explicit, audited rollback pins (1.5.0).
    /// `name` -> the pinned minimum version. A pin REPLACES that name's automatic high-water floor
    /// ([`first_party_high_water`](Self::first_party_high_water)) — it is how an operator rolls a
    /// first-party plugin back on purpose. Scoping per name keeps a rollback of plugin A from ever
    /// changing what plugin B is allowed to be.
    pub first_party_floors: BTreeMap<String, String>,
    /// The FIRST-PARTY ANTI-DOWNGRADE FLOOR: per-plugin-name HIGH-WATER MARKS — `name` -> the
    /// highest `version` of that name this deployment has actually SEEN AND LOADED.
    ///
    /// This is the control `docs/plugins.md` security-model item 3 promises. A validly-signed but OLD
    /// release is still a signed artifact an attacker with write access to `plugins.dir` can replay:
    /// it verifies against the embedded release key and, with nothing to compare it against, loads as
    /// `first-party` with no warning. The mark is what it is compared against. A name absent here
    /// carries NO floor — a FIRST install is not a downgrade, and the mark is only ever raised by a
    /// load this deployment itself performed.
    ///
    /// It is deliberately NOT the binary's version ([`binary_version`](Self::binary_version)): first-
    /// party plugins version on their own independent lines, so a binary floor rejected every
    /// correctly-signed current release. The high-water mark couples to the PLUGIN's own line.
    ///
    /// [`first_party_floors`](Self::first_party_floors) — the explicit, audited rollback pin —
    /// REPLACES this floor for the pinned name, and for that name only. That is the documented way
    /// past it, and it is why an operator can still roll a first-party plugin back on purpose.
    ///
    /// Maintained by `busbar_plugin_loader::HighWaterMarks`: persisted under the fleet data dir when
    /// one is configured, memory-only otherwise (PB-13/15 — no data dir, no files).
    pub first_party_high_water: BTreeMap<String, String>,
    /// THIRD-PARTY allowlist: publisher name -> ed25519 public key. The first-party publisher
    /// (`busbar`) never resolves here.
    pub publishers: BTreeMap<String, VerifyingKey>,
    /// Opt-in: load plugins that carry NO valid signature (unsigned / tampered). Default `false`.
    pub allow_unsigned: bool,
    /// Opt-in: load plugins validly signed by a publisher NOT in `publishers`. Default `false`.
    pub allow_third_party: bool,
    /// ANTI-DOWNGRADE floors: plugin `name` -> minimum acceptable `version`. A floored name must
    /// PROVE (via a trusted signature over a manifest at/above the floor) that it meets the floor;
    /// anything else is a hard reject no opt-in flag can relax. Applies to first- and third-party
    /// alike (first-party has no automatic floor).
    pub min_versions: BTreeMap<String, String>,
}

/// A `plugins:` block's trust facts, as plain data: what [`TrustPolicy::from_config`] resolves.
#[derive(Debug, Clone, Copy)]
pub struct TrustInput<'a> {
    /// The configured third-party publishers, `(name, hex ed25519 public key)`.
    pub publishers: &'a [(&'a str, &'a str)],
    /// `plugins.trust.allow_unsigned`.
    pub allow_unsigned: bool,
    /// `plugins.trust.allow_third_party`.
    pub allow_third_party: bool,
    /// `plugins.min_versions`: per-name anti-downgrade floors, first- and third-party alike.
    pub min_versions: &'a BTreeMap<String, String>,
    /// The runtime per-name first-party floor overrides (explicit rollback pins).
    pub first_party_floors: &'a BTreeMap<String, String>,
    /// Carried for diagnostics only; NOT a floor.
    pub binary_version: &'a str,
}

impl TrustPolicy {
    /// Resolve a `plugins:` block's trust facts: the EMBEDDED first-party release key, the binary's
    /// version (diagnostics only), the configured third-party publishers, opt-ins and per-name
    /// floors. The AUTOMATIC first-party floor (the per-name high-water marks) is NOT resolved
    /// here: it is an observed fact the registry build arms ([`crate::boot::registry`]).
    ///
    /// # Errors
    ///
    /// A publisher named for busbar's embedded key, or a malformed publisher key (a skipped trust
    /// anchor could wrongly reject a good plugin).
    pub fn from_config(i: TrustInput<'_>) -> Result<Self, String> {
        let mut publishers = BTreeMap::new();
        for &(name, public_key) in i.publishers {
            if name == FIRST_PARTY_PUBLISHER {
                return Err(format!(
                    "plugins.trust.publishers['{name}']: the publisher name '{FIRST_PARTY_PUBLISHER}' \
                     is reserved for busbar's embedded release key and cannot be configured"
                ));
            }
            let key = public_key_from_hex(public_key)
                .map_err(|e| format!("plugins.trust.publishers['{name}']: {e}"))?;
            publishers.insert(name.to_string(), key);
        }
        Ok(TrustPolicy {
            first_party_keys: embedded_release_keys(),
            revoked: revoked_digests(),
            release_keys_floor: 0,
            release_clock: None,
            release_enforce_expiry: false,
            binary_version: i.binary_version.to_string(),
            first_party_floors: i.first_party_floors.clone(),
            first_party_high_water: BTreeMap::new(),
            publishers,
            allow_unsigned: i.allow_unsigned,
            allow_third_party: i.allow_third_party,
            min_versions: i.min_versions.clone(),
        })
    }
}

/// The verdict for one plugin artifact that MAY proceed to load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A valid signature from a trusted key. `first_party` distinguishes the embedded busbar key
    /// from an allowlisted third-party publisher (display + logging).
    Trusted {
        publisher: String,
        first_party: bool,
    },
    /// Not trusted, but an EXPLICIT opt-in flag permits proceeding - the caller should log a
    /// warning naming `reason`.
    Allowed { reason: String, allow: AllowReason },
}

/// The engine's BINDING LIFECYCLE default for whether a settings change needs a process restart,
/// derived from plugin `kind` — never plugin-declared. `store`/`secret` plugins bind once at
/// process start (every field is restart-scoped by
/// construction, regardless of what a plugin author writes); `hook`/`auth` plugin registries
/// rebuild hot. An unrecognized kind defaults to the SAFE direction (restart-required) — the same
/// fail-safe posture [`effective_restart_required`]'s override gate takes.
pub fn kind_restart_default(kind: &str) -> bool {
    match kind {
        "hook" | "auth" => false,
        // "store" | "secret" | anything else: restart-required is the safe default. An unknown
        // kind should never have reached here (KNOWN_KINDS gates it earlier in the pipeline), but
        // this function must still answer something rather than panic, and restart-required is
        // the fail-safe direction to guess wrong in.
        _ => true,
    }
}

/// The EFFECTIVE restart-required verdict for one settings field: the kind-derived default
/// ([`kind_restart_default`]), with a per-field `x-busbar-restart-required` override honored
/// ASYMMETRICALLY:
///   * an override to `true` against a kind default of `false` is ALWAYS honored — claiming a field
///     needs a restart when the kind default says it doesn't is the safe direction to be wrong in
///     (worst case: one unnecessary restart);
///   * an override to `false` against a kind default of `true` is honored ONLY when the manifest
///     verifiably came from a TRUSTED, first-party (`publisher == "busbar"`) artifact — the same
///     trust+publisher gate `schema_derived`'s load-bearing rule uses, for the identical reason:
///     a third-party claim in the direction that could
///     cause a setting to silently fail to apply is not trusted; a claim in the fail-safe direction
///     is. `publisher` ALONE is never sufficient proof — `Verdict::Trusted { first_party: true, .. }`
///     is what `evaluate()` only ever returns for a manifest that verified against the EMBEDDED
///     release key, never a self-declared string (see `crates/plugin-loader/src/registry.rs`'s
///     existing refusal to trust `manifest.publisher` alone for the identical reason).
pub fn effective_restart_required(
    kind: &str,
    field_override: Option<bool>,
    verdict: &Verdict,
) -> bool {
    let default = kind_restart_default(kind);
    match field_override {
        None => default,
        Some(true) => true,
        Some(false) => {
            if !default {
                // The kind default is already hot-appliable; a `false` override changes nothing
                // observable, so there is nothing to gate — this is not the silent-data-loss
                // direction the asymmetry exists to guard against.
                false
            } else if matches!(
                verdict,
                Verdict::Trusted {
                    first_party: true,
                    ..
                }
            ) {
                // Trusted first-party: the override is HONORED — the field is hot-appliable.
                false
            } else {
                // Not trusted-first-party: the override is IGNORED — the kind default (true,
                // restart-required) is enforced regardless of what the manifest claims.
                true
            }
        }
    }
}

/// WHY a plugin was rejected — a STRUCTURED discriminant, so consumers (e.g. the `--list-plugins`
/// signature column) can label the outcome WITHOUT substring-matching the human-readable `reason`.
/// The former text match was itself a defect: the reason string embeds plugin-author-controlled bytes
/// (`manifest.publisher`), so a crafted publisher like `"anti-downgrade-bypass"` could make the reason
/// contain `"anti-downgrade"` and mislabel an unknown-publisher reject as "trusted (below floor)".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectKind {
    /// A pinned anti-downgrade floor (first-party automatic OR configured `min_versions`) was not met
    /// by an artifact that DID prove trust (labeled "trusted (below floor)"). Reserved for trusted
    /// artifacts: an UNTRUSTED artifact carrying a floored name is [`RejectKind::UntrustedFloored`], so
    /// this never mislabels an unsigned/unknown-publisher artifact as trusted.
    AntiDowngrade,
    /// A floored (`min_versions`) name whose artifact could NOT prove trust (unsigned/tampered/unknown
    /// publisher). Still a HARD reject the floor forbids relaxing — the floor requires trusted proof, so
    /// a stripped-signature copy cannot launder a downgrade past it even with `allow_unsigned`/
    /// `allow_third_party` set. Distinct from [`RejectKind::AntiDowngrade`] SOLELY so the display label
    /// reflects the real (untrusted) trust state instead of "trusted (below floor)".
    UntrustedFloored,
    /// No signature at all (or a first-party manifest in a build with no embedded key) and
    /// `allow_unsigned` is off.
    Unsigned,
    /// A signature was PRESENT but failed verification against a held key, and `allow_unsigned` is
    /// off — distinct from [`RejectKind::Unsigned`] for display purposes only.
    Tampered,
    /// Validly signed but by a publisher NOT in the allowlist, and `allow_third_party` is off.
    UnknownPublisher,
    /// Admitted on trust, but NOT first-party, and its Statement declares a connection need in an
    /// egress class the host grants to a first-party plugin only ([`egress_grant`]).
    EgressGrant,
    /// The library's digest is on this build's revocation list ([`REVOKED_DIGESTS`]): refused
    /// whoever signed it, before any opt-in.
    Revoked,
}

/// The egress classes (`BUSBAR-1.6.0.md` §5) the host grants to a FIRST-PARTY plugin only: a
/// provider's allow-list and metadata hosts (a plane's upstreams). The connector's default class
/// and the open web are any trusted plugin's (ARCHITECT ruling EGRESS-GRANT 2026-10-03; the cold
/// lane's `declares.egress` grant, on the door's needs).
///
/// `loopback-allowed` is NOT here (OWNER 2026-10-24, oracle BOOT-W23): a collector or hook on
/// loopback the operator admitted with `plugins.trust` loaded in 1.5.5, UNVERIFIED; the opt-in is
/// the operator's grant. `operator-infrastructure` is NOT here either. §5's egress-class table gives it to "databases, vault,
/// ldap; auth mint endpoints" with no first-party condition (`BUSBAR-1.6.0.md` l.604-611): its
/// targets come from operator settings, and the plugins that dial them (a store, a secret service, a
/// directory, an IdP's token exchange) were dropped-in plugins in 1.5.5 that an operator's
/// `plugins.trust` opt-in loaded. Refusing that class to a plugin the operator admitted changes what
/// 1.5.5 served, which only an owner signature may do ("Law beats table", l.613; "the default is
/// 1.5.5's behaviour", l.364-365); the opt-in is the operator's grant (l.829, Part 2 #75 l.2276).
pub const FIRST_PARTY_EGRESS: [(u32, &str); 1] = [(
    busbar_contract::abi::host::conn::connector::EGRESS_PROVIDER,
    "provider",
)];

/// THE EGRESS-CLASS GRANT on a door plugin's needs: `Err` naming the first need of `manifest`'s
/// stated Statement whose egress class is a first-party grant ([`FIRST_PARTY_EGRESS`]). Asked of a
/// plugin that is not first-party; a manifest that states no Statement (a cold plugin) declares no
/// need here.
///
/// # Errors
///
/// The refusal, naming the plugin and the class.
pub fn egress_grant(manifest: &Manifest) -> Result<(), String> {
    let Some(stated) = manifest.stated()? else {
        return Ok(());
    };
    for need in &stated.needs {
        if let Some((_, class)) = FIRST_PARTY_EGRESS
            .iter()
            .find(|(c, _)| *c == need.egress_class)
        {
            return Err(format!(
                "plugin '{}' declares a `{}` need in the `{class}` egress class, which the host \
                 grants to a first-party plugin only",
                manifest.name, need.transport
            ));
        }
    }
    Ok(())
}

/// Trust failure. The posture forbids loading this plugin; the message is safe to surface. `kind` is
/// the structured category (the authority for any label/column); `reason` is the human message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    pub reason: String,
    pub kind: RejectKind,
    /// The ids of every first-party key this build trusts, set when a `publisher: busbar` manifest
    /// carries a well-formed signature that verifies against NONE of them (a plugin signed by a
    /// retired or unknown key); empty otherwise. STRUCTURED, beside `reason` rather than inside it:
    /// `reason` keeps 1.5.5's bytes (`first-party signature failed: signature does not verify`),
    /// which the boot WARN line prints.
    pub trusted_keys: Vec<String>,
}

impl Rejected {
    /// Construct a rejection from a structured `kind` and a human `reason`.
    fn new(kind: RejectKind, reason: String) -> Self {
        Rejected {
            reason,
            kind,
            trusted_keys: Vec::new(),
        }
    }
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "plugin rejected: {}", self.reason)
    }
}
impl std::error::Error for Rejected {}

/// Lowercase-hex SHA-256 of `bytes` - the library digest stored in the manifest.
pub fn sha256_hex(bytes: &[u8]) -> String {
    busbar_contract::redacted::sha256_hex(bytes)
}

/// The canonical byte string that is signed/verified: the whole manifest MINUS its `signature`, as
/// deterministic sorted-key JSON. Using a `BTreeMap` makes the key order deterministic INDEPENDENT
/// of serde_json's `preserve_order` feature, so the signer and verifier always agree in any build.
/// Any field added to the manifest is automatically covered.
pub fn canonical_manifest_bytes(m: &Manifest) -> Vec<u8> {
    let value = serde_json::to_value(m).expect("manifest is serializable");
    let obj = value
        .as_object()
        .expect("manifest serializes to a JSON object");
    let sorted: BTreeMap<&str, &serde_json::Value> = obj
        .iter()
        .filter(|(k, _)| k.as_str() != "signature")
        .map(|(k, v)| (k.as_str(), v))
        .collect();
    serde_json::to_vec(&sorted).expect("canonical manifest serializes")
}

/// Sign a manifest with a publisher's key: set `sha256` from the artifact, clear any existing
/// `signature`, sign the canonical bytes, and return the completed [`Manifest`]. For the release
/// pipeline / packaging tooling - never runs in the engine (which only verifies).
pub fn sign(key: &SigningKey, mut manifest: Manifest, artifact: &[u8]) -> Manifest {
    manifest.sha256 = sha256_hex(artifact);
    manifest.signature = String::new();
    let sig = key.sign(&canonical_manifest_bytes(&manifest));
    manifest.signature = hex::encode(sig.to_bytes());
    manifest
}

/// Parse a hex-encoded 32-byte ed25519 public key (as configured in `plugins.trust.publishers`).
///
/// A WEAK (small-order / identity) key is REFUSED here rather than admitted to the allowlist.
/// `VerifyingKey::from_bytes` only checks that the point decompresses, and the identity point
/// decompresses fine — but a signature made against it satisfies the permissive cofactored
/// verification equation for EVERY message. An allowlist entry naming such a key (a placeholder, a
/// truncated or zero-filled paste, a key an attacker supplied in a vendor document) would therefore
/// mark ANY artifact as `Trusted`. The refusal is at parse time so the bad entry never becomes a
/// trust anchor; the strict verification below is the second half of the same guard.
pub fn public_key_from_hex(s: &str) -> Result<VerifyingKey, String> {
    let bytes = hex::decode(s.trim()).map_err(|e| format!("public key not valid hex: {e}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("public key must be 32 bytes, got {}", bytes.len()))?;
    let key =
        VerifyingKey::from_bytes(&arr).map_err(|e| format!("invalid ed25519 public key: {e}"))?;
    if key.is_weak() {
        return Err(
            "weak ed25519 public key (small-order point): it would verify any signature"
                .to_string(),
        );
    }
    Ok(key)
}

/// Whether a manifest's signature verifies against `bytes` using `key`: the library hash must match
/// the manifest's `sha256` (binding), and the signature must verify over the canonical manifest
/// (authenticity + integrity).
fn signature_ok(manifest: &Manifest, bytes: &[u8], key: &VerifyingKey) -> Result<(), String> {
    let sig = bound_signature(manifest, bytes)?;
    // STRICT verification, not the permissive cofactored `verify`. `verify_strict` refuses a weak
    // (small-order) public key and a non-canonically-encoded `R`, both of which the permissive
    // check accepts — and a weak key accepts a forged signature over ANY message, which is a
    // universal forgery against a trust anchor. Every honestly-generated key and every signature
    // this crate's `sign` produces verify identically under both, so no published artifact changes
    // verdict: the strictness only closes the forgery shapes.
    key.verify_strict(&canonical_manifest_bytes(manifest), &sig)
        .map_err(|_| "signature does not verify".to_string())
}

/// Why [`first_party_signer`] named no key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirstPartyUnverified {
    /// The library does not match the manifest, or the signature is malformed: the message.
    Malformed(String),
    /// A well-formed signature that verifies against none of the keys: the id of every key tried.
    NoKey { trusted_keys: Vec<String> },
    /// The manifest carries a RELEASE SEAL ([`crate::release_trust`]) whose chain does not hold:
    /// the refusal, and the id of every root key this build trusts.
    Release {
        refusal: Box<crate::release_trust::SealRefusal>,
        trusted_keys: Vec<String>,
    },
}

impl FirstPartyUnverified {
    /// The ids of every key the signature was tried against: empty for [`Self::Malformed`].
    #[must_use]
    pub fn trusted_keys(&self) -> &[String] {
        match self {
            FirstPartyUnverified::Malformed(_) => &[],
            FirstPartyUnverified::NoKey { trusted_keys }
            | FirstPartyUnverified::Release { trusted_keys, .. } => trusted_keys,
        }
    }

    /// The refusal naming every trusted key id, for an operator tool (`busbar-plugin-pack
    /// verify`): an operator holding a plugin signed by a retired or unknown key reads which keys
    /// this binary trusts. The loader's own reason is [`Display`](std::fmt::Display), 1.5.5's bytes.
    #[must_use]
    pub fn naming_trusted_keys(&self) -> String {
        match self {
            FirstPartyUnverified::Malformed(reason) => reason.clone(),
            FirstPartyUnverified::NoKey { trusted_keys } => format!(
                "signature verifies against none of this build's first-party keys [{}]",
                trusted_keys.join(", ")
            ),
            FirstPartyUnverified::Release { .. } => self.to_string(),
        }
    }
}

/// The loader's reason, byte-for-byte 1.5.5's: the boot WARN line and `Rejected.reason` carry it.
/// The key ids travel structured, in [`FirstPartyUnverified::trusted_keys`].
impl std::fmt::Display for FirstPartyUnverified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirstPartyUnverified::Malformed(reason) => f.write_str(reason),
            FirstPartyUnverified::NoKey { .. } => f.write_str("signature does not verify"),
            FirstPartyUnverified::Release { refusal, .. } => {
                write!(f, "release seal refused ({}): {refusal}", refusal.code())
            }
        }
    }
}

/// WHICH first-party key vouches for `manifest` over `bytes`.
///
/// * A manifest carrying a RELEASE SEAL ([`crate::release_trust::wire::read_seal`]): the root of
///   `keys` that signed the seal's keys document, once the whole chain holds
///   ([`crate::release_trust::verify_release`], judged at `checks`) for this binary's target.
/// * A per-plugin ed25519 `signature` (the pre-1.6.0 shape, a run key's): the first ed25519 key of
///   `keys` it verifies against (the same binding and strict check as every signature,
///   [`signature_ok`]).
///
/// # Errors
///
/// The library does not match the manifest or the signature is malformed
/// ([`FirstPartyUnverified::Malformed`]), a per-plugin signature verifies against none of `keys`
/// ([`FirstPartyUnverified::NoKey`]), or a seal's chain does not hold
/// ([`FirstPartyUnverified::Release`]); the last two carry every key id this build trusts.
pub fn first_party_signer<'k>(
    manifest: &Manifest,
    bytes: &[u8],
    keys: &'k [FirstPartyKey],
    checks: crate::release_trust::Checks,
) -> Result<&'k FirstPartyKey, FirstPartyUnverified> {
    first_party_signer_for(
        manifest,
        bytes,
        keys,
        checks,
        crate::release_trust::PLUGIN_TARGET,
    )
}

/// [`first_party_signer`] for a plugin built for `target` rather than this binary's own: the
/// release tooling verifies every target's tarball on one machine.
///
/// # Errors
///
/// As [`first_party_signer`].
pub fn first_party_signer_for<'k>(
    manifest: &Manifest,
    bytes: &[u8],
    keys: &'k [FirstPartyKey],
    checks: crate::release_trust::Checks,
    target: &str,
) -> Result<&'k FirstPartyKey, FirstPartyUnverified> {
    if let Some(seal) = crate::release_trust::wire::read_seal(&manifest.signature) {
        return first_party_sealed(manifest, bytes, keys, checks, seal, target);
    }
    let sig = bound_signature(manifest, bytes).map_err(FirstPartyUnverified::Malformed)?;
    let canonical = canonical_manifest_bytes(manifest);
    keys.iter()
        .find(|k| matches!(&k.key, ReleaseKey::Ed25519(key) if key.verify_strict(&canonical, &sig).is_ok()))
        .ok_or_else(|| FirstPartyUnverified::NoKey {
            trusted_keys: keys.iter().map(|k| k.id.clone()).collect(),
        })
}

/// [`first_party_signer`] for a sealed manifest.
fn first_party_sealed<'k>(
    manifest: &Manifest,
    bytes: &[u8],
    keys: &'k [FirstPartyKey],
    checks: crate::release_trust::Checks,
    seal: Result<crate::release_trust::wire::SealBytes, String>,
    target: &str,
) -> Result<&'k FirstPartyKey, FirstPartyUnverified> {
    use crate::release_trust::{verify_release, Seal, SealRefusal, Subject};
    let trusted_keys = || keys.iter().map(|k| k.id.clone()).collect::<Vec<_>>();
    let lib_sha256 = sha256_hex(bytes);
    if lib_sha256 != manifest.sha256.to_ascii_lowercase() {
        return Err(FirstPartyUnverified::Malformed(
            "library hash does not match the manifest".to_string(),
        ));
    }
    let (keys_doc, targets_doc) = seal.map_err(|why| FirstPartyUnverified::Release {
        refusal: Box::new(SealRefusal::Malformed {
            doc: "release seal",
            why,
        }),
        trusted_keys: trusted_keys(),
    })?;
    let canonical = sha256_hex(&canonical_manifest_bytes(manifest));
    let verified = verify_release(
        keys,
        Seal {
            keys: &keys_doc,
            targets: &targets_doc,
        },
        Subject {
            name: &manifest.name,
            version: &manifest.version,
            target,
            sha256: &canonical,
            lib_sha256: &lib_sha256,
        },
        checks,
    )
    .map_err(|refusal| FirstPartyUnverified::Release {
        refusal: Box::new(refusal),
        trusted_keys: trusted_keys(),
    })?;
    Ok(keys
        .iter()
        .find(|k| k.id == verified.root)
        .expect("the vouching root is one of `keys`"))
}

/// The signature `manifest` carries, once its `sha256` is proven to bind `bytes`.
fn bound_signature(manifest: &Manifest, bytes: &[u8]) -> Result<Signature, String> {
    // Normalize the manifest digest to lowercase before comparing, consistently with
    // `validate_structure` (which compares against `m.sha256.to_ascii_lowercase()`). `sha256_hex`
    // always emits lowercase hex; without this an uppercase-hex manifest digest would pass the
    // structural integrity check yet fail here, an inconsistency between the two verifiers.
    if sha256_hex(bytes) != manifest.sha256.to_ascii_lowercase() {
        return Err("library hash does not match the manifest".to_string());
    }
    let sig_bytes =
        hex::decode(&manifest.signature).map_err(|e| format!("signature not hex: {e}"))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;
    Ok(Signature::from_bytes(&sig_arr))
}

/// Parse a dotted version into its leading numeric components (`major.minor.patch`), ignoring any
/// pre-release/build suffix (`-rc1`, `+meta`) for the floor comparison. Dependency-free on purpose;
/// sufficient for an anti-downgrade floor, which only needs a monotonic numeric ordering. A
/// component that isn't a number stops the parse, so a garbage version compares as `0.0.0` and can
/// never slip past a non-zero floor.
fn version_components(v: &str) -> [u64; 3] {
    let mut out = [0u64; 3];
    let core = v.trim().split(['-', '+']).next().unwrap_or("");
    for (i, part) in core.split('.').take(3).enumerate() {
        match part.parse::<u64>() {
            Ok(n) => out[i] = n,
            Err(_) => break,
        }
    }
    out
}

/// True when `have` is greater-than-or-equal-to `floor` under [`version_components`] ordering.
///
/// A NON-EMPTY `floor` that is not [`valid_semver`] is UNSATISFIABLE — this returns `false` for every
/// `have`. `version_components` truncates at the first non-numeric component, so an unparsable floor
/// like `"v1.6.0"` would otherwise read as `0.0.0`, which every version satisfies: the anti-downgrade
/// control would silently invert into a no-op exactly when the operator believed it was armed. An
/// EMPTY floor is the documented "no floor" spelling and still admits everything.
pub fn version_at_least(have: &str, floor: &str) -> bool {
    if !floor.is_empty() && !valid_semver(floor) {
        return false;
    }
    version_components(have) >= version_components(floor)
}

/// Explanatory suffix for a floor rejection: empty for a well-formed floor, and for a malformed one a
/// clause that names the real cause. Without it an operator with `min_versions: v1.6.0` reads
/// "version 1.6.0 is below the pinned minimum v1.6.0" and concludes busbar is broken.
fn floor_note(floor: &str) -> &'static str {
    if floor.is_empty() || valid_semver(floor) {
        ""
    } else {
        " — NOTE: this floor is not a valid MAJOR.MINOR.PATCH version (no leading 'v', e.g. \
         '1.6.0'), so nothing can satisfy it. An unparsable floor used to read as 0.0.0, which \
         every version satisfies, silently disarming this control; it now refuses instead. Fix or \
         remove the entry."
    }
}

/// Is `s` a well-formed plugin name/alias: non-empty lowercase `[a-z0-9-]+`, no leading/trailing
/// dash. The tight charset keeps names filesystem-, config-, and log-safe.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Is `v` a well-formed semver core? The contract's one judge
/// ([`busbar_contract::plugin::valid_semver`]).
pub fn valid_semver(v: &str) -> bool {
    busbar_contract::plugin::valid_semver(v)
}

/// PHASE 1 - STRUCTURAL validation of a manifest + its library bytes, INDEPENDENT of trust: a
/// signed-but-malformed manifest still fails here. Checks every required field is present and
/// well-formed, the `sha256` integrity binding holds against `lib_bytes`, and the declared
/// `abi_version` is one this binary supports for the declared `kind` (`supported_abi`). Returns the
/// FIRST failure as a specific, named reason. Parse errors are the caller's (the manifest must
/// already have deserialized to call this).
pub fn validate_structure(
    m: &Manifest,
    lib_bytes: &[u8],
    supported_abi: &dyn Fn(&str) -> &'static [u32],
    host_identity: &str,
) -> Result<(), String> {
    validate_identity(m, host_identity)?;
    if m.sha256.len() != 64 || !m.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "manifest sha256 '{}' is not a 64-char hex digest",
            m.sha256
        ));
    }
    if sha256_hex(lib_bytes) != m.sha256.to_ascii_lowercase() {
        return Err(
            "library bytes do not match the manifest sha256 (integrity failure)".to_string(),
        );
    }
    validate_abi(m, supported_abi)
}

/// The STATEMENT half of [`validate_structure`] — everything a manifest says about the plugin rather
/// than about the artifact file (`sha256` is the file's): name, alias, former names, kind, version,
/// publisher, host. A plugin linked into the build has no artifact, and states exactly this; the registry's
/// linked door runs it, then [`validate_abi`], so a linked row passes the same structural gate a
/// dropped-in one does.
pub fn validate_identity(m: &Manifest, host_identity: &str) -> Result<(), String> {
    if !valid_name(&m.name) {
        return Err(format!(
            "manifest name '{}' is not a valid plugin name (lowercase [a-z0-9-]+)",
            m.name
        ));
    }
    if !valid_name(&m.alias) {
        return Err(format!(
            "manifest alias '{}' is not a valid plugin alias (lowercase [a-z0-9-]+)",
            m.alias
        ));
    }
    for (i, former) in m.former_names.iter().enumerate() {
        if !valid_name(former) {
            return Err(format!(
                "manifest former name '{former}' is not a valid plugin name (lowercase [a-z0-9-]+)"
            ));
        }
        if *former == m.name || *former == m.alias || m.former_names[..i].contains(former) {
            return Err(format!(
                "manifest former name '{former}' repeats another name of the plugin"
            ));
        }
    }
    if !KNOWN_KINDS.contains(&m.kind.as_str()) {
        return Err(format!(
            "manifest kind '{}' is not one of {KNOWN_KINDS:?}",
            m.kind
        ));
    }
    if m.declares.disk && m.kind != "secret" {
        return Err(format!(
            "manifest kind '{}' declares a disk need; only a `kind: secret` source may (THE DESIGN \
             §11.11 R4: the store and the export sink reach the disk lane through their host \
             services, and no other kind claims the exception)",
            m.kind
        ));
    }
    if !valid_semver(&m.version) {
        return Err(format!(
            "manifest version '{}' is not a semver version (MAJOR.MINOR.PATCH)",
            m.version
        ));
    }
    if m.publisher.trim().is_empty() {
        return Err("manifest publisher is empty".to_string());
    }
    // A stated Statement must be one whole rendering: every no-dlopen reader relies on it.
    m.stated()?;
    // HOST identity gate: an ABSENT `host` means `busbar` (backward compatible with every manifest
    // packed before this field existed). An EXPLICIT `host` that is not the caller's own identity
    // is a hard structural reject — not a silent ignore — because a sibling product (busbar-ui)
    // reuses the identical memory ABI and signed-manifest shape, so a foreign-host manifest
    // would otherwise pass the ABI handshake and go on to answer `kind`-matched calls (e.g.
    // `store`) with an incompatible payload contract. This check runs in phase 1 (structural),
    // independent of trust/signature, so even a validly-signed foreign-host manifest is refused.
    //
    // `host_identity` is a PARAMETER, not a hardcoded const: this verifier is shared verbatim by
    // sibling products with different host identities (busbar's own callers pass `HOST_IDENTITY` = `"busbar"`; busbar-ui passes its
    // own), so it cannot close over a single fixed value the way `supported_abi` never did either.
    if let Some(host) = m.host.as_deref() {
        if host != host_identity {
            return Err(format!(
                "manifest host '{host}' does not match this binary's host '{host_identity}' - \
                 refusing to load a plugin packaged for a different product (same plugin kind \
                 strings can carry incompatible payload contracts across hosts)"
            ));
        }
    }
    Ok(())
}

/// The payload-schema negotiation of [`validate_structure`]: the manifest's `abi_version` against the
/// binary's supported range for its kind.
pub fn validate_abi(
    m: &Manifest,
    supported_abi: &dyn Fn(&str) -> &'static [u32],
) -> Result<(), String> {
    // `supported_abi` returns a CONTIGUOUS `[floor, max]` inclusive range (its endpoints) of the
    // ABI versions the binary speaks for this kind (the kind's ONE version, THE DESIGN §11.2; a
    // manifest states no contract-ABI range). Negotiate the manifest's declared
    // `abi_version` against it: in range → ok; below floor / above max → refuse LOUD naming both.
    // An empty slice means the kind is unsupported (already caught by KNOWN_KINDS, but fail-closed).
    let supported = supported_abi(&m.kind);
    match (supported.first(), supported.last()) {
        (Some(&floor), Some(&max)) if m.abi_version >= floor && m.abi_version <= max => {}
        (Some(&floor), Some(&max)) => {
            // This arm is reached only for a version OFF the supported window — older OR newer.
            // C21/ABI-o1: each kind admits exactly its current version, so any mismatch is fixed the
            // same way — rebuild the plugin against THIS host's (1.6.0) SDK. Both ends name it.
            let rebuild = format!(" — {}", crate::dispatch::load::REBUILD);
            return Err(format!(
                "manifest abi_version {} is not supported for kind '{}' by this binary (supported \
                 range v{floor}..=v{max}){rebuild}",
                m.abi_version, m.kind
            ));
        }
        _ => {
            return Err(format!(
                "kind '{}' has no supported abi_version range in this binary",
                m.kind
            ));
        }
    }
    Ok(())
}

/// The reject kind of a seal refusal that no opt-in may relax: a revocation, or a keys-document
/// rollback (anti-downgrade). `None` for every other refusal, which is a failed first-party
/// signature like any other.
fn hard_seal_refusal(r: &crate::release_trust::SealRefusal) -> Option<RejectKind> {
    use crate::release_trust::SealRefusal as S;
    match r {
        S::DigestRevoked { .. } | S::SignerRevoked { .. } => Some(RejectKind::Revoked),
        S::KeysRollback { .. } => Some(RejectKind::AntiDowngrade),
        _ => None,
    }
}

/// The untrusted category of an artifact that is NOT signed by a trusted key - decides which
/// explicit opt-in flag (if any) could permit it.
enum Untrusted {
    /// No valid signature: empty/tampered signature, or a first-party manifest in a build with no
    /// embedded key. Opt-in is `allow_unsigned`. A tamper of a KNOWN key's signature is still
    /// "unsigned" for opt-in purposes - it never counts as third-party. `tampered` distinguishes a
    /// PRESENT-but-failed signature (verification failed against a held key) from a plain
    /// no-signature/no-key case, for display labels ONLY (both are `allow_unsigned`-gated).
    /// `trusted_keys`: the first-party key ids a well-formed `publisher: busbar` signature
    /// verified against none of (carried to [`Rejected::trusted_keys`]); empty otherwise.
    Unsigned {
        reason: String,
        tampered: bool,
        trusted_keys: Vec<String>,
    },
    /// A manifest whose `publisher` is NOT `busbar` and NOT in the allowlist. Its signature cannot
    /// be verified here (no key held), so it is a third-party artifact. Opt-in is
    /// `allow_third_party`.
    ThirdParty { publisher: String },
}

/// PHASE 2 - TRUST evaluation of a structurally-valid manifest + its exact library bytes against
/// the policy. Returns [`Verdict`] when the plugin may proceed (trusted, or
/// untrusted-but-explicitly-opted-in), or [`Rejected`] when it must NOT load - the DEFAULT for any
/// untrusted artifact, and ALWAYS for an anti-downgrade violation (which no opt-in can relax).
///
/// TRUST MODEL:
///   * `publisher: busbar` verifies against the EMBEDDED release key -> first-party TRUSTED with
///     zero config. Anti-downgrade is AUTOMATIC but keyed to the PLUGIN's own version line, not the
///     binary's: `version` must be at/above [`TrustPolicy::first_party_high_water`], the highest
///     version of that name this deployment has seen and loaded. An explicit rollback pin
///     ([`TrustPolicy::first_party_floors`]) replaces that floor for the pinned name.
///     [`TrustPolicy::binary_version`] is NOT a floor.
///   * A publisher in `publishers` whose signature verifies -> TRUSTED (third-party allowlisted).
///   * Unsigned/tampered -> [`Verdict::Allowed`] only under `allow_unsigned`; else [`Rejected`].
///   * Signed by an unknown publisher -> [`Verdict::Allowed`] only under `allow_third_party`; else
///     [`Rejected`].
///
/// Anti-downgrade floors (`min_versions`, keyed by manifest `name`) are checked BEFORE any opt-in
/// relaxation and require a TRUSTED manifest at/above the floor - so a stripped-signature or
/// unknown-publisher downgrade cannot be laundered through a loose posture. The `version` field is
/// signature-covered, so it cannot be forged upward.
pub fn evaluate(
    bytes: &[u8],
    manifest: &Manifest,
    policy: &TrustPolicy,
) -> Result<Verdict, Rejected> {
    // REVOCATION before anything else: a revoked library is refused whoever signed it, and no
    // opt-in reaches it. Keyed by the library's OWN digest, never the manifest's claim of it.
    let digest = sha256_hex(bytes);
    if let Some(why) = policy.revoked.get(&digest) {
        return Err(Rejected::new(
            RejectKind::Revoked,
            format!(
                "plugin '{}' version {} (library sha256 {digest}) is REVOKED by this build: {why}. \
                 A revoked artifact never loads, whoever signed it and whatever plugins.trust \
                 permits; install a release that is not revoked.",
                manifest.name, manifest.version
            ),
        ));
    }

    // Trust determination first: which key (if any) proves this manifest? A manifest with NO
    // signature at all is UNSIGNED regardless of its (unverifiable, self-declared) publisher -
    // only a PRESENT signature from a non-allowlisted publisher counts as third-party.
    let checks = crate::release_trust::Checks {
        now: policy
            .release_clock
            .unwrap_or_else(crate::release_trust::now),
        keys_floor: policy.release_keys_floor,
        enforce_expiry: true,
    };
    let trusted_or_untrusted: Result<bool, Untrusted> = if manifest.signature.trim().is_empty() {
        Err(Untrusted::Unsigned {
            reason: "manifest carries no signature".to_string(),
            tampered: false,
            trusted_keys: Vec::new(),
        })
    } else if manifest.publisher == FIRST_PARTY_PUBLISHER {
        if policy.first_party_keys.is_empty() {
            Err(Untrusted::Unsigned {
                reason: format!(
                    "manifest claims first-party publisher '{FIRST_PARTY_PUBLISHER}' but this \
                     build embeds no busbar release key, so it cannot be verified"
                ),
                tampered: false,
                trusted_keys: Vec::new(),
            })
        } else {
            match first_party_signer(manifest, bytes, &policy.first_party_keys, checks) {
                Ok(_) => Ok(true),
                // A revoked artefact or signer, or a rolled-back keys document: a hard reject no
                // opt-in relaxes, exactly as the compiled-in revocation list and the floors are.
                Err(FirstPartyUnverified::Release {
                    refusal,
                    trusted_keys,
                }) if hard_seal_refusal(&refusal).is_some() => {
                    let kind = hard_seal_refusal(&refusal).expect("matched");
                    return Err(Rejected {
                        trusted_keys,
                        ..Rejected::new(
                            kind,
                            format!(
                                "plugin '{}' version {}: first-party release seal refused ({}): \
                                 {refusal}. No plugins.trust opt-in admits it.",
                                manifest.name,
                                manifest.version,
                                refusal.code()
                            ),
                        )
                    });
                }
                // `reason` is 1.5.5's bytes ("signature does not verify"); the key ids it tried
                // travel structured, never in the reason the boot WARN line prints.
                Err(unverified) => Err(Untrusted::Unsigned {
                    reason: format!("first-party signature failed: {unverified}"),
                    tampered: true,
                    trusted_keys: unverified.trusted_keys().to_vec(),
                }),
            }
        }
    } else {
        match policy.publishers.get(&manifest.publisher) {
            None => Err(Untrusted::ThirdParty {
                publisher: manifest.publisher.clone(),
            }),
            Some(key) => match signature_ok(manifest, bytes, key) {
                Ok(()) => Ok(false),
                Err(reason) => Err(Untrusted::Unsigned {
                    reason: format!(
                        "signature from allowlisted publisher '{}' failed: {reason}",
                        manifest.publisher
                    ),
                    tampered: true,
                    trusted_keys: Vec::new(),
                }),
            },
        }
    };

    // FIRST-PARTY anti-downgrade: PER-NAME floors only. There is deliberately NO automatic
    // binary-version floor: first-party plugins version on their own independent lines (the
    // stores/auth/hooks ship 1.0.x under a 1.5.0 engine — product decision,
    // 2026-08-02), so "at or above the binary's version" would reject every correctly-signed
    // current release.
    //
    // The floor that IS applied is the per-name HIGH-WATER MARK (`first_party_high_water`): the
    // highest version of THIS name this deployment has itself seen and loaded. That couples the
    // floor to the plugin's own version line instead of the binary's, so it closes the replay
    // (`docs/plugins.md` security-model item 3) without rejecting current releases. A name with no
    // mark carries no floor — a first install is not a downgrade.
    //
    // An EXPLICIT, audited rollback pin (`first_party_floors`, from `POST /plugins/rollback` via the
    // persisted `plugin_versions` overlay) REPLACES the mark for the pinned name — that is the
    // documented override, and it is scoped per name so rolling A back never admits an old B.
    // `min_versions` (below) floors first- and third-party alike and is checked separately.
    if let Ok(true) = trusted_or_untrusted {
        let pinned = policy.first_party_floors.get(&manifest.name);
        let floor = pinned
            .or_else(|| policy.first_party_high_water.get(&manifest.name))
            .map(String::as_str)
            .unwrap_or("");
        if !floor.is_empty() && !version_at_least(&manifest.version, floor) {
            let why = if pinned.is_some() {
                "the PINNED first-party rollback floor"
            } else {
                "the highest version of this plugin this deployment has seen and loaded"
            };
            return Err(Rejected::new(
                RejectKind::AntiDowngrade,
                format!(
                    "first-party plugin '{}' version {} is below the required first-party floor {} \
                     ({why}) (first-party anti-downgrade). A validly-signed but OLD release is \
                     still a signed artifact an attacker can replay, so this is a hard reject no \
                     trust opt-in can relax. To install this version DELIBERATELY, roll the plugin \
                     back explicitly (the audited plugins.rollback admin action), which replaces \
                     the floor for this plugin name only.{}",
                    manifest.name,
                    manifest.version,
                    floor,
                    floor_note(floor)
                ),
            ));
        }
    }

    // CONFIGURED anti-downgrade floor (hard reject, BEFORE any opt-in relaxation), keyed by the
    // manifest name. A floored name must be TRUSTED and its (now-verified) version must clear the
    // floor; anything else is a hard reject no opt-in flag can relax. The reject KIND is split by trust
    // state so the display label is honest: a TRUSTED artifact below the floor is `AntiDowngrade`
    // ("trusted (below floor)"); an UNTRUSTED artifact carrying a floored name is `UntrustedFloored`
    // (labeled by its real untrusted state). Both are still hard rejects — the floor requires trusted
    // proof, so a stripped-signature copy cannot launder a downgrade past it — but the untrusted case
    // is never mislabeled "trusted (below floor)" in `--list-plugins`.
    if let Some(floor) = policy.min_versions.get(&manifest.name) {
        match &trusted_or_untrusted {
            Ok(_) if version_at_least(&manifest.version, floor) => {}
            Ok(_) => {
                return Err(Rejected::new(
                    RejectKind::AntiDowngrade,
                    format!(
                        "plugin '{}' version {} is below the pinned minimum {floor} \
                         (anti-downgrade){}",
                        manifest.name,
                        manifest.version,
                        floor_note(floor)
                    ),
                ));
            }
            Err(_) => {
                return Err(Rejected::new(
                    RejectKind::UntrustedFloored,
                    format!(
                        "plugin '{}' has a pinned minimum version {floor} but the load could not \
                         prove it meets the floor (not signed by a trusted key); a trusted manifest \
                         at or above the floor is required (anti-downgrade){}",
                        manifest.name,
                        floor_note(floor)
                    ),
                ));
            }
        }
    }

    match trusted_or_untrusted {
        Ok(first_party) => Ok(Verdict::Trusted {
            publisher: manifest.publisher.clone(),
            first_party,
        }),
        Err(Untrusted::Unsigned {
            reason,
            tampered,
            trusted_keys,
        }) => {
            if policy.allow_unsigned {
                Ok(Verdict::Allowed {
                    reason,
                    allow: AllowReason::Unsigned,
                })
            } else {
                let kind = if tampered {
                    RejectKind::Tampered
                } else {
                    RejectKind::Unsigned
                };
                Err(Rejected {
                    trusted_keys,
                    ..Rejected::new(
                        kind,
                        format!(
                            "{reason}; refusing to load an unsigned plugin. Set \
                             plugins.trust.allow_unsigned=true to permit unsigned plugins."
                        ),
                    )
                })
            }
        }
        Err(Untrusted::ThirdParty { publisher }) => {
            if policy.allow_third_party {
                Ok(Verdict::Allowed {
                    reason: format!("signed by non-allowlisted publisher '{publisher}'"),
                    allow: AllowReason::ThirdParty,
                })
            } else {
                Err(Rejected::new(
                    RejectKind::UnknownPublisher,
                    format!(
                        "publisher '{publisher}' is not in the allowlist; refusing to load a \
                         third-party plugin. Add the publisher to plugins.trust.publishers, or set \
                         plugins.trust.allow_third_party=true to permit third-party plugins."
                    ),
                ))
            }
        }
    }
}

#[cfg(test)]
#[allow(unsafe_code)] // TEST ONLY
#[path = "tests/sign_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/declares_reader_tests.rs"]
mod declares_reader_tests;

#[cfg(test)]
#[path = "tests/release_seal_tests.rs"]
mod release_seal_tests;
