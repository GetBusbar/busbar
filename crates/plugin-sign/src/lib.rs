// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin **manifest, signing input, structural validation, and trust evaluation** for busbar.
//!
//! A PLUGIN IS A PLUGIN: store, auth, and hook plugins share ONE manifest format and ONE trust
//! model, discriminated only by the manifest `kind` field. Every plugin ships as a signed tarball
//! containing exactly the cdylib and this manifest; identity comes from the SIGNED manifest, never
//! from the filename.
//!
//! The manifest carries:
//!
//! - **identity**: `name` (canonical, e.g. `busbar-store-valkey-plugin`), `alias` (the short config name,
//!   e.g. `valkey`), `kind` (`store` | `auth` | `hook` | `secret`), `version` (semver);
//! - **binding + compat**: `sha256` (of the library bytes, pinning the manifest to that exact
//!   binary) and `abi_version` (which busbar C ABI the cdylib exports for its `kind`);
//! - **authenticity**: `publisher` + `signature` over the *canonical whole manifest*;
//! - **display**: `description`, `homepage`, `license` (all signed, so they cannot be spoofed).
//!
//! The signature covers the entire manifest (every field except `signature` itself) via
//! [`canonical_manifest_bytes`], and the manifest pins the library by `sha256`, so **neither the
//! manifest nor the library can be altered or swapped independently**.
//!
//! ## Trust model
//!
//! - **First-party**: a manifest whose `publisher` is `busbar` verifies against the release public
//!   key EMBEDDED in the binary ([`embedded_release_pubkey`]) - trusted with ZERO configuration.
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
//! This crate is pure data + policy: no I/O, no engine state. Discovery, unpacking, and loading
//! live in `busbar-plugin-loader`; the engine sees neither. [`sign`] exists for the release
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
use ed25519_dalek::{Signature, Signer, Verifier};
pub use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The reserved first-party publisher name. A manifest carrying this publisher verifies against the
/// EMBEDDED release key ([`TrustPolicy::first_party_key`]), never against `publishers` - an operator
/// cannot (and need not) allowlist a key named `busbar`.
pub const FIRST_PARTY_PUBLISHER: &str = "busbar";

/// The plugin kinds this binary understands. ONE plugin subsystem: `kind` only selects which C ABI
/// the cdylib exports and which engine subsystem consumes it; discovery/trust/validation are shared.
pub const KNOWN_KINDS: &[&str] = &["store", "auth", "hook", "secret", "export"];

/// This binary's own host identity — the value [`Manifest::host`] must match (or omit) to load.
/// `busbar` names the OSS engine. A sibling product (e.g. `busbar-ui`) that reuses this exact
/// manifest/signing/ABI machinery stamps its own plugins `host: busbar-ui`; those manifests are
/// STRUCTURALLY VALID (same six-symbol C ABI, same signed-manifest shape, same `kind` vocabulary)
/// but semantically foreign — a `busbar-ui` `store` plugin persists tenants/deployments, not the
/// keys/denylists an engine `store` plugin implements. Same `kind` string, incompatible contracts,
/// so `host` is what disambiguates them structurally rather than trusting `kind` alone.
pub const HOST_IDENTITY: &str = "busbar";

/// The busbar release ed25519 PUBLIC key embedded at BUILD time via the `BUSBAR_RELEASE_PUBKEY`
/// environment variable (64 hex chars). `None` in a build where it was not provided (local dev
/// builds): first-party verification is then impossible and a `publisher: busbar` plugin is treated
/// as unsigned (loadable only under `allow_unsigned`).
///
/// TODO(release-keys): the REAL release keypair is generated separately by the release orchestrator;
/// CI must export `BUSBAR_RELEASE_PUBKEY=<hex public key>` when building release binaries (the
/// private half lives only in the `BUSBAR_SIGN_KEY` CI secret). Do NOT hardcode a key here.
pub fn embedded_release_pubkey() -> Option<VerifyingKey> {
    let hex_key: &str = option_env!("BUSBAR_RELEASE_PUBKEY")?;
    // A malformed build-time key is a build/packaging bug; fail closed to "no first-party key"
    // rather than panic in the engine (the plugin then simply cannot verify as first-party).
    public_key_from_hex(hex_key).ok()
}

/// The signed manifest that travels inside every plugin tarball. Every field except `signature` is
/// covered by the signature (via [`canonical_manifest_bytes`]), so none can be altered undetected.
///
/// `deny_unknown_fields`: a manifest with fields this binary does not understand FAILS structural
/// validation (fail-closed) rather than silently dropping content the signature may cover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Canonical plugin name, e.g. `busbar-store-valkey-plugin`. Lowercase `[a-z0-9-]+`.
    pub name: String,
    /// Short config alias, e.g. `valkey` - what `governance.store:` may reference. Lowercase
    /// `[a-z0-9-]+`. May equal `name`.
    pub alias: String,
    /// Plugin category: `store` | `secret` | `auth` | `hook`. Selects the C ABI the cdylib exports and the
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
    /// string - see `busbarAI-private/design/plugin-settings-schema-SPEC.md`.
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
    /// structurally enforced, a compile error rather than an assertion) — see
    /// `busbarAI-private/design/plugin-settings-schema-SPEC.md` question #4's round-3/5
    /// corrections. `false` by default (serde-default so every existing manifest still parses).
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

/// One axis of a hook manifest's declared intent — the SAME `no ⊂ ro ⊂ rw` ladder the operator grant
/// uses, so the core can compare "declared" against "granted" directly. `rw` is meaningful only on the
/// `prompt` axis (identity is never rewritten); on `user` it reads as "at least ro".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NeedLevel {
    /// Declares no need for this content (the default).
    #[default]
    No,
    /// Asks to READ this content.
    Ro,
    /// Asks to read AND rewrite (prompt axis only).
    Rw,
}

impl NeedLevel {
    /// Whether the plugin declared it needs to READ this axis (`ro` or `rw`).
    pub fn wants_read(self) -> bool {
        !matches!(self, NeedLevel::No)
    }
    /// Whether the plugin declared it needs to REWRITE (prompt axis; `rw`).
    pub fn wants_rewrite(self) -> bool {
        matches!(self, NeedLevel::Rw)
    }
}

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
    /// The embedded busbar release public key ([`embedded_release_pubkey`]). `None` in a build with
    /// no embedded key: first-party plugins then cannot verify (they are treated as unsigned).
    pub first_party_key: Option<VerifyingKey>,
    /// The running binary's version (`CARGO_PKG_VERSION`). Informational (error text/telemetry)
    /// only: it is NOT a floor. First-party plugins version on their own independent lines
    /// (1.0.x stores/auth/hooks, 2.x headroom, under a 1.5.0 engine), so the pre-release
    /// automatic "plugin >= binary version" floor would have rejected every correctly-signed
    /// current first-party release and was removed before 1.5.0 shipped.
    pub binary_version: String,
    /// PER-PLUGIN first-party anti-downgrade floors (1.5.0 rollback pins, M1) — with no automatic
    /// binary floor these are the ONLY first-party floors (alongside `min_versions`). `name` ->
    /// the pinned minimum version; a name absent here carries no first-party floor. Scoping per
    /// name keeps a rollback of plugin A from ever changing what plugin B is allowed to be.
    pub first_party_floors: BTreeMap<String, String>,
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
/// derived from plugin `kind` — never plugin-declared (plugin-settings-schema-SPEC.md question
/// #14). `store`/`secret` plugins bind once at process start (every field is restart-scoped by
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
/// ASYMMETRICALLY (question #14, round-4 correction):
///   * an override to `true` against a kind default of `false` is ALWAYS honored — claiming a field
///     needs a restart when the kind default says it doesn't is the safe direction to be wrong in
///     (worst case: one unnecessary restart);
///   * an override to `false` against a kind default of `true` is honored ONLY when the manifest
///     verifiably came from a TRUSTED, first-party (`publisher == "busbar"`) artifact — the same
///     trust+publisher gate `schema_derived`'s load-bearing rule uses (question #4's round-3/5
///     corrections), for the identical reason: a third-party claim in the direction that could
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
                // direction question #14 is guarding against.
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
}

/// Trust failure. The posture forbids loading this plugin; the message is safe to surface. `kind` is
/// the structured category (the authority for any label/column); `reason` is the human message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    pub reason: String,
    pub kind: RejectKind,
}

impl Rejected {
    /// Construct a rejection from a structured `kind` and a human `reason`.
    fn new(kind: RejectKind, reason: String) -> Self {
        Rejected { reason, kind }
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
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
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
pub fn public_key_from_hex(s: &str) -> Result<VerifyingKey, String> {
    let bytes = hex::decode(s.trim()).map_err(|e| format!("public key not valid hex: {e}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("public key must be 32 bytes, got {}", bytes.len()))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("invalid ed25519 public key: {e}"))
}

/// Whether a manifest's signature verifies against `bytes` using `key`: the library hash must match
/// the manifest's `sha256` (binding), and the signature must verify over the canonical manifest
/// (authenticity + integrity).
fn signature_ok(manifest: &Manifest, bytes: &[u8], key: &VerifyingKey) -> Result<(), String> {
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
    let sig = Signature::from_bytes(&sig_arr);
    key.verify(&canonical_manifest_bytes(manifest), &sig)
        .map_err(|_| "signature does not verify".to_string())
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

/// Is `v` a well-formed semver core (`MAJOR.MINOR.PATCH`, each a decimal integer, with an optional
/// `-pre`/`+meta` suffix)? The strict three-component core is what the anti-downgrade ordering
/// depends on, so it is validated structurally rather than best-effort parsed.
pub fn valid_semver(v: &str) -> bool {
    let core = v.split(['-', '+']).next().unwrap_or("");
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
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
    if !KNOWN_KINDS.contains(&m.kind.as_str()) {
        return Err(format!(
            "manifest kind '{}' is not one of {KNOWN_KINDS:?}",
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
    // HOST identity gate: an ABSENT `host` means `busbar` (backward compatible with every manifest
    // packed before this field existed). An EXPLICIT `host` that is not the caller's own identity
    // is a hard structural reject — not a silent ignore — because a sibling product (busbar-ui)
    // reuses the identical six-symbol ABI and signed-manifest shape, so a foreign-host manifest
    // would otherwise pass the ABI handshake and go on to answer `kind`-matched calls (e.g.
    // `store`) with an incompatible payload contract. This check runs in phase 1 (structural),
    // independent of trust/signature, so even a validly-signed foreign-host manifest is refused.
    //
    // `host_identity` is a PARAMETER, not a hardcoded const (see E-010 in busbar-ui's
    // ENGINE-BUGS.md): this verifier is shared verbatim by sibling products with different host
    // identities (busbar's own callers pass `HOST_IDENTITY` = `"busbar"`; busbar-ui passes its
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
    // `supported_abi` returns a CONTIGUOUS `[floor, max]` inclusive range (its endpoints) of the
    // PAYLOAD-schema versions the binary speaks for this kind. Negotiate the manifest's declared
    // `abi_version` against it: in range → ok; below floor / above max → refuse LOUD naming both.
    // An empty slice means the kind is unsupported (already caught by KNOWN_KINDS, but fail-closed).
    let supported = supported_abi(&m.kind);
    match (supported.first(), supported.last()) {
        (Some(&floor), Some(&max)) if m.abi_version >= floor && m.abi_version <= max => {}
        (Some(&floor), Some(&max)) => {
            return Err(format!(
                "manifest abi_version {} is not supported for kind '{}' by this binary (supported \
                 range v{floor}..=v{max})",
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

/// The untrusted category of an artifact that is NOT signed by a trusted key - decides which
/// explicit opt-in flag (if any) could permit it.
enum Untrusted {
    /// No valid signature: empty/tampered signature, or a first-party manifest in a build with no
    /// embedded key. Opt-in is `allow_unsigned`. A tamper of a KNOWN key's signature is still
    /// "unsigned" for opt-in purposes - it never counts as third-party. `tampered` distinguishes a
    /// PRESENT-but-failed signature (verification failed against a held key) from a plain
    /// no-signature/no-key case, for display labels ONLY (both are `allow_unsigned`-gated).
    Unsigned { reason: String, tampered: bool },
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
///     zero config. Anti-downgrade is AUTOMATIC: `version` must be at/above
///     [`TrustPolicy::binary_version`].
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
    // Trust determination first: which key (if any) proves this manifest? A manifest with NO
    // signature at all is UNSIGNED regardless of its (unverifiable, self-declared) publisher -
    // only a PRESENT signature from a non-allowlisted publisher counts as third-party.
    let trusted_or_untrusted: Result<bool, Untrusted> = if manifest.signature.trim().is_empty() {
        Err(Untrusted::Unsigned {
            reason: "manifest carries no signature".to_string(),
            tampered: false,
        })
    } else if manifest.publisher == FIRST_PARTY_PUBLISHER {
        match &policy.first_party_key {
            None => Err(Untrusted::Unsigned {
                reason: format!(
                    "manifest claims first-party publisher '{FIRST_PARTY_PUBLISHER}' but this \
                     build embeds no busbar release key, so it cannot be verified"
                ),
                tampered: false,
            }),
            Some(key) => match signature_ok(manifest, bytes, key) {
                Ok(()) => Ok(true),
                Err(reason) => Err(Untrusted::Unsigned {
                    reason: format!("first-party signature failed: {reason}"),
                    tampered: true,
                }),
            },
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
                }),
            },
        }
    };

    // FIRST-PARTY anti-downgrade: PER-NAME floors only (`first_party_floors`, plus the general
    // `min_versions` block below). There is deliberately NO automatic binary-version floor:
    // first-party plugins version on their own independent lines (the stores/auth/hooks ship
    // 1.0.x and headroom 2.x under a 1.5.0 engine — product decision, 2026-08-02), so "at or
    // above the binary's version" would reject every correctly-signed current release. The
    // replay threat the old automatic floor addressed is covered per name: a rollback pin
    // (`first_party_floors`) or an operator/registry `min_versions` floor, both hard rejects no
    // opt-in flag can relax. (Future: the plugin registry embeds known per-plugin floors at
    // release time, restoring zero-config anti-replay without version-line coupling.)
    if let Ok(true) = trusted_or_untrusted {
        let floor = policy
            .first_party_floors
            .get(&manifest.name)
            .map(String::as_str)
            .unwrap_or("");
        if !floor.is_empty() && !version_at_least(&manifest.version, floor) {
            return Err(Rejected::new(
                RejectKind::AntiDowngrade,
                format!(
                    "first-party plugin '{}' version {} is below the required first-party floor {} \
                     (automatic first-party anti-downgrade){}",
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
    // proof, so a stripped-signature copy cannot launder a downgrade past it — but the untrusted case is
    // NO LONGER mislabeled "trusted (below floor)" in `--list-plugins` (the round-1 regression).
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
        Err(Untrusted::Unsigned { reason, tampered }) => {
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
                Err(Rejected::new(
                    kind,
                    format!(
                        "{reason}; refusing to load an unsigned plugin. Set \
                         plugins.trust.allow_unsigned=true to permit unsigned plugins."
                    ),
                ))
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
mod tests {
    use super::*;

    /// Deterministic test key from a seed byte (no RNG needed in this crate's tests).
    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// A well-formed manifest (sha256/signature set by `sign`).
    fn manifest(name: &str, alias: &str, publisher: &str) -> Manifest {
        Manifest {
            name: name.to_string(),
            alias: alias.to_string(),
            kind: "store".to_string(),
            version: "1.5.0".to_string(),
            publisher: publisher.to_string(),
            abi_version: 1,
            sha256: String::new(),
            signature: String::new(),
            description: "A store plugin".to_string(),
            homepage: "https://example.dev".to_string(),
            license: "Apache-2.0".to_string(),
            needs: HookNeeds::default(),
            settings_schema: None,
            schema_derived: false,
            host: None,
        }
    }

    /// The advisory `needs:` intent is SIGNED (covered by the canonical bytes) so it cannot be
    /// spoofed, and a manifest omitting it parses with the default "asks for nothing". `NeedLevel`
    /// exposes the read/rewrite predicates the core compares against the operator grant.
    #[test]
    fn hook_needs_is_signed_and_defaults_to_none() {
        // Default (absent) needs → declares nothing.
        let n = HookNeeds::default();
        assert!(!n.declares_any());
        assert!(!n.prompt.wants_read());

        // A declared prompt:rw need round-trips through JSON and reads as read+rewrite.
        let json = r#"{"prompt":"rw","user":"ro"}"#;
        let parsed: HookNeeds = serde_json::from_str(json).unwrap();
        assert!(parsed.declares_any());
        assert!(parsed.prompt.wants_read() && parsed.prompt.wants_rewrite());
        assert!(parsed.user.wants_read() && !parsed.user.wants_rewrite());

        // It is covered by the signature: changing `needs` after signing breaks verification.
        let key = test_key(9);
        let mut m = manifest("busbar-hook-x", "x", "busbar");
        m.kind = "hook".into();
        let signed = sign(&key, m, b"lib");
        let mut tampered = signed.clone();
        tampered.needs = parsed;
        assert!(
            signature_ok(&tampered, b"lib", &key.verifying_key()).is_err(),
            "altering the declared intent after signing must fail verification"
        );
        assert!(signature_ok(&signed, b"lib", &key.verifying_key()).is_ok());
    }

    fn abi(_kind: &str) -> &'static [u32] {
        &[1]
    }

    /// A policy with the given first-party key, third-party publishers, and opt-in flags.
    fn policy(
        first_party: Option<&SigningKey>,
        pairs: &[(&str, &VerifyingKey)],
        allow_unsigned: bool,
        allow_third_party: bool,
    ) -> TrustPolicy {
        TrustPolicy {
            first_party_key: first_party.map(|k| k.verifying_key()),
            binary_version: "1.5.0".to_string(),
            first_party_floors: BTreeMap::new(),
            publishers: pairs.iter().map(|(n, k)| (n.to_string(), **k)).collect(),
            allow_unsigned,
            allow_third_party,
            min_versions: BTreeMap::new(),
        }
    }

    #[test]
    fn first_party_signed_is_trusted_with_zero_config() {
        let release = test_key(1);
        let artifact = b"\x7fELF first-party plugin";
        let m = sign(
            &release,
            manifest(
                "busbar-store-valkey-plugin",
                "valkey",
                FIRST_PARTY_PUBLISHER,
            ),
            artifact,
        );
        // Manifest round-trips through JSON (it travels inside the tarball).
        let j = serde_json::to_string(&m).unwrap();
        assert_eq!(serde_json::from_str::<Manifest>(&j).unwrap(), m);

        // ZERO configured publishers: the embedded key alone proves first-party.
        let pol = policy(Some(&release), &[], false, false);
        assert_eq!(
            evaluate(artifact, &m, &pol).unwrap(),
            Verdict::Trusted {
                publisher: FIRST_PARTY_PUBLISHER.into(),
                first_party: true
            }
        );
    }

    /// P2: `kind: secret` is a first-class plugin kind - a signed secret-module manifest passes
    /// structural validation and the trust evaluation identically to a store plugin (a plugin is a
    /// plugin), while an unknown kind still fails structure.
    #[test]
    fn secret_kind_is_known_and_signs_like_any_plugin() {
        assert!(KNOWN_KINDS.contains(&"secret"));
        let release = test_key(1);
        let artifact = b"\x7fELF secret plugin";
        let mut m0 = manifest("busbar-secret-vault", "vault", FIRST_PARTY_PUBLISHER);
        m0.kind = "secret".to_string();
        let m = sign(&release, m0, artifact);
        validate_structure(&m, artifact, &abi, HOST_IDENTITY)
            .expect("kind secret is structurally valid");
        let pol = policy(Some(&release), &[], false, false);
        assert_eq!(
            evaluate(artifact, &m, &pol).unwrap(),
            Verdict::Trusted {
                publisher: FIRST_PARTY_PUBLISHER.into(),
                first_party: true
            }
        );
        // A made-up kind still fails structure (the closed KNOWN_KINDS set).
        let mut bad = manifest("busbar-x", "x", FIRST_PARTY_PUBLISHER);
        bad.kind = "gizmo".to_string();
        let bad = sign(&release, bad, artifact);
        let err = validate_structure(&bad, artifact, &abi, HOST_IDENTITY).unwrap_err();
        assert!(err.contains("gizmo"), "got {err}");
    }

    /// `kind: export` is a first-class plugin kind — a signed export-sink manifest passes structural
    /// validation and trust evaluation identically to any other plugin (a plugin is a plugin). Mirrors
    /// `secret_kind_is_known_and_signs_like_any_plugin`.
    #[test]
    fn export_kind_is_known_and_signs_like_any_plugin() {
        assert!(KNOWN_KINDS.contains(&"export"));
        let release = test_key(1);
        let artifact = b"\x7fELF export plugin";
        let mut m0 = manifest("busbar-export-otlp", "otlp", FIRST_PARTY_PUBLISHER);
        m0.kind = "export".to_string();
        let m = sign(&release, m0, artifact);
        validate_structure(&m, artifact, &abi, HOST_IDENTITY)
            .expect("kind export is structurally valid");
        let pol = policy(Some(&release), &[], false, false);
        assert_eq!(
            evaluate(artifact, &m, &pol).unwrap(),
            Verdict::Trusted {
                publisher: FIRST_PARTY_PUBLISHER.into(),
                first_party: true
            }
        );
    }

    /// First-party plugin versions float FREE of the binary's version: the fleet ships 1.0.x
    /// stores/auth/hooks (and 2.x headroom) under a 1.5.0 engine, so a verified first-party
    /// plugin below the binary version MUST load when no per-name floor pins it. (The automatic
    /// binary-version floor this replaces rejected every correctly-signed current release.)
    #[test]
    fn first_party_version_floats_free_of_the_binary_version() {
        let release = test_key(1);
        let artifact = b"current first-party build on its own version line";
        let mut m = manifest(
            "busbar-store-valkey-plugin",
            "valkey",
            FIRST_PARTY_PUBLISHER,
        );
        m.version = "1.0.1".into(); // binary is 1.5.0 — and that must not matter
        let m = sign(&release, m, artifact);
        let pol = policy(Some(&release), &[], false, false);
        assert!(
            matches!(
                evaluate(artifact, &m, &pol),
                Ok(Verdict::Trusted {
                    first_party: true,
                    ..
                })
            ),
            "a verified first-party plugin with no per-name floor loads regardless of the binary version"
        );

        // A per-name floor (rollback pin / registry floor) still hard-rejects below it, and no
        // loose opt-in flag can launder that (verified first-party never consults opt-ins).
        let mut floored = policy(Some(&release), &[], true, true);
        floored.first_party_floors.insert(
            "busbar-store-valkey-plugin".to_string(),
            "1.0.2".to_string(),
        );
        let err = evaluate(artifact, &m, &floored).unwrap_err();
        assert!(
            err.reason.contains("first-party anti-downgrade"),
            "got {err:?}"
        );
    }

    /// M1 (per-name scoping, floors-only form): a PER-NAME first-party floor binds the pinned name
    /// ONLY. Plugin A's floor must never change what plugin B is allowed to be — B is judged
    /// solely by its own pin (or, absent one, no floor).
    #[test]
    fn first_party_floor_override_is_scoped_per_name() {
        let release = test_key(1);
        let artifact_a = b"old first-party A";
        let artifact_b = b"old first-party B";
        let mut a = manifest(
            "busbar-store-valkey-plugin",
            "valkey",
            FIRST_PARTY_PUBLISHER,
        );
        a.version = "1.4.0".into();
        let a = sign(&release, a, artifact_a);
        let mut b = manifest("busbar-hook-ranker", "ranker", FIRST_PARTY_PUBLISHER);
        b.version = "1.4.0".into();
        let b = sign(&release, b, artifact_b);

        // Floor A at 1.4.1 (above what A ships) and leave B unpinned.
        let mut pol = policy(Some(&release), &[], false, false);
        pol.first_party_floors.insert(
            "busbar-store-valkey-plugin".to_string(),
            "1.4.1".to_string(),
        );

        // A is below ITS OWN floor and is rejected.
        let err = evaluate(artifact_a, &a, &pol).unwrap_err();
        assert!(
            err.reason.contains("anti-downgrade"),
            "a pinned first-party plugin below its own floor is rejected: {err:?}"
        );
        // B, unpinned, is untouched by A's floor and loads.
        assert!(
            matches!(
                evaluate(artifact_b, &b, &pol),
                Ok(Verdict::Trusted {
                    first_party: true,
                    ..
                })
            ),
            "another plugin's floor must not leak onto an unpinned first-party plugin"
        );
    }

    #[test]
    fn first_party_claim_without_embedded_key_is_unsigned() {
        let release = test_key(1);
        let artifact = b"bytes";
        let m = sign(
            &release,
            manifest(
                "busbar-store-valkey-plugin",
                "valkey",
                FIRST_PARTY_PUBLISHER,
            ),
            artifact,
        );
        // No embedded key in this build: default posture rejects, naming the situation.
        let pol = policy(None, &[], false, false);
        let err = evaluate(artifact, &m, &pol).unwrap_err();
        assert!(
            err.reason.contains("embeds no busbar release key"),
            "got {err:?}"
        );
        // allow_unsigned permits it (dev builds), as the Unsigned category.
        let loose = policy(None, &[], true, false);
        assert!(matches!(
            evaluate(artifact, &m, &loose).unwrap(),
            Verdict::Allowed {
                allow: AllowReason::Unsigned,
                ..
            }
        ));
    }

    /// FIRST-PARTY IMPERSONATION is impossible: an attacker signs a plugin with their OWN key and
    /// sets `publisher: busbar` to masquerade as first-party. Even with the real release key
    /// EMBEDDED, evaluation routes a `publisher: busbar` manifest ONLY to the embedded key, so the
    /// attacker's signature fails and the plugin is UNSIGNED (rejected by default; never third-party
    /// laundered, and never trusted). Setting the publisher name buys nothing.
    #[test]
    fn first_party_publisher_name_cannot_be_forged_with_another_key() {
        let release = test_key(1); // the REAL embedded release key
        let attacker = test_key(9); // a key the operator never trusted
        let artifact = b"malicious plugin claiming to be busbar";
        // Attacker signs a busbar-branded manifest with their own key.
        let m = sign(
            &attacker,
            manifest(
                "busbar-store-valkey-plugin",
                "valkey",
                FIRST_PARTY_PUBLISHER,
            ),
            artifact,
        );
        // Embedded key present, attacker NOT in publishers. Default posture: rejected as unsigned
        // (the signature does not verify against the embedded first-party key).
        let pol = policy(Some(&release), &[], false, false);
        let err = evaluate(artifact, &m, &pol).unwrap_err();
        assert!(
            err.reason.contains("first-party signature failed"),
            "impersonation must be reported as a first-party signature failure, got {err:?}"
        );
        // Even allow_third_party cannot launder it: a `busbar` publisher never routes to the
        // third-party path, so the third-party opt-in is irrelevant. It stays UNSIGNED-category,
        // permitted ONLY by allow_unsigned (which is "load anything unsigned" by definition).
        let third_party_open = policy(Some(&release), &[], false, true);
        assert!(
            evaluate(artifact, &m, &third_party_open).is_err(),
            "allow_third_party must NOT permit a forged first-party plugin"
        );
        // And the attacker cannot get themselves allowlisted UNDER the name `busbar` to reach the
        // first-party branch: even if such a policy existed, the `publisher == busbar` branch only
        // consults the embedded key, never `publishers`. Prove the routing directly.
        let mut mislead = policy(Some(&release), &[], false, false);
        mislead
            .publishers
            .insert(FIRST_PARTY_PUBLISHER.to_string(), attacker.verifying_key());
        assert!(
            evaluate(artifact, &m, &mislead).is_err(),
            "a 'busbar' entry in publishers must never override the embedded first-party key"
        );
    }

    /// STRIPPED-SIGNATURE first-party downgrade: an attacker takes an OLD first-party release,
    /// strips its signature, and hopes the automatic first-party anti-downgrade (which only guards
    /// VERIFIED first-party manifests) no longer applies. Under the DEFAULT posture it is rejected
    /// as unsigned - the downgrade never lands. (Under allow_unsigned the operator has already
    /// opted into loading arbitrary unsigned code, so this is out of scope of the anti-downgrade
    /// guarantee, which is specifically about REPLAYING a still-VALIDLY-SIGNED old release.)
    #[test]
    fn stripped_signature_old_first_party_is_rejected_by_default() {
        let release = test_key(1);
        let artifact = b"old vulnerable first-party build";
        let mut old = manifest(
            "busbar-store-valkey-plugin",
            "valkey",
            FIRST_PARTY_PUBLISHER,
        );
        old.version = "1.0.0".into(); // below the 1.5.0 binary
        let old = sign(&release, old, artifact);
        // Strip the (valid) signature: now it is an unsigned artifact claiming to be busbar.
        let mut stripped = old.clone();
        stripped.signature = String::new();
        let pol = policy(Some(&release), &[], false, false);
        let err = evaluate(artifact, &stripped, &pol).unwrap_err();
        assert!(
            err.reason.contains("unsigned") || err.reason.contains("no signature"),
            "a stripped-signature old first-party plugin must be rejected as unsigned, got {err:?}"
        );
    }

    #[test]
    fn third_party_allowlisted_publisher_is_trusted() {
        let acme = test_key(2);
        let artifact = b"third-party bytes";
        let m = sign(
            &acme,
            manifest("acme-store-dynamo", "dynamo", "acme"),
            artifact,
        );
        let pol = policy(None, &[("acme", &acme.verifying_key())], false, false);
        assert_eq!(
            evaluate(artifact, &m, &pol).unwrap(),
            Verdict::Trusted {
                publisher: "acme".into(),
                first_party: false
            }
        );
    }

    #[test]
    fn tampering_any_signed_field_fails() {
        let key = test_key(1);
        let artifact = b"bytes";
        let m = sign(&key, manifest("acme-p", "p", "acme"), artifact);
        let pol = policy(None, &[("acme", &key.verifying_key())], false, false);

        // Flip a DISPLAY field: signature must break (the display card cannot be spoofed).
        let mut forged = m.clone();
        forged.description = "Busbar Official".into();
        assert!(evaluate(artifact, &forged, &pol).is_err());
        // Flip the ALIAS (the config-selection identity): signature must break.
        let mut forged = m.clone();
        forged.alias = "valkey".into();
        assert!(evaluate(artifact, &forged, &pol).is_err());
        // Swap the library under a good manifest -> hash mismatch.
        assert!(evaluate(b"different!", &m, &pol).is_err());
    }

    #[test]
    fn wrong_publisher_key_does_not_verify() {
        let key = test_key(1);
        let attacker = test_key(2);
        let artifact = b"bytes";
        let m = sign(&key, manifest("acme-p", "p", "acme"), artifact);
        let pol = policy(None, &[("acme", &attacker.verifying_key())], false, false);
        assert!(evaluate(artifact, &m, &pol).is_err());
    }

    #[test]
    fn unknown_publisher_needs_allow_third_party() {
        let key = test_key(3);
        let artifact = b"third-party bytes";
        let m = sign(&key, manifest("acme-p", "p", "acme"), artifact);

        // Default: refused, naming allow_third_party (NOT allow_unsigned).
        let err = evaluate(artifact, &m, &policy(None, &[], false, false)).unwrap_err();
        assert!(err.reason.contains("allow_third_party"), "got {err:?}");
        // allow_unsigned alone does NOT permit a third-party-signed plugin.
        assert!(evaluate(artifact, &m, &policy(None, &[], true, false)).is_err());
        // allow_third_party permits it.
        assert!(matches!(
            evaluate(artifact, &m, &policy(None, &[], false, true)).unwrap(),
            Verdict::Allowed {
                allow: AllowReason::ThirdParty,
                ..
            }
        ));
    }

    #[test]
    fn unsigned_needs_allow_unsigned() {
        let artifact = b"unsigned bytes";
        let mut m = manifest("acme-p", "p", "acme");
        m.sha256 = sha256_hex(artifact);
        // Publisher IS allowlisted but the signature is empty -> tamper/unsigned category.
        let key = test_key(1);
        let pol = policy(None, &[("acme", &key.verifying_key())], false, false);
        let err = evaluate(artifact, &m, &pol).unwrap_err();
        assert!(err.reason.contains("allow_unsigned"), "got {err:?}");
        let loose = policy(None, &[("acme", &key.verifying_key())], true, false);
        assert!(matches!(
            evaluate(artifact, &m, &loose).unwrap(),
            Verdict::Allowed {
                allow: AllowReason::Unsigned,
                ..
            }
        ));
    }

    #[test]
    fn canonical_bytes_are_stable_and_exclude_signature() {
        let key = test_key(1);
        let m = sign(&key, manifest("acme-p", "p", "acme"), b"bytes");
        let a = canonical_manifest_bytes(&m);
        let mut m2 = m.clone();
        m2.signature = "deadbeef".into();
        assert_eq!(a, canonical_manifest_bytes(&m2));
        // Sorted-key JSON: abi_version sorts before alias before name.
        let s = String::from_utf8(a).unwrap();
        assert!(s.find("\"abi_version\"").unwrap() < s.find("\"alias\"").unwrap());
        assert!(s.find("\"alias\"").unwrap() < s.find("\"name\"").unwrap());
    }

    #[test]
    fn public_key_hex_roundtrip() {
        let key = test_key(1);
        let hex = hex::encode(key.verifying_key().to_bytes());
        assert_eq!(public_key_from_hex(&hex).unwrap(), key.verifying_key());
        assert!(public_key_from_hex("zz").is_err());
    }

    #[test]
    fn version_ordering_is_numeric_not_lexical() {
        assert!(version_at_least("1.10.0", "1.9.0"), "10 > 9 numerically");
        assert!(version_at_least("2.0.0", "1.99.99"));
        assert!(version_at_least("1.4.0", "1.4.0"), "equal clears the floor");
        assert!(!version_at_least("1.3.9", "1.4.0"));
        assert!(version_at_least("1.4.0-rc1", "1.4.0"));
        assert!(!version_at_least("not-a-version", "0.0.1"));
    }

    #[test]
    fn name_and_semver_validators() {
        assert!(valid_name("busbar-store-valkey-plugin"));
        assert!(valid_name("valkey"));
        assert!(!valid_name(""));
        assert!(!valid_name("Valkey"));
        assert!(!valid_name("re dis"));
        assert!(!valid_name("-valkey"));
        assert!(!valid_name("valkey-"));
        assert!(!valid_name("../evil"));
        assert!(valid_semver("1.5.0"));
        assert!(valid_semver("1.5.0-rc1"));
        assert!(!valid_semver("1.5"));
        assert!(!valid_semver("1.5.x"));
        assert!(!valid_semver(""));
    }

    /// Phase-1 structural validation catches each malformation with a specific reason, independent
    /// of trust (a validly-signed malformed manifest still fails).
    #[test]
    fn structural_validation_names_each_failure() {
        let key = test_key(1);
        let bytes = b"lib bytes";
        let good = sign(&key, manifest("acme-p", "p", "acme"), bytes);
        assert!(validate_structure(&good, bytes, &abi, HOST_IDENTITY).is_ok());

        let mut bad = good.clone();
        bad.name = "Bad Name".into();
        assert!(validate_structure(&bad, bytes, &abi, HOST_IDENTITY)
            .unwrap_err()
            .contains("not a valid plugin name"));

        let mut bad = good.clone();
        bad.alias = "UP".into();
        assert!(validate_structure(&bad, bytes, &abi, HOST_IDENTITY)
            .unwrap_err()
            .contains("alias"));

        let mut bad = good.clone();
        bad.kind = "widget".into();
        assert!(validate_structure(&bad, bytes, &abi, HOST_IDENTITY)
            .unwrap_err()
            .contains("kind"));

        let mut bad = good.clone();
        bad.version = "latest".into();
        assert!(validate_structure(&bad, bytes, &abi, HOST_IDENTITY)
            .unwrap_err()
            .contains("semver"));

        let mut bad = good.clone();
        bad.publisher = " ".into();
        assert!(validate_structure(&bad, bytes, &abi, HOST_IDENTITY)
            .unwrap_err()
            .contains("publisher"));

        let mut bad = good.clone();
        bad.sha256 = "abc".into();
        assert!(validate_structure(&bad, bytes, &abi, HOST_IDENTITY)
            .unwrap_err()
            .contains("64-char hex"));

        // Integrity: right shape, wrong digest.
        let mut bad = good.clone();
        bad.sha256 = sha256_hex(b"other bytes");
        assert!(validate_structure(&bad, bytes, &abi, HOST_IDENTITY)
            .unwrap_err()
            .contains("integrity"));

        let mut bad = good.clone();
        bad.abi_version = 99;
        assert!(validate_structure(&bad, bytes, &abi, HOST_IDENTITY)
            .unwrap_err()
            .contains("abi_version"));
    }

    /// A manifest with an UNKNOWN field fails to parse at all (deny_unknown_fields): fail-closed
    /// against content this binary does not understand.
    #[test]
    fn unknown_manifest_field_fails_parse() {
        let key = test_key(1);
        let m = sign(&key, manifest("acme-p", "p", "acme"), b"bytes");
        let mut v = serde_json::to_value(&m).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("surprise".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<Manifest>(v).is_err());
    }

    /// Configured floor: a validly-signed-but-old third-party release is rejected once floored, and
    /// a stripped-signature copy cannot be laundered past the floor by a loose posture.
    #[test]
    fn configured_floor_rejects_downgrade_and_is_not_bypassable() {
        let acme = test_key(2);
        let artifact = b"older vulnerable build";
        let mut old = manifest("acme-store-dynamo", "dynamo", "acme");
        old.version = "1.0.0".into();
        let old = sign(&acme, old, artifact);

        // No floor: trusted (baseline).
        let mut pol = policy(None, &[("acme", &acme.verifying_key())], false, false);
        assert!(matches!(
            evaluate(artifact, &old, &pol).unwrap(),
            Verdict::Trusted { .. }
        ));

        // Floor pinned: the old validly-signed release is rejected.
        pol.min_versions
            .insert("acme-store-dynamo".to_string(), "2.0.0".to_string());
        let err = evaluate(artifact, &old, &pol).unwrap_err();
        assert!(err.reason.contains("anti-downgrade"), "got {err:?}");

        // Stripped signature + both opt-ins: STILL rejected (the floor requires trusted proof).
        let mut stripped = old.clone();
        stripped.signature = String::new();
        let mut loose = policy(None, &[], true, true);
        loose
            .min_versions
            .insert("acme-store-dynamo".to_string(), "2.0.0".to_string());
        let err = evaluate(artifact, &stripped, &loose).unwrap_err();
        assert!(err.reason.contains("anti-downgrade"), "got {err:?}");

        // A current signed release at the floor still passes.
        let mut cur = manifest("acme-store-dynamo", "dynamo", "acme");
        cur.version = "2.0.0".into();
        let cur = sign(&acme, cur, artifact);
        assert!(matches!(
            evaluate(artifact, &cur, &pol).unwrap(),
            Verdict::Trusted { .. }
        ));
    }

    /// class-12 D2: a MALFORMED `min_versions` floor (no leading `v`, so it fails [`valid_semver`])
    /// must be UNSATISFIABLE, not silently void. Before the fix, `version_components("v2.0.0")` ==
    /// `[0,0,0]`, so `version_at_least("1.0.0", "v2.0.0")` was `true` and the old artifact evaluated
    /// `Verdict::Trusted` — the exact silent admission F2 describes. RED, load-bearing: revert only
    /// the `version_at_least` hunk and this goes back to `Ok(..)`.
    #[test]
    fn garbage_min_version_floor_is_unsatisfiable_not_void() {
        let acme = test_key(2);
        let artifact = b"older vulnerable build";
        let mut old = manifest("acme-store-dynamo", "dynamo", "acme");
        old.version = "1.0.0".into();
        let old = sign(&acme, old, artifact);

        let mut pol = policy(None, &[("acme", &acme.verifying_key())], false, false);
        pol.min_versions
            .insert("acme-store-dynamo".to_string(), "v2.0.0".to_string());

        let err = evaluate(artifact, &old, &pol).unwrap_err();
        assert_eq!(err.kind, RejectKind::AntiDowngrade);
        assert!(
            err.reason.contains("v2.0.0"),
            "reason must name the malformed floor: {}",
            err.reason
        );
    }

    /// class-12 D2: a malformed `first_party_floors` override must NOT erase the automatic
    /// `binary_version` floor it REPLACES — the sharpest case in F2, because the override makes a
    /// plugin the automatic floor alone would have refused instead get ADMITTED, i.e. strictly LESS
    /// protection than configuring nothing at all. RED: before the fix, the override reads as
    /// `[0,0,0]`, which every version satisfies.
    #[test]
    fn garbage_first_party_floor_does_not_erase_the_binary_floor() {
        let release = test_key(1);
        let artifact = b"old first-party build";
        let mut old = manifest(
            "busbar-store-valkey-plugin",
            "valkey",
            FIRST_PARTY_PUBLISHER,
        );
        old.version = "1.0.0".into(); // below `binary_version` ("1.5.0", set by `policy()`)
        let old = sign(&release, old, artifact);

        let mut pol = policy(Some(&release), &[], false, false);
        pol.first_party_floors.insert(
            "busbar-store-valkey-plugin".to_string(),
            "v9.9.9".to_string(),
        );

        let err = evaluate(artifact, &old, &pol).unwrap_err();
        assert_eq!(err.kind, RejectKind::AntiDowngrade);
    }

    /// class-12 D2: `floor_note`'s operator-facing wording, pinned by a test rather than by review.
    /// LABEL: guard unit test on a NEW helper — it cannot go red against pre-fix source, because the
    /// helper does not exist there. Not a RED proof.
    #[test]
    fn malformed_floor_reason_says_the_floor_is_malformed() {
        assert_eq!(floor_note("1.6.0"), "");
        assert_eq!(floor_note(""), "");
        let note = floor_note("v1.6.0");
        assert!(!note.is_empty());
        assert!(note.contains("MAJOR.MINOR.PATCH"));
    }

    /// The embedded-release-key accessor parses a build-time hex key. In this test build the env is
    /// absent, so it returns None (a dev build has no first-party key).
    #[test]
    fn embedded_key_absent_in_dev_builds() {
        // The build for tests does not set BUSBAR_RELEASE_PUBKEY.
        assert!(embedded_release_pubkey().is_none());
    }

    /// `store`/`secret` default to restart-required; `hook`/`auth` default to hot-appliable
    /// (question #14) — derived from `kind`, never plugin-declared.
    #[test]
    fn kind_restart_default_matches_binding_lifecycle() {
        assert!(kind_restart_default("store"));
        assert!(kind_restart_default("secret"));
        assert!(!kind_restart_default("hook"));
        assert!(!kind_restart_default("auth"));
        // An unrecognized kind fails to the SAFE direction (restart-required), never the
        // hot-appliable one.
        assert!(kind_restart_default("widget"));
    }

    fn trusted_first_party() -> Verdict {
        Verdict::Trusted {
            publisher: FIRST_PARTY_PUBLISHER.to_string(),
            first_party: true,
        }
    }

    fn trusted_third_party() -> Verdict {
        Verdict::Trusted {
            publisher: "acme".to_string(),
            first_party: false,
        }
    }

    fn allowed_unsigned() -> Verdict {
        Verdict::Allowed {
            reason: "dev opt-in".to_string(),
            allow: AllowReason::Unsigned,
        }
    }

    /// The override direction that INCREASES caution (`true` against a `false` kind default) is
    /// ALWAYS honored, regardless of trust — the safe direction to be wrong in.
    #[test]
    fn restart_override_to_true_is_always_honored() {
        for verdict in [
            trusted_first_party(),
            trusted_third_party(),
            allowed_unsigned(),
        ] {
            assert!(effective_restart_required("hook", Some(true), &verdict));
            assert!(effective_restart_required("auth", Some(true), &verdict));
        }
    }

    /// The override direction that DECREASES caution (`false` against a `true` kind default) is
    /// honored ONLY for a trusted, first-party (`publisher == "busbar"`) manifest — the exact same
    /// trust+publisher gate `schema_derived`'s load-bearing rule uses (question #4/#14). A
    /// trusted THIRD-PARTY publisher, or an unsigned/allowed artifact, does NOT clear the gate —
    /// `publisher` alone is never sufficient; only `Verdict::Trusted { first_party: true, .. }` does.
    #[test]
    fn restart_override_to_false_requires_trusted_first_party() {
        assert!(
            !effective_restart_required("store", Some(false), &trusted_first_party()),
            "trusted first-party clears the gate: the false override is honored"
        );
        assert!(
            effective_restart_required("store", Some(false), &trusted_third_party()),
            "trusted THIRD-PARTY does not clear the gate: kind default (true) is enforced"
        );
        assert!(
            effective_restart_required("secret", Some(false), &allowed_unsigned()),
            "an unsigned/allowed artifact does not clear the gate: kind default enforced"
        );
    }

    /// With no per-field override, the kind default applies unconditionally (trust is irrelevant
    /// when there is nothing to override).
    #[test]
    fn restart_no_override_uses_kind_default_regardless_of_trust() {
        assert!(effective_restart_required(
            "store",
            None,
            &allowed_unsigned()
        ));
        assert!(!effective_restart_required(
            "hook",
            None,
            &allowed_unsigned()
        ));
    }

    /// A `false` override against an ALREADY hot-appliable kind default changes nothing observable
    /// (there is no restart-required claim being weakened), so it is honored regardless of trust —
    /// this is not the silent-data-loss direction question #14 guards against.
    #[test]
    fn restart_override_to_false_against_hot_default_is_a_no_op_honored_unconditionally() {
        assert!(!effective_restart_required(
            "hook",
            Some(false),
            &allowed_unsigned()
        ));
    }

    // ── E-008: manifest `host` disambiguates sibling products that share this exact plugin ABI ──

    /// BACKWARD COMPAT: a manifest with no `host` field at all (every manifest packed before this
    /// field existed — real packed tarballs, not just an in-memory struct) still parses AND still
    /// passes structural validation. Deserializes from raw JSON (not `Manifest { .. }` literal
    /// syntax) so this actually proves the wire format, not just that the Rust default exists.
    #[test]
    fn manifest_with_no_host_field_parses_and_loads() {
        let key = test_key(1);
        let artifact = b"pre-existing manifest bytes";
        let json = r#"{
            "name": "busbar-store-valkey-plugin",
            "alias": "valkey",
            "kind": "store",
            "version": "1.5.0",
            "publisher": "acme",
            "abi_version": 1,
            "sha256": "",
            "signature": "",
            "description": "",
            "homepage": "",
            "license": ""
        }"#;
        let m: Manifest = serde_json::from_str(json).expect("manifest with no host field parses");
        assert_eq!(m.host, None, "absent host deserializes to None");
        let m = sign(&key, m, artifact);
        validate_structure(&m, artifact, &abi, HOST_IDENTITY)
            .expect("a manifest with no host field must still pass structural validation");
    }

    /// A manifest that EXPLICITLY declares `host: busbar` (this binary's own identity) loads
    /// exactly like an absent `host` — the field is additive, not merely tolerated when omitted.
    #[test]
    fn manifest_with_host_busbar_loads() {
        let key = test_key(1);
        let artifact = b"same-host bytes";
        let mut m = manifest("busbar-store-valkey-plugin", "valkey", "acme");
        m.host = Some(HOST_IDENTITY.to_string());
        let m = sign(&key, m, artifact);
        validate_structure(&m, artifact, &abi, HOST_IDENTITY)
            .expect("host: busbar matches this binary's own identity and must load");
    }

    /// THE ACTUAL SAFETY PROPERTY: a manifest declaring a DIFFERENT host (e.g. `busbar-ui`, the
    /// sibling product that reuses this identical six-symbol ABI and signed-manifest shape) is
    /// REJECTED at structural validation — not silently ignored. This is what stops a busbar-ui
    /// `store` plugin (tenants/deployments) from `dlopen`ing into the engine and answering `store`
    /// calls with the wrong payload contract (keys/denylists) after passing the ABI handshake.
    /// Runs even on a VALIDLY SIGNED manifest, proving this is a structural (phase 1) gate that
    /// trust cannot override.
    #[test]
    fn manifest_with_foreign_host_is_rejected() {
        let key = test_key(1);
        let artifact = b"foreign-host bytes";
        let mut m = manifest("busbar-ui-store-tenants", "tenants", "acme");
        m.host = Some("busbar-ui".to_string());
        let m = sign(&key, m, artifact);
        let err = validate_structure(&m, artifact, &abi, HOST_IDENTITY).unwrap_err();
        assert!(
            err.contains("busbar-ui") && err.contains("host"),
            "rejection must name both the offending host and the field, got: {err}"
        );

        // Not just structural: even a manifest that WOULD verify as trusted first-party never
        // reaches `evaluate` in the real pipeline, because `registry.rs::examine` runs
        // `validate_structure` (phase 1) before `evaluate` (phase 2, trust) — a foreign host never
        // gets a chance to be laundered through a loose trust posture.
        let pol = policy(Some(&key), &[], true, true);
        assert!(
            validate_structure(&m, artifact, &abi, HOST_IDENTITY).is_err(),
            "the host gate is structural and does not consult TrustPolicy at all"
        );
        let _ = pol; // constructed only to make the "trust cannot help" point explicit above
    }

    /// A `host` value that is neither absent, `busbar`, nor a recognizable other product string
    /// (garbage / typo) is rejected the same way as a deliberately foreign host — there is no
    /// third "unknown, so allow" outcome.
    #[test]
    fn manifest_with_garbage_host_is_rejected() {
        let key = test_key(1);
        let artifact = b"garbage-host bytes";
        let mut m = manifest("acme-p", "p", "acme");
        m.host = Some("Busbar".to_string()); // case mismatch is still not an exact match
        let m = sign(&key, m, artifact);
        assert!(validate_structure(&m, artifact, &abi, HOST_IDENTITY).is_err());
    }

    /// E-010 REGRESSION GUARD: `host_identity` must be the parameter `validate_structure` actually
    /// consults, not a decorative signature widening that still checks against a hardcoded
    /// `HOST_IDENTITY` const internally. Every OTHER test in this file passes `HOST_IDENTITY`
    /// verbatim, so none of them can tell the difference between "the parameter is load-bearing"
    /// and "the parameter is ignored" — a manifest whose `host` is `busbar-ui`, validated by a
    /// caller whose own identity IS `busbar-ui`, must load; the identical manifest validated by a
    /// caller whose identity is `busbar` (this binary's own `HOST_IDENTITY`) must not. If a future
    /// change reverted the body to compare against `HOST_IDENTITY` instead of the parameter, this
    /// test is the one that would catch it — every other host test in this file would still pass.
    #[test]
    fn validate_structure_consults_the_host_identity_parameter_not_a_hardcoded_const() {
        let key = test_key(1);
        let artifact = b"sibling-product bytes";
        let mut m = manifest("busbar-ui-store-tenants", "tenants", "acme");
        m.host = Some("busbar-ui".to_string());
        let m = sign(&key, m, artifact);

        validate_structure(&m, artifact, &abi, "busbar-ui").expect(
            "a busbar-ui-hosted manifest must load when the CALLER's own identity is busbar-ui",
        );

        let err = validate_structure(&m, artifact, &abi, HOST_IDENTITY).unwrap_err();
        assert!(
            err.contains("busbar-ui"),
            "the same manifest validated by a busbar-identity caller must still be rejected, got: {err}"
        );
    }

    /// An ABSENT `host` matches ANY caller's identity (the field is additive/backward-compatible —
    /// see `manifest_with_no_host_field_parses_and_loads`), regardless of which host_identity is
    /// passed. Proves the "absent means match" branch doesn't secretly special-case `HOST_IDENTITY`.
    #[test]
    fn manifest_with_no_host_matches_any_caller_identity() {
        let key = test_key(1);
        let artifact = b"no-host bytes";
        let m = manifest("acme-p", "p", "acme");
        assert_eq!(m.host, None);
        let m = sign(&key, m, artifact);

        validate_structure(&m, artifact, &abi, HOST_IDENTITY)
            .expect("absent host must match this binary's own identity");
        validate_structure(&m, artifact, &abi, "busbar-ui")
            .expect("absent host must ALSO match a sibling product's identity");
        validate_structure(&m, artifact, &abi, "some-third-product")
            .expect("absent host must match ANY caller's identity, not just known ones");
    }
}
