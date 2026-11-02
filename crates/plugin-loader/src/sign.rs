// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use ed25519_dalek::Signature;
pub use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const FIRST_PARTY_PUBLISHER: &str = "busbar";

/// The plugin kinds this binary understands. ONE plugin subsystem: `kind` only selects which kind's
/// table the door answers and which engine subsystem consumes it; discovery/trust/validation are
/// shared. Each kind's manifest `abi_version` is that kind's one version (`supported_abi`, THE DESIGN
/// §11.2). Every kind, `plane` and `transport` included, loads only through its door.
#[rustfmt::skip]
pub const KNOWN_KINDS: &[&str] = &["store", "auth", "hook", "secret", "export", "plane", "transport"];

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
    pub fn unnamed(key: VerifyingKey) -> Self {
        let hex = hex::encode(key.as_bytes());
        FirstPartyKey {
            id: format!("ed25519:{}", &hex[..16]),
            key: ReleaseKey::Ed25519(key),
        }
    }

    #[must_use]
    pub fn retired_reason(&self) -> Option<&'static str> {
        self.key.retired_reason()
    }
}

pub const RELEASE_KEYS_ENV: &str = "BUSBAR_RELEASE_PUBKEY";

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
        if let Some(why) = key.retired_reason() {
            return Err(format!(
                "{RELEASE_KEYS_ENV} entry {n}: root '{}' is retired: {why}",
                key.id
            ));
        }
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

#[must_use]
pub fn embedded_release_keys() -> Vec<FirstPartyKey> {
    option_env!("BUSBAR_RELEASE_PUBKEY")
        .and_then(|spec| parse_release_keys(spec).ok())
        .unwrap_or_default()
}

pub fn embedded_release_pubkey() -> Option<VerifyingKey> {
    embedded_release_keys()
        .into_iter()
        .find_map(|root| match root.key {
            ReleaseKey::Ed25519(key) => Some(key),
            ReleaseKey::P256(_) => None,
        })
}

pub const RETIRED_RELEASE_KEYS: &[(&str, &str)] = &[(
    "b18395a332803151b9cd40a71489a86a96d8bea3ee6a37a45f59dec197bacba7",
    "the busbar 1.5 CI release key, retired 2026-10-28: its private seed was held in a GitHub \
     organisation secret every repository could read, and a copy was found on disk, so its \
     signature no longer proves busbar made the plugin",
)];

fn retired_signer<'a>(
    manifest: &Manifest,
    list: &[(&'a str, &'a str)],
) -> Option<(VerifyingKey, &'a str, &'a str)> {
    let sig: [u8; 64] = hex::decode(manifest.signature.trim())
        .ok()?
        .as_slice()
        .try_into()
        .ok()?;
    let sig = Signature::from_bytes(&sig);
    let canonical = canonical_manifest_bytes(manifest);
    list.iter().find_map(|&(hex_key, why)| {
        let key = public_key_from_hex(hex_key).ok()?;
        key.verify_strict(&canonical, &sig)
            .is_ok()
            .then_some((key, hex_key, why))
    })
}

pub const REVOKED_DIGESTS: &[(&str, &str)] = &[];

#[must_use]
pub fn revoked_digests() -> BTreeMap<String, String> {
    REVOKED_DIGESTS
        .iter()
        .map(|(digest, why)| (digest.to_ascii_lowercase(), (*why).to_owned()))
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
    pub fn config_names(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.alias.as_str()).chain(self.former_names.iter().map(String::as_str))
    }

    pub fn identities(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.name.as_str()).chain(self.config_names())
    }

    pub fn answers_to(&self, word: &str) -> bool {
        self.identities().any(|n| n == word)
    }

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
    /// The plane's BREAKER FACTS: how its members' breaker cells treat a transient
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
    /// The hook facts a `kind: hook` plugin declares
    /// as structured answers; see [`HookDecl`]. Absent, the
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

/// A plane's declared breaker facts (`declares.breaker`): per-plane facts about the
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
    pub const fn as_token(self) -> &'static str {
        match self {
            EgressPolicy::OpenWeb => "open-web",
            EgressPolicy::Collector => "collector",
        }
    }

    pub fn is_default(&self) -> bool {
        *self == EgressPolicy::OpenWeb
    }
}

impl Declares {
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

        if let Some(m) = doc.as_object_mut() {
            m.remove("contract_abi");
        }
        let read: Self =
            serde_json::from_value(doc).map_err(|e| format!("not a `declares` section: {e}"))?;

        if let Some(key) = read.keep.keys().find(|k| !read.destinations.contains(k)) {
            return Err(format!(
                "not a `declares` section: `keep` names `{key}`, which is not a declared destination"
            ));
        }
        Ok(read)
    }

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
    pub fn declares_any(&self) -> bool {
        self.prompt != NeedLevel::No || self.user != NeedLevel::No
    }
}

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
    /// The artifact is a first-party manifest signed by a RETIRED release key
    /// ([`RETIRED_RELEASE_KEYS`]) that the operator names under `plugins.trust.publishers`.
    RetiredKey,
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
    /// Named release roots. When nonempty these replace the compatibility single-key field.
    pub first_party_keys: Vec<FirstPartyKey>,
    /// Permanently revoked library SHA-256 digests, with their operator-facing reason.
    pub revoked: BTreeMap<String, String>,
    /// Highest authenticated keys-document version accepted by this deployment's Store.
    pub release_keys_floor: u64,
    /// The Unix clock used by release verification; None uses the system clock.
    pub release_clock: Option<u64>,
    /// Enforce document expiry for new installs; boot of installed bytes checks the chain,
    /// revocations and rollback without failing merely because time has passed.
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
            first_party_key: embedded_release_pubkey(),
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

pub fn kind_restart_default(kind: &str) -> bool {
    !matches!(kind, "hook" | "auth")
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
            default
                && !matches!(
                    verdict,
                    Verdict::Trusted {
                        first_party: true,
                        ..
                    }
                )
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
    /// An older build of a plugin whose newer build is in the same directory (the registry's
    /// supersede pass): not loaded, the newer build is.
    Superseded,
    /// A first-party manifest signed by a RETIRED release key ([`RETIRED_RELEASE_KEYS`]) the
    /// operator does not name under `plugins.trust.publishers`, whatever `allow_unsigned` says.
    RetiredKey,
    /// An authenticated artifact or signer was revoked; no trust opt-in can admit it.
    Revoked,
}

impl RejectKind {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AntiDowngrade => "anti_downgrade",
            Self::UntrustedFloored => "untrusted_floored",
            Self::Unsigned => "unsigned",
            Self::Tampered => "tampered",
            Self::UnknownPublisher => "unknown_publisher",
            Self::EgressGrant => "egress_grant",
            Self::Superseded => "superseded",
            Self::RetiredKey => "retired_key",
            Self::Revoked => "revoked",
        }
    }
}

pub const FIRST_PARTY_EGRESS: [(u32, &str); 1] = [(
    busbar_contract::abi::host::conn::connector::EGRESS_PROVIDER,
    "provider",
)];

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
    /// Named roots tried when a first-party signature or seal could not be verified.
    pub trusted_keys: Vec<String>,
}

impl Rejected {
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

pub fn sha256_hex(bytes: &[u8]) -> String {
    busbar_contract::redacted::sha256_hex(bytes)
}

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

pub fn sign(key: &SigningKey, mut manifest: Manifest, artifact: &[u8]) -> Manifest {
    manifest.sha256 = sha256_hex(artifact);
    manifest.signature = String::new();
    let sig = key.sign(&canonical_manifest_bytes(&manifest));
    manifest.signature = hex::encode(sig.to_bytes());
    manifest
}

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
    #[must_use]
    pub fn trusted_keys(&self) -> &[String] {
        match self {
            FirstPartyUnverified::Malformed(_) => &[],
            FirstPartyUnverified::NoKey { trusted_keys }
            | FirstPartyUnverified::Release { trusted_keys, .. } => trusted_keys,
        }
    }

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

pub fn first_party_signer_for<'k>(
    manifest: &Manifest,
    bytes: &[u8],
    keys: &'k [FirstPartyKey],
    checks: crate::release_trust::Checks,
    target: &str,
) -> Result<&'k FirstPartyKey, FirstPartyUnverified> {
    first_party_signer_evidence(manifest, bytes, keys, checks, target).map(|(root, _)| root)
}

fn first_party_signer_evidence<'k>(
    manifest: &Manifest,
    bytes: &[u8],
    keys: &'k [FirstPartyKey],
    checks: crate::release_trust::Checks,
    target: &str,
) -> Result<(&'k FirstPartyKey, Option<u64>), FirstPartyUnverified> {
    if let Some(seal) = crate::release_trust::wire::read_seal(&manifest.signature) {
        return first_party_sealed(manifest, bytes, keys, checks, seal, target);
    }
    let sig = bound_signature(manifest, bytes).map_err(FirstPartyUnverified::Malformed)?;
    let canonical = canonical_manifest_bytes(manifest);
    keys.iter()
        .find(|k| k.retired_reason().is_none() && matches!(&k.key, ReleaseKey::Ed25519(key) if key.verify_strict(&canonical, &sig).is_ok()))
        .map(|root| (root, None))
        .ok_or_else(|| FirstPartyUnverified::NoKey {
            trusted_keys: keys.iter().map(|k| k.id.clone()).collect(),
        })
}

fn first_party_sealed<'k>(
    manifest: &Manifest,
    bytes: &[u8],
    keys: &'k [FirstPartyKey],
    checks: crate::release_trust::Checks,
    seal: Result<crate::release_trust::wire::SealBytes, String>,
    target: &str,
) -> Result<(&'k FirstPartyKey, Option<u64>), FirstPartyUnverified> {
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
    Ok((
        keys.iter()
            .find(|k| k.id == verified.root)
            .expect("the vouching root is one of `keys`"),
        Some(verified.keys_version),
    ))
}

fn bound_signature(manifest: &Manifest, bytes: &[u8]) -> Result<Signature, String> {
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

fn signature_ok(manifest: &Manifest, bytes: &[u8], key: &VerifyingKey) -> Result<(), String> {
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

    key.verify_strict(&canonical_manifest_bytes(manifest), &sig)
        .map_err(|_| "signature does not verify".to_string())
}

fn version_components(v: &str) -> Option<[&str; 3]> {
    if !valid_semver(v) {
        return None;
    }
    let core = v.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let mut component = || {
        let digits = parts.next()?.trim_start_matches('0');
        Some(if digits.is_empty() { "0" } else { digits })
    };
    Some([component()?, component()?, component()?])
}

pub fn version_at_least(have: &str, floor: &str) -> bool {
    if floor.is_empty() {
        return true;
    }
    let (Some(have), Some(floor)) = (version_components(have), version_components(floor)) else {
        return false;
    };
    for (have, floor) in have.into_iter().zip(floor) {
        match have.len().cmp(&floor.len()).then_with(|| have.cmp(floor)) {
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Equal => {}
        }
    }
    true
}

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

pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn valid_semver(v: &str) -> bool {
    busbar_contract::plugin::valid_semver(v)
}

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

    m.stated()?;

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

pub fn validate_abi(
    m: &Manifest,
    supported_abi: &dyn Fn(&str) -> &'static [u32],
) -> Result<(), String> {
    let supported = supported_abi(&m.kind);
    match (supported.first(), supported.last()) {
        (Some(&floor), Some(&max)) if m.abi_version >= floor && m.abi_version <= max => {}
        (Some(&floor), Some(&max)) => {
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

fn hard_seal_refusal(refusal: &crate::release_trust::SealRefusal) -> Option<RejectKind> {
    use crate::release_trust::SealRefusal as S;
    match refusal {
        S::DigestRevoked { .. } | S::SignerRevoked { .. } => Some(RejectKind::Revoked),
        S::RetiredRoot { .. } | S::RetiredSigner { .. } => Some(RejectKind::RetiredKey),
        S::KeysRollback { .. } => Some(RejectKind::AntiDowngrade),
        _ => None,
    }
}

enum Untrusted {
    Unsigned {
        reason: String,
        tampered: bool,
    },

    ThirdParty {
        publisher: String,
    },

    Retired {
        key: String,
        why: String,
        trusted_as: Option<String>,
    },
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
    evaluate_with_evidence(bytes, manifest, policy).map(|(verdict, _)| verdict)
}

pub fn evaluate_with_evidence(
    bytes: &[u8],
    manifest: &Manifest,
    policy: &TrustPolicy,
) -> Result<(Verdict, Option<u64>), Rejected> {
    evaluate_against_with_evidence(bytes, manifest, policy, RETIRED_RELEASE_KEYS)
}

#[cfg(test)]
fn evaluate_against(
    bytes: &[u8],
    manifest: &Manifest,
    policy: &TrustPolicy,
    retired: &[(&str, &str)],
) -> Result<Verdict, Rejected> {
    evaluate_against_with_evidence(bytes, manifest, policy, retired).map(|(verdict, _)| verdict)
}

fn evaluate_against_with_evidence(
    bytes: &[u8],
    manifest: &Manifest,
    policy: &TrustPolicy,
    retired: &[(&str, &str)],
) -> Result<(Verdict, Option<u64>), Rejected> {
    let digest = sha256_hex(bytes);
    if let Some(why) = policy.revoked.get(&digest) {
        return Err(Rejected::new(RejectKind::Revoked,
            format!("plugin '{}' version {} (library sha256 {digest}) is REVOKED: {why}; no trust opt-in admits it", manifest.name, manifest.version)));
    }
    let roots = if policy.first_party_keys.is_empty() {
        std::borrow::Cow::Owned(
            policy
                .first_party_key
                .map(FirstPartyKey::unnamed)
                .into_iter()
                .collect::<Vec<_>>(),
        )
    } else {
        std::borrow::Cow::Borrowed(policy.first_party_keys.as_slice())
    };
    let checks = crate::release_trust::Checks {
        now: policy
            .release_clock
            .unwrap_or_else(crate::release_trust::now),
        keys_floor: policy.release_keys_floor,
        enforce_expiry: policy.release_enforce_expiry,
    };
    let stale = if policy.release_enforce_expiry {
        match crate::release_trust::wire::read_seal(&manifest.signature) {
            Some(Ok((keys, targets))) => crate::release_trust::check_fresh(
                crate::release_trust::Seal {
                    keys: &keys,
                    targets: &targets,
                },
                checks.now,
            )
            .err(),
            _ => None,
        }
    } else {
        None
    };
    if stale.is_some() && manifest.publisher == FIRST_PARTY_PUBLISHER && !roots.is_empty() {
        let boot_checks = crate::release_trust::Checks {
            enforce_expiry: false,
            ..checks
        };
        if let Err(FirstPartyUnverified::Release {
            refusal,
            trusted_keys,
        }) = first_party_signer_evidence(
            manifest,
            bytes,
            &roots,
            boot_checks,
            crate::release_trust::PLUGIN_TARGET,
        ) {
            if let Some(kind) = hard_seal_refusal(&refusal) {
                return Err(Rejected { trusted_keys, ..Rejected::new(kind,
                    format!("plugin '{}' version {}: first-party release seal refused ({}): {refusal}. No plugins.trust opt-in admits it.", manifest.name, manifest.version, refusal.code())) });
            }
        }
    }
    let mut authenticated_keys_version = None;
    let mut trusted_keys = Vec::new();

    let by_retired = (manifest.publisher == FIRST_PARTY_PUBLISHER)
        .then(|| retired_signer(manifest, retired))
        .flatten();
    let trusted_or_untrusted: Result<bool, Untrusted> = if let Some(refusal) = stale {
        trusted_keys = roots.iter().map(|root| root.id.clone()).collect();
        Err(Untrusted::Unsigned {
            reason: format!(
                "first-party signature failed: release seal refused ({}): {refusal}",
                refusal.code()
            ),
            tampered: true,
        })
    } else if manifest.signature.trim().is_empty() {
        Err(Untrusted::Unsigned {
            reason: "manifest carries no signature".to_string(),
            tampered: false,
        })
    } else if let Some((key, hex_key, why)) = by_retired {
        match policy.publishers.iter().find(|(_, k)| **k == key) {
            None => Err(Untrusted::Retired {
                key: hex_key.to_string(),
                why: why.to_string(),
                trusted_as: None,
            }),
            Some((name, _)) => match signature_ok(manifest, bytes, &key) {
                Ok(()) => Err(Untrusted::Retired {
                    key: hex_key.to_string(),
                    why: why.to_string(),
                    trusted_as: Some(name.clone()),
                }),
                Err(reason) => Err(Untrusted::Unsigned {
                    reason: format!(
                        "first-party signature by the retired release key {hex_key} failed: \
                         {reason}"
                    ),
                    tampered: true,
                }),
            },
        }
    } else if manifest.publisher == FIRST_PARTY_PUBLISHER {
        if roots.is_empty() {
            Err(Untrusted::Unsigned {
                reason: format!("manifest claims first-party publisher '{FIRST_PARTY_PUBLISHER}' but this build embeds no busbar release key, so it cannot be verified"),
                tampered: false,
            })
        } else {
            match first_party_signer_evidence(
                manifest,
                bytes,
                &roots,
                checks,
                crate::release_trust::PLUGIN_TARGET,
            ) {
                Ok((_, version)) => {
                    authenticated_keys_version = version;
                    Ok(true)
                }
                Err(FirstPartyUnverified::Release {
                    refusal,
                    trusted_keys,
                }) if hard_seal_refusal(&refusal).is_some() => {
                    return Err(Rejected { trusted_keys, ..Rejected::new(hard_seal_refusal(&refusal).expect("matched"),
                        format!("plugin '{}' version {}: first-party release seal refused ({}): {refusal}. No plugins.trust opt-in admits it.", manifest.name, manifest.version, refusal.code())) });
                }
                Err(unverified) => {
                    trusted_keys = unverified.trusted_keys().to_vec();
                    Err(Untrusted::Unsigned {
                        reason: format!("first-party signature failed: {unverified}"),
                        tampered: true,
                    })
                }
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
                }),
            },
        }
    };

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

    let verdict = match trusted_or_untrusted {
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

        Err(Untrusted::Retired {
            key,
            why,
            trusted_as: Some(name),
        }) => Ok(Verdict::Allowed {
            reason: format!(
                "first-party manifest signed by the RETIRED busbar release key {key} ({why}); \
                 loaded only because plugins.trust.publishers['{name}'] names that key. Replace \
                 the plugin with a release signed by a current key, then remove the entry."
            ),
            allow: AllowReason::RetiredKey,
        }),
        Err(Untrusted::Retired {
            key,
            why,
            trusted_as: None,
        }) => {
            let unsigned_note = if policy.allow_unsigned {
                " plugins.trust.allow_unsigned does not admit a retired key: a retired key is a \
                 revocation, not a missing signature."
            } else {
                ""
            };
            Err(Rejected::new(
                RejectKind::RetiredKey,
                format!(
                    "first-party manifest signed by the RETIRED busbar release key {key} ({why}); \
                     refusing to load it.{unsigned_note} Install the plugin's release signed by a \
                     current busbar key. To keep running this exact plugin, trust the retired \
                     key explicitly: add it under plugins.trust.publishers (any name but \
                     '{FIRST_PARTY_PUBLISHER}', public_key: {key})."
                ),
            ))
        }
    };
    verdict.map(|verdict| {
        let version = matches!(
            verdict,
            Verdict::Trusted {
                first_party: true,
                ..
            }
        )
        .then_some(authenticated_keys_version)
        .flatten();
        (verdict, version)
    })
}

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/sign_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/declares_reader_tests.rs"]
mod declares_reader_tests;

#[cfg(test)]
#[path = "tests/release_seal_tests.rs"]
mod release_seal_tests;
