// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `agents:` SECTION — the A2A plane's config grammar, and the one place its values are judged.
//!
//! ## The section IS the plane
//!
//! There is no `plane:`, `bind:` or `target:` selector anywhere in here. `pools:`, `tools:` and
//! `agents:` are SIBLINGS with the same shape, and which plane an entry is on is decided by which
//! map it is written in. Hooks attach BY BARE NAME from the one top-level `hooks:` map, exactly as
//! they do on the pool plane.
//!
//! ## Two words are reserved on every plane, including the ones that do not use them
//!
//! `hooks` and `upstream_credentials` are reserved at the section level here for the same reason
//! they are on `pools:` — so the word space is IDENTICAL across planes. An operator who learns the
//! rule once should not discover that a name legal on one plane is a section knob on another. There
//! is ONE declaration of the pair ([`busbar_substrate::plane::config::RESERVED_SECTION_KEYS`]) and one reader
//! of it, so that cannot drift. The reserved set is closed; a new A2A knob lands under a per-entry
//! key, never as a new section word.
//!
//! ## The pin is an OBJECT, and that is the whole trust story compressed into one field
//!
//! A2A's authenticity root is a JWS issuer key PLUS a card fingerprint, and where a card carries no
//! signature it degrades to a transport binding. That is four mechanisms carrying different
//! material, and a scalar `spki_pin:` can spell exactly one of them. So `pin:` is
//! `{mechanism, key?, fingerprint?}` and the mechanism is checked against the material it requires,
//! here, at parse. A registration cannot claim `jws_issuer_key` and carry nothing to verify with.
//!
//! `unpinned` is accepted and named out loud rather than being spelled as an absent field, because
//! an operator reading a list of registrations needs to SEE which entries have no root. It is legal
//! to write and impossible to approve: the cap lives in [`super::pin::approve_registration`], which
//! is where the ruling belongs, and this file only refuses to let it carry key material it would
//! never use.
//!
//! ## The pin is the peer's identity; `client_identity:` is busbar's
//!
//! [`ClientIdentityCfg`] is a SIBLING of `pin:`, not a field inside it, because the two describe
//! opposite ends of the same handshake and only one of them is a trust root. Its `cert:` and `key:`
//! are ordinary [`busbar_api::SecretRef`]s — the same spelling `tls.cert:` uses for busbar's
//! INBOUND identity — so key material is referenced and never written here, and it resolves through
//! the one resolver every other secret in the config goes through.
//!
//! ## Cross-plane reference is refused, not ignored
//!
//! An `agents:` entry may name hooks. It may not name a pool, a tool, or another agent. The
//! validator says so rather than silently dropping the reference, because a dropped reference is an
//! operator believing a control is attached that is not.

// PARTLY UNMOUNTED. Everything here is driven by boot and by the admin write path except
// [`AgentPinCfg::declaration`], the projection [`busbar_substrate::trust::declared`] reads this plane's pin
// through. The `connect`/`approve` verbs it was waiting for are now mounted
// (`super::verbs`), and they deliberately do NOT consult it: an approval locks the pin that was
// OBSERVED and verified against the operator's out-of-band root, and the operator attests to it by
// echoing the fingerprint back. Handing `Approval::approve` a declared pin as the override would
// lock a value nobody's fetch confirmed. So this stays a reader with no caller until a surface that
// genuinely wants the declared value — a config-vs-observed diff — exists to want it.
#![cfg_attr(not(test), allow(dead_code))]

use serde::{Deserialize, Serialize};

/// The default MAX VERIFICATION STALENESS for a registration that names none: five seconds.
///
/// The same `5s` as the sibling plane's `crate::mcp::config::DEFAULT_MCP_VERIFY_TTL`, because the
/// two are one decision about one risk — how long a signed card may have drifted before the DELEGATION
/// that submits to it re-verifies. Under verify-on-call this is a bound on reuse on the request path,
/// not a background cadence: the intrinsic verify→submit race is already ms–s, so sub-second precision
/// buys nothing, and single-flight holds the card fetch to at most one per `reverify_ttl` per agent.
/// `reverify_ttl: 0` is strict-live; a larger value is an explicit, docs-flagged security downgrade.
/// (The A2A key keeps its name `reverify_ttl`; the MCP sibling's is `verify_ttl` — the admin API
/// projects both under one `reverify_ttl` view field, so the concept is one across the two planes.)
pub(crate) const DEFAULT_REVERIFY_TTL: &str = "5s";

/// THE DEPLOYMENT-WIDE RECOVERY BACKOFF a registration gets when it spells no `recovery_backoff:`.
///
/// The RECOVERY half of the cadence, and the only half that has a default at all — there is
/// deliberately no deployment-wide knob for detection or demotion, because both would be a window an
/// upstream could open for itself by flapping. Fifteen minutes is long enough that an alternating
/// upstream collapses into one persistent quarantine rather than a demotion storm, and short enough
/// that a genuine recovery is believed within one operator's attention span.
///
/// Non-zero on purpose: zero is a legitimate PER-AGENT setting for an upstream an operator knows to
/// be flaky for boring reasons, but the boring explanation and the hostile one look identical from
/// here, so it is not what an unconfigured deployment gets.
pub(crate) const DEFAULT_RECOVERY_BACKOFF_MS: u64 = 15 * 60 * 1_000;

/// THE REFUSAL FOR `upstream_credentials: passthrough` ON THIS PLANE, written once so the per-entry
/// and section-level paths cannot say different things about the same rule.
///
/// `passthrough` means "forward the CALLER's credential upstream". On the delegation plane that
/// would hand a third-party vendor a working busbar credential belonging to somebody else — the
/// caller's key authenticated them TO busbar and authorised them against busbar's scopes, and it
/// means nothing anywhere else. The WORD stays reserved on every plane so the vocabulary is learned
/// once; the VALUE is refused loudly, because accepting it and quietly doing something else is how
/// an operator ends up believing a credential is being forwarded when it is not, or the reverse.
pub(crate) const REFUSE_PASSTHROUGH_SECTION: &str =
    "`upstream_credentials: passthrough` is refused on the `agents:` plane. busbar delegates AS \
     ITSELF: the caller's key authenticated them to busbar and means nothing to a third-party \
     agent, so forwarding it would hand that agent a working busbar credential belonging to \
     someone else. Use `own` with an `upstream_credential:` handle.";

/// `agents.<name>.pin.mechanism` — WHICH authenticity root this registration has.
///
/// The variants are the four the design names, and they are spelled in config exactly as
/// [`super::pin::CardPin::mechanism`] renders them, so an operator comparing a config file against
/// an admin response or an audit row is comparing the same strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PinMechanism {
    /// The card is SIGNED and verified against an operator-supplied, out-of-band JWS issuer key.
    JwsIssuerKey,
    /// The card is UNSIGNED; authenticity is bound to the card endpoint's certificate SPKI hash.
    CertSpki,
    /// The card is UNSIGNED and served behind mutual TLS; pinned on the peer certificate SPKI hash.
    Mtls,
    /// NO authenticity root. Registrable, never approvable.
    Unpinned,
}

impl PinMechanism {
    /// Is this mechanism an authenticity ROOT at all — and therefore, does it require
    /// operator-supplied key material?
    ///
    /// This is the predicate that makes the object form worth having: three of the four mechanisms
    /// are meaningless without material, and the fourth is meaningless WITH it.
    ///
    /// ONE predicate answers both questions on purpose. It is the boot-time rule below AND the one
    /// question [`busbar_substrate::trust::declared`] asks of a mechanism, so the reader that builds the
    /// artifact and the refusal that fires at boot cannot come to disagree about what "rooted"
    /// means.
    pub(crate) fn is_a_root(self) -> bool {
        !matches!(self, PinMechanism::Unpinned)
    }

    /// The config token, for diagnostics. Deliberately the same string `serde` accepts.
    fn token(self) -> &'static str {
        match self {
            PinMechanism::JwsIssuerKey => "jws_issuer_key",
            PinMechanism::CertSpki => "cert_spki",
            PinMechanism::Mtls => "mtls",
            PinMechanism::Unpinned => "unpinned",
        }
    }
}

/// `agents.<name>.client_identity` — THE CERTIFICATE BUSBAR PRESENTS to this agent's endpoint.
///
/// ## Why this is a sibling of `pin:` and not a field inside it
///
/// `pin:` answers "how do I know this card is the vendor's". This answers "how does the vendor know
/// this connection is busbar's". They are opposite directions of the same handshake and only one of
/// them is a trust root, so folding busbar's own key material into the object whose documented job
/// is "the operator-supplied trust root" would make `pin:` mean two things.
///
/// ## The two fields are SECRET REFERENCES, exactly as `tls:` spells them
///
/// `cert:` and `key:` are [`busbar_api::SecretRef`]s — `{module, settings}` with the `env` / `file`
/// sugar — which is the CLEAN-CONFIG rule the whole config surface already obeys and the same
/// spelling `tls.cert:` / `tls.key:` use for busbar's INBOUND identity. There is deliberately no way
/// to write PEM bytes here: a private key inlined in config is a private key in every config dump,
/// every `--validate` output, every admin GET and every version-history row. Reusing `SecretRef`
/// rather than inventing a path field also means this material resolves through the ONE resolver
/// (`env`/`file` built in, any `kind: secret` plugin beyond that), so a deployment that keeps its
/// keys in Vault keeps this one there too without busbar learning a second way to fetch a key.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientIdentityCfg {
    /// PEM certificate chain busbar presents, leaf first. Public material, still a reference:
    /// operators keep a chain and its key in the same place, and splitting the spelling would be an
    /// invitation to inline the other one.
    pub(crate) cert: busbar_api::SecretRef,
    /// PEM private key for `cert:` — PKCS#8, PKCS#1 or SEC1. NEVER the key itself.
    pub(crate) key: busbar_api::SecretRef,
}

/// `agents.<name>.pin` — the out-of-band operator-supplied trust root.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentPinCfg {
    /// Which root this is. Required: a pin whose mechanism is inferred is a pin whose meaning
    /// changes when the code that infers it changes.
    pub(crate) mechanism: PinMechanism,
    /// The operator-supplied material: a JWS verification key, or a certificate SPKI hash. Absent
    /// only for `unpinned`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) key: Option<String>,
    /// The approved canonical card fingerprint, where the operator already has one. Absent means
    /// "capture it at `connect` and let me approve it", which is the normal first registration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) fingerprint: Option<String>,
}

/// One entry in the top-level `agents:` NAMED-DEFINITION map — one registered external A2A agent.
///
/// Operator INTENT only. Everything that ACCUMULATES about an agent — every observed card, the
/// drift queue, the approval trail, the anomaly counters, the task rows — is store state and is
/// deliberately absent from this struct. The split is not tidiness: intent is what an operator
/// wrote and may edit, accumulation is what happened and may not be, and a field that lives in the
/// wrong one is a field an admin write can silently rewrite history through.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)] // a typo'd key must fail boot, not silently un-pin an agent.
pub(crate) struct AgentDefCfg {
    /// The real remote A2A endpoint. Never client-visible: callers reach it through busbar.
    pub(crate) url: String,
    /// The out-of-band trust root. REQUIRED, and required to be spelled even when it is
    /// `unpinned` — see the module note on why absence is not an acceptable spelling for "none".
    pub(crate) pin: AgentPinCfg,
    /// THE CLIENT CERTIFICATE BUSBAR PRESENTS ON THE HOP TO THIS AGENT. Required when
    /// `pin.mechanism: mtls` — that mechanism means "this endpoint is served behind mutual TLS", and
    /// a registration that says so with nothing to present cannot complete a handshake. Legal, and
    /// optional, under the other mechanisms: a vendor may demand a client certificate whatever it
    /// does about signing its card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) client_identity: Option<ClientIdentityCfg>,
    /// `<n><s|m|h|d>` — the LONGEST a verification may be reused on the delegation path before the
    /// card is re-fetched and re-verified. Absent ⇒ [`DEFAULT_REVERIFY_TTL`] (`5s`); `0` is strict-live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) reverify_ttl: Option<String>,
    /// How long after a DRIFT a clean answer is disbelieved. Absent ⇒ the deployment default.
    ///
    /// This is the recovery backoff, and it is the only half of the cadence that is ever held.
    /// There is deliberately no knob that slows DETECTION or delays a DEMOTION: both would be a
    /// window an upstream could open for itself by flapping, and choosing when to flap is entirely
    /// within its gift.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) recovery_backoff: Option<String>,
    /// The A2A protocol version this registration is PINNED to. Absent ⇒ the release default.
    /// Pinned per registration because the well-known card path moved between versions and a
    /// registration that follows whatever the upstream now claims has no pin at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) protocol_version: Option<String>,
    /// MAY THIS AGENT LIVE ON A PRIVATE OR LOOPBACK ADDRESS, AND BE REACHED OVER PLAINTEXT.
    ///
    /// The SAME spelling, the same semantics and the same fail-closed default as
    /// `crate::mcp::config::McpServerDefCfg::allow_private`, deliberately, because the two are one
    /// operator concept and an operator who has learned it on `tools:` must not have to learn it
    /// again here. What it permits, exactly as on the sibling plane:
    ///
    /// - a plaintext `http://` card endpoint, and
    /// - a host that resolves to a loopback, link-local, RFC1918 or CGNAT address.
    ///
    /// WHAT IT NEVER PERMITS, and this is the half that makes the knob safe to have: a
    /// CLOUD-METADATA endpoint. `169.254.169.254` and its family are refused whether this is set or
    /// not — see [`busbar_substrate::net_guard::ip_is_cloud_metadata`], whose own doc gives the reason: an
    /// `allow_private` that reached IMDS would be a configuration flag that hands out cloud
    /// credentials.
    ///
    /// Default FALSE. A hermetic rig, a laptop and a sidecar are real deployments, and every one of
    /// them is also what an SSRF looks like from inside the process — so it is the operator saying
    /// it out loud, per registration, or it does not happen.
    #[serde(default)]
    pub(crate) allow_private: bool,
    /// Outbound credential mode at delegation time. Same vocabulary as the pool plane's — and
    /// `passthrough` is REFUSED here, loudly, by [`validate_agent`]. The word is reserved on every
    /// plane so the vocabulary is learned once; a plane that cannot honor a VALUE says so rather
    /// than accepting it and doing something else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) upstream_credentials: Option<busbar_api::UpstreamCreds>,
    /// The LEASED outbound credential busbar presents to this agent: a secret-store handle
    /// plus its lease policy. Never the secret, never the caller's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) upstream_credential: Option<super::creds::OutboundCredential>,
    /// WHICH FRONTED AGENTS MAY DELEGATE HERE. Egress policy, over the same `ScopeRef` kind as
    /// inbound authZ. Absent or empty ⇒ NONE may: the fail-closed floor, because reading an empty
    /// list as "everyone" is a registration granting egress nobody wrote down.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) egress_scopes: Vec<String>,
    /// Hooks attached to THIS agent, by bare name from the top-level `hooks:` map. ADDS to the
    /// section-level `agents.hooks:` list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) hooks: Vec<String>,
}

/// The top-level `agents:` map, carrying the two [`busbar_substrate::plane::config::RESERVED_SECTION_KEYS`]
/// alongside the agents.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct AgentsCfg {
    /// The ALL-AGENTS attach list (the reserved `agents.hooks:` key). LIST ⇒ ADDITIVE: an agent's
    /// own `hooks:` are appended to this, deduped by name.
    pub(crate) all_agent_hooks: Vec<String>,
    /// The ALL-AGENTS `upstream_credentials:` default. SCALAR ⇒ OVERRIDE.
    pub(crate) all_agent_upstream_credentials: Option<busbar_api::UpstreamCreds>,
    /// The registrations. Insertion-ordered, so catalogue construction and every operator-facing
    /// listing are deterministic rather than hash-ordered.
    pub(crate) agents: indexmap::IndexMap<String, AgentDefCfg>,
}

impl<'de> Deserialize<'de> for AgentsCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // THE SECTION SPLIT is `plane::config`'s — the reserved-key refusals, the two typed lifts
        // and the order they happen in are a property of a plane SECTION, not of this plane. What
        // stays here is what is genuinely this plane's: `validate_agent`, run through the same
        // function the admin write path calls so the API rejects exactly what the file rejects, and
        // the passthrough refusal below.
        let section = crate::plane::config::split_section::<D, AgentDefCfg>(
            deserializer,
            "a2a",
            validate_agent,
        )?;

        // THE SECTION DEFAULT IS REFUSED HERE and not in the shared split, because it is a rule
        // about this plane's VALUES: `passthrough` is meaningless to an agent busbar fronts. It is
        // checked at the section level as well as per entry because a section default applies to
        // agents that never spell the key — precisely the set an entry-level check cannot see.
        if section.upstream_credentials == Some(busbar_api::UpstreamCreds::Passthrough) {
            return Err(serde::de::Error::custom(REFUSE_PASSTHROUGH_SECTION));
        }

        Ok(AgentsCfg {
            all_agent_hooks: section.hooks,
            all_agent_upstream_credentials: section.upstream_credentials,
            agents: section.entries,
        })
    }
}

impl busbar_substrate::plane::config::PlaneCfg for AgentsCfg {
    /// The A2A plane's secret references: each agent's LEASED outbound delegation credential
    /// (`agents.<name>.upstream_credential.secret`) and both halves of its outbound client identity
    /// (`agents.<name>.client_identity.cert` / `.key`). Moved here VERBATIM from the core
    /// `config_validate::secret_refs` walk so the exhaustive destructure that forces a
    /// secret/not-secret decision on every new field lives beside the fields it guards.
    fn secret_refs(&self) -> Vec<(String, &busbar_api::SecretRef)> {
        // EXHAUSTIVE, no `..`, at both levels: adding a field to `AgentsCfg`, `AgentDefCfg`,
        // `OutboundCredential` or `ClientIdentityCfg` fails to build with `E0027 pattern does not
        // mention field` until somebody decides, here, whether it carries a secret. That force used to
        // live in `config_validate::secret_refs`; it moved with the sweep.
        let mut refs: Vec<(String, &busbar_api::SecretRef)> = Vec::new();
        let AgentsCfg {
            // The all-agents attach list and credential MODE carry no reference: a hook name is a bare
            // name into the top-level `hooks:` map, and the mode is a `Copy` selector.
            all_agent_hooks: _,
            all_agent_upstream_credentials: _,
            agents,
        } = self;
        for (name, def) in agents {
            let AgentDefCfg {
                upstream_credential,
                client_identity,
                // An endpoint URL, an out-of-band VERIFICATION pin, two cadence strings, a pinned
                // protocol version, a private-address opt-in, a `Copy` credential-mode selector, egress
                // scope names and bare hook names. None of them is a credential, and `pin.key` is the one that most looks like
                // one: it is the public half of the operator's trust root, and an operator who cannot
                // publish it has the wrong value in the field.
                url: _,
                pin: _,
                reverify_ttl: _,
                recovery_backoff: _,
                protocol_version: _,
                allow_private: _,
                upstream_credentials: _,
                egress_scopes: _,
                hooks: _,
            } = def;
            if let Some(cred) = upstream_credential {
                let super::creds::OutboundCredential {
                    secret,
                    // Where the resolved value is placed on the wire, and how long the lease lasts.
                    // Neither is material.
                    placement: _,
                    lease_ttl_ms: _,
                } = cred;
                refs.push((format!("agents.{name}.upstream_credential.secret"), secret));
            }
            // THE OUTBOUND CLIENT IDENTITY. Both halves are references and both are walked: an
            // unresolvable `cert:` fails the handshake exactly as an unresolvable `key:` does, and
            // `--validate` that checked only the secret half would report a config that cannot connect
            // as valid.
            if let Some(identity) = client_identity {
                let ClientIdentityCfg { cert, key } = identity;
                refs.push((format!("agents.{name}.client_identity.cert"), cert));
                refs.push((format!("agents.{name}.client_identity.key"), key));
            }
        }
        refs
    }

    fn contains_def(&self, name: &str) -> bool {
        self.agents.contains_key(name)
    }

    fn def_names(&self) -> Vec<&str> {
        self.agents.keys().map(|s| s.as_str()).collect()
    }

    fn entry_document(&self, name: &str) -> Option<serde_json::Value> {
        self.agents
            .get(name)
            .and_then(|cfg| serde_json::to_value(cfg).ok())
    }

    fn insert_def(&mut self, name: &str, def: &serde_json::Value) -> Result<(), String> {
        // THE SAME typed parse the file runs, through the SAME error wording. The value rules already
        // ran through the plane's `config_validate` seam at the write path's `parse_def`; this parse
        // is the fail-closed backstop and cannot fail on a definition that reached install.
        let cfg: AgentDefCfg = serde_json::from_value(def.clone())
            .map_err(|e| format!("invalid `agents.{name}` definition: {e}"))?;
        self.agents.insert(name.to_string(), cfg);
        Ok(())
    }

    fn container_gates(&self) -> busbar_substrate::plane::config::ContainerGateInputs {
        busbar_substrate::plane::config::ContainerGateInputs {
            section_hooks: self.all_agent_hooks.clone(),
            containers: self
                .agents
                .iter()
                .map(|(name, def)| (name.clone(), def.hooks.clone()))
                .collect(),
        }
    }

    fn validate_registry(&self) -> Result<(), String> {
        // The A2A plane has no cross-registration section rule (the MCP published-name uniqueness is
        // the one plane that does); every A2A registry rule is per-entry, run at parse.
        Ok(())
    }

    fn is_present(&self) -> bool {
        !self.agents.is_empty()
            || !self.all_agent_hooks.is_empty()
            || self.all_agent_upstream_credentials.is_some()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn clone_box(&self) -> Box<dyn busbar_substrate::plane::config::PlaneCfg> {
        Box::new(self.clone())
    }

    fn clone_arc_any(&self) -> std::sync::Arc<dyn std::any::Any + Send + Sync> {
        std::sync::Arc::new(self.clone())
    }
}

/// THE VALUE-LEVEL RULES for one `agents:` entry.
///
/// Split out as a free function on purpose: `serde` types check SHAPE, and every rule below is
/// about a VALUE that is well-typed and still wrong. Boot calls it from the `Deserialize` above and
/// the admin write path calls it from
/// [`crate::config::named_map::NamedMapSection::parse_def`], so the two paths cannot drift into
/// different grammars — which is the exact defect that let the API persist a definition the file
/// would have refused, and then drop it at the next rebuild with a log line.
pub(crate) fn validate_agent(name: &str, def: &AgentDefCfg) -> Result<(), String> {
    let at = format!("`agents.{name}`");

    if def.url.trim().is_empty() {
        return Err(format!("{at}: `url:` must name the agent's A2A endpoint"));
    }
    // Scheme is checked here rather than at fetch time so the failure lands on the operator who
    // wrote it, at boot, rather than on a delegation six hours later.
    let scheme_ok = def.url.starts_with("https://") || def.url.starts_with("http://");
    if !scheme_ok {
        return Err(format!(
            "{at}: `url:` must be an http:// or https:// endpoint, got `{}`",
            def.url
        ));
    }

    // THE PIN, matched against the material its mechanism needs. This is the rule the object form
    // exists to make expressible.
    let has_key = def.pin.key.as_deref().is_some_and(|k| !k.trim().is_empty());
    if def.pin.mechanism.is_a_root() && !has_key {
        return Err(format!(
            "{at}: `pin.mechanism: {}` needs `pin.key:` — the out-of-band material this \
             registration is verified against. A pin with nothing to verify with is not a pin.",
            def.pin.mechanism.token()
        ));
    }
    if !def.pin.mechanism.is_a_root() && has_key {
        return Err(format!(
            "{at}: `pin.mechanism: unpinned` must not carry `pin.key:`. `unpinned` means there is \
             no authenticity root; key material that is never verified against reads to an \
             operator as protection that does not exist. Name the real mechanism, or drop the key."
        ));
    }

    // THE CLIENT IDENTITY, matched against the mechanism and the scheme the same way the pin is
    // matched against its material. `mtls` is defined as "served behind mutual TLS"; a registration
    // that claims it and names no certificate cannot get past the peer's `CertificateRequired`
    // alert, and it would fail six hours later on a re-verification tick rather than here.
    if def.pin.mechanism == PinMechanism::Mtls && def.client_identity.is_none() {
        return Err(format!(
            "{at}: `pin.mechanism: mtls` needs `client_identity:` — the `cert:` and `key:` \
             references to the certificate busbar PRESENTS to this endpoint. `mtls` means the \
             endpoint is served behind mutual TLS, and a client with nothing to present is refused \
             at the handshake with `CertificateRequired`, not at the pin."
        ));
    }
    // A client certificate is a TLS-handshake object. Over `http://` there is no handshake to put it
    // in, so an operator who wrote one there is being protected by nothing while reading the config
    // as though they were — the same failure the `unpinned`-with-a-key rule above refuses.
    if def.client_identity.is_some() && def.url.starts_with("http://") {
        return Err(format!(
            "{at}: `client_identity:` is a TLS client certificate and `url:` is `http://`, which \
             has no handshake to present it in. Name an `https://` endpoint, or drop the identity."
        ));
    }

    // THE CALLER'S CREDENTIAL NEVER LEAVES BUSBAR. `passthrough` means "forward the CALLER's
    // credential upstream", and a busbar key handed to a third-party vendor is a working busbar
    // credential belonging to somebody else. Refused at parse, on this plane only, because the
    // word is reserved on every plane and only the VALUE is inapplicable here.
    if def.upstream_credentials == Some(busbar_api::UpstreamCreds::Passthrough) {
        return Err(format!("{at}: {REFUSE_PASSTHROUGH_SECTION}"));
    }
    if let Some(cred) = def.upstream_credential.as_ref() {
        // A lease that has expired before it is used is a credential that can never be presented,
        // so a zero TTL is an operator getting something other than what they wrote.
        if cred.lease_ttl_ms == 0 {
            return Err(format!(
                "{at}: `upstream_credential.lease_ttl_ms:` must be greater than zero. A lease that \
                 expires at the instant it is minted is a credential that can never be presented."
            ));
        }
        if let super::creds::CredentialPlacement::Header(name) = &cred.placement {
            if name.trim().is_empty() {
                return Err(format!(
                    "{at}: `upstream_credential.placement.header:` must name a header"
                ));
            }
        }
    }

    for scope in &def.egress_scopes {
        if scope.trim().is_empty() {
            return Err(format!(
                "{at}: `egress_scopes:` contains an empty name; an empty scope grants nothing and \
                 reads as though it grants something"
            ));
        }
    }

    if let Some(ttl) = def.reverify_ttl.as_deref() {
        crate::admin::parse_duration_secs(ttl).map_err(|e| format!("{at}: `reverify_ttl:` {e}"))?;
    }
    if let Some(backoff) = def.recovery_backoff.as_deref() {
        crate::admin::parse_duration_secs(backoff)
            .map_err(|e| format!("{at}: `recovery_backoff:` {e}"))?;
    }

    // THE PARSE-TIME PLANE BOUNDARY, owned by `plane::config` and called with this plane's own
    // wording for the site. The section list it judges against is DERIVED from the config grammar,
    // so a section added to `Plane::ALL` or `NamedMapSection::ALL` is refused here with nothing
    // written in this file.
    let sections = crate::plane::config::config_sections();
    for hook in &def.hooks {
        busbar_substrate::plane::config::refuse_cross_plane_reference(&at, hook, &sections)?;
    }
    Ok(())
}

/// The effective re-verification cadence for one registration, as the pure-function policy
/// [`super::reverify`] consumes.
///
/// Config in, policy out, no clock and no I/O — so the cadence an operator wrote and the cadence
/// the decision uses are provably the same value rather than two parallel readings of it.
pub(crate) fn policy_for(
    def: &AgentDefCfg,
    default_backoff_ms: u64,
) -> Result<super::reverify::Policy, String> {
    let ttl = def.reverify_ttl.as_deref().unwrap_or(DEFAULT_REVERIFY_TTL);
    let ttl_ms = crate::admin::parse_duration_secs(ttl)?.saturating_mul(1_000);
    let recovery_backoff_ms = match def.recovery_backoff.as_deref() {
        None => default_backoff_ms,
        Some(v) => crate::admin::parse_duration_secs(v)?.saturating_mul(1_000),
    };
    Ok(super::reverify::Policy {
        ttl_ms,
        recovery_backoff_ms,
    })
}

impl AgentPinCfg {
    /// This `pin:` object as the plane-neutral reader takes it. A projection, not a decision: every
    /// question asked of it is [`busbar_substrate::trust::declared`]'s, and this plane's answers are its
    /// [`busbar_substrate::trust::declared::Declares`] impl in [`super::pin`].
    pub(crate) fn declaration(
        &self,
    ) -> busbar_substrate::trust::declared::Declaration<'_, PinMechanism> {
        busbar_substrate::trust::declared::Declaration {
            mechanism: self.mechanism,
            key: self.key.as_deref(),
            fingerprint: self.fingerprint.as_deref(),
        }
    }
}

#[cfg(test)]
#[path = "tests/config_tests.rs"]
mod config_tests;
