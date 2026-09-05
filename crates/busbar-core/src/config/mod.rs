// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// The busbar-owned config overlay (persistence substrate for API-applied hook changes).
pub mod overlay;

/// The top-level `groups:` limit tree: GroupCfg + the generic limit shape.
pub mod groups;
/// The 1.4.x -> 1.5.0 config migrator + the loud fail-closed 1.x detector.
pub mod migrate;
pub(crate) mod migrate_export;
/// The 1.5.3 named-DEFINITION map sections (`identity-providers:`, `export:`), described ONCE as
/// data so every surface that serves the universal pattern is parameterized instead of copied.
pub mod named_map;
/// The secret-reference type: `{ module, settings }` + the `{env}`/`{file}` sugar.
pub(crate) mod patch;
pub mod secret;

pub use groups::GroupCfg;
pub(crate) use groups::LimitCfg;
pub use secret::SecretRef;

// Re-export status_class_from_str for config validation
pub(crate) use crate::breaker::status_class_from_str;
use crate::diagnostics::{
    diag_warn, CONFIG_ANTIDOWNGRADE_FLOOR_INVALID, CONFIG_FIRSTPARTY_FLOOR_INVALID,
};
use crate::plane::config::{AgentsSection, McpEndpointSection, StreamsSection, ToolsSection}; // plane-purity: frozen-wire McpEndpointSection is the snapshot-recorded type of the mcp: field

/// Reject an env-var value that could break out of the surrounding YAML scalar when substituted
/// into the raw config text BEFORE parsing. `interpolate_env` splices each value in verbatim, so a
/// value carrying a YAML-structural control character — most critically a NEWLINE or carriage
/// return — can close the quoted (or plain) scalar it sits inside and inject sibling YAML nodes.
/// This is the FIRST of two layers: it is a fast, cheap, clear-error rejection of the
/// newline-based injection shape. It is NOT sufficient on its own — see
/// [`interpolate_env_with`]'s structural-equivalence check for the second layer, which closes the
/// remaining injection surface that needs no newline at all: inside a YAML FLOW collection
/// (`{ }` / `[ ]` — used by this project's own documented interpolation examples, e.g.
/// `client_tokens: [ "${VAR}" ]`), a value containing a bare `,`, `"`, or `'` can inject sibling
/// structure on a single line. A flow SEQUENCE has no schema-level defense against an extra
/// element (it silently widens e.g. a client-token allowlist), and an opaque `settings:` map
/// (`serde_json::Map`, used by auth-chain/hook module config and `SecretRef`) has no
/// `deny_unknown_fields` to reject an injected sibling key either — both are real, exploitable
/// shapes in this config format. (A typed struct like `PluginsCfg`, which DOES carry
/// `#[serde(deny_unknown_fields)]` on every field, blocks a bare sibling-key injection at the
/// deserialize layer for that specific struct — but that is struct-specific luck, not a general
/// guarantee, and does not help flow sequences or opaque maps at all.)
///
/// No legitimate secret, token, URL, or path value contains a raw control character, so blocking
/// the entire C0 control range (plus DEL and the C1 NEL/LS/PS line-breaks YAML also treats as line
/// boundaries) closes the newline-based injection vector with effectively zero false positives. A
/// double-quote, `#`, or comma on its own is harmless without a line break to terminate the
/// current scalar in most positions, and YAML's own quoting handles them, so we do not
/// over-reject those here — the flow-collection case they DO enable is handled by the structural
/// check instead, which is not a character-based check.
fn reject_yaml_unsafe_value(var_name: &str, value: &str) -> Result<(), String> {
    if let Some(bad) = value.chars().find(|c| {
        // C0 controls (incl. \n, \r, \t, NUL) and DEL, plus the Unicode line/paragraph separators
        // and NEL that YAML treats as line breaks (U+0085 NEL, U+2028 LS, U+2029 PS).
        c.is_control() || matches!(c, '\u{2028}' | '\u{2029}')
    }) {
        return Err(format!(
            "environment variable '{var_name}' contains a control character (U+{:04X}) that could \
             inject YAML structure during config interpolation; remove it",
            bad as u32
        ));
    }
    Ok(())
}

/// How [`interpolate_env_with`] treats a `${VAR}` whose environment variable is unset.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EnvSubst {
    /// Boot / reload: an unset variable is a hard error (fail loud — a real deployment must have its
    /// secrets present before it serves traffic).
    Strict,
    /// `busbar --validate`: an unset variable is substituted with a placeholder (its own name) and
    /// recorded, so config STRUCTURE can be validated without secrets present (CI, pre-reload dry runs).
    Lenient,
}

/// Expand `${VAR}` tokens from the environment (see [`EnvSubst`] for unset-variable behavior). See
/// [`interpolate_env_with`] for the two-layer injection defense applied to every substituted value.
pub fn interpolate_env(s: &str) -> Result<String, String> {
    interpolate_env_with(s, EnvSubst::Strict, &mut Vec::new())
}

/// A single `${VAR}` occurrence resolved during interpolation: the real substituted text and the
/// per-occurrence placeholder token that stands in for it in the "shape" pass (see
/// [`assert_interpolation_preserves_structure`]). Recorded in source order so a structural
/// mismatch can be attributed back to a specific occurrence / variable, best-effort.
struct Occurrence {
    var_name: String,
    real_value: String,
    placeholder: String,
}

/// See [`interpolate_env`]. In [`EnvSubst::Lenient`] mode each unset variable name is pushed into
/// `unset` (first-seen, deduped) and a placeholder substituted; in `Strict` mode `unset` is untouched.
///
/// Two independent layers guard every substituted value against breaking out of the raw YAML text
/// it is spliced into, verbatim, BEFORE parsing:
///
/// 1. [`reject_yaml_unsafe_value`] rejects a NEWLINE (or other YAML-structural control character)
///    in the value outright — cheap, and gives a precise error for that shape.
/// 2. A structural-equivalence check (this function, below): after interpolation, the SAME raw
///    template is interpolated a second time with every `${VAR}` replaced by a unique, YAML-inert
///    placeholder token instead of its real value. Both results are parsed to `serde_yaml::Value`
///    and their trees are compared for structural equivalence (same map keys, same sequence
///    lengths, same node kind, at every position — NOT scalar leaf values, which are expected and
///    allowed to differ in content and even inferred type). Any difference means a substituted
///    value injected or removed YAML structure — the config would parse into a different SHAPE
///    than the template declares — and interpolation is rejected. This closes injection shapes
///    that need no newline at all (flow-collection `,`/`"`/`'` breakout, anchor/tag games), which
///    (1) alone cannot see.
pub fn interpolate_env_with(
    s: &str,
    mode: EnvSubst,
    unset: &mut Vec<String>,
) -> Result<String, String> {
    let mut result = String::with_capacity(s.len());
    let mut occurrences: Vec<Occurrence> = Vec::new();
    let mut chars = s.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut var_name = String::new();
            let mut closed = false;
            for ch in chars.by_ref() {
                if ch == '}' {
                    closed = true;
                    break;
                }
                var_name.push(ch);
            }
            // The inner loop also exits when the iterator is exhausted, so a token with no closing
            // brace (e.g. `${FOO`) would otherwise be treated as `${FOO}` — silently succeeding if
            // FOO happens to be set, or reporting a misleading "unset variable" if it is not. Reject
            // the malformed token loudly instead so config typos surface at boot.
            if !closed {
                return Err(format!(
                    "unclosed variable reference starting at '${{{var_name}'"
                ));
            }
            if var_name.is_empty() {
                return Err("empty variable name in ${}".into());
            }
            let value = match std::env::var(&var_name) {
                Ok(v) => v,
                Err(_) => match mode {
                    EnvSubst::Strict => {
                        return Err(format!("unset environment variable: {}", var_name));
                    }
                    EnvSubst::Lenient => {
                        if !unset.contains(&var_name) {
                            unset.push(var_name.clone());
                        }
                        var_name.clone() // placeholder: a non-empty, YAML-safe scalar
                    }
                },
            };
            // Reject a structurally-unsafe value BEFORE splicing it in, so it cannot break out of
            // the surrounding YAML scalar and inject sibling nodes (e.g. extra client_tokens).
            reject_yaml_unsafe_value(&var_name, &value)?;
            result.push_str(&value);
            // Unique PER OCCURRENCE (not per var name): two different `${VAR}` references never
            // collapse to the same placeholder token, so a real shape difference between two
            // occurrences of the same variable can never be masked by the placeholder pass
            // accidentally making them look like "the same node twice". Reusing the SAME var's
            // real value at multiple points needs no special handling either way — the shape
            // check never compares scalar leaf VALUES, only node kind/keys/lengths, so two
            // occurrences sharing a real value are indistinguishable, structurally, from two
            // occurrences with different values; both are fine.
            let placeholder = structural_placeholder(occurrences.len());
            occurrences.push(Occurrence {
                var_name,
                real_value: value,
                placeholder,
            });
        } else {
            result.push(ch);
        }
    }

    if !occurrences.is_empty() {
        assert_interpolation_preserves_structure(s, &result, &occurrences)?;
    }

    Ok(result)
}

/// The per-occurrence placeholder token used by the structural-equivalence check: alphanumeric +
/// underscore only, so it can never itself introduce YAML structure (no `,` `"` `'` `&` `*` `!`
/// `:` `[` `]` `{` `}` `#` `|` `>` `-` or whitespace) regardless of where in the template it lands.
fn structural_placeholder(occurrence_index: usize) -> String {
    format!("__BUSBAR_INTERP_PLACEHOLDER_{occurrence_index}__")
}

/// Re-run the interpolation of `template` with the placeholder token substituted for occurrence
/// `keep_real` (kept as its real value) and every OTHER occurrence's placeholder for all others,
/// re-scanning `template` for `${...}` spans in the same left-to-right order `occurrences` was
/// built in. Used only on the (rare, boot-time-only) attribution path after a mismatch is already
/// known, to isolate which single occurrence's real value is responsible.
fn splice_occurrences(
    template: &str,
    occurrences: &[Occurrence],
    keep_real: Option<usize>,
) -> String {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    let mut idx = 0usize;
    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next();
            for ch in chars.by_ref() {
                if ch == '}' {
                    break;
                }
            }
            let occ = &occurrences[idx];
            if keep_real == Some(idx) {
                out.push_str(&occ.real_value);
            } else {
                out.push_str(&occ.placeholder);
            }
            idx += 1;
        } else {
            out.push(ch);
        }
    }
    out
}

/// The structural-equivalence check (see [`interpolate_env_with`] doc comment). `real` is the
/// already fully-interpolated text; `template` is the original raw source (re-scanned to build the
/// all-placeholder text and, on the failure path, single-occurrence hybrids for attribution).
fn assert_interpolation_preserves_structure(
    template: &str,
    real: &str,
    occurrences: &[Occurrence],
) -> Result<(), String> {
    // If the real text doesn't even parse as YAML, that already fails safely downstream (the
    // caller re-parses it and gets a loud, ordinary parse error) — nothing "succeeded silently",
    // so there is nothing for this check to add. Skip rather than invent a confusing second error.
    let real_value: serde_yaml::Value = match serde_yaml::from_str(real) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };

    let placeholder_text = splice_occurrences(template, occurrences, None);
    let placeholder_value: serde_yaml::Value = match serde_yaml::from_str(&placeholder_text) {
        Ok(v) => v,
        Err(e) => {
            // The placeholder text is built from YAML-inert tokens, so this should not normally
            // happen. Real interpolation succeeded (parsed fine above) but we cannot verify it
            // preserves the template's structure — fail closed rather than let an unverifiable
            // interpolation through.
            return Err(format!(
                "could not verify that environment-variable interpolation preserves config \
                 structure (internal placeholder document failed to parse: {e}); refusing to \
                 proceed"
            ));
        }
    };

    if structural_shapes_match(&real_value, &placeholder_value, 0) {
        return Ok(());
    }

    // Mismatch: try to isolate which single occurrence's real value is responsible by swapping
    // real values back in one at a time against the all-placeholder baseline. Boot-time-only,
    // rare (error) path, so re-parsing per occurrence is a non-issue.
    let mut culprits: Vec<String> = Vec::new();
    for (i, occ) in occurrences.iter().enumerate() {
        let hybrid_text = splice_occurrences(template, occurrences, Some(i));
        let matches = match serde_yaml::from_str::<serde_yaml::Value>(&hybrid_text) {
            Ok(hybrid_value) => structural_shapes_match(&hybrid_value, &placeholder_value, 0),
            Err(_) => false, // this occurrence alone breaks parsing outright: also a culprit
        };
        if !matches && !culprits.contains(&occ.var_name) {
            culprits.push(occ.var_name.clone());
        }
    }

    if culprits.is_empty() {
        // No single occurrence reproduces the mismatch in isolation (e.g. it takes two or more
        // values together) — name every candidate rather than guess wrong.
        let mut all: Vec<String> = occurrences.iter().map(|o| o.var_name.clone()).collect();
        all.sort();
        all.dedup();
        Err(format!(
            "environment-variable interpolation would change the config's YAML structure (extra \
             or missing key, different sequence length, or different node kind at some position), \
             but no single variable reproduces it in isolation — inspect: {}",
            all.join(", ")
        ))
    } else {
        Err(format!(
            "environment variable(s) {} would change the config's YAML structure when \
             interpolated (extra or missing key, different sequence length, or different node \
             kind) — a substituted value must only ever change a scalar leaf's content, never the \
             document's shape",
            culprits.join(", ")
        ))
    }
}

/// The node "kind" compared by the structural-equivalence check: every scalar variant (`Null`,
/// `Bool`, `Number`, `String`) folds into one bucket, because interpolation legitimately changes a
/// leaf's content and even its INFERRED TYPE (e.g. `port: ${PORT}` — a real `8080` infers as
/// `Number`, the placeholder token infers as `String`) without that being an injection. `Mapping`,
/// `Sequence`, and `Tagged` stay distinct: those are shapes a plain scalar substitution should
/// never turn into, so seeing one appear only on the real side (or vice versa) IS the signal.
///
/// `depth` bounds the recursion (mirrors `json::MAX_JSON_DEPTH`'s reasoning, at the same limit):
/// this walks an UNTYPED `serde_yaml::Value` tree built from a config file only "trusted but
/// validated" per this project's own threat model (a typo shouldn't become a crash), and unlike
/// the typed deserialize path this function has no schema to bound its own depth — a config with
/// deeply nested (even accidentally, via a templating bug) mappings/sequences could otherwise
/// stack-overflow the boot/reload path. Past the limit, treat the pair as a shape MISMATCH (fail
/// closed into the ordinary "would change structure" rejection) rather than let a document too
/// deep to safely verify slip through.
const MAX_STRUCTURAL_COMPARE_DEPTH: usize = 128;

fn structural_shapes_match(a: &serde_yaml::Value, b: &serde_yaml::Value, depth: usize) -> bool {
    use serde_yaml::Value;
    if depth > MAX_STRUCTURAL_COMPARE_DEPTH {
        return false;
    }
    match (a, b) {
        (Value::Mapping(ma), Value::Mapping(mb)) => {
            let mut ka: Vec<String> = ma.iter().map(|(k, _)| mapping_key_repr(k)).collect();
            let mut kb: Vec<String> = mb.iter().map(|(k, _)| mapping_key_repr(k)).collect();
            ka.sort();
            kb.sort();
            // Compared as a SET, not in map order: a real injection would not necessarily
            // preserve key order, and order carries no semantic meaning for a YAML mapping here
            // (`serde_yaml` / the typed structs downstream don't treat map key order as
            // significant either), so an order-sensitive compare would be both meaningless and a
            // source of spurious failures.
            if ka != kb {
                return false;
            }
            ma.iter().all(|(k, va)| match mb.get(k.clone()) {
                Some(vb) => structural_shapes_match(va, vb, depth + 1),
                None => false,
            })
        }
        (Value::Sequence(sa), Value::Sequence(sb)) => {
            sa.len() == sb.len()
                && sa
                    .iter()
                    .zip(sb.iter())
                    .all(|(va, vb)| structural_shapes_match(va, vb, depth + 1))
        }
        (Value::Tagged(ta), Value::Tagged(tb)) => {
            ta.tag == tb.tag && structural_shapes_match(&ta.value, &tb.value, depth + 1)
        }
        (Value::Mapping(_), _) | (_, Value::Mapping(_)) => false,
        (Value::Sequence(_), _) | (_, Value::Sequence(_)) => false,
        (Value::Tagged(_), _) | (_, Value::Tagged(_)) => false,
        // Both plain scalars (Null/Bool/Number/String in any combination): shape matches
        // regardless of content or inferred type — see the doc comment above.
        _ => true,
    }
}

/// A YAML mapping key rendered to a comparable string for the structural-equivalence check's
/// key-set comparison. Every key in this project's config surface is a plain YAML string, so the
/// common case is exact; the fallback exists only so a non-string key (not expected in practice)
/// degrades to a still-deterministic, still-comparable representation instead of panicking.
fn mapping_key_repr(key: &serde_yaml::Value) -> String {
    match key {
        serde_yaml::Value::String(s) => s.clone(),
        other => format!("{other:?}"),
    }
}

/// The fully-resolved runtime config. NOT deserialized from YAML: the on-disk shape is `DeployCfg`
/// (+ provider definitions), and `RootCfg` is constructed exclusively by [`resolve`]. It therefore
/// carries no `Deserialize` derive and no field-level serde defaults — those would be inert, and
/// implying a YAML parse path here would mislead a reader into reasoning about defaults that never
/// fire.
#[derive(Debug)]
pub struct RootCfg {
    pub listen: String,
    /// busbar's PUBLIC base URL (top-level `public_url:`). The externally-reachable origin used to
    /// build `/auth/token` links AND shown to devs as the `base_url` they point BYOK clients at (no
    /// `/v1` suffix — clients append their own). Absent ⇒ no hosted-login/token links can be built.
    /// Validated (absolute https; loopback http allowed; no path/query, no cloud-metadata host).
    pub public_url: Option<String>,
    /// The VALIDATED per-plane endpoint resources, keyed by the owning plane's CONFIG SECTION and
    /// each type-erased as `Arc<dyn Any>`. Empty when no endpoint plane is configured. Each is lowered
    /// and refused at boot by that plane's `lower_endpoint` seam hook, so core names no plane resource
    /// type and nothing downstream re-parses the canonical URI or re-derives the mount path. The
    /// plane's own module downcasts its entry back to its concrete resource; read it via
    /// [`RootCfg::endpoint_resource`] keyed by the plane's config section — never a per-plane field.
    pub endpoint_resources:
        std::collections::HashMap<&'static str, std::sync::Arc<dyn std::any::Any + Send + Sync>>,
    /// The VALIDATED authorization server (`oauth_as:`), or `None` when this deployment is not one.
    /// Derived and refused at boot by `crate::oauth_as::config::AsIdentity::from_cfg`, so nothing
    /// downstream re-parses the issuer or re-derives an endpoint path.
    pub oauth_as: Option<crate::oauth_as::config::AsIdentity>,
    /// The `tools:` MCP server registry, carried through `resolve` VERBATIM.
    ///
    /// Verbatim on purpose: this is operator INTENT (owner ruling 3), and the only derivation that
    /// happens to it is building the catalogue snapshot, which is a separate value with its own
    /// generation. Lowering it here would give the registry two representations that could disagree
    /// about what the operator approved — precisely the disagreement the trust lifecycle removes by
    /// DERIVING state from intent-versus-observation instead of storing it.
    pub tool_defs: Box<dyn crate::plane::config::PlaneCfg>,
    /// Optional native inbound TLS. `None` ⇒ plain HTTP (today's path, byte-for-byte).
    pub tls: Option<TlsCfg>,
    /// Separate admin listen address — the admin API is served ONLY here, never on the data
    /// listener. Defaults to loopback (`127.0.0.1:8081`).
    pub admin_listen: String,
    /// TLS/mTLS for the admin listener (only meaningful with `admin_listen`).
    pub admin_tls: Option<TlsCfg>,
    pub auth: Option<AuthCfg>,
    pub providers: HashMap<String, ProviderCfg>,
    pub models: HashMap<String, ModelCfg>,
    pub pools: HashMap<String, PoolCfg>,
    /// The ALL-POOLS `upstream_credentials:` default, resolved from the reserved
    /// `pools.upstream_credentials:` key (1.5.3 — moved off the retired `auth.upstream_credentials:`).
    /// A pool's own `upstream_credentials:` OVERRIDES this (SCALAR combine rule).
    pub upstream_credentials: crate::auth::UpstreamCreds,
    /// The RUNTIME hook registry, LOWERED by `resolve` from the top-level `hooks:` NAMED-DEFINITION
    /// map (1.5.3: [`DeployCfg::hooks`] — a hook is DEFINED once and REFERENCED by bare name from
    /// `pools.hooks:` / `pools.<p>.hooks:`). Admin-registered hooks land here too.
    pub hooks: HashMap<String, HookCfg>,
    /// The ADMIN auth chain module names (from `auth.admin_auth:`, in order) gating
    /// `/api/v1/admin/*`. Default `[admin-tokens]`. `[]` = OPEN admin (dev only; loud boot
    /// warning).
    pub admin_auth: Vec<String>,
    /// The top-level `groups:` limit tree.
    pub groups: std::collections::BTreeMap<String, GroupCfg>,
    /// The top-level `rate_card:` - the ONLY cost source. See `DeployCfg::rate_card`.
    pub rate_card: Option<std::collections::BTreeMap<String, RateEntryCfg>>,
    /// Flat cents charged per request (default 0).
    pub per_request_fee: i64,
    /// The `store:` block as configured; `None` = the block was ABSENT (ephemeral RAM store,
    /// presence-driven governance stays off unless another governance signal is present).
    pub store: Option<StoreCfg>,
    /// Module-level `open()` config for `kind: secret` plugins, keyed by module name (the top-level
    /// `secrets:` block). Empty = every secret plugin opens with `{}` (the prior behavior). The
    /// built-in `env` / `file` modules take no config and must not appear here.
    pub secrets: std::collections::BTreeMap<String, SecretModuleCfg>,
    /// Names of hooks that fire on EVERY request — the registry names lowered from the reserved
    /// all-pools attach key `pools.hooks:` (1.5.3), in order. RUNTIME-only: there is no
    /// config-facing `global_hooks:` key any more.
    pub global_hooks: Vec<String>,
    /// Operator-supplied additions to the hardcoded cloud-metadata denylist (see
    /// [`SecurityCfg::blocked_metadata_hosts`]). Resolved from `DeployCfg.security`; empty when no
    /// `security:` block is present. Threaded into `config_validate::validate` so a provider
    /// `base_url` (and any path-override composition) targeting one of these hosts is rejected at
    /// boot unless that host is carved out by an allow-override.
    pub blocked_metadata_hosts: Vec<String>,
    /// Global SURGICAL allow-override: cloud-metadata hosts/IPs to UNBLOCK for ALL providers
    /// (`security.allow_metadata_hosts`). Unioned with each provider's own `allow_metadata_hosts`
    /// when the guard runs; a host on the denylist is permitted iff it appears in this union (or
    /// `allow_all_metadata` is set). Matched with the same canonicalization as the block check (an IP
    /// entry unblocks all its spellings). Default empty.
    pub allow_metadata_hosts: Vec<String>,
    /// Nuclear override (`security.allow_all_metadata`): when true the metadata SSRF guard is fully
    /// DISABLED — every cloud-metadata endpoint is reachable by every provider. Logs a startup WARN.
    /// Default false.
    pub allow_all_metadata: bool,
    /// Fully-resolved operational limits ("NEVER CODED CAPS"), projected from the `limits:` /
    /// `observability:` / `governance:` / `metrics:` / `health:` / `routing:` config sections. Every
    /// value defaults to its historical hardcoded const, so an all-default config is unchanged. Read
    /// by `config_validate::validate`, threaded into the store/client/TLS/App at startup, and
    /// installed into the process-wide `crate::limits` statics for the deep call-stack use sites.
    pub limits: LimitsResolved,
    /// The resolved `export:` block — the built-in observability exporters. Default
    /// (all-`None`) ⇒ collection inert. Read at App construction to install the recorder + build the
    /// `/metrics` plugin route (prometheus) and to configure the request-log sinks.
    pub export: ExportCfg,
    /// The `identity-providers:` NAMED-DEFINITION map, carried through resolve VERBATIM (the
    /// EFFECTIVE map: base `config.yaml` + the overlay's API-applied entries, merged pre-resolve).
    /// `auth`/`admin_auth` above are the RESOLVED projection of it; this is the definition surface
    /// the admin API reads and rewrites (`GET/PUT/PATCH/DELETE /identity-providers/{name}`).
    pub identity_providers: IdentityProviders,
    /// The `export:` NAMED-DEFINITION map, carried through resolve VERBATIM — the definition twin of
    /// the typed `export` projection above, for the same reason `identity_providers` is carried:
    /// the admin API serves DEFINITIONS, not the lowered per-module runtime shape.
    pub export_defs: ExportDefs,
    /// The `agents:` NAMED-DEFINITION map, carried through resolve VERBATIM, for the same reason
    /// `identity_providers` and `export_defs` are: the admin API serves DEFINITIONS, and the A2A
    /// control plane derives its runtime `AgentRegistration` from this plus what the store has
    /// accumulated. Nothing here is accumulation.
    // Neutral capture when the A2A plane is compiled out: the resolved registry type does not exist
    // then, and a non-empty `agents:` section is refused at `resolve` (the raw capture is carried
    // through unchanged, as `RootCfg` for `mcp:`/`tools:` is when `plane-mcp` is off).
    pub agent_defs: Box<dyn crate::plane::config::PlaneCfg>,
    /// The `tool_pools:` MCP failover pools, carried through `resolve` VERBATIM — operator intent,
    /// like `tool_defs` beside it, projected onto `state::App::tool_pools` at build. Empty ⇒ no
    /// MCP failover.
    pub tool_pools: std::collections::BTreeMap<String, crate::failover::CandidatePoolCfg>,
    /// The `agent_pools:` A2A failover pools, carried through `resolve` VERBATIM onto
    /// `state::App::agent_pools`. Empty ⇒ no A2A failover.
    pub agent_pools: std::collections::BTreeMap<String, crate::failover::CandidatePoolCfg>,
}

impl RootCfg {
    /// The VALIDATED endpoint resource for a plane, keyed by that plane's config `section`, or `None`
    /// when this deployment configures no such endpoint (or the owning plane was compiled out). The
    /// resource is type-erased as `Arc<dyn Any>` — the owning plane's own module downcasts it back to
    /// its concrete resource. This is the NEUTRAL, section-keyed read the composition root uses in
    /// place of a per-plane field, mirroring `tool_defs`/`agent_defs` beside it.
    pub fn endpoint_resource(
        &self,
        section: &str,
    ) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
        self.endpoint_resources.get(section).cloned()
    }
}

/// Native inbound TLS configuration for the client↔Busbar hop. Absent (`Config.tls == None`) ⇒
/// Busbar serves plain HTTP exactly as before. Present ⇒ Busbar terminates TLS itself; if
/// `client_ca` is also set, it additionally requires and verifies a client certificate (mTLS).
/// All three values are SECRET REFERENCES (`{ file: … }` / `{ env: … }` / a secret module)
/// resolving to PEM bytes; they are resolved once at startup and any resolve/parse error is fatal
/// (`die`). Key bytes are never logged.
// Moved to `busbar_substrate::config::sections`; re-exported at its historical `config::` path.
pub use busbar_substrate::config::sections::TlsCfg;

/// One entry in the top-level `identity-providers:` NAMED-DEFINITION map, the resolved auth-chain
/// entry, the role-binding grant, the token-mint policy, the built-in provider names, and the
/// WIRE/RESOLVED `auth:` block itself: plain data with serde derives and pure accessors — nothing
/// here loads a file, resolves a secret, or touches the running `App`. Moved to
/// `busbar_substrate::config::auth`; the resolver that joins chain NAMES to definitions
/// (`resolve_auth`, just below) stays here. Re-exported at their historical `config::` path.
pub use busbar_substrate::config::auth::{
    AuthCfg, AuthChainEntry, AuthDeployCfg, AuthMethodCfg, AuthMethods, AuthPolicyCfg, BindingMode,
    BrowserLoginCfg, IdentityProviderCfg, IdentityProviders, MintCeilingCfg, RoleBindingCfg,
    RoleBindings, ADMIN_TOKENS_MODULE, BUILTIN_IDENTITY_PROVIDERS, DEFAULT_MAX_ADMIN_SCOPE,
    KEYS_MODULE,
};


/// The built-in signed-key verifier module name (`auth.chain: [keys]`).
/// The config shape `--migrate-config` targets, for anything that needs to NAME it in output.
///
/// Derived from the crate version rather than written down, because the previous hardcoded "1.5.0"
/// in the migrator's banner was still claiming 1.5.0 three releases after the target moved. A
/// version string a human has to remember to bump is a version string that goes stale.
pub(crate) const CONFIG_TARGET_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Join each `auth.chain:` / `auth.admin_auth:` NAME to its `identity-providers:` definition, producing
/// the RESOLVED [`AuthCfg`] every runtime consumer reads.
///
/// The DEDUPE property this whole redesign exists for: one provider definition referenced from BOTH
/// chains yields two [`AuthChainEntry`]s that share one definition — same module, same settings, same
/// ceiling, by construction. The pre-1.5.3 shape needed the operator to write the settings twice, and
/// nothing stopped the two copies from drifting.
///
/// Errors are ACCUMULATED into `errors`:
/// - a name with no definition that is not a bare built-in (a dangling reference — fail closed, never
///   a silently-skipped auth module);
/// - a `token:` on a provider whose module is not the built-in `admin-tokens` (meaningless there);
/// - a definition with an empty `module:`.
///
/// The `max_admin_scope` DEFAULT is applied here, once, so every downstream reader sees the resolved
/// ceiling rather than re-deriving it: absent ⇒ [`DEFAULT_MAX_ADMIN_SCOPE`] for every provider except
/// the built-in `admin-tokens` operator credential, which stays `None` (exempt, full by definition) —
/// byte-identical to the pre-1.5.3 semantics.
/// THE ONE `identity-providers.<name>.token:` PLACEMENT RULE. `token:` is the built-in
/// `admin-tokens` operator credential; on any other module it is inert, so it is almost certainly a
/// MISPLACED SECRET and must fail loud rather than sit in config doing nothing.
///
/// Shared by [`resolve_auth`] (which sees only providers REFERENCED from a chain) and by
/// `NamedMapSection::parse_def` (which sees every DEFINITION the admin API writes, referenced or
/// not). The definition-side call is the one that matters: `resolve_auth`'s check is keyed off the
/// resolved chain, so a provider defined through the admin API and not yet referenced escaped it
/// entirely — the API answered 200 and stored the misplaced credential, and the error surfaced only
/// once something named the provider.
pub(crate) fn validate_token_placement(
    name: &str,
    module: &str,
    has_token: bool,
) -> Result<(), String> {
    if has_token && module != ADMIN_TOKENS_MODULE {
        return Err(format!(
            "identity-providers.{name}: `token:` is the built-in `admin-tokens` operator \
             credential and is meaningless on `module: {module}`"
        ));
    }
    Ok(())
}

pub(crate) fn resolve_auth(
    auth: &AuthDeployCfg,
    providers: &IdentityProviders,
    errors: &mut Vec<String>,
) -> AuthCfg {
    let mut resolve_one = |plane: &str, name: &String| -> AuthChainEntry {
        match providers.get(name) {
            Some(def) => {
                let module = def.module.trim().to_string();
                if module.is_empty() {
                    errors.push(format!(
                        "identity-providers.{name}.module must be a non-empty module name"
                    ));
                }
                if let Err(e) = validate_token_placement(name, &module, def.token.is_some()) {
                    errors.push(e);
                }
                let max_admin_scope = def.max_admin_scope.clone().or_else(|| {
                    (module != ADMIN_TOKENS_MODULE).then(|| DEFAULT_MAX_ADMIN_SCOPE.to_string())
                });
                AuthChainEntry {
                    name: name.clone(),
                    module,
                    max_admin_scope,
                    token: def.token.clone(),
                    settings: def.settings.clone(),
                }
            }
            // A BARE BUILT-IN needs no definition. Anything else is a dangling reference.
            None if BUILTIN_IDENTITY_PROVIDERS.contains(&name.as_str()) => {
                AuthChainEntry::bare(name.clone())
            }
            None => {
                errors.push(format!(
                    "auth.{plane} references '{name}', which is not defined in \
                     `identity-providers:` (and is not a built-in: {}). Define it, or reference a \
                     built-in by its bare name.",
                    BUILTIN_IDENTITY_PROVIDERS.join(" / ")
                ));
                AuthChainEntry::bare(name.clone())
            }
        }
    };

    let chain = auth
        .chain
        .iter()
        .map(|n| resolve_one("chain", n))
        .collect::<Vec<_>>();
    let admin_auth = auth
        .admin_auth
        .iter()
        .map(|n| resolve_one("admin_auth", n))
        .collect::<Vec<_>>();

    // FREEZE BLOCKER — every `identity-providers:` entry is a potential hosted-login method; the
    // `browser_login:` block on it is what puts a BUTTON on the login page. (A provider that is not
    // in either chain still resolves here: headless `POST /auth/token` against a defined provider is
    // exactly what the retired `auth.methods:` map allowed, so nothing narrows.)
    let methods: AuthMethods = providers
        .iter()
        .filter(|(_, def)| !BUILTIN_IDENTITY_PROVIDERS.contains(&def.module.trim()))
        .map(|(name, def)| {
            (
                name.clone(),
                AuthMethodCfg {
                    module: def.module.trim().to_string(),
                    browser_login: def.browser_login.clone(),
                    settings: def.settings.clone(),
                },
            )
        })
        .collect();

    AuthCfg {
        signing_key: auth.signing_key.clone(),
        chain,
        admin_auth,
        role_bindings: auth.role_bindings.clone(),
        methods,
        key_ttl: auth.key_ttl.clone(),
        policy: auth.policy.clone(),
    }
}

/// Append a targeted migration hint to a config-deserialize error when it is the removed 1.3.0
/// `auth.mode:` key (rejected by `AuthCfg`'s `deny_unknown_fields`), so an upgrading operator gets
/// actionable guidance instead of serde's bare "unknown field `mode`, expected one of …". Additive:
/// any other error is returned verbatim. (1.4.0 config compatibility — the key was renamed to
/// `auth.chain:` / `auth.upstream_credentials:` but the failure gave no upgrade breadcrumb.)
pub(crate) fn augment_config_error(err: impl std::fmt::Display) -> String {
    let msg = err.to_string();
    if msg.contains("unknown field `mode`") {
        format!(
            "{msg}\n  hint: the `auth.mode:` key was removed in favor of `auth.chain:` — `mode: none` \
             maps to an empty/omitted chain, `mode: token` or `mode: apikey` to `chain: [tokens]`, and \
             `mode: passthrough` to `auth.upstream_credentials: passthrough`"
        )
    } else if let Some((old, new)) = RENAMED_HOOK_STAGES
        .iter()
        .copied()
        .find(|(old, _)| msg.contains(&format!("unknown variant `{old}`")))
    {
        // 1.5.3 HARD rename of the tap `at:` vocabulary (Route→Candidate, Attempt→Routing,
        // Completion→Response). Serde rejects the old wire string as an unknown variant with no
        // upgrade breadcrumb; name the old AND the new value + point at the migrator.
        format!(
            "{msg}\n  hint: hook tap stage `{old}` was renamed to `{new}` in 1.5.3 — run \
             `busbar --migrate-config <config.yaml>` or update the `at:` value to `{new}`"
        )
    } else if let Some((old, new)) = RETIRED_OBSERVABILITY_KEYS
        .iter()
        .copied()
        .find(|(old, _)| msg.contains(&format!("unknown field `{old}`")))
    {
        // 1.5.3 observability→export lift-out. Serde rejects the retired key as an unknown
        // field; name the old key AND its new home under the built-in exporters + point at the
        // migrator, exactly like the HookStage rename above.
        format!(
            "{msg}\n  hint: `{old}` was retired in 1.5.3 — the observability sink moved to the \
             built-in EXPORTERS (`{new}`). Run `busbar --migrate-config <config.yaml>` or move the \
             field yourself"
        )
    } else if let Some((old, new)) = RETIRED_CONFIG_KEYS_1_5_3
        .iter()
        .copied()
        .find(|(old, _)| msg.contains(&format!("unknown field `{old}`")))
    {
        // The 1.5.3 GRAMMAR-LOCK retirements. Same shared-table discipline as
        // the two branches above: one table drives this hint, the `detect_legacy_markers` boot
        // loud-fail, AND the migrator's rewrite, so the three can never disagree about a key.
        format!(
            "{msg}\n  hint: `{old}` was retired in 1.5.3 — it is now `{new}`. Run \
             `busbar --migrate-config <config.yaml>` to rewrite it in place"
        )
    } else {
        msg
    }
}

/// The 1.5.3 GRAMMAR-LOCK retired keys (retired key → its new home), shared by
/// [`augment_config_error`]'s loud-fail hint, `config::migrate::detect_legacy_markers` (the
/// boot/`--validate` loud-fail) and `migrate_config`'s mechanical rewrite so the three cannot drift —
/// the same shared-table discipline [`RENAMED_HOOK_STAGES`] and [`RETIRED_OBSERVABILITY_KEYS`] use.
///
/// These are the LAST breaking config changes: 1.5.3 is the break-once release, and everything here
/// is frozen additive-only afterwards.
pub(crate) const RETIRED_CONFIG_KEYS_1_5_3: &[(&str, &str)] = &[
    // The whole block is DELETED. Listed FIRST so an `observability:` block carrying any of its
    // retired leaves reports the block-level move (the leaves have nowhere left to live).
    (
        "observability",
        "the `export:` NAMED map — a `module: prometheus` / `module: request-log-webhook` / \
         `module: otlp` instance (all telemetry egress is now the single `export:` surface)",
    ),
    // Inverted so the SAFE posture is the default.
    ("admin_insecure", "admin_require_mtls (INVERTED: `admin_insecure: true` ⇒ `admin_require_mtls: false`)"),
    // Whose credential reaches the upstream is a routing property, not an inbound-auth one.
    ("upstream_credentials", "pools.upstream_credentials (the all-pools default) + a per-pool `pools.<p>.upstream_credentials` override"),
    // The IdP is DEFINED once and REFERENCED by name.
    ("methods", "the matching `identity-providers:` definition (browser_login + settings are per-provider)"),
    // The last `observability:` field folded into `export:`.
    ("otlp_url", "an `export:` instance with `module: otlp` and `settings.url`"),
    ("otlp_endpoint", "an `export:` instance with `module: otlp` and `settings.url`"),
];

/// The 1.5.3 tap-stage `at:` renames (old wire string → new), shared by `augment_config_error`'s
/// loud-fail hint and the `--migrate-config` rewrite so the two cannot drift.
pub(crate) const RENAMED_HOOK_STAGES: &[(&str, &str)] = &[
    ("route", "candidate"),
    ("attempt", "routing"),
    ("completion", "response"),
];

/// The 1.5.3 observability→export RETIRED keys (retired LEAF key → its new home under the built-in
/// exporters), shared by `augment_config_error`'s loud-fail hint, `config::migrate::detect_legacy_markers`
/// (the boot/`--validate` loud-fail), and `migrate_config`'s mechanical rewrite so the three cannot
/// drift — the same shared-table discipline the HookStage rename uses ([`RENAMED_HOOK_STAGES`]).
pub(crate) const RETIRED_OBSERVABILITY_KEYS: &[(&str, &str)] = &[
    (
        "request_log_webhook_url",
        "export.request-log-webhook.settings.url",
    ),
    (
        "max_inflight_webhook_deliveries",
        "export.request-log-webhook.settings.max_inflight_deliveries",
    ),
    (
        "webhook_delivery_timeout_secs",
        "export.request-log-webhook.settings.delivery_timeout_secs",
    ),
    (
        "metrics",
        "export.prometheus.settings (buffer_seconds / key_gauge_limit)",
    ),
];

/// The 1.5.3 store-plugin RENAME: every retired spelling of the first-party Valkey store
/// plugin, as a `store.module:` VALUE. The plugin was renamed wholesale — repo, crate, artifact,
/// manifest `name` (now [`STORE_MODULE_VALKEY_NAME`]) and config `alias` (now
/// [`STORE_MODULE_VALKEY`]) — so NONE of these resolve against the renamed artifact's manifest.
///
/// Unlike the other retirement tables this one is keyed on a VALUE, not a field name, so serde never
/// sees it: `store.module` is a plain `String` and any spelling parses. The loud-fail therefore has
/// to come from `config::migrate::detect_legacy_markers` (which this table drives, together with
/// `migrate_config`'s mechanical rewrite, so the two cannot drift) — without it the operator gets
/// the loader's generic "does not match any plugin", which names neither the rename nor the fix.
pub(crate) const RETIRED_STORE_MODULES_1_5_3: &[&str] =
    &["redis", "busbar-store-redis", "busbar-store-redis-plugin"];

/// The config ALIAS the renamed first-party Valkey store plugin answers to (`store.module: valkey`).
pub(crate) const STORE_MODULE_VALKEY: &str = "valkey";

/// The renamed plugin's canonical MANIFEST NAME — what `busbar-plugin-pack --name` stamps and what a
/// `plugins.min_versions` / `plugin_versions` anti-downgrade floor must be keyed by. It is the plugin
/// CRATE name (`…-plugin`), which is how that repo's release workflow packs it.
pub(crate) const STORE_MODULE_VALKEY_NAME: &str = "busbar-store-valkey-plugin";

/// The renamed plugin's release-ASSET stem: the published tarball is
/// `busbar-store-valkey-<ver>-<target>.tar.gz` (the WORKSPACE name, without the `-plugin` suffix the
/// cdylib crate and the manifest carry). Two different strings on purpose — see that repo's
/// `release.yml`, which passes `--name busbar-store-valkey-plugin --out busbar-store-valkey-…`.
pub(crate) const STORE_MODULE_VALKEY_ASSET_STEM: &str = "busbar-store-valkey";

// The `providers:` / `models:` config SHAPES — the catalog definition, the operator deployment, the
// resolved provider the runtime reads, the active-health block and the per-model entry — are plain
// serde data; the catalog/deployment MERGE that produces a `ProviderCfg` stays here (`resolve`).
// Moved to `busbar_substrate::config::providers`; re-exported at their historical `config::` path.
pub use busbar_substrate::config::providers::{
    default_protocol, neg1, HealthCfg, HealthMode, ModelCfg, ProviderCfg, ProviderDef,
    ProviderDeploy, DEFAULT_PROTOCOL,
};

// ABI-purity CONFIG-ENUMS: the per-provider auth-style selector is an LLM-runtime config value
// concept; it moved DOWN to `busbar_substrate::config` (serde `Deserialize` + the `#[serde(rename)]`
// wire strings VERBATIM, byte-identical) so a plane names it via the ABI. Re-exported here at its
// historical `config::ProviderAuth` path so the frozen providers.yaml grammar parse is unchanged.
pub use busbar_substrate::config::ProviderAuth;

// ABI-purity CONFIG-ENUM: the resolved on_error/on_empty TERMINAL moved to
// `busbar_substrate::config` (serde derives + rename VERBATIM); re-exported here at its historical
// `config::PolicyOnError` path so the frozen config grammar + every deserialization are unchanged.
pub use busbar_substrate::config::PolicyOnError;

// The `hooks:` config SHAPES (the named definition, the runtime registry entry, the structured
// `on_error:` value, the mode/access/stage enums, the reserved terminal + strategy vocabulary, and
// the two pure scope predicates) and the `pools:` config SHAPES (the pool itself, its members, the
// ranking strategy, the breaker/failover/affinity blocks and the `on_exhausted:` value) are plain
// serde data with pure accessors — no loader, validator, or `App` touch. They moved to
// `busbar_substrate::config::{hooks, pools}`; re-exported here at their historical `config::` path
// so no caller (this module's own definition-to-registry lowering, validation, `config_validate`,
// `store`) moves.
pub use busbar_substrate::config::hooks::{
    caller_in_hook_groups, default_on_error, default_policy_timeout_ms, on_error_terminal,
    HookCfg, HookDefCfg, HookDefs, HookKind, HookStage, OnErrorCfg, PromptAccess, UserAccess,
    ALL_HOOK_STAGES, CORE_HOOK_PHASES, DEFAULT_POLICY_TIMEOUT_MS, FROZEN_HOOK_NAME_WORD_SPACE,
    ON_ERROR_FIRST, ON_ERROR_NOTHING, ON_ERROR_REJECT, ON_ERROR_WEIGHTED, RESERVED_HOOK_NAMES,
};
pub use busbar_substrate::config::pools::{
    default_cooldown, default_consecutive_n, default_failover_timeout, default_max_cooldown,
    default_max_hops, default_min_requests, default_threshold, default_trip_mode,
    default_weight, default_window_secs, is_strategy_name, parse_strategy, AffinityCfg,
    AffinityMode, BreakerCfg, BreakerTripConfig, BreakerTripMode, FailoverCfg, OnExhausted,
    OnExhaustedCfg, PoolCfg, PoolMember, PoolPolicy, DEFAULT_BREAKER_BASE_COOLDOWN_SECS,
    DEFAULT_BREAKER_CONSECUTIVE_N, DEFAULT_BREAKER_MAX_COOLDOWN_SECS,
    DEFAULT_BREAKER_MIN_REQUESTS, DEFAULT_BREAKER_THRESHOLD, DEFAULT_BREAKER_WINDOW_SECS,
    STRATEGY_CHEAPEST, STRATEGY_FASTEST, STRATEGY_LEAST_BUSY, STRATEGY_USAGE,
};

// The FAILOVER BUDGET numeric defaults/bounds are plain scalars with no config grammar attached, so
// they live in the neutral `busbar_substrate::failover` (a plane names the per-request failover
// budget without reaching into `busbar-core`); re-exported here at their historical
// `crate::config::*` paths so every core call site (`appbuild`, `config_validate`, `test_support`,
// the pools `default_failover_timeout`/`default_max_hops` serde defaults) resolves unchanged.
pub use busbar_substrate::failover::{
    DEFAULT_FAILOVER_CAP, DEFAULT_FAILOVER_DEADLINE_SECS, MAX_FAILOVER_DEADLINE_SECS,
};

pub use busbar_substrate::config::auth::{default_admin_auth, default_admin_auth_names};

// THE FROZEN reserved key set of the `pools:` SECTION (freeze blocker, 1.5.3): `hooks` and
// `upstream_credentials` are section-level knobs, NOT pool names — `pools.hooks:` (LIST → ADDITIVE:
// attach to ALL pools) and `pools.upstream_credentials:` (SCALAR → OVERRIDE: the all-pools default),
// alongside real pools like `pools.fast:`.
//
// THIS SET IS CLOSED AND MUST NEVER GROW. Every reserved word here is a word an operator can no longer
// use as a POOL NAME, so ADDING one in a later release retroactively turns a previously-legal config
// into a boot failure — exactly the class of break 1.5.3 exists to make impossible. Every FUTURE
// all-scope knob must therefore land under a reserved `defaults:` sub-key (`pools.defaults.<knob>`),
// which costs one word ONCE and is then additive forever.
//
// THIS IS THE ONLY DECLARATION, on every plane, and it now lives in the neutral substrate as
// `busbar_substrate::plane::config::RESERVED_SECTION_KEYS` (the shared section split that reads it
// moved there): `tools:` and `agents:` reserve the same two words by reading that ONE slice, not by
// restating it. Pinned by `pools_reserved_section_keys_are_frozen` in the config tests.

/// THE ONE CHECK BOTH FAILOVER SECTIONS GET, parameterised by which registry a bare name resolves
/// against rather than written once per plane. `tool_pools:` and `agent_pools:` are the same grammar
/// over two registries, so a second copy of this would be the shape `structure-lint.sh`'s plane
/// ledger calls DEBT: the copy that is hardened and the copy that is not look identical from outside.
///
/// Three refusals, in the order an operator can act on them: a pool with fewer than two members is a
/// pool that cannot fail over (a typo, or a leftover), a member on the WRONG PLANE is named as the
/// thing it actually is, and a member that exists nowhere is a plain dangling reference.
#[allow(clippy::too_many_arguments)] // eight small, positional facts about ONE check; bundling them
                                     // into a struct would move the same arguments one line up.
fn check_failover_pool(
    errors: &mut Vec<String>,
    section: &str,
    pool: &str,
    def: &crate::failover::CandidatePoolCfg,
    on_this_plane: impl Fn(&str) -> bool,
    on_other_plane: impl Fn(&str) -> bool,
    this_registry: &str,
    other_registry: &str,
) {
    if def.members.len() < 2 {
        errors.push(format!(
            "{section}.{pool}: a failover pool needs at least TWO members (it has {}). A pool with \
             one member has nowhere to fail over to, so it changes nothing; remove it or add the \
             second registration.",
            def.members.len()
        ));
    }
    // The plane breaker store's lane table is FIXED (process-lifetime, sized
    // `store::MAX_POOL_MEMBERS`; see `store/planes.rs` for why it cannot track config), so a pool
    // must fit it — refused here, where the operator can act, rather than indexed past at dispatch.
    if def.members.len() > crate::store::MAX_POOL_MEMBERS {
        errors.push(format!(
            "{section}.{pool}: {} members exceeds the supported maximum of {} per failover pool \
             (the breaker's per-member lane table is fixed at process start). Split the pool or \
             drop members.",
            def.members.len(),
            crate::store::MAX_POOL_MEMBERS
        ));
    }
    // A pool named after a REGISTRATION on its own plane would alias the registration's degenerate
    // breaker cell (`tool:<id>` / `agent:<id>` — the same string either way), merging two targets'
    // learned health into one cell. The keyspace rule is the audit's; this is its enforcement.
    if on_this_plane(pool) {
        errors.push(format!(
            "{section}.{pool}: `{pool}` is also the id of a `{this_registry}:` registration. A \
             pool's name shares the breaker keyspace with registration ids on its plane, so it \
             must not collide with one; rename the pool."
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for member in &def.members {
        if !seen.insert(member.as_str()) {
            errors.push(format!(
                "{section}.{pool}: `{member}` is named twice. A repeated member would be tried \
                 twice against the same upstream, which is a retry wearing a failover's clothes."
            ));
        }
        if on_this_plane(member) {
            continue;
        }
        if on_other_plane(member) {
            errors.push(format!(
                "{section}.{pool}: `{member}` is an entry in the top-level `{other_registry}:` \
                 section, not `{this_registry}:`. A failover pool may not straddle two planes — the \
                 section a pool is written in IS which plane it is on."
            ));
        } else {
            errors.push(format!(
                "{section}.{pool}: `{member}` is not defined in the top-level `{this_registry}:` \
                 map. Define it there, or remove it from the pool."
            ));
        }
    }
    // `repeatable:` naming an operation is a SAFETY declaration, so a typo in it silently leaves the
    // operation non-repeatable — which fails SAFE and is therefore not an error. It is still worth
    // nothing to write, so it is refused when it is empty of meaning: a `repeatable:` list on a pool
    // is only ever read for operations dispatched through that pool.
    for op in &def.repeatable {
        if op.trim().is_empty() {
            errors.push(format!(
                "{section}.{pool}: `repeatable:` holds an empty entry. Every entry names ONE \
                 operation that may be performed twice; an empty one names nothing."
            ));
        }
    }
}

/// The top-level `pools:` map (1.5.3), which carries the two reserved section keys
/// ([`busbar_substrate::plane::config::RESERVED_SECTION_KEYS`]) alongside the
/// pools themselves. Every key that is NOT one of those two reserved words is a pool. A pool may NOT be
/// named `hooks` or `upstream_credentials` — both are REJECTED at parse with a clear error. The custom
/// `Deserialize` lifts the reserved keys out first, then parses the remainder as the pool map.
#[derive(Debug, Clone, Default)]
pub(crate) struct PoolsCfg {
    /// The ALL-POOLS attach list — hook names that fire for EVERY pool (the reserved `pools.hooks:`
    /// key). Empty when absent. Firing order: these fire BEFORE a pool's own hooks. LIST ⇒ ADDITIVE
    /// a pool's own `hooks:` are appended to this, deduped by name (see
    /// [`combine_hook_refs`]).
    pub(crate) all_pool_hooks: Vec<String>,
    /// The ALL-POOLS `upstream_credentials:` default (the reserved `pools.upstream_credentials:`
    /// key). SCALAR ⇒ OVERRIDE: a pool's own value REPLACES this. `None` = absent ⇒ the
    /// built-in default (`own`).
    pub(crate) all_pool_upstream_credentials: Option<crate::auth::UpstreamCreds>,
    /// The real pools, keyed by name (every top-level key except the two reserved section keys).
    pub(crate) pools: HashMap<String, PoolCfg>,
}

impl<'de> Deserialize<'de> for PoolsCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // THE SECTION SPLIT is `plane::config`'s, and the pool plane reads its section through the
        // same six steps in the same order as `tools:` and `agents:` — including the refusal of a
        // reserved key holding a MAPPING before the typed lifts, which is the step this rule exists
        // for and the step a per-plane copy is likeliest to lose.
        //
        // The pool plane declares NO value rules here: `PoolCfg`'s are run later, over the whole
        // config, where they can see the cross-section references a single entry cannot.
        let section = crate::plane::config::split_section::<D, PoolCfg>(
            deserializer,
            crate::plane::fallback_key(),
            |_, _| Ok(()),
        )?;
        Ok(PoolsCfg {
            all_pool_hooks: section.hooks,
            all_pool_upstream_credentials: section.upstream_credentials,
            // The pool map is a `HashMap` and its order is never read back; converted here, once,
            // where the loss of order is visible rather than assumed.
            pools: section.entries.into_iter().collect::<HashMap<_, _>>(),
        })
    }
}

/// The ADDITIVE-LIST DEDUPE rule, in ONE place so every plane section that
/// ships an additive `hooks:` list (today `pools:`; later `tools:`/`agents:`) combines identically.
///
/// The locked combine rule says section-level LISTS are ADDITIVE, but "additive" alone does not
/// say what happens when the SAME hook name appears in BOTH `pools.hooks:` and a pool's own `hooks:`.
/// Both answers were defensible, so 1.5.3 PINS one forever:
///
/// > **A hook named in both lists fires ONCE, at its FIRST position** — i.e. the section-level
/// > position, since section-level hooks precede the entity's own.
///
/// Rationale: attaching a hook to all pools and then *also* naming it on one pool is the natural way
/// an operator writes "…and definitely on this one" — reading that as "fire twice" would silently
/// double-charge a gate's latency budget and double-count a tap's audit record. Deduping by NAME is
/// safe precisely because the name IS the instance: two DIFFERENT configurations of one
/// module are two different NAMES, so dedupe can never collapse two distinct hooks.
pub(crate) fn combine_hook_refs(section: &[String], entity: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(section.len() + entity.len());
    for name in section.iter().chain(entity.iter()) {
        if !out.iter().any(|existing| existing == name) {
            out.push(name.clone());
        }
    }
    out
}

/// The RUNTIME projection of the additive-list rule (see [`combine_hook_refs`]). busbar fires the
/// section list and the entity list through two SEPARATE resolved chains (`App::global_gates` then
/// `PoolRuntime::gates`), so the dedupe has to be applied to the ENTITY half: this returns the
/// entity's own references with (a) intra-list duplicates and (b) anything already named at the
/// section level removed. Concatenating `section` with this result reproduces
/// [`combine_hook_refs`] exactly — the property `hook_refs_combine_is_section_then_entity_only`
/// pins, so the two can never drift.
pub(crate) fn entity_only_hook_refs(section: &[String], entity: &[String]) -> Vec<String> {
    combine_hook_refs(section, entity)
        .into_iter()
        .skip(combine_hook_refs(section, &[]).len())
        .collect()
}

// The two listen-address defaults are plain string literals; moved to
// `busbar_substrate::config::sections`, re-exported at their historical `config::` path.
pub use busbar_substrate::config::sections::{DEFAULT_ADMIN_LISTEN_ADDR, DEFAULT_LISTEN_ADDR};

fn default_listen() -> String {
    DEFAULT_LISTEN_ADDR.into()
}

fn default_admin_listen() -> String {
    DEFAULT_ADMIN_LISTEN_ADDR.into()
}

/// The serde default for `admin_require_mtls:` — **true**. 1.5.3 inverted the retired
/// `admin_insecure:` boolean: the SAFE posture is the DEFAULT and the waiver is the
/// explicit `false`, so a config that says nothing gets the guard rather than the hole.
fn default_admin_require_mtls() -> bool {
    true
}

/// True iff `addr` (a `host:port` bind string) binds ONLY to the loopback interface, so a service
/// on it is unreachable from off-host. Drives the admin-plane boot-guard: a loopback admin listener
/// is safe without mTLS; anything else is treated as network-exposed. Unclassifiable hostnames fail
/// CLOSED (treated as exposed) so an ambiguous bind never silently waives the mTLS requirement.
pub(crate) fn bind_is_loopback(addr: &str) -> bool {
    // Strip the trailing `:port`. IPv6 literals contain colons, so split from the RIGHT, then peel
    // the `[...]` brackets an IPv6 host carries in `[::1]:8081` form.
    let host = addr.rsplit_once(':').map_or(addr, |(h, _port)| h);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false, // a hostname we can't resolve here → assume exposed (fail closed)
    }
}

/// Deployment configuration - operator-owned config.yaml structure.
// deny_unknown_fields: a typo'd or unknown TOP-LEVEL key (e.g. `plugin:` for `plugins:`) must be a
// loud startup error, not a silently-ignored block - the fail-closed posture every nested
// security-relevant struct (auth/governance/plugins/security) already enforces.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployCfg {
    #[serde(default = "default_listen")]
    pub(crate) listen: String,
    /// busbar's PUBLIC base URL (top-level `public_url:`) — see [`RootCfg::public_url`]. Absent by
    /// default; required once a `browser_login` method or `/auth/token` link generation is in play.
    #[serde(default)]
    pub public_url: Option<String>,
    /// Optional native inbound TLS / mTLS. Absent ⇒ plain HTTP (unchanged default).
    #[serde(default)]
    pub(crate) tls: Option<TlsCfg>,
    /// SEPARATE listen address for the admin API (`/api/v1/admin/*`). The admin surface ALWAYS runs
    /// here and is NEVER mounted on the data `listen` — the management plane stays isolated so it can
    /// carry its own TLS/mTLS, bind, and firewall posture independent of public LLM traffic. Defaults
    /// to loopback (`127.0.0.1:8081`); set an exposed address (+ `admin_tls`) to manage off-host.
    #[serde(default = "default_admin_listen")]
    pub(crate) admin_listen: String,
    /// Config-MANAGEMENT policy (`config:` block, 1.5.3): whether the admin API may mutate config and
    /// WHERE those changes persist. Absent ⇒ durable-by-default (mutable + a file overlay next to
    /// config.yaml). See [`ConfigMgmtCfg`].
    #[serde(default)]
    pub(crate) config: ConfigMgmtCfg,
    /// Optional pointer to the providers CATALOG file (`providers_file:`, 1.5.3). Relative paths
    /// resolve against the config.yaml directory. Absent ⇒ `providers.yaml` next to the resolved
    /// config.yaml. The `--providers <path>` CLI flag overrides this (1.6.0). The two-file model is
    /// preserved: this names the vetted, shippable catalog that config.yaml's `providers:` map
    /// references.
    #[serde(default)]
    pub(crate) providers_file: Option<String>,
    /// The top-level `mcp:` block (1.6.0): busbar's own MCP endpoint, as an OAuth 2.1 resource
    /// server. Its PRESENCE is what mounts the MCP plane — absent, the deployment carries no MCP
    /// ingress and no `.well-known` document, and nothing joins the route table. See
    /// `crate::mcp::McpCfg`.
    // Type-erased through the neutral `McpEndpointSection` seam: the `mcp:` block deserializes into
    // the MCP plane's own endpoint config behind `dyn PlaneEndpointCfg`, so `DeployCfg` names no
    // `crate::mcp` endpoint type. The plane compiled out captures it raw and refuses a present block
    // at `resolve` (the deletion-gate leg).
    #[serde(default)]
    pub(crate) mcp: McpEndpointSection, // plane-purity: frozen-wire the mcp: top-level wire key + McpEndpointSection snapshot type (frozen since 1.5.3)
    /// `oauth_as:` — busbar AS an OAuth 2.1 authorization server, for the deployment that has no
    /// identity provider (or has one that will not do dynamic registration). ABSENT BY DEFAULT, and
    /// absent means nothing is built: see `crate::oauth_as`.
    #[serde(default)]
    pub(crate) oauth_as: Option<crate::oauth_as::config::OauthAsCfg>,
    /// The top-level `tools:` NAMED-DEFINITION map (1.6.0) — THE MCP PLANE's registry: server name →
    /// `{url, pin, tools_allow, …}`. Sibling of `pools:` and `agents:` with the same shape and the
    /// same two reserved section keys; there is no `plane:`/`bind:`/`target:` selector, because the
    /// section an entry is written in IS which plane it is on: a `tools:` entry is an MCP server
    /// and an `agents:` entry is an A2A agent, so there is no second declaration that could
    /// disagree with the first.
    ///
    /// Distinct from `mcp:` above and the pair is not redundant: `mcp:` is busbar's OWN endpoint as
    /// a resource server (the door), `tools:` is the set of upstreams whose capabilities that door
    /// exposes (the rooms). A deployment may configure either without the other.
    // Type-erased through the neutral `ToolsSection` seam: the `tools:` registry deserializes into
    // the MCP plane's own `ToolsCfg` behind `dyn PlaneCfg`, so `DeployCfg` names no `crate::mcp`
    // registry type. The plane compiled out captures it raw and refuses a present section at
    // `resolve`.
    #[serde(default)]
    pub(crate) tools: ToolsSection,
    /// TLS/mTLS for the admin listener (only meaningful with `admin_listen`). Its own cert + optional
    /// `client_ca_file`, so admin can require client certificates without forcing them on data-plane
    /// clients. A network-exposed `admin_listen` REQUIRES `client_ca_file` here unless
    /// `admin_require_mtls: false`.
    #[serde(default)]
    pub(crate) admin_tls: Option<TlsCfg>,
    /// TOP-LEVEL boot-policy flag: does a network-exposed admin plane REQUIRE mTLS?
    /// `true` (the DEFAULT) ⇒ a non-loopback `admin_listen` without `admin_tls.client_ca` REFUSES to
    /// boot. `false` ⇒ the operator deliberately accepts a token-only admin plane on an exposed
    /// address (mTLS terminated upstream by a mesh). Loopback binds are exempt either way.
    ///
    /// 1.5.3 BREAKING: this INVERTS and replaces the retired `admin_insecure:` boolean, so the safe
    /// posture is what an omitted key gives you. It lives at the TOP LEVEL, not under `admin_tls:`,
    /// precisely because the mesh case has NO `admin_tls` block at all — nesting it would make the
    /// waiver unreachable for the deployment that needs it. It is NOT redundant with
    /// `admin_tls.client_ca`: that says "here is the CA", this says "an exposed plane must have one".
    #[serde(default = "default_admin_require_mtls")]
    pub(crate) admin_require_mtls: bool,
    pub(crate) auth: Option<AuthDeployCfg>,
    /// The top-level `identity-providers:` NAMED-DEFINITION map (1.5.3): provider NAME →
    /// [`IdentityProviderCfg`]. An IdP is DEFINED here once and REFERENCED by bare name from
    /// `auth.chain:`, `auth.admin_auth:` and `auth.role_bindings:`. Absent ⇒ only the bare built-ins
    /// (`keys` / `admin-tokens`) are referenceable.
    #[serde(default, rename = "identity-providers")]
    pub(crate) identity_providers: IdentityProviders,
    pub(crate) providers: HashMap<String, ProviderDeploy>,
    pub(crate) models: HashMap<String, ModelCfg>,
    /// Pools are optional: a deployment can route to models directly (`/<model>/v1/messages`)
    /// without defining any pool. Carries the reserved `pools.hooks:` all-pools attach key (1.5.3);
    /// see [`PoolsCfg`].
    #[serde(default)]
    pub(crate) pools: PoolsCfg,
    /// The top-level `hooks:` NAMED-DEFINITION map (1.5.3): instance name → [`HookDefCfg`]. This
    /// REPLACES the removed `global_hooks:` list — hooks are DEFINED here once (which plugin backs
    /// each, its `groups:`/`phase:` scope, its role/projection) and REFERENCED by bare name from the
    /// all-pools `pools.hooks:` list or a per-pool `hooks:` list. Absent ⇒ no hooks.
    #[serde(default)]
    pub(crate) hooks: HookDefs,
    /// The top-level `groups:` block - THE one limit tree. Optional; absent = no groups.
    #[serde(default)]
    pub(crate) groups: std::collections::BTreeMap<String, GroupCfg>,
    /// The top-level `rate_card:` - the ONLY cost source. Per-model entry; ALL-OR-NOTHING:
    /// absent => token pricing is 0 for every model; present => AUTHORITATIVE and COMPLETE (every
    /// configured model must have an entry or boot/`--validate` FAIL naming the missing models).
    /// The numbers are ABSTRACT cost units (no currency, no FX).
    #[serde(default)]
    pub(crate) rate_card: Option<std::collections::BTreeMap<String, RateEntryCfg>>,
    /// Flat cents (abstract minor units) charged per request for budget accounting. Default 0.
    #[serde(default = "default_per_request_fee")]
    pub(crate) per_request_fee: i64,
    /// The durable store as `{ module, settings }`. Absent = the ephemeral RAM store.
    #[serde(default)]
    pub store: Option<StoreCfg>,
    /// Module-level `open()` config for `kind: secret` plugins, keyed by module name — the delivery
    /// path a Vault-style secret plugin needs (address / namespace / auth token / CA). Absent = every
    /// secret plugin opens with `{}`. Mirrors `store.settings` for the store plugin.
    #[serde(default)]
    pub(crate) secrets: std::collections::BTreeMap<String, SecretModuleCfg>,
    /// Internal tuning knobs (the `advanced:` block).
    #[serde(default)]
    pub advanced: AdvancedCfg,
    /// The top-level `export:` NAMED-DEFINITION map (1.5.3): instance name → [`ExportDefCfg`]. THE
    /// single telemetry-egress surface. Absent/empty ⇒ collection inert (no recorder, no request-log
    /// sink, no tracer).
    ///
    /// 1.5.3 also DELETED the `observability:` block outright: its last remaining field
    /// (`otlp_url`) is now an `export:` instance with `module: otlp`. A config still carrying
    /// `observability:` LOUD-FAILS with the `--migrate-config` breadcrumb.
    #[serde(default)]
    pub export: ExportDefs,
    /// The top-level `agents:` NAMED-DEFINITION map (1.6.0): agent NAME →
    /// [`crate::a2a::config::AgentDefCfg`]. THE A2A plane. Sibling in shape to `pools:` and
    /// `tools:`, carrying the same two reserved section words, and no entry on it may reference an
    /// entry on another plane. Absent ⇒ no agent is registered and nothing can be delegated to.
    // Type-erased through the neutral `AgentsSection` seam: the `agents:` registry deserializes into
    // the A2A plane's own `AgentsCfg` behind `dyn PlaneCfg`, so `DeployCfg` names no `crate::a2a`
    // registry type. The plane compiled out captures it raw and refuses a present section at
    // `resolve`.
    #[serde(default)]
    pub(crate) agents: AgentsSection,
    /// The top-level `streams:` section (1.6.0) — THE VOICE PLANE's owned config: the locked session
    /// defaults (media/VAD/`SessionConfig`) plus the three session ceilings (wall-clock, context
    /// window, per-response output tokens). SINGULAR typed section (one live-voice posture per
    /// deployment), NOT a named-definition map, so it carries no reserved section words and no
    /// registrations.
    // Type-erased through the neutral `StreamsSection` seam: `streams:` deserializes into the voice
    // plane's own `StreamsCfg` behind `dyn PlaneCfg`, so `DeployCfg` names no `busbar_voice` type. The
    // plane compiled out (voice off-default) captures it RAW and refuses a present section at
    // `resolve`, exactly as `tools:`/`agents:` do — so no `#[cfg]` guards the field itself.
    #[serde(default)]
    pub(crate) streams: StreamsSection,
    // 1.6.0 UNIFIED POOLS: the separate `tool_pools:` and `agent_pools:` sections are GONE. There is
    // ONE neutral top-level `pools:` (above); a pool's kind is INFERRED from its members and MCP/A2A
    // pools are projected to their plane carriers in `resolve`. A 1.5.4/1.6.0-dev config still
    // carrying `tool_pools:`/`agent_pools:` LOUD-FAILS here (unknown field) with the
    // `--migrate-config` breadcrumb, exactly as the retired `observability:` block does — the
    // migrator folds them into `pools:`.
    /// The dynamic plugin subsystem (`plugins:` block, top-level). Absent = disabled (the default
    /// `enabled: false` master switch): no plugin is ever discovered or loaded.
    #[serde(default)]
    pub plugins: PluginsCfg,
    /// Optional security controls. Today this carries only `blocked_metadata_hosts`, the operator
    /// extension to the hardcoded cloud-metadata SSRF denylist. Absent ⇒ only the hardcoded denylist
    /// applies.
    #[serde(default)]
    pub security: Option<SecurityCfg>,
    /// Operator-tunable global operational limits ("NEVER CODED CAPS"). Whole block optional; each
    /// field defaults to its historical hardcoded value (absent = today's behavior).
    #[serde(default)]
    pub(crate) limits: LimitsCfg,
    /// Process-wide active-probe fallbacks (per-lane overrides still win).
    #[serde(default)]
    pub(crate) health: HealthDefaultsCfg,
    /// Routing global default policy timeout (per-policy override still wins).
    #[serde(default)]
    pub(crate) routing: RoutingCfg,
}

impl DeployCfg {
    /// The operator-declared `providers_file:` pointer, if any — read by the bin's 1.6.0
    /// providers-override startup notice (the `providers_file` field is `pub(crate)`, so the bin
    /// crate needs this accessor). `None` ⇒ the key is absent from config.yaml.
    pub fn providers_file(&self) -> Option<&str> {
        self.providers_file.as_deref()
    }

    /// This plane-owned named-map section's always-present type-erased carrier, resolved by its
    /// config-section KEY — the seam the generic named-map machinery reaches a `tools:`/`agents:`
    /// registry through without naming a plane field. `None` for a key that is not a plane section
    /// (the two core sections, or an unknown key). The two plane fields exist unconditionally (they
    /// hold a `RawPlaneSection` when their plane is compiled out), so a present key always answers
    /// `Some`; the section KEYS are read off the frozen static
    /// [`busbar_substrate::plane::config::NAMED_MAP_SECTIONS`] mirror so this accessor spells no
    /// plane noun.
    pub(crate) fn plane_section(
        &self,
        section: &str,
    ) -> Option<&dyn crate::plane::config::PlaneCfg> {
        let mirror = busbar_substrate::plane::config::NAMED_MAP_SECTIONS;
        if section == mirror[2] {
            Some(&*self.tools.0)
        } else if section == mirror[3] {
            Some(&*self.agents.0)
        } else {
            None
        }
    }

    /// The mutable twin of [`DeployCfg::plane_section`] — the seam the named-map WRITE path installs a
    /// parsed `tools:`/`agents:` definition through, again resolved by config-section key so core
    /// names no plane field.
    pub(crate) fn plane_section_mut(
        &mut self,
        section: &str,
    ) -> Option<&mut dyn crate::plane::config::PlaneCfg> {
        let mirror = busbar_substrate::plane::config::NAMED_MAP_SECTIONS;
        if section == mirror[2] {
            Some(&mut *self.tools.0)
        } else if section == mirror[3] {
            Some(&mut *self.agents.0)
        } else {
            None
        }
    }
}

// Moved to `busbar_substrate::config::sections`; re-exported at its historical `config::` path.
pub use busbar_substrate::config::sections::SecurityCfg;

/// The top-level `plugins:` block — the ONLY configuration surface of the dynamic plugin subsystem.
/// A plugin is a plugin: store, auth, and hook plugins share this one block (one directory, one
/// trust model, one master switch); the manifest `kind` inside each signed tarball selects which
/// engine subsystem consumes it.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct PluginsCfg {
    /// MASTER SWITCH, default FALSE. When false (or the whole `plugins:` block is absent), NO
    /// plugin is ever loaded — a tarball dropped into the directory is INERT. Referencing a plugin
    /// while disabled (`store.module:` other than `memory`) is a BOOT ERROR naming this flag.
    #[serde(default)]
    pub enabled: bool,
    /// Directory the signed plugin tarballs live in. Default `plugins` (relative to the working
    /// directory).
    #[serde(default = "default_plugins_dir")]
    pub dir: String,
    /// Trust policy for plugin signatures. busbar's OWN release key is EMBEDDED in the binary —
    /// first-party plugins verify with zero configuration; this block is for THIRD-PARTY keys and
    /// the explicit untrusted opt-ins.
    #[serde(default)]
    pub(crate) trust: PluginsTrustCfg,
    /// ANTI-DOWNGRADE floors: plugin canonical `name` -> minimum acceptable `version`. Third-party
    /// only in practice — first-party plugins are automatically floored at the running binary's
    /// version. A floored plugin must prove (trusted signature, version at/above the floor) that it
    /// meets the floor; nothing else loads it. Sibling of `trust` (a version axis, not a trust axis).
    #[serde(default)]
    pub(crate) min_versions: std::collections::BTreeMap<String, String>,
    /// RUNTIME-ONLY (never in config, `#[serde(skip)]`): PER-PLUGIN FIRST-PARTY anti-downgrade floor
    /// OVERRIDES for EXPLICIT operator rollbacks (1.5.0). Empty (the default, and the ONLY value the
    /// automatic boot/reload path ever sees) = every first-party plugin uses the running binary's own
    /// version — the full automatic floor. An explicit, audited `POST /plugins/rollback` of a
    /// FIRST-PARTY plugin adds a `name -> pinned target version` entry so `busbar_plugin_sign::evaluate`
    /// admits the prior artifact for THAT NAME ONLY (an unpinned first-party plugin still faces the full
    /// floor — replacing the earlier single global floor). Derived from the persisted
    /// `plugin_versions` pins during a rebuild (`overlay::apply_plugin_versions_to_deploy`); it is
    /// never deserialized, so config parsing + `deny_unknown_fields` are unchanged.
    #[serde(skip)]
    pub(crate) first_party_floors: std::collections::BTreeMap<String, String>,
    /// Declarative plugin FETCH list (`plugins.fetch:`): tarballs busbar downloads into `dir` at
    /// boot (fatal-on-miss) and on `POST /plugins/reload` (warn-on-miss) BEFORE preflight. Each entry
    /// is a github release ref, a direct url, or an env var holding one — optionally sha256-pinned
    /// (integrity + download-skip cache key). NOT consulted by `--validate` (zero-network contract).
    /// Signature verification remains the trust gate; sha256 is integrity/cache only. Default empty.
    #[serde(default)]
    pub(crate) fetch: Vec<PluginFetch>,
}

/// One `plugins.fetch:` entry — an UNTAGGED enum discriminated by which key is present. `github` is a
/// `org/repo@tag` release ref (asset resolved by the loader); `url` is a direct tarball URL; `env`
/// names an environment variable holding a URL (or `url@sha256`). `sha256` (github/url) is the
/// lowercase-hex integrity pin: it is BOTH the download-skip cache key (a file in `dir` already
/// hashing to it ⇒ no network) and the verify-before-write gate. Per-variant `deny_unknown_fields`
/// so a typo'd key can't be silently reinterpreted as a different variant.
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub(crate) enum PluginFetch {
    /// `- { github: "org/repo@v1.2.3", sha256?: "…" }`
    Github(GithubFetch),
    /// `- { url: "https://host/plugin.tar.gz", sha256?: "…" }`
    Url(UrlFetch),
    /// `- { env: "BUSBAR_PLUGIN_URL" }` (the VAR holds a url, or `url@sha256`)
    Env(EnvFetch),
}

/// The `{ github, sha256? }` fetch shape. `deny_unknown_fields` on each variant struct is what gives
/// the untagged enum real typo rejection: an entry with a stray key matches NO variant and errors,
/// rather than being silently reinterpreted.
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct GithubFetch {
    pub(crate) github: String,
    #[serde(default)]
    pub(crate) sha256: Option<String>,
}

/// The `{ url, sha256? }` fetch shape.
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct UrlFetch {
    pub(crate) url: String,
    #[serde(default)]
    pub(crate) sha256: Option<String>,
}

/// The `{ env }` fetch shape (the VAR's value is a url, optionally `url@sha256`).
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnvFetch {
    pub(crate) env: String,
}

/// The tarball filename inside `plugins.dir` a fetch URL writes to: the last path segment (before any
/// `?`/`#`), which must be non-empty. Errors if the URL has no usable basename.
fn fetch_filename_from_url(url: &str) -> Result<String, String> {
    let path = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let path = path.split(['?', '#']).next().unwrap_or(path);
    let base = path.rsplit('/').next().unwrap_or("");
    if base.is_empty() {
        return Err(format!(
            "plugins.fetch url '{url}' has no filename (a signed tarball basename is required)"
        ));
    }
    Ok(base.to_string())
}

/// Map one [`PluginFetch`] to a loader [`busbar_plugin_loader::FetchSpec`].
fn fetch_spec_from(f: &PluginFetch) -> Result<busbar_plugin_loader::FetchSpec, String> {
    match f {
        PluginFetch::Github(g) => {
            // "org/repo@tag" → the GitHub release-asset URL. busbar plugins ship one signed
            // `{repo}.tar.gz` per release, so the asset name is derived, not discovered.
            let (repo_path, tag) = g.github.split_once('@').ok_or_else(|| {
                format!(
                    "plugins.fetch github '{}' must be 'org/repo@tag' (missing '@tag')",
                    g.github
                )
            })?;
            let (org, repo) = repo_path.split_once('/').ok_or_else(|| {
                format!(
                    "plugins.fetch github '{}' must be 'org/repo@tag' (missing 'org/repo')",
                    g.github
                )
            })?;
            if org.is_empty() || repo.is_empty() || tag.is_empty() {
                return Err(format!(
                    "plugins.fetch github '{}' must be a non-empty 'org/repo@tag'",
                    g.github
                ));
            }
            let filename = format!("{repo}.tar.gz");
            let url = format!("https://github.com/{org}/{repo}/releases/download/{tag}/{filename}");
            Ok(busbar_plugin_loader::FetchSpec {
                url,
                sha256: g.sha256.clone(),
                filename,
            })
        }
        PluginFetch::Url(u) => Ok(busbar_plugin_loader::FetchSpec {
            url: u.url.clone(),
            sha256: u.sha256.clone(),
            filename: fetch_filename_from_url(&u.url)?,
        }),
        PluginFetch::Env(e) => {
            let raw = std::env::var(&e.env).map_err(|_| {
                format!(
                    "plugins.fetch env '{}' is not set (it must hold a url or 'url@sha256')",
                    e.env
                )
            })?;
            // The var value is `url` or `url@sha256`. Split on the LAST '@' so a userinfo '@' in the
            // URL isn't mistaken for the pin separator (pins are hex, no '@').
            let (url, sha256) = match raw.rsplit_once('@') {
                Some((u, s)) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit()) => {
                    (u.to_string(), Some(s.to_string()))
                }
                _ => (raw.clone(), None),
            };
            Ok(busbar_plugin_loader::FetchSpec {
                filename: fetch_filename_from_url(&url)?,
                url,
                sha256,
            })
        }
    }
}

impl Default for PluginsCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            dir: default_plugins_dir(),
            trust: PluginsTrustCfg::default(),
            min_versions: std::collections::BTreeMap::new(),
            first_party_floors: std::collections::BTreeMap::new(),
            fetch: Vec::new(),
        }
    }
}

/// `plugins.trust` — how the engine treats plugin signatures. A first-party (busbar-signed) plugin
/// verifies against the EMBEDDED release key; a third-party plugin verifies against `publishers`;
/// anything else (unsigned, tampered, unknown publisher) is UNTRUSTED and, by DEFAULT, logged and
/// SKIPPED (never `dlopen`ed) unless the matching opt-in flag is set.
#[derive(Deserialize, Clone, Default, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct PluginsTrustCfg {
    /// THIRD-PARTY allowlist: publishers whose signatures mark a plugin TRUSTED. Each maps a
    /// publisher name to a hex ed25519 public key. The first-party `busbar` key is embedded in the
    /// binary and never configured here.
    #[serde(default)]
    pub(crate) publishers: Vec<PluginPublisher>,
    /// EXPLICIT opt-in: load plugins that carry NO valid signature (unsigned / tampered). Default
    /// `false` — an unsigned plugin found in `plugins.dir` is LOGGED and SKIPPED (never `dlopen`ed
    /// / executed), at boot and in the admin catalog.
    #[serde(default)]
    pub(crate) allow_unsigned: bool,
    /// EXPLICIT opt-in: load plugins that ARE validly signed but by a publisher NOT in
    /// `publishers`. Default `false` — a third-party-signed plugin is LOGGED and SKIPPED.
    #[serde(default)]
    pub(crate) allow_third_party: bool,
}

/// One allowlisted plugin publisher: a name and its hex ed25519 public key.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct PluginPublisher {
    pub(crate) name: String,
    pub(crate) public_key: String,
}

impl PluginsCfg {
    /// Resolve `plugins.fetch:` into the loader's [`busbar_plugin_loader::FetchSpec`] list: each
    /// entry becomes a `{ url, sha256?, filename }`. `github: "org/repo@tag"` → the release-asset
    /// download URL (busbar's one-file-per-plugin `{repo}.tar.gz` convention); `url:` → itself, with
    /// the target filename taken from the URL basename; `env:` → the named var's value (a `url` or
    /// `url@sha256`), erroring if the var is unset. Called at boot/reload BEFORE the fetch; never in
    /// `--validate` (the zero-network contract).
    pub(crate) fn fetch_specs(&self) -> Result<Vec<busbar_plugin_loader::FetchSpec>, String> {
        self.fetch.iter().map(fetch_spec_from).collect()
    }

    /// Resolve into the `busbar-plugin-sign` trust policy: the EMBEDDED first-party release key +
    /// the binary's own version (the automatic first-party anti-downgrade floor) + the configured
    /// third-party publishers/opt-ins/floors. A malformed publisher key is a boot error, not a
    /// silent skip (a skipped trust anchor could wrongly reject a good plugin).
    pub fn to_policy(&self) -> Result<busbar_plugin_sign::TrustPolicy, String> {
        // The AUTOMATIC anti-downgrade posture: the first-party floor is the running binary's own
        // version, so a validly-signed but OLD first-party artifact can never be REPLAYED into a newer
        // binary and silently accepted as "current". This is the policy every automatic path
        // (boot / config reload / config apply / admin plugin reload) uses — UNLESS an explicit,
        // audited rollback has set `first_party_floor` (a runtime-only, serde-skip field derived from
        // the persisted `plugin_versions` pins), in which case the operator's pinned floor stands.
        // `first_party_floors` is EMPTY on every path except a rebuild carrying persisted rollback
        // pins, so the automatic guarantee is unchanged by default. Each entry lowers the floor for
        // ONE named first-party plugin only; every other first-party plugin still faces the
        // running binary's version.
        self.to_policy_with_floor(env!("CARGO_PKG_VERSION"))
    }

    /// Build the trust policy. `binary_version` is carried on the policy for error text/telemetry
    /// only — it is NOT a floor: `busbar_plugin_sign::evaluate` applies PER-NAME floors alone
    /// (`first_party_floors` rollback pins + `min_versions`), because first-party plugins version
    /// on independent lines (1.0.x stores/auth/hooks, 2.x headroom, under a 1.5.0 engine) and an
    /// automatic "plugin >= binary version" floor rejected every correctly-signed current release
    /// (removed before 1.5.0 shipped; see plugin-sign's evaluate() for the full rationale).
    ///
    /// Anti-downgrade still holds per name: an explicit operator ROLLBACK (Full-scope, If-Match,
    /// audited) persists a per-name pin via the overlay `plugin_versions` mechanism (see
    /// `overlay::apply_plugin_versions_to_deploy`), and `plugins.min_versions` floors first- and
    /// third-party alike. (Future: the plugin registry embeds known per-plugin floors at release
    /// time, restoring zero-config anti-replay without version-line coupling.)
    pub(crate) fn to_policy_with_floor(
        &self,
        binary_version: &str,
    ) -> Result<busbar_plugin_sign::TrustPolicy, String> {
        let mut publishers = std::collections::BTreeMap::new();
        for p in &self.trust.publishers {
            if p.name == busbar_plugin_sign::FIRST_PARTY_PUBLISHER {
                return Err(format!(
                    "plugins.trust.publishers['{}']: the publisher name '{}' is reserved for \
                     busbar's embedded release key and cannot be configured",
                    p.name,
                    busbar_plugin_sign::FIRST_PARTY_PUBLISHER
                ));
            }
            let key = busbar_plugin_sign::public_key_from_hex(&p.public_key)
                .map_err(|e| format!("plugins.trust.publishers['{}']: {e}", p.name))?;
            publishers.insert(p.name.clone(), key);
        }
        // A malformed floor is not a config error (it does not stop the boot — `version_at_least`
        // fails closed at the comparator, refusing just the one floored plugin) but
        // it IS worth telling the operator about early, before an artifact is even present: an
        // unparsable floor silently disarms the anti-downgrade control, so an operator who believes
        // it is armed should not have to discover that from a missing `--list-plugins` row.
        for (name, floor) in &self.min_versions {
            if !floor.is_empty() && !busbar_plugin_sign::valid_semver(floor) {
                diag_warn!(
                    CONFIG_ANTIDOWNGRADE_FLOOR_INVALID,
                    key = %format!("plugins.min_versions['{name}']"),
                    value = %floor,
                    "anti-downgrade floor is not a valid MAJOR.MINOR.PATCH version (no leading \
                     'v'); it cannot be satisfied, so this plugin will be refused. Fix or remove \
                     the entry."
                );
            }
        }
        for (name, floor) in &self.first_party_floors {
            if !floor.is_empty() && !busbar_plugin_sign::valid_semver(floor) {
                diag_warn!(
                    CONFIG_FIRSTPARTY_FLOOR_INVALID,
                    key = %format!("plugins.first_party_floors['{name}']"),
                    value = %floor,
                    "anti-downgrade floor is not a valid MAJOR.MINOR.PATCH version (no leading \
                     'v'); it cannot be satisfied, so this plugin will be refused — and this pin \
                     REPLACES the binary-version floor, so the plugin is refused unconditionally \
                     until this is fixed. Fix or remove the entry."
                );
            }
        }
        Ok(busbar_plugin_sign::TrustPolicy {
            first_party_key: busbar_plugin_sign::embedded_release_pubkey(),
            binary_version: binary_version.to_string(),
            first_party_floors: self.first_party_floors.clone(),
            publishers,
            allow_unsigned: self.trust.allow_unsigned,
            allow_third_party: self.trust.allow_third_party,
            min_versions: self.min_versions.clone(),
        })
    }
}

// The `store:` block and the `secrets:` per-module init block are plain serde data (`{ module,
// settings }` shapes). Moved to `busbar_substrate::config::sections`; re-exported at their
// historical `config::` path.
pub use busbar_substrate::config::sections::{
    default_governance_store, SecretModuleCfg, StoreCfg, GOVERNANCE_STORE_MEMORY,
};

// The `advanced:` block (INTERNAL tuning knobs) and its nested `response_headers:` block are plain
// serde data with `Default` impls that route through the same shared consts as their `#[serde(default
// = ...)]` fns, so the omitted-block and omitted-field paths cannot drift. Moved to
// `busbar_substrate::config::sections`; re-exported at their historical `config::` path. Needed here
// (not just at their own call sites) because `LimitsResolved::from_sections` takes `&AdvancedCfg`.
pub use busbar_substrate::config::sections::{
    default_response_headers_route_policy, default_response_headers_server_timing, AdvancedCfg,
    ResponseHeadersCfg, DEFAULT_RESPONSE_HEADERS_ROUTE_POLICY, DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
};

// The `config:` config-management-policy block, its `overlay:` backend selector, the `rate_card:`
// entry, and the `export:` NAMED-DEFINITION entry (+ its module vocabulary) are plain serde data.
// Moved to `busbar_substrate::config::sections`; re-exported at their historical `config::` path.
pub use busbar_substrate::config::sections::{
    rate_entry_per_mtok, ConfigMgmtCfg, ExportDefCfg, ExportDefs, OverlayBackend, OverlayCfg,
    RateEntryCfg, EXPORT_MODULES, EXPORT_MODULE_OTLP, EXPORT_MODULE_PROMETHEUS,
    EXPORT_MODULE_REQUEST_LOG_FILE, EXPORT_MODULE_REQUEST_LOG_WEBHOOK,
};

/// The serde default for `per_request_fee:` - 0 (no flat per-request charge; token spend derives
/// from the ledger x rate_card).
fn default_per_request_fee() -> i64 {
    0
}

/// The RESOLVED `export:` block: the typed, per-module projection [`resolve_export`] lowers the named
/// definition map into, and the shape every runtime consumer reads. NOT deserialized from YAML (the
/// on-disk shape is [`ExportDefs`]).
///
/// Note the asymmetry, which is deliberate and load-bearing: the two LOG sinks are `Vec`s (multiple
/// named instances are the whole point of the named map), while `prometheus` and `otlp` are at most
/// ONE each — `prometheus` owns the single well-known `/metrics` route and `otlp` installs the one
/// process-global tracer subscriber, so a second instance could not do anything except silently lose.
/// A second instance of either is therefore a loud boot error, never a silent no-op.
///
/// Each sink's settings carry that instance's resolved [`crate::export::projection::Projection`] —
/// the streams + fields THAT sink is granted. Core builds every payload TO that projection, so an
/// ungranted field is never serialized and never crosses the ABI.
#[derive(Debug, Clone, Default)]
pub struct ExportCfg {
    /// The `prometheus` instance's settings, if one is configured. `None` ⇒ no recorder installed,
    /// `/metrics` not mounted, every emit site a true no-op (the zero-config default).
    pub prometheus: Option<PrometheusSettings>,
    /// Every configured `request-log-webhook` instance, in config order. Empty ⇒ no webhook sink.
    pub(crate) request_log_webhooks: Vec<WebhookSettings>,
    /// Every configured `request-log-file` instance, in config order. Empty ⇒ no file sink.
    pub(crate) request_log_files: Vec<FileSettings>,
    /// The `otlp` instance's settings, if one is configured. `None` ⇒ no tracer/span export.
    pub otlp: Option<OtlpSettings>,
}

impl ExportCfg {
    /// The generation's UNION OF PROJECTIONS — "what does ANYTHING configured here want". Computed
    /// ONCE per config apply and carried on the `App` (next to `requested_signals`, which is the
    /// same mechanism for hook signals), then read per request as the COMPUTE GATE: core generates a
    /// stream's records ONLY when some sink declared it. Supersedes the one-off
    /// `export::request_log_configured()` boolean — one mechanism, not two.
    pub(crate) fn projection_union(&self) -> crate::export::projection::ProjectionUnion {
        crate::export::projection::ProjectionUnion::of(
            self.prometheus
                .iter()
                .map(|s| &s.projection)
                .chain(self.request_log_webhooks.iter().map(|s| &s.projection))
                .chain(self.request_log_files.iter().map(|s| &s.projection))
                .chain(self.otlp.iter().map(|s| &s.projection)),
        )
    }
}

/// The two limits `LimitsResolved` sources from the resolved `export:` block rather than from
/// `limits:` itself (1.5.3: moved from the retired `observability.*`/`metrics.*` keys onto the
/// built-in EXPORTER settings). `busbar_substrate::config::limits::LimitsResolved::from_sections`
/// takes anything that converts to `ExportLimits`, so core (the only crate that knows the typed
/// `ExportCfg` shape) hands the reduction across through this `From` impl instead of the resolver
/// re-walking `export.*` itself.
impl From<&ExportCfg> for busbar_substrate::config::limits::ExportLimits {
    fn from(export: &ExportCfg) -> Self {
        // `max_inflight_webhook_deliveries` seeds ONE shared `AdmissionGate` across every webhook
        // instance, so with several named instances it takes the MAXIMUM of the CONFIGURED values:
        // the shared bound must accommodate the most permissive sink, or a generous instance would be
        // silently throttled by a stingy sibling. No instances ⇒ the historical default. (The
        // per-delivery TIMEOUT needs no such reconciliation and is NOT projected here: it is applied
        // per instance off `WebhookSettings::delivery_timeout_secs` at the delivery site, and bounds
        // -checked per instance by `config_validate` — which is what named instances are FOR.)
        let max_inflight_webhook_deliveries = export
            .request_log_webhooks
            .iter()
            .map(|w| w.max_inflight_deliveries)
            .max()
            .unwrap_or_else(default_max_inflight_webhook_deliveries);
        let key_gauge_limit = export
            .prometheus
            .as_ref()
            .map_or_else(default_key_gauge_limit, |p| p.key_gauge_limit);
        Self {
            max_inflight_webhook_deliveries,
            key_gauge_limit,
        }
    }
}

/// `settings:` of an `export.<name>.module: prometheus` instance — relocated from the retired
/// `observability.metrics` block.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PrometheusSettings {
    /// Retention window (SECONDS) for the rolling quantile summary — REQUIRED, exactly as the retired
    /// `observability.metrics.buffer_seconds` was (turning metrics on is a deliberate choice + a
    /// memory cost the operator names).
    pub buffer_seconds: u64,
    #[serde(default = "default_key_gauge_limit")]
    pub(crate) key_gauge_limit: usize,
    /// THIS INSTANCE'S RESOLVED PROJECTION — the streams + fields this sink is granted, from its
    /// `streams:` / `fields:` keys (see `crate::export::projection`). NOT an operator key: it is
    /// `#[serde(skip)]` so the `settings:` bag stays exactly what the operator wrote, and it is
    /// filled in by [`resolve_export`]. It rides here so the delivery path can build this sink's
    /// payload TO ITS PROJECTION without a second lookup keyed on instance name.
    #[serde(skip)]
    pub(crate) projection: crate::export::projection::Projection,
}

/// `settings:` of an `export.<name>.module: request-log-webhook` instance — relocated from the retired
/// `observability` webhook keys. Also absorbs the retired `generic-webhook` exporter: its ONLY extra
/// over this one was `auth_header:`, which is now just a setting here, and its other reason to exist
/// (a SECOND webhook target) is what the named-instance map itself provides.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WebhookSettings {
    /// The webhook target URL — REQUIRED, `https://`-only, SSRF-guarded (relocated from the retired
    /// `observability.request_log_webhook_url`).
    pub(crate) url: String,
    /// An optional auth header applied to every delivery from THIS instance (e.g.
    /// `{ name: Authorization, value: "Bearer ${WEBHOOK_TOKEN}" }`). The `value` rides the config's
    /// `${VAR}` env interpolation, so a secret is never stored literally.
    #[serde(default)]
    pub(crate) auth_header: Option<ExportAuthHeader>,
    /// Max concurrent deliveries (default 64) — relocated from `max_inflight_webhook_deliveries`.
    #[serde(default = "default_max_inflight_webhook_deliveries")]
    pub(crate) max_inflight_deliveries: usize,
    /// Per-delivery timeout (seconds, default 2) — relocated from `webhook_delivery_timeout_secs`.
    /// Applied PER INSTANCE (each sink carries its own deadline), which is what having named
    /// instances is for.
    #[serde(default = "default_webhook_delivery_timeout_secs")]
    pub(crate) delivery_timeout_secs: u64,
    /// THIS INSTANCE'S RESOLVED PROJECTION — the streams + fields this sink is granted, from its
    /// `streams:` / `fields:` keys (see `crate::export::projection`). NOT an operator key: it is
    /// `#[serde(skip)]` so the `settings:` bag stays exactly what the operator wrote, and it is
    /// filled in by [`resolve_export`]. It rides here so the delivery path can build this sink's
    /// payload TO ITS PROJECTION without a second lookup keyed on instance name.
    #[serde(skip)]
    pub(crate) projection: crate::export::projection::Projection,
}

/// `settings:` of an `export.<name>.module: request-log-file` instance.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileSettings {
    /// The JSONL file path each request-log line is appended to — REQUIRED.
    pub(crate) path: String,
    /// Optional size (MiB) at which the file is rotated (best-effort; absent ⇒ never rotate).
    #[serde(default)]
    pub(crate) rotate_mb: Option<u64>,
    /// THIS INSTANCE'S RESOLVED PROJECTION — the streams + fields this sink is granted, from its
    /// `streams:` / `fields:` keys (see `crate::export::projection`). NOT an operator key: it is
    /// `#[serde(skip)]` so the `settings:` bag stays exactly what the operator wrote, and it is
    /// filled in by [`resolve_export`]. It rides here so the delivery path can build this sink's
    /// payload TO ITS PROJECTION without a second lookup keyed on instance name.
    #[serde(skip)]
    pub(crate) projection: crate::export::projection::Projection,
}

/// `settings:` of an `export.<name>.module: otlp` instance — the new home of the DELETED
/// `observability.otlp_url`. The tracer/log-init machinery in `crate::observability` is
/// unchanged; only the config surface that drives it moved.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OtlpSettings {
    /// OTLP/HTTP traces endpoint URL (e.g. `http://localhost:4318/v1/traces`) — REQUIRED. When an
    /// `otlp` export instance is present busbar installs an OpenTelemetry tracer + exports spans.
    pub url: String,
    /// THIS INSTANCE'S RESOLVED PROJECTION — the streams + fields this sink is granted, from its
    /// `streams:` / `fields:` keys (see `crate::export::projection`). NOT an operator key: it is
    /// `#[serde(skip)]` so the `settings:` bag stays exactly what the operator wrote, and it is
    /// filled in by [`resolve_export`]. It rides here so the delivery path can build this sink's
    /// payload TO ITS PROJECTION without a second lookup keyed on instance name.
    #[serde(skip)]
    pub(crate) projection: crate::export::projection::Projection,
}

/// One `{ name, value }` auth header for a webhook export instance.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExportAuthHeader {
    pub(crate) name: String,
    pub(crate) value: String,
}

/// Lower the `export:` NAMED-DEFINITION map into the typed [`ExportCfg`] every runtime consumer reads.
/// Errors are ACCUMULATED (not short-circuited) so `--validate` reports every bad exporter at once,
/// the same posture `resolve` takes everywhere else.
///
/// Enforced here:
/// - an unknown `module:` is a boot error naming the four built-ins (never a silently-ignored sink);
/// - a bad/typo'd key inside `settings:` is a boot error (each settings struct is
///   `deny_unknown_fields`, so the opaque bag is only opaque to the OUTER layer);
/// - a SECOND `prometheus` or `otlp` instance is a boot error (see [`ExportCfg`] — those two are
///   process-singleton by construction and a second one could only lose silently);
/// - the instance's PROJECTION (`streams:` / `fields:` / `durable:`) is resolved + validated by
///   [`crate::export::projection::resolve_projection`], which is where the HARD RULE lives: a stream
///   with no producer in this release, a stream the module cannot carry, a `fields:` list that omits
///   a pinned field, and `durable: true` are all LOUD errors here rather than a sink that validates
///   and delivers nothing.
pub fn resolve_export(defs: &ExportDefs, errors: &mut Vec<String>) -> ExportCfg {
    let mut out = ExportCfg::default();
    // The instance name that already claimed each singleton module, for the "named twice" diagnostic.
    let mut prometheus_owner: Option<&str> = None;
    let mut otlp_owner: Option<&str> = None;

    for (name, def) in defs {
        let projection = crate::export::projection::resolve_projection(
            name,
            def.module.trim(),
            def.streams.as_deref(),
            def.fields.as_deref(),
            def.durable,
            errors,
        );
        let settings = serde_json::Value::Object(def.settings.clone());
        // Parse the opaque bag into this module's typed settings struct. One helper so every module
        // produces the identical `export.<name>.settings: …` error prefix.
        macro_rules! typed {
            ($t:ty) => {
                match serde_json::from_value::<$t>(settings) {
                    // The resolved projection rides onto the typed settings here, so every sink the
                    // delivery path sees already carries the bound on what it may be handed. There
                    // is no path that produces settings WITHOUT a projection.
                    Ok(mut v) => {
                        v.projection = projection;
                        Some(v)
                    }
                    Err(e) => {
                        errors.push(format!("export.{name}.settings: {e}"));
                        None
                    }
                }
            };
        }
        match def.module.trim() {
            EXPORT_MODULE_PROMETHEUS => {
                if let Some(owner) = prometheus_owner {
                    errors.push(format!(
                        "export.{name}: a second `module: prometheus` instance (already defined as \
                         '{owner}'). Prometheus serves the ONE well-known /metrics route, so a \
                         second instance could only be silently ignored — keep a single instance."
                    ));
                    continue;
                }
                prometheus_owner = Some(name);
                out.prometheus = typed!(PrometheusSettings);
            }
            EXPORT_MODULE_REQUEST_LOG_WEBHOOK => {
                if let Some(v) = typed!(WebhookSettings) {
                    out.request_log_webhooks.push(v);
                }
            }
            EXPORT_MODULE_REQUEST_LOG_FILE => {
                if let Some(v) = typed!(FileSettings) {
                    out.request_log_files.push(v);
                }
            }
            EXPORT_MODULE_OTLP => {
                if let Some(owner) = otlp_owner {
                    errors.push(format!(
                        "export.{name}: a second `module: otlp` instance (already defined as \
                         '{owner}'). OTLP installs the ONE process-global tracer subscriber, so a \
                         second instance could only be silently ignored — keep a single instance."
                    ));
                    continue;
                }
                otlp_owner = Some(name);
                out.otlp = typed!(OtlpSettings);
            }
            other => errors.push(format!(
                "export.{name}.module: unknown exporter '{other}'; the built-in export modules are \
                 {}",
                EXPORT_MODULES.join(" | ")
            )),
        }
    }
    out
}

// ───────────────────────────────────────────────────────────────────────────────────────────────
// The operational-limit config SHAPES ("NEVER CODED CAPS"): the historical default constants, the
// `limits:` / `health:` / `routing:` blocks and the flat resolved `LimitsResolved` every startup
// wire reads. Every field defaults — via a `default = "fn"` whose body is the historical hardcoded
// const — to today's behavior, so an absent key (the common case) is byte-for-byte unchanged. Moved
// to `busbar_substrate::config::limits`; the process-wide INSTALL of the resolved values and the
// `ExportCfg` → `ExportLimits` reduction (see the `From` impl above `ExportCfg`) stay here.
// Re-exported at their historical `config::` path so no caller moves.
pub use busbar_substrate::config::limits::{
    default_default_max_tokens, default_hard_down_cooldown_secs, default_hook_content_max_bytes,
    default_key_gauge_limit, default_max_auto_provisioned_groups,
    default_max_honored_retry_after_secs, default_max_inbound_concurrent,
    default_max_inflight_webhook_deliveries, default_max_keys_per_principal,
    default_pool_idle_timeout_secs, default_pool_max_idle_per_host, default_probe_interval_secs,
    default_probe_timeout_secs, default_rate_sweep_interval, default_reasoning_high,
    default_reasoning_low, default_reasoning_medium, default_reasoning_minimal,
    default_request_body_max_bytes, default_request_body_read_timeout_secs,
    default_tls_handshake_timeout_secs, default_upstream_error_body_max_bytes,
    default_upstream_request_timeout_secs, default_usage_flush_interval_ms,
    default_webhook_delivery_timeout_secs, ExportLimits, HealthDefaultsCfg, LimitsCfg,
    LimitsResolved, ReasoningEffortBudgets, RoutingCfg,
    DEFAULT_DEFAULT_MAX_TOKENS, DEFAULT_HARD_DOWN_COOLDOWN_SECS, DEFAULT_KEY_GAUGE_LIMIT,
    DEFAULT_MAX_HONORED_RETRY_AFTER_SECS, DEFAULT_MAX_INBOUND_CONCURRENT,
    DEFAULT_MAX_INFLIGHT_WEBHOOK_DELIVERIES, DEFAULT_PLUGIN_FETCH_MAX_BYTES,
    DEFAULT_POOL_IDLE_TIMEOUT_SECS, DEFAULT_POOL_MAX_IDLE_PER_HOST, DEFAULT_PROBE_INTERVAL_SECS,
    DEFAULT_PROBE_TIMEOUT_SECS,
    DEFAULT_RATE_SWEEP_INTERVAL, DEFAULT_REQUEST_BODY_MAX_BYTES,
    DEFAULT_REQUEST_BODY_READ_TIMEOUT_SECS, DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS,
    DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES, DEFAULT_UPSTREAM_REQUEST_TIMEOUT_SECS,
    DEFAULT_USAGE_FLUSH_INTERVAL_MS, DEFAULT_WEBHOOK_DELIVERY_TIMEOUT_SECS,
    REQUEST_BODY_MAX_BYTES_CEIL, REQUEST_BODY_MAX_BYTES_FLOOR,
};

fn default_plugins_dir() -> String {
    "plugins".to_string()
}


/// Resolve DeployCfg + ProviderDef map into resolved RootCfg.
/// For each deployed provider, look up its definition by name; produce a resolved ProviderCfg
/// = def's protocol/base_url/error_map (with any config.yaml override applied) + the deployment's api_key_env.
/// Build a runtime [`HookCfg`] registry entry from one top-level `hooks:` NAMED DEFINITION (1.5.3).
/// `module:` names the `kind: hook` PLUGIN that backs the hook (by signed-manifest name/alias) and
/// lowers to the runtime `plugin:` field; `settings:` stays fully opaque (pushed to the plugin via
/// `configure`). The `groups:`/`phase:` SELECTION scope carries onto the `HookCfg` for the firing
/// filter. The plugin reference must be non-empty; an unresolvable/wrong-kind reference is caught
/// fail-closed at the plugin pre-flight (like a store/auth ref). A named hook attached to a pool is a
/// decision point by default, so an unset `kind:` defaults to `gate`.
fn hook_cfg_from_def(def: &HookDefCfg) -> Result<HookCfg, String> {
    let plugin = def.module.trim().to_string();
    if plugin.is_empty() {
        return Err(
            "a hook definition must name a non-empty `module:` (a `kind: hook` plugin)".to_string(),
        );
    }
    Ok(HookCfg {
        kind: def.kind.unwrap_or(HookKind::Gate),
        plugin,
        timeout_ms: def.timeout_ms.unwrap_or(DEFAULT_POLICY_TIMEOUT_MS),
        on_error: def
            .on_error
            .as_ref()
            .map(|o| o.as_name().to_string())
            .unwrap_or_else(default_on_error),
        prompt: def.prompt.unwrap_or_default(),
        user: def.user.unwrap_or_default(),
        priority: def.priority.unwrap_or(0),
        on_empty: def.on_empty.clone(),
        settings: def.settings.clone(),
        // A named-definition shorthand has no `signals:` sub-key in this pass.
        signals: Vec::new(),
        global: false,
        default: false,
        groups: def.groups.clone(),
        phase: def.phase.clone(),
    })
}

#[cold] // boot/admin-only — keeps hot text dense (never inlined into a warm path)
#[inline(never)]
pub fn resolve(
    deploy: &DeployCfg,
    defs: &HashMap<String, ProviderDef>,
) -> Result<RootCfg, Vec<String>> {
    let mut errors = Vec::new();

    // Lower the `export:` NAMED-DEFINITION map into the typed per-module projection. Unknown modules,
    // bad settings, and duplicate singleton instances land in `errors` here.
    let export = resolve_export(&deploy.export, &mut errors);

    // A prometheus instance with `buffer_seconds: 0` would ask busbar to retain observations for no
    // time at all: the rolling window is empty at every scrape, so `/metrics` renders quantiles over
    // nothing while the hot path still pays the full recording cost — opted-in metrics that report
    // nothing. Omitting the instance is how collection is turned OFF; `0` is not that, so it fails
    // boot loudly rather than silently producing an inert collector.
    if export
        .prometheus
        .as_ref()
        .is_some_and(|p| p.buffer_seconds == 0)
    {
        errors.push(
            "the `module: prometheus` export instance sets settings.buffer_seconds: 0, which \
             retains no observations — every scrape would report empty quantiles while still paying \
             the recording cost. Name a positive retention window in seconds, or remove the \
             instance to turn metrics off"
                .to_string(),
        );
    }
    let mut resolved_providers: HashMap<String, ProviderCfg> = HashMap::new();

    for (deploy_name, deploy_cfg) in &deploy.providers {
        // Look up the provider definition by name
        let def = match defs.get(deploy_name) {
            Some(d) => d,
            None => {
                errors.push(format!(
                    "provider '{}' referenced in config.yaml not found in providers.yaml",
                    deploy_name
                ));
                continue;
            }
        };

        // Apply overrides from deployment (rarely used)
        let protocol = deploy_cfg
            .protocol
            .clone()
            .unwrap_or_else(|| def.protocol.clone());
        let base_url = deploy_cfg
            .base_url
            .clone()
            .unwrap_or_else(|| def.base_url.clone());

        // Merge error_map: def's map with deployment override taking precedence
        let mut error_map = def.error_map.clone();
        if let Some(override_map) = &deploy_cfg.error_map {
            for (code, class) in override_map {
                error_map.insert(code.clone(), class.clone());
            }
        }

        resolved_providers.insert(
            deploy_name.clone(),
            ProviderCfg {
                protocol,
                base_url,
                api_key: deploy_cfg.api_key.clone(),
                // Deployment health config wins over the catalog default (mirrors path/auth), so
                // the `health:` block documented in config.yaml actually takes effect.
                health: deploy_cfg.health.clone().or_else(|| def.health.clone()),
                error_map,
                // deployment override wins over the catalog default
                path: deploy_cfg.path.clone().or_else(|| def.path.clone()),
                path_base: deploy_cfg
                    .path_base
                    .clone()
                    .or_else(|| def.path_base.clone()),
                token_url: deploy_cfg
                    .token_url
                    .clone()
                    .or_else(|| def.token_url.clone()),
                scope: deploy_cfg.scope.clone().or_else(|| def.scope.clone()),
                subject: deploy_cfg.subject.clone().or_else(|| def.subject.clone()),
                auth: deploy_cfg.auth.or(def.auth),
                // deployment override (Some) replaces the catalog default
                allow_metadata_hosts: deploy_cfg
                    .allow_metadata_hosts
                    .clone()
                    .unwrap_or_else(|| def.allow_metadata_hosts.clone()),
            },
        );
    }

    // 1.5.3 NAMED-HOOKS: build the runtime hook registry from the top-level `hooks:` DEFINITION map
    // (define-once). Each definition becomes a `HookCfg` registry entry keyed by its own name (the
    // instance id); the SAME `module` may back multiple names, each an independent hook with its own
    // `groups:`/`phase:` scope. A definition name may not shadow a reserved terminal / built-in
    // strategy (validated). References BY BARE NAME then resolve against this registry: the reserved
    // all-pools list (`pools.hooks:`) lowers to the runtime `global_hooks` (fires on EVERY pool), and
    // each pool's own bare names populate `pool.gates`. An unresolvable/wrong-kind plugin behind a
    // `module:` is a FAIL-CLOSED plugin-preflight error (like a store/auth ref).
    let mut hooks_registry: HashMap<String, HookCfg> = HashMap::new();
    let mut pools = deploy.pools.pools.clone();
    // FREEZE BLOCKER — additive-list DEDUPE. A hook named in BOTH `pools.hooks:` and a pool's own
    // `hooks:` fires ONCE, at its FIRST (section-level) position. The section list is fired through
    // `App::global_gates` and the pool's own through `PoolRuntime::gates`, so the dedupe is applied
    // to the POOL half here, at the single lowering point — see [`entity_only_hook_refs`].
    for pool in pools.values_mut() {
        pool.gates = entity_only_hook_refs(&deploy.pools.all_pool_hooks, &pool.gates);
    }
    // ── UNIFIED `pools:` KIND INFERENCE (1.6.0). The single neutral `pools:` map holds pools of
    // every plane; a pool's KIND is INFERRED from its members (never declared), and the pool is
    // routed to the plane that owns those members. LLM pools stay in `pools` (their rich members and
    // routing knobs are read by the model plane exactly as before — byte-identical); MCP and A2A
    // pools are projected to the neutral `CandidatePoolCfg` carriers the two non-LLM planes already
    // consume. HOMOGENEITY is enforced here (a pool whose members span two nouns is refused) and an
    // unresolvable member is refused — the two checks the design puts before resolution so that a
    // clean `--validate` is a clean boot. This is the ONLY place a pool's plane is decided.
    let mut tool_pools_derived: std::collections::BTreeMap<
        String,
        crate::failover::CandidatePoolCfg,
    > = std::collections::BTreeMap::new();
    let mut agent_pools_derived: std::collections::BTreeMap<
        String,
        crate::failover::CandidatePoolCfg,
    > = std::collections::BTreeMap::new();
    {
        // A pool's KIND discriminant is its members' shared CONFIG SECTION — the plane-declared
        // grammar key, used as OPAQUE DATA. The router never names a plane: `tools:` routes to the
        // tool-pool projection, `agents:` to the agent-pool one, and the residual `models:` section
        // stays on the LLM lane. Reading the discriminant off the frozen named-map mirror (rather
        // than a hard-coded plane key) is what lets a registered plane's pools route with nothing
        // about that plane written here.
        let tools_section = busbar_substrate::plane::config::NAMED_MAP_SECTIONS[2];
        let agents_section = busbar_substrate::plane::config::NAMED_MAP_SECTIONS[3];
        let member_kind = |name: &str| -> Option<&'static str> {
            // Global-unique noun names make this a name-only lookup — the router never asks "which
            // kind of `x`?". A name defined in two nouns is a collision the validator rejects.
            if deploy.models.contains_key(name) {
                return Some(crate::plane::fallback_key());
            }
            // The plane registry sections read through the always-present type-erased seam, resolved
            // by config section. With the owning plane compiled out the seam holds a
            // `RawPlaneSection`, whose `contains_def` is empty (a present section is refused earlier),
            // so no name resolves there.
            if deploy
                .plane_section(tools_section)
                .is_some_and(|cfg| cfg.contains_def(name))
            {
                return Some(tools_section);
            }
            if deploy
                .plane_section(agents_section)
                .is_some_and(|cfg| cfg.contains_def(name))
            {
                return Some(agents_section);
            }
            None
        };
        let mut non_llm: Vec<String> = Vec::new();
        for (pool_name, pool) in pools.iter() {
            // The pool's kind = its members' shared kind. Determine it from the FIRST resolvable
            // member, then require every other member to agree (homogeneity).
            let mut kind: Option<&'static str> = None;
            let mut homogeneous = true;
            for m in &pool.members {
                match member_kind(m.name()) {
                    None => {
                        errors.push(format!(
                            "pools.{pool_name}: member `{}` is not defined in any of the top-level \
                             `models:`, `tools:`, or `agents:` maps. Define it there, or remove it \
                             from the pool.",
                            m.name()
                        ));
                    }
                    Some(k) => match kind {
                        None => kind = Some(k),
                        Some(prev) if prev == k => {}
                        Some(_) => {
                            homogeneous = false;
                        }
                    },
                }
            }
            if !homogeneous {
                errors.push(format!(
                    "pools.{pool_name}: members resolve to more than one plane (a mix of \
                     `models:`/`tools:`/`agents:`). A pool's kind is INFERRED from its members, so \
                     every member of a pool must be the same kind. Split the pool by plane."
                ));
                continue;
            }
            match kind {
                Some(k) if k == tools_section => {
                    tool_pools_derived.insert(
                        pool_name.clone(),
                        crate::failover::CandidatePoolCfg {
                            members: pool.members.iter().map(|m| m.model.clone()).collect(),
                            repeatable: pool.repeatable.clone(),
                        },
                    );
                    non_llm.push(pool_name.clone());
                }
                Some(k) if k == agents_section => {
                    agent_pools_derived.insert(
                        pool_name.clone(),
                        crate::failover::CandidatePoolCfg {
                            members: pool.members.iter().map(|m| m.model.clone()).collect(),
                            repeatable: pool.repeatable.clone(),
                        },
                    );
                    non_llm.push(pool_name.clone());
                }
                // LLM pools (or an all-unresolvable pool that already pushed errors) stay in `pools`.
                _ => {}
            }
        }
        // A pool that is NOT an LLM pool must not remain in the LLM `pools` map (its bare members do
        // not resolve to `models:` and would fail the model-lane build). Remove the projected ones.
        for name in non_llm {
            pools.remove(&name);
        }
    }
    // NEUTRAL POOL-LEVEL ROUTING KNOBS → members (1.6.0, LLM plane). `weights:`/`tier:`/
    // `attempt_timeout_ms:` on the pool refine any member that did NOT state the value inline (an
    // inline per-member value WINS, for byte-identity with 1.5.4 rich-member configs). This lets a
    // uniform bare-name LLM pool carry weights/tier/timeouts without per-member rich objects. On the
    // MCP/A2A planes these knobs are carried on the pool but their ordered-failover engines do not yet
    // read `weights:` — the projection to `CandidatePoolCfg` above is deliberately behaviour-neutral.
    for pool in pools.values_mut() {
        for m in pool.members.iter_mut() {
            if let Some(&w) = pool.weights.get(&m.model) {
                // A member left at the default weight (1) takes the pool-level weight; an inline
                // non-default weight is the operator's explicit per-member choice and stands.
                if m.weight == default_weight() {
                    m.weight = w;
                }
            }
            if m.tier.is_none() {
                m.tier = pool.tier.clone();
            }
            if m.attempt_timeout_ms.is_none() {
                m.attempt_timeout_ms = pool.attempt_timeout_ms;
            }
        }
    }
    // THE A2A PLANE'S SECTION-LEVEL ATTACH, judged by the same rule its per-agent lists are. The
    // per-agent lists are checked at parse (`a2a::config::validate_agent`); the section list has no
    // per-entry parse to hang off, so it is checked here, where every other cross-reference is.
    // `` `agents.hooks` `` is this plane's own WORDING for the site; the rule and the sentence are
    // `plane::config`'s, shared with the `tools:` plane below.
    //
    // The whole block reads the `agents:` registry through its always-present type-erased seam.
    // With the owning plane compiled out the seam holds a `RawPlaneSection` whose `container_gates`
    // is empty (a present `agents:` section is refused earlier as naming an absent plane), so the
    // loops below do nothing — the same as the per-plane feature gate compiling this out entirely.
    // A hook an `agents:` entry names must EXIST in the one top-level `hooks:` map. A dangling
    // reference is an operator believing a control is attached that is not, so it is an error and
    // not a warning, exactly as it is for `auth.chain`. Both the section-level attach and each
    // agent's own list are read through the neutral `container_gates` seam, in registry order.
    {
        let g = deploy.agents.0.container_gates();
        if let Err(e) = crate::plane::config::validate_section_hooks(
            "`agents.hooks`",
            &g.section_hooks,
            &crate::plane::config::config_sections(),
        ) {
            errors.push(e);
        }
        for (agent, hooks) in &g.containers {
            for hook in g.section_hooks.iter().chain(hooks.iter()) {
                if !deploy.hooks.contains_key(hook) {
                    errors.push(format!(
                        "agents.{agent}: `hooks:` names `{hook}`, which is not defined in the                      top-level `hooks:` map. Define it there, or remove the reference."
                    ));
                }
            }
        }
    }
    // THE FAILOVER POOLS' CROSS-REFERENCES, judged exactly like every other bare-name reference in
    // this function. A member naming nothing is an operator believing a request has somewhere to go
    // when it does not, which is the same class of defect as a dangling hook reference and is
    // therefore an error rather than a warning. NO POOL MAY STRADDLE TWO PLANES: `tool_pools:`
    // members resolve ONLY against `tools:` and `agent_pools:` members ONLY against `agents:`, so an
    // agent named in a tool pool fails here rather than at dispatch — and the message says which
    // section the name actually lives in, because "not found" would send an operator looking for a
    // typo they did not make.
    // Whether `m` names an MCP `tools:` server. Always false when the MCP plane is compiled out:
    // there is no `tools:` registry then, and no pool is inferred onto the MCP plane, so
    // `tool_pools_derived` is empty and the first loop below never iterates.
    let is_tool_member = |m: &str| -> bool { deploy.tools.0.contains_def(m) };
    // Whether `m` names an A2A `agents:` registration. Always false when the A2A plane is compiled
    // out: there is no `agents:` registry then, and no pool is inferred onto the A2A plane, so
    // `agent_pools_derived` is empty and the second loop below never iterates.
    let is_agent_member = |m: &str| -> bool { deploy.agents.0.contains_def(m) };
    for (pool, def) in &tool_pools_derived {
        check_failover_pool(
            &mut errors,
            "pools",
            pool,
            def,
            is_tool_member,
            is_agent_member,
            "tools",
            "agents",
        );
    }
    for (pool, def) in &agent_pools_derived {
        check_failover_pool(
            &mut errors,
            "pools",
            pool,
            def,
            is_agent_member,
            is_tool_member,
            "agents",
            "tools",
        );
    }
    // ONE POOL PER MEMBER, per plane. The dispatch route resolves a registration to ITS pool and
    // records health into that pool's cells; a registration in two pools would be two cell
    // histories for one upstream with the winner chosen by map iteration order — a nondeterminism
    // an operator cannot see. Refused as config, where the ambiguity was written.
    for (section, pools) in [
        ("pools", &tool_pools_derived),
        ("pools", &agent_pools_derived),
    ] {
        let mut owner: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
        for (pool, def) in pools {
            for member in &def.members {
                if let Some(first) = owner.insert(member.as_str(), pool.as_str()) {
                    if first != pool.as_str() {
                        errors.push(format!(
                            "{section}: `{member}` is a member of both `{first}` and `{pool}`. A \
                             registration belongs to at most ONE failover pool — its learned \
                             health lives in that pool's breaker cells, and two pools would keep \
                             two contradictory histories for one upstream."
                        ));
                    }
                }
            }
        }
    }
    for (name, def) in &deploy.hooks {
        if RESERVED_HOOK_NAMES.contains(&name.as_str()) {
            errors.push(format!(
                "hooks.{name}: '{name}' is a reserved name (an on_error terminal, built-in ranking \
                 strategy, or built-in auth module) and cannot name a hook definition"
            ));
            continue;
        }
        match hook_cfg_from_def(def) {
            Ok(cfg) => {
                hooks_registry.insert(name.clone(), cfg);
            }
            Err(e) => errors.push(format!("hooks.{name}: {e}")),
        }
    }
    // The pool bare-name references are already parsed onto `pool.gates` (the non-strategy names in
    // each pool's `hooks:` list); existence + kind are validated by `config_validate`. The reserved
    // all-pools attach (`pools.hooks:`) becomes the runtime `global_hooks` list — the ONLY global
    // mechanism (fires on every pool, filtered per hook by `groups`/`phase`/`kind`).
    let global_hook_names: Vec<String> = deploy.pools.all_pool_hooks.clone();

    // THE `tools:` PLANE's hook references, held to the SAME rules as the pool plane's: bare names
    // only, into the ONE top-level `hooks:` map, and a dangling one is a boot error rather than a
    // silently dropped attachment. A dropped reference leaves an operator believing a control is
    // attached that is not, which is worse than the typo it came from.
    //
    // The whole block reads the `tools:` registry through its always-present type-erased seam. With
    // the owning plane compiled out the seam holds a `RawPlaneSection` whose `container_gates` is
    // empty (a present `tools:` section is refused earlier as naming an absent plane), so the loops
    // below do nothing — the same as the per-plane feature gate compiling this out entirely.
    {
        let g = deploy.tools.0.container_gates();
        if let Err(e) = crate::plane::config::validate_section_hooks(
            "`tools.hooks`",
            &g.section_hooks,
            &crate::plane::config::config_sections(),
        ) {
            errors.push(e);
        }
        for (server, hooks) in &g.containers {
            for hook in g.section_hooks.iter().chain(hooks.iter()) {
                if !deploy.hooks.contains_key(hook) {
                    errors.push(format!(
                        "tools.{server}: `hooks:` names `{hook}`, which is not defined in the top-level \
                         `hooks:` map. Define it there, or remove the reference."
                    ));
                }
            }
        }
    }

    // THE `tools:` PLANE's PUBLISHED-NAME UNIQUENESS, and it has to run HERE rather than inside
    // `validate_server` because it is the one MCP rule that is not about one server: a
    // `publish_as:` override on one registration can collide with the `{server}_{tool}` default of
    // another, and neither server can see the other. `resolve` is where the whole EFFECTIVE registry
    // exists — file base plus whatever the admin API applied — and it is the single point boot,
    // `--validate`, the admin config-apply rebuild and the admin dry-run validate endpoint all pass
    // through, so a config that boots is exactly the config that validates.
    // `validate_registry` runs through the always-present seam; a compiled-out `RawPlaneSection`
    // answers `Ok(())`, so this is a no-op when the plane is absent.
    if let Err(e) = deploy.tools.0.validate_registry() {
        errors.push(e);
    }
    // A present plane registry section whose owning plane is NOT registered names a registry this
    // build cannot serve: refuse it (the config deletion-gate leg), naming the SECTION (its
    // plane-declared grammar key) rather than a hard-coded plane. With the plane registered the decl
    // is present and this never fires; with it compiled out the `RawPlaneSection` reports
    // `is_present()` for a section the operator wrote, and there is no decl for it.
    //
    // FAIL-CLOSED: this reads the FROZEN STATIC noun source
    // `busbar_substrate::plane::config::NAMED_MAP_SECTIONS`, NOT the registry-derived
    // `NamedMapSection::sections()` — the latter goes EMPTY of a plane's section when the plane is
    // compiled out, which would let a `tools:`/`agents:` block for an absent plane slip through
    // silently. The mirror's two core sections (`identity-providers`/`export`) are not plane sections,
    // so `plane_section` answers `None` for them (never present) and they are skipped; only a plane
    // section that is present with no decl is refused, byte-identical to the former `[Tools, Agents]`
    // loop.
    for section in busbar_substrate::plane::config::NAMED_MAP_SECTIONS {
        let present = deploy
            .plane_section(section)
            .is_some_and(|cfg| cfg.is_present());
        if present && crate::plane::registry::plane_decl_for_config_section(section).is_none() {
            errors.push(format!(
                "`{section}:` is configured, but this build was compiled without the plane that \
                 owns it, so busbar cannot serve it. Rebuild with that plane's feature enabled, or \
                 remove the `{section}:` block."
            ));
        }
    }
    // The VOICE plane's `streams:` section is SINGULAR (one live-voice posture per deployment), so it
    // is NOT a `NamedMapSection` and not in the mirror above — it is checked the same way in its own
    // right: a present `streams:` block with no registered voice plane (the default, voice-off build)
    // names a section this build cannot serve and is refused at resolve, byte-identical to a present
    // `tools:`/`agents:` naming a compiled-out plane. With voice registered the decl is present and
    // this never fires; with it compiled out the `RawPlaneSection` reports `is_present()` for a
    // section the operator wrote, and there is no decl for it.
    if deploy.streams.0.is_present()
        && crate::plane::registry::plane_decl_for_config_section("streams").is_none()
    {
        errors.push(
            "`streams:` is configured, but this build was compiled without the plane that owns it, \
             so busbar cannot serve it. Rebuild with that plane's feature enabled, or remove the \
             `streams:` block."
                .to_string(),
        );
    }

    // ADMIN-PLANE BOOT-GUARD: a network-exposed admin listener MUST require client certificates
    // (mTLS) — the management surface is the highest-value target and must not sit on a public bind
    // behind a bearer token alone. Loopback binds are safe (unreachable off-host); an explicit
    // `admin_require_mtls: false` waives the guard for operators fronting admin with a mesh that
    // terminates mTLS. Anything else that would expose admin without a client CA refuses to boot.
    // 1.5.3: the flag INVERTED (`admin_insecure: true` → `admin_require_mtls: false`); the BEHAVIOR
    // below is byte-identical, only the spelling of the waiver changed.
    {
        let admin_listen = &deploy.admin_listen;
        let exposed = !bind_is_loopback(admin_listen);
        let has_client_mtls = deploy
            .admin_tls
            .as_ref()
            .is_some_and(|t| t.client_ca.is_some());
        if exposed && !has_client_mtls && deploy.admin_require_mtls {
            errors.push(format!(
                "admin_listen '{admin_listen}' is network-exposed but the admin plane has no mTLS \
                 (admin_tls.client_ca is unset). Require client certificates by supplying \
                 admin_tls.client_ca, bind admin_listen to loopback, or set admin_require_mtls: \
                 false to deliberately run a token-only admin plane (e.g. behind a mesh)."
            ));
        }
    }

    // Join every `auth.chain:`/`auth.admin_auth:` NAME to its `identity-providers:` definition
    // (define once, reference by name). Dangling references land in `errors`.
    let resolved_auth = deploy
        .auth
        .as_ref()
        .map(|a| resolve_auth(a, &deploy.identity_providers, &mut errors));
    let admin_auth_names: Vec<String> = resolved_auth.as_ref().map_or_else(
        || {
            default_admin_auth()
                .iter()
                .map(|e| e.name.clone())
                .collect()
        },
        |a| a.admin_auth.iter().map(|e| e.name.clone()).collect(),
    );

    // The `mcp:` block is validated HERE, into `errors`, rather than at first request: an MCP plane
    // whose canonical URI is malformed would advertise one audience in its metadata document and
    // expect another in its verifier, and every correctly-behaved client in the world would obtain a
    // token this server then refuses. A boot refusal names the field and what to type; a runtime one
    // is discovered by an agent that cannot connect and cannot say why.
    // The `mcp:` endpoint is LOWERED through the plane seam into its validated resource, type-erased
    // as `Option<Arc<dyn Any>>` — so `RootCfg` names no `crate::mcp` resource type. The plane's
    // `lower_endpoint` hook returns the SAME `McpCfgError` `Display` string boot produced, collected
    // verbatim. With the MCP plane compiled out there is no hook: a PRESENT `mcp:` block names a plane
    // this build does not carry, so it is refused (the config deletion-gate leg) with the same wording.
    // plane-purity: frozen-wire deploy.mcp is the frozen mcp: wire field on DeployCfg
    let endpoint_block = deploy.mcp.0.as_ref();
    let lowered_endpoint: Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> =
        match endpoint_block {
            None => None,
            Some(ep) => {
                // The endpoint's owning plane is looked up by its CONFIG SECTION (the `tools:` plane owns
                // the `mcp:` door), so no plane key is named here. Compiled out ⇒ no decl ⇒ the
                // deletion-gate refusal below.
                match crate::plane::registry::plane_decl_for_config_section(
                    busbar_substrate::plane::config::NAMED_MAP_SECTIONS[2],
                )
                .and_then(|d| d.lower_endpoint)
                {
                    Some(lower) => match lower(&**ep) {
                        Ok(resource) => Some(resource),
                        Err(e) => {
                            errors.push(e);
                            None
                        }
                    },
                    None => {
                        if ep.is_present() {
                            errors.push(
                            "an endpoint block is configured for a plane this build was compiled \
                             without, so busbar cannot serve it. Rebuild with that plane's feature \
                             enabled, or remove the block."
                                .to_string(),
                        );
                        }
                        None
                    }
                }
            }
        };

    // The lowered endpoint resource, if any, keyed by its owning plane's config SECTION — the
    // neutral, section-keyed shape `RootCfg` carries in place of a per-plane field (mirroring
    // `tool_defs`/`agent_defs` beside it). The `tools:` plane owns the endpoint door, so its section
    // key is the map key; a build compiled without that plane produced no resource and inserts none.
    let mut endpoint_resources: std::collections::HashMap<
        &'static str,
        std::sync::Arc<dyn std::any::Any + Send + Sync>,
    > = std::collections::HashMap::new();
    if let Some(resource) = lowered_endpoint {
        endpoint_resources.insert(
            busbar_substrate::plane::config::NAMED_MAP_SECTIONS[2],
            resource,
        );
    }

    // The `oauth_as:` block, validated HERE for the same reason the endpoint block is: an authorization server
    // whose issuer is malformed advertises endpoints at paths it does not serve, and every
    // conforming client discovers them and fails. A boot refusal names the field; a runtime one is
    // found by an agent that cannot log in and cannot say why.
    let oauth_as = match deploy
        .oauth_as
        .as_ref()
        .map(crate::oauth_as::config::AsIdentity::from_cfg)
    {
        None => None,
        Some(Ok(identity)) => Some(identity),
        Some(Err(e)) => {
            errors.push(e.to_string());
            None
        }
    };

    if errors.is_empty() {
        Ok(RootCfg {
            listen: deploy.listen.clone(),
            public_url: deploy.public_url.clone(),
            endpoint_resources,
            oauth_as,
            tool_defs: deploy.tools.0.clone_box(),
            tool_pools: tool_pools_derived,
            agent_pools: agent_pools_derived,
            tls: deploy.tls.clone(),
            admin_listen: deploy.admin_listen.clone(),
            admin_tls: deploy.admin_tls.clone(),
            auth: resolved_auth,
            providers: resolved_providers,
            models: deploy.models.clone(),
            pools,
            upstream_credentials: deploy
                .pools
                .all_pool_upstream_credentials
                .unwrap_or_default(),
            hooks: hooks_registry,
            // The admin chain PROVIDER NAMES, from `auth.admin_auth:` (default `[admin-tokens]`
            // when the whole `auth:` block is absent). 1.5.3: the runtime identity of an admin chain
            // entry is its provider NAME (what `role_bindings.<name>` binds), not its module.
            admin_auth: admin_auth_names,
            groups: deploy.groups.clone(),
            rate_card: deploy.rate_card.clone(),
            per_request_fee: deploy.per_request_fee,
            store: deploy.store.clone(),
            secrets: deploy.secrets.clone(),
            global_hooks: global_hook_names,
            blocked_metadata_hosts: deploy
                .security
                .as_ref()
                .map(|s| s.blocked_metadata_hosts.clone())
                .unwrap_or_default(),
            allow_metadata_hosts: deploy
                .security
                .as_ref()
                .map(|s| s.allow_metadata_hosts.clone())
                .unwrap_or_default(),
            allow_all_metadata: deploy
                .security
                .as_ref()
                .map(|s| s.allow_all_metadata)
                .unwrap_or(false),
            // Project the operational-limit sections onto a flat resolved struct. The `advanced:` /
            // `export:` blocks are optional; absent ⇒ their section defaults (the historical
            // hardcoded values, via the manual `Default` impls).
            limits: LimitsResolved::from_sections(
                &deploy.limits,
                &deploy.advanced,
                &export,
                &deploy.health,
                &deploy.routing,
            ),
            export,
            identity_providers: deploy.identity_providers.clone(),
            export_defs: deploy.export.clone(),
            agent_defs: deploy.agents.0.clone_box(),
        })
    } else {
        Err(errors)
    }
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/named_map_merge_tests.rs"]
mod named_map_merge_tests;

// The CONFIG BACK-COMPAT CORPUS GATE: the resolved billing/limits surface is byte-stable across
// 1.6.0 changes (the baseline M3's config-noun eviction must preserve). Lives here because it reads
// the `pub(crate)` resolved fields (`limits.default_max_tokens`, `reasoning_effort_budgets`) that an
// out-of-crate integration test cannot see.
#[cfg(test)]
#[path = "tests/config_backcompat_corpus.rs"]
mod config_backcompat_corpus;
