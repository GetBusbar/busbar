// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// The busbar-owned config overlay (persistence substrate for API-applied hook changes).
pub(crate) mod overlay;

/// The top-level `groups:` limit tree: GroupCfg + the generic limit shape.
pub(crate) mod groups;
/// The 1.4.x -> 1.5.0 config migrator + the loud fail-closed 1.x detector.
pub(crate) mod migrate;
pub(crate) mod migrate_export;
/// The 1.5.3 named-DEFINITION map sections (`identity-providers:`, `export:`), described ONCE as
/// data so every surface that serves the universal pattern is parameterized instead of copied.
pub(crate) mod named_map;
/// The secret-reference type: `{ module, settings }` + the `{env}`/`{file}` sugar.
pub(crate) mod patch;
pub(crate) mod secret;

pub(crate) use groups::{GroupCfg, LimitCfg};
pub(crate) use secret::SecretRef;

// Re-export status_class_from_str for config validation
pub(crate) use crate::breaker::status_class_from_str;
use crate::proto::PROTO_ANTHROPIC;

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
pub(crate) enum EnvSubst {
    /// Boot / reload: an unset variable is a hard error (fail loud — a real deployment must have its
    /// secrets present before it serves traffic).
    Strict,
    /// `busbar --validate`: an unset variable is substituted with a placeholder (its own name) and
    /// recorded, so config STRUCTURE can be validated without secrets present (CI, pre-reload dry runs).
    Lenient,
}

/// Expand `${VAR}` tokens from the environment (see [`EnvSubst`] for unset-variable behavior). See
/// [`interpolate_env_with`] for the two-layer injection defense applied to every substituted value.
pub(crate) fn interpolate_env(s: &str) -> Result<String, String> {
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
pub(crate) fn interpolate_env_with(
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
pub(crate) struct RootCfg {
    pub(crate) listen: String,
    /// busbar's PUBLIC base URL (top-level `public_url:`). The externally-reachable origin used to
    /// build `/auth/token` links AND shown to devs as the `base_url` they point BYOK clients at (no
    /// `/v1` suffix — clients append their own). Absent ⇒ no hosted-login/token links can be built.
    /// Validated (absolute https; loopback http allowed; no path/query, no cloud-metadata host).
    pub(crate) public_url: Option<String>,
    /// The VALIDATED MCP resource (`mcp:`), or `None` when this deployment is not an MCP server.
    /// Derived and refused at boot by [`crate::mcp::McpResource::from_cfg`], so nothing downstream
    /// re-parses the canonical URI or re-derives the mount path.
    pub(crate) mcp: Option<crate::mcp::McpResource>,
    /// The VALIDATED authorization server (`oauth_as:`), or `None` when this deployment is not one.
    /// Derived and refused at boot by `crate::oauth_as::config::AsIdentity::from_cfg`, so nothing
    /// downstream re-parses the issuer or re-derives an endpoint path.
    pub(crate) oauth_as: Option<crate::oauth_as::config::AsIdentity>,
    /// The `tools:` MCP server registry, carried through `resolve` VERBATIM.
    ///
    /// Verbatim on purpose: this is operator INTENT (owner ruling 3), and the only derivation that
    /// happens to it is building the catalogue snapshot, which is a separate value with its own
    /// generation. Lowering it here would give the registry two representations that could disagree
    /// about what the operator approved — precisely the disagreement the trust lifecycle removes by
    /// DERIVING state from intent-versus-observation instead of storing it.
    pub(crate) tool_defs: crate::mcp::config::ToolsCfg,
    /// Optional native inbound TLS. `None` ⇒ plain HTTP (today's path, byte-for-byte).
    pub(crate) tls: Option<TlsCfg>,
    /// Separate admin listen address — the admin API is served ONLY here, never on the data
    /// listener. Defaults to loopback (`127.0.0.1:8081`).
    pub(crate) admin_listen: String,
    /// TLS/mTLS for the admin listener (only meaningful with `admin_listen`).
    pub(crate) admin_tls: Option<TlsCfg>,
    pub(crate) auth: Option<AuthCfg>,
    pub(crate) providers: HashMap<String, ProviderCfg>,
    pub(crate) models: HashMap<String, ModelCfg>,
    pub(crate) pools: HashMap<String, PoolCfg>,
    /// The ALL-POOLS `upstream_credentials:` default, resolved from the reserved
    /// `pools.upstream_credentials:` key (1.5.3 — moved off the retired `auth.upstream_credentials:`).
    /// A pool's own `upstream_credentials:` OVERRIDES this (SCALAR combine rule).
    pub(crate) upstream_credentials: crate::auth::UpstreamCreds,
    /// The RUNTIME hook registry, LOWERED by `resolve` from the top-level `hooks:` NAMED-DEFINITION
    /// map (1.5.3: [`DeployCfg::hooks`] — a hook is DEFINED once and REFERENCED by bare name from
    /// `pools.hooks:` / `pools.<p>.hooks:`). Admin-registered hooks land here too.
    pub(crate) hooks: HashMap<String, HookCfg>,
    /// The ADMIN auth chain module names (from `auth.admin_auth:`, in order) gating
    /// `/api/v1/admin/*`. Default `[admin-tokens]`. `[]` = OPEN admin (dev only; loud boot
    /// warning).
    pub(crate) admin_auth: Vec<String>,
    /// The top-level `groups:` limit tree.
    pub(crate) groups: std::collections::BTreeMap<String, GroupCfg>,
    /// The top-level `rate_card:` - the ONLY cost source. See `DeployCfg::rate_card`.
    pub(crate) rate_card: Option<std::collections::BTreeMap<String, RateEntryCfg>>,
    /// Flat cents charged per request (default 0).
    pub(crate) per_request_fee: i64,
    /// The `store:` block as configured; `None` = the block was ABSENT (ephemeral RAM store,
    /// presence-driven governance stays off unless another governance signal is present).
    pub(crate) store: Option<StoreCfg>,
    /// Module-level `open()` config for `kind: secret` plugins, keyed by module name (the top-level
    /// `secrets:` block). Empty = every secret plugin opens with `{}` (the prior behavior). The
    /// built-in `env` / `file` modules take no config and must not appear here.
    pub(crate) secrets: std::collections::BTreeMap<String, SecretModuleCfg>,
    /// Names of hooks that fire on EVERY request — the registry names lowered from the reserved
    /// all-pools attach key `pools.hooks:` (1.5.3), in order. RUNTIME-only: there is no
    /// config-facing `global_hooks:` key any more.
    pub(crate) global_hooks: Vec<String>,
    /// Operator-supplied additions to the hardcoded cloud-metadata denylist (see
    /// [`SecurityCfg::blocked_metadata_hosts`]). Resolved from `DeployCfg.security`; empty when no
    /// `security:` block is present. Threaded into `config_validate::validate` so a provider
    /// `base_url` (and any path-override composition) targeting one of these hosts is rejected at
    /// boot unless that host is carved out by an allow-override.
    pub(crate) blocked_metadata_hosts: Vec<String>,
    /// Global SURGICAL allow-override: cloud-metadata hosts/IPs to UNBLOCK for ALL providers
    /// (`security.allow_metadata_hosts`). Unioned with each provider's own `allow_metadata_hosts`
    /// when the guard runs; a host on the denylist is permitted iff it appears in this union (or
    /// `allow_all_metadata` is set). Matched with the same canonicalization as the block check (an IP
    /// entry unblocks all its spellings). Default empty.
    pub(crate) allow_metadata_hosts: Vec<String>,
    /// Nuclear override (`security.allow_all_metadata`): when true the metadata SSRF guard is fully
    /// DISABLED — every cloud-metadata endpoint is reachable by every provider. Logs a startup WARN.
    /// Default false.
    pub(crate) allow_all_metadata: bool,
    /// Fully-resolved operational limits ("NEVER CODED CAPS"), projected from the `limits:` /
    /// `observability:` / `governance:` / `metrics:` / `health:` / `routing:` config sections. Every
    /// value defaults to its historical hardcoded const, so an all-default config is unchanged. Read
    /// by `config_validate::validate`, threaded into the store/client/TLS/App at startup, and
    /// installed into the process-wide `crate::limits` statics for the deep call-stack use sites.
    pub(crate) limits: LimitsResolved,
    /// The resolved `export:` block — the built-in observability exporters. Default
    /// (all-`None`) ⇒ collection inert. Read at App construction to install the recorder + build the
    /// `/metrics` plugin route (prometheus) and to configure the request-log sinks.
    pub(crate) export: ExportCfg,
    /// The `identity-providers:` NAMED-DEFINITION map, carried through resolve VERBATIM (the
    /// EFFECTIVE map: base `config.yaml` + the overlay's API-applied entries, merged pre-resolve).
    /// `auth`/`admin_auth` above are the RESOLVED projection of it; this is the definition surface
    /// the admin API reads and rewrites (`GET/PUT/PATCH/DELETE /identity-providers/{name}`).
    pub(crate) identity_providers: IdentityProviders,
    /// The `export:` NAMED-DEFINITION map, carried through resolve VERBATIM — the definition twin of
    /// the typed `export` projection above, for the same reason `identity_providers` is carried:
    /// the admin API serves DEFINITIONS, not the lowered per-module runtime shape.
    pub(crate) export_defs: ExportDefs,
    /// The `agents:` NAMED-DEFINITION map, carried through resolve VERBATIM, for the same reason
    /// `identity_providers` and `export_defs` are: the admin API serves DEFINITIONS, and the A2A
    /// control plane derives its runtime `AgentRegistration` from this plus what the store has
    /// accumulated. Nothing here is accumulation.
    pub(crate) agent_defs: crate::a2a::config::AgentsCfg,
    /// The `tool_pools:` MCP failover pools, carried through `resolve` VERBATIM — operator intent,
    /// like `tool_defs` beside it. Empty ⇒ no MCP failover.
    #[cfg_attr(not(test), allow(dead_code))]
    // read by the dispatch-path wiring; see crate::failover
    pub(crate) tool_pools: std::collections::BTreeMap<String, crate::failover::CandidatePoolCfg>,
    /// The `agent_pools:` A2A failover pools, carried through `resolve` VERBATIM. Empty ⇒ no A2A
    /// failover.
    #[cfg_attr(not(test), allow(dead_code))]
    // read by the dispatch-path wiring; see crate::failover
    pub(crate) agent_pools: std::collections::BTreeMap<String, crate::failover::CandidatePoolCfg>,
}

/// Native inbound TLS configuration for the client↔Busbar hop. Absent (`Config.tls == None`) ⇒
/// Busbar serves plain HTTP exactly as before. Present ⇒ Busbar terminates TLS itself; if
/// `client_ca` is also set, it additionally requires and verifies a client certificate (mTLS).
/// All three values are SECRET REFERENCES (`{ file: … }` / `{ env: … }` / a secret module)
/// resolving to PEM bytes; they are resolved once at startup and any resolve/parse error is fatal
/// (`die`). Key bytes are never logged.
// deny_unknown_fields: a typo under `tls:` - e.g. `client_c:` for `client_ca:` - would
// otherwise be SILENTLY IGNORED, leaving mTLS DISABLED while the operator believes it is on
// (a security downgrade with no diagnostic). Reject any unknown key here so the typo fails boot.
#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct TlsCfg {
    /// PEM certificate chain, leaf first (e.g. fullchain.pem), as a secret reference.
    pub(crate) cert: SecretRef,
    /// PEM private key matching the leaf cert (PKCS#8, PKCS#1, or SEC1), as a secret reference.
    pub(crate) key: SecretRef,
    /// PEM CA bundle to verify client certs against. `Some` ⇒ mTLS required: a client must present
    /// a cert chaining to this CA to complete the handshake at all. `None` ⇒ server-only TLS.
    #[serde(default)]
    pub(crate) client_ca: Option<SecretRef>,
}

/// One entry in the top-level `identity-providers:` NAMED-DEFINITION map (1.5.3). The map
/// KEY is the provider INSTANCE name — the bare name `auth.chain:`, `auth.admin_auth:` and
/// `role_bindings:` all reference — and this value says which `kind: auth` module backs it, how it is
/// configured, and what admin ceiling it carries.
///
/// ```yaml
/// identity-providers:
///   admin-tokens: { module: admin-tokens, token: { env: BUSBAR_ADMIN_TOKEN } }
///   corp-ad:      { module: ad, settings: { server: "ldaps://corp" }, max_admin_scope: read-only }
/// auth:
///   chain:      [keys, corp-ad]     # ← bare NAMES
///   admin_auth: [admin-tokens, corp-ad]
///   role_bindings: { corp-ad: { platform: { admin_scope: full } } }
/// ```
///
/// This REVERSES the 1.5.0 inlining: an IdP that serves BOTH planes used to be defined twice (once in
/// `chain:`, once in `admin_auth:`) with two independent copies of its settings that could silently
/// drift. Now it is defined ONCE and referenced twice.
///
/// The built-in `keys` (data-plane signed-key verifier) and `admin-tokens` (operator credential)
/// are referenced BARE with no definition at all; a definition entry exists only when the provider
/// needs config (e.g. `admin-tokens` carrying its `token:` secret ref).
// `Serialize` is required by the overlay's per-entry MERGE (`config::patch::merge_entry`): an
// overlay entry is a PATCH, so the base entry has to be projected back to JSON in order to be
// patched. The projection is config-internal and round-trips straight back into this same struct;
// it reaches no reader and no HTTP response, which is the distinction the settings-leak lint's
// category (c) turns on.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)] // a typo'd key must fail boot, never silently disable a ceiling.
pub(crate) struct IdentityProviderCfg {
    /// The module backing this provider: the built-in `keys` / `admin-tokens`, or a `kind: auth`
    /// plugin name/alias resolved through the validated plugin registry. REQUIRED, non-empty.
    pub(crate) module: String,
    /// Ceiling on the ADMIN scope obtainable through THIS PROVIDER, regardless of what
    /// `role_bindings:` grants. The accepted values are exactly `read-only` and `full` — the two
    /// `crate::admin::v1::contract::Scope::parse` knows. Anything else is a HARD BOOT ERROR
    /// ("unknown max_admin_scope '…': expected read-only or full"): [`resolve_auth`] copies this
    /// value onto the RESOLVED `AuthChainEntry` for every provider named in `auth.chain:` /
    /// `auth.admin_auth:`, and `config_validate`'s chain-entry rule parses every one of those. It is
    /// never a silently-ignored key.
    ///
    /// THERE IS NO `none`. To grant NO admin authority through a provider, grant no `admin_scope`
    /// under that provider's `role_bindings:` — the ceiling caps what a grant can reach, it cannot
    /// express the absence of one. (An earlier version of this comment listed `none`, and every doc
    /// page and example config copied it from here; they told operators to write a config the binary
    /// refuses. The value list and the "absent = most restrictive" prose below now agree.)
    ///
    /// 1.5.3 moved this ONTO the definition: it used to sit on a data-plane CHAIN entry,
    /// which was incoherent — an admin ceiling is a property of the identity source, not of one
    /// plane's reference to it. Absent = the MOST RESTRICTIVE default (`read-only`) for every
    /// provider EXCEPT the built-in `admin-tokens` operator credential, which is `full` by
    /// definition and exempt. `full` from an external IdP is always an explicit opt-in.
    #[serde(default)]
    pub(crate) max_admin_scope: Option<String>,
    /// The operator ADMIN credential, for a provider whose `module` is the built-in `admin-tokens`
    /// (a secret reference). Meaningless on any other module (validated).
    #[serde(default)]
    pub(crate) token: Option<SecretRef>,
    /// HOSTED-LOGIN parameters (freeze blocker). The 1.5.2 `auth.methods:` block FOLDED into this
    /// definition: `browser_login` is inherently per-provider (a client id/secret belongs to ONE
    /// IdP registration), so a separate parallel map was duplicate structure whose two halves could
    /// disagree. PRESENCE of this block is what puts a button on the hosted login page; a provider
    /// without it is headless-only (still usable via `POST /auth/token`).
    #[serde(default)]
    pub(crate) browser_login: Option<BrowserLoginCfg>,
    /// The module's own opaque settings (pushed to the auth plugin verbatim).
    #[serde(default)]
    // settings-leak-lint: allow — operator CONFIG struct, not a projection: this is the
    // `settings:` the operator WROTE. Every admin read of it serves
    // `service::settings_keys(&…settings)`, or passes the tree through
    // `service::redact_settings_bags` first. The struct now derives `Serialize`, and that
    // serialization has exactly ONE consumer: the overlay's per-entry merge, which projects the
    // base entry to JSON, patches it, and parses it straight back into this same struct.
    pub(crate) settings: serde_json::Map<String, serde_json::Value>,
}

/// The top-level `identity-providers:` map: provider NAME → [`IdentityProviderCfg`]. Insertion-ordered
/// so the hosted-login button order is the operator's config order.
pub(crate) type IdentityProviders = indexmap::IndexMap<String, IdentityProviderCfg>;

/// A RESOLVED auth-chain entry: one `auth.chain:` / `auth.admin_auth:` NAME joined to the
/// `identity-providers:` definition it references (or synthesized for a bare built-in that needs no
/// definition). This is an INTERNAL type built by [`resolve_auth`] — it is never deserialized, because
/// 1.5.3 removed the inline chain-entry form entirely (a chain is now a list of bare NAMES).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AuthChainEntry {
    /// The PROVIDER NAME (the `identity-providers:` key) — the runtime identity `role_bindings.<name>`
    /// binds and `auth_scope_caps` keys off. For a bare built-in this equals the module name.
    pub(crate) name: String,
    /// The module backing this provider (built-in `keys` / `admin-tokens`, or a plugin name/alias).
    pub(crate) module: String,
    /// The provider's admin ceiling, from its definition. See [`IdentityProviderCfg::max_admin_scope`].
    pub(crate) max_admin_scope: Option<String>,
    /// The `admin-tokens` operator credential, from its definition.
    pub(crate) token: Option<SecretRef>,
    /// The module's own opaque settings (pushed to an auth plugin verbatim).
    // settings-leak-lint: allow — operator CONFIG struct, not a projection: this is the
    // `settings:` the operator WROTE. Every admin read of it serves
    // `service::settings_keys(&…settings)`, or passes the tree through
    // `service::redact_settings_bags` first.
    pub(crate) settings: serde_json::Map<String, serde_json::Value>,
}

impl AuthChainEntry {
    /// A bare, definition-less built-in entry (`chain: [keys]` / `admin_auth: [admin-tokens]`).
    pub(crate) fn bare(module: impl Into<String>) -> Self {
        let module = module.into();
        Self {
            name: module.clone(),
            module,
            max_admin_scope: None,
            token: None,
            settings: serde_json::Map::new(),
        }
    }
}

/// One `auth.role_bindings.<module>.<role>` entry - the operator-owned PURE-AUTH policy granted to
/// a ROLE asserted by that specific module (bindings are NESTED BY MODULE, so `ad.platform`
/// and `oidc.platform` are distinct grants and a module can never ride another module's binding).
/// An unbound role grants NOTHING (fail closed). Limits live on the bound `group`, never here.
#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RoleBindingCfg {
    /// DATA-PLANE grant: pools this role may target. OMITTED = ALL pools;
    /// an explicit `[]` = NO pools (empty list is the empty set).
    #[serde(default)]
    pub(crate) allowed_pools: Option<Vec<String>>,
    /// The `groups:` bucket this role's principals charge through. Absent = no group (unlimited).
    #[serde(default)]
    pub(crate) group: Option<String>,
    /// The ADMIN scope this role grants: `read-only` | `full`. Absent = no admin access from this
    /// role. A principal holds the UNION of what its bound roles grant (see `Grants` in the contract
    /// module), ceilinged by the asserting module's `max_admin_scope`.
    #[serde(default)]
    pub(crate) admin_scope: Option<String>,
}

/// `role_bindings:` - module name -> role name -> grant.
pub(crate) type RoleBindings =
    std::collections::BTreeMap<String, std::collections::BTreeMap<String, RoleBindingCfg>>;

/// Per-provider browser-login parameters (`identity-providers.<name>.browser_login:`). PRESENCE of
/// this block is what makes a provider show a button on the hosted login page; a provider WITHOUT it
/// is headless-only (still usable via `POST /auth/token`). Holds the confidential-client secret used by
/// the CORE (never the plugin) during the code→token exchange. `deny_unknown_fields`: a typo here
/// (e.g. `client_secrets:`) must fail boot, not silently disable the button.
// `Serialize` for the same single reason `IdentityProviderCfg` has it: it is a nested field of one,
// so the overlay's per-entry merge projection needs it. Config-internal, never a reader-facing view.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct BrowserLoginCfg {
    /// The OAuth/OIDC confidential-client secret, a SECRET REFERENCE. OPTIONAL: only the REDIRECT
    /// (OAuth-family) flow is a confidential client that needs one — a CREDENTIAL method (LDAP/AD-bind)
    /// has none. Enforced per the method's `login_kind` at build (`login_kind == Redirect` ⇒ REQUIRED;
    /// `== Credential` ⇒ must be ABSENT). Injected by the core ONLY into the token-exchange hop's
    /// `client_secret` form field; never serialized back to the plugin.
    #[serde(default)]
    pub(crate) client_secret: Option<SecretRef>,
    /// The OAuth client id advertised on the authorize URL. Optional here (an IdP-specific plugin may
    /// carry its own); shown on the login button when present.
    #[serde(default)]
    pub(crate) client_id: Option<String>,
}

/// One RESOLVED hosted-login method — the projection of an `identity-providers:` definition that
/// carries a `browser_login:` block (freeze blocker). Built by [`resolve_auth`], never
/// deserialized: the config-facing shape is the provider definition itself, and this is just the
/// slice of it the login machinery reads.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AuthMethodCfg {
    /// The `kind: auth` PLUGIN backing this method — the provider definition's `module:`. Distinct
    /// from the map KEY, which is the provider NAME (two named providers may share one module).
    pub(crate) module: String,
    /// Browser-login parameters; `Some` ⇒ this provider renders a button on the hosted login page.
    pub(crate) browser_login: Option<BrowserLoginCfg>,
    /// The module's own opaque settings, pushed to the module verbatim (issuer, audience, …).
    // settings-leak-lint: allow — operator CONFIG struct, not a projection: this is the
    // `settings:` the operator WROTE. Every admin read of it serves
    // `service::settings_keys(&…settings)`, or passes the tree through
    // `service::redact_settings_bags` first.
    pub(crate) settings: serde_json::Map<String, serde_json::Value>,
}

/// The resolved hosted-login methods — insertion-ordered (operator order = login-page button order),
/// keyed by PROVIDER NAME.
pub(crate) type AuthMethods = indexmap::IndexMap<String, AuthMethodCfg>;

/// The WIRE shape of the `auth:` block (1.5.3). `chain:` / `admin_auth:` are lists of bare NAMES
/// referencing the top-level `identity-providers:` map (or a bare built-in) — the inline
/// `- <module>: { settings: … }` entry form is REMOVED: a provider is defined once, by name.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct AuthDeployCfg {
    /// See [`AuthCfg::signing_key`].
    #[serde(default)]
    pub(crate) signing_key: Option<SecretRef>,
    /// The DATA-PLANE authentication chain, as ordered PROVIDER NAMES. Empty (the default) is the
    /// open front door. `keys` is the built-in signed-key verifier, referenced bare.
    #[serde(default)]
    pub(crate) chain: Vec<String>,
    /// The ADMIN auth chain gating `/api/v1/admin/*`, as ordered PROVIDER NAMES. Default
    /// `[admin-tokens]`. `[]` = OPEN admin (dev only; loud boot warning).
    #[serde(default = "default_admin_auth_names")]
    pub(crate) admin_auth: Vec<String>,
    /// Role → policy bindings, NESTED BY PROVIDER NAME (see [`RoleBindingCfg`]).
    #[serde(default)]
    pub(crate) role_bindings: RoleBindings,
    /// See [`AuthCfg::key_ttl`].
    #[serde(default)]
    pub(crate) key_ttl: Option<String>,
}

impl Default for AuthDeployCfg {
    /// The all-omitted `auth:` block: open front door (empty data chain) + the default
    /// `[admin-tokens]` admin chain, matching the per-field serde defaults exactly.
    fn default() -> Self {
        Self {
            signing_key: None,
            chain: Vec::new(),
            admin_auth: default_admin_auth_names(),
            role_bindings: RoleBindings::new(),
            key_ttl: None,
        }
    }
}

/// The RESOLVED `auth:` block — each `chain:`/`admin_auth:` NAME joined to its `identity-providers:`
/// definition (see [`resolve_auth`]). This is what every runtime consumer reads; it is constructed by
/// `resolve`, never parsed from YAML.
#[derive(Debug, Clone)]
pub(crate) struct AuthCfg {
    /// The key-signing key: a SECRET REFERENCE resolving to the ed25519 signing key busbar
    /// mints + verifies virtual-key tokens with. Fleet-shared (every node verifying the same tokens
    /// resolves the same key). REQUIRED when the data-plane chain names the built-in `keys` verifier
    /// (signed-token auth); `config_validate` fails closed if it is missing there. 1.5.1 BREAKING:
    /// busbar NO LONGER auto-generates one when absent (the 1.5.0 generate-and-persist-beside-config
    /// behavior boot-looped a read-only config mount) - generate one with
    /// `busbar --generate-signing-key`. Rotating it revokes every outstanding key.
    pub(crate) signing_key: Option<SecretRef>,
    /// The DATA-PLANE authentication CHAIN — resolved provider entries in config order. Empty is the
    /// open front door.
    pub(crate) chain: Vec<AuthChainEntry>,
    /// The ADMIN auth chain gating `/api/v1/admin/*` (the parallel of `chain` for the operator
    /// surface). Default `[admin-tokens]`. `[]` = OPEN admin (dev only; loud boot warning).
    pub(crate) admin_auth: Vec<AuthChainEntry>,
    /// Role -> policy bindings, NESTED BY PROVIDER NAME (see [`RoleBindingCfg`]).
    pub(crate) role_bindings: RoleBindings,
    /// The resolved hosted-login methods — every `identity-providers:` entry, keyed by provider name
    /// (see [`AuthMethods`], freeze blocker). Empty when no providers are defined.
    pub(crate) methods: AuthMethods,
    /// Admin-set default lifetime for self-service / minted keys (`auth.key_ttl:`), a duration string
    /// (`"90d"`, `"24h"`, …) parsed by `parse_duration_secs`. Absent ⇒ the built-in
    /// `DEFAULT_KEY_TTL_SECS` (90d).
    pub(crate) key_ttl: Option<String>,
}

impl AuthCfg {
    /// Create a default (open front door, default admin chain) AuthCfg for initialization.
    pub(crate) fn default_none() -> Self {
        Self {
            signing_key: None,
            chain: vec![],
            admin_auth: default_admin_auth(),
            role_bindings: RoleBindings::new(),
            methods: AuthMethods::new(),
            key_ttl: None,
        }
    }

    /// The `admin-tokens` operator-credential secret reference, if configured.
    pub(crate) fn admin_token_ref(&self) -> Option<&SecretRef> {
        self.admin_auth
            .iter()
            .chain(self.chain.iter())
            .find(|e| e.module == ADMIN_TOKENS_MODULE)
            .and_then(|e| e.token.as_ref())
    }

    /// Whether a USABLE ADMIN MINT PATH exists — the STRUCTURAL precondition for putting the `keys`
    /// verifier in `auth.chain` (a busbar-MINTED credential can only be issued through an admin
    /// endpoint, so if nothing can mint one every data-plane request would reject). Checked at
    /// validate/boot, which runs BEFORE secrets resolve, so this is purely structural:
    /// - `admin_auth` is explicitly OPEN (`[]`) → anyone can mint (dev). TRUE — the caller WARNs.
    /// - an `admin-tokens` entry carries a `token:` secret ref → the operator credential can mint.
    /// - an external admin module names `max_admin_scope: full` → an admin IdP can mint (1.5.2 scope
    ///   collapse retired the narrower `mint` ceiling; `full` is now the only mutation grant).
    ///
    /// Does NOT resolve the token or consult `role_bindings` (neither is available here); a ceiling of
    /// `full` is the operator's explicit structural declaration that minting is reachable.
    pub(crate) fn usable_mint_path(&self) -> bool {
        if self.admin_auth.is_empty() {
            return true;
        }
        self.admin_auth.iter().any(|e| {
            (e.module == ADMIN_TOKENS_MODULE && e.token.is_some())
                || (e.module != ADMIN_TOKENS_MODULE
                    && matches!(e.max_admin_scope.as_deref(), Some("full")))
        })
    }
}

/// The built-in signed-key verifier module name (`auth.chain: [keys]`).
/// The config shape `--migrate-config` targets, for anything that needs to NAME it in output.
///
/// Derived from the crate version rather than written down, because the previous hardcoded "1.5.0"
/// in the migrator's banner was still claiming 1.5.0 three releases after the target moved. A
/// version string a human has to remember to bump is a version string that goes stale.
pub(crate) const CONFIG_TARGET_VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) const KEYS_MODULE: &str = "keys";
/// The built-in operator admin-token module name (`auth.admin_auth: [admin-tokens]`).
pub(crate) const ADMIN_TOKENS_MODULE: &str = "admin-tokens";

/// The BUILT-IN identity providers, referenced BARE from `auth.chain:`/`auth.admin_auth:` with no
/// `identity-providers:` definition at all. A definition entry for one of these exists
/// only when it needs config — `admin-tokens` carrying its `token:` secret ref is the one real case.
pub(crate) const BUILTIN_IDENTITY_PROVIDERS: &[&str] = &[KEYS_MODULE, ADMIN_TOKENS_MODULE];

/// The MOST RESTRICTIVE admin ceiling — the default for a provider whose definition omits
/// `max_admin_scope:`. "Most restrictive" is `read-only`, matching the pre-1.5.3 behavior
/// exactly (the retired chain-entry field defaulted the same way); the built-in `admin-tokens`
/// operator credential is EXEMPT (full by definition), which is why this is applied by
/// [`resolve_auth`] only to non-`admin-tokens` providers.
pub(crate) const DEFAULT_MAX_ADMIN_SCOPE: &str = "read-only";

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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)] // a typo'd provider key must fail boot, not be silently ignored.
pub(crate) struct ProviderCfg {
    #[serde(default = "default_protocol")]
    pub(crate) protocol: String,
    pub(crate) base_url: String,
    /// The provider credential as a SECRET REFERENCE - `{ env: VAR }`, `{ file: … }`, or a
    /// secret module. Resolved once at startup; the resolved value never appears in config or logs.
    pub(crate) api_key: SecretRef,
    /// Active health-probe settings for this provider's lanes (mode + interval + timeout).
    #[serde(default)]
    pub(crate) health: Option<HealthCfg>,
    // error_map is REQUIRED on every provider — NO default (fail loud if missing)
    pub(crate) error_map: HashMap<String, String>,
    /// Optional upstream request-path override (see ProviderDef::path).
    #[serde(default)]
    pub(crate) path: Option<String>,
    /// Optional path-BASE override (see ProviderDef::path_base) — replaces a URL-model protocol's
    /// hardcoded base segment so the per-request `/{model}:verb` suffix is appended to it (Vertex AI).
    #[serde(default)]
    pub(crate) path_base: Option<String>,
    /// OAuth token endpoint for `auth: oauth-client-credentials` (see ProviderDef::token_url).
    #[serde(default)]
    pub(crate) token_url: Option<String>,
    /// OAuth scope for `auth: oauth-client-credentials` (see ProviderDef::scope).
    #[serde(default)]
    pub(crate) scope: Option<String>,
    /// JWT-bearer assertion `sub` (subject) claim for `auth: jwt-bearer` (see ProviderDef::subject).
    #[serde(default)]
    pub(crate) subject: Option<String>,
    /// Optional auth-style override (see ProviderDef::auth).
    #[serde(default)]
    pub(crate) auth: Option<ProviderAuth>,
    /// Per-provider SURGICAL escape hatch: the cloud-metadata hosts/IPs to UNBLOCK for THIS
    /// provider's `base_url` (and path-override composition) only. Each entry carves a single
    /// exception out of the metadata denylist (hardcoded ∪ `security.blocked_metadata_hosts`) — e.g.
    /// `allow_metadata_hosts: ["169.254.169.254"]` lets only this provider reach IMDS while every
    /// OTHER metadata endpoint (and every other provider) stays blocked. An entry is matched with the
    /// SAME canonicalization as the block check, so an IP entry also unblocks its obfuscated spellings
    /// (decimal-int, IPv4-mapped IPv6, trailing-dot). For an everywhere-unblock use
    /// `security.allow_metadata_hosts`; for a full disable use `security.allow_all_metadata`.
    /// Loopback / RFC-1918 / CGNAT / public targets are allowed regardless — a client never chooses a
    /// provider URL (model NAME → operator pool → operator URL), so private upstreams pose no
    /// client-driven SSRF and local models (Ollama / vLLM) "just work" with no entry. Default empty
    /// (all metadata blocked).
    #[serde(default)]
    pub(crate) allow_metadata_hosts: Vec<String>,
}

/// Default provider protocol when not specified. Wire-contract: providers.yaml catalog entries
/// and un-overridden deployments use this protocol for the dispatch registry lookup.
const DEFAULT_PROTOCOL: &str = PROTO_ANTHROPIC;

fn default_protocol() -> String {
    DEFAULT_PROTOCOL.to_string()
}

/// Per-provider auth-style override. Closed set: the request is signed with the protocol's native
/// auth (`bearer`) unless `api-key` selects an `api-key: <key>` header (Azure OpenAI). The wire
/// strings are unchanged from the pre-enum `Option<String>` field (`bearer` / `api-key`), so an
/// unknown spelling is now a deserialize error instead of a hand-checked validation error.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderAuth {
    #[serde(rename = "bearer")]
    Bearer,
    #[serde(rename = "api-key")]
    ApiKey,
    /// OAuth 2.0 JWT-bearer grant (RFC 7523): the provider's credential is a signing key (delivered as
    /// a Google service-account JSON in `api_key_env`), which busbar uses to mint + auto-refresh a
    /// short-lived bearer token per lane. Generic — Vertex AI is the first provider to select it. The
    /// token minting/refresh lives in `crate::egress_auth::jwt_bearer`; this is only the selector.
    #[serde(rename = "jwt-bearer")]
    JwtBearer,
    /// OAuth 2.0 client-credentials grant (RFC 6749 §4.4): `api_key_env` carries
    /// `client_id:client_secret`, and the provider's `token_url` + `scope` complete the exchange for
    /// an auto-refreshed bearer. Generic — Azure OpenAI via Microsoft Entra ID is the first consumer.
    /// The token minting/refresh lives in `crate::egress_auth::oauth_client_credentials`.
    #[serde(rename = "oauth-client-credentials")]
    OAuthClientCredentials,
}

/// Active health-probe mode for a provider's lanes.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HealthMode {
    /// No active probing. Health is inferred purely from organic traffic (the breaker trips on
    /// real failures and recovers via the half-open probe). This is the default.
    #[default]
    None,
    /// Periodically re-probe ONLY lanes that are currently tripped (Open/HalfOpen), so a recovered
    /// upstream is picked back up promptly instead of waiting for organic traffic to probe it.
    Dead,
    /// Periodically probe EVERY lane, so a silently-dead upstream is tripped out before real
    /// traffic hits it. Sends a tiny billable request per interval — opt-in.
    Active,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct HealthCfg {
    /// Probing strategy (see `HealthMode`). Defaults to `none` — a `health:` block with only an
    /// interval does nothing until a mode is chosen.
    #[serde(default)]
    pub(crate) mode: HealthMode,
    /// Seconds between probes for this provider's lanes (default 30, floored at 1).
    #[serde(default)]
    pub(crate) interval_secs: Option<u64>,
    /// Per-probe request timeout in seconds (default 5, floored at 1).
    #[serde(default)]
    pub(crate) timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct ModelCfg {
    #[serde(default = "neg1")]
    pub(crate) max_requests: i64,
    pub(crate) provider: String,
    /// Per-lane concurrency limiter: the max number of in-flight requests admitted to this lane at
    /// once (excess requests park on the lane's semaphore until a slot frees or the request budget
    /// expires). OPTIONAL — omitted means UNBOUNDED (no concurrency cap), the same opt-in-limiter
    /// posture as `max_requests` (default -1 = unlimited). Set a positive integer to opt into a cap;
    /// `0` is rejected at boot (`config_validate`) as a lane that admits nothing. Unbounded is
    /// realized as a `Semaphore` seeded with `tokio::sync::Semaphore::MAX_PERMITS` (see main.rs) —
    /// "effectively unbounded"; a literal `usize::MAX` would panic (tokio caps permits at
    /// `MAX_PERMITS`).
    #[serde(default)]
    pub(crate) max_concurrent: Option<usize>,
    /// Default max output tokens injected when a cross-protocol translation targets a backend that
    /// REQUIRES `max_tokens` (Anthropic Messages) and the source request omitted it (legal for
    /// OpenAI). Unset falls back to `crate::proto::DEFAULT_MAX_TOKENS`. Must be > 0 when set.
    #[serde(default)]
    pub(crate) default_max_tokens: Option<u32>,
    /// Optional upstream model name override. When set, this value is sent to the provider as the
    /// model identifier in the request body and URL path, instead of the config key. Useful when
    /// the provider expects a different model string (e.g. Bedrock model IDs).
    #[serde(default)]
    pub(crate) upstream_model: Option<String>,
    /// Per-ATTEMPT time-to-response-headers cap (ms). If this lane has not returned response headers
    /// within the budget, the attempt is abandoned (transient → breaker) and the request FAILS OVER
    /// to the next member — the hang detector. Model-level default; a pool member's
    /// `attempt_timeout_ms` overrides it per workload. Absent = bounded only by the request budget.
    #[serde(default)]
    pub(crate) attempt_timeout_ms: Option<u64>,
    /// Operator declaration that THIS model accepts reasoning/thinking request parameters
    /// (Anthropic `thinking`, Gemini `thinkingConfig`, OpenAI `reasoning_effort`). Capability is
    /// per-MODEL, not per-provider (Sonnet takes `thinking`, Haiku 400s on it), and busbar keeps no
    /// model database — this flag is the operator asserting what they deployed, in the same family
    /// as `context_max`/`cost_per_mtok`. When absent/false, a cross-protocol reasoning ask is
    /// DROPPED at the seam with a warn (never sent, so a non-reasoning model can never 400 from
    /// translation). A pool member's `reasoning` overrides this per pool. Same-protocol passthrough
    /// is byte-exact and ignores the flag.
    #[serde(default)]
    pub(crate) reasoning: Option<bool>,
    /// Operator declaration that THIS model accepts prompt-cache markers on dialects where the
    /// marker is model-gated (Bedrock Converse `cachePoint`: Claude accepts it, Amazon Nova
    /// hard-rejects it with 400 "extraneous key"). Same family as `reasoning` — busbar keeps no
    /// model database, the operator asserts what they deployed. When absent/false, cross-protocol
    /// `cache_control` breakpoints headed to such a dialect are DROPPED at the seam with a warn
    /// (the request proceeds uncached — fail-safe, never a translation-induced 400). Dialects
    /// whose cache form is universally accepted (Anthropic `cache_control`) ignore this flag, as
    /// does same-protocol passthrough (byte-exact).
    #[serde(default)]
    pub(crate) prompt_caching: Option<bool>,
}

fn neg1() -> i64 {
    -1
}

/// One entry in the top-level `hooks:` NAMED-DEFINITION map (1.5.3). The map KEY is the hook
/// INSTANCE id (the name a pool or the all-pools list references); this value says which plugin backs
/// it and how it is scoped. The SAME `module` may back MULTIPLE named hooks (e.g. `pii-eng` and
/// `pii-all`, same module, different `groups:`) — the name is the instance, the module is just the
/// plugin. `groups:`/`phase:` are the SELECTION axes: a hook fires only for callers in its `groups:`
/// scope, at the pipeline stages in its `phase:` list. The remaining fields are the existing hook
/// role/projection vocabulary (`kind`, `prompt`, `on_error`, …). `deny_unknown_fields`: a typo'd key
/// fails boot, never a silent no-op. Converted to a runtime [`HookCfg`] registry entry by
/// [`hook_cfg_from_def`] (`module:` → `plugin:`); `groups:`/`phase:` carry onto the `HookCfg`.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HookDefCfg {
    /// The `kind: hook` PLUGIN backing this named hook (by signed-manifest name/alias). REQUIRED,
    /// non-empty; an unresolvable/wrong-kind reference is a fail-closed plugin-preflight error.
    pub(crate) module: String,
    /// The module's own opaque settings (busbar never interprets them; pushed to the plugin via
    /// `configure`).
    #[serde(default)]
    // settings-leak-lint: allow — operator CONFIG struct, not a projection: this is the
    // `settings:` the operator WROTE. Every admin read of it serves
    // `service::settings_keys(&…settings)`, or passes the tree through
    // `service::redact_settings_bags` first.
    pub(crate) settings: serde_json::Map<String, serde_json::Value>,
    /// SCOPE: the caller groups this hook fires for. Omit or `[]` = ALL callers. A USER is a leaf
    /// group (e.g. `user:bob`); membership walks the `groups:` tree (self OR any ancestor).
    #[serde(default)]
    pub(crate) groups: Vec<String>,
    /// PHASE: the pipeline stages this hook fires at (generalizes the single tap `at:` to a list).
    /// Omit = THE FOUR CORE STAGES and only those, never "every stage that will ever exist" (the
    /// frozen meaning of an omitted `phase:`, see the FREEZE BLOCKER on [`CORE_HOOK_PHASES`]; this
    /// doc line used to say "all stages", which is the reading that note exists to rule out).
    /// A named definition never carries the legacy `at:`, so the resolved set is readable over the
    /// admin API as `fires_at` (see [`HookCfg::resolved_stages`]).
    #[serde(default)]
    pub(crate) phase: Vec<HookStage>,
    /// The hook's MODE: `gate` (fire-and-wait) or `tap` (fire-and-forget). Default `gate` (a named
    /// hook attached to a pool is a decision point by default).
    #[serde(default)]
    pub(crate) kind: Option<HookKind>,
    /// Gate decision deadline in ms (default 1).
    #[serde(default)]
    pub(crate) timeout_ms: Option<u64>,
    /// Gate failure posture (`reject` | `nothing` | named fallback chain). Default `nothing`.
    #[serde(default)]
    pub(crate) on_error: Option<OnErrorCfg>,
    /// Gate restrict empty-intersection behavior.
    #[serde(default)]
    pub(crate) on_empty: Option<PolicyOnError>,
    /// PROMPT access grant (`no` | `ro` | `rw`).
    #[serde(default)]
    pub(crate) prompt: Option<PromptAccess>,
    /// Caller-identity access grant (`no` | `ro`).
    #[serde(default)]
    pub(crate) user: Option<UserAccess>,
    /// Ordering key (default 0).
    #[serde(default)]
    pub(crate) priority: Option<u16>,
}

/// The top-level `hooks:` NAMED-DEFINITION map (1.5.3): instance name → [`HookDefCfg`]. Insertion
/// order is preserved so the resolved registry / firing order is deterministic. This REPLACES the
/// removed `global_hooks:` list — a hook is DEFINED here once and REFERENCED by bare name (at the
/// all-pools `pools.hooks:` list or a per-pool `hooks:` list).
pub(crate) type HookDefs = indexmap::IndexMap<String, HookDefCfg>;

/// A structured `on_error:` value: a reserved keyword stays BARE
/// (`nothing` | `weighted` | `reject` | `first`); a fallback-hook reference is `{ hook: <name> }`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum OnErrorCfg {
    /// One of the reserved terminals (see [`on_error_terminal`]).
    Terminal(String),
    /// A fallback hook reference.
    Hook(String),
}

impl OnErrorCfg {
    /// The flat NAME the existing on_error chain machinery resolves (terminal word or hook name).
    pub(crate) fn as_name(&self) -> &str {
        match self {
            OnErrorCfg::Terminal(s) | OnErrorCfg::Hook(s) => s,
        }
    }
}

impl<'de> Deserialize<'de> for OnErrorCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct HookRefBody {
            hook: String,
        }

        let value = serde_yaml::Value::deserialize(deserializer)?;
        match value {
            serde_yaml::Value::String(word) => {
                if on_error_terminal(&word).is_some() {
                    Ok(OnErrorCfg::Terminal(word))
                } else {
                    Err(serde::de::Error::custom(format!(
                        "on_error keyword '{word}' is not one of the reserved terminals \
                         (nothing | weighted | reject | first); a fallback HOOK is referenced \
                         structured: `on_error: {{ hook: {word} }}`"
                    )))
                }
            }
            v @ serde_yaml::Value::Mapping(_) => {
                let body: HookRefBody =
                    serde_yaml::from_value(v).map_err(serde::de::Error::custom)?;
                if body.hook.trim().is_empty() {
                    return Err(serde::de::Error::custom(
                        "on_error: { hook: … } must name a non-empty hook",
                    ));
                }
                Ok(OnErrorCfg::Hook(body.hook))
            }
            _ => Err(serde::de::Error::custom(
                "on_error is a bare terminal (nothing | weighted | reject | first) or a \
                 structured hook reference `{ hook: <name> }`",
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PoolCfg {
    pub(crate) members: Vec<PoolMember>,
    /// Per-pool OVERRIDE of the all-pools `pools.upstream_credentials:` default (a
    /// SCALAR, so the entity value REPLACES the inherited one — it does not union). `None` = inherit
    /// the `pools:`-level default. Moved here (out of the retired `auth.upstream_credentials:`) in
    /// 1.5.3: whose credential reaches the upstream is a routing property of the pool, not of the
    /// inbound auth chain.
    pub(crate) upstream_credentials: Option<crate::auth::UpstreamCreds>,
    /// Per-pool breaker settings (resolved into `store::BreakerCfg` at startup; drives trip
    /// thresholds and cooldown backoff for this pool's lanes).
    pub(crate) breaker: Option<BreakerCfg>,
    pub(crate) failover: Option<FailoverCfg>,
    pub(crate) on_exhausted: Option<OnExhaustedCfg>,
    pub(crate) affinity: Option<AffinityCfg>,
    /// The pool's native ranking STRATEGY (a strategy name in `hooks: [...]`). `weighted`
    /// (default / absent) is today's SWRR
    /// with ZERO added cost — no `RoutingPolicy` object, byte-identical hot path. `cheapest`/`fastest`/
    /// `least_busy`/`usage` resolve a native ordering policy that runs once before the failover loop.
    /// This is the pool's ranking FLOOR.
    pub(crate) policy: PoolPolicy,
    /// The pool's GATES (the non-strategy names in `hooks: [...]`). Each names an entry in the
    /// top-level `hooks:` registry; validated to be `kind: gate` at startup.
    /// Empty = no per-pool gate (pure native ordering). Config order is preserved — it is the
    /// phase-2 chain order (order last-wins; reject/restrict commute).
    pub(crate) gates: Vec<String>,
    /// Whether the pool EXPLICITLY named its base ordering strategy (a strategy name in
    /// `hooks: [...]`), vs leaving it defaulted. `false` (defaulted) is the pool that INHERITS the
    /// `default:` hook when one is registered (else the compiled-in `weighted` backstop); `true` means
    /// the operator picked a base, so the `default:` hook does NOT override it. `policy` alone can't
    /// carry this — it defaults to `Weighted` indistinguishably from an explicit `weighted`.
    pub(crate) base_named: bool,
}

/// Whether `name` is one of the native ordering strategies (usable BARE in a pool `hooks:` list).
/// The strategy set is fixed + known at parse time; any OTHER bare name is a hook-NAME reference
/// (1.5.3: no inline instances — a hook is defined in the top-level `hooks:` map and referenced by
/// bare name here).
fn is_strategy_name(name: &str) -> bool {
    matches!(
        name,
        ON_ERROR_WEIGHTED
            | STRATEGY_CHEAPEST
            | STRATEGY_FASTEST
            | STRATEGY_LEAST_BUSY
            | STRATEGY_USAGE
    )
}

fn parse_strategy(name: &str) -> PoolPolicy {
    match name {
        STRATEGY_CHEAPEST => PoolPolicy::Cheapest,
        STRATEGY_FASTEST => PoolPolicy::Fastest,
        STRATEGY_LEAST_BUSY => PoolPolicy::LeastBusy,
        STRATEGY_USAGE => PoolPolicy::Usage,
        _ => PoolPolicy::Weighted,
    }
}

/// Manual `Deserialize` for [`PoolCfg`]: the `hooks: [...]` list is THE pool form — one ORDERED list
/// mixing an optional built-in ordering strategy (bare `cheapest`/… ) and hook NAMES (bare names
/// referencing the top-level `hooks:` DEFINITION map, 1.5.3 — no inline instances). The strategy sets
/// the base ordering; every other bare name is a hook reference stored in `gates` (validated to exist
/// and be a `kind: gate` at startup).
impl<'de> Deserialize<'de> for PoolCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deny unknown keys so a typo'd pool key fails boot.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawPoolCfg {
            #[serde(default)]
            members: Vec<PoolMember>,
            #[serde(default)]
            breaker: Option<BreakerCfg>,
            #[serde(default)]
            failover: Option<FailoverCfg>,
            #[serde(default)]
            on_exhausted: Option<OnExhaustedCfg>,
            #[serde(default)]
            affinity: Option<AffinityCfg>,
            /// The pool's hooks - an ordering strategy (bare built-in name) and/or hook NAMES
            /// (bare names referencing the top-level `hooks:` map) - in ONE ordered list.
            #[serde(default)]
            hooks: Option<Vec<String>>,
            /// Per-pool override of the all-pools `pools.upstream_credentials:` default.
            #[serde(default)]
            upstream_credentials: Option<crate::auth::UpstreamCreds>,
        }

        let raw = RawPoolCfg::deserialize(deserializer)?;

        // Split the `hooks:` list into (base policy, referenced hook names). A strategy name sets
        // the base ordering (at most one); every other name is a hook reference.
        let (policy, gates, base_named) = if let Some(entries) = raw.hooks {
            let mut policy: Option<PoolPolicy> = None;
            let mut gates: Vec<String> = Vec::new();
            for name in entries {
                if name.trim().is_empty() {
                    return Err(serde::de::Error::custom(
                        "a pool `hooks:` entry must be a non-empty strategy keyword or hook name",
                    ));
                }
                if is_strategy_name(&name) {
                    if policy.is_some() {
                        return Err(serde::de::Error::custom(
                            "a pool `hooks:` list names more than one ordering strategy; a pool \
                             has one base ordering",
                        ));
                    }
                    policy = Some(parse_strategy(&name));
                } else {
                    gates.push(name);
                }
            }
            let base_named = policy.is_some();
            (policy.unwrap_or_default(), gates, base_named)
        } else {
            (PoolPolicy::default(), Vec::new(), false)
        };

        Ok(PoolCfg {
            members: raw.members,
            upstream_credentials: raw.upstream_credentials,
            breaker: raw.breaker,
            failover: raw.failover,
            on_exhausted: raw.on_exhausted,
            affinity: raw.affinity,
            policy,
            gates,
            base_named,
        })
    }
}

/// The FROZEN reserved key set of the `pools:` SECTION (freeze blocker, 1.5.3). These two names
/// are section-level knobs, NOT pool names:
///
/// ```yaml
/// pools:
///   hooks: [pii]                  # RESERVED (LIST → ADDITIVE): attach to ALL pools
///   upstream_credentials: own     # RESERVED (SCALAR → OVERRIDE): the all-pools default
///   fast:                         # a real pool
///     members: [ ... ]
///     hooks: [cheapest, pii]
///     upstream_credentials: passthrough
/// ```
///
/// **THIS SET IS CLOSED AND MUST NEVER GROW.** Every reserved word here is a word an operator can no
/// longer use as a POOL NAME, so ADDING one in a later release retroactively turns a previously-legal
/// config into a boot failure — exactly the class of break 1.5.3 exists to make impossible. Every
/// FUTURE all-scope knob must therefore land under a reserved `defaults:` sub-key
/// (`pools.defaults.<knob>`), which costs one word ONCE and is then additive forever. The same rule
/// governs the parallel `tools:`/`agents:` sections when they ship (1.6.0): reserve the same two
/// words in every plane section, even where a plane chooses not to implement one, so the word space is
/// identical across planes.
///
/// Pinned by `pools_reserved_section_keys_are_frozen` in the config tests.
pub(crate) const RESERVED_POOLS_SECTION_KEYS: &[&str] = &["hooks", "upstream_credentials"];

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

/// The top-level `pools:` map (1.5.3), which carries the [`RESERVED_POOLS_SECTION_KEYS`] alongside the
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
    /// The real pools, keyed by name (every top-level key except [`RESERVED_POOLS_SECTION_KEYS`]).
    pub(crate) pools: HashMap<String, PoolCfg>,
}

impl<'de> Deserialize<'de> for PoolsCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Parse into a raw name→Value map so the reserved keys can be lifted out before the
        // remaining entries are parsed as pools. A bare list under `hooks` is the all-pools attach;
        // a bare `own`/`passthrough` scalar under `upstream_credentials` is the all-pools default.
        let mut raw: indexmap::IndexMap<String, serde_yaml::Value> =
            indexmap::IndexMap::deserialize(deserializer)?;
        // A RESERVED key whose value is a MAPPING is an attempt to define a POOL by that name
        // (freeze blocker). Caught here, BEFORE the typed lifts below, so the operator gets
        // "that name is reserved" instead of a confusing "expected a sequence" type error.
        for reserved in RESERVED_POOLS_SECTION_KEYS {
            if raw
                .get(*reserved)
                .is_some_and(|v| matches!(v, serde_yaml::Value::Mapping(_)))
            {
                return Err(serde::de::Error::custom(format!(
                    "a pool may not be named `{reserved}`: that key is RESERVED at the `pools:` \
                     section level (the all-pools `hooks:` attach list and `upstream_credentials:` \
                     default). Rename the pool."
                )));
            }
        }
        let all_pool_hooks: Vec<String> = match raw.shift_remove("hooks") {
            None => Vec::new(),
            Some(v) => Vec::<String>::deserialize(v).map_err(|e| {
                serde::de::Error::custom(format!(
                    "the reserved `pools.hooks:` all-pools attach must be a list of hook names: {e}"
                ))
            })?,
        };
        let all_pool_upstream_credentials = match raw.shift_remove("upstream_credentials") {
            None => None,
            Some(v) => Some(crate::auth::UpstreamCreds::deserialize(v).map_err(|e| {
                serde::de::Error::custom(format!(
                    "the reserved `pools.upstream_credentials:` all-pools default must be \
                         `own` or `passthrough`: {e}"
                ))
            })?),
        };
        let mut pools = HashMap::new();
        for (name, value) in raw {
            // A pool named by a RESERVED section key is rejected (freeze blocker): those names are
            // section-level knobs, not pools. (Lifting them out above already consumed the well-typed
            // forms; this guard catches the map-valued "I meant a pool" spelling with a precise
            // message instead of a confusing type error.)
            if RESERVED_POOLS_SECTION_KEYS.contains(&name.as_str()) {
                return Err(serde::de::Error::custom(format!(
                    "a pool may not be named `{name}`: that key is RESERVED at the `pools:` section \
                     level (the all-pools `hooks:` attach list and `upstream_credentials:` default). \
                     Rename the pool."
                )));
            }
            let pool: PoolCfg = PoolCfg::deserialize(value).map_err(serde::de::Error::custom)?;
            pools.insert(name, pool);
        }
        Ok(PoolsCfg {
            all_pool_hooks,
            all_pool_upstream_credentials,
            pools,
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

/// A pool's native ranking STRATEGY — the base ordering strategy named in a pool's `hooks:` list
/// (the retired `policy:` key). `weighted` (default / absent) is today's smooth-weighted-round-robin:
/// ZERO added cost, no policy object constructed, the byte-identical hot path. The others resolve a
/// Busbar-native ordering policy that runs once before the failover loop. This is the pool's ranking
/// FLOOR; a gate named in the pool's `hooks:` list can override it per-request.
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PoolPolicy {
    /// Smooth-weighted-round-robin (SWRR). Default and also the absent case. Zero added cost.
    #[default]
    Weighted,
    Cheapest,
    Fastest,
    LeastBusy,
    Usage,
}

impl PoolPolicy {
    /// The ranking-registry name for this strategy (`plugins::hooks::ranking::native_policy`).
    /// `weighted` returns `None` — it IS the zero-cost inline-SWRR default and constructs no policy
    /// object. Engine-level `STRATEGY_*` consts (not the ranking plugin's constants) so this
    /// compiles when the `hooks-ranking` plugin is removed; the plugin matches the same names.
    pub(crate) fn native_name(&self) -> Option<&'static str> {
        match self {
            PoolPolicy::Weighted => None,
            PoolPolicy::Cheapest => Some(STRATEGY_CHEAPEST),
            PoolPolicy::Fastest => Some(STRATEGY_FASTEST),
            PoolPolicy::LeastBusy => Some(STRATEGY_LEAST_BUSY),
            PoolPolicy::Usage => Some(STRATEGY_USAGE),
        }
    }
}

/// A hook's MODE — the `kind:` key. A hook is one thing; `tap`/`gate` just say whether busbar waits
/// for a reply. `tap` = fire-and-forget (watch). `gate` = fire-and-wait (decide: nothing / reject /
/// restrict / order / rewrite). Only a gate can influence dispatch; a gate named in a pool's `hooks:`
/// list must be `kind: gate`.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HookKind {
    Tap,
    Gate,
}

/// A hook's PROMPT access grant (`prompt:`) — the trust ladder for request content, monotonic
/// `no ⊂ ro ⊂ rw`. DEFAULT `no` (shape-only; no prompt text leaves the process). `ro` sends the
/// prompt for READ-ONLY inspection (PII screening, guardrails, audit). `rw` additionally lets a GATE
/// return a `rewrite` arm that mutates the body (compression, redaction) — rewrite REQUIRES read, so
/// it is the top rung of the SAME ladder, not a separate flag. Immutable after registration.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PromptAccess {
    #[default]
    No,
    Ro,
    Rw,
}

impl PromptAccess {
    /// Whether the prompt projection is built + sent (both `ro` and `rw`).
    pub(crate) fn sends_prompt(self) -> bool {
        !matches!(self, PromptAccess::No)
    }
    /// Whether the hook may return a `rewrite` arm (only `rw`).
    pub(crate) fn can_rewrite(self) -> bool {
        matches!(self, PromptAccess::Rw)
    }
}

/// A hook's caller-IDENTITY access grant (`user:`). `no` (default) = no identity in the payload; `ro`
/// = the governance key id/name (NEVER the secret) + the body end-user field. No `rw`: identity is
/// established by the auth plugin and hooks never rewrite it. Immutable after registration.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UserAccess {
    #[default]
    No,
    Ro,
}

impl UserAccess {
    /// Whether the caller-identity projection is built + sent (`ro`).
    pub(crate) fn sends_user(self) -> bool {
        matches!(self, UserAccess::Ro)
    }
}

/// The pipeline stage a TAP observes (`at:`). Parsed now; the seam that fires taps at each stage
/// lands in a later slice. Inert on a gate.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HookStage {
    Request,
    Candidate,
    Routing,
    Response,
}

impl HookStage {
    /// The ONE wire spelling of a stage, shared by every surface that names one: the serde
    /// representation above, the admin read projection's `at`/`phase`/`fires_at`, and any
    /// diagnostic. Kept as a method rather than re-matched per call site because the admin
    /// projection used to carry its own copy of this mapping, which is exactly how a wire
    /// vocabulary drifts from the one the parser accepts.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            HookStage::Request => "request",
            HookStage::Candidate => "candidate",
            HookStage::Routing => "routing",
            HookStage::Response => "response",
        }
    }
}

/// EVERY stage this build knows, in pipeline order: the domain [`HookCfg::fires_at_stage`] is asked
/// about when resolving a hook's actual stage set.
///
/// Deliberately a SEPARATE constant from [`CORE_HOOK_PHASES`], not an alias for it, even though the
/// two are byte-identical today. They answer different questions and are frozen to DIVERGE: this one
/// is "which stages exist", which grows with every release that adds one; `CORE_HOOK_PHASES` is
/// "which stages an omitted `phase:` means", which is FROZEN at the four and must never grow (see its
/// FREEZE BLOCKER). Collapsing them would re-introduce the precise defect that freeze note exists to
/// prevent: an added stage would silently join the default set and widen every already-deployed
/// unscoped hook.
///
/// Pinned by `all_hook_stages_lists_every_stage_variant` in the admin hook-stage projection tests.
pub(crate) const ALL_HOOK_STAGES: &[HookStage] = &[
    HookStage::Request,
    HookStage::Candidate,
    HookStage::Routing,
    HookStage::Response,
];

/// # FREEZE BLOCKER: THE FROZEN MEANING OF AN OMITTED `phase:`
///
/// **`phase:` omitted means THESE FOUR CORE STAGES — it does NOT mean "every stage that will ever
/// exist".** The distinction is the whole finding: if omission meant "all stages", then adding an
/// MCP tool-invocation stage in 1.6.0 or an A2A delegation stage in 1.6.0 would retroactively make
/// every already-deployed unscoped hook start firing at brand-new points in a brand-new plane —
/// silently widening what an operator signed off on, with no config change and no diagnostic. Pinning
/// the default to this frozen list means a later stage is strictly ADDITIVE: to fire there, a hook
/// must NAME it.
///
/// Two further properties, frozen with it:
///
/// - **`phase:` is PLANE-NEUTRAL.** These four names describe the shape of a request's lifecycle
///   (arrive → choose candidates → dispatch → finish), which every plane shares. A later plane REUSES
///   them; it does NOT re-type `phase:` into a per-plane enum, because a re-typed `phase:` would break
///   every existing hook definition.
/// - **An INAPPLICABLE phase silently does not fire** — it is NOT a config error. A hook named on both
///   `pools:` and (later) `tools:` may legitimately want a phase that only one plane reaches; making
///   that an error would mean an operator could not write one hook definition for two planes, which
///   is precisely the reuse the named-definition pattern exists to enable.
///
/// Pinned by `omitted_phase_is_exactly_the_four_core_stages` in the config tests.
pub(crate) const CORE_HOOK_PHASES: &[HookStage] = &[
    HookStage::Request,
    HookStage::Candidate,
    HookStage::Routing,
    HookStage::Response,
];

/// A resolved on_error/on_empty TERMINAL. `Weighted` (default) is the non-negotiable safety
/// stance: a broken/slow policy is indistinguishable from no policy and NEVER blocks or fails a
/// request. `Reject` is fail-closed (503). `First` uses the configured member order (a
/// deterministic degraded pick). The `on_error` CONFIG field is a free string (a fallback chain of
/// hook names bottoming out on one of these three reserved terminals); `on_empty` parses this enum
/// directly.
#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PolicyOnError {
    #[default]
    Weighted,
    Reject,
    First,
}

/// The serde default for a hook's `on_error` — `nothing`: a failing gate
/// DOES NOT PARTICIPATE by default — it cannot steer, and it cannot displace another gate's
/// verdict. Security gates opt into `reject`; ordering gates name `weighted` explicitly.
fn default_on_error() -> String {
    ON_ERROR_NOTHING.to_string()
}

/// The native ranking-strategy names — shared by the pool `hooks:` classifier/parser,
/// `PoolPolicy::native_name`, `RESERVED_HOOK_NAMES`, and the config validator's built-in-strategy
/// check, so the vocabulary cannot drift. `weighted` is NOT listed here: it is the zero-cost
/// inline-SWRR floor and its name is owned by `ON_ERROR_WEIGHTED` below.
pub(crate) const STRATEGY_CHEAPEST: &str = "cheapest";
pub(crate) const STRATEGY_FASTEST: &str = "fastest";
pub(crate) const STRATEGY_LEAST_BUSY: &str = "least_busy";
pub(crate) const STRATEGY_USAGE: &str = "usage";

/// The RESERVED on_error terminal names — every fallback chain must bottom out on one.
pub(crate) const ON_ERROR_WEIGHTED: &str = "weighted";
pub(crate) const ON_ERROR_REJECT: &str = "reject";
pub(crate) const ON_ERROR_FIRST: &str = "first";
/// The explicit DO-NOT-PARTICIPATE terminal: the failing gate simply drops out of the decision —
/// it cannot steer, and it cannot displace any OTHER gate's verdict (in the concurrent reconcile a
/// non-participating outcome is skipped by every pass). The right posture for a gate whose job is
/// orthogonal to routing (e.g. a compressor): its failure should never reshape traffic. Internally
/// identical to the `weighted` terminal — "didn't participate" and "busbar's normal ordering" are
/// the same behavior — but the NAME teaches the correct mental model.
pub(crate) const ON_ERROR_NOTHING: &str = "nothing";

/// Map an `on_error` NAME to its reserved terminal, if it is one. `None` = the name is a fallback
/// hook reference (a ranking strategy or a registry gate), resolved by routing / validated at boot.
pub(crate) fn on_error_terminal(name: &str) -> Option<PolicyOnError> {
    match name {
        ON_ERROR_WEIGHTED | ON_ERROR_NOTHING => Some(PolicyOnError::Weighted),
        ON_ERROR_REJECT => Some(PolicyOnError::Reject),
        ON_ERROR_FIRST => Some(PolicyOnError::First),
        _ => None,
    }
}

/// Names a hook may NOT take, enforced on EVERY hook-write path (boot validation, config apply, and
/// the runtime register/PUT API). Two reasons, one rule:
/// - REGISTRY UNIQUENESS: the native ranking strategies + built-in auth modules already answer to
///   their names — two things can't answer to one name.
/// - UNION DISAMBIGUATION: `on_error` is a string union of "reserved terminal"
///   vs "fallback hook name". Reserving EVERY terminal word (`weighted`/`reject`/`first`/`nothing`)
///   as an illegal hook name makes the union closed and unambiguous for machine consumers: a value
///   in this set is a terminal; anything else is a hook reference — no hook can ever collide.
/// # FREEZE BLOCKER: THE HOOK-NAME NAMESPACE IS CLOSED AS OF 1.5.3
///
/// `RESERVED_HOOK_NAMES` and the pool `hooks:` strategy keywords share ONE word space: a bare word in
/// a pool's `hooks:` list is EITHER a built-in ordering strategy OR a reference to a hook the operator
/// defined, and a bare word in `on_error:` is EITHER a reserved terminal OR a fallback hook name.
///
/// **Therefore this list must NEVER GROW.** Adding a bare terminal in a later release (a new
/// `on_error` word, a new ranking strategy, an MCP bounded-default floor) would retroactively
/// INVALIDATE a config that is legal today: an operator's hook named `least_bad` boots fine in 1.5.3
/// and would become a boot failure — or, worse, silently rebind to the new built-in — the moment the
/// word were reserved. That is exactly the break 1.5.3 exists to make impossible.
///
/// **Every future terminal must therefore arrive STRUCTURED, never as a new bare word.** The
/// mechanism already ships: `on_error:` takes `{ hook: <name> }` for a hook reference
/// ([`OnErrorCfg`]), so a new BEHAVIOR gets a new structured key (e.g. `on_error: { strategy: x }`,
/// `hooks: [{ strategy: x }]`) which no bare name can ever collide with. A structured form is
/// unambiguously not a name, so it costs zero words from the frozen space.
///
/// Pinned by `reserved_hook_names_are_frozen` in the config tests, which asserts the EXACT contents
/// (not a subset) so that adding a word here fails a test that points back at this comment.
pub(crate) const RESERVED_HOOK_NAMES: &[&str] = &[
    // on_error terminals (see ON_ERROR_*) — includes `weighted`, which is ALSO the native floor.
    ON_ERROR_WEIGHTED,
    ON_ERROR_REJECT,
    ON_ERROR_FIRST,
    ON_ERROR_NOTHING,
    // native ranking strategies (PoolPolicy::native_name)
    STRATEGY_CHEAPEST,
    STRATEGY_FASTEST,
    STRATEGY_LEAST_BUSY,
    STRATEGY_USAGE,
    // built-in auth modules (AuthModule::name)
    "tokens",
    "admin-tokens",
];

/// The FROZEN 1.5.3 hook-name word space (freeze blocker) — the UNION of [`RESERVED_HOOK_NAMES`]
/// and the pool-`hooks:` strategy keywords accepted bare by [`is_strategy_name`]. This is the exact
/// set of words an operator may NOT use as a hook name, and it is closed forever (see
/// [`RESERVED_HOOK_NAMES`] for why, and for the structured escape hatch every future terminal uses).
///
/// Kept as its own constant, rather than derived, so the freeze is a VALUE a test can pin literally:
/// `hook_name_word_space_is_frozen` asserts both that this equals the runtime union AND that its
/// contents are exactly these eleven words.
// Consumed by the freeze test (`reserved_hook_names_are_frozen`) rather than by runtime code — that
// is the POINT: it is the declared, reviewable VALUE of the freeze, and the test proves it equals
// the runtime union. Marked `allow(dead_code)` so the freeze artifact does not need a contrived
// runtime read to survive `-D warnings`.
#[allow(dead_code)]
pub(crate) const FROZEN_HOOK_NAME_WORD_SPACE: &[&str] = &[
    "admin-tokens",
    "cheapest",
    "fastest",
    "first",
    "least_busy",
    "nothing",
    "reject",
    "tokens",
    "usage",
    "weighted",
];

/// The serde default for `auth.admin_auth:` - the built-in `admin-tokens` provider, referenced bare
/// (the single operator admin token; byte-identical to the pre-chain behavior).
fn default_admin_auth_names() -> Vec<String> {
    vec![ADMIN_TOKENS_MODULE.to_string()]
}

/// The RESOLVED form of [`default_admin_auth_names`].
fn default_admin_auth() -> Vec<AuthChainEntry> {
    vec![AuthChainEntry::bare(ADMIN_TOKENS_MODULE)]
}

/// A named entry in the top-level `hooks:` registry — a single hook (tap or gate) and the `kind: hook`
/// PLUGIN that backs it. A hook is now a dlopen plugin under the hybrid ABI (the 1.5.0 retirement of
/// the out-of-process socket/webhook transport): exactly ONE `plugin:` reference names the signed
/// plugin (by manifest name/alias), loaded like a store/auth plugin. Shared runtime knobs carry over
/// from the 1.2.1 policy block. A pool references a GATE by name via its `hook:` key; global taps/gates
/// via `global_hooks:` (or inline `global: true`).
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct HookCfg {
    /// The hook's MODE: `tap` (fire-and-forget) or `gate` (fire-and-wait, returns a reply arm).
    pub(crate) kind: HookKind,
    // ── plugin reference (exactly one, required) ─────────────────────────────────────────────────
    /// The `kind: hook` PLUGIN backing this hook, by signed-manifest name or alias — resolved against
    /// the same validated plugin registry that store/auth plugins load through (fail-closed: an
    /// unresolvable or wrong-kind reference refuses to boot). This REPLACES the retired
    /// `socket`/`webhook` out-of-process transports: a hook now runs in-process behind the frozen
    /// plugin ABI. Required and non-empty.
    ///
    /// FREEZE BLOCKER: the WIRE name is `module`, matching the locked grammar's one word for "which
    /// plugin backs this instance" everywhere (`hooks.<n>.module`, `identity-providers.<n>.module`,
    /// `export.<n>.module`, `store.module`). The Rust field keeps the older `plugin` spelling only
    /// because it is referenced at ~100 internal sites; nothing user-facing says `plugin:` any more.
    /// `alias = "plugin"` is READ-ONLY back-compat so a config overlay written by an earlier build
    /// still loads — serialization always emits `module`.
    #[serde(rename = "module", alias = "plugin")]
    pub(crate) plugin: String,
    // ── shared runtime knobs ─────────────────────────────────────────────────────────────────────
    /// Hard wall-clock deadline for a gate decision, in milliseconds (default 1). An in-process gate
    /// is microseconds; RAISE it for a hook plugin that does real work (a DB/network/model call).
    /// On timeout the decision is coerced to `on_error` and the request proceeds.
    #[serde(default = "default_policy_timeout_ms")]
    pub(crate) timeout_ms: u64,
    /// Fallback when a GATE times out/errors/saturates — a NAME resolved against the same registry
    /// as any hook (default `weighted` = proceed as busbar normally would). Reserved terminals:
    /// `nothing` (do not participate — a failing gate drops out and cannot displace another gate's
    /// verdict; the posture for non-routing gates like compressors) | `weighted` (same behavior,
    /// named as the ordering floor) | `reject` (fail closed — security gates set this) | `first`.
    /// Any other name is a
    /// fallback HOOK (a built-in ranking strategy or another gate) fired when this one fails; its
    /// own `on_error` chains further, and boot validation proves every chain terminates (unknown
    /// names, taps, and cycles are boot errors).
    #[serde(default = "default_on_error")]
    pub(crate) on_error: String,
    /// PROMPT access grant: `no` (default, shape-only) | `ro` (read prompt content) | `rw` (read +
    /// may `rewrite` the body). The single trust ladder for request content; `rw` is how a gate is
    /// granted rewrite. Immutable after registration. `rw` on a tap is a config error.
    #[serde(default)]
    pub(crate) prompt: PromptAccess,
    /// Caller-IDENTITY access grant: `no` (default) | `ro` (governance key id/name — never the secret
    /// — + body end-user field). Enables route-by-who gates. Immutable after registration.
    #[serde(default)]
    pub(crate) user: UserAccess,
    /// Hook ordering key (default 0). Orders the rewrite transform chain and the phase-2 decision
    /// chain (which reject surfaces; which order is "last" — see design-hooks-v2). Ascending;
    /// ties keep globals before pool gates, then config order.
    #[serde(default)]
    pub(crate) priority: u16,
    /// TAP observation stage (`request`/`route`/`attempt`/`completion`; unset = `request`).
    /// `request` observes the (post-rewrite) request; `route` the post-reconcile candidate set;
    /// `attempt` every dispatch attempt (the failover story); `completion` the outcome — including
    /// the SYNTHETIC rejected completion, so audit taps see denials. Inert on a gate.
    #[serde(default)]
    pub(crate) at: Option<HookStage>,
    /// GATE restrict empty-intersection behavior (default `reject`, fail-closed; `weighted` is the
    /// advisory escape — the gate's restriction is skipped). Applied per gate in the phase-2
    /// reconcile.
    #[serde(default)]
    pub(crate) on_empty: Option<PolicyOnError>,
    /// OPAQUE settings map pushed to the hook via the `configure` op: sent to the plugin at
    /// load and re-pushed (commit-on-ack) by `PATCH /api/v1/admin/hooks/{name}/settings`. Busbar
    /// never interprets the contents.
    #[serde(default)]
    // settings-leak-lint: allow — operator CONFIG struct, not a projection: this is the
    // `settings:` the operator WROTE. Every admin read of it serves
    // `service::settings_keys(&…settings)`, or passes the tree through
    // `service::redact_settings_bags` first.
    pub(crate) settings: serde_json::Map<String, serde_json::Value>,
    /// The "decision observability" DECLARED-SIGNAL surface: the typed
    /// [`busbar_api::Signal`] catalog entries this hook wants computed + projected onto its own
    /// wire payload. Default empty (no signal beyond the always-on core fields) — the zero-cost
    /// default this whole design protects. Parsed via `Signal`'s own `#[serde(rename_all =
    /// "snake_case")]` derive, so an unrecognized name is a BOOT-TIME config error (this struct is
    /// `deny_unknown_fields`; a typo'd catalog name fails closed at parse, never a silent runtime
    /// no-op) — the "plugin references the typed `Signal` constant" contract, expressed here as
    /// the canonical name of that constant rather than a free-typed string a human could misspell
    /// undetected. Every hook's declaration is UNIONED once per config generation into the
    /// process-wide `RequestedSignals` bitmask (`hooks::requested_signals`) that gates every
    /// compute fn — declaring a signal here is necessary AND sufficient for it to start being
    /// computed + projected; nothing else (a code change, a recompile) is required.
    #[serde(default)]
    pub(crate) signals: Vec<busbar_api::Signal>,
    /// Fire on EVERY request — inline sugar for adding this name to `global_hooks:`. Default false.
    #[serde(default)]
    pub(crate) global: bool,
    /// Mark this hook as THE default — the base a pool inherits when it names no hook of its own.
    /// REPLACEMENT semantics (unlike `global:`, which is an overlay ON TOP of the base): a `default`
    /// hook becomes the base, so the compiled-in backstop (`weighted`) is not used. Exactly like
    /// `auth: [sso]` means the built-in `tokens` is not loaded. AT MOST ONE hook may set `default:
    /// true` (boot AND every admin apply → error naming both); 0 ⇒ the compiled-in backstop. Only an
    /// ordering hook (one that returns `order`) is a meaningful default. Default false. Resolution:
    /// `hooks::resolve_pool_ordering` gives this hook to every pool whose base is unnamed.
    #[serde(default)]
    pub(crate) default: bool,
    /// 1.5.3 named-hook SCOPE: the caller groups this hook fires for. A hook fires only for a request
    /// whose caller belongs to one of these groups (self OR any ancestor in the `groups:` tree — a
    /// USER is a leaf group, e.g. `user:bob`). EMPTY (the default) = ALL callers (unscoped). Populated
    /// from the top-level `hooks:` definition map's `groups:` key; consulted at firing time by
    /// [`caller_in_hook_groups`]. Immutable after registration.
    #[serde(default)]
    pub(crate) groups: Vec<String>,
    /// 1.5.3 named-hook PHASE set: the pipeline stages this hook fires at. GENERALIZES the single
    /// tap `at:` to a list. EMPTY (the default) falls back to `at:`, which pins exactly one stage and
    /// so preserves today's single-stage behavior byte-for-byte; with BOTH omitted the hook fires at
    /// THE FOUR CORE STAGES and only those — the frozen meaning of an omitted `phase:`, see FREEZE
    /// BLOCKER on [`CORE_HOOK_PHASES`]. (`--migrate-config` therefore writes an EXPLICIT
    /// `phase: [request]` onto a legacy tap that carried neither, so migrating never widens one.)
    /// Consulted by [`HookCfg::fires_at_stage`]. Inert on a gate (gates fire at every decision point).
    #[serde(default)]
    pub(crate) phase: Vec<HookStage>,
}

impl HookCfg {
    /// Whether this hook observes at `stage` (freeze blocker — see [`CORE_HOOK_PHASES`]).
    ///
    /// Precedence, frozen:
    /// 1. a non-empty `phase:` LIST is authoritative — the hook fires at exactly those stages;
    /// 2. otherwise the legacy single `at:` (the admin-API registration surface still carries it),
    ///    which pins one stage;
    /// 3. otherwise — BOTH omitted — the hook fires at THE FOUR CORE STAGES, and only those. Never
    ///    "every stage that will ever exist": a stage added by a later release is not in
    ///    [`CORE_HOOK_PHASES`], so it cannot retroactively widen a hook that already shipped.
    pub(crate) fn fires_at_stage(&self, stage: HookStage) -> bool {
        if !self.phase.is_empty() {
            return self.phase.contains(&stage);
        }
        match self.at {
            Some(at) => at == stage,
            None => CORE_HOOK_PHASES.contains(&stage),
        }
    }

    /// The RESOLVED stage set: every stage this hook ACTUALLY fires at, in pipeline order.
    ///
    /// This is the honest answer to the only question an operator asks about stage scoping, and
    /// neither `phase:` nor `at:` answers it alone. Reading `phase:` back tells you which of the two
    /// spellings happened to be used, not what it resolves to: an EMPTY `phase:` is ambiguous between
    /// "falls back to `at:`" and "falls back to the four core stages", and `at:` is `None` for every
    /// hook written in the current (1.5.3 named-definition) grammar, because `hook_cfg_from_def`
    /// never sets it. So the admin read projects this alongside both spellings.
    ///
    /// Computed by asking [`Self::fires_at_stage`], the SAME predicate the firing path consults,
    /// once per stage, so the read cannot drift from the behavior it describes. A future stage is
    /// picked up here for free the moment it joins [`ALL_HOOK_STAGES`].
    pub(crate) fn resolved_stages(&self) -> Vec<HookStage> {
        ALL_HOOK_STAGES
            .iter()
            .copied()
            .filter(|stage| self.fires_at_stage(*stage))
            .collect()
    }
}

/// Whether a caller bound to `caller_group` is "in" one of `hook_groups` (the named-hook scope
/// check, 1.5.3). An EMPTY `hook_groups` means the hook is UNSCOPED and fires for every caller
/// (returns `true` regardless of `caller_group`). Otherwise the caller matches iff its group — OR any
/// ancestor of it, walked through the `groups:` tree's `parent` chain — appears in `hook_groups`; a
/// caller with NO group binding never matches a scoped hook. This reuses the same acyclic `groups:`
/// tree the governance limit chain walks, so a hook scoped to `engineering` fires for a caller in a
/// `user:bob` leaf whose chain climbs through `engineering`. The walk is bounded by the tree size (a
/// validated-acyclic tree cannot revisit a node without a cycle), so an untrusted/malformed tree can
/// never spin here.
pub(crate) fn caller_in_hook_groups(
    caller_group: Option<&str>,
    hook_groups: &[String],
    groups_tree: &std::collections::BTreeMap<String, GroupCfg>,
) -> bool {
    if hook_groups.is_empty() {
        return true;
    }
    let Some(start) = caller_group else {
        return false;
    };
    let mut cursor = Some(start);
    for _ in 0..=groups_tree.len() {
        let Some(name) = cursor else { break };
        if hook_groups.iter().any(|g| g == name) {
            return true;
        }
        cursor = groups_tree.get(name).and_then(|g| g.parent.as_deref());
    }
    false
}

/// The default hard wall-clock deadline for a gate decision, in milliseconds. Used by serde's
/// `default = "default_policy_timeout_ms"`. Also the single source of truth consumed at the
/// resolution sites in [`crate::limits`] and [`crate::hooks`].
pub(crate) const DEFAULT_POLICY_TIMEOUT_MS: u64 = 1;

fn default_policy_timeout_ms() -> u64 {
    DEFAULT_POLICY_TIMEOUT_MS
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)] // a typo'd pool-member key must fail boot, not be silently ignored.
pub(crate) struct PoolMember {
    /// The member's MODEL (a `models:` key). Reference fields name the referenced thing
    /// (renamed from the 1.4.x `target:`).
    pub(crate) model: String,
    #[serde(default = "default_weight")]
    pub(crate) weight: u32,
    #[serde(default)]
    pub(crate) context_max: Option<usize>,
    /// Operator-declared routing tier (e.g. `"large"`/`"small"`/`"primary"`/`"overflow"`). Projected
    /// into the routing `Candidate` (via `MemberMeta`) and read by hook plugin policies.
    #[serde(default)]
    pub(crate) tier: Option<String>,
    /// Per-ATTEMPT time-to-response-headers cap (ms) for THIS member in THIS pool — overrides the
    /// model-level `attempt_timeout_ms`, so one model can be patient in an image pool (10000) and
    /// ruthless in a realtime pool (50). See `ModelCfg::attempt_timeout_ms` for semantics.
    #[serde(default)]
    pub(crate) attempt_timeout_ms: Option<u64>,
    /// Per-pool override of the model-level `reasoning` capability flag (member wins), so the same
    /// lane can allow thinking in a research pool and refuse it in a latency-critical one. See
    /// `ModelCfg::reasoning` for semantics.
    #[serde(default)]
    pub(crate) reasoning: Option<bool>,
    /// Free-form operator tags (e.g. `["opus"]`) a policy can match on. Projected into the routing
    /// `Candidate` and read by hook plugin policies.
    ///
    /// NOTE: the 1.4.x `cost_per_mtok:` member field is REMOVED: `rate_card` is the ONLY cost
    /// source, and routing (`cheapest`) derives its scalar from the member's model's rate entry.
    #[serde(default)]
    pub(crate) tags: Vec<String>,
}

fn default_weight() -> u32 {
    1
}

/// The routing-scalar projection of a rate entry (abstract units per million tokens), fed to the
/// `cheapest` policy and the hook `Candidate.cost_per_mtok` signal: the blended
/// (input + output) / 2 (1 micro-unit/token == 1 unit/mtok, so no further scaling).
pub(crate) fn rate_entry_per_mtok(r: &RateEntryCfg) -> f64 {
    (r.input_utok + r.output_utok) / 2.0
}

/// Trip mode for breaker configuration.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BreakerTripMode {
    #[default]
    ErrorRate,
    Consecutive,
}

/// Trip configuration parameters (ADR-0002 defaults).
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct BreakerTripConfig {
    #[serde(default = "default_trip_mode")]
    pub(crate) mode: BreakerTripMode,
    /// Sliding-window length in seconds (one canonical name; the pre-1.0 `window_s` alias is
    /// GONE - an unknown key fails boot).
    #[serde(default = "default_window_secs")]
    pub(crate) window_secs: u64,
    #[serde(default = "default_threshold")]
    pub(crate) threshold: f64,
    #[serde(default = "default_min_requests")]
    pub(crate) min_requests: usize,
    /// Consecutive-failure threshold for `BreakerTripMode::Consecutive` (one canonical name;
    /// the pre-1.0 `n` alias is GONE).
    #[serde(default = "default_consecutive_n")]
    pub(crate) consecutive_n: u32,
}

fn default_trip_mode() -> BreakerTripMode {
    BreakerTripMode::ErrorRate
}

/// Default sliding-window length in seconds for the breaker trip evaluation (ADR-0002).
const DEFAULT_BREAKER_WINDOW_SECS: u64 = 30;
/// Default error-rate threshold for tripping the breaker (fraction in (0.0, 1.0]).
const DEFAULT_BREAKER_THRESHOLD: f64 = 0.5;
/// Default minimum request count before the error-rate breaker can trip.
const DEFAULT_BREAKER_MIN_REQUESTS: usize = 5;
/// Default consecutive-failure streak length for `BreakerTripMode::Consecutive`.
const DEFAULT_BREAKER_CONSECUTIVE_N: u32 = 3;

fn default_window_secs() -> u64 {
    DEFAULT_BREAKER_WINDOW_SECS
}

fn default_threshold() -> f64 {
    DEFAULT_BREAKER_THRESHOLD
}

fn default_min_requests() -> usize {
    DEFAULT_BREAKER_MIN_REQUESTS
}

fn default_consecutive_n() -> u32 {
    DEFAULT_BREAKER_CONSECUTIVE_N
}

/// Breaker configuration per pool with full trip settings (ADR-0002).
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct BreakerCfg {
    #[serde(default = "default_cooldown")]
    pub(crate) base_cooldown_secs: u64,
    #[serde(default = "default_max_cooldown")]
    pub(crate) max_cooldown_secs: u64,
    #[serde(default)]
    pub(crate) trip: Option<BreakerTripConfig>,
}

impl Default for BreakerCfg {
    fn default() -> Self {
        // Delegate to the serde-default fns so the `breaker:`-omitted path (this `Default`) and the
        // per-field-omitted path (`#[serde(default = ...)]`) share a single source of truth for the
        // cooldown literals and cannot drift. See `breaker_cfg_default_matches_serde_default_fns`.
        Self {
            base_cooldown_secs: default_cooldown(),
            max_cooldown_secs: default_max_cooldown(),
            trip: Some(BreakerTripConfig::default()),
        }
    }
}

/// Default base cooldown (seconds) for the escalating breaker back-off (ADR-0002). Single source
/// of truth for both `BreakerCfg::default()` and the `#[serde(default)]` path.
const DEFAULT_BREAKER_BASE_COOLDOWN_SECS: u64 = 15;
/// Default maximum cooldown (seconds) for the escalating breaker back-off (ADR-0002).
const DEFAULT_BREAKER_MAX_COOLDOWN_SECS: u64 = 120;

fn default_cooldown() -> u64 {
    // Single source of truth for the base cooldown: both `BreakerCfg::default()` (used when a pool
    // omits the `breaker:` block) and `#[serde(default = "default_cooldown")]` (used when the block
    // is present but omits `base_cooldown_secs`) route through here, so the value is a consistent
    // 15s on every path.
    DEFAULT_BREAKER_BASE_COOLDOWN_SECS
}

fn default_max_cooldown() -> u64 {
    DEFAULT_BREAKER_MAX_COOLDOWN_SECS
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct FailoverCfg {
    /// Failover wall-clock budget in seconds (one canonical name; the pre-1.0 `deadline_secs`
    /// alias is GONE).
    #[serde(default = "default_failover_timeout")]
    pub(crate) timeout_secs: u64,
    /// Member model names excluded from this pool's candidate set — never selected (primary or
    /// failover). A per-pool blocklist for temporarily benching a member without editing `members`.
    #[serde(default)]
    pub(crate) exclusions: Option<Vec<String>>,
    /// Maximum failover hops per request (one canonical name; the pre-1.0 `cap` alias is GONE).
    #[serde(default = "default_max_hops")]
    pub(crate) max_hops: usize,
}

/// Default failover wall-clock budget (seconds) when a pool doesn't set `failover.timeout_secs`.
pub(crate) const DEFAULT_FAILOVER_DEADLINE_SECS: u64 = 120;
/// Upper bound (seconds) on a pool's `failover.timeout_secs`. 24h is already absurdly long for a
/// per-request failover budget — anything larger is a fat-finger typo (extra zeros). Enforced at
/// `--validate`/boot so a merely-oversized value fails CLOSED with an actionable message instead of
/// being accepted and later feeding `RequestCtx::new` a duration large enough to overflow the
/// monotonic-clock `Instant` math (see `RequestCtx::new`).
pub(crate) const MAX_FAILOVER_DEADLINE_SECS: u64 = 86_400;
/// Default maximum failover hops per request when a pool doesn't set `failover.max_hops`.
pub(crate) const DEFAULT_FAILOVER_CAP: usize = 3;

fn default_failover_timeout() -> u64 {
    DEFAULT_FAILOVER_DEADLINE_SECS
}

fn default_max_hops() -> usize {
    DEFAULT_FAILOVER_CAP
}

/// A pool's STRUCTURED `on_exhausted:` (a keyword stays bare, a reference is structured):
///
/// ```yaml
/// on_exhausted: reject                       # 503 + Retry-After (the default)
/// on_exhausted: least_bad                    # degraded: soonest-recovering member
/// on_exhausted: { fallback_pool: cold }      # route to another pool
/// on_exhausted: { queue: { max_ms: 250 } }   # bounded wait for a freed permit, then reject
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OnExhaustedCfg {
    Reject,
    LeastBad,
    FallbackPool(String),
    /// Bounded wait for a concurrency permit to free on an at-capacity member, then fall through to
    /// reject. `max_ms` is the wait ceiling in milliseconds (validated `> 0` and `<= resolved
    /// failover.timeout_secs * 1000` at `--validate`).
    Queue {
        max_ms: u64,
    },
}

impl OnExhaustedCfg {
    /// The executable behavior this config value selects.
    pub(crate) fn to_runtime(&self) -> OnExhausted {
        match self {
            OnExhaustedCfg::Reject => OnExhausted::Status503,
            OnExhaustedCfg::LeastBad => OnExhausted::LeastBad,
            OnExhaustedCfg::FallbackPool(name) => OnExhausted::FallbackPool(name.clone()),
            OnExhaustedCfg::Queue { max_ms } => OnExhausted::Queue { max_ms: *max_ms },
        }
    }
}

impl<'de> Deserialize<'de> for OnExhaustedCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct FallbackBody {
            fallback_pool: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct QueueInner {
            max_ms: u64,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct QueueBody {
            queue: QueueInner,
        }

        let value = serde_yaml::Value::deserialize(deserializer)?;
        match value {
            serde_yaml::Value::String(word) => match word.as_str() {
                "reject" => Ok(OnExhaustedCfg::Reject),
                "least_bad" => Ok(OnExhaustedCfg::LeastBad),
                other => Err(serde::de::Error::custom(format!(
                    "unknown on_exhausted keyword '{other}': the bare keywords are `reject` | \
                     `least_bad`; a fallback pool is referenced structured: \
                     `on_exhausted: {{ fallback_pool: <pool> }}`, a bounded wait as \
                     `on_exhausted: {{ queue: {{ max_ms: <ms> }} }}`"
                ))),
            },
            v @ serde_yaml::Value::Mapping(_) => {
                // A structured `on_exhausted` mapping is DISAMBIGUATED by its key set rather than
                // force-fit into `FallbackBody` — peek the top-level keys so `fallback_pool` and
                // `queue` route to distinct variants, both keys present is an explicit error, and an
                // unrecognized mapping still gets the actionable "one of …" message.
                let has_fallback = v.get("fallback_pool").is_some();
                let has_queue = v.get("queue").is_some();
                match (has_fallback, has_queue) {
                    (true, true) => Err(serde::de::Error::custom(
                        "on_exhausted takes exactly one of `fallback_pool` | `queue`, not both",
                    )),
                    (true, false) => {
                        let body: FallbackBody =
                            serde_yaml::from_value(v).map_err(serde::de::Error::custom)?;
                        if body.fallback_pool.trim().is_empty() {
                            return Err(serde::de::Error::custom(
                                "on_exhausted: { fallback_pool: … } must name a non-empty pool",
                            ));
                        }
                        Ok(OnExhaustedCfg::FallbackPool(body.fallback_pool))
                    }
                    (false, true) => {
                        let body: QueueBody =
                            serde_yaml::from_value(v).map_err(serde::de::Error::custom)?;
                        Ok(OnExhaustedCfg::Queue {
                            max_ms: body.queue.max_ms,
                        })
                    }
                    (false, false) => Err(serde::de::Error::custom(
                        "on_exhausted is `reject`, `least_bad`, `{ fallback_pool: <pool> }`, or \
                         `{ queue: { max_ms: <ms> } }`",
                    )),
                }
            }
            _ => Err(serde::de::Error::custom(
                "on_exhausted is `reject`, `least_bad`, `{ fallback_pool: <pool> }`, or \
                 `{ queue: { max_ms: <ms> } }`",
            )),
        }
    }
}

/// Pool exhaustion mode - the executable behavior when all members are tripped/excluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OnExhausted {
    /// Status503: return 503 Service Unavailable with Retry-After header
    /// set to the soonest member's cooldown expiry.
    Status503,
    /// FallbackPool(name): route to a configured fallback pool by name.
    /// Guard against loops via depth cap (max 1) or visited pool tracking.
    FallbackPool(String),
    /// LeastBad: send to the member with soonest cooldown expiry even though Open.
    /// Log loudly that this is a degraded path.
    LeastBad,
    /// Queue{max_ms}: wait up to `max_ms` (bounded also by the failover budget) for a concurrency
    /// permit to free on an at-capacity member, dispatch on the freed lane, else fall through to a
    /// 503 + Retry-After. Handled in `walk.rs` on_exhausted dispatch, never inside `pick_among`.
    Queue { max_ms: u64 },
}

/// Affinity mode. `session` is the default and only supported mode. Modelled as a (currently
/// single-variant) enum so an unrecognized spelling (e.g. `sticky`) is a deserialize error rather
/// than a silently-accepted value that degrades to default behaviour. The wire string (`session`)
/// is unchanged from the pre-enum `String` field.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AffinityMode {
    #[default]
    Session,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct AffinityCfg {
    /// Affinity mode. `session` (the default and only supported mode) pins a session to a lane
    /// using the header named by `header_name`.
    #[serde(default)]
    pub(crate) mode: AffinityMode,
    /// Request header carrying the session id (defaults to `x-session-id` when unset).
    #[serde(default)]
    pub(crate) header_name: Option<String>,
}

/// Default listen address for the inbound HTTP server.
pub(crate) const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:8080";

fn default_listen() -> String {
    DEFAULT_LISTEN_ADDR.into()
}

/// Default admin-plane listen address. The admin API (`/api/v1/admin/…`) ALWAYS runs on its own
/// listener, never sharing the data port — the management plane is privileged and stays isolated by
/// default. The default binds LOOPBACK so a zero-config deployment boots (an exposed default would
/// trip the mTLS boot-guard); to manage Busbar off-host, set an exposed `admin_listen` with
/// `admin_tls.client_ca_file` (mTLS) or an explicit `admin_require_mtls: false` waiver.
pub(crate) const DEFAULT_ADMIN_LISTEN_ADDR: &str = "127.0.0.1:8081";

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

/// Provider definition - vetted knowledge shipped in providers.yaml (no keys).
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ProviderDef {
    pub(crate) protocol: String,
    pub(crate) base_url: String,
    #[serde(default)]
    pub(crate) error_map: HashMap<String, String>,
    #[serde(default)]
    pub(crate) health: Option<HealthCfg>,
    /// Optional override of the upstream request path appended to `base_url`. Defaults to the
    /// protocol's standard path. Use it for OpenAI-compatible providers that embed the API version
    /// in `base_url` and serve `/chat/completions` (no `/v1`), e.g. `base_url: .../api/paas/v4` +
    /// `path: /chat/completions`.
    #[serde(default)]
    pub(crate) path: Option<String>,
    /// Optional path-BASE override for URL-model protocols (Gemini): replaces the protocol's
    /// hardcoded base segment (`/v1beta/models`) so the per-request `/{model}:verb` suffix is appended
    /// to a different layout. Unlike `path` (a static full path that ignores the model), `path_base`
    /// keeps the model in the URL — e.g. Vertex AI: `path_base:
    /// /v1/projects/{project}/locations/{location}/publishers/google/models`.
    #[serde(default)]
    pub(crate) path_base: Option<String>,
    /// OAuth token endpoint for `auth: oauth-client-credentials` — the URL busbar POSTs the client
    /// credentials to for a bearer. Required for that auth style; ignored otherwise. E.g. Azure Entra:
    /// `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`.
    #[serde(default)]
    pub(crate) token_url: Option<String>,
    /// OAuth scope for `auth: oauth-client-credentials`. Required for that auth style; ignored
    /// otherwise. E.g. Azure OpenAI: `https://cognitiveservices.azure.com/.default`.
    #[serde(default)]
    pub(crate) scope: Option<String>,
    /// JWT-bearer assertion `sub` (subject) claim for `auth: jwt-bearer` (RFC 7523 §3). Optional and
    /// UNSET by default — omitted entirely, not merely empty. Google's own client libraries
    /// (`google-auth-python` et al.) only emit `sub` when a subject/impersonation is explicitly
    /// configured, because for a Google service account the mere PRESENCE of `sub` switches the grant
    /// into domain-wide-delegation/impersonation semantics regardless of its value — so this must stay
    /// opt-in, never defaulted to `iss`, or every plain (non-delegated) service account (e.g. the
    /// shipped Vertex AI setup) starts failing `unauthorized_client`/`invalid_grant`. Set this only when
    /// impersonating a specific principal (Google domain-wide delegation) or when a non-Google IdP's
    /// jwt-bearer profile requires `sub`. Ignored for every other auth style.
    #[serde(default)]
    pub(crate) subject: Option<String>,
    /// Optional auth-style override. Defaults to the protocol's native auth (bearer for
    /// openai/anthropic/responses, `x-goog-api-key` for gemini, SigV4 for bedrock). Set to
    /// `api-key` for backends that authenticate with an `api-key: <key>` header instead of a
    /// bearer token — e.g. Azure OpenAI (which also carries `?api-version=` and the deployment in
    /// its `path`). Recognized values: `bearer` (default) | `api-key`.
    #[serde(default)]
    pub(crate) auth: Option<ProviderAuth>,
    /// Catalog default for the per-provider metadata allow-override (see
    /// `ProviderCfg::allow_metadata_hosts`). A deployment's `allow_metadata_hosts` (`Some`) replaces
    /// this; `None` falls back to the catalog list. Default empty (all metadata blocked).
    #[serde(default)]
    pub(crate) allow_metadata_hosts: Vec<String>,
}

/// Provider deployment - operator config in config.yaml (names provider + supplies key).
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderDeploy {
    /// The provider credential as a SECRET REFERENCE. Replaces the removed `api_key_env:`
    /// (`api_key_env: VAR` becomes `api_key: { env: VAR }`).
    pub(crate) api_key: SecretRef,
    #[serde(default)]
    pub(crate) protocol: Option<String>,
    #[serde(default)]
    pub(crate) base_url: Option<String>,
    #[serde(default)]
    pub(crate) error_map: Option<HashMap<String, String>>,
    /// Optional upstream request-path override (see ProviderDef::path).
    #[serde(default)]
    pub(crate) path: Option<String>,
    /// Optional path-BASE override (see ProviderDef::path_base) — replaces a URL-model protocol's
    /// hardcoded base segment so the per-request `/{model}:verb` suffix is appended to it (Vertex AI).
    #[serde(default)]
    pub(crate) path_base: Option<String>,
    /// OAuth token endpoint for `auth: oauth-client-credentials` (see ProviderDef::token_url).
    #[serde(default)]
    pub(crate) token_url: Option<String>,
    /// OAuth scope for `auth: oauth-client-credentials` (see ProviderDef::scope).
    #[serde(default)]
    pub(crate) scope: Option<String>,
    /// JWT-bearer assertion `sub` claim for `auth: jwt-bearer` (see ProviderDef::subject). Opt-in;
    /// unset (the default) means no `sub` claim, unchanged from before this field existed.
    #[serde(default)]
    pub(crate) subject: Option<String>,
    /// Optional auth-style override (see ProviderDef::auth).
    #[serde(default)]
    pub(crate) auth: Option<ProviderAuth>,
    /// Per-provider metadata allow-override (see `ProviderCfg::allow_metadata_hosts`). `Some` REPLACES
    /// the catalog default; `None` falls back to the catalog's `allow_metadata_hosts`.
    #[serde(default)]
    pub(crate) allow_metadata_hosts: Option<Vec<String>>,
    /// Optional active health-probe settings (see ProviderDef::health). Overrides the catalog's
    /// `health` when set; this is the block the shipped `config.yaml` documents under a provider.
    #[serde(default)]
    pub(crate) health: Option<HealthCfg>,
}

/// Deployment configuration - operator-owned config.yaml structure.
// deny_unknown_fields: a typo'd or unknown TOP-LEVEL key (e.g. `plugin:` for `plugins:`) must be a
// loud startup error, not a silently-ignored block - the fail-closed posture every nested
// security-relevant struct (auth/governance/plugins/security) already enforces.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeployCfg {
    #[serde(default = "default_listen")]
    pub(crate) listen: String,
    /// busbar's PUBLIC base URL (top-level `public_url:`) — see [`RootCfg::public_url`]. Absent by
    /// default; required once a `browser_login` method or `/auth/token` link generation is in play.
    #[serde(default)]
    pub(crate) public_url: Option<String>,
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
    /// Optional pointer to the providers CATALOG file (`providers_file:`, 1.5.3 — migrated from the
    /// `BUSBAR_PROVIDERS` env var). Relative paths resolve against the config.yaml directory. Absent ⇒
    /// `providers.yaml` next to the resolved config.yaml (the `BUSBAR_PROVIDERS` env var still works as
    /// a deprecated fallback for one release). The two-file model is preserved: this names the vetted,
    /// shippable catalog that config.yaml's `providers:` map references.
    #[serde(default)]
    pub(crate) providers_file: Option<String>,
    /// The top-level `mcp:` block (1.6.0): busbar's own MCP endpoint, as an OAuth 2.1 resource
    /// server. Its PRESENCE is what mounts the MCP plane — absent, the deployment carries no MCP
    /// ingress and no `.well-known` document, and nothing joins the route table. See
    /// [`crate::mcp::McpCfg`].
    #[serde(default)]
    pub(crate) mcp: Option<crate::mcp::McpCfg>,
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
    #[serde(default)]
    pub(crate) tools: crate::mcp::config::ToolsCfg,
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
    pub(crate) store: Option<StoreCfg>,
    /// Module-level `open()` config for `kind: secret` plugins, keyed by module name — the delivery
    /// path a Vault-style secret plugin needs (address / namespace / auth token / CA). Absent = every
    /// secret plugin opens with `{}`. Mirrors `store.settings` for the store plugin.
    #[serde(default)]
    pub(crate) secrets: std::collections::BTreeMap<String, SecretModuleCfg>,
    /// Internal tuning knobs (the `advanced:` block).
    #[serde(default)]
    pub(crate) advanced: AdvancedCfg,
    /// The top-level `export:` NAMED-DEFINITION map (1.5.3): instance name → [`ExportDefCfg`]. THE
    /// single telemetry-egress surface. Absent/empty ⇒ collection inert (no recorder, no request-log
    /// sink, no tracer).
    ///
    /// 1.5.3 also DELETED the `observability:` block outright: its last remaining field
    /// (`otlp_url`) is now an `export:` instance with `module: otlp`. A config still carrying
    /// `observability:` LOUD-FAILS with the `--migrate-config` breadcrumb.
    #[serde(default)]
    pub(crate) export: ExportDefs,
    /// The top-level `agents:` NAMED-DEFINITION map (1.6.0): agent NAME →
    /// [`crate::a2a::config::AgentDefCfg`]. THE A2A plane. Sibling in shape to `pools:` and
    /// `tools:`, carrying the same two reserved section words, and no entry on it may reference an
    /// entry on another plane. Absent ⇒ no agent is registered and nothing can be delegated to.
    #[serde(default)]
    pub(crate) agents: crate::a2a::config::AgentsCfg,
    /// The top-level `tool_pools:` map (1.6.0) — MCP FAILOVER, and OPT-IN. Pool name →
    /// [`crate::failover::CandidatePoolCfg`], whose `members:` are bare names from `tools:`.
    ///
    /// The same concept as `pools:` on the model plane, deliberately spelled with the same words, so
    /// an operator learns "a pool is a set of interchangeable upstreams" ONCE. ABSENT ⇒ no MCP
    /// failover anywhere, which is every deployment that exists today.
    ///
    /// It is a SEPARATE top-level section rather than a reserved key inside `tools:` for one reason:
    /// adding a reserved word to an existing section container retroactively outlaws a server name
    /// that is legal today, and the config grammar is additive-only after 1.5.3.
    #[serde(default)]
    pub(crate) tool_pools: std::collections::BTreeMap<String, crate::failover::CandidatePoolCfg>,
    /// The top-level `agent_pools:` map (1.6.0) — A2A FAILOVER, and OPT-IN. Pool name →
    /// [`crate::failover::CandidatePoolCfg`], whose `members:` are bare names from `agents:`.
    ///
    /// The A2A twin of `tool_pools:`, sharing its type rather than copying its shape: a second struct
    /// would be a second grammar for one idea, and the two would diverge the first time either grew a
    /// key. Which registry a bare name resolves against is decided by the SECTION it is written in,
    /// exactly as `tools:` and `agents:` already decide which plane an entry is on — so there is no
    /// selector that could disagree with the section, and no pool can straddle two planes.
    #[serde(default)]
    pub(crate) agent_pools: std::collections::BTreeMap<String, crate::failover::CandidatePoolCfg>,
    /// The dynamic plugin subsystem (`plugins:` block, top-level). Absent = disabled (the default
    /// `enabled: false` master switch): no plugin is ever discovered or loaded.
    #[serde(default)]
    pub(crate) plugins: PluginsCfg,
    /// Optional security controls. Today this carries only `blocked_metadata_hosts`, the operator
    /// extension to the hardcoded cloud-metadata SSRF denylist. Absent ⇒ only the hardcoded denylist
    /// applies.
    #[serde(default)]
    pub(crate) security: Option<SecurityCfg>,
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

/// Operator-owned security controls (config.yaml `security:` block).
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecurityCfg {
    /// Additional hosts/IPs APPENDED to the hardcoded cloud-metadata denylist. A provider `base_url`
    /// resolving to any of these is rejected at boot (unless carved out by an allow-override),
    /// exactly like the built-in metadata endpoints. This is the answer to "an unknown cloud's
    /// metadata IP/hostname is not in the built-in list" — add it here. Entries may be IP literals
    /// (matched against the resolved host, including the obfuscation-decoded forms) or DNS hostnames
    /// (matched case-insensitively, trailing dot stripped). Default empty.
    #[serde(default)]
    pub(crate) blocked_metadata_hosts: Vec<String>,
    /// Global SURGICAL allow-override: hosts/IPs to UNBLOCK from the cloud-metadata denylist for ALL
    /// providers. Carves a single exception out of the denylist everywhere (the everywhere-scoped
    /// twin of per-provider `allow_metadata_hosts`). An IP entry also unblocks its obfuscated
    /// spellings, mirroring how a block entry blocks all spellings. Default empty.
    #[serde(default)]
    pub(crate) allow_metadata_hosts: Vec<String>,
    /// Nuclear override: when true the cloud-metadata SSRF guard is FULLY DISABLED for every provider
    /// (every metadata/IMDS endpoint becomes reachable). Logs a startup WARNING. Default false.
    #[serde(default)]
    pub(crate) allow_all_metadata: bool,
}

/// The top-level `plugins:` block — the ONLY configuration surface of the dynamic plugin subsystem.
/// A plugin is a plugin: store, auth, and hook plugins share this one block (one directory, one
/// trust model, one master switch); the manifest `kind` inside each signed tarball selects which
/// engine subsystem consumes it.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct PluginsCfg {
    /// MASTER SWITCH, default FALSE. When false (or the whole `plugins:` block is absent), NO
    /// plugin is ever loaded — a tarball dropped into the directory is INERT. Referencing a plugin
    /// while disabled (`store.module:` other than `memory`) is a BOOT ERROR naming this flag.
    #[serde(default)]
    pub(crate) enabled: bool,
    /// Directory the signed plugin tarballs live in. Default `plugins` (relative to the working
    /// directory).
    #[serde(default = "default_plugins_dir")]
    pub(crate) dir: String,
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
    pub(crate) fn to_policy(&self) -> Result<busbar_plugin_sign::TrustPolicy, String> {
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
                tracing::warn!(
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
                tracing::warn!(
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

/// The compiled-in store name (`store.module: memory`) - the only store that is not a plugin.
pub(crate) const GOVERNANCE_STORE_MEMORY: &str = "memory";

/// The top-level `store:` block: the durable store as `{ module, settings }` - the same
/// module/settings shape as every other plugin instance. `settings` is the store module's OWN
/// config, passed through verbatim (the built-in sqlite plugin reads `db_path` /
/// `busy_timeout_ms`; postgres/valkey read `url`). Absent block = the compiled-in ephemeral RAM
/// store (keys/usage reset on restart).
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoreCfg {
    /// The store module, by plugin ALIAS or CANONICAL NAME. `memory` (default) is the compiled-in
    /// ephemeral RAM store. Anything else names a STORE PLUGIN resolved from the `plugins.*`
    /// registry - the shipped first-party stores (`sqlite` / `postgres` / `valkey`, canonically
    /// `busbar-store-<x>-plugin`) or a third-party store by its manifest name. A non-`memory` store
    /// REQUIRES `plugins.enabled: true`; anything else is a boot error naming the flag.
    #[serde(default = "default_governance_store")]
    pub(crate) module: String,
    /// The module's own opaque settings, passed through verbatim as its config JSON.
    #[serde(default)]
    // settings-leak-lint: allow — operator CONFIG struct, not a projection: this is the
    // `settings:` the operator WROTE. Every admin read of it serves
    // `service::settings_keys(&…settings)`, or passes the tree through
    // `service::redact_settings_bags` first.
    pub(crate) settings: serde_json::Map<String, serde_json::Value>,
}

impl Default for StoreCfg {
    fn default() -> Self {
        Self {
            module: default_governance_store(),
            settings: serde_json::Map::new(),
        }
    }
}

fn default_governance_store() -> String {
    GOVERNANCE_STORE_MEMORY.to_string()
}

/// A top-level `secrets:` entry — MODULE-LEVEL initialization config for a `kind: secret` plugin,
/// keyed by the module NAME (alias or canonical). This is the delivery path for the config a secret
/// plugin needs in its `open()` (a Vault plugin's address / namespace / auth token / TLS CA), exactly
/// as `store.settings` carries a store plugin's `open()` config. WITHOUT this block a `kind: secret`
/// plugin's `open()` receives `{}`, forcing operators to repeat every piece of module config in EVERY
/// individual `SecretRef.settings` (multiplying exposure of the Vault address/token). The built-in
/// `env` / `file` modules take no module config and MUST NOT appear here (validated).
///
/// The `settings` are resolved against the BUILT-IN `env` / `file` secret resolvers ONLY (so
/// `{ token: { env: VAULT_TOKEN } }` works) — NEVER against another secret plugin, which would be a
/// bootstrap cycle (a secret module cannot resolve its OWN config through itself).
///
/// # FREEZE BLOCKER: `secrets:` IS A DELIBERATE EXEMPTION FROM THE NAMED-INSTANCE PATTERN
///
/// Every OTHER plugin-instance kind in 1.5.3 is a top-level NAMED-DEFINITION map — `hooks:`,
/// `identity-providers:`, `export:`, `store:` are all `name → {module, settings, …}` and are
/// referenced by bare name. **`secrets:` is deliberately NOT, and must stay that way.**
///
/// The reason is that `secrets:` does not configure an INSTANCE. It configures a MODULE's `open()` —
/// the one-time initialization of the secret backend itself. There is nothing to reference by name:
/// a `SecretRef` already names its module (`{ module: vault, settings: {…} }`), and the entry here
/// supplies the module-wide half of that module's configuration. Wrapping it in a named map would
/// invent an instance identity that no reference site can use, and would then require every
/// `SecretRef` in the config to be rewritten to point at an instance name instead of a module — a
/// large break that buys nothing.
///
/// This is recorded HERE, on the struct, precisely so nobody later "fixes" the inconsistency: the
/// module-keyed shape is the correct shape for module-level `open()` config, and it is frozen.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecretModuleCfg {
    /// The module's own opaque module-level settings, delivered to the plugin's `open()` as its config
    /// JSON. Any `SecretRef`-typed value (e.g. `token: { env: VAULT_TOKEN }`) is resolved via the
    /// built-in env/file modules before it crosses the ABI.
    #[serde(default)]
    // settings-leak-lint: allow — operator CONFIG struct, not a projection: this is the
    // `settings:` the operator WROTE. Every admin read of it serves
    // `service::settings_keys(&…settings)`, or passes the tree through
    // `service::redact_settings_bags` first.
    pub(crate) settings: serde_json::Map<String, serde_json::Value>,
}

/// The `advanced:` block - INTERNAL tuning knobs (formerly under `governance:`). Every field
/// defaults to its historical value; the whole block is normally omitted.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdvancedCfg {
    /// Amortization interval for the rate-limiter stale-entry sweep: every Nth `check_rate` pays
    /// the full retain (default 256).
    #[serde(default = "default_rate_sweep_interval")]
    pub(crate) rate_sweep_interval: u32,
    /// Write-behind flush cadence (ms) for the in-memory usage/budget counters. On an UNGRACEFUL
    /// crash (kill -9 / power loss) at most this many ms of accrued spend/requests can be lost; a
    /// graceful shutdown flushes fully. Default 100.
    #[serde(default = "default_usage_flush_interval_ms")]
    pub(crate) usage_flush_interval_ms: u64,
    /// Tokio worker-thread count (`advanced.worker_threads`, migrated from `BUSBAR_WORKER_THREADS`).
    /// A BOOT-TIME knob read once before the runtime is built — not runtime-mutable via the overlay.
    /// Absent (`None`) ⇒ one worker per available core (`available_parallelism`, capped at
    /// `MAX_WORKER_THREADS`). The env var still works as a deprecated fallback for one release.
    #[serde(default)]
    pub(crate) worker_threads: Option<usize>,
    /// Pin the shared upstream client to HTTP/1.1 (`advanced.upstream_http1_only`, migrated from
    /// `BUSBAR_UPSTREAM_HTTP1_ONLY`). BOOT-TIME (client-build) knob; default `false` (ALPN default:
    /// h2 where the backend accepts it, h1 otherwise). The env var still works as a deprecated
    /// fallback for one release.
    #[serde(default)]
    pub(crate) upstream_http1_only: bool,
    /// Force HTTP/2 prior-knowledge to cleartext upstreams (`advanced.upstream_h2_prior_knowledge`,
    /// migrated from `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE`). BOOT-TIME (client-build) knob; default
    /// `false` — prior-knowledge h2c measurably HURT throughput in perf testing. The env var still
    /// works as a deprecated fallback for one release.
    #[serde(default)]
    pub(crate) upstream_h2_prior_knowledge: bool,
    /// The `advanced.response_headers:` block — opt-in toggles for every busbar-INJECTED response
    /// header. Every busbar-injected header is a fingerprint an unauthenticated client
    /// can observe on every response, so each one is OFF by default and an operator opts IN
    /// per-header. See `docs/observability.md#response-headers` for the full catalogue. BOOT-TIME
    /// (restart-to-apply), same freezing mechanism as the rest of this struct's non-`Patch`able
    /// fields: `server_timing` is baked into router middleware state at process start
    /// (`main.rs::apply_common_layers`) and `route_policy` seeds a process-wide `OnceLock` read by
    /// `proxy::wire::maybe_attach_route_policy` — neither is rebuilt by a config apply.
    #[serde(default)]
    pub(crate) response_headers: ResponseHeadersCfg,
}

impl Default for AdvancedCfg {
    fn default() -> Self {
        Self {
            rate_sweep_interval: default_rate_sweep_interval(),
            usage_flush_interval_ms: default_usage_flush_interval_ms(),
            worker_threads: None,
            upstream_http1_only: false,
            upstream_h2_prior_knowledge: false,
            response_headers: ResponseHeadersCfg::default(),
        }
    }
}

/// The `advanced.response_headers:` block: opt-in toggles for every busbar-INJECTED
/// response header, unified in ONE place instead of each header having its own bespoke gate (or, as
/// `x-busbar-route-policy`/`-target` had before this, NO gate at all). Every field defaults `false`
/// (invisible out of the box) — see each field's doc comment for the header it controls and why it
/// defaults off.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResponseHeadersCfg {
    /// Emit the `Server-Timing: busbar;dur=<ms>` response header (default `false`). MIGRATED from
    /// the 1.5.x `observability.emit_server_timing`; the old key is now
    /// an `unknown field` boot error (`deny_unknown_fields` on `ObservabilityCfg`) — run
    /// `busbar --migrate-config` to move it. The header is a useful latency probe, but it is also an
    /// in-band busbar fingerprint on an otherwise anti-fingerprinting gateway — and the one
    /// fingerprint observable by an UNAUTHENTICATED client on every response — so it defaults OFF to
    /// preserve backend-facing indistinguishability. Operators who want the latency probe (and accept
    /// the product tell) opt IN by setting `true`.
    #[serde(default = "default_response_headers_server_timing")]
    pub(crate) server_timing: bool,
    /// Emit the `x-busbar-route-policy` / `x-busbar-route-target` TRANSPARENCY headers on a response
    /// whose lane was chosen by a non-default routing policy (default `false`). Previously emitted
    /// UNCONDITIONALLY whenever a non-default policy fired (no config gate at all) — the same
    /// fingerprinting concern as `server_timing` above: the header names apply, so it defaults OFF and
    /// an operator opts IN by setting `true`.
    #[serde(default = "default_response_headers_route_policy")]
    pub(crate) route_policy: bool,
}

impl Default for ResponseHeadersCfg {
    fn default() -> Self {
        Self {
            server_timing: default_response_headers_server_timing(),
            route_policy: default_response_headers_route_policy(),
        }
    }
}

/// `Server-Timing: busbar` header is SUPPRESSED by default (indistinguishability); operators opt IN.
pub(crate) const DEFAULT_RESPONSE_HEADERS_SERVER_TIMING: bool = false;
fn default_response_headers_server_timing() -> bool {
    DEFAULT_RESPONSE_HEADERS_SERVER_TIMING
}

/// `x-busbar-route-policy` / `x-busbar-route-target` are SUPPRESSED by default (same fingerprinting
/// concern as `server_timing`); operators opt IN.
pub(crate) const DEFAULT_RESPONSE_HEADERS_ROUTE_POLICY: bool = false;
fn default_response_headers_route_policy() -> bool {
    DEFAULT_RESPONSE_HEADERS_ROUTE_POLICY
}

/// The top-level `config:` block — config-MANAGEMENT policy (1.5.3). This is DISTINCT from the
/// data-plane `store:` section (where request/usage data lives): `config:` governs whether the admin
/// API may mutate config and WHERE those mutations persist. Absent ⇒ durable-by-default: `locked:
/// false` and an overlay file `busbar-overlay.json` next to the resolved config.yaml, so out of the
/// box admin mutations survive a restart (the 1.5.3 fix for silent RAM-only mutation).
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConfigMgmtCfg {
    /// `false` (default) ⇒ MUTABLE: the admin API may change config, and every change persists to the
    /// `overlay` backend. `true` ⇒ IMMUTABLE (GitOps posture): admin-API config mutations are refused
    /// at runtime; `overlay` is irrelevant and ignored. Edit config.yaml + POST /config/reload to
    /// change a locked deployment.
    #[serde(default)]
    pub(crate) locked: bool,
    /// WHERE a mutable config's changes persist — a PLUGGABLE backend. Absent ⇒ the default file
    /// backend (`busbar-overlay.json` next to the resolved config.yaml). `overlay: false` disables it
    /// explicitly (only valid together with `locked: true`, else boot refuses — see the boot
    /// invariant). `overlay: { file: <path> }` selects the file backend at a chosen path.
    #[serde(default)]
    pub(crate) overlay: Option<OverlayCfg>,
}

/// The `config.overlay` value — either an explicit DISABLE (`overlay: false`) or a named BACKEND
/// (`overlay: { file: <path> }`). Untagged so both YAML forms parse. The map form names the backend
/// by KEY (`file:` today), mirroring the top-level `store: { module, settings }` shape so a second
/// backend (e.g. `db:`) is ADDITIVE, not a breaking reshape.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub(crate) enum OverlayCfg {
    /// `overlay: false` ⇒ no writable overlay backend. Only `false` is meaningful; `true` is rejected
    /// at boot (it names no backend). Reachable-to-boot only with `locked: true`.
    Disabled(bool),
    /// `overlay: { file: <path> }` ⇒ the builtin file backend.
    Backend(OverlayBackend),
}

/// A named overlay backend. Exactly one backend key may be set. Today only `file:` exists; a future
/// durable-store backend slots in as an additive sibling field (`db:`), validated at boot to be
/// mutually exclusive with `file:`.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct OverlayBackend {
    /// File-backend path. Relative paths resolve against the config.yaml directory. Absent ⇒ treated
    /// as "no backend named" (equivalent to disabled).
    #[serde(default)]
    pub(crate) file: Option<String>,
}

/// The serde default for `per_request_fee:` - 0 (no flat per-request charge; token spend derives
/// from the ledger x rate_card).
fn default_per_request_fee() -> i64 {
    0
}

/// One top-level `rate_card:` entry: the four per-token rates in MICRO-units (1e-6 abstract cost
/// unit) per token, one per pricing tier. A tier omitted in YAML prices at 0 for that tier (e.g. a
/// model with no cache pricing simply omits the cache rates). Values must be finite and >= 0
/// (validated at boot). Floats exist ONLY here at the config boundary: they are converted once at
/// resolve time to integer nano-units per token, and the hot path does pure integer math.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct RateEntryCfg {
    #[serde(default)]
    pub(crate) input_utok: f64,
    #[serde(default)]
    pub(crate) output_utok: f64,
    #[serde(default)]
    pub(crate) cache_read_utok: f64,
    #[serde(default)]
    pub(crate) cache_write_utok: f64,
}

/// One entry in the top-level `export:` NAMED-DEFINITION map (1.5.3). The map KEY is the
/// exporter INSTANCE name; `module:` says which built-in exporter backs it and `settings:` is the
/// opaque per-module bag — the SAME shape as `hooks:` / `identity-providers:` / `store:`.
///
/// The whole point of the rename from the retired TYPE-KEYED `export:` block is that the SAME module
/// may back MULTIPLE named instances: two `request-log-webhook`s shipping to two different URLs is a
/// real deployment (app logs + SIEM) that the type-keyed shape could not express at all.
///
/// The four modules map onto the export-ABI streams: `prometheus` → Metrics (PULL
/// `/metrics`), `request-log-webhook` / `request-log-file` → Logs (PUSH per request), `otlp` →
/// Traces. `otlp` ABSORBS the DELETED `observability:` block's only remaining field (`otlp_url`), so
/// `export:` is now the single telemetry-egress surface.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)] // a typo'd key must fail boot, not silently disable telemetry.
pub(crate) struct ExportDefCfg {
    /// The built-in exporter module backing this instance: `prometheus` | `request-log-webhook` |
    /// `request-log-file` | `otlp` (see [`EXPORT_MODULES`]). An unknown module is a boot error.
    pub(crate) module: String,
    /// `streams:` — WHAT this sink subscribes to, as tokens of the frozen
    /// [`busbar_plugin_loader::ExportStream`] vocabulary. Each stream carries DOCUMENTED
    /// DEFAULT FIELDS. Absent ⇒ the streams the instance's `module:` itself carries (which is what
    /// every pre-projection config means), never "nothing".
    ///
    /// Deserialized as RAW STRINGS, not as the typed enum, so every diagnostic is ours: serde's
    /// "unknown variant" could not say that `audit` was REMOVED and why, nor that a stream exists in
    /// the vocabulary but has no producer in this release. Parsed + validated by
    /// [`crate::export::projection::resolve_projection`].
    #[serde(default)]
    pub(crate) streams: Option<Vec<String>>,
    /// `fields:` — an optional EXHAUSTIVE OVERRIDE of what this sink receives. If present it fully
    /// REPLACES the subscribed streams' default field sets; it is never additive.
    ///
    /// THE ASYMMETRY WITH `hooks:` IS DELIBERATE AND IS A SECURITY PROPERTY. `hooks:` lists COMBINE
    /// ADDITIVELY (see `config::overlay`) because hooks compose BEHAVIOUR. Projections bound
    /// DISCLOSURE, and if `fields:` were additive then a future release that adds a field to a
    /// stream's defaults would SILENTLY WIDEN what every already-configured sink receives. Override
    /// means the operator's list is exhaustive, so a field added next year can never leak into a
    /// sink someone configured today.
    ///
    /// It bounds DISCLOSURE but must not break STRUCTURE: omitting a PINNED field (the join key, the
    /// chain link) is a LOUD config error, never a silent no-op.
    #[serde(default)]
    pub(crate) fields: Option<Vec<String>>,
    /// `durable:` — should core SPOOL this sink's records before the request completes (core owns
    /// the completeness guarantee; the exporter drains, delayed and retried, and never blocks a
    /// request)? The key is part of the frozen surface; the spool that backs it is a later unit, so
    /// `true` is a LOUD "not yet implemented" error rather than a promise nothing keeps.
    #[serde(default)]
    pub(crate) durable: bool,
    /// The module's own settings bag. OPAQUE at this layer exactly like `hooks.<name>.settings` —
    /// typed per module by [`resolve_export`], so a typo inside it still fails boot loudly.
    #[serde(default)]
    // settings-leak-lint: allow — operator CONFIG struct, not a projection: this is the
    // `settings:` the operator WROTE. Every admin read of it serves
    // `service::settings_keys(&…settings)`, or passes the tree through
    // `service::redact_settings_bags` first.
    pub(crate) settings: serde_json::Map<String, serde_json::Value>,
}

/// The top-level `export:` NAMED-DEFINITION map: instance name → [`ExportDefCfg`]. Insertion-ordered
/// so the resolved sink order (and therefore delivery order) is deterministic.
pub(crate) type ExportDefs = indexmap::IndexMap<String, ExportDefCfg>;

/// `export.<name>.module: prometheus` — the PULL metrics exporter (Metrics stream).
pub(crate) const EXPORT_MODULE_PROMETHEUS: &str = "prometheus";
/// `export.<name>.module: request-log-webhook` — the PUSH per-request webhook (Logs stream).
pub(crate) const EXPORT_MODULE_REQUEST_LOG_WEBHOOK: &str = "request-log-webhook";
/// `export.<name>.module: request-log-file` — the PUSH per-request JSONL append (Logs stream).
pub(crate) const EXPORT_MODULE_REQUEST_LOG_FILE: &str = "request-log-file";
/// `export.<name>.module: otlp` — the OTLP/HTTP trace exporter (Traces stream). Absorbs the DELETED
/// `observability.otlp_url`.
pub(crate) const EXPORT_MODULE_OTLP: &str = "otlp";

/// Every built-in `export:` module, for the boot-time unknown-module diagnostic.
pub(crate) const EXPORT_MODULES: &[&str] = &[
    EXPORT_MODULE_PROMETHEUS,
    EXPORT_MODULE_REQUEST_LOG_WEBHOOK,
    EXPORT_MODULE_REQUEST_LOG_FILE,
    EXPORT_MODULE_OTLP,
];

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
pub(crate) struct ExportCfg {
    /// The `prometheus` instance's settings, if one is configured. `None` ⇒ no recorder installed,
    /// `/metrics` not mounted, every emit site a true no-op (the zero-config default).
    pub(crate) prometheus: Option<PrometheusSettings>,
    /// Every configured `request-log-webhook` instance, in config order. Empty ⇒ no webhook sink.
    pub(crate) request_log_webhooks: Vec<WebhookSettings>,
    /// Every configured `request-log-file` instance, in config order. Empty ⇒ no file sink.
    pub(crate) request_log_files: Vec<FileSettings>,
    /// The `otlp` instance's settings, if one is configured. `None` ⇒ no tracer/span export.
    pub(crate) otlp: Option<OtlpSettings>,
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

/// `settings:` of an `export.<name>.module: prometheus` instance — relocated from the retired
/// `observability.metrics` block.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrometheusSettings {
    /// Retention window (SECONDS) for the rolling quantile summary — REQUIRED, exactly as the retired
    /// `observability.metrics.buffer_seconds` was (turning metrics on is a deliberate choice + a
    /// memory cost the operator names).
    pub(crate) buffer_seconds: u64,
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
pub(crate) struct OtlpSettings {
    /// OTLP/HTTP traces endpoint URL (e.g. `http://localhost:4318/v1/traces`) — REQUIRED. When an
    /// `otlp` export instance is present busbar installs an OpenTelemetry tracer + exports spans.
    pub(crate) url: String,
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
pub(crate) fn resolve_export(defs: &ExportDefs, errors: &mut Vec<String>) -> ExportCfg {
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
// Operator-tunable operational limits ("NEVER CODED CAPS"). Every field defaults — via a
// `default = "fn"` whose body is the historical hardcoded const — to today's behavior, so an absent
// key (the common case) is byte-for-byte unchanged. Each section struct is itself `#[serde(default)]`
// at its `DeployCfg` field, so omitting the whole block is valid. The resolved values are projected
// onto `LimitsResolved` (on `RootCfg`) and threaded/installed at startup (see `crate::limits`).
// ───────────────────────────────────────────────────────────────────────────────────────────────

/// Default upstream per-request timeout (seconds). Single source of truth for both serde's
/// `default = "..."` and the resolved-default fallback. Mirrors the historical `main.rs` const.
const DEFAULT_UPSTREAM_REQUEST_TIMEOUT_SECS: u64 = 300;
/// Default maximum accepted request body size (bytes). Couples to the egress translate-body cap
/// (`crate::limits::translate_body_max_bytes`): a body the gateway accepts inbound must also be
/// buffer-translatable on egress, so ONE knob (`limits.request_body_max_bytes`) drives both.
pub(crate) const DEFAULT_REQUEST_BODY_MAX_BYTES: usize = 32 * 1024 * 1024;
/// Hard floor on `request_body_max_bytes` — a too-small cap would reject legitimate multi-turn /
/// multimodal requests with no recourse. 64 KiB comfortably holds a minimal request.
pub(crate) const REQUEST_BODY_MAX_BYTES_FLOOR: usize = 64 * 1024;
/// Hard ceiling on `request_body_max_bytes` — the body is buffered per request, so an absurd value
/// is a memory-exhaustion foot-gun. 1 GiB is far above any legitimate completion payload.
pub(crate) const REQUEST_BODY_MAX_BYTES_CEIL: usize = 1024 * 1024 * 1024;
/// Default max idle keep-alive connections the upstream client pools per host. Mirrors `main.rs`.
///
/// Sized for the sustained-throughput regime, not the idle-footprint regime: under an LLM-latency
/// workload the in-flight connection count is `RPS × upstream_latency` (Little's law) — e.g. 40k RPS
/// against a 20 ms upstream needs ~800 sockets held open concurrently. A small idle cap (the former
/// 64) forces reqwest to CLOSE every connection beyond the cap the instant a request completes, so
/// the next request re-pays a full TCP + TLS handshake on the hot path — connection CHURN that both
/// caps sustained RPS and inflates tail latency. 1024 lets the pool retain the working set for a
/// 4-core box saturating a 20 ms upstream without reconnecting, at a bounded idle-socket cost
/// (idle keep-alives are cheap; the OS reclaims them and `pool_idle_timeout`/`tcp_keepalive` bound
/// their lifetime). Operators with many distinct upstream hosts can lower it; high-RPS single-host
/// deployments are the ones this default protects.
const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = 1024;
/// Default idle keep-alive lifetime (seconds) for pooled upstream connections.
///
/// EXPLICIT 300s, replacing reqwest's implicit 90s default: under a bursty LLM workload the warm
/// working set (`pool_max_idle_per_host` sockets, each carrying an amortized TCP+TLS handshake and
/// — on h2 — an established multiplexed session) should SURVIVE inter-burst gaps of a few minutes
/// instead of being reaped at 90s and re-paid as cold handshakes on the hot path when the next
/// burst lands. Safe to hold that long because `tcp_keepalive(60s)` actively validates every idle
/// socket — a middlebox silently dropping a long-idle connection is detected by the keepalive
/// probe, not discovered as a spurious request failure — so the longer lifetime adds warm-socket
/// retention without adding stale-socket risk. Bounded: the OS reclaims idle sockets under
/// pressure, and `pool_max_idle_per_host` caps the count.
pub(crate) const DEFAULT_POOL_IDLE_TIMEOUT_SECS: u64 = 300;
/// Default inbound concurrency limit. `0` = unlimited (NO layer added).
///
/// Non-zero by default because this is the ONLY global bound on buffered request memory: every
/// request buffers its body (up to `request_body_max_bytes`, default 32 MiB) BEFORE any handler
/// logic can reject it, so peak memory is `(concurrent requests) x (body cap)` — with no admission
/// bound, a hostile connection burst is an OOM, not a slowdown. The limit layer is applied
/// OUTERMOST (see `apply_inbound_concurrency_limit`), so a queued request has NOT yet buffered its
/// body — the bound genuinely caps peak at `limit x body cap`. 8192 is ~4x the highest useful
/// in-flight count measured on a 4-core box (sustained throughput peaks near 1-2k concurrent) —
/// far above any legitimate working set, low enough that the worst case stays bounded. Operators
/// who want the old unlimited posture set `limits.max_inbound_concurrent: 0` explicitly.
pub(crate) const DEFAULT_MAX_INBOUND_CONCURRENT: usize = 8192;
/// Default hard-down sticky cooldown (seconds). Mirrors `store.rs`.
pub(crate) const DEFAULT_HARD_DOWN_COOLDOWN_SECS: u64 = 1800;
/// Default ceiling on a honored upstream `Retry-After` (seconds). Mirrors `store.rs` (24h).
pub(crate) const DEFAULT_MAX_HONORED_RETRY_AFTER_SECS: u64 = 86_400;
/// Default cap on a buffered upstream ERROR / verbatim-relay body (bytes). Mirrors `proxy engine`.
pub(crate) const DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES: usize = 256 * 1024;
/// Default cap on a single `plugins.fetch:` download (bytes). Mirrors the same defense the
/// token-endpoint reads already apply (`egress_auth::read_capped_token_response`,
/// `proxy::wire::read_capped`): a mistyped or compromised `plugins.fetch` URL serving a multi-GB
/// body must NOT be buffered whole into memory via an unbounded `resp.bytes()` read — that OOMs
/// busbar on boot (`fatal_on_miss`) or on `POST /plugins/reload`. 256 MiB comfortably holds any
/// legitimate signed plugin tarball while bounding the worst case; the download is aborted with a
/// clear "exceeded the cap" error the instant more bytes arrive, never buffered past it.
pub(crate) const DEFAULT_PLUGIN_FETCH_MAX_BYTES: usize = 256 * 1024 * 1024;
/// Default TLS handshake wall-clock bound (seconds). Mirrors `tls.rs`.
pub(crate) const DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 10;
/// Default inbound request-BODY read bound (seconds): the max time allowed BETWEEN inbound body
/// frames before the connection is dropped. Bounds a slow-loris that dribbles the request body one
/// byte at a time (the header-read timeout only covers the header phase). Mirrors `tls.rs`. 30s is
/// far longer than any real client needs to send its next body chunk, so it cannot false-positive on
/// a healthy upload.
pub(crate) const DEFAULT_REQUEST_BODY_READ_TIMEOUT_SECS: u64 = 30;
/// Default global fallback for the translation-injected `max_tokens` (mirrors `proto::DEFAULT_MAX_TOKENS`).
pub(crate) const DEFAULT_DEFAULT_MAX_TOKENS: u32 = 4096;
/// Default max concurrent webhook deliveries. Mirrors `observability.rs`.
pub(crate) const DEFAULT_MAX_INFLIGHT_WEBHOOK_DELIVERIES: usize = 64;
/// Default per-webhook delivery timeout (seconds). Mirrors `observability.rs`.
pub(crate) const DEFAULT_WEBHOOK_DELIVERY_TIMEOUT_SECS: u64 = 2;
/// Default max per-key gauge series emitted per scrape. Mirrors `metrics.rs`.
pub(crate) const DEFAULT_KEY_GAUGE_LIMIT: usize = 2000;
/// Default rate-sweep amortization interval. Mirrors `governance.rs`.
pub(crate) const DEFAULT_RATE_SWEEP_INTERVAL: u32 = 256;
/// Default write-behind flush cadence (ms) for the in-memory governance usage/budget counters.
/// Mirrors `governance.rs`.
pub(crate) const DEFAULT_USAGE_FLUSH_INTERVAL_MS: u64 = 100;
/// Default active-probe interval (seconds) — the process-wide fallback for the per-lane override.
pub(crate) const DEFAULT_PROBE_INTERVAL_SECS: u64 = 30;
/// Default active-probe timeout (seconds) — the process-wide fallback for the per-lane override.
pub(crate) const DEFAULT_PROBE_TIMEOUT_SECS: u64 = 5;

fn default_upstream_request_timeout_secs() -> u64 {
    DEFAULT_UPSTREAM_REQUEST_TIMEOUT_SECS
}
fn default_request_body_max_bytes() -> usize {
    DEFAULT_REQUEST_BODY_MAX_BYTES
}
fn default_pool_max_idle_per_host() -> usize {
    DEFAULT_POOL_MAX_IDLE_PER_HOST
}
fn default_pool_idle_timeout_secs() -> u64 {
    DEFAULT_POOL_IDLE_TIMEOUT_SECS
}
fn default_max_inbound_concurrent() -> usize {
    DEFAULT_MAX_INBOUND_CONCURRENT
}
/// `0` = unlimited keys per group (today's behavior — an absent knob changes nothing).
fn default_max_keys_per_principal() -> usize {
    0
}
/// `0` = unlimited auto-provisioned groups (today's behavior — an absent knob changes nothing).
fn default_max_auto_provisioned_groups() -> usize {
    0
}
fn default_hook_content_max_bytes() -> usize {
    crate::proxy::DEFAULT_HOOK_CONTENT_MAX_BYTES
}
fn default_hard_down_cooldown_secs() -> u64 {
    DEFAULT_HARD_DOWN_COOLDOWN_SECS
}
fn default_max_honored_retry_after_secs() -> u64 {
    DEFAULT_MAX_HONORED_RETRY_AFTER_SECS
}
fn default_upstream_error_body_max_bytes() -> usize {
    DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES
}
fn default_tls_handshake_timeout_secs() -> u64 {
    DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS
}
fn default_request_body_read_timeout_secs() -> u64 {
    DEFAULT_REQUEST_BODY_READ_TIMEOUT_SECS
}
fn default_default_max_tokens() -> u32 {
    DEFAULT_DEFAULT_MAX_TOKENS
}
fn default_max_inflight_webhook_deliveries() -> usize {
    DEFAULT_MAX_INFLIGHT_WEBHOOK_DELIVERIES
}
fn default_webhook_delivery_timeout_secs() -> u64 {
    DEFAULT_WEBHOOK_DELIVERY_TIMEOUT_SECS
}
pub(crate) fn default_key_gauge_limit() -> usize {
    DEFAULT_KEY_GAUGE_LIMIT
}
fn default_plugins_dir() -> String {
    "plugins".to_string()
}
fn default_rate_sweep_interval() -> u32 {
    DEFAULT_RATE_SWEEP_INTERVAL
}
fn default_usage_flush_interval_ms() -> u64 {
    DEFAULT_USAGE_FLUSH_INTERVAL_MS
}
fn default_probe_interval_secs() -> u64 {
    DEFAULT_PROBE_INTERVAL_SECS
}
fn default_probe_timeout_secs() -> u64 {
    DEFAULT_PROBE_TIMEOUT_SECS
}

/// The `limits:` block — global operational caps. Each field defaults to its historical hardcoded
/// value, so an absent field (or an absent block) is today's behavior.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)] // a typo'd limits key must fail boot, not be silently ignored.
pub(crate) struct LimitsCfg {
    #[serde(default = "default_upstream_request_timeout_secs")]
    pub(crate) upstream_request_timeout_secs: u64,
    /// Max accepted inbound body (bytes). COUPLED: also drives the egress translate-body cap
    /// (`crate::limits::translate_body_max_bytes`) — one knob feeds both so an accepted request is
    /// always buffer-translatable on egress.
    #[serde(default = "default_request_body_max_bytes")]
    pub(crate) request_body_max_bytes: usize,
    #[serde(default = "default_pool_max_idle_per_host")]
    pub(crate) pool_max_idle_per_host: usize,
    /// Idle keep-alive lifetime (seconds) for pooled upstream connections — see
    /// `DEFAULT_POOL_IDLE_TIMEOUT_SECS` for the 300s (vs reqwest's implicit 90s) rationale.
    #[serde(default = "default_pool_idle_timeout_secs")]
    pub(crate) pool_idle_timeout_secs: u64,
    /// Inbound concurrency cap. `0` (default) = unlimited: NO layer is added (a true no-op). When
    /// `>0`, a `tower` global concurrency limit wraps the router as the outermost layer.
    #[serde(default = "default_max_inbound_concurrent")]
    pub(crate) max_inbound_concurrent: usize,
    /// Cap on how many keys may be BOUND TO ONE GROUP — the anti-sprawl mitigation for self-service
    /// minting. Because a `user:<sub>` leaf group IS the principal, this is
    /// effectively "max keys per principal": a self-issued mint into a group already holding this
    /// many keys is a `409`. `0` (default) = UNLIMITED (today's behavior — an absent knob changes
    /// nothing). Enforced at `POST /keys` only; keys already present are never retroactively revoked.
    #[serde(default = "default_max_keys_per_principal")]
    pub(crate) max_keys_per_principal: usize,
    /// Cap on how many groups `POST /keys` may AUTO-PROVISION (`parent:` self-service). The
    /// key-count cap bounds keys per group but says nothing about the number of GROUPS, so a
    /// `mint`-scope credential could grow the limit tree without bound — every new `user:<sub>`
    /// leaf is a new bucket in the enforcement chain, the version log and the persisted overlay
    /// Counted over the WHOLE runtime (overlay) group set, since that is what
    /// auto-provisioning grows. `0` (default) = UNLIMITED (an absent knob changes nothing).
    /// Explicitly configured groups are unaffected: the ceiling gates auto-provisioning only.
    #[serde(default = "default_max_auto_provisioned_groups")]
    pub(crate) max_auto_provisioned_groups: usize,
    /// Ceiling, in bytes, on the request CONTENT a hook holding a `prompt: ro|rw` grant is shown in
    /// one projection (default 65536). Over-cap content is OMITTED WHOLE — never truncated
    /// mid-value, because a guardrail that screens half a payload and passes it is worse than one
    /// that refuses — and the hook is sent an EMPTY content projection, which the wire distinguishes
    /// from an ungranted one; the always-present size bucket still reports the real total, so the
    /// omission is visible in the payload rather than silent. `busbar_hook_content_truncated_total`
    /// counts it. This bounds a widening: a content-granted hook now also sees tool-call arguments
    /// and tool-result content, which on an agent request is bounded by neither a context window nor
    /// a token count. `0` = unlimited.
    #[serde(default = "default_hook_content_max_bytes")]
    pub(crate) hook_content_max_bytes: usize,
    #[serde(default = "default_hard_down_cooldown_secs")]
    pub(crate) hard_down_cooldown_secs: u64,
    #[serde(default = "default_upstream_error_body_max_bytes")]
    pub(crate) upstream_error_body_max_bytes: usize,
    #[serde(default = "default_tls_handshake_timeout_secs")]
    pub(crate) tls_handshake_timeout_secs: u64,
    /// Max time (seconds) allowed BETWEEN inbound request-body frames before the connection is
    /// dropped - the slow-loris body defense the header-read timeout does not cover. See
    /// `DEFAULT_REQUEST_BODY_READ_TIMEOUT_SECS`.
    #[serde(default = "default_request_body_read_timeout_secs")]
    pub(crate) request_body_read_timeout_secs: u64,
    #[serde(default = "default_max_honored_retry_after_secs")]
    pub(crate) max_honored_retry_after_secs: u64,
    #[serde(default = "default_default_max_tokens")]
    pub(crate) default_max_tokens: u32,
    /// Effort-word → thinking-token-budget table for the cross-protocol reasoning carry: what
    /// OpenAI's `reasoning_effort` words mean in tokens when projected onto Anthropic
    /// `thinking.budget_tokens` / Gemini `thinkingBudget` (and, inverted, the bucket thresholds
    /// when a numeric budget is projected onto an effort word). "Medium" is a cost decision, so
    /// operators can override it; defaults 1024/4096/8192/16384.
    #[serde(default)]
    pub(crate) reasoning_effort_budgets: ReasoningEffortBudgets,
}

/// The `minimal/low/medium/high` → token-budget table (see `LimitsCfg::reasoning_effort_budgets`).
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct ReasoningEffortBudgets {
    #[serde(default = "default_reasoning_minimal")]
    pub(crate) minimal: u32,
    #[serde(default = "default_reasoning_low")]
    pub(crate) low: u32,
    #[serde(default = "default_reasoning_medium")]
    pub(crate) medium: u32,
    #[serde(default = "default_reasoning_high")]
    pub(crate) high: u32,
}

impl Default for ReasoningEffortBudgets {
    fn default() -> Self {
        Self {
            minimal: default_reasoning_minimal(),
            low: default_reasoning_low(),
            medium: default_reasoning_medium(),
            high: default_reasoning_high(),
        }
    }
}

fn default_reasoning_minimal() -> u32 {
    1024
}
fn default_reasoning_low() -> u32 {
    4096
}
fn default_reasoning_medium() -> u32 {
    8192
}
fn default_reasoning_high() -> u32 {
    16384
}

impl Default for LimitsCfg {
    fn default() -> Self {
        // Route every field through the serde-default fn so the omitted-block path (this `Default`)
        // and the omitted-field path share one source of truth and cannot drift.
        Self {
            upstream_request_timeout_secs: default_upstream_request_timeout_secs(),
            request_body_max_bytes: default_request_body_max_bytes(),
            pool_max_idle_per_host: default_pool_max_idle_per_host(),
            pool_idle_timeout_secs: default_pool_idle_timeout_secs(),
            max_inbound_concurrent: default_max_inbound_concurrent(),
            max_keys_per_principal: default_max_keys_per_principal(),
            max_auto_provisioned_groups: default_max_auto_provisioned_groups(),
            hook_content_max_bytes: default_hook_content_max_bytes(),
            hard_down_cooldown_secs: default_hard_down_cooldown_secs(),
            upstream_error_body_max_bytes: default_upstream_error_body_max_bytes(),
            tls_handshake_timeout_secs: default_tls_handshake_timeout_secs(),
            request_body_read_timeout_secs: default_request_body_read_timeout_secs(),
            max_honored_retry_after_secs: default_max_honored_retry_after_secs(),
            default_max_tokens: default_default_max_tokens(),
            reasoning_effort_budgets: ReasoningEffortBudgets::default(),
        }
    }
}

// 1.5.3: the `metrics:` block (`MetricsCfg`) was RETIRED into the `export.prometheus` built-in
// exporter — `buffer_seconds`/`key_gauge_limit` now live under `export.prometheus.settings`
// ([`PrometheusSettings`]). An un-migrated config carrying `metrics:` LOUD-FAILS at boot via the
// retired-key markers in `config::migrate::detect_legacy_markers`; `--migrate-config` rewrites it.

/// The `health:` block — process-wide active-probe fallbacks (per-lane `health.interval_secs` /
/// `timeout_secs` still override these).
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)] // a typo'd health key must fail boot, not be silently ignored.
pub(crate) struct HealthDefaultsCfg {
    #[serde(default = "default_probe_interval_secs")]
    pub(crate) default_probe_interval_secs: u64,
    #[serde(default = "default_probe_timeout_secs")]
    pub(crate) default_probe_timeout_secs: u64,
}

impl Default for HealthDefaultsCfg {
    fn default() -> Self {
        Self {
            default_probe_interval_secs: default_probe_interval_secs(),
            default_probe_timeout_secs: default_probe_timeout_secs(),
        }
    }
}

/// The `routing:` block — the global default policy timeout (per-policy `policy.timeout_ms` still
/// overrides).
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)] // a typo'd routing key must fail boot, not be silently ignored.
pub(crate) struct RoutingCfg {
    #[serde(default = "default_policy_timeout_ms")]
    pub(crate) default_policy_timeout_ms: u64,
}

impl Default for RoutingCfg {
    fn default() -> Self {
        Self {
            default_policy_timeout_ms: default_policy_timeout_ms(),
        }
    }
}

/// Fully-resolved operational limits, projected onto `RootCfg` by `resolve`. Grouped here so the
/// startup wiring (`crate::limits::install` + the explicit main.rs/store threading) reads a flat
/// struct rather than re-walking optional config sections.
#[derive(Debug, Clone)]
pub(crate) struct LimitsResolved {
    pub(crate) upstream_request_timeout_secs: u64,
    pub(crate) request_body_max_bytes: usize,
    pub(crate) pool_max_idle_per_host: usize,
    pub(crate) pool_idle_timeout_secs: u64,
    pub(crate) max_inbound_concurrent: usize,
    /// Max keys bound to one group (0 = unlimited) — the self-service mint anti-sprawl cap.
    pub(crate) max_keys_per_principal: usize,
    /// Max groups a mint may AUTO-PROVISION (0 = unlimited) — the sibling anti-sprawl cap on the
    /// SHAPE of the limit tree, not just its contents.
    pub(crate) max_auto_provisioned_groups: usize,
    /// Ceiling on the request CONTENT a `prompt: ro|rw` hook is shown in one projection (0 =
    /// unlimited). Over-cap content is omitted WHOLE, never truncated mid-value.
    pub(crate) hook_content_max_bytes: usize,
    pub(crate) hard_down_cooldown_secs: u64,
    pub(crate) upstream_error_body_max_bytes: usize,
    pub(crate) tls_handshake_timeout_secs: u64,
    pub(crate) request_body_read_timeout_secs: u64,
    pub(crate) max_honored_retry_after_secs: u64,
    pub(crate) default_max_tokens: u32,
    pub(crate) reasoning_effort_budgets: ReasoningEffortBudgets,
    /// The SHARED webhook-delivery admission bound (max across every configured
    /// `request-log-webhook` export instance — see `LimitsResolved::from_sections`). The per-delivery
    /// TIMEOUT is deliberately NOT here: it is per instance on [`WebhookSettings`].
    pub(crate) max_inflight_webhook_deliveries: usize,
    pub(crate) key_gauge_limit: usize,
    pub(crate) rate_sweep_interval: u32,
    pub(crate) usage_flush_interval_ms: u64,
    /// Pin the shared upstream client to HTTP/1.1 (`advanced.upstream_http1_only`). BOOT-TIME knob
    /// read once at client build. Carried here (like `rate_sweep_interval`) so the client-build wiring
    /// reads a flat struct; the `BUSBAR_UPSTREAM_HTTP1_ONLY` env var overrides it for one release.
    pub(crate) upstream_http1_only: bool,
    /// Force HTTP/2 prior-knowledge to cleartext upstreams (`advanced.upstream_h2_prior_knowledge`).
    /// BOOT-TIME knob; default off. The `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` env var overrides it for
    /// one release.
    pub(crate) upstream_h2_prior_knowledge: bool,
    pub(crate) default_probe_interval_secs: u64,
    pub(crate) default_probe_timeout_secs: u64,
    pub(crate) default_policy_timeout_ms: u64,
}

impl Default for LimitsResolved {
    fn default() -> Self {
        Self::from_sections(
            &LimitsCfg::default(),
            &AdvancedCfg::default(),
            &ExportCfg::default(),
            &HealthDefaultsCfg::default(),
            &RoutingCfg::default(),
        )
    }
}

impl LimitsResolved {
    fn from_sections(
        limits: &LimitsCfg,
        advanced: &AdvancedCfg,
        export: &ExportCfg,
        health: &HealthDefaultsCfg,
        routing: &RoutingCfg,
    ) -> Self {
        // 1.5.3: the webhook + gauge limits moved from the retired `observability.*`/`metrics.*` keys
        // onto the built-in EXPORTER settings. Source them from `export.*` (historical defaults when
        // the exporter is absent) so the deep `crate::limits` readers (metrics gauge cap, webhook
        // admission bound) are unchanged while the CONFIG SURFACE they read from is the new one.
        //
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
            upstream_request_timeout_secs: limits.upstream_request_timeout_secs,
            request_body_max_bytes: limits.request_body_max_bytes,
            pool_max_idle_per_host: limits.pool_max_idle_per_host,
            pool_idle_timeout_secs: limits.pool_idle_timeout_secs,
            max_inbound_concurrent: limits.max_inbound_concurrent,
            max_keys_per_principal: limits.max_keys_per_principal,
            max_auto_provisioned_groups: limits.max_auto_provisioned_groups,
            hook_content_max_bytes: limits.hook_content_max_bytes,
            hard_down_cooldown_secs: limits.hard_down_cooldown_secs,
            upstream_error_body_max_bytes: limits.upstream_error_body_max_bytes,
            tls_handshake_timeout_secs: limits.tls_handshake_timeout_secs,
            request_body_read_timeout_secs: limits.request_body_read_timeout_secs,
            max_honored_retry_after_secs: limits.max_honored_retry_after_secs,
            default_max_tokens: limits.default_max_tokens,
            reasoning_effort_budgets: limits.reasoning_effort_budgets,
            max_inflight_webhook_deliveries,
            key_gauge_limit,
            rate_sweep_interval: advanced.rate_sweep_interval,
            usage_flush_interval_ms: advanced.usage_flush_interval_ms,
            upstream_http1_only: advanced.upstream_http1_only,
            upstream_h2_prior_knowledge: advanced.upstream_h2_prior_knowledge,
            default_probe_interval_secs: health.default_probe_interval_secs,
            default_probe_timeout_secs: health.default_probe_timeout_secs,
            default_policy_timeout_ms: routing.default_policy_timeout_ms,
        }
    }
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
        // `phase:` is the 1.5.3 stage set; the legacy single `at:` is unused by a named definition.
        at: None,
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

pub(crate) fn resolve(
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
    // THE A2A PLANE'S SECTION-LEVEL ATTACH, judged by the same rule its per-agent lists are. The
    // per-agent lists are checked at parse (`a2a::config::validate_agent`); the section list has no
    // per-entry parse to hang off, so it is checked here, where every other cross-reference is.
    // `` `agents.hooks` `` is this plane's own WORDING for the site; the rule and the sentence are
    // `plane::config`'s, shared with the `tools:` plane below.
    if let Err(e) = crate::plane::config::validate_section_hooks(
        "`agents.hooks`",
        &deploy.agents.all_agent_hooks,
        &crate::plane::config::config_sections(),
    ) {
        errors.push(e);
    }
    // A hook an `agents:` entry names must EXIST in the one top-level `hooks:` map. A dangling
    // reference is an operator believing a control is attached that is not, so it is an error and
    // not a warning, exactly as it is for `auth.chain`.
    for (agent, def) in &deploy.agents.agents {
        for hook in deploy.agents.all_agent_hooks.iter().chain(def.hooks.iter()) {
            if !deploy.hooks.contains_key(hook) {
                errors.push(format!(
                    "agents.{agent}: `hooks:` names `{hook}`, which is not defined in the                      top-level `hooks:` map. Define it there, or remove the reference."
                ));
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
    for (pool, def) in &deploy.tool_pools {
        check_failover_pool(
            &mut errors,
            "tool_pools",
            pool,
            def,
            |m| deploy.tools.servers.contains_key(m),
            |m| deploy.agents.agents.contains_key(m),
            "tools",
            "agents",
        );
    }
    for (pool, def) in &deploy.agent_pools {
        check_failover_pool(
            &mut errors,
            "agent_pools",
            pool,
            def,
            |m| deploy.agents.agents.contains_key(m),
            |m| deploy.tools.servers.contains_key(m),
            "agents",
            "tools",
        );
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
    if let Err(e) = crate::plane::config::validate_section_hooks(
        "`tools.hooks`",
        &deploy.tools.all_server_hooks,
        &crate::plane::config::config_sections(),
    ) {
        errors.push(e);
    }
    for (server, def) in &deploy.tools.servers {
        for hook in deploy.tools.all_server_hooks.iter().chain(def.hooks.iter()) {
            if !deploy.hooks.contains_key(hook) {
                errors.push(format!(
                    "tools.{server}: `hooks:` names `{hook}`, which is not defined in the top-level \
                     `hooks:` map. Define it there, or remove the reference."
                ));
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
    if let Err(e) = crate::mcp::config::validate_published_names(&deploy.tools) {
        errors.push(e);
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
    let mcp = match deploy.mcp.as_ref().map(crate::mcp::McpResource::from_cfg) {
        None => None,
        Some(Ok(resource)) => Some(resource),
        Some(Err(e)) => {
            errors.push(e.to_string());
            None
        }
    };

    // The `oauth_as:` block, validated HERE for the same reason `mcp:` is: an authorization server
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
            mcp,
            oauth_as,
            tool_defs: deploy.tools.clone(),
            tool_pools: deploy.tool_pools.clone(),
            agent_pools: deploy.agent_pools.clone(),
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
            agent_defs: deploy.agents.clone(),
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
