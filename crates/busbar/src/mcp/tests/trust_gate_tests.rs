// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE OWNER FOR "MAY THIS ARTIFACT SERVE?" IN THE MCP SERVER PLANE.
//!
//! The invariant: the dispatch gate in [`super::Catalogue::resolve`] is the SAME comparison the
//! operator's trust surfaces are computed from — `crate::trust::Approval::serves` — and there is no
//! second implementation of it anywhere in this module.
//!
//! Why that is a correctness property and not a tidiness one: two implementations of "may this
//! serve?" agree right up until they do not, the divergence is silent, and it fails OPEN in exactly
//! the case that matters — a de-approval the operator believes they made, honoured by the surface
//! they are looking at and not by the gate the call goes through.
//!
//! Three kinds of proof, because each alone is weak:
//!
//! 1. THE EQUIVALENCE MATRIX. The predicate that used to live inline in `resolve` is restated here
//!    as an ORACLE, and the whole `(pin mechanism × approved-hash)` space is driven through both.
//!    This is what licensed the deletion: the routed gate answers what the deleted one answered, on
//!    every case that can be built.
//! 2. THE SOURCE SCAN. No code line of `catalogue.rs` may re-derive the answer from the raw
//!    registration fields, and `serves` must appear exactly once. A behavioural test only covers the
//!    shapes somebody thought of; this covers the shape a future convenience would add.
//! 3. THE COMPANION. The scan's predicate is checked against a string that WOULD be a violation, so
//!    the scan cannot be passing because its predicate never matches anything.
//!
//! The equivalence is not total, and the ONE case where the two decisions differ is asserted rather
//! than left to be discovered: a keyed mechanism carrying no material. See
//! `a_keyed_mechanism_with_no_material_is_refused_where_the_deleted_decision_admitted`.

use super::{Catalogue, DispatchRefusal};
use crate::mcp::client::catalogue::LiveSightings;
use crate::mcp::config::{McpPinMechanism, McpServerDefCfg, ServerPinCfg, ToolAllowCfg, ToolsCfg};

/// Every mechanism the grammar admits, so the matrix below is exhaustive over the enum rather than
/// over the two arms somebody remembered.
const MECHANISMS: &[McpPinMechanism] = &[
    McpPinMechanism::PinnedPubkey,
    McpPinMechanism::CertSpki,
    McpPinMechanism::Mtls,
    McpPinMechanism::Unpinned,
];

/// Every shape an approved hash can take in config: absent, present, and present-but-empty. The
/// empty one is in the matrix deliberately — it is the case where a "is a hash configured" test and
/// a "does the digest match" test could plausibly disagree, so it is the case the equivalence claim
/// has to survive.
const HASHES: &[Option<&str>] = &[None, Some("sha256:approved"), Some("")];

/// One registered server with one tool, at the given mechanism and approved hash.
///
/// The key material MATCHES the mechanism, so every row of the matrix is a registration
/// `validate_server` would accept. That is what makes the matrix an equivalence proof about the
/// deployments that can exist; the registrations validation refuses are covered separately, below,
/// because there the two decisions deliberately DISAGREE.
fn cfg_of(mechanism: McpPinMechanism, schema_hash: Option<&str>) -> ToolsCfg {
    let key = match mechanism {
        McpPinMechanism::Unpinned => None,
        _ => Some("sha256/K=".to_string()),
    };
    cfg_with(mechanism, key, schema_hash)
}

/// The same fixture with the key material stated EXPLICITLY, so a test can build the registrations
/// `validate_server` refuses and assert what the gate does with one anyway.
fn cfg_with(
    mechanism: McpPinMechanism,
    key: Option<String>,
    schema_hash: Option<&str>,
) -> ToolsCfg {
    let mut tools_allow = indexmap::IndexMap::new();
    tools_allow.insert(
        "read".to_string(),
        ToolAllowCfg {
            schema_hash: schema_hash.map(str::to_string),
            description: None,
            input_schema: None,
            ask_caller: Vec::new(),
            ..ToolAllowCfg::default()
        },
    );
    let mut c = ToolsCfg::default();
    c.servers.insert(
        "fs".to_string(),
        McpServerDefCfg {
            // This registration is reached over the network, so it carries none of the spawn keys.
            command: None,
            args: Vec::new(),
            env: Default::default(),
            cwd: None,
            refresh_ttl: None,
            timeout: None,
            url: "https://fs.internal/mcp".to_string(),
            pin: ServerPinCfg { mechanism, key },
            tools_allow,
            prompts_allow: indexmap::IndexMap::new(),
            resources_allow: indexmap::IndexMap::new(),
            resource_templates_allow: Default::default(),
            transport: None,
            aud: None,
            grants: Default::default(),
            allow_private: false,
            token_exchange: None,
            max_input_required_rounds: None,
            max_caller_ask_rounds: None,
            upstream_credentials: None,
            hooks: Vec::new(),
        },
    );
    c
}

/// A grant that reaches the one tool, so the matrix isolates the TRUST decision from the grant one.
fn full_grant(kind: &str, value: &str) -> bool {
    matches!(
        (kind, value),
        ("mcp_server", "fs") | ("mcp_tool", "fs_read")
    )
}

/// THE ORACLE: the decision `Catalogue::resolve` used to make INLINE, restated verbatim.
///
/// It reads the raw registration fields exactly as the deleted code did — "the mechanism is not
/// `unpinned`" and "an approved hash is present" — and it is the only place in the tree those two
/// facts are still turned into an admission answer. It lives in a test so that it can be COMPARED
/// against the routed gate; it decides nothing in production, which is the whole point of the
/// deletion it licensed.
fn deleted_inline_decision(
    mechanism: McpPinMechanism,
    schema_hash: Option<&str>,
) -> Result<(), DispatchRefusal> {
    if matches!(mechanism, McpPinMechanism::Unpinned) {
        return Err(DispatchRefusal::NotPinned("fs".to_string()));
    }
    if schema_hash.is_none() {
        return Err(DispatchRefusal::NotApproved("fs_read".to_string()));
    }
    Ok(())
}

/// THE EQUIVALENCE MATRIX. Every mechanism × every approved-hash shape, through both decisions.
///
/// Asserted on the FULL result, not on a boolean: a refusal that admits nothing but names the wrong
/// reason is still a regression, because the reason is what the operator's audit row says happened.
#[test]
fn the_routed_gate_answers_exactly_what_the_deleted_inline_decision_answered() {
    let mut cases = 0usize;
    let mut admitted = 0usize;
    let mut refused = 0usize;
    for &mechanism in MECHANISMS {
        for &schema_hash in HASHES {
            cases += 1;
            let cat = Catalogue::build(&cfg_of(mechanism, schema_hash));
            let got = cat
                .resolve(&full_grant, LiveSightings::unsighted(), "fs_read")
                .map(|_| ());
            let oracle = deleted_inline_decision(mechanism, schema_hash);
            assert_eq!(
                got,
                oracle,
                "the routed gate and the deleted inline decision disagree at mechanism `{}` with \
                 schema_hash {schema_hash:?}: routed said {got:?}, inline said {oracle:?}",
                mechanism.token()
            );
            if got.is_ok() {
                admitted += 1;
            } else {
                refused += 1;
            }
        }
    }
    // A FLOOR ON THE MATRIX. Without it the loops could agree by covering nothing, or by producing
    // one answer for every case — an equivalence proof between two constants proves nothing.
    assert_eq!(
        cases,
        MECHANISMS.len() * HASHES.len(),
        "the matrix must drive every mechanism against every approved-hash shape"
    );
    assert!(
        admitted > 0 && refused > 0,
        "the matrix must contain both admissions ({admitted}) and refusals ({refused}); a gate that \
         answers one way everywhere is trivially equal to any other such gate"
    );
}

/// THE ONE PLACE THE TWO DECISIONS DISAGREE, stated rather than discovered later.
///
/// A registration naming a keyed mechanism but carrying no material is not a pin — there is nothing
/// to verify the endpoint against. The deleted inline decision read only the mechanism WORD, so it
/// called such a registration pinned and admitted it on the strength of a configured hash. The
/// routed gate has no artifact to lock, so there is no approval and it refuses.
///
/// The divergence is fail-CLOSED and unreachable in a booted deployment (`validate_server` refuses
/// the registration at boot, asserted here so the claim is checked rather than remembered). It is a
/// strengthening, and it is asserted so that it can never be mistaken for the regression it would
/// look like from the equivalence matrix alone.
#[test]
fn a_keyed_mechanism_with_no_material_is_refused_where_the_deleted_decision_admitted() {
    let c = cfg_with(McpPinMechanism::CertSpki, None, Some("sha256:approved"));
    let def = c.servers.get("fs").expect("fixture server");

    // It cannot BOOT: the registration is refused where an operator finds out, at config load.
    let err = crate::mcp::config::validate_server("fs", def)
        .expect_err("a keyed mechanism with no material must be refused at boot");
    assert!(
        err.contains("pin.key"),
        "the boot refusal must name the missing material, got: {err}"
    );

    // And were it to reach the gate by any other route, the gate refuses it too — where the deleted
    // decision, reading the mechanism word alone, would have admitted it.
    assert_eq!(
        Catalogue::build(&c).resolve(&full_grant, LiveSightings::unsighted(), "fs_read"),
        Err(DispatchRefusal::NotPinned("fs".to_string())),
        "a mechanism word with nothing behind it is not an authenticity root"
    );
    assert_eq!(
        deleted_inline_decision(McpPinMechanism::CertSpki, Some("sha256:approved")),
        Ok(()),
        "the deleted decision admitted it, which is why this divergence is written down"
    );
}

/// The refusal REASONS are equivalent too, arm for arm, and they are distinct from each other.
///
/// `NotPinned` and `NotApproved` are two different audit rows and two different operator actions
/// (supply a trust root / approve a hash). A rewrite that collapsed them into one refusal would pass
/// an admission-only comparison and still lose the operator the answer to "why".
#[test]
fn the_two_refusal_reasons_survive_the_reroute_and_stay_distinct() {
    let unpinned = Catalogue::build(&cfg_of(McpPinMechanism::Unpinned, Some("sha256:approved")));
    assert_eq!(
        unpinned.resolve(&full_grant, LiveSightings::unsighted(), "fs_read"),
        Err(DispatchRefusal::NotPinned("fs".to_string())),
        "no authenticity root ⇒ no locked pin ⇒ pending, whatever the tool's hash says"
    );

    let pending = Catalogue::build(&cfg_of(McpPinMechanism::CertSpki, None));
    assert_eq!(
        pending.resolve(&full_grant, LiveSightings::unsighted(), "fs_read"),
        Err(DispatchRefusal::NotApproved("fs_read".to_string())),
        "a locked pin with no approved digest for this capability is pending on the capability"
    );

    assert_ne!(
        DispatchRefusal::NotPinned("fs".into()).audit_reason(),
        DispatchRefusal::NotApproved("fs_read".into()).audit_reason()
    );
}

/// A tool the operator approved AT a hash serves; the tool BESIDE it on the same, fully pinned
/// server does not, because approval is per capability and the server pin is not a blanket one.
///
/// This is the half `serves` contributes that a `pinned && hash.is_some()` pair only appeared to:
/// the comparison is against the digest of THIS capability, looked up by THIS capability's name.
#[test]
fn approval_is_per_capability_on_one_pinned_server() {
    let mut c = cfg_of(McpPinMechanism::CertSpki, Some("sha256:approved"));
    c.servers
        .get_mut("fs")
        .expect("fixture server")
        .tools_allow
        .insert("write".to_string(), ToolAllowCfg::default());
    let cat = Catalogue::build(&c);
    let grant = |kind: &str, value: &str| {
        matches!(
            (kind, value),
            ("mcp_server", "fs") | ("mcp_tool", "fs_read") | ("mcp_tool", "fs_write")
        )
    };
    assert!(cat
        .resolve(&grant, LiveSightings::unsighted(), "fs_read")
        .is_ok());
    assert_eq!(
        cat.resolve(&grant, LiveSightings::unsighted(), "fs_write"),
        Err(DispatchRefusal::NotApproved("fs_write".to_string())),
        "the pin is the server's; the approval is the capability's"
    );
}

// ── THE SOURCE SCAN THAT USED TO LIVE HERE ──────────────────────────────────────────────────────
//
// `the_catalogue_holds_no_second_may_this_serve_comparison` and its companion
// `the_may_this_serve_scan_would_catch_a_violation` `include_str!`-ed `../catalogue.rs` and failed
// on `.pinned` / `schema_hash.is_some()` / `schema_hash.is_none()`, plus a positive half asserting
// exactly one `Approval::serves` call in that file.
//
// They defended a live invariant — THERE IS EXACTLY ONE TRUST COMPARISON — through a dead medium:
// their subject was a path, and `mcp/` is being rebuilt. Both halves now live in
// `scripts/structure-lint.sh`, which is file-agnostic and goes RED rather than quiet when its
// subject moves:
//
//   * the NEGATIVE half is choke point `I-trust-serve-derivation`, which bans those same raw-field
//     re-derivations TREE-WIDE (not in one named file) outside `crates/busbar/src/trust/`;
//   * the POSITIVE half is declaration-census row `trust-serve-decision`, which requires exactly
//     ONE `fn serves(` in production code. Two is the divergence; ZERO is the false green the old
//     `assert_eq!(serves_calls, 1)` was watching for, and the census reports it as SUBJECT-MISSING
//     rather than as a pass.
//
// Both were proven red before this deletion: a planted `entry.schema_hash.is_none()` in
// `catalogue.rs` and a planted second `fn serves` in the same file each failed the lint.
