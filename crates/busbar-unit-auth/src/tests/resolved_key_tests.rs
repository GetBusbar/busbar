// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the ONE enforced key shape carries, and what it refuses to carry.
//!
//! Owner ruling 13:0x (6): `ResolvedKey` is the home; the legacy `VirtualKey` dies with core; the
//! money-carrying fields go to the cost and ledger views. Every field asserted here is a field the
//! reader census (`docs/design/1.6.0-virtualkey-reader-table.md`) found a production reader for,
//! and every field asserted ABSENT is one the census found no reader for — or, in the money cases,
//! a reader that ruling 6 sends somewhere else.

use crate::chain::{KeyScope, ResolvedKey};

/// A key that grants exactly the listed scopes.
fn scoped(scopes: &[(&str, &str)]) -> ResolvedKey {
    ResolvedKey {
        scopes: Some(
            scopes
                .iter()
                .map(|(k, v)| KeyScope {
                    kind: (*k).to_string(),
                    value: (*v).to_string(),
                })
                .collect(),
        ),
        ..ResolvedKey::unrestricted("vk_scoped", "scoped")
    }
}

// ── SCOPE ────────────────────────────────────────────────────────────────────────────────────────
//
// PROVEN BY: substrate/egress_auth/gate.rs:224, substrate/trust/validate.rs:353,
// core/governance/mod.rs:869 (`pool_allowed`), core/plane_host/dispatch.rs:272,
// llm/unit/verify.rs:300, voice/mount.rs:106, and the mcp/a2a sites that delegate to the gate.
// Thirteen production call sites; two independent `PoolView` traits exist only because the
// resolved key had nowhere to put this.

#[test]
fn omitted_scope_list_is_every_scope_of_every_kind() {
    // `None` is the wildcard — the grant was omitted at mint. This is the 1.5.3-frozen reading.
    let k = ResolvedKey::unrestricted("vk_open", "open");
    assert!(k.scope_allowed("pool", "anything"));
    assert!(k.scope_allowed("agent", "anything"));
    assert!(k.scope_allowed("a-kind-invented-tomorrow", "anything"));
}

#[test]
fn an_empty_scope_list_is_the_empty_set_and_never_all() {
    // The trap the frozen semantics exist to close: `Some([])` grants NOTHING.
    let k = scoped(&[]);
    assert!(!k.scope_allowed("pool", "anything"));
    assert!(!k.scope_allowed("agent", "anything"));
}

#[test]
fn an_explicit_list_is_exhaustive_across_all_kinds_not_per_kind() {
    // A key naming only pools grants NOTHING for any other kind. The alternative reading — an
    // unlisted kind is "unconstrained, therefore allowed" — is fail-OPEN, and would turn every
    // existing pool-scoped key into a wildcard over a brand-new kind, silently, on upgrade.
    let k = scoped(&[("pool", "blue")]);
    assert!(k.scope_allowed("pool", "blue"));
    assert!(!k.scope_allowed("pool", "green"));
    assert!(!k.scope_allowed("agent", "blue"));
    assert!(!k.scope_allowed("mcp_server", "blue"));
}

// ── EXPIRY + REVOCATION, AS ONE PREDICATE ────────────────────────────────────────────────────────
//
// PROVEN BY: substrate/egress_auth/gate.rs:217 and substrate/trust/validate.rs:339 and :562 each
// spell the IDENTICAL triple `!is_live() || !enabled || expires_at.is_some_and(|e| now >= e)`;
// core/plane_host/dispatch.rs:269 spells two thirds of it. One predicate, four spellings, is the
// defect the single shape closes.

#[test]
fn a_live_enabled_unexpiring_key_is_live_at_every_instant() {
    let k = ResolvedKey::unrestricted("vk_live", "live");
    assert!(k.is_live(0));
    assert!(k.is_live(u64::MAX));
}

#[test]
fn a_disabled_key_is_not_live() {
    let k = ResolvedKey {
        enabled: false,
        ..ResolvedKey::unrestricted("vk_off", "off")
    };
    assert!(!k.is_live(1000));
}

#[test]
fn a_tombstoned_key_is_not_live_even_though_its_row_survives() {
    // The row is KEPT so billing and audit keep resolving the id forever; liveness is the check,
    // and the row's existence is not.
    let k = ResolvedKey {
        deleted_at: Some(500),
        ..ResolvedKey::unrestricted("vk_gone", "gone")
    };
    assert!(!k.is_live(1000));
    assert!(!k.is_live(0));
}

#[test]
fn expiry_is_reached_at_the_instant_and_not_after_it() {
    // `now >= exp`, exactly as the two substrate sites spell it. The boundary is load-bearing:
    // a `>` would leave a key live for the whole second it expires in.
    let k = ResolvedKey {
        expires_at: Some(1000),
        ..ResolvedKey::unrestricted("vk_exp", "exp")
    };
    assert!(k.is_live(999));
    assert!(!k.is_live(1000));
    assert!(!k.is_live(1001));
}

// ── WHAT THE SHAPE DOES NOT CARRY ────────────────────────────────────────────────────────────────

#[test]
fn the_shape_carries_no_money_and_no_secret() {
    // KIND ISOLATION, as a text assertion over this crate's own CODE, because there is no type to
    // assert against: the point is that the auth unit never learned the vocabulary. `group` is the
    // charging-pot reference and belongs to the cost/ledger views under ruling 6; `generation_hash`
    // is secret-equivalent and was redacted even in the legacy `Debug`.
    //
    // COMMENTS ARE STRIPPED, which is the construction gate's own scanning discipline and not a
    // convenience: this file's prose has to be free to say the word `budget` in order to explain
    // why no identifier does. A rule you cannot describe in the source it governs is a rule nobody
    // will be able to maintain.
    let code: String = include_str!("../chain.rs")
        .lines()
        .map(str::trim_start)
        .filter(|l| !l.starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for banned in [
        "budget",
        "rate_card",
        "RateCard",
        "cents",
        "nanos",
        "price",
        "generation_hash",
        "group",
    ] {
        assert!(
            !code.contains(banned),
            "busbar-unit-auth's chain names `{banned}` in code; the auth unit holds no money \
             vocabulary and no secret-equivalent field"
        );
    }
}

#[test]
fn debug_is_derivable_because_nothing_here_is_secret() {
    // The legacy key hand-rolled `Debug` to redact `generation_hash`. This shape needs no such
    // hand-rolling, and that is the observable difference: every field is printable verbatim.
    let rendered = format!("{:?}", scoped(&[("pool", "blue")]));
    assert!(rendered.contains("vk_scoped"));
    assert!(rendered.contains("blue"));
}
