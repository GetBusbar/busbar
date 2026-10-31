// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`AuthRows`] over the registry: what it answers, and what it refuses to open.

use std::sync::Arc;
use std::time::Duration;

use super::AuthRows;
use crate::dispatch::{Budgets, DispatchConfig, Dispatcher};
use crate::PluginRegistry;

fn empty() -> AuthRows {
    let d = Arc::new(Dispatcher::new(DispatchConfig {
        workers: 1,
        budgets: Budgets::default(),
        watchdog_period: Duration::from_millis(20),
        ..DispatchConfig::default()
    }));
    AuthRows::new(Arc::new(PluginRegistry::empty()), d)
}

#[test]
fn a_module_no_row_answers_is_refused_by_name() {
    let rows = empty();
    assert!(!rows.answers("nobody"));
    assert!(!rows.linked("nobody"));
    assert!(rows.linked_names().is_empty());
    let err = rows
        .open("nobody", "nobody", &serde_json::json!({}))
        .err()
        .expect("refused");
    assert_eq!(err, "no `kind: auth` plugin answers to 'nobody'");
}

/// A verify-only fixture plugin whose verdict is never read: these tests read Statements.
struct Fixture;

impl busbar_contract::abi::sdk::auth_door::VerifyPlugin for Fixture {
    fn validate(settings: &[u8]) -> Result<(), busbar_contract::abi::sdk::life::Refusal> {
        busbar_contract::abi::sdk::auth_door::validate_by_opening::<Self>(settings)
    }

    fn open(
        _settings: &[u8],
        _secrets: &[&[u8]],
    ) -> Result<Self, busbar_contract::abi::sdk::life::Refusal> {
        Ok(Self)
    }

    fn verify(
        &self,
        _request: &busbar_contract::abi::sdk::auth_door::VerifyView<'_>,
    ) -> busbar_contract::abi::sdk::auth_door::Answer {
        busbar_contract::abi::sdk::auth_door::Verdict::Pass.into()
    }
}

/// The fixture's carrier marks, in the order its Statement states them (opaque words here).
const MARKS: &[busbar_contract::abi::mechanism::door::MarkWord] = &[
    busbar_contract::abi::sdk::auth_door::carrier("line-one"),
    busbar_contract::abi::sdk::auth_door::carrier("line-two"),
    busbar_contract::abi::sdk::auth_door::carrier("line-three"),
];

const DEFAULT_TAIL: &busbar_contract::abi::auth::AuthTail =
    &busbar_contract::abi::sdk::auth_door::verify_tail(
        busbar_contract::abi::auth::FACT_DEFAULT_INBOUND_STYLE,
        busbar_contract::abi::auth::AuthPoints::HEAD,
    );

const PLAIN_TAIL: &busbar_contract::abi::auth::AuthTail =
    &busbar_contract::abi::sdk::auth_door::verify_tail(
        0,
        busbar_contract::abi::auth::AuthPoints::HEAD,
    );

const fn stating(
    name: &'static str,
    tail: &'static busbar_contract::abi::auth::AuthTail,
    marks: &'static [busbar_contract::abi::mechanism::door::MarkWord],
) -> busbar_contract::abi::mechanism::door::Statement {
    busbar_contract::abi::sdk::auth_door::with_tail(
        busbar_contract::abi::mechanism::door::Statement {
            mark_words: marks.as_ptr(),
            mark_words_len: marks.len(),
            ..busbar_contract::abi::sdk::door::statement(name, "1.0.0", 4)
        },
        tail,
    )
}

mod default_a {
    busbar_contract::auth_verify_door!(
        super::Fixture,
        super::stating("default-a", super::DEFAULT_TAIL, super::MARKS)
    );
}

mod default_b {
    busbar_contract::auth_verify_door!(
        super::Fixture,
        super::stating("default-b", super::DEFAULT_TAIL, super::MARKS)
    );
}

mod plain {
    busbar_contract::auth_verify_door!(
        super::Fixture,
        super::stating("plain", super::PLAIN_TAIL, super::MARKS)
    );
}

mod markless_default {
    busbar_contract::auth_verify_door!(
        super::Fixture,
        super::stating("markless-default", super::DEFAULT_TAIL, &[])
    );
}

/// The auth rows over `doors`, each linked under its name.
fn linking(doors: &[(&str, busbar_contract::abi::mechanism::door::DoorFn)]) -> AuthRows {
    let d = Arc::new(Dispatcher::new(DispatchConfig {
        workers: 1,
        budgets: Budgets::default(),
        watchdog_period: Duration::from_millis(20),
        ..DispatchConfig::default()
    }));
    let linked = doors
        .iter()
        .map(|(name, door)| crate::LinkedPlugin::auth_door(name, *door))
        .collect();
    let registry = PluginRegistry::empty()
        .link(linked)
        .expect("the linked doors admit");
    AuthRows::new(Arc::new(registry), d)
}

/// THE HOST'S DEFAULT INBOUND STYLE (row 159, K3#1): the carriers of the one row stating
/// `FACT_DEFAULT_INBOUND_STYLE`, in its Statement's order; a row that does not state it lends
/// none, and no row stating it is none.
#[test]
fn the_default_inbound_style_is_the_one_stating_rows_carriers_in_order() {
    let rows = linking(&[("plain", plain::door), ("default-a", default_a::door)]);
    assert_eq!(
        rows.default_inbound_style(),
        Ok(vec![
            "line-one".to_string(),
            "line-two".to_string(),
            "line-three".to_string()
        ])
    );
    assert_eq!(rows.carriers("plain").len(), 3, "a row's own carriers");
    assert!(rows.carriers("nobody").is_empty());
    let none = linking(&[("plain", plain::door)]);
    assert_eq!(none.default_inbound_style(), Ok(Vec::new()));
}

/// TWO ROWS stating the default inbound style refuse boot, naming both (RED arm: one row answers).
#[test]
fn two_default_inbound_styles_refuse_naming_both() {
    let rows = linking(&[
        ("default-a", default_a::door),
        ("default-b", default_b::door),
    ]);
    assert_eq!(
        rows.default_inbound_style(),
        Err(super::two_default_inbound_styles(&[
            "default-a",
            "default-b"
        ]))
    );
}

/// The default inbound style IS its carriers: a Statement that states the fact and no carrier is
/// refused at load, so it states nothing here.
#[test]
fn a_default_inbound_style_with_no_carrier_is_refused_at_load() {
    let rows = linking(&[("markless-default", markless_default::door)]);
    assert_eq!(rows.default_inbound_style(), Ok(Vec::new()));
    let err = rows
        .open(
            "markless-default",
            "markless-default",
            &serde_json::json!({}),
        )
        .err()
        .expect("refused");
    assert!(
        err.contains("states the default inbound style and its Statement names no carrier"),
        "{err}"
    );
}

/// LAW 7 (BUSBAR-1.6.0.md Part 1: a plugin loads iff config uses it; ARCHITECT ruling 2026-10-20 on
/// root#7 / loader#9: reading a row's static declaration, its kind tail included, is reading, not
/// loading). The boot's fact reads — the credential readers, the default inbound style, the
/// operator row, a module's carriers — read every linked row's Statement and bind none; opening
/// the one module config names binds that row and no other.
#[test]
fn a_linked_row_the_configuration_does_not_name_is_never_bound() {
    let rows = linking(&[("plain", plain::door), ("default-a", default_a::door)]);
    let bound = || {
        rows.bound
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    };
    assert_eq!(rows.default_inbound_style().map(|c| c.len()), Ok(3));
    assert!(rows.credential_readers().is_empty());
    assert_eq!(rows.operator(), None);
    assert_eq!(rows.carriers("plain").len(), 3);
    assert_eq!(bound(), Vec::<String>::new(), "a fact read binds no row");
    rows.open("plain", "plain", &serde_json::json!({}))
        .expect("the named row opens");
    assert_eq!(
        bound(),
        vec!["plain".to_string()],
        "only the named row is bound"
    );
}

// ── THE SIGNED MANIFEST IS THE NO-DLOPEN SOURCE OF A DROPPED-IN ROW'S TAIL (ARCHITECT ruling
// 2026-10-20 on root#7 / loader#9: the canonical rendering carries the whole kind tail) ──────────

/// The operator principal [`operator_row`] states.
const OPERATOR_PRINCIPAL: &str = "manifest-operator";

const OPERATOR_TAIL: &busbar_contract::abi::auth::AuthTail =
    &busbar_contract::abi::sdk::auth_door::with_operator(
        busbar_contract::abi::sdk::auth_door::verify_tail(
            busbar_contract::abi::auth::FACT_OPERATOR,
            busbar_contract::abi::auth::AuthPoints::HEAD,
        ),
        OPERATOR_PRINCIPAL,
    );

mod operator_row {
    busbar_contract::auth_verify_door!(
        super::Fixture,
        super::stating("operator-row", super::OPERATOR_TAIL, super::MARKS)
    );
}

const CACHEABLE_TAIL: &busbar_contract::abi::auth::AuthTail =
    &busbar_contract::abi::sdk::auth_door::verify_tail(
        busbar_contract::abi::auth::FACT_CACHEABLE,
        busbar_contract::abi::auth::AuthPoints::HEAD,
    );

/// [`plain`]'s Statement in every field but one tail fact (`FACT_CACHEABLE`).
mod cacheable {
    busbar_contract::auth_verify_door!(
        super::Fixture,
        super::stating("plain", super::CACHEABLE_TAIL, super::MARKS)
    );
}

/// The auth rows of a plugins directory holding ONE dropped-in `kind: auth` row, aliased `alias`:
/// signed first-party, its manifest stating `door`'s Statement rendering (what the pack tool signs),
/// and its library NOT A LIBRARY. A fact read that opened it would find nothing to open.
fn dropping(alias: &str, door: busbar_contract::abi::mechanism::door::DoorFn) -> AuthRows {
    use crate::sign::{sign, Manifest, SigningKey, TrustPolicy, FIRST_PARTY_PUBLISHER};
    let key = SigningKey::from_bytes(&[0x3c; 32]);
    let lib: &[u8] = b"not a library: a fact read never opens it";
    let stated = crate::dispatch::rendering_of(door).expect("the door states itself");
    let m = sign(
        &key,
        Manifest {
            name: format!("busbar-auth-{alias}"),
            alias: alias.into(),
            kind: "auth".into(),
            version: "1.0.0".into(),
            publisher: FIRST_PARTY_PUBLISHER.into(),
            abi_version: crate::registry::supported_abi("auth")[0],
            statement: Some(hex::encode(stated)),
            ..Default::default()
        },
        lib,
    );
    let dir = std::env::temp_dir().join(format!(
        "busbar-auth-axis-{alias}-{}-{}",
        std::process::id(),
        crate::stage::next_seq()
    ));
    std::fs::create_dir_all(&dir).expect("a scratch plugins directory");
    std::fs::write(
        dir.join(format!("{alias}.tar.gz")),
        crate::tarball::package(&m, "lib.so", lib).expect("it packs"),
    )
    .expect("the tarball is written");
    let policy = TrustPolicy {
        first_party_key: Some(key.verifying_key()),
        ..Default::default()
    };
    let registry = crate::registry::scan_and_validate(&dir, &policy).expect("the row scans");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        registry.loadable().len(),
        1,
        "the dropped-in row is loadable"
    );
    let d = Arc::new(Dispatcher::new(DispatchConfig {
        workers: 1,
        budgets: Budgets::default(),
        watchdog_period: Duration::from_millis(20),
        ..DispatchConfig::default()
    }));
    AuthRows::new(Arc::new(registry), d)
}

/// RED BEFORE THE TAIL WAS RENDERED WHOLE: a dropped-in row's auth facts (its operator fact and
/// principal, its carriers) are read from its SIGNED MANIFEST, with no `dlopen`: its library is not
/// one, and no row is bound. Before, the rendering stated the tail's size alone, so the row was
/// loaded to read them, and a row that would not load stated nothing.
#[test]
fn red_a_dropped_rows_tail_facts_are_read_from_its_signed_manifest_with_no_dlopen() {
    let rows = dropping("manifest-operator", operator_row::door);
    assert_eq!(
        rows.operator(),
        Some((
            "manifest-operator".to_string(),
            OPERATOR_PRINCIPAL.to_string()
        )),
        "the operator row and its principal are the manifest's"
    );
    assert_eq!(
        rows.carriers("manifest-operator"),
        vec![
            "line-one".to_string(),
            "line-two".to_string(),
            "line-three".to_string()
        ],
        "the carriers are the manifest's"
    );
    assert!(rows.credential_readers().is_empty());
    let bound = rows
        .bound
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(bound, Vec::<String>::new(), "a fact read binds no row");
}

/// RED BEFORE THE TAIL WAS RENDERED WHOLE: the admit comparison covers the kind tail. A stated
/// rendering whose auth tail is not the door's ([`plain`]'s, stated for [`cacheable`]'s door, every
/// field equal but `FACT_CACHEABLE`) refuses the load; the door's own rendering admits it. Before,
/// the rendering stated the tail's size alone, so a manifest could state any tail of that size.
#[test]
fn red_a_stated_rendering_whose_tail_is_not_the_doors_is_refused_at_admit() {
    use crate::dispatch::kinds::auth::Auth;
    use crate::dispatch::{load_linked, Bind, ConnTable, LinkedRow, LoadError, NoSink};
    let bind = || Bind {
        instance: Arc::from("tail-admit"),
        max_inflight_cap: 4,
        sink: Arc::new(NoSink),
        dispatcher: crate::dispatch::Adopter::unwatched(),
        conns: ConnTable::NoNeeds,
    };
    let lying = LinkedRow {
        statement: LinkedRow::of(plain::door)
            .expect("the plain door states itself")
            .statement,
        door: crate::dispatch::load::raw(cacheable::door),
    };
    assert_eq!(
        load_linked::<Auth>(&lying, bind())
            .err()
            .map(|e| e.to_string()),
        Some(LoadError::StatementMismatch.to_string()),
        "a manifest stating another tail is refused at admit"
    );
    let own = LinkedRow::of(cacheable::door).expect("the door states itself");
    assert!(
        load_linked::<Auth>(&own, bind()).is_ok(),
        "the door's own rendering admits it"
    );
}

/// A credential reader's kinds: it reads host-held credentials of one kind.
const READER_KINDS: &[busbar_contract::abi::mechanism::call::AbiStr] =
    &[busbar_contract::abi::sdk::door::abi_str("kind-a")];

const READER_TAIL: &busbar_contract::abi::auth::AuthTail =
    &busbar_contract::abi::sdk::auth_door::with_credential_kinds(
        busbar_contract::abi::sdk::auth_door::verify_tail(
            0,
            busbar_contract::abi::auth::AuthPoints::HEAD,
        ),
        READER_KINDS,
    );

/// One issued-credential word mark of `class`.
const fn issued_mark(
    class: u32,
    word: &'static str,
) -> busbar_contract::abi::mechanism::door::MarkWord {
    busbar_contract::abi::mechanism::door::MarkWord {
        class,
        word: busbar_contract::abi::sdk::door::abi_str(word),
        ..busbar_contract::abi::mechanism::door::MarkWord::ZERO
    }
}

/// The credential reader's issued-credential shape, in its `MARK_WORD_ISSUED_*` word marks.
const ISSUED_MARKS: &[busbar_contract::abi::mechanism::door::MarkWord] = &[
    issued_mark(
        busbar_contract::abi::mechanism::door::MARK_WORD_ISSUED_ID_PREFIX,
        "PFX",
    ),
    issued_mark(
        busbar_contract::abi::mechanism::door::MARK_WORD_ISSUED_ID_LENGTH,
        "20",
    ),
    issued_mark(
        busbar_contract::abi::mechanism::door::MARK_WORD_ISSUED_ID_ALPHABET,
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    ),
    issued_mark(
        busbar_contract::abi::mechanism::door::MARK_WORD_ISSUED_SECRET_LENGTH,
        "40",
    ),
    issued_mark(
        busbar_contract::abi::mechanism::door::MARK_WORD_ISSUED_SECRET_ALPHABET,
        "abc+/",
    ),
];

mod issuing_reader {
    busbar_contract::auth_verify_door!(
        super::Fixture,
        super::stating("issuing-reader", super::READER_TAIL, super::ISSUED_MARKS)
    );
}

/// LAW 7 (BUSBAR-1.6.0.md Part 1: a plugin loads iff config uses it; ARCHITECT ruling 2026-10-20 on
/// root#7 / loader#9: reading a row's static declaration is reading, not loading). THE CREDENTIAL
/// THE HOST ISSUES is a fact read every auth build makes: it reads the linked rows' Statements, the
/// credential reader's issued shape included, and binds none. RED before: it bound every auth row
/// to read its facts, so the bound recorder held each linked row's key.
#[test]
fn the_issued_credential_read_binds_no_row() {
    let rows = linking(&[
        ("plain", plain::door),
        ("issuing-reader", issuing_reader::door),
    ]);
    assert_eq!(
        rows.issued_credential(),
        Some((
            "kind-a".to_string(),
            busbar_contract::auth_calls::IssuedShape {
                id_prefix: "PFX".into(),
                id_len: 20,
                id_alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".into(),
                secret_len: 40,
                secret_alphabet: "abc+/".into(),
            }
        ))
    );
    let bound = rows
        .bound
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(bound, Vec::<String>::new(), "a fact read binds no row");
}
