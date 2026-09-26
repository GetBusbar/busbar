// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `Transport::composed_over` has no default body: every implementor answers it explicitly. This
//! is the witness that the linked wires' answers agree with how they are actually built — by the
//! same bottom-up fold the boot seal (`busbar::root::registry::compose`) runs over the linked
//! transport table, which build.rs hands this test as data (`$OUT_DIR/linked_transports.rs`).
//!
//! A wire that opens its own socket answers `None` no matter what it declares in `COMPOSES_OVER`; a
//! wire that is only ever built by being handed another instance names that instance's key. Both
//! halves are checked against the shipped fold (`src/root/tests/fixtures/transport_fold.txt`, the
//! same rows the root's own fold test reads): every wire's answer is the layer that table names, and
//! a composed wire's answer is one of the layers it declares — which is exactly what the registry's
//! boot check (`busbar_contract::transport::registry::check_composition`) relies on being true. The
//! test names no transport: every key it holds is one a linked row declared.

use busbar_contract::transport::TransportSettings;

include!(concat!(env!("OUT_DIR"), "/linked_transports.rs"));

/// The shipped fold: `<wire key> <layer it was composed over, or ->`, in build order.
const TRANSPORT_FOLD: &str = include_str!("../src/root/tests/fixtures/transport_fold.txt");

fn shipped_fold() -> Vec<(&'static str, Option<&'static str>)> {
    TRANSPORT_FOLD
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_once(' ').expect("`<wire> <layer>` row"))
        .map(|(key, over)| (key, (over != "-").then_some(over)))
        .collect()
}

#[test]
fn every_real_transport_answers_composed_over_consistently_with_its_construction() {
    let shipped = shipped_fold();
    // Every linked transport row is built: the fold's rows plus the rows this build leaves unlinked
    // are the shipped table, so a row dropped from the manifest is a row missing here.
    assert_eq!(
        LINKED_TRANSPORTS.len() + LINKED_TRANSPORTS_OFF,
        shipped.len(),
        "the linked transport table and the shipped fold disagree on how many wires there are"
    );

    let built = fold_linked_transports(&TransportSettings::default());
    assert_eq!(
        built.len(),
        LINKED_TRANSPORTS.len(),
        "every linked wire is built"
    );
    let mut composed = 0;
    for (row, t) in &built {
        assert_eq!(t.key(), row.key, "a wire answers the key its row declares");
        let (_, expected) = shipped
            .iter()
            .find(|(key, _)| *key == row.key)
            .unwrap_or_else(|| panic!("`{}` is linked but the shipped fold has no row", row.key));
        let over = t.composed_over();
        match over {
            // A wire that opens its own socket: `None`, regardless of what it declares.
            None => assert_eq!(
                *expected, None,
                "{} opens its own socket and must answer composed_over() = None",
                row.key
            ),
            // A wire only ever built composed: the layer it was actually given, which must be one
            // of the layers `COMPOSES_OVER` names and the one the shipped fold names.
            Some(over) => {
                composed += 1;
                assert!(
                    row.composes_over.contains(&over),
                    "{}.composed_over() = {over:?}, which is not in its own COMPOSES_OVER {:?}",
                    row.key,
                    row.composes_over
                );
                assert_eq!(
                    Some(over),
                    *expected,
                    "{} is built over a layer the shipped fold does not name",
                    row.key
                );
            }
        }
    }
    // The composed half is not vacuous: every composed row of the shipped fold this build links.
    let shipped_composed = shipped
        .iter()
        .filter(|(key, over)| over.is_some() && LINKED_TRANSPORTS.iter().any(|r| r.key == *key))
        .count();
    assert_eq!(composed, shipped_composed, "a composed wire answered None");
    assert!(composed > 0, "the fold composed no wire over another");
}
