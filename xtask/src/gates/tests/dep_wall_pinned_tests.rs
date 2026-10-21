// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! dep-wall over the git-pinned plugins' own source, and the ledger held against the merge-base
//! (audit Q128 xtask p3, findings 1 and 2).

use super::*;
use crate::gates::construction::ceilings::BASE_PIN_KEY;

/// The base this file's cases pin, and the ledger it carried: today's ledger, verbatim.
const BASE: &str = "zz-dep-wall-base";

fn based(cx: &Ctx) -> Overlay {
    let mut ov = Overlay::new();
    ov.set_command(BASE_PIN_KEY, BASE);
    ov.set_command(
        format!("git-show:{BASE}:{LEDGER}"),
        cx.read(LEDGER).expect("the ledger reads"),
    );
    ov
}

/// Whether `row` FAILED over `cx` with `ov` planted, and its detail.
fn row(cx: &Ctx, ov: Overlay, row: &str) -> (bool, String) {
    let verdict = crate::gates::execute(&DepWallGate, &cx.with_overlay(ov));
    verdict
        .rows
        .iter()
        .find(|r| r.id == row)
        .map(|r| (r.status == crate::ledger::Status::Fail, r.detail.clone()))
        .unwrap_or_default()
}

const SOCKET: &str = "pub fn dial() { let _ = std::net::TcpStream::connect(\"127.0.0.1:1\"); }\n";

#[test]
fn a_socket_in_a_pinned_plane_the_base_lays_is_a_new_offender() {
    let cx = Ctx::workspace().expect("workspace context");
    let mut ov = based(&cx);
    ov.set(
        "crates/busbar-plane-decisions/src/planted_socket.rs",
        SOCKET,
    );
    let (red, new) = row(&cx, ov, ROW_NEW);
    assert!(
        red && new.contains("busbar-plane-decisions") && new.contains("std::net"),
        "std::net planted in the pinned plane busbar-plane-decisions went unreported: {new}"
    );
}

#[test]
fn a_socket_in_a_pinned_plugin_the_base_does_not_lay_is_a_new_offender() {
    let cx = Ctx::workspace().expect("workspace context");
    let mut ov = based(&cx);
    ov.set("crates/busbar-auth-header/src/planted_socket.rs", SOCKET);
    let (red, new) = row(&cx, ov, ROW_NEW);
    assert!(
        red && new.contains("busbar-auth-header") && new.contains("std::net"),
        "std::net planted in the pinned auth plugin busbar-auth-header went unreported: {new}"
    );
}

#[test]
fn a_pin_the_base_ledger_does_not_carry_is_refused() {
    let cx = Ctx::workspace().expect("workspace context");
    let mut ov = based(&cx);
    ov.set("crates/busbar-llm/src/planted_socket.rs", SOCKET);
    ov.set(
        LEDGER,
        format!(
            "{}\nbusbar-llm\tstd::net\n",
            cx.read(LEDGER).unwrap_or_default().trim_end()
        ),
    );
    let (red, new) = row(&cx, ov, ROW_NEW);
    assert!(
        red && new.contains("busbar-llm\tstd::net"),
        "a pin written in the same change as its offence was accepted: {new}"
    );
}

#[test]
fn a_carrier_row_is_refused_whatever_crate_it_names() {
    let cx = Ctx::workspace().expect("workspace context");
    let mut ov = based(&cx);
    ov.set(
        LEDGER,
        format!(
            "{}\ncarrier\tbusbar-transport-ws\n",
            cx.read(LEDGER).unwrap_or_default().trim_end()
        ),
    );
    let (red, scope) = row(&cx, ov, ROW_SCOPE);
    assert!(
        red && scope.contains("carrier<TAB>busbar-transport-ws")
            && scope.contains("Strike the row"),
        "a crate-named carrier row was accepted: {scope}"
    );
}

#[test]
fn a_renamed_tokio_or_a_net_feature_the_plugin_forwards_is_an_offence() {
    let renamed = Pkg {
        name: "x".into(),
        source: None,
        manifest_path: String::new(),
        deps: vec![("tk".into(), vec!["net".into()], false, true)],
        features: BTreeMap::new(),
        packages: BTreeMap::from([("tk".into(), "tokio".into())]),
    };
    assert_eq!(asks(&renamed), ["tokio (net)"]);
    let forwarded = Pkg {
        name: "x".into(),
        source: None,
        manifest_path: String::new(),
        deps: vec![
            ("tk".into(), Vec::new(), true, true),
            ("redis".into(), Vec::new(), false, true),
        ],
        features: BTreeMap::from([
            ("sock".into(), vec!["dep:tk".into(), "tk?/net".into()]),
            ("cache".into(), vec!["redis/tokio-comp".into()]),
        ]),
        packages: BTreeMap::from([("tk".into(), "tokio".into())]),
    };
    assert!(asks(&forwarded).is_empty());
    let mut got = forwards(&forwarded);
    got.sort();
    assert_eq!(got, ["redis (aio)", "tokio (net)"]);
}
