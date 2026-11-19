// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The outbound carrier table (dial decision v2, sections 2.3 to 2.5): one supplier per carrier, a checked read of
//! an untrusted carrier number, the build's assignment refused when doubled, validated on described facts, and
//! bound once to the opened instances.

use std::sync::Arc;

use busbar_plugin_abi::plane::{
    CARRIER_DEFAULT, CARRIER_GRPC, CARRIER_HTTP, CARRIER_RTC, CARRIER_STDIO, CARRIER_WEBSOCKET,
};
use busbar_plugin_abi::transport::{FB_CLIENT, FB_DATAGRAM, FB_SERVER};
use busbar_plugin_abi::types::KindCode;

use super::{CarrierRefused, Carriers, NativeFramers};
use crate::root::min3_boot::transports::tests::with_facts;

const FOUR: [(u32, &str); 4] = [
    (CARRIER_HTTP, "stream-image"),
    (CARRIER_GRPC, "rpc-image"),
    (CARRIER_WEBSOCKET, "session-image"),
    (CARRIER_RTC, "datagram-image"),
];

fn table(pairs: &[(u32, &str)]) -> Result<Carriers<Arc<str>>, String> {
    Carriers::of(
        pairs
            .iter()
            .map(|(carrier, identity)| Ok((*carrier, Arc::from(*identity)))),
    )
}

fn described<'r>(
    rows: &'r [(&'r str, KindCode, u64)],
) -> impl Fn(&str) -> Option<(KindCode, u64)> + 'r {
    move |identity| {
        rows.iter()
            .find(|(id, _, _)| *id == identity)
            .map(|(_, kind, facts)| (*kind, *facts))
    }
}

#[test]
fn the_checked_read_refuses_zero_stdio_and_out_of_range_without_a_panic() {
    let empty = table(&[]).expect("an empty assignment");
    let full = table(&FOUR).expect("the four carriers");
    for carriers in [&empty, &full] {
        assert_eq!(
            carriers.get(CARRIER_DEFAULT),
            Err(CarrierRefused::Unresolved)
        );
        assert_eq!(carriers.get(CARRIER_STDIO), Err(CarrierRefused::Stdio));
        for out in [6, 7, 1_000, u32::MAX] {
            assert_eq!(carriers.get(out), Err(CarrierRefused::OutOfRange(out)));
        }
    }
    for (carrier, _) in FOUR {
        assert_eq!(empty.get(carrier), Err(CarrierRefused::NoSupplier(carrier)));
    }
    assert!(CarrierRefused::Unresolved
        .to_string()
        .contains("core fault"));
    assert!(CarrierRefused::Stdio.to_string().contains("core fault"));
    assert!(CarrierRefused::OutOfRange(6)
        .to_string()
        .contains("the plane's exchange is refused"));
    assert!(CarrierRefused::NoSupplier(CARRIER_GRPC)
        .to_string()
        .contains("`grpc`"));
}

#[test]
fn each_carrier_reads_its_own_supplier() {
    let full = table(&FOUR).expect("the four carriers");
    for (carrier, identity) in FOUR {
        assert_eq!(&**full.get(carrier).expect("assigned"), identity);
    }
    let one = table(&[(CARRIER_WEBSOCKET, "ws")]).expect("one carrier");
    assert_eq!(&**one.get(CARRIER_WEBSOCKET).expect("assigned"), "ws");
    for carrier in [CARRIER_HTTP, CARRIER_GRPC, CARRIER_RTC] {
        assert_eq!(one.get(carrier), Err(CarrierRefused::NoSupplier(carrier)));
    }
}

#[test]
fn a_doubled_carrier_an_image_under_two_carriers_and_a_bad_number_are_refused() {
    let doubled = table(&[(CARRIER_HTTP, "a"), (CARRIER_HTTP, "b")])
        .err()
        .expect("a carrier assigned twice");
    assert!(doubled.contains("`http` is assigned twice"), "{doubled}");
    let two = table(&[(CARRIER_HTTP, "a"), (CARRIER_GRPC, "a")])
        .err()
        .expect("one image under two carriers");
    assert!(
        two.contains("`a` is assigned two carriers, `http` and `grpc`"),
        "{two}"
    );
    for bad in [CARRIER_DEFAULT, CARRIER_STDIO, 9] {
        assert!(table(&[(bad, "a")]).is_err(), "carrier {bad} has no slot");
    }
    let admission = Carriers::of([Err::<(u32, Arc<str>), String>("refused header".into())])
        .err()
        .expect("a header that does not admit refuses the assignment");
    assert_eq!(admission, "refused header");
}

#[test]
fn validation_reads_the_described_kind_and_role() {
    let full = table(&FOUR).expect("the four carriers");
    let good = [
        ("stream-image", KindCode::Transport, FB_SERVER | FB_CLIENT),
        ("rpc-image", KindCode::Transport, FB_CLIENT),
        ("session-image", KindCode::Transport, FB_CLIENT),
        ("datagram-image", KindCode::Transport, FB_DATAGRAM),
    ];
    full.check(described(&good))
        .expect("each image holds its carrier's role");
    table(&[])
        .expect("an empty assignment")
        .check(described(&[]))
        .expect("nothing assigned, nothing to check");

    let missing = full
        .check(described(&good[1..]))
        .err()
        .expect("an assigned image that is not admitted");
    assert!(
        missing.contains("`http`") && missing.contains("not admitted"),
        "{missing}"
    );

    for (row, kind, facts, carrier) in [
        (0, KindCode::Transport, FB_SERVER, "`http`"),
        (0, KindCode::Transport, FB_CLIENT | FB_DATAGRAM, "`http`"),
        (2, KindCode::Plane, FB_CLIENT, "`websocket`"),
        (3, KindCode::Transport, FB_CLIENT, "`rtc`"),
    ] {
        let mut rows = good.to_vec();
        rows[row].1 = kind;
        rows[row].2 = facts;
        let refused = full
            .check(described(&rows))
            .err()
            .expect("the wrong kind or role");
        assert!(refused.contains(carrier), "{refused}");
    }
}

#[test]
fn the_opened_table_lends_the_assigned_instance_and_refuses_the_rest() {
    let http = with_facts("stream-image", FB_SERVER | FB_CLIENT);
    let rtc = with_facts("datagram-image", FB_DATAGRAM);
    let (http_port, rtc_port) = (Arc::clone(&http.port), Arc::clone(&rtc.port));
    let assigned = table(&[
        (CARRIER_HTTP, "stream-image"),
        (CARRIER_RTC, "datagram-image"),
    ])
    .expect("two carriers");
    let framers = NativeFramers::new(vec![with_facts("other", FB_CLIENT), rtc, http])
        .carrying(&assigned)
        .expect("each assigned image is opened");

    let lent = framers.for_carrier(CARRIER_HTTP).expect("http is assigned");
    assert_eq!(&*lent.instance, "stream-image");
    assert!(Arc::ptr_eq(&lent.port, &http_port));
    assert_eq!(
        Arc::strong_count(&http_port),
        2,
        "a lookup borrows: the served table and the test's copy hold the port, the lookup takes no count"
    );
    let rtc_lent = framers.for_carrier(CARRIER_RTC).expect("rtc is assigned");
    assert!(Arc::ptr_eq(&rtc_lent.port, &rtc_port));

    for carrier in [CARRIER_GRPC, CARRIER_WEBSOCKET] {
        assert_eq!(
            framers.for_carrier(carrier).err(),
            Some(CarrierRefused::NoSupplier(carrier))
        );
    }
    assert_eq!(
        framers.for_carrier(CARRIER_DEFAULT).err(),
        Some(CarrierRefused::Unresolved)
    );
    assert_eq!(
        framers.for_carrier(CARRIER_STDIO).err(),
        Some(CarrierRefused::Stdio)
    );
    assert_eq!(
        framers.for_carrier(6).err(),
        Some(CarrierRefused::OutOfRange(6))
    );

    let held = framers.clone();
    drop(framers);
    assert_eq!(
        &*held
            .for_carrier(CARRIER_HTTP)
            .expect("the generation keeps its table")
            .instance,
        "stream-image"
    );
    assert_eq!(
        held.carrier_line(),
        "outbound carriers (assigned by the build): http=stream-image grpc=none websocket=none \
         rtc=datagram-image"
    );
}

#[test]
fn an_assigned_image_with_no_opened_instance_refuses_the_boot() {
    let assigned = table(&[(CARRIER_GRPC, "rpc-image")]).expect("one carrier");
    let refused = NativeFramers::new(vec![with_facts("stream-image", FB_CLIENT)])
        .carrying(&assigned)
        .err()
        .expect("the assigned image was not opened");
    assert!(
        refused.contains("`grpc`") && refused.contains("no opened instance"),
        "{refused}"
    );
    let none = NativeFramers::new(Vec::new())
        .carrying(&table(&[]).expect("an empty assignment"))
        .expect("nothing assigned binds nothing");
    assert_eq!(
        none.carrier_line(),
        "outbound carriers (assigned by the build): http=none grpc=none websocket=none rtc=none"
    );
}

#[test]
fn the_build_assignment_and_its_listing_read_the_generated_table() {
    let carriers = super::assigned(crate::LINKED_CARRIERS).expect("the build's assignment admits");
    let lines = super::listing().expect("the listing");
    assert_eq!(lines.len(), 4);
    for ((carrier, word), line) in super::CARRIERS.iter().zip(&lines) {
        assert!(line.starts_with(&format!("  {word}")), "{line}");
        match carriers.get(*carrier) {
            Ok(identity) => assert!(line.contains(&**identity), "{line}"),
            Err(_) => assert!(line.ends_with(" none"), "{line}"),
        }
    }
    assert!(super::assigned(&[]).is_ok());
}
