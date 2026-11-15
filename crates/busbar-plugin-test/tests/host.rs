// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SAFE TEST HOST end to end (SDK-SAFE-TEST-HOST §7 MR 2): the facade's own fixtures, linked
//! and cdylib, opened and driven with no `unsafe`; forged doors refused at load.

#[path = "fixtures/store_door.rs"]
mod store_door;
#[path = "fixtures/transport_door.rs"]
mod transport_door;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::transport::{slot, WriteIn};
use busbar_contract::persistence::{DatasetId, PersistenceBackend};
use busbar_plugin_loader::dispatch::kinds::{store_v4::StoreV4, transport::Transport};
use busbar_plugin_loader::dispatch::LoadError;
use busbar_plugin_test::{both, Called, Host, Image, Loans, Mutant, Refused};

fn host() -> Host {
    Host::new(busbar_contract::services::test_caller_binding())
}

#[test]
fn the_store_fixture_opens_through_both_images() {
    both::<StoreV4>("store_fixture", store_door::door, |image, img| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime");
        rt.block_on(async {
            let store = host()
                .store(img, "host-fixture-store", b"{}")
                .await
                .unwrap_or_else(|e| panic!("{image}: {e:?}"));
            let info = store.info();
            assert_eq!(info.dataset, DatasetId([1; 16]), "{image}");
            let clock = store
                .clock(info.dataset)
                .await
                .unwrap_or_else(|e| panic!("{image}: {e:?}"));
            assert_eq!(clock.unix_seconds, 41, "{image}");
        });
    });
}

#[test]
fn a_kind_op_crosses_both_images_with_the_loans_own_lengths() {
    both::<Transport>("transport_fixture", transport_door::door, |image, img| {
        let h = host();
        let mut t = h
            .open(img, "host-fixture-transport", b"{}")
            .unwrap_or_else(|e| panic!("{image}: {e:?}"));
        let mut i = Loans::<WriteIn>::new();
        i.bytes(b"hello").len(999).conn(7);
        match t.call::<{ slot::WRITE }>(i) {
            Called::Ready(a) => {
                assert_eq!(a.outcome(), Outcome::Ready, "{image}: {:?}", a.error());
                assert_eq!(
                    a.get(|o| o.len),
                    12,
                    "{image}: 5 lent bytes and connection 7, never the forged length"
                );
            }
            Called::Pending(p) => {
                p.leak_loans();
                panic!("{image}: write never answers SHORT");
            }
        };
    });
}

#[test]
fn a_forged_door_is_refused_at_load() {
    let h = host();
    let wrong = h.open(
        Image::<Transport>::mutant(Mutant::of(transport_door::door).kind_abi(9)),
        "mutant-kind-abi",
        b"{}",
    );
    assert!(
        matches!(
            wrong,
            Err(Refused::Load(LoadError::KindAbi { door: 9, .. }))
        ),
        "{:?}",
        wrong.err()
    );
    let null = h.open(
        Image::<Transport>::mutant(Mutant::of(transport_door::door).null()),
        "mutant-null",
        b"{}",
    );
    assert!(
        matches!(null, Err(Refused::Load(LoadError::NullDoor))),
        "{:?}",
        null.err()
    );
}

#[test]
#[should_panic(expected = "no cdylib for `no_such_fixture`")]
fn a_missing_cdylib_panics_naming_where_it_looked() {
    let _ = Image::<Transport>::cdylib("no_such_fixture", transport_door::door);
}
