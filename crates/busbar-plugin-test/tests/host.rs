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
                    5,
                    "{image}: the 5 lent bytes on connection 7, never the forged length 999"
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

#[test]
fn a_mutant_stating_another_version_is_refused_against_its_twin() {
    let wrong = host().open(
        Image::<Transport>::mutant_as(
            Mutant::of(transport_door::door).version("0.0.0-restated"),
            transport_door::door,
        ),
        "mutant-version",
        b"{}",
    );
    assert!(
        matches!(wrong, Err(Refused::Load(LoadError::StatementMismatch))),
        "{:?}",
        wrong.err()
    );
}

#[test]
fn a_transport_stating_another_frame_piece_size_is_refused() {
    let host_size = busbar_contract::abi::transport::FRAME_PIECE_SIZE;
    let wrong = host().open(
        Image::<Transport>::mutant(
            Mutant::of(transport_door::door).frame_piece_size(host_size - 8),
        ),
        "mutant-frame-piece",
        b"{}",
    );
    assert!(
        matches!(
            wrong,
            Err(Refused::Load(LoadError::FramePieceSize { stated, host, .. }))
                if stated == host_size - 8 && host == host_size
        ),
        "{:?}",
        wrong.err()
    );
}

#[test]
#[should_panic(expected = "this row edits a Plane tail only")]
fn a_tail_row_refuses_another_kind_s_door() {
    let _ = Mutant::of(transport_door::door).answer_layout(1);
}

#[test]
fn a_failing_ready_refuses_the_open_once_with_its_text() {
    let before = Mutant::failed_readies();
    let refused = host().open(
        Image::<Transport>::mutant(
            Mutant::of(transport_door::door).failing_ready("fixture: discovery refused"),
        ),
        "mutant-ready",
        b"{}",
    );
    assert!(
        matches!(
            &refused,
            Err(Refused::Ready(text))
                if text == "plugin 'host-fixture-transport' ready failed: fixture: discovery refused"
        ),
        "{:?}",
        refused.err()
    );
    assert_eq!(Mutant::failed_readies() - before, 1, "READY is not retried");
}

#[test]
fn scripted_services_answer_what_the_test_says_and_name_the_rest() {
    use busbar_contract::abi::mechanism::KindCode;
    use busbar_contract::services::HostServices;
    use busbar_plugin_test::{Caller, Reading, Services, Stored, UNSERVED};

    let svc = std::sync::Arc::new(
        Services::new()
            .on_now(|| Reading {
                wall_ns: 5,
                mono_ns: 6,
            })
            .on_sign(|_, data| Stored::ready(data.len() as u64)),
    );
    let caller = Caller::for_test("services-fixture".into(), KindCode::Plane);
    assert_eq!(
        HostServices::now(&*svc),
        Reading {
            wall_ns: 5,
            mono_ns: 6
        }
    );
    assert_eq!(HostServices::sign(&*svc, &caller, b"four").value, 4);
    let unserved = HostServices::random_fill(&*svc, 16);
    assert_eq!(
        (unserved.outcome, unserved.value, unserved.error),
        (
            Outcome::Refused,
            busbar_contract::abi::host::service::REFUSED_UNSERVED,
            UNSERVED
        )
    );
    assert_eq!(svc.unscripted(), ["random_fill"]);
    // The double is what a host binds.
    let _ = host().services(svc);
}
