// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Valid service frames against real linked and independently loaded SDK instances.
use super::*;
use crate::dispatch::{
    load_dropped, load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, Kind, LinkedRow,
    NoSink, Plugin,
};

fn instance<K: Kind>(
    dispatcher: &Dispatcher,
    door: busbar_contract::abi::mechanism::door::DoorFn,
    example: &str,
    dropped: bool,
) -> Plugin<K> {
    let row = LinkedRow::of(door).expect("neutral descriptor states itself");
    let bind = Bind {
        instance: Arc::from("kind-boundary-loaded"),
        max_inflight_cap: 8,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: ConnTable::Probe,
    };
    let plugin = if dropped {
        load_dropped::<K>(
            &crate::both_ways::example_cdylib(example),
            &crate::dispatch::rendering_of(door).unwrap(),
            bind,
        )
    } else {
        load_linked::<K>(&row, bind)
    }
    .expect("neutral SDK instance is admitted");
    assert_eq!(
        crate::door_both_ways::open(&plugin, b"{}").outcome,
        Outcome::Ready
    );
    plugin
}

fn exercise<K: Kind>(
    door: busbar_contract::abi::mechanism::door::DoorFn,
    example: &str,
    allowed: bool,
) {
    for dropped in [false, true] {
        let provider = Arc::new(Provider::default());
        let dispatcher = Dispatcher::with_services(
            DispatchConfig::default(),
            provider.clone(),
            busbar_contract::services::test_caller_binding(),
        );
        let plugin = instance::<K>(&dispatcher, door, example, dropped);
        let ctx = plugin.test_host_context();
        let ticket = dispatcher.mint(0).expect("live operation ticket");
        let mut bytes = [0u8; 16];
        let mut spans = [NO_SPAN; 1];
        let get = RecordsGetIn {
            head: head(op::RECORDS_GET, ticket, 0, size_of::<RecordsGetIn>()),
            kind: text("approval"),
            key: text("k1"),
            into: bufs(&mut bytes, &mut spans),
        };
        let put = VerifyStoreIn {
            head: head(
                op::VERIFY_STORE,
                Ticket::NONE,
                0,
                size_of::<VerifyStoreIn>(),
            ),
            key: text("card:a"),
            entry: blob_over(b"verified-entry"),
            ttl_ms: 9,
        };
        plugin.test_in_host_operation(|| {
            let mut out = blank();
            // SAFETY: exact initialized C ABI frames and live nested buffers; the callback
            // is deliberately cached from the full host table, bypassing the advertised mask.
            let result = unsafe {
                HOST_SLOTS.records_get.unwrap()(ctx, std::ptr::from_ref(&get).cast(), &mut out)
            };
            assert_eq!(
                result.outcome(),
                if allowed {
                    Outcome::Ready
                } else {
                    Outcome::Refused
                }
            );
            if allowed {
                assert!(unsafe { svc::check_records_get(&get, result, &out) }.is_ok());
                assert_eq!(&bytes[..4], b"k1=v");
            } else {
                assert!(error(&out).contains("this kind or lifecycle phase"));
                assert_eq!(bytes, [0u8; 16]);
                assert!(provider.scoped.lock().unwrap().is_empty());
            }
            let mut out = blank();
            // SAFETY: valid unticketed exact-service request with nonempty key and entry.
            let result = unsafe {
                HOST_SLOTS.verify_store.unwrap()(ctx, std::ptr::from_ref(&put).cast(), &mut out)
            };
            assert_eq!(
                result.outcome(),
                if allowed {
                    Outcome::Ready
                } else {
                    Outcome::Refused
                }
            );
            if allowed {
                assert!(check_verify_store(&put, result, &out).is_ok());
            } else {
                assert!(error(&out).contains("this kind or lifecycle phase"));
            }
        });
        assert_eq!(
            provider.scoped.lock().unwrap().len(),
            if allowed { 2 } else { 0 }
        );
        assert_eq!(provider.judged.load(Ordering::SeqCst), 0);
        assert!(provider.held.lock().unwrap().is_empty());
        assert!(
            !plugin.is_faulted(),
            "a denied capability does not fault its caller"
        );
        assert!(
            plugin.is_open(),
            "the negative control used a live instance"
        );
        dispatcher.recycle(ticket);
        assert_eq!(
            crate::door_both_ways::close(&plugin).outcome,
            Outcome::Ready
        );
    }
}

#[test]
fn well_formed_raw_callbacks_refuse_wrong_kinds_before_provider_in_both_loading_modes() {
    exercise::<crate::dispatch::kinds::store_v4::StoreV4>(
        crate::neutral_store::door,
        "neutral_store_door",
        false,
    );
    exercise::<crate::dispatch::kinds::secret::Secret>(
        crate::neutral_secret::door,
        "neutral_secret_door",
        false,
    );
    exercise::<crate::dispatch::kinds::export::Export>(
        crate::neutral_export::door,
        "neutral_export_door",
        false,
    );
    // Identical frames reach a provider through the permitted kind on both loading paths.
    exercise::<crate::dispatch::kinds::auth::Auth>(
        crate::neutral_auth::door,
        "neutral_auth_door",
        true,
    );
}

#[test]
fn rejected_auth_and_unit_bindings_never_reach_a_live_provider() {
    let (d, side) = served_double();
    let other = double_for(busbar_contract::abi::mechanism::KindCode::Transport);
    let auth = mint_auth_ref(owner(&d), generation(), 3).unwrap();
    let (mut bytes, mut spans) = ([0u8; 64], [NO_FIELD_SPAN; 4]);
    let mut answer = answer_slot();
    for bad in [
        mint_auth_ref(owner(&other), generation(), 3).unwrap(),
        mint_auth_ref(owner(&d), generation().wrapping_sub(1), 3).unwrap(),
        AuthRef {
            mac: auth.mac ^ 1,
            ..auth
        },
    ] {
        let input = auth_call_into(bad, &mut answer, &mut bytes, &mut spans);
        let (ret, out) = call_auth(d.ctx, &input);
        assert_eq!(ret.outcome(), Outcome::Refused);
        assert_eq!(error(&out), REF_NOT_MINTED);
        assert!(side.calls.lock().unwrap().is_empty());
    }
    side.units.lock().unwrap().push((
        owner(&d),
        9,
        UnitSecret {
            secret: SIDE_SECRET,
            generation: generation(),
            line: 2,
        },
    ));
    for bad in [
        mint_unit_ref(SIDE_SECRET, generation(), owner(&other), 2, 9).unwrap(),
        mint_unit_ref(SIDE_SECRET, generation().wrapping_sub(1), owner(&d), 2, 9).unwrap(),
        mint_unit_ref(SIDE_SECRET, generation(), owner(&d), 3, 9).unwrap(),
    ] {
        let mut input = auth_call_into(auth, &mut answer, &mut bytes, &mut spans);
        input.unit = bad;
        let (ret, out) = call_auth(d.ctx, &input);
        assert_eq!(ret.outcome(), Outcome::Refused);
        assert_eq!(error(&out), REF_NOT_MINTED);
        assert!(side.calls.lock().unwrap().is_empty());
    }
    let input = auth_call_into(auth, &mut answer, &mut bytes, &mut spans);
    {
        let _crossing = crossing(Ticket {
            generation: TICKET.generation ^ 1,
            ..TICKET
        });
        let (ret, out) = call_auth(d.ctx, &input);
        assert_eq!(ret.outcome(), Outcome::Refused);
        assert_eq!(error(&out), NOT_THIS_CROSSING);
    }
    d.wake.revoked.store(true, Ordering::Release);
    assert_eq!(call_auth(d.ctx, &input).0.outcome(), Outcome::Refused);
    assert!(side.calls.lock().unwrap().is_empty());
    assert!(side.hands.lock().unwrap().is_empty());
    assert!(side.refusals.lock().unwrap().is_empty());
    assert!(side.held.lock().unwrap().is_empty());

    // Restore the fixture's lifecycle for an otherwise-identical positive control.
    d.wake.revoked.store(false, Ordering::Release);
    let (ret, out) = call_auth(d.ctx, &input);
    assert_eq!(ret.outcome(), Outcome::Ready, "{}", error(&out));
    assert_eq!(side.calls.lock().unwrap().len(), 1);
}
