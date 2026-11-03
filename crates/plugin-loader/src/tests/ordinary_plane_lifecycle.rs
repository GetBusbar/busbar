// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Ordinary lifecycle ownership on the actual MCP image, both loading paths.
use crate::dispatch::kinds::plane::{open_door, refresh_door, retire_door, Plane};
use crate::dispatch::{
    load_dropped, load_linked, rendering_of_library, Adopter, Bind, ConnTable, LinkedRow, NoSink,
    Plugin,
};
use std::sync::Arc;
fn binding() -> Bind {
    Bind {
        instance: "mcp-lifecycle".into(),
        max_inflight_cap: 8,
        sink: Arc::new(NoSink),
        dispatcher: Adopter::unwatched(),
        conns: ConnTable::Probe,
    }
}
fn linked() -> Plugin<Plane> {
    load_linked::<Plane>(&LinkedRow::of(crate::actual_mcp::door).unwrap(), binding()).unwrap()
}
fn dropped() -> Plugin<Plane> {
    load_dropped::<Plane>(
        &crate::actual_mcp::cdylib(),
        &rendering_of_library(&crate::actual_mcp::cdylib())
            .unwrap()
            .expect("actual product exports its statement"),
        binding(),
    )
    .unwrap()
}
#[test]
fn repeated_plane_loads_reuse_owned_static_words_after_the_image_is_released() {
    const CHILD: &str = "BUSBAR_ACTUAL_DROPPED_WORDS_CHILD";
    const WITNESS: &str = "actual-dropped-word-ownership-complete";
    if std::env::var_os(CHILD).is_none() {
        let output=std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "ordinary_plane_lifecycle::repeated_plane_loads_reuse_owned_static_words_after_the_image_is_released", "--nocapture", "--test-threads=1"])
            .env(CHILD,"1").output().expect("isolated actual image-release control");
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(WITNESS),
            "isolated exact test really ran"
        );
        return;
    }
    let reaped = || {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while crate::dispatch::load::live_reapers() != 0 {
            assert!(
                std::time::Instant::now() < end,
                "actual library unload did not return"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    };
    // The dropped case runs before actual_mcp::door retains any linked descriptor image.
    for (index, make) in [dropped as fn() -> Plugin<Plane>, linked]
        .into_iter()
        .enumerate()
    {
        let first = make();
        let a = first.served();
        let declared = first.declared();
        let owned_section = a.section.to_string();
        let owned_classes = a
            .op_classes
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>();
        let owned_kinds = declared
            .record_kinds
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>();
        reaped();
        let before = crate::dispatch::load::UNLOADS.load(std::sync::atomic::Ordering::SeqCst);
        drop(first);
        reaped();
        if index == 0 {
            assert!(
                crate::dispatch::load::UNLOADS.load(std::sync::atomic::Ordering::SeqCst) > before,
                "the first actual dropped image was released"
            );
        }
        // Read every original word after actual unload and BEFORE a reload can remap it.
        assert_eq!(a.section, owned_section);
        assert_eq!(
            a.op_classes
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>(),
            owned_classes
        );
        assert_eq!(
            declared
                .record_kinds
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>(),
            owned_kinds
        );
        let second = make();
        let b = second.served();
        assert_eq!(a.section, b.section);
        assert_eq!(a.op_classes, b.op_classes);
        assert!(
            std::ptr::eq(a.section, b.section),
            "same declaration has one permanent word copy"
        );
        assert!(!a.op_classes.is_empty());
        assert!(std::ptr::eq(a.op_classes[0], b.op_classes[0]));
        assert!(!declared.record_kinds.is_empty());
        assert!(std::ptr::eq(
            declared.record_kinds[0],
            second.declared().record_kinds[0]
        ));
        reaped();
        let before = crate::dispatch::load::UNLOADS.load(std::sync::atomic::Ordering::SeqCst);
        drop(second);
        reaped();
        if index == 0 {
            assert!(
                crate::dispatch::load::UNLOADS.load(std::sync::atomic::Ordering::SeqCst) > before,
                "the second actual dropped image was released"
            );
        }
        assert_eq!(a.section, "tools");
        assert!(!a.op_classes.is_empty());
        assert_eq!(declared.record_kinds.len(), 4);
    }
    println!("{WITNESS}");
}

#[test]
fn the_hosts_snapshot_copy_survives_the_actual_plugins_next_refresh() {
    for p in [linked(), dropped()] {
        let first = open_door(&p, b"{}", b"{}", None).unwrap();
        let published = first.clone();
        assert_eq!(first.generation, 1);
        let second = refresh_door(&p, b"{}", b"{}", 2).unwrap();
        assert_eq!(second.generation, 2);
        retire_door(&p, 1);
        assert_eq!(
            first, published,
            "generation1 owned copy outlives its retire"
        );
    }
}
#[test]
fn facing_replaces_old_open_inputs_and_closes_its_last_probe() {
    for make in [linked as fn() -> Plugin<Plane>, dropped] {
        let held = Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed = held.clone();
        let bind = Arc::new(move || {
            let p = make();
            observed.lock().unwrap().push(p.inner.clone());
            Ok(p)
        });
        let reg = crate::dispatch::kinds::plane::registration(bind).unwrap();
        let first = (reg.facing)(b"{}", b"", Some("https://one.example"), &[]).unwrap();
        let first_copy = first.clone();
        let again = (reg.facing)(b"{}", b"", Some("https://one.example"), &[]).unwrap();
        assert_eq!(again, first);
        assert_eq!(
            held.lock().unwrap().len(),
            2,
            "same inputs refresh existingprobe"
        );
        (reg.facing)(b"{}", b"{}", Some("https://two.example"), &[]).unwrap();
        assert!(!held.lock().unwrap()[1].is_open(), "supersededinput closed");
        (reg.facing)(b"{}", b"", Some("https://one.example"), &[]).unwrap();
        assert!(!held.lock().unwrap()[2].is_open(), "secondinput closed");
        assert_eq!(first, first_copy, "ownedfacing survivesprobeclose");
        let last = reg.facing.clone();
        drop(reg);
        assert!(held.lock().unwrap()[3].is_open(), "facing owner exists");
        drop(last);
        assert!(
            held.lock().unwrap().iter().all(|p| !p.is_open()),
            "lastowner closesprobe"
        );
    }
}

mod wrong_lifecycle_shape {
    use super::*;
    use crate::dispatch::{in_head, out_head, Frame};
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::mechanism::door::Door;
    use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
    use busbar_contract::abi::sdk::door::{kind_op, Lifecycle, RawSlot};
    struct LifecycleOpen;
    impl RawSlot for LifecycleOpen {
        type In = OpenIn;
        type Out = OpenOut;
        unsafe fn call(_: *mut std::ffi::c_void, _: &OpenIn, out: &mut OpenOut) -> Outcome {
            out.instance = std::ptr::NonNull::<u8>::dangling().as_ptr().cast();
            Outcome::Ready
        }
    }

    static LIFECYCLE_CLOSES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    struct LifecycleClose;
    impl RawSlot for LifecycleClose {
        type In = busbar_contract::abi::mechanism::call::InHead;
        type Out = busbar_contract::abi::mechanism::call::OutHead;
        unsafe fn call(
            _: *mut std::ffi::c_void,
            _: &busbar_contract::abi::mechanism::call::InHead,
            _: &mut busbar_contract::abi::mechanism::call::OutHead,
        ) -> Outcome {
            LIFECYCLE_CLOSES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Outcome::Ready
        }
    }

    struct TestCapture;
    impl busbar_contract::abi::sdk::capture::CaptureHome for TestCapture {
        fn retention() -> &'static busbar_contract::abi::sdk::capture::CaptureRetention {
            static RETENTION: std::sync::OnceLock<
                busbar_contract::abi::sdk::capture::CaptureRetention,
            > = std::sync::OnceLock::new();
            RETENTION.get_or_init(Default::default)
        }
        fn with<R>(f: impl FnOnce(&mut busbar_contract::abi::sdk::capture::CaptureSlot) -> R) -> R {
            thread_local! {
                static SLOT: std::cell::RefCell<busbar_contract::abi::sdk::capture::CaptureSlot> =
                    std::cell::RefCell::new(busbar_contract::abi::sdk::capture::CaptureSlot::new());
            }
            SLOT.with(|s| f(&mut s.borrow_mut()))
        }
    }

    extern "C" fn lifecycle_open_door() -> *const Door {
        // SAFETY: the macro's `'static` door and its plane table.
        let (d, ops) = unsafe {
            let d = crate::actual_mcp::door();
            (d, *d.ops().cast::<busbar_contract::abi::plane::Ops>())
        };
        let mut ops = ops;
        ops.head.open = kind_op::<Lifecycle, LifecycleOpen, TestCapture, { life::OPEN }>();
        ops.head.close = kind_op::<Lifecycle, LifecycleClose, TestCapture, { life::CLOSE }>();
        let ops: &'static busbar_contract::abi::plane::Ops = Box::leak(Box::new(ops));
        Box::leak(Box::new(unsafe {
            Door::__from_parts(busbar_contract::abi::mechanism::door::DoorParts {
                ops: std::ptr::from_ref(ops).cast(),
                ..d.parts()
            })
        }))
    }

    #[test]
    fn red_a_plane_open_over_the_lifecycle_structs_publishes_no_snapshot_and_faults() {
        use busbar_contract::abi::mechanism::call::BLOB_JSON;
        use busbar_contract::abi::plane::{PlaneOpenIn, PlaneOpenOut};
        let red = load_linked::<Plane>(&LinkedRow::of_raw(lifecycle_open_door).unwrap(), binding())
            .unwrap();
        let blob = crate::dispatch::lifecycle::blob(b"{}", BLOB_JSON, 0);
        let mut o = Frame::new(
            PlaneOpenIn {
                open: crate::dispatch::lifecycle::open_in(blob),
                public_url: busbar_contract::abi::mechanism::call::AbiStr::ZERO,
                owned: blob,
                providers: std::ptr::null(),
                providers_len: 0,
            },
            PlaneOpenOut {
                open: crate::dispatch::lifecycle::open_out(),
                snapshot: std::ptr::null(),
            },
        );
        assert_eq!(red.call(life::OPEN, &mut o).outcome, Outcome::Fault);
        assert!(o.out.snapshot.is_null(), "no snapshot reachedhost");
        assert_eq!(
            LIFECYCLE_CLOSES.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "host closed malformed-open instance"
        );
        assert!(!red.is_open());
        let green = linked();
        let snapshot = open_door(&green, b"{}", b"{}", None)
            .expect("actual correct PlaneOPEN snapshot copies");
        assert_eq!(snapshot.generation, 1);
        let mut e = Frame::new(in_head(), out_head());
        assert_eq!(green.call(life::CLOSE, &mut e).outcome, Outcome::Ready);
    }
}

#[test]
fn a_door_states_its_actual_registry_facts_and_judges_its_section() {
    let check = |make: fn() -> Plugin<Plane>| {
        let facts = make();
        let served = facts.served();
        let declared = facts.declared();
        let reg = crate::dispatch::kinds::plane::registration(Arc::new(move || Ok(make())))
            .expect("actual image registration");
        assert_eq!(reg.key, "mcp");
        assert_eq!(reg.section, "tools");
        assert_eq!(
            (reg.label, reg.subject_noun, reg.admin_noun, reg.audit_kind),
            ("MCP", "MCP server", "mcp-server", "mcp_server")
        );
        assert_eq!(reg.dialects, vec!["jsonrpc"]);
        assert_eq!(reg.record_kinds, declared.record_kinds);
        assert_eq!(reg.scope_kinds, declared.scope_kinds);
        assert_eq!(reg.trust_keys, declared.trust_keys);
        assert_eq!(reg.signing, declared.signing);
        assert!(
            reg.signing.is_some(),
            "actual MCP declares its signing domain"
        );
        assert_eq!(
            reg.billable_classes,
            served
                .billable_classes
                .iter()
                .copied()
                .zip(served.billable_families.iter().copied())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            reg.caller_credential_refusal,
            Some(served.caller_credential_refusal)
        );
        assert_eq!((reg.validate)(b"{}"), Ok(()));
        assert!(
            (reg.validate)(b"{").is_err(),
            "actual product refuses malformed settings"
        );
        let faced = (reg.facing)(b"{}", b"", None, &[]).expect("actual product facesworld");
        let again = (reg.facing)(b"{}", b"", None, &[]).expect("same actual input facesagain");
        assert_eq!(again, faced);
        format!("{reg:?}")
    };
    assert_eq!(
        check(linked),
        check(dropped),
        "same actual declaredfacts whicheverloadingpath"
    );
}
