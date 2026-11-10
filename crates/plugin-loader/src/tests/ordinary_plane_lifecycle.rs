// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Ordinary lifecycle ownership on the neutral SDK plane image, both loading paths.
use crate::dispatch::kinds::plane::{open_door, refresh_door, retire_door, Plane};
use crate::dispatch::{
    load_dropped, load_linked, rendering_of_library, Adopter, Bind, ConnTable, LinkedRow, NoSink,
    Plugin,
};
use std::sync::Arc;
fn binding() -> Bind {
    Bind {
        instance: "witness-lifecycle".into(),
        max_inflight_cap: 8,
        sink: Arc::new(NoSink),
        dispatcher: Adopter::unwatched(),
        conns: ConnTable::Probe,
    }
}
fn linked() -> Plugin<Plane> {
    load_linked::<Plane>(
        &LinkedRow::of(crate::neutral_plane::door).unwrap(),
        binding(),
    )
    .unwrap()
}
fn dropped() -> Plugin<Plane> {
    load_dropped::<Plane>(
        &crate::neutral_plane::cdylib(),
        &rendering_of_library(&crate::neutral_plane::cdylib())
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
        assert_eq!(a.section, crate::neutral_plane::SECTION);
        assert!(!a.op_classes.is_empty());
        assert_eq!(declared.record_kinds, ["witness_record", "witness_history"]);
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
        assert_eq!(first.generation, 1);
        assert!(first.claims.is_empty());
        let routes: Vec<_> = first
            .admin_routes
            .iter()
            .map(|r| (r.verb.as_str(), r.target.as_str(), r.audit_verb.as_str()))
            .collect();
        assert_eq!(
            routes,
            [
                ("POST", "/witness/{name}/update", "update"),
                ("GET", "/witness/{name}/status", ""),
            ],
            "generation 1 still reads the literal routes the plugin published"
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
    use busbar_contract::abi::sdk::door::{kind_op, RawSlot};
    struct LifecycleOpen;
    impl RawSlot for LifecycleOpen {
        type Kind = busbar_contract::plugin::markers::PlaneKind;
        type In = OpenIn;
        type Out = OpenOut;
        unsafe fn call(_: *mut std::ffi::c_void, _: &OpenIn, out: &mut OpenOut) -> Outcome {
            out.instance = std::ptr::NonNull::<u8>::dangling().as_ptr().cast();
            Outcome::Ready
        }
    }

    unsafe extern "C" fn malformed_open(
        instance: *mut std::ffi::c_void,
        input: *const std::ffi::c_void,
        out: *mut std::ffi::c_void,
    ) -> busbar_contract::abi::mechanism::call::RawOutcome {
        // SAFETY: this deliberate malformed fixture consumes only the lifecycle prefix
        // of the loader's full plane frames and leaves the required snapshot absent.
        let outcome = unsafe {
            LifecycleOpen::call(
                instance,
                &*input.cast::<OpenIn>(),
                &mut *out.cast::<OpenOut>(),
            )
        };
        unsafe {
            (*out.cast::<OpenOut>()).head.outcome =
                busbar_contract::abi::mechanism::call::RawOutcome::of(outcome);
        }
        busbar_contract::abi::mechanism::call::RawOutcome::of(outcome)
    }

    static LIFECYCLE_CLOSES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    struct LifecycleClose;
    impl RawSlot for LifecycleClose {
        type Kind = busbar_contract::plugin::markers::PlaneKind;
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
            let d = crate::neutral_plane::door();
            (d, *d.ops().cast::<busbar_contract::abi::plane::Ops>())
        };
        let mut ops = ops;
        ops.head.open = Some(malformed_open);
        ops.head.close = kind_op::<
            busbar_contract::abi::plane::Ops,
            busbar_contract::abi::plane::PlaneLifecycle,
            LifecycleClose,
            TestCapture,
            { life::CLOSE },
        >();
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
        assert_eq!(reg.key, crate::neutral_plane::NAME);
        assert_eq!(reg.section, crate::neutral_plane::SECTION);
        assert_eq!(
            (reg.label, reg.subject_noun, reg.admin_noun, reg.audit_kind),
            ("Witness", "witness entry", "witness-entry", "witness_entry")
        );
        assert_eq!(reg.dialects, vec!["witness-wire"]);
        assert_eq!(reg.record_kinds, declared.record_kinds);
        assert_eq!(reg.scope_kinds, declared.scope_kinds);
        assert_eq!(reg.trust_keys, declared.trust_keys);
        assert_eq!(reg.signing, declared.signing);
        assert!(
            reg.signing.is_some(),
            "neutral SDK plane declares its signing domain"
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

mod lifecycle_connections {
    use busbar_contract::abi::mechanism::rendering::ReadNeed;
    use busbar_contract::conn::{
        ConnError, ConnId, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece, Program,
        Ticket,
    };
    use busbar_contract::transport::ConnFacts;
    use std::collections::HashSet;
    use std::sync::Mutex;

    /// The witness configuration performs no connector I/O, but serving still binds every
    /// actual declared need. Probe mode intentionally omits those generation bindings.
    pub(super) struct Table(Mutex<HashSet<(InstanceId, NeedId)>>, HashSet<String>);

    impl Default for Table {
        fn default() -> Self {
            let row = crate::dispatch::LinkedRow::of(crate::neutral_plane::door)
                .expect("the actual plane states its needs");
            let stated = busbar_contract::abi::mechanism::rendering::read(&row.statement)
                .expect("the actual plane statement reads");
            Self(
                Mutex::default(),
                stated
                    .needs
                    .into_iter()
                    .map(|need| need.transport)
                    .collect(),
            )
        }
    }

    impl Conns for Table {
        fn open(&self, _: InstanceId, _: NeedId, _: &OpenDesc<'_>) -> Result<ConnId, ConnError> {
            panic!("empty lifecycle configuration must not open a connection")
        }
        fn write(
            &self,
            _: InstanceId,
            _: ConnId,
            _: &[u8],
            _: bool,
            _: bool,
        ) -> Result<usize, ConnError> {
            panic!("empty lifecycle configuration must not write a connection")
        }
        fn read(
            &self,
            _: InstanceId,
            _: ConnId,
            _: Ticket,
            _: &mut [u8],
        ) -> Result<Piece, ConnError> {
            panic!("empty lifecycle configuration must not read a connection")
        }
        fn wait(&self, _: InstanceId, _: &[ConnId], _: Ticket) -> Result<usize, ConnError> {
            panic!("empty lifecycle configuration must not wait on a connection")
        }
        fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
            panic!("empty lifecycle configuration has no connection facts")
        }
        fn close(&self, _: InstanceId, _: ConnId) -> Result<(), ConnError> {
            panic!("empty lifecycle configuration must not close a connection")
        }
    }

    impl DeclaredConns for Table {
        fn declare(
            &self,
            owner: InstanceId,
            need: NeedId,
            spec: &ReadNeed,
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<(), ConnError> {
            assert!(self.serves_scheme(&spec.transport));
            assert!(
                !spec.target_from.is_empty(),
                "the neutral SDK plane need is settings-bound"
            );
            self.0.lock().unwrap().insert((owner, need));
            Ok(())
        }
        fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
            self.0
                .lock()
                .unwrap()
                .contains(&(owner, need))
                .then_some(Ok(()))
        }
        fn serves_scheme(&self, transport: &str) -> bool {
            self.1.contains(transport)
        }
        fn declare_member_programs(
            &self,
            owner: InstanceId,
            need: NeedId,
            spec: &ReadNeed,
            programs: &[(String, Program)],
        ) -> Result<(), ConnError> {
            assert!(
                programs.is_empty(),
                "the fixture has no configured programs"
            );
            self.declare(owner, need, spec, None, None)
        }
        fn forget(&self, owner: InstanceId) {
            self.0
                .lock()
                .unwrap()
                .retain(|(declared, _)| *declared != owner);
        }
    }
}

fn served_lifecycle_binding(dispatcher: &Arc<crate::dispatch::Dispatcher>) -> Bind {
    Bind {
        dispatcher: dispatcher.adopter(),
        conns: ConnTable::Host(crate::dispatch::test_admissions(Arc::new(
            lifecycle_connections::Table::default(),
        ))),
        ..binding()
    }
}

fn served_lifecycle_plane(
    dropped_image: bool,
    dispatcher: &Arc<crate::dispatch::Dispatcher>,
) -> Plugin<Plane> {
    let binding = served_lifecycle_binding(dispatcher);
    if dropped_image {
        load_dropped::<Plane>(
            &crate::neutral_plane::cdylib(),
            &rendering_of_library(&crate::neutral_plane::cdylib())
                .unwrap()
                .unwrap(),
            binding,
        )
        .unwrap()
    } else {
        load_linked::<Plane>(&LinkedRow::of(crate::neutral_plane::door).unwrap(), binding).unwrap()
    }
}

#[test]
fn served_refresh_waits_for_a_crossing_then_publishes_the_actual_plane_generation() {
    use crate::dispatch::kinds::plane::refresh_door_on;
    use crate::dispatch::{DispatchConfig, Dispatcher};
    use busbar_contract::abi::mechanism::{lifecycle::slot, ticket::Ticket};
    use std::time::{Duration, Instant};

    for dropped_image in [false, true] {
        let dispatcher = Arc::new(Dispatcher::new(
            DispatchConfig::default(),
            busbar_contract::services::test_caller_binding(),
        ));
        let plugin = Arc::new(served_lifecycle_plane(dropped_image, &dispatcher));
        let first = open_door(&plugin, b"{}", b"{}", None).unwrap();
        let held = plugin
            .inner
            .export_admission(slot::TICK, Ticket::NONE)
            .unwrap()
            .expect("the actual plane has generation-bound connection needs");
        assert!(
            refresh_door(&plugin, b"{}", b"{}", 2).is_err(),
            "the old ticketless path refuses this exact crossing"
        );
        let (sent, received) = std::sync::mpsc::channel();
        let join = {
            let plugin = Arc::clone(&plugin);
            let dispatcher = Arc::clone(&dispatcher);
            std::thread::spawn(move || {
                let result = refresh_door_on(&plugin, &dispatcher, b"{}", b"{}", 2);
                sent.send(result).unwrap();
            })
        };
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                received.try_recv().is_err(),
                "refresh must wait for the held crossing"
            );
            if plugin.inner.inflight() != 0 {
                break;
            }
            assert!(
                Instant::now() < until,
                "the queued refresh takes lifecycle custody"
            );
            std::thread::yield_now();
        }
        drop(held);
        let second = received
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        join.join().unwrap();
        assert_eq!(second.generation, 2);
        assert_eq!(first.generation, 1, "the prior snapshot is an owned copy");
        assert!(
            refresh_door_on(&plugin, &dispatcher, b"{", b"{}", 3).is_err(),
            "a terminal plugin refusal is not retried as admission contention"
        );
        let third = refresh_door_on(&plugin, &dispatcher, b"{}", b"{}", 3).unwrap();
        assert_eq!(
            third.generation, 3,
            "the refused generation was not published"
        );
        retire_door(&plugin, 1);
        retire_door(&plugin, 2);
        assert_eq!(
            second.generation, 2,
            "the copied queued snapshot survives retirement"
        );
    }
}

#[test]
fn served_refresh_cancels_a_timed_out_admission_without_publishing_later() {
    use crate::dispatch::kinds::plane::refresh_door_on;
    use crate::dispatch::{DispatchConfig, Dispatcher};
    use busbar_contract::abi::mechanism::{lifecycle::slot, ticket::Ticket};
    use std::time::{Duration, Instant};

    for dropped_image in [false, true] {
        let mut config = DispatchConfig::default();
        config.budgets.lifecycle = Duration::from_millis(100);
        let dispatcher = Arc::new(Dispatcher::new(
            config,
            busbar_contract::services::test_caller_binding(),
        ));
        let plugin = Arc::new(served_lifecycle_plane(dropped_image, &dispatcher));
        open_door(&plugin, b"{}", b"{}", None).unwrap();
        let prior = plugin.inner.wake.exports.pin(Ticket::NONE).unwrap();
        let held = plugin
            .inner
            .export_admission(slot::TICK, Ticket::NONE)
            .unwrap()
            .unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        let join = {
            let plugin = Arc::clone(&plugin);
            let dispatcher = Arc::clone(&dispatcher);
            std::thread::spawn(move || {
                let _ = sent.send(refresh_door_on(&plugin, &dispatcher, b"{}", b"{}", 2));
            })
        };
        let refused = received
            .recv_timeout(Duration::from_secs(5))
            .expect("a blocked queue settles within its deadline")
            .unwrap_err();
        join.join().unwrap();
        assert!(refused.contains("did not refresh"), "{refused}");
        drop(held);
        let until = Instant::now() + Duration::from_secs(5);
        while !plugin.inner.enter_lifecycle() {
            assert!(
                Instant::now() < until,
                "timed-out refresh releases lifecycle custody"
            );
            std::thread::yield_now();
        }
        plugin.inner.leave_lifecycle();
        assert!(
            Arc::ptr_eq(
                &prior,
                &plugin.inner.wake.exports.pin(Ticket::NONE).unwrap()
            ),
            "canceled admission never published a connection generation"
        );
        let applied = refresh_door_on(&plugin, &dispatcher, b"{}", b"{}", 2).unwrap();
        assert_eq!(
            applied.generation, 2,
            "canceled admission never crossed the plugin"
        );
    }
}

#[test]
fn served_refresh_keeps_active_result_custody_past_its_queue_deadline() {
    use crate::dispatch::kinds::plane::refresh_door_on;
    use crate::dispatch::{DispatchConfig, Dispatcher};
    use busbar_contract::abi::mechanism::call::{InHead, Op, RawOutcome};
    use busbar_contract::abi::mechanism::{lifecycle::slot, ticket::Ticket};
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::sync::{mpsc, LazyLock, Mutex};
    use std::time::{Duration, Instant};

    struct Crossing {
        actual: Op,
        entered: mpsc::Sender<u64>,
        release: mpsc::Receiver<()>,
    }
    static CROSSINGS: LazyLock<Mutex<HashMap<u64, Crossing>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));
    extern "C" fn held_refresh(
        instance: *mut c_void,
        input: *const c_void,
        output: *mut c_void,
    ) -> RawOutcome {
        // SAFETY: the validated lifecycle frame begins with the initialized host header.
        let head = unsafe { &*input.cast::<InHead>() };
        let crossing = CROSSINGS.lock().unwrap().remove(&head.host.handle).unwrap();
        // SAFETY: the actual product receives its live instance and the original checked frame.
        let outcome = unsafe { (crossing.actual)(instance, input, output) };
        crossing.entered.send(head.deadline_ns).unwrap();
        crossing
            .release
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        outcome
    }

    let mut config = DispatchConfig::default();
    config.budgets.lifecycle = Duration::from_secs(2);
    let dispatcher = Arc::new(Dispatcher::new(
        config,
        busbar_contract::services::test_caller_binding(),
    ));
    let mut validated = crate::dispatch::load::validate_door::<Plane>(crate::neutral_plane::door())
        .expect("the neutral SDK plane descriptor validates before wrapping REFRESH");
    let actual = validated.slots[slot::REFRESH as usize];
    validated.slots[slot::REFRESH as usize] = held_refresh;
    let plugin = Arc::new(
        Plugin::<Plane>::bind(validated, None, served_lifecycle_binding(&dispatcher)).unwrap(),
    );
    open_door(&plugin, b"{}", b"{}", None).unwrap();
    let (entered, crossing) = mpsc::channel();
    struct Release(Option<mpsc::Sender<()>>);
    impl Drop for Release {
        fn drop(&mut self) {
            if let Some(release) = self.0.take() {
                let _ = release.send(());
            }
        }
    }
    let (release, released) = mpsc::channel();
    let mut release = Release(Some(release));
    CROSSINGS.lock().unwrap().insert(
        plugin.inner.ctx().handle,
        Crossing {
            actual,
            entered,
            release: released,
        },
    );
    let held = plugin
        .inner
        .export_admission(slot::TICK, Ticket::NONE)
        .unwrap()
        .unwrap();
    let (sent, received) = mpsc::channel();
    let join = {
        let dispatcher = Arc::clone(&dispatcher);
        let plugin = Arc::clone(&plugin);
        std::thread::spawn(move || {
            sent.send(refresh_door_on(&plugin, &dispatcher, b"{}", b"{}", 2))
                .unwrap();
        })
    };
    let until = Instant::now() + Duration::from_secs(5);
    while plugin.inner.inflight() == 0 {
        assert!(Instant::now() < until, "refresh takes queued custody");
        std::thread::yield_now();
    }
    std::thread::sleep(Duration::from_secs(1));
    drop(held);
    let deadline = crossing.recv_timeout(Duration::from_secs(1)).unwrap();
    let release_at = deadline.saturating_add(100_000_000);
    std::thread::sleep(Duration::from_nanos(
        release_at.saturating_sub(crate::dispatch::now_ns()),
    ));
    // Queue time plus this legitimate crossing exceeds L; the active crossing itself
    // remains below L. An external Reply::wait(L) would already have abandoned it.
    assert!(
        matches!(received.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "an admitted refresh keeps result custody past the admission deadline"
    );
    release.0.take().unwrap().send(()).unwrap();
    let refreshed = received
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
        .unwrap();
    join.join().unwrap();
    assert_eq!(
        refreshed.generation, 2,
        "the actual publication is observed"
    );
    assert!(
        !plugin.is_faulted(),
        "the legitimate crossing stays within its own budget"
    );
}

#[test]
fn authenticated_route_pends_and_resumes_on_same_unit_and_caller_on_both_loading_paths() {
    use crate::dispatch::{in_head, out_head, DispatchConfig, Dispatcher, Frame};
    use busbar_contract::abi::{
        mechanism::call::{AbiStr, DeadlineClass, Outcome},
        plane::{self, AuthenticatedRouteIn, AuthenticatedRouteOut},
    };
    for dropped_image in [false, true] {
        let dispatcher = Arc::new(Dispatcher::new(
            DispatchConfig::default(),
            busbar_contract::services::test_caller_binding(),
        ));
        let plugin = Arc::new(served_lifecycle_plane(dropped_image, &dispatcher));
        open_door(&plugin, b"{}", b"{}", None).unwrap();
        let ticket = dispatcher.mint(0).unwrap();
        let entry = Arc::new(std::sync::Mutex::new(Box::new(
            [0u8; plane::MAX_ROUTE_ENTRY_BYTES],
        )));
        let entry_ptr = entry.lock().unwrap().as_mut_ptr();
        let input = AuthenticatedRouteIn {
            head: in_head(),
            unit: 42,
            caller_ref: AbiStr::over(b"verified-caller"),
            entry_buf: entry_ptr,
            entry_cap: plane::MAX_ROUTE_ENTRY_BYTES,
        };
        let out = AuthenticatedRouteOut {
            head: out_head(),
            ..busbar_contract::abi::sdk::door::blank_out()
        };
        let reply = dispatcher.submit_unit(
            &plugin,
            ticket,
            plane::slot::AUTHENTICATED_ROUTE,
            Frame::new(input, out),
            DeadlineClass::Call,
            0,
            entry.clone(),
        );
        let done = reply
            .wait(std::time::Duration::from_secs(5))
            .expect("bounded pending continuation");
        assert_eq!(done.outcome, Outcome::Ready, "dropped={dropped_image}");
        let out = done.frame.unwrap().out;
        assert_eq!(out.route, plane::ROUTE_DIRECT);
        assert_eq!(
            &entry.lock().unwrap()[..out.entry_written as usize],
            b"stored-entry"
        );
        assert!(
            plugin
                .inner
                .resumes
                .load(std::sync::atomic::Ordering::Relaxed)
                > 0
        );
        dispatcher.recycle(ticket);

        let ticket = dispatcher.mint(0).unwrap();
        let input = AuthenticatedRouteIn {
            head: in_head(),
            unit: 43,
            caller_ref: AbiStr::over(b"verified-caller"),
            entry_buf: entry_ptr,
            entry_cap: plane::MAX_ROUTE_ENTRY_BYTES,
        };
        let out = AuthenticatedRouteOut {
            head: out_head(),
            ..busbar_contract::abi::sdk::door::blank_out()
        };
        let reply = dispatcher.submit_unit(
            &plugin,
            ticket,
            plane::slot::AUTHENTICATED_ROUTE,
            Frame::new(input, out),
            DeadlineClass::Call,
            crate::dispatch::now_ns() + 20_000_000,
            entry.clone(),
        );
        let done = reply
            .wait(std::time::Duration::from_secs(5))
            .expect("bounded cancellation");
        assert_eq!(
            done.outcome,
            Outcome::Failed,
            "dropped={dropped_image}, disposition={:?}, error={:?}",
            done.disposition,
            done.error
        );
        assert_eq!(
            done.disposition,
            Some(plane::CANCEL_ABORTED),
            "the actual cancel must retain read-only authority on the FFI thread"
        );
        dispatcher.recycle(ticket);
    }
}
