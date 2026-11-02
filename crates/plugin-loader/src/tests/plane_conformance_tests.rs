// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::sign::{sign, Manifest, SigningKey, TrustPolicy};

fn plane_manifest(name: &str, alias: &str, publisher: &str) -> Manifest {
    Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: "plane".into(),
        version: "1.6.0".into(),
        publisher: publisher.into(),
        abi_version: busbar_contract::abi::plane::ABI_VERSION,
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
        statement: None,
        former_names: Vec::new(),
    }
}

fn first_party_only_policy(release: &SigningKey) -> TrustPolicy {
    TrustPolicy {
        first_party_key: Some(release.verifying_key()),
        binary_version: "1.6.0".into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
        ..TrustPolicy::default()
    }
}

fn plane_tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-plane-trust-{}-{tag}-{}",
        std::process::id(),
        crate::stage::next_seq()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_plane_tarball(dir: &std::path::Path, file: &str, m: &Manifest, lib: &[u8]) {
    let bytes = crate::tarball::package(m, "libplane.so", lib).unwrap();
    std::fs::write(dir.join(file), bytes).unwrap();
}

#[test]
fn a_plane_with_no_door_is_refused() {
    let release = SigningKey::from_bytes(&[1u8; 32]);
    let dir = plane_tmpdir("no-door");
    let m = sign(
        &release,
        plane_manifest("busbar-plane-gamma-plugin", "gamma", "busbar"),
        b"plane lib",
    );
    write_plane_tarball(&dir, "plane.tar.gz", &m, b"plane lib");

    let reg =
        crate::registry::scan_and_validate(&dir, &first_party_only_policy(&release)).expect("scan");
    let err = reg
        .open_planes(&[])
        .map(|_| ())
        .expect_err("a plane with no door is refused");
    assert!(
        err.contains("busbar-plane-gamma-plugin") && err.contains("busbar_plugin_door"),
        "the refusal names the plane and the door it lacks: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn plane_supported_abi_is_the_plane_kinds_one_version() {
    let range = crate::registry::supported_abi("plane");
    assert_eq!(range, &[busbar_contract::abi::plane::ABI_VERSION]);

    assert!(!crate::registry::supported_abi("store").is_empty());
    assert!(crate::registry::supported_abi("nonsense").is_empty());
}

mod door {
    use std::mem::zeroed;
    use std::sync::Arc;

    use busbar_contract::abi::hook::{SignalEntry, SIGNAL_TAG_U64};
    use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, Span, BLOB_OCTETS};
    use busbar_contract::abi::mechanism::door::Door;
    use busbar_contract::abi::mechanism::lifecycle::{
        slot as life, GenIn, OpenIn, OpenOut, RefreshIn, TickIn, TickOut, ValidateIn,
    };
    use busbar_contract::abi::plane::{
        self, slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneDriveIn,
        PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, PlaneSnapshot, ProjectIn,
        ProjectOut, RecordWrite, RefusalIn, RefusalOut, ServeIn, ServeOut, UnitCount,
        CANCEL_ABORTED, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END, FROM_KERNEL,
        MARK_GATE_REJECTED, PIECE_LAST, REFUSAL_GATE, UNITS_REPORTED, VERDICT_OK,
    };
    use busbar_contract::abi::sdk::door::{kind_op, Lifecycle, RawSlot};

    use crate::dispatch::kinds::plane::Plane;
    use crate::dispatch::{
        in_head, load_dropped, load_linked, out_head, rendering_of, Adopter, Bind, Frame,
        LinkedRow, NoSink, Plugin,
    };
    use crate::plane_door_plugin as plug;

    fn z<T>() -> T {
        // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
        unsafe { zeroed() }
    }

    fn bind() -> Bind {
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: Adopter::unwatched(),
            conns: crate::dispatch::ConnTable::NoNeeds,
        }
    }

    #[derive(Default)]
    struct ProjectScope {
        seen: std::sync::Mutex<Vec<(String, Option<u64>, String)>>,
    }

    impl crate::services_double::ServicesDouble for ProjectScope {
        fn entitlement_check(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            target: &str,
        ) -> crate::dispatch::Stored {
            self.seen
                .lock()
                .unwrap()
                .push((caller.instance.to_string(), unit, target.to_owned()));
            crate::dispatch::Stored::ready(busbar_contract::abi::host::service::ENTITLED)
        }
    }

    #[test]
    fn project_attributes_host_services_to_its_unit_linked_and_dropped() {
        use crate::dispatch::{DispatchConfig, Dispatcher};
        for is_dropped in [false, true] {
            let provider = Arc::new(crate::services_double::Double(ProjectScope::default()));
            let dispatcher = Dispatcher::with_services(DispatchConfig::default(), provider.clone());
            let binding = Bind {
                dispatcher: dispatcher.adopter(),
                ..bind()
            };
            let p = if is_dropped {
                let path = crate::both_ways::example_cdylib("plane_door_plugin");
                let stated = rendering_of(plug::door).unwrap();
                load_dropped::<Plane>(&path, &stated, binding).unwrap()
            } else {
                let row = LinkedRow::of(plug::door).unwrap();
                load_linked::<Plane>(&row, binding).unwrap()
            };
            assert_eq!(
                p.call(life::OPEN, &mut open_frame(1)).outcome,
                Outcome::Ready
            );
            for unit in [73, 0] {
                let (mut signals, mut arena) = ([z::<SignalEntry>(); 2], [0_u8; 64]);
                let mut frame: Frame<ProjectIn, ProjectOut> = Frame::new(z(), z());
                frame.input.head = in_head();
                frame.out.head = out_head();
                frame.input.unit = unit;
                frame.input.target = text(plug::PROJECT_ENTITLEMENT_TARGET);
                frame.input.body = octets(b"abc");
                frame.input.signals_buf = signals.as_mut_ptr();
                frame.input.signals_cap = signals.len();
                frame.input.arena_buf = arena.as_mut_ptr();
                frame.input.arena_cap = arena.len();

                assert_eq!(p.call(slot::PROJECT, &mut frame).outcome, Outcome::Ready);
            }
            assert_eq!(
                *provider.0.seen.lock().unwrap(),
                vec![
                    ("the-instance".into(), Some(73), "door:project-scope".into()),
                    ("the-instance".into(), None, "door:project-scope".into()),
                ],
                "dropped={is_dropped}"
            );
            let mut close: Frame<
                busbar_contract::abi::mechanism::call::InHead,
                busbar_contract::abi::mechanism::call::OutHead,
            > = Frame::new(in_head(), out_head());
            assert_eq!(p.call(life::CLOSE, &mut close).outcome, Outcome::Ready);
        }
    }

    fn octets(b: &'static [u8]) -> Blob {
        Blob {
            ptr: b.as_ptr(),
            len: b.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        }
    }

    fn text(b: &'static [u8]) -> AbiStr {
        AbiStr {
            ptr: b.as_ptr(),
            len: b.len(),
        }
    }

    fn at(buf: &[u8], offset: usize, len: usize) -> String {
        String::from_utf8_lossy(&buf[offset..offset + len]).into_owned()
    }

    fn arena(buf: &[u8], s: Span) -> String {
        at(buf, s.offset as usize, s.len as usize)
    }

    fn snapshot(p: *const PlaneSnapshot) -> String {
        assert!(!p.is_null(), "a READY open/refresh publishes a snapshot");
        // SAFETY: the plugin's generation data, valid until `retire` of its generation.
        let s = unsafe { &*p };
        // SAFETY: the snapshot names `claims_len` claims.
        let claim = unsafe { &*s.claims };
        // SAFETY: the claim's target is `'static` plugin text.
        let target = unsafe { std::slice::from_raw_parts(claim.target.ptr, claim.target.len) };
        format!(
            "gen={} claims={} target={} routes={}",
            s.generation,
            s.claims_len,
            String::from_utf8_lossy(target),
            s.admin_routes_len
        )
    }

    fn linked() -> Plugin<Plane> {
        let row = LinkedRow::of(plug::door).expect("the linked plane states its Statement");
        load_linked::<Plane>(&row, bind()).expect("the linked plane door loads")
    }

    fn dropped() -> Plugin<Plane> {
        let path = crate::both_ways::example_cdylib("plane_door_plugin");

        let stated = rendering_of(plug::door).expect("the plane renders its Statement");
        load_dropped::<Plane>(&path, &stated, bind()).expect("the dropped plane door loads")
    }

    fn open_frame(generation: u64) -> Frame<PlaneOpenIn, PlaneOpenOut> {
        let mut i: PlaneOpenIn = z();
        i.open.head = in_head();
        i.open.generation = generation;
        let mut o: PlaneOpenOut = z();
        o.open.head = out_head();
        Frame::new(i, o)
    }

    #[derive(Default)]
    struct PendingDriveServices {
        immediate: std::sync::atomic::AtomicBool,
        waiting: std::sync::Mutex<Vec<busbar_contract::services::Later>>,
        calls: std::sync::atomic::AtomicUsize,
        releases: std::sync::atomic::AtomicUsize,
    }

    impl crate::services_double::ServicesDouble for PendingDriveServices {
        fn records_get(
            &self,
            _: &busbar_contract::services::Caller,
            kind: &str,
            key: &[u8],
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            assert_eq!((kind, key), ("last", b"drive".as_slice()));
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.immediate.load(std::sync::atomic::Ordering::SeqCst) {
                return busbar_contract::services::Ran::Now(drive_completed());
            }
            self.waiting.lock().unwrap().push(later);
            busbar_contract::services::Ran::Later
        }

        fn entitlement_check(
            &self,
            _: &busbar_contract::services::Caller,
            _: Option<u64>,
            target: &str,
        ) -> crate::dispatch::Stored {
            assert_eq!(target, "door:drive-release");
            self.releases
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            crate::dispatch::Stored::ready(busbar_contract::abi::host::service::ENTITLED)
        }
    }

    fn pending_drive_plugin(
        dropped: bool,
        settings: &'static [u8],
    ) -> (
        crate::dispatch::Dispatcher,
        Plugin<Plane>,
        Arc<crate::services_double::Double<PendingDriveServices>>,
    ) {
        let services = Arc::new(crate::services_double::Double(
            PendingDriveServices::default(),
        ));
        let dispatcher = crate::dispatch::Dispatcher::with_services(
            crate::dispatch::DispatchConfig::default(),
            services.clone(),
        );
        let binding = Bind {
            dispatcher: dispatcher.adopter(),
            ..bind()
        };
        let plugin = if dropped {
            let path = crate::both_ways::example_cdylib("plane_door_plugin");
            load_dropped::<Plane>(&path, &rendering_of(plug::door).unwrap(), binding).unwrap()
        } else {
            load_linked::<Plane>(&LinkedRow::of(plug::door).unwrap(), binding).unwrap()
        };
        let mut open = open_frame(1);
        open.input.open.settings = octets(settings);
        assert_eq!(plugin.call(life::OPEN, &mut open).outcome, Outcome::Ready);
        (dispatcher, plugin, services)
    }

    fn drive_tick(
        dispatcher: &crate::dispatch::Dispatcher,
        plugin: &Plugin<Plane>,
        ticket: busbar_contract::abi::mechanism::ticket::Ticket,
        now_ns: u64,
    ) -> u64 {
        let mut frame: Frame<TickIn, TickOut> = Frame::new(z(), z());
        frame.input.head = in_head();
        frame.input.now_ns = now_ns;
        frame.out.head = out_head();
        let reply = dispatcher
            .submit(
                plugin,
                ticket,
                life::TICK,
                frame,
                busbar_contract::abi::mechanism::call::DeadlineClass::Call,
                0,
            )
            .wait(std::time::Duration::from_secs(5))
            .unwrap();
        assert_eq!(reply.outcome, Outcome::Ready);
        reply.frame.unwrap().out.next_tick_ns
    }

    fn drive_until(mut done: impl FnMut() -> bool) {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !done() {
            assert!(
                std::time::Instant::now() < end,
                "the driver did not make progress"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    fn drive_completed() -> crate::dispatch::Stored {
        let mut result = crate::dispatch::Stored::ready(busbar_contract::abi::host::service::FOUND);
        result.bytes = b"completed".to_vec();
        result
            .spans
            .push(busbar_contract::abi::host::service::ItemSpan {
                key: busbar_contract::abi::mechanism::call::Span::ZERO,
                value: busbar_contract::abi::mechanism::call::Span { offset: 0, len: 9 },
            });
        result
    }

    #[test]
    fn pending_drive_delivers_sessions_and_keeps_service_custody_linked_and_dropped() {
        use std::sync::atomic::Ordering::SeqCst;
        for dropped in [false, true] {
            let (dispatcher, plugin, services) = pending_drive_plugin(dropped, plug::PENDING_DRIVE);
            let driver = dispatcher.driver(&plugin, 0).unwrap();
            let mut piece = Piece::new();
            assert_eq!(
                piece.call(&plugin, FROM_CALLER, b"hi", (0, b"")).0,
                Outcome::Ready
            );
            crate::dispatch::ticket::host_wake(plugin.inner.ctx(), driver);
            drive_until(|| plugin.inner.driven.answers() == 1);
            drive_tick(&dispatcher, &plugin, driver, 0);
            assert_eq!(plugin.inner.driven.drain(), vec![5], "dropped={dropped}");
            assert_eq!(dispatcher.services().held.held(driver), 1);
            assert_eq!(dispatcher.services().held(), 1);
            assert_eq!(services.0.releases.load(SeqCst), 1);

            crate::dispatch::ticket::host_wake(plugin.inner.ctx(), driver);
            drive_until(|| plugin.inner.driven.answers() == 2);
            assert_eq!(
                drive_tick(&dispatcher, &plugin, driver, plug::DRIVE_RESUMES),
                1
            );
            assert!(plugin.inner.driven.drain().is_empty());
            assert_eq!(services.0.calls.load(SeqCst), 1);
            assert_eq!(services.0.releases.load(SeqCst), 2);
            assert_eq!(dispatcher.services().held.held(driver), 1);

            assert_eq!(
                piece.call(&plugin, FROM_CALLER, b"hi", (0, b"")).0,
                Outcome::Ready
            );
            let later = services.0.waiting.lock().unwrap().pop().unwrap();
            later(drive_completed());
            assert_eq!(
                plugin
                    .inner
                    .driven
                    .answered_after(2, std::time::Duration::from_secs(5)),
                Some(Outcome::Ready)
            );
            drive_tick(&dispatcher, &plugin, driver, plug::DRIVE_RESTART);
            assert_eq!(plugin.inner.driven.drain(), vec![5]);
            assert_eq!(dispatcher.services().held.held(driver), 0);
            assert_eq!(dispatcher.services().held(), 0);
            assert_eq!(services.0.releases.load(SeqCst), 3);

            let session = dispatcher.mint(0).unwrap();
            let mut frame: Frame<OnPieceIn, OnPieceOut> = Frame::new(z(), z());
            frame.input.head = in_head();
            frame.input.from = FROM_CALLER;
            frame.input.stream = 5;
            frame.input.bytes = octets(b"pending-session");
            frame.out.head = out_head();
            let reply = dispatcher.submit(
                &plugin,
                session,
                slot::ON_PIECE,
                frame,
                busbar_contract::abi::mechanism::call::DeadlineClass::Call,
                0,
            );
            drive_until(|| dispatcher.is_pending(session));
            dispatcher.drop_client(session);
            let cancelled = reply.wait(std::time::Duration::from_secs(5)).unwrap();
            assert_eq!(cancelled.disposition, Some(CANCEL_ABORTED));
            dispatcher.recycle(session);

            crate::dispatch::ticket::host_wake(plugin.inner.ctx(), driver);
            drive_until(|| plugin.inner.driven.answers() == 4);
            drive_tick(&dispatcher, &plugin, driver, 0);
            assert_eq!(services.0.calls.load(SeqCst), 2);
            assert_eq!(services.0.releases.load(SeqCst), 4);
            assert!(plugin.inner.driven.drain().is_empty());
            let late = services.0.waiting.lock().unwrap().pop().unwrap();
            dispatcher.recycle(driver);
            let barrier = dispatcher.mint(0).unwrap();
            drive_tick(&dispatcher, &plugin, barrier, 0);
            assert_eq!(dispatcher.services().held(), 0);
            assert_eq!(dispatcher.services().held.held(driver), 0);
            late(drive_completed());
            drive_tick(&dispatcher, &plugin, barrier, 0);
            assert_eq!(plugin.inner.driven.answers(), 4);
            assert!(plugin.inner.driven.drain().is_empty());
            dispatcher.recycle(barrier);
        }
    }

    #[test]
    fn malformed_pending_drive_is_fault_and_releases_its_answer_linked_and_dropped() {
        use std::sync::atomic::Ordering::SeqCst;
        for dropped in [false, true] {
            for settings in [plug::PENDING_DRIVE_OVER_CAP, plug::PENDING_DRIVE_NEEDED] {
                let (dispatcher, plugin, services) = pending_drive_plugin(dropped, settings);
                let driver = dispatcher.driver(&plugin, 0).unwrap();
                let mut piece = Piece::new();
                assert_eq!(
                    piece.call(&plugin, FROM_CALLER, b"hi", (0, b"")).0,
                    Outcome::Ready
                );
                crate::dispatch::ticket::host_wake(plugin.inner.ctx(), driver);
                assert_eq!(
                    plugin
                        .inner
                        .driven
                        .answered_after(0, std::time::Duration::from_secs(5)),
                    Some(Outcome::Fault)
                );
                drive_until(|| services.0.releases.load(SeqCst) == 1);
                assert!(plugin.inner.driven.drain().is_empty());
                assert_eq!(services.0.calls.load(SeqCst), 1);
                dispatcher.recycle(driver);
            }
        }
    }

    #[test]
    fn completed_result_ack_is_checked_and_confirmed_before_lease_release_linked_and_dropped() {
        use std::sync::atomic::Ordering::SeqCst;
        for dropped in [false, true] {
            for settings in [plug::ACK_PENDING, plug::ACK_READY] {
                let (dispatcher, plugin, services) = pending_drive_plugin(dropped, settings);
                services.0.immediate.store(true, SeqCst);
                let driver = dispatcher.driver(&plugin, 0).unwrap();
                crate::dispatch::ticket::host_wake(plugin.inner.ctx(), driver);

                drive_until(|| {
                    plugin.inner.driven.answers() == 2 && services.0.releases.load(SeqCst) == 2
                });
                assert_eq!(
                    plugin
                        .inner
                        .driven
                        .answered_after(1, std::time::Duration::from_secs(5)),
                    Some(Outcome::Ready)
                );
                assert_eq!(services.0.calls.load(SeqCst), 1);
                assert_eq!(dispatcher.services().held(), 0);
                assert_eq!(dispatcher.services().held.held(driver), 0);
                dispatcher.recycle(driver);
            }
        }
    }

    #[test]
    fn rejected_main_answers_never_consume_completed_result_custody_linked_and_dropped() {
        use std::sync::atomic::Ordering::SeqCst;
        for dropped in [false, true] {
            for settings in [
                plug::ACK_FAILED,
                plug::ACK_SHORT,
                plug::ACK_MALFORMED,
                plug::ACK_WRONG_OWNER,
                plug::ACK_WRONG_NONCE,
            ] {
                let (dispatcher, plugin, services) = pending_drive_plugin(dropped, settings);
                services.0.immediate.store(true, SeqCst);
                let driver = dispatcher.driver(&plugin, 0).unwrap();
                crate::dispatch::ticket::host_wake(plugin.inner.ctx(), driver);
                assert_eq!(
                    plugin
                        .inner
                        .driven
                        .answered_after(0, std::time::Duration::from_secs(5)),
                    Some(Outcome::Fault),
                    "{settings:?}, dropped={dropped}"
                );
                drive_until(|| services.0.releases.load(SeqCst) == 1);
                assert_eq!(
                    dispatcher.services().held(),
                    1,
                    "rejected ACK preserves the original result"
                );
                assert_eq!(services.0.calls.load(SeqCst), 1);
                assert!(plugin.inner.driven.drain().is_empty());
                dispatcher.recycle(driver);
            }
        }
    }

    #[test]
    fn cancel_cannot_ack_a_drivers_result_linked_and_dropped() {
        use std::sync::atomic::Ordering::SeqCst;
        for dropped in [false, true] {
            let (dispatcher, plugin, services) = pending_drive_plugin(dropped, plug::ACK_CANCEL);
            services.0.immediate.store(true, SeqCst);
            let driver = dispatcher.driver(&plugin, 0).unwrap();
            crate::dispatch::ticket::host_wake(plugin.inner.ctx(), driver);
            drive_until(|| {
                plugin.inner.driven.answers() == 1 && services.0.releases.load(SeqCst) == 1
            });
            assert_eq!(dispatcher.services().held(), 1);
            let session = dispatcher.mint(0).unwrap();
            let mut frame: Frame<OnPieceIn, OnPieceOut> = Frame::new(z(), z());
            frame.input.head = in_head();
            frame.out.head = out_head();
            frame.input.from = FROM_CALLER;
            frame.input.stream = 5;
            frame.input.bytes = octets(b"pending-session");
            let reply = dispatcher.submit(
                &plugin,
                session,
                slot::ON_PIECE,
                frame,
                busbar_contract::abi::mechanism::call::DeadlineClass::Call,
                0,
            );
            drive_until(|| dispatcher.is_pending(session));
            dispatcher.drop_client(session);
            assert_eq!(
                reply
                    .wait(std::time::Duration::from_secs(5))
                    .unwrap()
                    .outcome,
                Outcome::Fault
            );
            drive_until(|| services.0.releases.load(SeqCst) == 2);
            assert_eq!(dispatcher.services().held(), 1);
            dispatcher.recycle(session);
            dispatcher.recycle(driver);
        }
    }

    struct Piece {
        reply: [u8; 64],
        units: [UnitCount; 2],
        records: [RecordWrite; 2],
        fields: [OutField; 2],
        arena: [u8; 64],
    }

    impl Piece {
        fn new() -> Box<Self> {
            Box::new(Self {
                reply: [0; 64],
                units: [z(); 2],
                records: [z(); 2],
                fields: [z(); 2],
                arena: [0; 64],
            })
        }

        fn call(
            &mut self,
            p: &Plugin<Plane>,
            from: u32,
            bytes: &'static [u8],
            attempt: (u32, &'static [u8]),
        ) -> (Outcome, OnPieceOut) {
            let mut i: OnPieceIn = z();
            i.head = in_head();
            i.from = from;
            i.flags = PIECE_LAST;
            i.stream = 5;
            i.bytes = octets(bytes);
            (i.reply_buf, i.reply_cap) = (self.reply.as_mut_ptr(), self.reply.len());
            (i.units_buf, i.units_cap) = (self.units.as_mut_ptr(), self.units.len());
            (i.records_buf, i.records_cap) = (self.records.as_mut_ptr(), self.records.len());
            (i.fields_buf, i.fields_cap) = (self.fields.as_mut_ptr(), self.fields.len());
            (i.arena_buf, i.arena_cap) = (self.arena.as_mut_ptr(), self.arena.len());
            (i.attempt_no, i.member) = (attempt.0, text(attempt.1));
            let mut o: OnPieceOut = z();
            o.head = out_head();
            let mut f = Frame::new(i, o);
            let c = p.call(slot::ON_PIECE, &mut f);
            (c.outcome, f.out)
        }
    }

    fn script(p: &Plugin<Plane>) -> Vec<String> {
        let mut t = Vec::new();

        let mut v = Frame::new(
            ValidateIn {
                head: in_head(),
                settings: octets(plug::BAD_SETTINGS),
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            },
            out_head(),
        );
        t.push(format!(
            "validate bad {:?}",
            p.call(life::VALIDATE, &mut v).outcome
        ));
        v.input.settings = octets(b"{}");
        t.push(format!(
            "validate {:?}",
            p.call(life::VALIDATE, &mut v).outcome
        ));

        let mut o = open_frame(1);
        let c = p.call(life::OPEN, &mut o);
        t.push(format!("open {:?} {}", c.outcome, snapshot(o.out.snapshot)));

        for s in [slot::HYDRATE, slot::START] {
            let mut g = Frame::new(
                GenIn {
                    head: in_head(),
                    generation: 1,
                },
                out_head(),
            );
            t.push(format!("{s} {:?}", p.call(s, &mut g).outcome));
        }

        let mut units = [z::<UnitCount>(); 2];
        let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(z(), z());
        (a.input.head, a.out.head) = (in_head(), out_head());
        a.input.body = octets(b"hello");
        (a.input.units_buf, a.input.units_cap) = (units.as_mut_ptr(), units.len());
        let c = p.call(slot::ARRIVE, &mut a);
        t.push(format!(
            "arrive {:?} units={} amount={} op_class={}",
            c.outcome, a.out.units_written, units[0].amount, a.out.op_class
        ));
        a.input.units_cap = 0;
        let c = p.call(slot::ARRIVE, &mut a);
        t.push(format!(
            "arrive short {:?} needed={} recall={}",
            c.outcome,
            a.out.units_needed,
            c.recall.is_some()
        ));

        let mut piece = Piece::new();
        let (c, _) = piece.call(p, FROM_CALLER, b"hi", (0, b""));
        t.push(format!("on_piece caller {c:?}"));
        let mut sessions = [0_u64; 4];
        let mut d: Frame<PlaneDriveIn, PlaneDriveOut> = Frame::new(z(), z());
        (d.input.drive.head, d.out.head) = (in_head(), out_head());
        (d.input.sessions_buf, d.input.sessions_cap) = (sessions.as_mut_ptr(), sessions.len());
        let c = p.call(life::DRIVE, &mut d);
        t.push(format!(
            "drive {:?} sessions={} first={}",
            c.outcome, d.out.sessions_written, sessions[0]
        ));
        let (c, out) = piece.call(p, FROM_KERNEL, b"", (0, b""));
        t.push(format!(
            "on_piece session {c:?} {}",
            at(&piece.reply, 0, out.emitted as usize)
        ));

        let (c, out) = piece.call(p, FROM_KERNEL, b"", (1, b"m1"));
        t.push(format!(
            "on_piece attempt {c:?} {} {} {} to_far_end={}",
            arena(&piece.arena, out.verb),
            arena(&piece.arena, out.target),
            at(&piece.reply, 0, out.emitted as usize),
            out.flags & EMIT_TO_FAR_END != 0
        ));

        let (c, out) = piece.call(p, FROM_FAR_END, b"answer", (0, b""));
        t.push(format!(
            "on_piece far_end {c:?} {} status={} done={} verdict_ok={} units={}:{}:{} \
             record={}={} field={}={}",
            at(&piece.reply, 0, out.emitted as usize),
            out.reply_status,
            out.flags & EMIT_DONE != 0,
            out.verdict == VERDICT_OK,
            out.units_written,
            piece.units[0].amount,
            piece.units[0].source == UNITS_REPORTED,
            arena(&piece.arena, piece.records[0].key),
            arena(&piece.arena, piece.records[0].value),
            arena(&piece.arena, piece.fields[0].name),
            arena(&piece.arena, piece.fields[0].value),
        ));

        let (mut reply, mut fields, mut buf) = ([0_u8; 16], [z::<OutField>(); 1], [0_u8; 32]);
        let mut r: Frame<RefusalIn, RefusalOut> = Frame::new(z(), z());
        (r.input.head, r.out.head) = (in_head(), out_head());
        (r.input.cause, r.input.status, r.input.text) = (REFUSAL_GATE, 403, text(b"denied"));
        (r.input.reply_buf, r.input.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (r.input.fields_buf, r.input.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (r.input.arena_buf, r.input.arena_cap) = (buf.as_mut_ptr(), buf.len());
        let c = p.call(slot::REFUSAL, &mut r);
        t.push(format!(
            "refusal {:?} {} gate={} field={}",
            c.outcome,
            at(&reply, 0, r.out.reply_written as usize),
            r.out.marker == MARK_GATE_REJECTED,
            arena(&buf, fields[0].name)
        ));

        let mut reply = [0_u8; 16];
        let mut s: Frame<ServeIn, ServeOut> = Frame::new(z(), z());
        (s.input.head, s.out.head) = (in_head(), out_head());
        (s.input.reply_buf, s.input.reply_cap) = (reply.as_mut_ptr(), reply.len());
        let c = p.call(slot::SERVE, &mut s);
        t.push(format!(
            "serve {:?} {} {}",
            c.outcome,
            s.out.status,
            at(&reply, 0, s.out.reply_written as usize)
        ));

        let (mut signals, mut buf) = ([z::<SignalEntry>(); 2], [0_u8; 32]);
        let mut j: Frame<ProjectIn, ProjectOut> = Frame::new(z(), z());
        (j.input.head, j.out.head) = (in_head(), out_head());
        j.input.body = octets(b"abc");
        (j.input.signals_buf, j.input.signals_cap) = (signals.as_mut_ptr(), signals.len());
        (j.input.arena_buf, j.input.arena_cap) = (buf.as_mut_ptr(), buf.len());
        let c = p.call(slot::PROJECT, &mut j);
        // SAFETY: the signal's tag is checked to name `u64_` first.
        let value = (signals[0].tag == SIGNAL_TAG_U64).then(|| unsafe { signals[0].value.u64_ });
        t.push(format!(
            "project {:?} signals={} value={value:?} body={}",
            c.outcome,
            j.out.view.signals_len,
            arena(&buf, j.out.body)
        ));

        let mut k = Frame::new(
            TickIn {
                head: in_head(),
                now_ns: 1_000,
            },
            TickOut {
                head: out_head(),
                next_tick_ns: 0,
            },
        );
        let c = p.call(life::TICK, &mut k);
        t.push(format!("tick {:?} next={}", c.outcome, k.out.next_tick_ns));

        let mut x: Frame<
            busbar_contract::abi::plane::PlaneCancelIn,
            busbar_contract::abi::plane::PlaneCancelOut,
        > = Frame::new(z(), z());
        (x.input.cancel.head, x.out.cancel.head) = (in_head(), out_head());
        let c = p.call(life::CANCEL, &mut x);
        t.push(format!(
            "cancel {:?} aborted={}",
            c.outcome,
            x.out.cancel.disposition == CANCEL_ABORTED
        ));

        let mut f: Frame<RefreshIn, PlaneRefreshOut> = Frame::new(z(), z());
        (f.input.head, f.out.head) = (in_head(), out_head());
        f.input.generation = 2;
        let c = p.call(life::REFRESH, &mut f);
        t.push(format!(
            "refresh {:?} {}",
            c.outcome,
            snapshot(f.out.snapshot)
        ));

        let mut g = Frame::new(
            GenIn {
                head: in_head(),
                generation: 1,
            },
            out_head(),
        );
        t.push(format!("retire {:?}", p.call(life::RETIRE, &mut g).outcome));
        let mut e = Frame::new(in_head(), out_head());
        t.push(format!("close {:?}", p.call(life::CLOSE, &mut e).outcome));
        t
    }

    #[test]
    fn repeated_plane_loads_reuse_owned_static_words_after_the_image_is_released() {
        for make in [linked as fn() -> Plugin<Plane>, dropped] {
            let first = make();
            let a = first.served();
            let declared = first.declared();
            drop(first);
            let second = make();
            let b = second.served();
            assert_eq!(a.section, b.section);
            assert_eq!(a.op_classes, b.op_classes);
            assert!(
                std::ptr::eq(a.section, b.section),
                "same declaration has one permanent word copy"
            );
            assert!(std::ptr::eq(a.op_classes[0], b.op_classes[0]));
            assert!(std::ptr::eq(
                declared.record_kinds[0],
                second.declared().record_kinds[0]
            ));
            drop(second);
            assert_eq!(a.section, "door");
            assert_eq!(a.op_classes, vec!["echo"]);
            assert_eq!(declared.record_kinds, vec!["last"]);
        }
    }

    const EXPECTED: &[&str] = &[
        "validate bad Refused",
        "validate Ready",
        "open Ready gen=1 claims=1 target=/echo routes=0",
        "13 Ready",
        "14 Ready",
        "arrive Ready units=1 amount=5 op_class=0",
        "arrive short Failed needed=1 recall=true",
        "on_piece caller Ready",
        "drive Ready sessions=1 first=5",
        "on_piece session Ready ping",
        "on_piece attempt Ready POST /up m1 to_far_end=true",
        "on_piece far_end Ready answer status=200 done=true verdict_ok=true units=1:6:true \
         record=k=v field=x-plane=door",
        "refusal Ready denied gate=false field=x-refusal",
        "serve Ready 200 ok",
        "project Ready signals=1 value=Some(3) body=abc",
        "tick Ready next=1001000",
        "cancel Ready aborted=true",
        "refresh Ready gen=2 claims=1 target=/echo routes=1",
        "retire Ready",
        "close Ready",
    ];

    #[test]
    fn a_macro_built_plane_answers_every_op_the_same_linked_and_dropped() {
        let linked = script(&linked());
        assert_eq!(linked, EXPECTED, "the linked plane door");
        assert_eq!(script(&dropped()), linked, "the dropped plane door");
    }

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
            let d = plug::door();
            (d, *d.ops().cast::<plane::Ops>())
        };
        let mut ops = ops;
        ops.head.open = kind_op::<Lifecycle, LifecycleOpen, TestCapture, { life::OPEN }>();
        ops.head.close = kind_op::<Lifecycle, LifecycleClose, TestCapture, { life::CLOSE }>();
        let ops: &'static plane::Ops = Box::leak(Box::new(ops));
        Box::leak(Box::new(unsafe {
            Door::__from_parts(busbar_contract::abi::mechanism::door::DoorParts {
                ops: std::ptr::from_ref(ops).cast(),
                ..d.parts()
            })
        }))
    }

    #[test]
    fn red_a_plane_open_over_the_lifecycle_structs_publishes_no_snapshot_and_faults() {
        let row = LinkedRow::of_raw(lifecycle_open_door).expect("the door states its Statement");
        let red = load_linked::<Plane>(&row, bind()).expect("the door loads");
        let mut o = open_frame(1);
        assert_eq!(red.call(life::OPEN, &mut o).outcome, Outcome::Fault);
        assert!(o.out.snapshot.is_null(), "no snapshot reached the host");
        assert_eq!(
            LIFECYCLE_CLOSES.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the host closed the instance its FAULTed open left the plugin holding"
        );
        assert!(!red.is_open());

        let green = linked();
        let mut o = open_frame(1);
        assert_eq!(green.call(life::OPEN, &mut o).outcome, Outcome::Ready);
        assert!(!o.out.snapshot.is_null());
        let mut e = Frame::new(in_head(), out_head());
        assert_eq!(green.call(life::CLOSE, &mut e).outcome, Outcome::Ready);
    }

    #[test]
    fn red_the_hosts_snapshot_copy_survives_the_plugins_next_refresh() {
        for p in [linked(), dropped()] {
            let mut o = open_frame(1);
            let (c, first) = p.open(&mut o);
            assert_eq!(c.outcome, Outcome::Ready);
            let first = first.expect("a READY open's snapshot is copied");
            let published = first.clone();
            assert_eq!(first.generation, 1);
            assert_eq!(first.claims.len(), 1);
            assert_eq!(first.claims[0].target, "/echo");
            assert!(first.admin_routes.is_empty());

            let mut r: Frame<RefreshIn, PlaneRefreshOut> = Frame::new(z(), z());
            (r.input.head, r.out.head) = (in_head(), out_head());
            r.input.generation = 2;
            let (c, second) = p.refresh(&mut r);
            assert_eq!(c.outcome, Outcome::Ready);
            let second = second.expect("a READY refresh's snapshot is copied");
            assert_eq!((second.generation, second.admin_routes.len()), (2, 1));

            let mut g = Frame::new(
                GenIn {
                    head: in_head(),
                    generation: 1,
                },
                out_head(),
            );
            assert_eq!(p.call(life::RETIRE, &mut g).outcome, Outcome::Ready);
            assert_eq!(first, published, "generation 1's copy outlives its retire");
        }
    }

    #[test]
    fn facing_replaces_old_open_inputs_and_closes_its_last_probe() {
        for make in [linked as fn() -> Plugin<Plane>, dropped] {
            let held = Arc::new(std::sync::Mutex::new(Vec::new()));
            let observed = Arc::clone(&held);
            let bind = Arc::new(move || {
                let p = make();
                observed.lock().unwrap().push(Arc::clone(&p.inner));
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
                "same inputs refresh the existing probe"
            );
            (reg.facing)(b"{}", b"{}", Some("https://two.example"), &[]).unwrap();
            assert!(
                !held.lock().unwrap()[1].is_open(),
                "superseded input was closed"
            );
            (reg.facing)(b"{}", b"", Some("https://one.example"), &[]).unwrap();
            assert!(
                !held.lock().unwrap()[2].is_open(),
                "the second input was closed"
            );
            assert_eq!(first, first_copy, "owned facing survives its probe close");
            let last = Arc::clone(&reg.facing);
            drop(reg);
            assert!(
                held.lock().unwrap()[3].is_open(),
                "a facing owner still exists"
            );
            drop(last);
            assert!(
                held.lock().unwrap().iter().all(|p| !p.is_open()),
                "last owner closes its probe"
            );
        }
    }

    #[test]
    fn a_door_states_its_registry_facts_and_judges_its_section() {
        let check = |bind: crate::dispatch::kinds::plane::ProbeBind| {
            let reg = crate::dispatch::kinds::plane::registration(bind).expect("the door binds");
            assert_eq!(reg.key, "plane-door");
            assert_eq!(reg.section, "door");
            assert_eq!(
                (reg.label, reg.subject_noun, reg.admin_noun, reg.audit_kind),
                ("Door", "door", "door", "door")
            );
            assert_eq!(reg.dialects, vec!["door/1"]);
            assert_eq!(reg.billable_classes, vec![("bytes", "bytes")]);
            assert_eq!(reg.record_kinds, vec!["last"]);
            assert!(reg.scope_kinds.is_empty() && reg.trust_keys.is_empty());
            assert_eq!(reg.signing, None);
            assert_eq!(reg.caller_credential_refusal, None);
            assert_eq!((reg.validate)(b"{}"), Ok(()));
            assert!(
                (reg.validate)(plug::BAD_SETTINGS).is_err(),
                "the door refuses its bad settings"
            );
            let faced = (reg.facing)(b"{}", b"", None, &[]).expect("the door faces the world");
            assert_eq!(faced.claims, vec![("/echo".to_string(), "door/1")]);
            assert_eq!(faced.admission, None, "the fixture binds no audience");
            assert_eq!(
                faced.listed,
                vec![plug::LISTED.to_string()],
                "the names its snapshot lists cross to the host"
            );
            let again =
                (reg.facing)(b"{}", b"", None, &[]).expect("a probe closes, so it opens again");
            assert_eq!(again, faced);
            format!("{reg:?}")
        };
        let linked = check(Arc::new(|| Ok(linked())));
        let dropped = check(Arc::new(|| Ok(dropped())));
        assert_eq!(linked, dropped, "the same facts, whichever door");
    }
}
