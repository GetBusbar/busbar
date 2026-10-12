// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PUBLISHED CONFORMANCE SUITE, run over this plane (TODO ABI-b4; OWNER 2026-10-03: plugins
//! test themselves against busbar's published suite). The linked door (`plane_door::door`) and
//! this crate's dropped-in image (the `decisions_door` example `cdylib`, which `cargo test --test
//! conformance` does not build: build it first with `cargo build -p busbar-plane-decisions
//! --example decisions_door`), each through the one loader, driven by busbar-plugin-loader's plane
//! script over `conformance.json`, every step at its pinned crossing count, the two folds equal.
//! This is the plugin's own both-ways witness at the path every plugin repo keeps it
//! (`tests/conformance.rs`, the file kind-isolation's witness grant names), so the plane repo
//! (GetBusbar/busbar-plane-decisions) takes it as it is once the plane is extracted.

busbar_plugin_loader::conformance_suite! {
    door: busbar_plane_decisions::plane_door::door,
    cdylib: "decisions_door",
    inputs: include_str!("conformance.json"),
}

/// THE DOOR'S UNITS, through the one loader over the linked door: the Q128 plane-decisions cells
/// (findings 1 to 7 and the MEDIUM). They live in this file because it is the plane's one loader
/// witness (kind-isolation grants the loader dev-edge to `tests/conformance.rs` alone); the plane
/// repo keeps them as `plane-decisions-plugin/tests/units.rs`.
mod units {
    //! THE DOOR'S PER-UNIT STATE, driven through busbar's one loader over the linked door (Q128
    //! plane-decisions findings 6 and 8):
    //!
    //! * a unit's state is dropped when the unit ends by a refusal or a cancel, not only at its last
    //!   piece, so refused and cancelled traffic never fills the instance;
    //! * at `MAX_UNITS` live units a NEW unit is refused (`AT_CAPACITY`, 429) and no live unit is
    //!   evicted, so a unit in flight keeps its request and its count;
    //! * the far end's answer is held to its last piece and relayed whole: nothing reaches the caller
    //!   before the answer can be billed.

    use busbar_contract::abi::mechanism::call::{
        AbiStr, Blob, DeadlineClass, Outcome, Span, BLOB_OCTETS,
    };
    use busbar_contract::abi::mechanism::lifecycle::slot as life;
    use busbar_contract::abi::mechanism::ticket::Ticket;
    use busbar_contract::abi::plane::{
        slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneCancelIn, PlaneCancelOut,
        PlaneOpenIn, PlaneOpenOut, RefusalIn, RefusalOut, UnitCount, EMIT_DONE, EMIT_TO_FAR_END,
        FROM_CALLER, FROM_FAR_END, FROM_KERNEL, PIECE_HAS_STATUS, PIECE_LAST, REFUSAL_GATE,
    };
    use busbar_plane_decisions::plane_door::{
        door, AT_CAPACITY, MAX_UNITS, NO_MODEL_NAMED, UNKNOWN_MODEL,
    };
    use busbar_plugin_loader::conformance::{dispatcher, input, json, load, output, Leg, Subject};
    use busbar_plugin_loader::dispatch::kinds::plane::Plane;
    use busbar_plugin_loader::dispatch::{Dispatcher, Frame, Plugin};

    /// The section every instance here opens over: one model.
    const SETTINGS: &[u8] = br#"{"models":{"jev":{"provider":"typesafe","protocol":"jev"}}}"#;

    /// A caller's request body.
    const REQUEST: &[u8] = br#"{"state":{"session":"s"},"context":{}}"#;

    /// A far end's success answer.
    const ANSWER: &[u8] = br#"{"request_id":"req_1","usage":{"units":42},"answers":{}}"#;

    fn abi(b: &[u8]) -> AbiStr {
        AbiStr {
            ptr: b.as_ptr(),
            len: b.len(),
        }
    }

    fn octets(b: &[u8]) -> Blob {
        Blob {
            ptr: b.as_ptr(),
            len: b.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        }
    }

    /// The linked door, opened over [`SETTINGS`], on a dispatcher of its own.
    fn opened() -> (std::sync::Arc<Dispatcher>, Plugin<Plane>) {
        opened_over(SETTINGS)
    }

    /// The linked door, opened over `settings`.
    fn opened_over(settings: &[u8]) -> (std::sync::Arc<Dispatcher>, Plugin<Plane>) {
        let s = Subject::new(door, "decisions_door", include_str!("conformance.json"));
        let d = dispatcher();
        let p = load::<Plane>(&s, Leg::Linked, s.bind(&d, "plane")).expect("the door loads");
        let mut f: Frame<PlaneOpenIn, PlaneOpenOut> = Frame::new(input(), output());
        (f.input.open.generation, f.input.open.settings) = (1, json(settings));
        let (called, _) = p.open(&mut f);
        assert_eq!(called.outcome, Outcome::Ready, "the door opens");
        (d, p)
    }

    /// `arrive` of `unit` on `POST /v1/systemone`: its outcome, refusal code and status.
    fn arrive(p: &Plugin<Plane>, unit: u64) -> (Outcome, u32, u32) {
        arrive_with(p, unit, REQUEST)
    }

    /// `arrive` of `unit` carrying `body`.
    fn arrive_with(p: &Plugin<Plane>, unit: u64, body: &[u8]) -> (Outcome, u32, u32) {
        arrive_at(p, unit, b"/v1/systemone", body).0
    }

    /// `arrive` of `unit` on `POST <target>` carrying `body`: its outcome, refusal code and status,
    /// and the dialect it answered.
    fn arrive_at(
        p: &Plugin<Plane>,
        unit: u64,
        target: &[u8],
        body: &[u8],
    ) -> ((Outcome, u32, u32), u32) {
        let mut units = [UnitCount {
            class: 0,
            source: 0,
            amount: 0,
        }; 4];
        let mut f: Frame<ArriveIn, ArriveOut> = Frame::new(input(), output());
        f.input.unit = unit;
        (f.input.method, f.input.target) = (abi(b"POST"), abi(target));
        f.input.body = octets(body);
        (f.input.units_buf, f.input.units_cap) = (units.as_mut_ptr(), units.len());
        let c = p.call(slot::ARRIVE, &mut f);
        (
            (c.outcome, f.out.refusal, f.out.refusal_status),
            f.out.dialect,
        )
    }

    /// `refusal` of `unit`: the kernel refused it (a gate, a limit), and the unit ends.
    fn refuse(p: &Plugin<Plane>, unit: u64) {
        let (mut reply, mut arena) = ([0_u8; 512], [0_u8; 256]);
        let mut fields = [OutField {
            name: Span { offset: 0, len: 0 },
            value: Span { offset: 0, len: 0 },
        }; 2];
        let mut f: Frame<RefusalIn, RefusalOut> = Frame::new(input(), output());
        (f.input.cause, f.input.status, f.input.text) = (REFUSAL_GATE, 429, abi(b"limited"));
        f.input.unit = unit;
        (f.input.reply_buf, f.input.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (f.input.fields_buf, f.input.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (f.input.arena_buf, f.input.arena_cap) = (arena.as_mut_ptr(), arena.len());
        assert_eq!(p.call(slot::REFUSAL, &mut f).outcome, Outcome::Ready);
    }

    /// `cancel` of the op on `ticket`.
    fn cancel(p: &Plugin<Plane>, ticket: Ticket) {
        let mut f: Frame<PlaneCancelIn, PlaneCancelOut> = Frame::new(input(), output());
        f.input.cancel.ticket = ticket;
        assert_eq!(p.call(life::CANCEL, &mut f).outcome, Outcome::Ready);
    }

    /// The host's buffers for one piece.
    struct Bufs {
        reply: Vec<u8>,
        units: Vec<UnitCount>,
        fields: Vec<OutField>,
        arena: Vec<u8>,
    }

    /// What one piece answered.
    #[derive(Debug)]
    struct Answered {
        outcome: Outcome,
        emitted: Vec<u8>,
        flags: u32,
        status: u32,
        units: Vec<(u32, u64)>,
    }

    impl Bufs {
        fn new() -> Self {
            let span = Span { offset: 0, len: 0 };
            Self {
                reply: vec![0; 4096],
                units: vec![
                    UnitCount {
                        class: 0,
                        source: 0,
                        amount: 0
                    };
                    8
                ],
                fields: vec![
                    OutField {
                        name: span,
                        value: span
                    };
                    8
                ],
                arena: vec![0; 1024],
            }
        }

        fn frame(
            &mut self,
            unit: u64,
            from: u32,
            flags: u32,
            bytes: &[u8],
            attempt_no: u32,
        ) -> Frame<OnPieceIn, OnPieceOut> {
            let mut i: OnPieceIn = input();
            (i.unit, i.from, i.flags, i.bytes) = (unit, from, flags, octets(bytes));
            i.attempt_no = attempt_no;
            if flags & PIECE_HAS_STATUS != 0 {
                i.status_code = 200;
            }
            (i.reply_buf, i.reply_cap) = (self.reply.as_mut_ptr(), self.reply.len());
            (i.units_buf, i.units_cap) = (self.units.as_mut_ptr(), self.units.len());
            (i.fields_buf, i.fields_cap) = (self.fields.as_mut_ptr(), self.fields.len());
            (i.arena_buf, i.arena_cap) = (self.arena.as_mut_ptr(), self.arena.len());
            Frame::new(i, output())
        }

        fn answered(&self, outcome: Outcome, o: &OnPieceOut) -> Answered {
            let n = usize::try_from(o.emitted).map_or(0, |n| n.min(self.reply.len()));
            Answered {
                outcome,
                emitted: self.reply[..n].to_vec(),
                flags: o.flags,
                status: o.reply_status,
                units: self.units[..(o.units_written as usize).min(self.units.len())]
                    .iter()
                    .map(|u| (u.class, u.amount))
                    .collect(),
            }
        }
    }

    /// One piece of `unit`, ticket-less.
    fn piece(p: &Plugin<Plane>, unit: u64, from: u32, flags: u32, bytes: &[u8]) -> Answered {
        let attempt_no = u32::from(from == FROM_KERNEL);
        let mut b = Bufs::new();
        let mut f = b.frame(unit, from, flags, bytes, attempt_no);
        let c = p.call(slot::ON_PIECE, &mut f);
        b.answered(c.outcome, &f.out)
    }

    /// One piece of `unit` on `ticket`, as the kernel submits a unit's pieces.
    fn piece_on(
        d: &Dispatcher,
        p: &Plugin<Plane>,
        ticket: Ticket,
        unit: u64,
        from: u32,
        flags: u32,
        bytes: &[u8],
    ) -> Outcome {
        let attempt_no = u32::from(from == FROM_KERNEL);
        let mut b = Bufs::new();
        let f = b.frame(unit, from, flags, bytes, attempt_no);
        d.submit(p, ticket, slot::ON_PIECE, f, DeadlineClass::Call, 0)
            .wait_done()
            .outcome
    }

    /// The ATTEMPT of `unit`, then its caller's body: the body must go to the far end, unchanged.
    fn body_reaches_the_far_end(p: &Plugin<Plane>, unit: u64) -> bool {
        let attempt = piece(p, unit, FROM_KERNEL, 0, b"");
        assert_eq!(attempt.outcome, Outcome::Ready, "the ATTEMPT is answered");
        let body = piece(p, unit, FROM_CALLER, PIECE_LAST, REQUEST);
        body.outcome == Outcome::Ready
            && body.flags & EMIT_TO_FAR_END != 0
            && body.emitted == REQUEST
    }

    /// RED (finding 6, the leak): units the kernel refused after `arrive` used to keep their state until
    /// eviction. Refusing `MAX_UNITS` units one by one must leave the instance empty, so the next unit
    /// is admitted and served.
    #[test]
    fn a_refused_unit_drops_its_state() {
        let (_d, p) = opened();
        for unit in 0..MAX_UNITS as u64 {
            assert_eq!(arrive(&p, 1_000 + unit).0, Outcome::Ready, "unit {unit}");
            refuse(&p, 1_000 + unit);
        }
        assert_eq!(
            arrive(&p, 1).0,
            Outcome::Ready,
            "refused units hold no place"
        );
        assert!(body_reaches_the_far_end(&p, 1));
    }

    /// RED (finding 6, the leak): a cancelled unit drops its state, found by the ticket its pieces
    /// crossed on.
    #[test]
    fn a_cancelled_unit_drops_its_state() {
        let (d, p) = opened();
        for unit in 0..MAX_UNITS as u64 {
            let key = 1_000 + unit;
            assert_eq!(arrive(&p, key).0, Outcome::Ready, "unit {unit}");
            let ticket = d.mint(0).expect("a ticket");
            assert_eq!(
                piece_on(&d, &p, ticket, key, FROM_KERNEL, 0, b""),
                Outcome::Ready
            );
            cancel(&p, ticket);
            d.recycle(ticket);
        }
        assert_eq!(
            arrive(&p, 1).0,
            Outcome::Ready,
            "cancelled units hold no place"
        );
        assert!(body_reaches_the_far_end(&p, 1));
    }

    /// RED (finding 6, eviction): with `MAX_UNITS` units live, the next one is REFUSED at the cap,
    /// 429, and the live unit with the smallest key (the one oldest-first eviction dropped) still
    /// forwards its caller's body.
    #[test]
    fn at_the_cap_a_new_unit_is_refused_and_no_live_unit_is_evicted() {
        let (_d, p) = opened();
        assert_eq!(arrive(&p, 1).0, Outcome::Ready);
        assert_eq!(piece(&p, 1, FROM_KERNEL, 0, b"").outcome, Outcome::Ready);
        for unit in 1..MAX_UNITS as u64 {
            assert_eq!(arrive(&p, 1_000 + unit).0, Outcome::Ready, "unit {unit}");
        }
        assert_eq!(
            arrive(&p, 99_999),
            (Outcome::Refused, AT_CAPACITY, 429),
            "past the cap a new unit is refused"
        );
        let body = piece(&p, 1, FROM_CALLER, PIECE_LAST, REQUEST);
        assert_eq!(body.outcome, Outcome::Ready);
        assert!(
            body.flags & EMIT_TO_FAR_END != 0 && body.emitted == REQUEST,
            "the live unit kept its ATTEMPT: {body:?}"
        );
    }

    /// RED (finding 8): the far end's answer is HELD until its last piece: a first piece reaches the
    /// caller as nothing, and the last relays the whole answer, unchanged, with its status and count.
    #[test]
    fn the_answer_is_held_to_its_last_piece_and_relayed_whole() {
        let (_d, p) = opened();
        assert_eq!(arrive(&p, 5).0, Outcome::Ready);
        assert_eq!(piece(&p, 5, FROM_KERNEL, 0, b"").outcome, Outcome::Ready);
        assert_eq!(
            piece(&p, 5, FROM_CALLER, PIECE_LAST, REQUEST).outcome,
            Outcome::Ready
        );
        let (head, tail) = ANSWER.split_at(20);
        let first = piece(&p, 5, FROM_FAR_END, PIECE_HAS_STATUS, head);
        assert_eq!(first.outcome, Outcome::Ready);
        assert!(
            first.emitted.is_empty() && first.status == 0 && first.flags & EMIT_DONE == 0,
            "nothing reaches the caller before the answer is whole: {first:?}"
        );
        let last = piece(&p, 5, FROM_FAR_END, PIECE_LAST, tail);
        assert_eq!(last.outcome, Outcome::Ready);
        assert_eq!(last.emitted, ANSWER, "the whole answer, unchanged");
        assert_eq!(last.status, 200);
        assert!(last.flags & EMIT_DONE != 0);
        assert_eq!(last.units, vec![(0, 42), (1, 1), (2, 0), (3, 0)]);
    }

    /// Two models, the first with an `upstream_model` that differs from its name.
    const TWO: &[u8] = br#"{"models":{"jev":{"provider":"typesafe","protocol":"jev","upstream_model":"jev-1.13.0"},"alt":{"provider":"typesafe","protocol":"jev"}}}"#;

    /// RED (finding 1, DECISIONS D8b): with several models a request that names none is refused 400,
    /// and one naming a model no generation configures is refused 404, before the unit holds state.
    #[test]
    fn several_models_route_by_name_and_refuse_none_or_unknown() {
        let (_d, p) = opened_over(TWO);
        assert_eq!(
            arrive_with(&p, 1, REQUEST),
            (Outcome::Refused, NO_MODEL_NAMED, 400)
        );
        assert_eq!(
            arrive_with(&p, 2, br#"{"model":"nope","state":{}}"#),
            (Outcome::Refused, UNKNOWN_MODEL, 404)
        );
        assert_eq!(
            arrive_with(&p, 3, br#"{"model":"alt","state":{}}"#).0,
            Outcome::Ready
        );
    }

    /// RED (finding 1): with ONE model, a request naming another model is 404, not routed to the one.
    #[test]
    fn one_model_refuses_an_unknown_named_model() {
        let (_d, p) = opened();
        assert_eq!(
            arrive_with(&p, 1, br#"{"model":"nope","state":{}}"#),
            (Outcome::Refused, UNKNOWN_MODEL, 404)
        );
    }

    /// THE DEFAULT IS BYTE-IDENTICAL (D8b, predev's behaviour): one model, none named, and the caller's
    /// body reaches the far end unchanged.
    #[test]
    fn one_model_and_none_named_is_the_default_byte_for_byte() {
        let (_d, p) = opened();
        assert_eq!(arrive(&p, 1).0, Outcome::Ready);
        assert!(body_reaches_the_far_end(&p, 1));
    }

    /// RED (finding 2, D8b): `upstream_model` rewrites the top-level `model` value alone, by span
    /// splice, when the request names that model; a model with none set passes byte for byte.
    #[test]
    fn upstream_model_is_spliced_into_the_body_bound_for_the_far_end() {
        let (_d, p) = opened_over(TWO);
        let named = br#"{"model":"jev", "state":{"model":"jev"}}"#;
        assert_eq!(arrive_with(&p, 7, named).0, Outcome::Ready);
        assert_eq!(piece(&p, 7, FROM_KERNEL, 0, b"").outcome, Outcome::Ready);
        let body = piece(&p, 7, FROM_CALLER, PIECE_LAST, named);
        assert!(body.flags & EMIT_TO_FAR_END != 0);
        assert_eq!(
            body.emitted, br#"{"model":"jev-1.13.0", "state":{"model":"jev"}}"#,
            "only the top-level model value changed"
        );
        let plain = br#"{"model":"alt","state":{}}"#;
        assert_eq!(arrive_with(&p, 8, plain).0, Outcome::Ready);
        assert_eq!(piece(&p, 8, FROM_KERNEL, 0, b"").outcome, Outcome::Ready);
        assert_eq!(piece(&p, 8, FROM_CALLER, PIECE_LAST, plain).emitted, plain);
    }

    /// One served unit `unit` to its far end's last piece: `answer`, at `status`.
    fn answered(p: &Plugin<Plane>, unit: u64, status: u32, answer: &[u8]) -> Answered {
        assert_eq!(arrive(p, unit).0, Outcome::Ready);
        assert_eq!(piece(p, unit, FROM_KERNEL, 0, b"").outcome, Outcome::Ready);
        assert_eq!(
            piece(p, unit, FROM_CALLER, PIECE_LAST, REQUEST).outcome,
            Outcome::Ready
        );
        let mut b = Bufs::new();
        let mut f = b.frame(unit, FROM_FAR_END, PIECE_HAS_STATUS | PIECE_LAST, answer, 0);
        f.input.status_code = status;
        let c = p.call(slot::ON_PIECE, &mut f);
        b.answered(c.outcome, &f.out)
    }

    /// RED ($, finding 4): a 2xx answer with no readable count is REFUSED and nothing of it reaches
    /// the caller; it used to be relayed and billed no decision.
    #[test]
    fn a_success_with_no_count_is_refused_before_any_byte_is_relayed() {
        let (_d, p) = opened();
        for (unit, answer) in [
            (1, &br#"{"request_id":"r","answers":{}}"#[..]),
            (2, br#"{"usage":{"units":1.5}}"#),
        ] {
            let last = answered(&p, unit, 200, answer);
            assert_eq!(last.outcome, Outcome::Refused, "unit {unit}");
            assert!(last.emitted.is_empty() && last.units.is_empty(), "{last:?}");
        }
    }

    /// RED ($, finding 4): a non-2xx answer bills nothing, even one carrying a count; it is relayed.
    #[test]
    fn a_non_success_answer_bills_nothing_and_is_relayed() {
        let (_d, p) = opened();
        let answer = br#"{"usage":{"units":9}}"#;
        let last = answered(&p, 3, 422, answer);
        assert_eq!(last.outcome, Outcome::Ready);
        assert_eq!(last.emitted, answer);
        assert_eq!(last.status, 422);
        assert!(last.units.is_empty(), "{last:?}");
    }

    /// A NanoJev model beside a jev one (each by its override).
    const MIXED: &[u8] = br#"{"models":{"jev":{"provider":"typesafe","protocol":"jev"},"nano":{"provider":"local","protocol":"nanojev"}}}"#;

    /// A NanoJev request, in its server's own shape.
    const EVALUATE: &[u8] = br#"{"states":[{"id":"a","state":"A","questions":{"q":{"type":"boolean","instructions":"Is A present?"}}}]}"#;

    /// THE NANOJEV DIALECT, through the one loader (THE DESIGN section 2): `POST /api/evaluate` arrives
    /// in dialect 1, routes to the NanoJev model, goes to its far end unchanged on `/api/evaluate`,
    /// and bills its own unit, `execution.states`.
    #[test]
    fn nanojev_is_served_on_its_own_claim_and_meters_execution_states() {
        let (_d, p) = opened_over(MIXED);
        assert_eq!(
            arrive_at(&p, 1, b"/api/evaluate", EVALUATE),
            ((Outcome::Ready, 0, 0), 1)
        );
        let mut b = Bufs::new();
        let mut f = b.frame(1, FROM_KERNEL, 0, b"", 1);
        assert_eq!(p.call(slot::ON_PIECE, &mut f).outcome, Outcome::Ready);
        let target = f.out.target;
        let at = |s: Span| {
            String::from_utf8_lossy(&b.arena[s.offset as usize..(s.offset + s.len) as usize])
                .into_owned()
        };
        assert_eq!(at(target), "/api/evaluate");
        let body = piece(&p, 1, FROM_CALLER, PIECE_LAST, EVALUATE);
        assert_eq!(body.emitted, EVALUATE, "the request passes byte for byte");
        let answer =
            br#"{"execution":{"states":1,"forward_passes":1},"states":[{"id":"a","answers":{}}]}"#;
        let mut b = Bufs::new();
        let mut f = b.frame(1, FROM_FAR_END, PIECE_HAS_STATUS | PIECE_LAST, answer, 0);
        let c = p.call(slot::ON_PIECE, &mut f);
        let last = b.answered(c.outcome, &f.out);
        assert_eq!(last.outcome, Outcome::Ready);
        assert_eq!(last.emitted, answer);
        assert_eq!(last.units, vec![(0, 1), (1, 1), (2, 0), (3, 0)]);
    }

    /// A model of the other dialect gets this dialect's unknown-model refusal (404); a NanoJev answer
    /// with no count is refused, never served free.
    #[test]
    fn nanojev_wrong_dialect_and_uncounted_answers_are_refused() {
        let (_d, p) = opened_over(MIXED);
        assert_eq!(
            arrive_at(&p, 2, b"/v1/systemone", br#"{"model":"nano"}"#),
            ((Outcome::Refused, UNKNOWN_MODEL, 404), 0)
        );
        assert_eq!(
            arrive_at(&p, 3, b"/api/evaluate", EVALUATE).0 .0,
            Outcome::Ready
        );
        assert_eq!(piece(&p, 3, FROM_KERNEL, 0, b"").outcome, Outcome::Ready);
        assert_eq!(
            piece(&p, 3, FROM_CALLER, PIECE_LAST, EVALUATE).outcome,
            Outcome::Ready
        );
        let last = piece(
            &p,
            3,
            FROM_FAR_END,
            PIECE_HAS_STATUS | PIECE_LAST,
            br#"{"execution":{"forward_passes":1},"states":[]}"#,
        );
        assert_eq!(last.outcome, Outcome::Refused);
        assert!(last.emitted.is_empty());
    }

    /// A NanoJev model that sets `upstream_model` is refused at `open`, naming it.
    #[test]
    fn nanojev_upstream_model_is_refused_at_open() {
        let s = Subject::new(door, "decisions_door", include_str!("conformance.json"));
        let d = dispatcher();
        let p = load::<Plane>(&s, Leg::Linked, s.bind(&d, "plane")).expect("the door loads");
        let settings =
            br#"{"models":{"n":{"provider":"local","protocol":"nanojev","upstream_model":"x"}}}"#;
        let mut f: Frame<PlaneOpenIn, PlaneOpenOut> = Frame::new(input(), output());
        (f.input.open.generation, f.input.open.settings) = (1, json(settings));
        let (called, _) = p.open(&mut f);
        assert_ne!(called.outcome, Outcome::Ready);
    }
}
