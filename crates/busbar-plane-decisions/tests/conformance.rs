//! The plane, driven over three byte fixtures this crate authors itself.
//!
//! jev has no public conformance battery the way MCP/A2A do (no third-party suite exists for a
//! provider-scoped decision protocol this workspace does not operate). So these fixtures are
//! authored here, against the shapes `JEV-DESIGN-SIGNED-v4.md` and the ruling describe: a
//! `systemone` success carrying a usage count, a `systemone` 422 whose body echoes the caller's
//! `state` and the provider's `answers` (the PII witness case — see `pii_witness` below and
//! `tests/jev.rs`), and a `models` list. Each is driven through `decode_ingress`/`decode_response`
//! and the operation class + correlation/finish it produces is pinned; the encoder is pinned
//! byte-for-byte against the same fixture, because byte-identity passthrough IS the dialect.

mod common;

use busbar_contract::bounded::FactValue;
use busbar_contract::plane::{Ingress, Plane, Progress, Response};
use busbar_contract::unit::FinishClass;
use busbar_contract::wire::FrameCursor;
use busbar_plane_decisions::{facts, ops, DecisionPlane};
use common::{frame, response_frame, Scaffold};

/// `POST /v1/systemone` — a successful decision, billing 42 units.
const SYSTEMONE_SUCCESS: &[u8] =
    br#"{"request_id":"req_1","usage":{"units":42},"answers":{"decision":"approve"}}"#;

/// `POST /v1/systemone` — a 422, echoing the caller's `state` and the provider's `answers`. The
/// PII witness fixture: `tests/jev.rs::pii_witness` drives this and asserts neither value ever
/// reaches a fact this plane emits.
const SYSTEMONE_422: &[u8] = br#"{"error":{"code":"invalid_state","message":"bad transition"},"state":{"session":"caller-secret-state-xyz"},"answers":{"leaked":"should-never-surface"}}"#;

/// `GET /v1/models` — the provider's own catalogue, relayed as-is.
const MODELS_LIST: &[u8] =
    br#"{"request_id":"req_2","data":[{"id":"jev-1.13.0","object":"model"}]}"#;

/// The request body a `systemone` call carries — this plane never reads a pointer off it (see
/// `codec::REQUEST_PTRS`), so its shape only matters for byte-identity forwarding.
const SYSTEMONE_REQUEST: &[u8] = br#"{"state":{"session":"caller-secret-state-xyz"},"context":{}}"#;

#[test]
fn decode_ingress_names_systemone_and_waits_for_its_body() {
    let plane = DecisionPlane::EMPTY;
    let scaffold = Scaffold::new("http")
        .with_method("POST")
        .on_path("/v1/systemone");
    let ctx = scaffold.ctx();
    let frames = vec![frame(SYSTEMONE_REQUEST)];
    let mut cursor = FrameCursor::new(&frames);
    let Ok(Ingress::OneShot(draft)) = plane.decode_ingress(&mut cursor, None, &ctx) else {
        panic!("a systemone POST with a body decodes as one shot");
    };
    assert_eq!(draft.op, ops::OP_SYSTEMONE);
    assert_eq!(
        draft.facts.get(facts::FACT_OP),
        Some(FactValue::Str("systemone"))
    );
    // Byte-identity: the whole request body is carried, untouched.
    assert_eq!(draft.body_ir.body(), SYSTEMONE_REQUEST);
}

#[test]
fn decode_ingress_names_models_with_no_body_to_wait_for() {
    let plane = DecisionPlane::EMPTY;
    let scaffold = Scaffold::new("http")
        .with_method("GET")
        .on_path("/v1/models");
    let ctx = scaffold.ctx();
    // No frame at all — a GET carries no body, and `models` must not wait for one.
    let frames: Vec<busbar_contract::wire::Frame> = Vec::new();
    let mut cursor = FrameCursor::new(&frames);
    let Ok(Ingress::OneShot(draft)) = plane.decode_ingress(&mut cursor, None, &ctx) else {
        panic!("a bodyless GET /v1/models decodes as one shot with no frame read");
    };
    assert_eq!(draft.op, ops::OP_MODELS);
}

#[test]
fn decode_ingress_refuses_an_unclaimed_surface() {
    let plane = DecisionPlane::EMPTY;
    let scaffold = Scaffold::new("http")
        .with_method("POST")
        .on_path("/v1/unknown");
    let ctx = scaffold.ctx();
    let frames = vec![frame(b"{}")];
    let mut cursor = FrameCursor::new(&frames);
    assert!(plane.decode_ingress(&mut cursor, None, &ctx).is_err());
}

#[test]
fn decode_response_reads_success_as_complete_with_usage() {
    let plane = DecisionPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let frames = vec![response_frame(SYSTEMONE_SUCCESS)];
    let mut cursor = FrameCursor::new(&frames);
    let Ok(Progress::Terminal { r, .. }) =
        plane.decode_response(&mut cursor, &common::sealed_destination(), None, &ctx)
    else {
        panic!("a whole systemone answer decodes as terminal");
    };
    assert_eq!(r.finish, FinishClass::Complete);
    assert_eq!(
        r.facts.get(facts::FACT_HAS_ERROR),
        Some(FactValue::Bool(false))
    );
    assert_eq!(
        r.facts.get(facts::FACT_USAGE_UNITS),
        Some(FactValue::Int(42))
    );
    assert_eq!(r.ir.body(), SYSTEMONE_SUCCESS);
}

#[test]
fn decode_response_reads_422_as_error_with_no_usage() {
    let plane = DecisionPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let frames = vec![response_frame(SYSTEMONE_422)];
    let mut cursor = FrameCursor::new(&frames);
    let Ok(Progress::Terminal { r, .. }) =
        plane.decode_response(&mut cursor, &common::sealed_destination(), None, &ctx)
    else {
        panic!("a whole 422 answer decodes as terminal");
    };
    assert_eq!(r.finish, FinishClass::Error);
    assert_eq!(
        r.facts.get(facts::FACT_HAS_ERROR),
        Some(FactValue::Bool(true))
    );
    assert_eq!(r.facts.get(facts::FACT_USAGE_UNITS), None);
}

#[test]
fn encode_response_is_byte_identical_to_the_fixture() {
    let plane = DecisionPlane::EMPTY;
    for fixture in [SYSTEMONE_SUCCESS, SYSTEMONE_422, MODELS_LIST] {
        let scaffold = Scaffold::new("http");
        let ctx = scaffold.ctx();
        let r = Response {
            ir: busbar_contract::bounded::Ir::new(fixture, &[]),
            finish: FinishClass::Complete,
            facts: busbar_contract::bounded::Facts::new(),
        };
        let out = plane
            .encode_response(&r, None, &ctx)
            .expect("every fixture re-encodes");
        assert_eq!(
            out.as_slice(),
            fixture,
            "encode_response is not byte-identical"
        );
    }
}

/// THE DOOR, BOTH WAYS: the linked door (`plane_door::door`) and this crate's dropped-in image (the
/// `decisions_door` example, the same door behind `export_door!`), each admitted through the one
/// loader, run ONE script through every plane op, each answer read back. The two transcripts must
/// be identical, and equal to the one the plane's answers to the driver require.
///
/// RED ARM, kept: the same door with `on_piece` swapped for one that relays the far end's answer
/// and reports no count. Its transcript differs at the far end's answer, so a door that stopped
/// metering cannot pass for this one.
mod door {
    use std::mem::zeroed;
    use std::sync::Arc;

    use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, Outcome, Span, BLOB_OCTETS};
    use busbar_contract::abi::mechanism::door::Door;
    use busbar_contract::abi::mechanism::lifecycle::{
        slot as life, CancelIn, CancelOut, GenIn, RefreshIn, TickIn, TickOut, ValidateIn,
    };
    use busbar_contract::abi::plane::{
        self, slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneOpenIn,
        PlaneOpenOut, PlaneRefreshOut, ProjectIn, ProjectOut, RefusalIn, RefusalOut, ServeIn,
        ServeOut, UnitCount, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END, FROM_KERNEL,
        PIECE_HAS_STATUS, PIECE_LAST, PRINCIPAL_REQUIRED, REFUSAL_GATE, UNITS_REPORTED,
    };
    use busbar_contract::abi::sdk::capture::{CaptureHome, CaptureSlot};
    use busbar_contract::abi::sdk::door::kind_op;
    use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
    use busbar_plane_decisions::plane_door;
    use busbar_plugin_loader::dispatch::kinds::plane::Plane;
    use busbar_plugin_loader::dispatch::{
        in_head, load_dropped, load_linked, out_head, rendering_of, Bind, DispatchConfig,
        Dispatcher, Frame, LinkedRow, NoSink, Plugin,
    };

    fn z<T>() -> T {
        // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
        unsafe { zeroed() }
    }

    fn bind(d: &Dispatcher) -> Bind {
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: None,
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

    fn at(buf: &[u8], s: Span) -> String {
        String::from_utf8_lossy(&buf[s.offset as usize..(s.offset + s.len) as usize]).into_owned()
    }

    /// One model configured: `systemone` is claimed.
    const ONE_MODEL: &[u8] = br#"{"models":{"jev":{"provider":"typesafe"}}}"#;
    /// Two models: nothing is claimed.
    const TWO_MODELS: &[u8] =
        br#"{"models":{"a":{"provider":"typesafe"},"b":{"provider":"typesafe"}}}"#;
    /// What the caller sends.
    const REQUEST: &[u8] = br#"{"state":{"session":"s"},"context":{}}"#;
    /// What the far end answers: a decision billing 42 units.
    const ANSWER: &[u8] = br#"{"request_id":"req_1","usage":{"units":42},"answers":{}}"#;
    /// The far end's kept response field.
    const HEAD: &[Field] = &[Field {
        name: AbiStr {
            ptr: b"content-type".as_ptr(),
            len: 12,
        },
        value: AbiStr {
            ptr: b"application/json".as_ptr(),
            len: 16,
        },
    }];

    /// The host's buffers for one `on_piece`.
    struct Piece {
        reply: Vec<u8>,
        units: [UnitCount; 2],
        fields: [OutField; 2],
        arena: [u8; 128],
    }

    impl Piece {
        fn new(reply_cap: usize) -> Box<Self> {
            Box::new(Self {
                reply: vec![0; reply_cap],
                units: [z(); 2],
                fields: [z(); 2],
                arena: [0; 128],
            })
        }

        /// One piece of `unit`, answered: the outcome, and what it wrote, as text.
        fn call(
            &mut self,
            p: &Plugin<Plane>,
            unit: u64,
            from: u32,
            flags: u32,
            bytes: &'static [u8],
            attempt_no: u32,
        ) -> String {
            let mut i: OnPieceIn = z();
            i.head = in_head();
            (i.unit, i.from, i.flags, i.bytes) = (unit, from, flags, octets(bytes));
            (i.attempt_no, i.member) = (attempt_no, text(b"jev"));
            if flags & PIECE_HAS_STATUS != 0 {
                i.status_code = 200;
                (i.head_fields, i.head_fields_len) = (HEAD.as_ptr(), HEAD.len());
            }
            (i.reply_buf, i.reply_cap) = (self.reply.as_mut_ptr(), self.reply.len());
            (i.units_buf, i.units_cap) = (self.units.as_mut_ptr(), self.units.len());
            (i.fields_buf, i.fields_cap) = (self.fields.as_mut_ptr(), self.fields.len());
            (i.arena_buf, i.arena_cap) = (self.arena.as_mut_ptr(), self.arena.len());
            let mut o: OnPieceOut = z();
            o.head = out_head();
            let mut f = Frame::new(i, o);
            let c = p.call(slot::ON_PIECE, &mut f);
            let o = f.out;
            let fields: Vec<String> = self.fields[..o.fields_written as usize]
                .iter()
                .map(|f| format!("{}={}", at(&self.arena, f.name), at(&self.arena, f.value)))
                .collect();
            let units: Vec<String> = self.units[..o.units_written as usize]
                .iter()
                .map(|u| format!("{}:{}:{}", u.class, u.amount, u.source == UNITS_REPORTED))
                .collect();
            format!(
                "{:?} emitted={} more={} to_far_end={} done={} status={} verb={} target={} \
                 fields={fields:?} units={units:?}",
                c.outcome,
                String::from_utf8_lossy(&self.reply[..o.emitted as usize]),
                o.more,
                o.flags & EMIT_TO_FAR_END != 0,
                o.flags & EMIT_DONE != 0,
                o.reply_status,
                at(&self.arena, o.verb),
                at(&self.arena, o.target),
            )
        }
    }

    fn arrive(
        p: &Plugin<Plane>,
        unit: u64,
        method: &'static [u8],
        target: &'static [u8],
    ) -> String {
        let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(z(), z());
        (a.input.head, a.out.head) = (in_head(), out_head());
        (a.input.unit, a.input.method, a.input.target) = (unit, text(method), text(target));
        a.input.body = octets(REQUEST);
        let c = p.call(slot::ARRIVE, &mut a);
        let pool = if a.out.pool.ptr.is_null() {
            String::new()
        } else {
            // SAFETY: a READY answer's entry name lives in the instance past the call.
            String::from_utf8_lossy(unsafe {
                std::slice::from_raw_parts(a.out.pool.ptr, a.out.pool.len)
            })
            .into_owned()
        };
        format!(
            "arrive {:?} op_class={} principal_required={} dialect={} refusal={} status={} \
             route={} pool={pool}",
            c.outcome,
            a.out.op_class,
            a.out.principal_need == PRINCIPAL_REQUIRED,
            a.out.dialect,
            a.out.refusal,
            a.out.refusal_status,
            a.out.route
        )
    }

    /// THE SCRIPT: every plane op, each answer read back.
    fn script(p: &Plugin<Plane>) -> Vec<String> {
        let mut t = Vec::new();

        let mut v = Frame::new(
            ValidateIn {
                head: in_head(),
                settings: octets(br#"{"modles":{}}"#),
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            },
            out_head(),
        );
        t.push(format!(
            "validate typo {:?}",
            p.call(life::VALIDATE, &mut v).outcome
        ));
        v.input.settings = octets(ONE_MODEL);
        t.push(format!(
            "validate {:?}",
            p.call(life::VALIDATE, &mut v).outcome
        ));

        let mut i: PlaneOpenIn = z();
        i.open.head = in_head();
        (i.open.generation, i.open.settings) = (1, octets(ONE_MODEL));
        let mut o: PlaneOpenOut = z();
        o.open.head = out_head();
        let (c, snapshot) = p.open(&mut Frame::new(i, o));
        t.push(format!("open {:?} {snapshot:?}", c.outcome));

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

        t.push(arrive(p, 7, b"POST", b"/v1/systemone"));
        t.push(arrive(p, 8, b"GET", b"/v1/models"));

        // One unit: the ATTEMPT, the caller's body, the far end's whole answer.
        let mut piece = Piece::new(256);
        t.push(format!(
            "attempt {}",
            piece.call(p, 7, FROM_KERNEL, 0, b"", 1)
        ));
        t.push(format!(
            "body {}",
            piece.call(p, 7, FROM_CALLER, PIECE_LAST, REQUEST, 0)
        ));
        let whole = PIECE_HAS_STATUS | PIECE_LAST;
        t.push(format!(
            "far_end {}",
            piece.call(p, 7, FROM_FAR_END, whole, ANSWER, 0)
        ));

        // Another, whose answer is written 16 bytes at a time.
        let mut narrow = Piece::new(16);
        t.push(format!(
            "attempt {}",
            narrow.call(p, 9, FROM_KERNEL, 0, b"", 1)
        ));
        t.push(format!(
            "far_end narrow {}",
            narrow.call(p, 9, FROM_FAR_END, whole, ANSWER, 0)
        ));
        for _ in 0..3 {
            t.push(format!(
                "more {}",
                narrow.call(p, 9, FROM_FAR_END, 0, b"", 0)
            ));
        }

        // A caller body that ended empty.
        t.push(format!(
            "empty {}",
            piece.call(p, 10, FROM_CALLER, PIECE_LAST, b"", 0)
        ));

        let (mut reply, mut fields, mut buf) = ([0_u8; 128], [z::<OutField>(); 1], [0_u8; 64]);
        let mut r: Frame<RefusalIn, RefusalOut> = Frame::new(z(), z());
        (r.input.head, r.out.head) = (in_head(), out_head());
        (r.input.cause, r.input.status, r.input.text) = (REFUSAL_GATE, 403, text(b"denied"));
        (r.input.reply_buf, r.input.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (r.input.fields_buf, r.input.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (r.input.arena_buf, r.input.arena_cap) = (buf.as_mut_ptr(), buf.len());
        let c = p.call(slot::REFUSAL, &mut r);
        t.push(format!(
            "refusal {:?} {} {}={} status={}",
            c.outcome,
            String::from_utf8_lossy(&reply[..r.out.reply_written as usize]),
            at(&buf, fields[0].name),
            at(&buf, fields[0].value),
            r.out.status
        ));

        let mut s: Frame<ServeIn, ServeOut> = Frame::new(z(), z());
        (s.input.head, s.out.head) = (in_head(), out_head());
        t.push(format!("serve {:?}", p.call(slot::SERVE, &mut s).outcome));
        let mut j: Frame<ProjectIn, ProjectOut> = Frame::new(z(), z());
        (j.input.head, j.out.head) = (in_head(), out_head());
        t.push(format!(
            "project {:?}",
            p.call(slot::PROJECT, &mut j).outcome
        ));

        let mut k = Frame::new(
            TickIn {
                head: in_head(),
                now_ns: 1_000,
            },
            TickOut {
                head: out_head(),
                next_tick_ns: 7,
            },
        );
        let c = p.call(life::TICK, &mut k);
        t.push(format!("tick {:?} next={}", c.outcome, k.out.next_tick_ns));
        let mut x: Frame<CancelIn, CancelOut> = Frame::new(z(), z());
        (x.input.head, x.out.head) = (in_head(), out_head());
        let c = p.call(life::CANCEL, &mut x);
        t.push(format!("cancel {:?} {}", c.outcome, x.out.disposition));

        let mut f: Frame<RefreshIn, PlaneRefreshOut> = Frame::new(z(), z());
        (f.input.head, f.out.head) = (in_head(), out_head());
        (f.input.generation, f.input.settings) = (2, octets(TWO_MODELS));
        let (c, snapshot) = p.refresh(&mut f);
        t.push(format!("refresh {:?} {snapshot:?}", c.outcome));

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

    /// The transcript the plane's answers to the driver require, linked or dropped.
    const EXPECTED: &[&str] = &[
        "validate typo Refused",
        "validate Ready",
        "open Ready Some(OwnedSnapshot { generation: 1, claims: [OwnedClaim { verb: \"POST\", \
         target: \"/v1/systemone\", carrier: \"http\", flags: 2, refusal_dialect: 0 }], \
         admin_routes: [], openapi: None, audience: None, resource_metadata: None })",
        "13 Ready",
        "14 Ready",
        // The one model routes directly (ARCHITECT Q-SW6/Q-FL3: ROUTE_DIRECT = 1).
        "arrive Ready op_class=0 principal_required=true dialect=0 refusal=0 status=0 route=1 \
         pool=jev",
        "arrive Refused op_class=0 principal_required=false dialect=0 refusal=1 status=404 \
         route=0 pool=",
        "attempt Ready emitted= more=0 to_far_end=true done=false status=0 verb=POST \
         target=/v1/systemone fields=[\"content-type=application/json\"] units=[]",
        "body Ready emitted={\"state\":{\"session\":\"s\"},\"context\":{}} more=0 to_far_end=true \
         done=false status=0 verb= target= fields=[] units=[]",
        "far_end Ready emitted={\"request_id\":\"req_1\",\"usage\":{\"units\":42},\"answers\":{}} \
         more=0 to_far_end=false done=true status=200 verb= target= \
         fields=[\"content-type=application/json\"] units=[\"0:42:true\"]",
        "attempt Ready emitted= more=0 to_far_end=true done=false status=0 verb=POST \
         target=/v1/systemone fields=[\"content-type=application/json\"] units=[]",
        "far_end narrow Ready emitted={\"request_id\":\"r more=1 to_far_end=false done=false \
         status=200 verb= target= fields=[\"content-type=application/json\"] units=[\"0:42:true\"]",
        "more Ready emitted=eq_1\",\"usage\":{\" more=1 to_far_end=false done=false status=0 verb= \
         target= fields=[] units=[]",
        "more Ready emitted=units\":42},\"answ more=1 to_far_end=false done=false status=0 verb= \
         target= fields=[] units=[]",
        "more Ready emitted=ers\":{}} more=0 to_far_end=false done=true status=0 verb= target= \
         fields=[] units=[]",
        "empty Refused emitted= more=0 to_far_end=false done=false status=0 verb= target= \
         fields=[] units=[]",
        "refusal Ready {\"error\":{\"code\":\"unsupported_operation\",\"message\":\"denied\"}} \
         content-type=application/json status=0",
        "serve Refused",
        "project Refused",
        "tick Ready next=0",
        "cancel Ready 3",
        "refresh Ready Some(OwnedSnapshot { generation: 2, claims: [], admin_routes: [], \
         openapi: None, audience: None, resource_metadata: None })",
        "retire Ready",
        "close Ready",
    ];

    fn linked(d: &Dispatcher) -> Plugin<Plane> {
        let row = LinkedRow::of(plane_door::door).expect("the linked door states its Statement");
        load_linked(&row, bind(d)).expect("the linked door loads")
    }

    /// This crate's dropped-in image, the `decisions_door` example `cargo test` builds. A missing
    /// artifact is a failure, never a skip: this test IS the dropped-in door's proof.
    fn dropped(d: &Dispatcher) -> Plugin<Plane> {
        let exe = std::env::current_exe().expect("the test binary has a path");
        let examples = exe
            .parent()
            .and_then(|d| d.parent())
            .expect("target/<profile>")
            .join("examples");
        let file = busbar_plugin_loader::plugin_library_filename("decisions_door");
        let path = [examples.join(&file), examples.join("deps").join(&file)]
            .into_iter()
            .find(|p| p.exists())
            .unwrap_or_else(|| panic!("the decisions_door example ({file}) is not built"));
        let stated = rendering_of(plane_door::door).expect("the door renders its Statement");
        load_dropped(&path, &stated, bind(d)).expect("the dropped door loads")
    }

    #[test]
    fn the_linked_and_the_dropped_in_door_answer_every_op_the_same() {
        let d = Dispatcher::new(DispatchConfig::default());
        let linked = script(&linked(&d));
        assert_eq!(linked, EXPECTED, "the linked door");
        assert_eq!(script(&dropped(&d)), linked, "the dropped-in door");
    }

    /// A call capture for the hand-built table entry below: one slot per thread, as `plugin_door!`
    /// expands for a plugin's own image.
    struct TestCapture;
    impl CaptureHome for TestCapture {
        fn with<R>(f: impl FnOnce(&mut CaptureSlot) -> R) -> R {
            thread_local! {
                static SLOT: std::cell::RefCell<CaptureSlot> =
                    std::cell::RefCell::new(CaptureSlot::new());
            }
            SLOT.with(|s| f(&mut s.borrow_mut()))
        }
    }

    /// An `on_piece` that relays every piece's bytes to the caller and reports no count.
    struct Uncounted;
    impl SafeSlot for Uncounted {
        type In = OnPieceIn;
        type Out = OnPieceOut;
        type State = ();
        fn call(
            _: Instance<'_, ()>,
            input: Lent<'_, OnPieceIn>,
            mut out: Out<'_, OnPieceOut>,
        ) -> Outcome {
            let bytes = input.field(|i| &i.bytes).bytes();
            let n = input.reply_buf().stream(bytes);
            out.set(|o| &o.emitted, n as u64);
            if input.from == FROM_FAR_END && input.flags & PIECE_LAST != 0 {
                out.set(|o| &o.flags, EMIT_DONE);
            }
            Outcome::Ready
        }
    }

    /// The decisions door with `on_piece` swapped for [`Uncounted`].
    extern "C" fn uncounted_door() -> *const Door {
        // SAFETY: the macro's `'static` door and its plane table.
        let (d, mut ops) = unsafe {
            let d = &*plane_door::door();
            (d, *d.ops.cast::<plane::Ops>())
        };
        ops.on_piece = kind_op::<plane::Ops, Safe<Uncounted>, TestCapture, { slot::ON_PIECE }>();
        let ops: &'static plane::Ops = Box::leak(Box::new(ops));
        Box::leak(Box::new(Door {
            ops: std::ptr::from_ref(ops).cast(),
            ..*d
        }))
    }

    #[test]
    fn red_a_door_that_stops_counting_the_far_ends_units_answers_differently() {
        let d = Dispatcher::new(DispatchConfig::default());
        let row = LinkedRow::of(uncounted_door).expect("the door states its Statement");
        let red = script(&load_linked::<Plane>(&row, bind(&d)).expect("the door loads"));
        let far_end = |t: &[String]| t.iter().find(|l| l.starts_with("far_end ")).cloned();
        let honest = far_end(&EXPECTED.iter().map(ToString::to_string).collect::<Vec<_>>());
        assert!(honest
            .as_deref()
            .is_some_and(|l| l.contains("units=[\"0:42:true\"]")));
        let red_line = far_end(&red).expect("the red door answers the far end");
        assert!(red_line.contains("units=[]"), "{red_line}");
        assert_ne!(
            Some(red_line),
            honest,
            "the far end's answer is where the two differ"
        );
        assert_ne!(red, EXPECTED);
    }
}
