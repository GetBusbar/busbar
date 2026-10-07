//! The plane's vocabulary against the conformance battery, and the plane's door driven both ways.
//!
//! The judge of this work is the battery: the official suite and the in-house adversarial battery,
//! both of which speak to a booted node over a socket. The vocabulary tests here read the
//! battery's own sources (its method names, error code table, metadata keys and revision) and
//! assert this crate's tables carry them, so a battery that starts sending something new fails HERE
//! rather than in a run someone has to interpret. The `both_ways` module drives the served door
//! through the loader, linked and dropped-in, and compares the transcripts.
//!
//! The tests that drove the unserved `Plane` trait impl (decode, encode, verify, route, meter) were
//! retired with that impl (finding 12; the coordinator's order "delete the dead Plane impl with
//! its struck route"); the served door's own tests carry what the door does.

use busbar_contract::plane::PlaneMeta;
use busbar_plane_mcp::{jsonrpc, tool_facts as facts, tool_ops as ops, McpPlane};
use std::path::{Path, PathBuf};

/// The battery's own source tree.
fn battery() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/mcp-conformance")
}

/// Every method name the battery's suites and fake peers name.
///
/// Read out of the battery rather than restated, which is the whole point: a battery that starts
/// sending a method this plane does not carry must fail at build time, not in a run.
fn battery_methods() -> Vec<String> {
    let mut found = Vec::new();
    let mut walk = |dir: PathBuf| {
        // A directory that is not there is NOT "no methods here". The three below are the three
        // places the battery keeps the names this plane is checked against, and a missing one used
        // to return quietly: the surviving two still filled `found`, the non-empty floor below
        // still held, and the coverage this test claims silently shrank to whatever was left. If
        // the battery moves a directory, that must be a red here rather than a smaller test.
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("the battery's {} is readable ({e})", dir.display()));
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "mjs") {
                let text = std::fs::read_to_string(&path).expect("a battery source is readable");
                for piece in text.split('\'').skip(1).step_by(2) {
                    if looks_like_a_method(piece) && !found.contains(&piece.to_string()) {
                        found.push(piece.to_string());
                    }
                }
            }
        }
    };
    walk(battery().join("src/suites"));
    walk(battery().join("src/core"));
    walk(battery().join("fakepeer"));
    assert!(
        !found.is_empty(),
        "no method names were read out of the battery"
    );
    found
}

/// Whether a quoted piece of the battery's source is a method name of this protocol.
fn looks_like_a_method(piece: &str) -> bool {
    let heads = [
        "server/",
        "tools/",
        "prompts/",
        "resources/",
        "completion/",
        "tasks/",
        "subscriptions/",
        "notifications/",
        "sampling/",
        "roots/",
        "elicitation/",
    ];
    heads.iter().any(|h| piece.starts_with(h)) && !piece.contains(' ')
}

/// Every method the battery sends is one this plane carries, in one of its three roles.
#[test]
fn every_method_the_battery_sends_is_carried() {
    for method in battery_methods() {
        let carried = ops::method_row_for(&method).is_some() || ops::is_known_notification(&method);
        // The battery names three notices this node emits rather than receives, and one deliberate
        // nonsense name. Everything else it names, it sends.
        let emitted_only = matches!(
            method.as_str(),
            "notifications/message"
                | "notifications/progress"
                | "notifications/cancelled"
                | "notifications/subscriptions/acknowledged"
        );
        assert!(
            carried || emitted_only,
            "the battery names {method} and this plane neither carries nor emits it"
        );
    }
}

/// How many rows of each role the method table declares, and how many notices this plane knows.
///
/// Every loop below is a FILTER over a declared table, so a table that lost the rows a loop selects
/// would leave that loop iterating zero times — and a conformance test that drove nothing reports
/// `ok`. These three numbers are what turns "the loop found nothing" into a failure. Raise one
/// deliberately, in the commit that adds the row.
const CLIENT_ROWS: usize = 13;
/// The rows only a paired server may send. See [`CLIENT_ROWS`].
const PROVIDER_ROWS: usize = 3;
/// The notices this plane recognises. See [`CLIENT_ROWS`].
const NOTICE_ROWS: usize = 3;

/// The declared method rows of one role.
fn rows_of(sender: ops::Sender) -> Vec<&'static ops::RpcMethodRow> {
    ops::METHODS.iter().filter(|r| r.sender == sender).collect()
}

/// The method table keeps the roles the door serves: how many rows each role has, every row's class
/// is one the plane declares, and exactly the held stream is event-framed.
///
/// The surviving, plane-free half of what the decode-driven tests asserted (finding 12): the door
/// reads this same table (`ops::method_row_for`), so the table is what is pinned here.
#[test]
fn the_method_table_keeps_its_roles_and_its_declared_classes() {
    assert_eq!(rows_of(ops::Sender::Client).len(), CLIENT_ROWS);
    assert_eq!(rows_of(ops::Sender::Provider).len(), PROVIDER_ROWS);
    assert_eq!(ops::NOTIFICATIONS.len(), NOTICE_ROWS);
    for row in ops::METHODS {
        assert!(
            McpPlane::OP_CLASSES.contains(&row.op),
            "{} names the undeclared class {}",
            row.method,
            row.op
        );
    }
    let framed: Vec<_> = ops::METHODS
        .iter()
        .filter(|r| r.event_framed)
        .map(|r| r.op)
        .collect();
    assert_eq!(framed, vec![ops::OP_SUBSCRIPTIONS_LISTEN]);
}

/// The revision the battery declares is the revision the codec declares.
#[test]
fn the_revision_is_the_codecs_own() {
    let spec = std::fs::read_to_string(battery().join("src/core/spec.mjs"))
        .expect("the battery's own revision is readable");
    assert!(
        spec.contains(busbar_plane_mcp::codec::PROTOCOL_VERSION),
        "the battery and the codec no longer agree on the revision"
    );
}

/// The battery's own error code table is the one this plane writes from.
#[test]
fn the_error_codes_are_the_batterys_own() {
    let source = std::fs::read_to_string(battery().join("src/core/jsonrpc.mjs"))
        .expect("the battery's own code table is readable");
    for code in [
        jsonrpc::CODE_PARSE_ERROR,
        jsonrpc::CODE_INVALID_REQUEST,
        jsonrpc::CODE_METHOD_NOT_FOUND,
        jsonrpc::CODE_INVALID_PARAMS,
        jsonrpc::CODE_INTERNAL,
        jsonrpc::CODE_HEADER_MISMATCH,
        jsonrpc::CODE_MISSING_CLIENT_CAPABILITY,
        jsonrpc::CODE_UNSUPPORTED_PROTOCOL_VERSION,
    ] {
        assert!(
            names_the_number(&source, code),
            "the battery no longer names the code {code}"
        );
    }
    // And the two the battery calls RETIRED are two this plane cannot write.
    for retired in jsonrpc::RETIRED_CODES {
        assert!(
            names_the_number(&source, *retired),
            "the battery no longer names the retired code {retired}"
        );
        assert!(!jsonrpc::CODES.contains(retired));
    }
}

/// Whether a source file names EXACTLY this number, rather than merely containing its digits.
///
/// A bare substring search answers yes for a code that is a prefix of a longer one — `-32700` is
/// inside `-327001` — and yes for the digits of a code that appears in a version string, a byte
/// count or a comment. Either way the check would report the battery still names a code it had
/// dropped. Requiring a non-digit on each side is what makes the match the number itself.
fn names_the_number(source: &str, code: i64) -> bool {
    let needle = code.to_string();
    let bytes = source.as_bytes();
    source.match_indices(&needle).any(|(at, _)| {
        let before_ok = at == 0 || !bytes[at - 1].is_ascii_digit();
        let after = at + needle.len();
        let after_ok = after == bytes.len() || !bytes[after].is_ascii_digit();
        before_ok && after_ok
    })
}

/// The metadata keys are the ones the battery actually sends.
#[test]
fn the_metadata_keys_are_the_batterys_own() {
    let source = std::fs::read_to_string(battery().join("src/core/jsonrpc.mjs"))
        .expect("the battery's own key table is readable");
    for key in [
        facts::META_PROTOCOL_VERSION,
        facts::META_CLIENT_CAPABILITIES,
        facts::META_PROGRESS_TOKEN,
    ] {
        assert!(source.contains(key), "the battery no longer sends {key}");
    }
}

/// THE MCP PLANE'S CONFORMANCE RIG, BOTH WAYS (BUSBAR-1.6.0.md, the plane driver's "Proven by":
/// the plane conformance suite, compiled-in and dropped-in through one table).
///
/// The linked door (`plane_door::door`) and this crate's dropped-in image (the `mcp_door` example,
/// the same door behind `export_door!`) are each admitted through the one loader on one
/// dispatcher and run ONE script through every plane op, each answer read back. The two
/// transcripts must be identical, step for step, and the linked one must say what the plane's
/// own pure functions say the door answers: the snapshot is `door::endpoint_snapshot_spec`'s, a refused
/// arrival renders the plane's own words at its own status, and a request the plane answers from
/// what it holds is the catalogue's answer.
///
/// RED ARM, kept: the same door with `on_piece` swapped for one that relays the caller's bytes
/// back instead of answering from the catalogue. Its transcript differs at the answer, so a door
/// that stopped answering from what the plane holds cannot pass for this one.
mod both_ways {
    use std::mem::zeroed;
    use std::sync::Arc;

    use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, Outcome, Span, BLOB_OCTETS};
    use busbar_contract::abi::mechanism::door::Door;
    use busbar_contract::abi::mechanism::lifecycle::{
        slot as life, CancelIn, CancelOut, GenIn, RefreshIn, TickIn, TickOut, ValidateIn,
    };
    use busbar_contract::abi::plane::{
        self, slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneOpenIn,
        PlaneOpenOut, PlaneRefreshOut, ProjectIn, ProjectOut, RecordWrite, RefusalIn, RefusalOut,
        ServeIn, ServeOut, UnitCount, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END,
        FROM_KERNEL, PIECE_HAS_STATUS, PIECE_LAST, PRINCIPAL_REQUIRED, REFUSAL_ARRIVE,
        REFUSAL_GATE,
    };
    use busbar_contract::abi::sdk::capture::{CaptureHome, CaptureSlot};
    use busbar_contract::abi::sdk::door::{abi_str, kind_op};
    use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
    use busbar_plane_mcp::codec::{H_MCP_METHOD, H_MCP_NAME, H_PROTOCOL_VERSION, PROTOCOL_VERSION};
    use busbar_plane_mcp::{door, tool_door as plane_door, tool_ops as ops};
    use busbar_plugin_loader::dispatch::kinds::plane::{OwnedSnapshot, Plane};
    use busbar_plugin_loader::dispatch::{
        in_head, load_dropped, load_linked, out_head, rendering_of, Bind, DispatchConfig,
        Dispatcher, Frame, LinkedRow, NoSink, Plugin,
    };
    use serde_json::{json, Value};

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
            // The conformance door is driven op by op and opens nothing: bound as a probe.
            conns: busbar_plugin_loader::dispatch::ConnTable::Probe,
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

    // ── the fixtures ─────────────────────────────────────────────────────────────────────────────────

    /// One fronted server, the section the door's own tests read.
    const SECTION: &[u8] =
        br#"{"fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"}}}"#;
    /// [`SECTION`] as stage 3g deals it to `validate` (`{tools: <section>}`), and a dealt section
    /// the grammar refuses: a server id holding the routing-key separator.
    const DEALT: &[u8] =
        br#"{"tools": {"fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"}}}}"#;
    const BAD_DEALT: &[u8] =
        br#"{"tools": {"my_fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"}}}}"#;
    /// The deployment's public base URL the host lends `open`.
    const PUBLIC_URL: &str = "https://busbar.example";

    /// A stateless-revision `tools/list`.
    const TOOLS_LIST: &[u8] = br#"{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    /// A stateless-revision `tools/call`: sent on, never answered from what the plane holds.
    const TOOLS_CALL: &[u8] = br#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"fs_read_file","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    /// A notification: acknowledged, never answered.
    const NOTICE: &[u8] = br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    /// A body that is not JSON.
    const NOT_JSON: &[u8] = b"{not json";

    const fn field(name: &'static str, value: &'static str) -> Field {
        Field {
            name: abi_str(name),
            value: abi_str(value),
        }
    }

    const LIST_FIELDS: &[Field] = &[
        field(H_PROTOCOL_VERSION, PROTOCOL_VERSION),
        field(H_MCP_METHOD, "tools/list"),
    ];
    const CALL_FIELDS: &[Field] = &[
        field(H_PROTOCOL_VERSION, PROTOCOL_VERSION),
        field(H_MCP_METHOD, "tools/call"),
        field(H_MCP_NAME, "fs_read_file"),
    ];

    /// The route index of `(verb, target)` in the door's route table (its first such row), the claim
    /// an arrival carries.
    fn claim(verb: &str, target: &str) -> u32 {
        let i = door::ROUTES
            .iter()
            .position(|r| r.verb == verb && r.target == target)
            .expect("the door routes it");
        u32::try_from(i).expect("a small table")
    }

    // ── one step of the transcript ───────────────────────────────────────────────────────────────────

    /// What one op answered, read back: the outcome, the status it stated, the bytes it wrote and
    /// the head fields, and anything else the op answers in its own out struct.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Step {
        what: &'static str,
        outcome: Outcome,
        status: u32,
        reply: Vec<u8>,
        fields: Vec<(String, String)>,
        detail: String,
        snapshot: Option<OwnedSnapshot>,
        /// The record writes the answers carried: `(kind, key, value)`.
        records: Vec<(u32, Vec<u8>, Vec<u8>)>,
        /// The audit rows the answers carried (`RECORD_AUDIT` writes): `(outcome, action,
        /// resource)`.
        audits: Vec<(u32, String, String)>,
        /// The last ledger lane an answer named.
        lane: Option<String>,
        /// The counts the answers reported: `(class, amount)`.
        units: Vec<(u32, u64)>,
    }

    impl Step {
        fn new(what: &'static str, outcome: Outcome) -> Self {
            Step {
                what,
                outcome,
                status: 0,
                reply: Vec::new(),
                fields: Vec::new(),
                detail: String::new(),
                snapshot: None,
                records: Vec::new(),
                audits: Vec::new(),
                lane: None,
                units: Vec::new(),
            }
        }
    }

    fn arrive(
        p: &Plugin<Plane>,
        what: &'static str,
        unit: u64,
        (verb, target): (&'static str, &'static str),
        body: &'static [u8],
        fields: &'static [Field],
    ) -> (Step, Option<Vec<u8>>) {
        let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(z(), z());
        (a.input.head, a.out.head) = (in_head(), out_head());
        a.input.unit = unit;
        a.input.claim = claim(verb, target);
        (a.input.method, a.input.target) = (text(verb.as_bytes()), text(target.as_bytes()));
        a.input.body = octets(body);
        (a.input.fields, a.input.fields_len) = (fields.as_ptr(), fields.len());
        let c = p.call(slot::ARRIVE, &mut a);
        let mut s = Step::new(what, c.outcome);
        s.status = a.out.refusal_status;
        s.detail = format!(
            "op_class={} principal_required={} dialect={} refusal={}",
            a.out.op_class,
            a.out.principal_need == PRINCIPAL_REQUIRED,
            a.out.dialect,
            a.out.refusal
        );
        (s, c.error)
    }

    /// One piece as the kernel pushes it: who it is from, its flags and status, the attempt it
    /// starts and the member it names, the far end's head fields and the bytes.
    #[derive(Clone, Copy)]
    struct Push {
        from: u32,
        flags: u32,
        status: u32,
        attempt: u32,
        member: &'static str,
        head: &'static [Field],
        bytes: &'static [u8],
    }

    impl Push {
        /// The caller's whole body.
        const fn caller(bytes: &'static [u8]) -> Self {
            Push {
                from: FROM_CALLER,
                flags: PIECE_LAST,
                status: 0,
                attempt: 0,
                member: "",
                head: &[],
                bytes,
            }
        }

        /// The kernel's ATTEMPT piece naming `member`.
        const fn attempt(member: &'static str) -> Self {
            Push {
                from: FROM_KERNEL,
                flags: 0,
                status: 0,
                attempt: 1,
                member,
                head: &[],
                bytes: b"",
            }
        }

        /// The far end's whole answer: its status, its kept head fields and its body.
        const fn far(status: u32, head: &'static [Field], bytes: &'static [u8]) -> Self {
            Push {
                from: FROM_FAR_END,
                flags: PIECE_LAST | PIECE_HAS_STATUS,
                status,
                attempt: 0,
                member: "",
                head,
                bytes,
            }
        }
    }

    /// One `on_piece` of `unit` with a reply buffer of `cap` bytes, then re-called with the same
    /// `from` and zero bytes while the door answers `more = 1`. The bytes of every call, in order,
    /// the head fields and the request line it wrote, and its flags.
    fn push(p: &Plugin<Plane>, what: &'static str, unit: u64, given: Push, cap: usize) -> Step {
        let mut reply = vec![0_u8; cap];
        let (mut fields, mut arena) = ([z::<OutField>(); 16], vec![0_u8; 4096]);
        let mut records = [z::<RecordWrite>(); 16];
        let mut units = [z::<UnitCount>(); 8];
        let mut out = Step::new(what, Outcome::Ready);
        let mut calls = 0;
        let mut flags = 0;
        let mut line = String::new();
        let mut first = true;
        loop {
            let mut i: OnPieceIn = z();
            i.head = in_head();
            (i.unit, i.from) = (unit, given.from);
            if first {
                (i.flags, i.bytes) = (given.flags, octets(given.bytes));
                (i.status_code, i.attempt_no) = (given.status, given.attempt);
                i.member = text(given.member.as_bytes());
                (i.head_fields, i.head_fields_len) = (given.head.as_ptr(), given.head.len());
            } else {
                i.bytes = octets(b"");
            }
            (i.reply_buf, i.reply_cap) = (reply.as_mut_ptr(), reply.len());
            (i.fields_buf, i.fields_cap) = (fields.as_mut_ptr(), fields.len());
            (i.arena_buf, i.arena_cap) = (arena.as_mut_ptr(), arena.len());
            (i.records_buf, i.records_cap) = (records.as_mut_ptr(), records.len());
            (i.units_buf, i.units_cap) = (units.as_mut_ptr(), units.len());
            let mut o: OnPieceOut = z();
            o.head = out_head();
            let mut f = Frame::new(i, o);
            let c = p.call(slot::ON_PIECE, &mut f);
            out.units.extend(
                units[..f.out.units_written as usize]
                    .iter()
                    .map(|u| (u.class, u.amount)),
            );
            let span = |s: Span| {
                let at = s.offset as usize;
                arena[at..at + s.len as usize].to_vec()
            };
            for r in &records[..f.out.records_written as usize] {
                if r.op == busbar_contract::abi::plane::RECORD_AUDIT {
                    out.audits
                        .push((r.kind, at(&arena, r.key), at(&arena, r.value)));
                } else {
                    out.records.push((r.kind, span(r.key), span(r.value)));
                }
            }
            if f.out.lane.len != 0 {
                out.lane = Some(at(&arena, f.out.lane));
            }
            calls += 1;
            first = false;
            out.outcome = c.outcome;
            if f.out.reply_status != 0 {
                out.status = f.out.reply_status;
            }
            out.fields.extend(
                fields[..f.out.fields_written as usize]
                    .iter()
                    .map(|f| (at(&arena, f.name), at(&arena, f.value))),
            );
            if f.out.verb.len != 0 {
                line = format!("{} {}", at(&arena, f.out.verb), at(&arena, f.out.target));
            }
            flags |= f.out.flags;
            out.reply
                .extend_from_slice(&reply[..usize::try_from(f.out.emitted).expect("small")]);
            if c.outcome != Outcome::Ready || f.out.more == 0 || calls > 256 {
                out.detail = format!(
                    "calls={calls} done={} far={} more={} request={line}",
                    flags & EMIT_DONE != 0,
                    flags & EMIT_TO_FAR_END != 0,
                    f.out.more
                );
                return out;
            }
        }
    }

    /// The caller's whole body, answered through buffers of `cap` bytes.
    fn piece(
        p: &Plugin<Plane>,
        what: &'static str,
        unit: u64,
        from: u32,
        body: &'static [u8],
        cap: usize,
    ) -> Step {
        let given = Push {
            from,
            ..Push::caller(body)
        };
        push(p, what, unit, given, cap)
    }

    fn refusal(
        p: &Plugin<Plane>,
        what: &'static str,
        cause: u32,
        status: u32,
        words: &[u8],
    ) -> Step {
        let (mut reply, mut fields, mut arena) = ([0_u8; 512], [z::<OutField>(); 2], [0_u8; 64]);
        let mut r: Frame<RefusalIn, RefusalOut> = Frame::new(z(), z());
        (r.input.head, r.out.head) = (in_head(), out_head());
        (r.input.cause, r.input.status) = (cause, status);
        r.input.text = AbiStr {
            ptr: words.as_ptr(),
            len: words.len(),
        };
        (r.input.reply_buf, r.input.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (r.input.fields_buf, r.input.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (r.input.arena_buf, r.input.arena_cap) = (arena.as_mut_ptr(), arena.len());
        let c = p.call(slot::REFUSAL, &mut r);
        let mut s = Step::new(what, c.outcome);
        s.status = r.out.status;
        s.reply = reply[..usize::try_from(r.out.reply_written).expect("small")].to_vec();
        s.fields = fields[..r.out.fields_written as usize]
            .iter()
            .map(|f| (at(&arena, f.name), at(&arena, f.value)))
            .collect();
        s
    }

    /// THE SCRIPT: every plane op, each answer read back.
    fn script(p: &Plugin<Plane>) -> Vec<Step> {
        let mut t = Vec::new();

        let mut v = Frame::new(
            ValidateIn {
                head: in_head(),
                settings: octets(BAD_DEALT),
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            },
            out_head(),
        );
        t.push(Step::new(
            "validate refused",
            p.call(life::VALIDATE, &mut v).outcome,
        ));
        v.input.settings = octets(DEALT);
        t.push(Step::new(
            "validate",
            p.call(life::VALIDATE, &mut v).outcome,
        ));

        let mut i: PlaneOpenIn = z();
        i.open.head = in_head();
        (i.open.generation, i.open.settings) = (1, octets(SECTION));
        i.public_url = text(PUBLIC_URL.as_bytes());
        let mut o: PlaneOpenOut = z();
        o.open.head = out_head();
        let (c, snapshot) = p.open(&mut Frame::new(i, o));
        let mut s = Step::new("open", c.outcome);
        s.snapshot = snapshot;
        t.push(s);

        for (what, op) in [("hydrate", slot::HYDRATE), ("start", slot::START)] {
            let mut g = Frame::new(
                GenIn {
                    head: in_head(),
                    generation: 1,
                },
                out_head(),
            );
            t.push(Step::new(what, p.call(op, &mut g).outcome));
        }

        // A request the plane answers from what it holds, written 32 bytes at a time.
        let post = ("POST", "/mcp");
        t.push(arrive(p, "arrive tools/list", 7, post, TOOLS_LIST, LIST_FIELDS).0);
        t.push(piece(
            p,
            "answer tools/list",
            7,
            FROM_CALLER,
            TOOLS_LIST,
            32,
        ));
        // A notification: acknowledged with no body.
        t.push(arrive(p, "arrive notice", 8, post, NOTICE, &[]).0);
        t.push(piece(p, "answer notice", 8, FROM_CALLER, NOTICE, 256));
        // A call the plane sends on: not answered here.
        t.push(arrive(p, "arrive tools/call", 9, post, TOOLS_CALL, CALL_FIELDS).0);
        t.push(piece(
            p,
            "answer tools/call",
            9,
            FROM_CALLER,
            TOOLS_CALL,
            256,
        ));
        // A far end's piece for a unit the plane answered itself.
        t.push(arrive(p, "arrive again", 10, post, TOOLS_LIST, LIST_FIELDS).0);
        t.push(piece(p, "far end", 10, FROM_FAR_END, b"{}", 256));

        // Refused arrivals, each rendered in the plane's own words.
        let (s, words) = arrive(p, "arrive not json", 11, post, NOT_JSON, &[]);
        t.push(s);
        let words = words.unwrap_or_default();
        t.push(refusal(p, "refusal not json", REFUSAL_ARRIVE, 0, &words));
        let (s, words) = arrive(p, "arrive GET /mcp", 12, ("GET", "/mcp"), b"", &[]);
        t.push(s);
        let words = words.unwrap_or_default();
        t.push(refusal(p, "refusal GET /mcp", REFUSAL_ARRIVE, 0, &words));
        let metadata = ("GET", busbar_plane_mcp::tool_claims::DEFAULT_METADATA);
        t.push(arrive(p, "arrive metadata", 13, metadata, b"", &[]).0);
        // A refusal the kernel decided (a gate), in the one error envelope.
        t.push(refusal(p, "refusal gate", REFUSAL_GATE, 403, b"denied"));

        // A trust verb naming no registration: `404`, before anything else.
        let mut s: Frame<ServeIn, ServeOut> = Frame::new(z(), z());
        (s.input.head, s.out.head) = (in_head(), out_head());
        let (mut reply, mut fields, mut arena) = (
            vec![0u8; 256],
            vec![
                OutField {
                    name: Span { offset: 0, len: 0 },
                    value: Span { offset: 0, len: 0 },
                };
                4
            ],
            vec![0u8; 256],
        );
        let target = b"/tools/nope/health";
        s.input.target = AbiStr {
            ptr: target.as_ptr(),
            len: target.len(),
        };
        s.input.route = 2;
        (s.input.reply_buf, s.input.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (s.input.fields_buf, s.input.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (s.input.arena_buf, s.input.arena_cap) = (arena.as_mut_ptr(), arena.len());
        let mut step_serve = Step::new("serve", p.call(slot::SERVE, &mut s).outcome);
        step_serve.status = s.out.status;
        t.push(step_serve);
        let mut j: Frame<ProjectIn, ProjectOut> = Frame::new(z(), z());
        (j.input.head, j.out.head) = (in_head(), out_head());
        t.push(Step::new("project", p.call(slot::PROJECT, &mut j).outcome));

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
        let mut s = Step::new("tick", p.call(life::TICK, &mut k).outcome);
        s.detail = format!("next={}", k.out.next_tick_ns);
        t.push(s);
        let mut x: Frame<CancelIn, CancelOut> = Frame::new(z(), z());
        (x.input.head, x.out.head) = (in_head(), out_head());
        let mut s = Step::new("cancel", p.call(life::CANCEL, &mut x).outcome);
        s.detail = format!("disposition={}", x.out.disposition);
        t.push(s);

        let mut f: Frame<RefreshIn, PlaneRefreshOut> = Frame::new(z(), z());
        (f.input.head, f.out.head) = (in_head(), out_head());
        (f.input.generation, f.input.settings) = (2, octets(b""));
        let (c, snapshot) = p.refresh(&mut f);
        let mut s = Step::new("refresh", c.outcome);
        s.snapshot = snapshot;
        t.push(s);

        let mut g = Frame::new(
            GenIn {
                head: in_head(),
                generation: 1,
            },
            out_head(),
        );
        t.push(Step::new("retire", p.call(life::RETIRE, &mut g).outcome));
        let mut e = Frame::new(in_head(), out_head());
        t.push(Step::new("close", p.call(life::CLOSE, &mut e).outcome));
        t
    }

    /// The head field of a JSON answer.
    fn json_type() -> (String, String) {
        ("content-type".to_string(), "application/json".to_string())
    }

    /// A whole answer's stated length (the served engine's JSON answers stated theirs).
    fn length_of(reply: &[u8]) -> (String, String) {
        ("content-length".to_string(), reply.len().to_string())
    }

    fn step<'a>(t: &'a [Step], what: &str) -> &'a Step {
        t.iter()
            .find(|s| s.what == what)
            .unwrap_or_else(|| panic!("the script has no `{what}` step"))
    }

    fn document(bytes: &[u8]) -> Value {
        serde_json::from_slice(bytes).expect("a JSON document")
    }

    /// The op class index the door's tail holds for `op`.
    fn class(op: busbar_contract::ids::OpClassId) -> u32 {
        door::op_class_index(op).expect("the tail holds it")
    }

    // ── the doors ────────────────────────────────────────────────────────────────────────────────────

    fn linked(d: &Dispatcher) -> Plugin<Plane> {
        let row = LinkedRow::of(plane_door::door).expect("the linked door states its Statement");
        load_linked(&row, bind(d)).expect("the linked door loads")
    }

    /// This crate's dropped-in image, the `mcp_door` example `cargo test` builds. A missing artifact
    /// is a failure, never a skip: this test IS the dropped-in door's proof.
    fn dropped(d: &Dispatcher) -> Plugin<Plane> {
        let exe = std::env::current_exe().expect("the test binary has a path");
        let examples = exe
            .parent()
            .and_then(|d| d.parent())
            .expect("target/<profile>")
            .join("examples");
        let file = busbar_plugin_loader::plugin_library_filename("mcp_door");
        let path = [examples.join(&file), examples.join("deps").join(&file)]
            .into_iter()
            .find(|p| p.exists())
            .unwrap_or_else(|| panic!("the mcp_door example ({file}) is not built"));
        let stated = rendering_of(plane_door::door).expect("the door renders its Statement");
        load_dropped(&path, &stated, bind(d)).expect("the dropped door loads")
    }

    /// The Statement's sections, as the loader reads them, are the grammar's: `tools:` declared and
    /// the `mcp:` endpoint block owned beside it (the door states them as literals, which the
    /// config-schema census reads).
    #[test]
    fn the_statements_sections_are_the_grammars() {
        let d = Dispatcher::new(DispatchConfig::default());
        let served = linked(&d).served();
        assert_eq!(served.section, busbar_plane_mcp::tools_config::SECTION);
        assert_eq!(served.owns, vec![door::ENDPOINT_SECTION]);
    }

    #[test]
    fn the_linked_and_the_dropped_in_door_answer_every_op_the_same() {
        let d = Dispatcher::new(DispatchConfig::default());
        let linked = script(&linked(&d));
        assert_eq!(script(&dropped(&d)), linked, "the dropped-in door");
    }

    /// The linked transcript is the one the plane's own pure functions say the door answers.
    #[test]
    fn the_door_answers_what_the_plane_says() {
        let d = Dispatcher::new(DispatchConfig::default());
        let t = script(&linked(&d));

        // Lifecycle: the grammar judges the section; the snapshot is the door's own.
        assert_eq!(step(&t, "validate refused").outcome, Outcome::Refused);
        assert_eq!(step(&t, "validate").outcome, Outcome::Ready);
        let open = step(&t, "open");
        assert_eq!(open.outcome, Outcome::Ready);
        let snapshot = open.snapshot.as_ref().expect("open publishes a snapshot");
        let spec = door::endpoint_snapshot_spec(Some(PUBLIC_URL));
        assert_eq!(snapshot.generation, 1);
        let claims: Vec<_> = snapshot
            .claims
            .iter()
            .map(|c| {
                (
                    c.verb.as_str(),
                    c.target.as_str(),
                    c.carrier.as_str(),
                    c.flags,
                )
            })
            .collect();
        let want: Vec<_> = spec
            .claims
            .iter()
            .map(|c| {
                (
                    c.verb.as_str(),
                    c.target.as_str(),
                    c.carrier.as_str(),
                    c.flags,
                )
            })
            .collect();
        assert_eq!(claims, want, "the claims are the door's routes");
        assert_eq!(claims.len(), door::ROUTES.len());
        let admin: Vec<_> = snapshot
            .admin_routes
            .iter()
            .map(|r| (r.verb.as_str(), r.target.as_str(), r.flags))
            .collect();
        let want: Vec<_> = spec
            .admin_routes
            .iter()
            .map(|r| (r.verb.as_str(), r.target.as_str(), r.flags))
            .collect();
        assert_eq!(admin, want, "the admin routes are the door's");
        assert_eq!(snapshot.audience, spec.audience);
        assert_eq!(snapshot.resource_metadata, spec.resource_metadata);
        assert_eq!(
            snapshot.audience.as_deref(),
            Some("https://busbar.example/mcp")
        );

        // A request answered from what the plane holds: the catalogue's answer, written whole.
        let a = step(&t, "arrive tools/list");
        assert_eq!(a.outcome, Outcome::Ready);
        assert_eq!(
            a.detail,
            format!(
                "op_class={} principal_required=true dialect=0 refusal=0",
                class(ops::OP_TOOLS_LIST)
            )
        );
        let answer = step(&t, "answer tools/list");
        assert_eq!((answer.outcome, answer.status), (Outcome::Ready, 200));
        assert!(
            answer.detail.starts_with("calls=")
                && answer
                    .detail
                    .ends_with("done=true far=false more=0 request="),
            "{}",
            answer.detail
        );
        let calls: usize = answer.detail["calls=".len()..]
            .split(' ')
            .next()
            .and_then(|n| n.parse().ok())
            .expect("a call count");
        assert!(
            calls > 1,
            "a 32-byte buffer takes the answer over several calls"
        );
        let catalogue = busbar_plane_mcp::catalogue::Catalogue::build(
            1,
            &door::read_tools_section(SECTION).expect("the section reads"),
        );
        let want = catalogue.tools_list(&json!(9), &|_: &str, _: &str| false, |_| false);
        assert_eq!(answer.reply, want, "the catalogue's own bytes");
        assert_eq!(document(&answer.reply)["id"], json!(9));
        assert_eq!(
            answer.fields,
            vec![json_type(), length_of(&answer.reply)],
            "a JSON document says so, and states its length"
        );

        // A notification: acknowledged, no body.
        let a = step(&t, "arrive notice");
        assert_eq!(a.outcome, Outcome::Ready);
        assert!(a
            .detail
            .starts_with(&format!("op_class={} ", class(ops::OP_NOTIFICATION))));
        let n = step(&t, "answer notice");
        assert_eq!(
            (n.outcome, n.status, n.reply.as_slice()),
            (Outcome::Ready, 202, &b""[..])
        );

        // A call naming a tool the section does not approve is the catalogue's refusal, written
        // here; a far end's piece for a unit the plane answered itself is declined.
        assert_eq!(step(&t, "arrive tools/call").outcome, Outcome::Ready);
        let c = step(&t, "answer tools/call");
        assert_eq!((c.outcome, c.status), (Outcome::Ready, 404));
        assert_eq!(
            document(&c.reply)["error"]["data"]["reason"],
            json!("unknown_tool")
        );
        assert_eq!(step(&t, "far end").outcome, Outcome::Refused);

        // Refused arrivals: the plane's own words at its own status.
        let a = step(&t, "arrive not json");
        assert_eq!((a.outcome, a.status), (Outcome::Refused, 400));
        let r = step(&t, "refusal not json");
        assert_eq!((r.outcome, r.status), (Outcome::Ready, 400));
        let body = document(&r.reply);
        assert_eq!(body["error"]["code"], json!(-32700));
        assert_eq!(
            body["error"]["message"],
            json!(busbar_plane_mcp::tool_arrival::NOT_JSON)
        );
        assert_eq!(body["id"], Value::Null);

        let a = step(&t, "arrive GET /mcp");
        assert_eq!((a.outcome, a.status), (Outcome::Refused, 405));
        let r = step(&t, "refusal GET /mcp");
        assert_eq!((r.outcome, r.status), (Outcome::Ready, 405));
        assert_eq!(r.reply, door::method_not_allowed_body());
        assert_eq!(
            r.fields,
            vec![("allow".to_string(), "POST".to_string()), json_type()]
        );

        let a = step(&t, "arrive metadata");
        assert_eq!((a.outcome, a.status), (Outcome::Refused, 404));
        assert!(a
            .detail
            .ends_with(&format!("refusal={}", plane_door::UNSERVED)));

        let r = step(&t, "refusal gate");
        assert_eq!((r.outcome, r.status), (Outcome::Ready, 0));
        let body = document(&r.reply);
        assert_eq!(
            body["error"]["code"],
            json!(busbar_plane_mcp::codec::CODE_REFUSED)
        );
        assert_eq!(body["error"]["message"], json!("denied"));

        // The ops the driver does not call on this door yet, and the rest of the lifecycle.
        // Nothing to restore and no background work; no admin route is served yet, and a body that
        // carries no invocation projects an empty view (no entry, no body: no hook fires on it).
        for what in ["hydrate", "start"] {
            assert_eq!(step(&t, what).outcome, Outcome::Ready, "{what}");
        }
        let serve = step(&t, "serve");
        assert_eq!((serve.outcome, serve.status), (Outcome::Ready, 404));
        assert_eq!(step(&t, "project").outcome, Outcome::Ready, "project");
        // The tick is the clock of the subscriptions held as sessions (ARCHITECT round 5
        // Q-L3B-K6-HTTP (a)): it asks to run again a poll interval on (250 ms).
        assert_eq!(
            step(&t, "tick").detail,
            format!("next={}", 1_000 + 250_000_000)
        );
        assert_eq!(
            step(&t, "cancel").detail,
            format!("disposition={}", plane::CANCEL_ABORTED)
        );
        let refresh = step(&t, "refresh");
        assert_eq!(refresh.outcome, Outcome::Ready);
        let snapshot = refresh.snapshot.as_ref().expect("refresh publishes");
        assert_eq!(snapshot.generation, 2);
        assert_eq!(
            snapshot.audience, spec.audience,
            "the base URL `open` was lent"
        );
        for what in ["retire", "close"] {
            assert_eq!(step(&t, what).outcome, Outcome::Ready, "{what}");
        }
    }

    // ── the relayed call and the entitlement binding ───────────────────────────────────────────────

    /// A HOST whose entitlement answer is a fixed table of `"<kind>:<name>"` grants, and which
    /// serves nothing else: the kernel's entitlement service, as the door asks it. As the kernel's
    /// (`KernelServices::entitled`), a crossing that serves no unit is entitled to nothing: the
    /// loader's request lookup must hand the unit the crossing serves.
    struct Grants(&'static [&'static str]);

    impl busbar_plugin_loader::dispatch::HostServices for Grants {
        fn now(&self) -> busbar_plugin_loader::dispatch::Reading {
            busbar_plugin_loader::dispatch::Reading {
                wall_ns: 0,
                mono_ns: 0,
            }
        }
        fn dest_judge(
            &self,
            _: &str,
            _: u32,
            _: u32,
            _: Option<busbar_plugin_loader::dispatch::Later>,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn records_get(
            &self,
            _: &Caller,
            _: &str,
            _: &[u8],
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn records_list(
            &self,
            _: &Caller,
            _: busbar_contract::services::RecordsList,
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn records_claim(
            &self,
            _: &Caller,
            _: &str,
            _: &[u8],
            _: u64,
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn sign(&self, _: &Caller, _: &[u8]) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn unit_nest(
            &self,
            _: &Caller,
            _: Option<u64>,
            _: busbar_contract::services::NestAsk,
            _: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(Stored::refused(UNSERVED))
        }
        fn work_open(
            &self,
            _: &Caller,
            _: Option<u64>,
            _: &str,
            _: &[u8],
            _: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(Stored::refused(UNSERVED))
        }
        fn work_find(
            &self,
            _: &Caller,
            _: Option<u64>,
            _: &[u8],
            _: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(Stored::refused(UNSERVED))
        }
        fn work_settle(
            &self,
            _: &Caller,
            _: u64,
            _: &[u8],
            _: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(Stored::refused(UNSERVED))
        }
        fn work_resume(
            &self,
            _: &Caller,
            _: Option<u64>,
            _: u64,
            _: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(Stored::refused(UNSERVED))
        }
        fn trust_sight(
            &self,
            _: &Caller,
            _: &str,
            _: &str,
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        /// The kernel's Approve as this section's approvals seed it: `read_file` approved at its
        /// digest, `draft` allowed and pending (ARCHITECT Q3: the door renders the verdict).
        fn trust_serves(
            &self,
            _: &Caller,
            counterparty: &str,
            item: Option<&str>,
            _: Option<&str>,
        ) -> Stored {
            use busbar_contract::abi::host::service::{
                DISTRUST_NONE, DISTRUST_NOT_APPROVED, DISTRUST_UNKNOWN_ITEM,
            };
            Stored::ready(match (counterparty, item) {
                ("fs", Some("read_file")) => DISTRUST_NONE,
                ("fs", Some("draft")) => DISTRUST_NOT_APPROVED,
                _ => DISTRUST_UNKNOWN_ITEM,
            })
        }
        fn trust_due(&self, _: &Caller) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn trust_verify(&self, _: &Caller, _: &str, _: &[u8], _: &[u8]) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn entitlement_check(&self, _: &Caller, unit: Option<u64>, target: &str) -> Stored {
            Stored::ready(if unit.is_some() && self.0.contains(&target) {
                busbar_contract::abi::host::service::ENTITLED
            } else {
                busbar_contract::abi::host::service::NOT_ENTITLED
            })
        }
        fn random_fill(&self, _: u64) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn records_secret(
            &self,
            _: &str,
            _: &str,
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn disk_append(
            &self,
            _: &busbar_contract::services::DiskDest,
            _: Vec<u8>,
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn verify_lookup(
            &self,
            _: &Caller,
            _: &[u8],
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn verify_store(&self, _: &Caller, _: &[u8], _: &[u8], _: u64) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn content_scan(
            &self,
            _: &Caller,
            _: Option<u64>,
            _: &[u8],
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn hook_call(
            &self,
            _: &Caller,
            _: Option<u64>,
            _: busbar_contract::services::HookAsk,
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn snapshot_read(&self, _: &Caller, _: u32) -> busbar_contract::services::Snapshot {
            busbar_contract::services::Snapshot::Refused(UNSERVED)
        }
    }

    use busbar_contract::services::{Caller, Stored, UNSERVED};

    /// Every grant the relayed calls need.
    const ALL: &[&str] = &[
        "mcp_server:fs",
        "mcp_tool:fs_read_file",
        "mcp_tool:fs_draft",
    ];

    /// One server with one approved tool (its `path` argument mirrored in `Mcp-Param-Path`), one
    /// tool awaiting approval, and the `roots` grant with nothing declared to disclose.
    const RELAY_SECTION: &[u8] = br#"{"fs": {"url": "https://mcp.example/fs/rpc?v=1", "pin": {"mechanism": "pinned_pubkey", "key": "sha256/K="}, "grants": {"roots": true}, "tools_allow": {"read_file": {"schema_hash": "sha256:aa", "input_schema": {"type": "object", "properties": {"path": {"type": "string", "x-mcp-header": "Path"}}}}, "draft": {}}}}"#;

    /// A relayed call, its path argument mirrored.
    const RELAY_CALL: &[u8] = br#"{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"fs_read_file","arguments":{"path":"/a"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    const RELAY_FIELDS: &[Field] = &[
        field(H_PROTOCOL_VERSION, PROTOCOL_VERSION),
        field(H_MCP_METHOD, "tools/call"),
        field(H_MCP_NAME, "fs_read_file"),
        field("mcp-param-path", "/a"),
    ];
    /// The same call whose mirrored header disagrees with its body.
    const MISMATCH_FIELDS: &[Field] = &[
        field(H_PROTOCOL_VERSION, PROTOCOL_VERSION),
        field(H_MCP_METHOD, "tools/call"),
        field(H_MCP_NAME, "fs_read_file"),
        field("mcp-param-path", "/b"),
    ];
    /// A call to the tool no schema hash was approved for.
    const DRAFT_CALL: &[u8] = br#"{"jsonrpc":"2.0","id":31,"method":"tools/call","params":{"name":"fs_draft","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    const DRAFT_FIELDS: &[Field] = &[
        field(H_PROTOCOL_VERSION, PROTOCOL_VERSION),
        field(H_MCP_METHOD, "tools/call"),
        field(H_MCP_NAME, "fs_draft"),
    ];
    /// A listing from a caller that prefers an event stream.
    const STREAM_LIST_FIELDS: &[Field] = &[
        field(H_PROTOCOL_VERSION, PROTOCOL_VERSION),
        field(H_MCP_METHOD, "tools/list"),
        field("accept", "text/event-stream, application/json"),
    ];

    const JSON_HEAD: &[Field] = &[field("content-type", "application/json")];
    const SSE_HEAD: &[Field] = &[field("content-type", "text/event-stream")];
    /// The far end's answers: a result, a JSON-RPC error, a result streamed after a progress
    /// frame, and an ask for roots busbar holds the grant for and has nothing to disclose.
    const FAR_OK: &[u8] =
        br#"{"jsonrpc":"2.0","id":0,"result":{"content":[{"type":"text","text":"hi"}]}}"#;
    const FAR_ERROR: &[u8] =
        br#"{"jsonrpc":"2.0","id":0,"error":{"code":-32601,"message":"nope"}}"#;
    const FAR_SSE: &[u8] = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":\"busbar-0\",\"progress\":1}}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{\"content\":[]}}\n\n";
    const FAR_ASK: &[u8] = br#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"}}}}"#;

    /// THE RELAY SCRIPT: the calls a member answers, the ones the plane refuses itself, and the
    /// listings the kernel's entitlement narrows; each answer read back.
    fn relay_script(p: &Plugin<Plane>) -> Vec<Step> {
        let mut t = Vec::new();
        let mut i: PlaneOpenIn = z();
        i.open.head = in_head();
        (i.open.generation, i.open.settings) = (1, octets(RELAY_SECTION));
        i.public_url = text(PUBLIC_URL.as_bytes());
        let mut o: PlaneOpenOut = z();
        o.open.head = out_head();
        t.push(Step::new("open", p.open(&mut Frame::new(i, o)).0.outcome));

        let post = ("POST", "/mcp");
        let far_answers = [
            ("answer ok", FAR_OK, JSON_HEAD),
            ("answer error", FAR_ERROR, JSON_HEAD),
            ("answer stream", FAR_SSE, SSE_HEAD),
            ("answer ask", FAR_ASK, JSON_HEAD),
        ];
        for (n, (what, far, head)) in (40_u64..).zip(far_answers) {
            t.push(arrive(p, "arrive call", n, post, RELAY_CALL, RELAY_FIELDS).0);
            t.push(push(p, "attempt", n, Push::attempt("fs"), 64));
            t.push(push(p, "send", n, Push::caller(RELAY_CALL), 64));
            t.push(push(p, what, n, Push::far(200, head, far), 64));
        }
        t.push(arrive(p, "arrive draft", 50, post, DRAFT_CALL, DRAFT_FIELDS).0);
        t.push(push(p, "attempt draft", 50, Push::attempt("fs"), 64));
        t.push(push(p, "answer draft", 50, Push::caller(DRAFT_CALL), 64));
        t.push(arrive(p, "arrive mismatch", 51, post, RELAY_CALL, MISMATCH_FIELDS).0);
        t.push(push(p, "answer mismatch", 51, Push::caller(RELAY_CALL), 64));
        t.push(arrive(p, "arrive list", 52, post, TOOLS_LIST, LIST_FIELDS).0);
        t.push(push(p, "answer list", 52, Push::caller(TOOLS_LIST), 64));
        t.push(
            arrive(
                p,
                "arrive stream list",
                53,
                post,
                TOOLS_LIST,
                STREAM_LIST_FIELDS,
            )
            .0,
        );
        t.push(push(
            p,
            "answer stream list",
            53,
            Push::caller(TOOLS_LIST),
            64,
        ));
        t.push(project(p, "project call", RELAY_CALL));
        t.push(project(p, "project list", TOOLS_LIST));
        t.push(project_with(
            p,
            "project rewritten",
            RELAY_CALL,
            Some(br#"{"messages":[{"role":"user","content":"{\"path\":\"/redacted\"}"}],"tools":null}"#),
        ));
        t.push(project_with(
            p,
            "project unusable rewrite",
            RELAY_CALL,
            Some(br#"{"messages":[{"role":"user","content":"not arguments"}],"tools":null}"#),
        ));
        t
    }

    /// `project` of `body`: the view's scalars and strings and the projected body, read back.
    fn project(p: &Plugin<Plane>, what: &'static str, body: &'static [u8]) -> Step {
        project_with(p, what, body, None)
    }

    /// `project` of `body` with a request-stage hook's `rewrite`: the view's scalars and strings,
    /// the projected body (`reply`), the prompt view's turns and the rewritten body (`fields`, as
    /// `("turn:<role>", text)` and `("rewritten", body)`), read back through the arena.
    fn project_with(
        p: &Plugin<Plane>,
        what: &'static str,
        body: &'static [u8],
        rewrite: Option<&'static [u8]>,
    ) -> Step {
        let mut arena = vec![0_u8; 4096];
        let mut turns = vec![
            busbar_contract::abi::hook::MessageView {
                role: AbiStr {
                    ptr: std::ptr::null(),
                    len: 0,
                },
                text: AbiStr {
                    ptr: std::ptr::null(),
                    len: 0,
                },
            };
            4
        ];
        let mut j: Frame<ProjectIn, ProjectOut> = Frame::new(z(), z());
        (j.input.head, j.out.head) = (in_head(), out_head());
        j.input.body = octets(body);
        if let Some(rewrite) = rewrite {
            j.input.rewrite = octets(rewrite);
        }
        (j.input.arena_buf, j.input.arena_cap) = (arena.as_mut_ptr(), arena.len());
        (j.input.messages_buf, j.input.messages_cap) = (turns.as_mut_ptr(), turns.len());
        let c = p.call(slot::PROJECT, &mut j);
        let mut s = Step::new(what, c.outcome);
        if c.outcome == Outcome::Ready {
            let base = arena.as_ptr() as usize;
            let view = j.out.view;
            // A string the view leaves unset (NULL) reads as empty, as a span absent from the arena.
            let span_of = |a: AbiStr| {
                if a.ptr.is_null() {
                    return Span { offset: 0, len: 0 };
                }
                Span {
                    offset: u32::try_from(a.ptr as usize - base).expect("in the arena"),
                    len: u32::try_from(a.len).expect("small"),
                }
            };
            s.detail = format!(
                "messages={} chars={} flags={} pool={:?} dialect={}",
                view.message_count,
                view.total_chars,
                view.flags,
                at(&arena, span_of(view.pool)),
                at(&arena, span_of(view.ingress_dialect)),
            );
            if j.out.body.offset != busbar_contract::abi::plane::SPAN_ABSENT {
                s.reply = at(&arena, j.out.body).into_bytes();
            }
            for turn in turns.iter().take(j.out.prompt.messages_len) {
                s.fields.push((
                    format!("turn:{}", at(&arena, span_of(turn.role))),
                    at(&arena, span_of(turn.text)),
                ));
            }
            if j.out.rewritten.len != 0 {
                s.fields
                    .push(("rewritten".to_string(), at(&arena, j.out.rewritten)));
            }
        }
        s
    }

    /// `project`: a call is one turn of tool arguments named by the plane, with its
    /// `{tool, arguments}` body, its view's entry the registered server the tool is served by (the
    /// entry a gate-first plane's hooks are attached to); a listing carries no invocation and
    /// projects an empty view.
    #[test]
    fn a_call_projects_its_invocation_for_the_hooks() {
        let t = relay_script(&linked(&served(ALL)));
        let call = step(&t, "project call");
        assert_eq!(call.outcome, Outcome::Ready);
        let invocation =
            busbar_plane_mcp::call::invocation(RELAY_CALL).expect("a call is an invocation");
        let shape = busbar_contract::ir::facts::IrFacts::shape(&invocation);
        assert_eq!(
            call.detail,
            format!(
                "messages=1 chars={} flags={} pool=\"fs\" dialect=mcp",
                shape.text_chars,
                busbar_contract::abi::hook::REQUEST_HAS_TOOLS
            )
        );
        assert_eq!(
            document(&call.reply),
            json!({ "tool": "fs_read_file", "arguments": { "path": "/a" } })
        );
        let list = step(&t, "project list");
        assert_eq!(list.outcome, Outcome::Ready);
        assert!(
            list.reply.is_empty() && list.fields.is_empty(),
            "a listing projects no invocation and no turn: {list:?}"
        );
    }

    /// `project`'s PROMPT VIEW is the served engine's projection of an invocation: one `user` turn,
    /// the arguments as JSON text (what a content-granted gate or rewrite hook screens).
    #[test]
    fn a_call_projects_one_user_turn_of_its_arguments() {
        let t = relay_script(&linked(&served(ALL)));
        let call = step(&t, "project call");
        assert_eq!(
            call.fields,
            vec![("turn:user".to_string(), r#"{"path":"/a"}"#.to_string())]
        );
    }

    /// A REQUEST-STAGE HOOK'S REWRITE (BUSBAR-1.6.0.md Part 3 section 12, "Hooks"): the plane applies
    /// it in its own dialect (the arguments replaced, every other member as the caller sent it),
    /// answers the rewritten request, and projects THAT request; a rewrite with no usable arguments
    /// object is not applied and the request projects as it came (the served engine's call went out
    /// untouched).
    #[test]
    fn a_rewrite_replaces_the_arguments_and_the_rewritten_call_is_projected() {
        let t = relay_script(&linked(&served(ALL)));
        let rewritten = step(&t, "project rewritten");
        assert_eq!(rewritten.outcome, Outcome::Ready);
        assert_eq!(
            document(&rewritten.reply),
            json!({ "tool": "fs_read_file", "arguments": { "path": "/redacted" } })
        );
        let body = rewritten
            .fields
            .iter()
            .find(|(n, _)| n == "rewritten")
            .map(|(_, v)| v.clone())
            .expect("the rewritten request is answered");
        let mut expected = document(RELAY_CALL);
        expected["params"]["arguments"] = json!({ "path": "/redacted" });
        assert_eq!(document(body.as_bytes()), expected);
        let unusable = step(&t, "project unusable rewrite");
        assert_eq!(unusable.outcome, Outcome::Ready);
        assert!(unusable.fields.iter().all(|(n, _)| n != "rewritten"));
        assert_eq!(
            document(&unusable.reply),
            json!({ "tool": "fs_read_file", "arguments": { "path": "/a" } })
        );
    }

    fn served(grants: &'static [&'static str]) -> Dispatcher {
        Dispatcher::with_services(DispatchConfig::default(), Arc::new(Grants(grants)))
    }

    #[test]
    fn the_linked_and_the_dropped_in_door_relay_the_same() {
        let d = served(ALL);
        let want = relay_script(&linked(&d));
        assert_eq!(relay_script(&dropped(&d)), want, "the dropped-in door");
        let d = served(&[]);
        let want = relay_script(&linked(&d));
        assert_eq!(
            relay_script(&dropped(&d)),
            want,
            "the dropped-in door, entitled to nothing"
        );
    }

    /// What the plane's own pure functions say one relayed call answers.
    fn admitted() -> busbar_plane_mcp::call::AdmittedCall {
        let section = door::read_tools_section(RELAY_SECTION).expect("the section reads");
        let catalogue = busbar_plane_mcp::catalogue::Catalogue::build(1, &section);
        let params = document(RELAY_CALL)["params"].clone();
        let header = |name: &str| (name == "mcp-param-path").then(|| "/a".to_string());
        match busbar_plane_mcp::call::admit_call(
            &catalogue,
            &json!(30),
            Some(&params),
            &header,
            &|_, _| true,
            &mut |_, _| busbar_plane_mcp::ask::AskDecision::Proceed,
        ) {
            busbar_plane_mcp::call::Admission::Go(a) => a,
            other => panic!("the call is admitted: {other:?}"),
        }
    }

    fn settled(far: &[u8], sse: bool) -> (u32, Vec<u8>) {
        let section = door::read_tools_section(RELAY_SECTION).expect("the section reads");
        match busbar_plane_mcp::call::settle_call(
            &admitted(),
            section.servers.get("fs"),
            200,
            far,
            sse,
            0,
        ) {
            busbar_plane_mcp::call::Settled::Answer { status, body, .. } => (status, body),
            other => panic!("an answer: {other:?}"),
        }
    }

    /// The relayed call: the ATTEMPT is taken, the caller's body becomes the request bound for the
    /// member (the dialect's own builder, at the path of the member's URL), and the far end's
    /// answer is settled as the plane's pure settle says, in JSON.
    #[test]
    fn a_relayed_call_is_the_request_and_the_answer_the_plane_says() {
        let t = relay_script(&linked(&served(ALL)));
        let attempt = step(&t, "attempt");
        assert_eq!((attempt.outcome, attempt.reply.len()), (Outcome::Ready, 0));
        let send = step(&t, "send");
        assert_eq!(send.outcome, Outcome::Ready);
        assert!(
            send.detail
                .ends_with("done=false far=true more=0 request=POST /fs/rpc?v=1"),
            "{}",
            send.detail
        );
        let section = door::read_tools_section(RELAY_SECTION).expect("the section reads");
        let def = section.servers.get("fs").expect("registered");
        let want = busbar_plane_mcp::call::outbound(&admitted(), "fs", def, 0, None)
            .expect("the member is reachable");
        assert_eq!(send.reply, want.body, "the dialect builder's body");
        assert_eq!(send.fields, want.fields, "the dialect builder's head");
        assert_eq!(document(&send.reply)["params"]["name"], json!("read_file"));

        let ok = step(&t, "answer ok");
        assert_eq!(
            (ok.outcome, ok.status),
            (Outcome::Ready, settled(FAR_OK, false).0)
        );
        assert_eq!(ok.reply, settled(FAR_OK, false).1);
        assert_eq!(document(&ok.reply)["id"], json!(30));
        assert_eq!(
            document(&ok.reply)["result"]["resultType"],
            json!("complete")
        );
        assert_eq!(ok.fields, vec![json_type(), length_of(&ok.reply)]);
        assert!(ok.detail.contains("done=true far=false"), "{}", ok.detail);
        // THE METER: a call the server answered is counted, once, as one tool call (tail class 0)
        // and the bytes of the document it answered with (tail class 1, a Response class: "the
        // length of the document it just read back"), and the success earns its fee unit (tail
        // class 2, `per_request`). The plane states its counts; the kernel prices them.
        assert_eq!(
            ok.units,
            vec![
                (door::CLASS_FEE_INDEX, 1),
                (0, 1),
                (1, u64::try_from(FAR_OK.len()).expect("a small answer"))
            ],
            "the one tool call the server answered, its answer's bytes, and its fee unit"
        );
        // THE CALL LOG (RULE-CHECK 2026-09-30): the answer carries the call's one chained record,
        // keyed by the caller's chain scope (no caller reference: the ungoverned scope), its suffix
        // the plane's own fields at the host clock's reading (this HOST's clock reads 0).
        assert_eq!(
            ok.records,
            vec![(
                door::RECORD_CALL,
                busbar_plane_mcp::ask::UNGOVERNED.as_bytes().to_vec(),
                busbar_plane_mcp::record::call_suffix(
                    0,
                    "fs",
                    "fs_read_file",
                    "dispatched",
                    "",
                    "sha256:aa",
                    1
                ),
            )],
            "one call record"
        );
        // THE AUDIT ROW (SEAM-L(k)): the dispatched call's one `mcp_tool.call` row, applied, on the
        // published tool; and THE LEDGER LANE (SEAM-L(j)): the published tool, as the served engine
        // priced and ledgered a call.
        assert_eq!(
            ok.audits,
            vec![(
                busbar_contract::abi::plane::AUDIT_APPLIED,
                "mcp_tool.call".to_string(),
                "mcp_tool:fs_read_file".to_string()
            )],
            "one applied audit row"
        );
        assert_eq!(
            send.lane.as_deref(),
            Some("fs_read_file"),
            "the call's lane"
        );

        let error = step(&t, "answer error");
        assert_eq!(error.reply, settled(FAR_ERROR, false).1);
        assert_eq!(document(&error.reply)["result"]["isError"], json!(true));

        let stream = step(&t, "answer stream");
        assert_eq!(
            stream.reply,
            settled(FAR_SSE, true).1,
            "the stream's last event"
        );

        // A GRANTED ASK IS RELAYED under busbar's sealed state (Law 11); a host that signs nothing
        // cannot seal it, so the ask is refused, never answered by busbar.
        let ask = step(&t, "answer ask");
        assert_eq!(ask.status, 403);
        assert_eq!(
            document(&ask.reply)["error"]["data"]["reason"],
            json!("ask_no_sealer")
        );
    }

    /// The calls the plane refuses itself, with a member picked: the catalogue's and the mirror's
    /// refusals, written to the caller as a local answer and never sent on.
    #[test]
    fn a_call_the_plane_refuses_is_answered_and_never_sent() {
        let t = relay_script(&linked(&served(ALL)));
        let draft = step(&t, "answer draft");
        assert_eq!((draft.outcome, draft.status), (Outcome::Ready, 403));
        assert!(
            draft.detail.contains("done=true far=false"),
            "{}",
            draft.detail
        );
        assert_eq!(
            document(&draft.reply)["error"]["data"]["reason"],
            json!("not_approved")
        );
        let mismatch = step(&t, "answer mismatch");
        assert_eq!(mismatch.status, 400);
        assert_eq!(
            document(&mismatch.reply)["error"]["code"],
            json!(busbar_plane_mcp::codec::CODE_HEADER_MISMATCH)
        );
    }

    /// THE ENTITLEMENT BINDING: what a caller sees and may call is the kernel's answer for it.
    #[test]
    fn what_a_caller_sees_and_calls_is_what_the_kernel_entitles() {
        let granted = relay_script(&linked(&served(ALL)));
        let tools = document(&step(&granted, "answer list").reply)["result"]["tools"].clone();
        assert_eq!(tools.as_array().map(Vec::len), Some(2));
        let none = relay_script(&linked(&served(&[])));
        let tools = document(&step(&none, "answer list").reply)["result"]["tools"].clone();
        assert_eq!(tools, json!([]));
        let refused = step(&none, "send");
        assert_eq!((refused.outcome, refused.status), (Outcome::Ready, 404));
        assert_eq!(
            document(&refused.reply)["error"]["data"]["reason"],
            json!("not_granted")
        );
        assert!(
            refused.detail.contains("far=false"),
            "never sent: {}",
            refused.detail
        );
    }

    /// A caller that prefers an event stream is answered with one: the answer after the plane's
    /// own log records.
    #[test]
    fn a_caller_preferring_a_stream_is_answered_with_one() {
        let t = relay_script(&linked(&served(ALL)));
        let s = step(&t, "answer stream list");
        assert_eq!(s.status, 200);
        assert_eq!(
            s.fields,
            vec![
                ("content-type".to_string(), "text/event-stream".to_string()),
                (
                    "cache-control".to_string(),
                    "no-cache, no-store".to_string()
                ),
            ]
        );
        let text = String::from_utf8(s.reply.clone()).expect("text");
        let events: Vec<Value> = text
            .lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .map(|d| serde_json::from_str(d).expect("an event"))
            .collect();
        assert_eq!(events.last().map(|e| e["id"].clone()), Some(json!(9)));
        assert_eq!(events[0]["method"], json!("notifications/message"));
    }

    // ── the red arm ──────────────────────────────────────────────────────────────────────────────────

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

    /// An `on_piece` that relays the caller's bytes back instead of answering from the catalogue.
    struct Echo;
    impl SafeSlot for Echo {
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
            out.set(|o| &o.reply_status, 200);
            out.set(|o| &o.flags, EMIT_DONE);
            Outcome::Ready
        }
    }

    /// The mcp door with `on_piece` swapped for [`Echo`].
    extern "C" fn echo_door() -> *const Door {
        // SAFETY: the macro's `'static` door and its plane table.
        let (d, mut ops) = unsafe {
            let d = &*plane_door::door();
            (d, *d.ops.cast::<plane::Ops>())
        };
        ops.on_piece = kind_op::<plane::Ops, Safe<Echo>, TestCapture, { slot::ON_PIECE }>();
        let ops: &'static plane::Ops = Box::leak(Box::new(ops));
        Box::leak(Box::new(Door {
            ops: std::ptr::from_ref(ops).cast(),
            ..*d
        }))
    }

    #[test]
    fn red_a_door_that_stops_answering_from_the_catalogue_answers_differently() {
        let d = Dispatcher::new(DispatchConfig::default());
        let honest = script(&linked(&d));
        let row = LinkedRow::of(echo_door).expect("the door states its Statement");
        let red = script(&load_linked::<Plane>(&row, bind(&d)).expect("the door loads"));
        let (h, r) = (
            step(&honest, "answer tools/list"),
            step(&red, "answer tools/list"),
        );
        assert_ne!(r.reply, h.reply, "the answer is where the two differ");
        assert_ne!(red, honest);
    }
}
