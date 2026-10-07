//! The plane, driven over the vocabulary the conformance rigs actually send.
//!
//! ## Why this shape, and what it is not
//!
//! The judges of this work are the rigs: the official suite and the in-house battery, both of which
//! speak to a booted node over a socket. These tests take the METHOD VOCABULARY out of the rig's own
//! table and out of the codec's own source, drive each entry through the door's arrival (the one
//! decode step the plane has, since the flip deleted the engine and its in-process `Plane` impl), and
//! assert the operation class and the request id it reads; the door itself is then driven op by op,
//! linked and dropped in, by `both_ways`.

use busbar_plane_a2a::arrival::{self, Disposition};
use busbar_plane_a2a::ops;

/// The rig's own vocabulary table, read out of the file the rig imports it from.
///
/// Reading the rig's source rather than restating it is the whole point: a rig that starts sending a
/// method this plane does not carry must fail HERE, at build time, rather than in a battery run that
/// someone has to interpret.
fn rig_vocabulary(table: &str) -> Vec<(String, String)> {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testing/a2a-supplement/a2asup/transport.py"),
    )
    .expect("the rig's vocabulary table is readable");
    let start = source
        .find(&format!("{table} = {{"))
        .unwrap_or_else(|| panic!("the rig no longer declares {table}"));
    let body = &source[start..];
    let end = body.find('}').expect("the table closes");
    let mut rows = Vec::new();
    for line in body[..end].lines().skip(1) {
        let line = line.trim().trim_end_matches(',');
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().trim_matches('"');
        let value = value.trim().trim_matches('"');
        if !key.is_empty() && !value.is_empty() {
            rows.push((key.to_string(), value.to_string()));
        }
    }
    assert!(!rows.is_empty(), "the rig's {table} table read as empty");
    rows
}

/// One request envelope of this protocol, with the method and identifier a caller would send.
fn request(id: &str, method: &str) -> Vec<u8> {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{{}}}}"#).into_bytes()
}

/// Drive one body through the door's arrival (the JSON-RPC line, no head fields) and hand back the
/// method row it classed the request under and the request id it read.
fn decode(body: &[u8]) -> Result<(ops::MethodRow, serde_json::Value), String> {
    match arrival::decide(body, |_| None) {
        Disposition::Request { row, id, .. } => Ok((*row, id)),
        other => Err(format!("{other:?}")),
    }
}

/// Every method the rig's later-revision table names decodes to a declared class.
#[test]
fn every_method_of_the_later_vocabulary_decodes() {
    // The slot name is the rig's own key for the row; the two tables are paired on it by
    // `the_two_vocabularies_agree_slot_for_slot`, which is where that pairing is actually proved.
    for (_slot, method) in rig_vocabulary("METHODS_1_0") {
        let body = request("1", &method);
        let (row, correlation) = decode(&body)
            .unwrap_or_else(|e| panic!("the rig sends {method} and this plane answered {e:?}"));
        assert_eq!(row.method, method);
        assert_eq!(
            row.wording,
            ops::Wording::Verb,
            "{method} is the verb wording"
        );
        assert_eq!(correlation, 1, "{method} lost its identifier");
    }
}

/// Every method the rig's earlier-revision table names decodes to a declared class.
#[test]
fn every_method_of_the_earlier_vocabulary_decodes() {
    for (_, method) in rig_vocabulary("METHODS_0_3") {
        let body = request("1", &method);
        let (row, _) = decode(&body)
            .unwrap_or_else(|e| panic!("the rig sends {method} and this plane answered {e:?}"));
        assert_eq!(row.method, method);
        assert_eq!(row.wording, ops::Wording::Slashed);
    }
}

/// The two vocabularies agree slot for slot on the class the unit is.
///
/// This is the property that says a caller's choice of wording does not move the money, checked
/// against the rig's OWN pairing of the two tables rather than against this crate's.
#[test]
fn the_two_vocabularies_agree_slot_for_slot() {
    let later = rig_vocabulary("METHODS_1_0");
    let earlier = rig_vocabulary("METHODS_0_3");
    assert_eq!(
        later.len(),
        earlier.len(),
        "the rig's two tables differ in size"
    );
    for (slot, method) in &later {
        let partner = earlier
            .iter()
            .find(|(k, _)| k == slot)
            .unwrap_or_else(|| panic!("the rig names {slot} in one table only"));
        let (a, _) = decode(&request("1", method)).expect("the later wording decodes");
        let (b, _) = decode(&request("1", &partner.1)).expect("the earlier wording decodes");
        assert_eq!(
            a.op, b.op,
            "the two wordings of {slot} price differently: {} against {}",
            a.op, b.op
        );
        assert_eq!(
            a.multi_frame, b.multi_frame,
            "the two wordings of {slot} stream differently"
        );
    }
}

/// Every method the codec's own local-verb table names is one this plane carries.
///
/// The table itself, iterated. This SCRAPED it out of the server half's source once — an
/// `include_str!` over `../../busbar-a2a/src/a2a/local.rs`, then a hand-rolled scan for quoted
/// pieces that look like a method name — which coupled this crate to a sibling its manifest does not
/// name, so the plane could be neither built nor deleted on its own. The table is the codec's now,
/// and the server half's `verb_of` is pinned against it in the crate that owns the match. A method
/// the codec answers and this plane does not carry would arrive here as an unsupported operation.
#[test]
fn every_local_verb_of_the_codec_is_carried() {
    let mut seen = 0usize;
    for method in busbar_plane_a2a::LOCAL_VERB_METHODS {
        assert!(
            decode(&request("1", method)).is_ok(),
            "the codec answers {method} and this plane does not carry it"
        );
        seen += 1;
    }
    assert!(
        seen >= 11,
        "only {seen} verbs were read out of the codec's table"
    );
}

/// THE DOOR, BOTH WAYS (BUSBAR-1.6.0.md Part 2 #2 steps (4) and (5); Part 3 section 12 "Proven
/// by": the plane conformance suite, compiled-in and dropped-in through one table). The plane's
/// `plane_door::door` is loaded LINKED (`load_linked`) and DROPPED (this crate's `a2a_door`
/// example, `load_dropped`) on one dispatcher, and ONE script drives every op through the loader's
/// plane kind: the lifecycle (`validate` in the grammar's own sentence, `open` and `refresh` with
/// their snapshots read through the loader's own copy, `retire`, `tick`, `drive`, `cancel`), the
/// request path (`arrive` on the JSON-RPC and the HTTP+JSON lines, a refused arrival rendered by
/// `refusal` in the plane's words, a kernel's and a gate's refusal at the kernel's status) and
/// `project` (the `{tool, arguments}` view, its session, its prompt view and a request-stage
/// rewrite applied and re-projected). The two transcripts must be identical.
mod both_ways {
    use std::mem::zeroed;
    use std::sync::Arc;

    use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, Outcome, Span, BLOB_OCTETS};
    use busbar_contract::abi::mechanism::lifecycle::{
        slot as life, GenIn, RefreshIn, TickIn, TickOut, ValidateIn,
    };
    use busbar_contract::abi::plane::{
        slot, ArriveIn, ArriveOut, OutField, PlaneCancelIn, PlaneCancelOut, PlaneDriveIn,
        PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, ProjectIn, ProjectOut,
        RefusalIn, RefusalOut, REFUSAL_ARRIVE, REFUSAL_GATE, REFUSAL_KERNEL,
    };
    use busbar_contract::abi::sdk::door::abi_str;
    use busbar_plane_a2a::door::{self, DIALECT_DOCUMENT, DIALECT_FRAMED, DIALECT_TARGET};
    use busbar_plane_a2a::{plane_door, MOUNT_PATH};
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
            instance: Arc::from("both-ways"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: busbar_plugin_loader::dispatch::ConnTable::Probe,
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

    fn text(b: &[u8]) -> AbiStr {
        AbiStr {
            ptr: b.as_ptr(),
            len: b.len(),
        }
    }

    fn at(buf: &[u8], s: Span) -> String {
        String::from_utf8_lossy(&buf[s.offset as usize..(s.offset + s.len) as usize]).into_owned()
    }

    /// A string the door wrote into `arena`, read back by its offset.
    fn in_arena(arena: &[u8], s: AbiStr) -> String {
        if s.ptr.is_null() || s.len == 0 {
            return String::new();
        }
        let start = s.ptr as usize - arena.as_ptr() as usize;
        String::from_utf8_lossy(&arena[start..start + s.len]).into_owned()
    }

    // ── the fixtures ─────────────────────────────────────────────────────────────────────────────

    /// One fronted agent.
    const GOOD: &[u8] =
        br#"{"vendor": {"url": "https://vendor.example/agent", "pin": {"mechanism": "unpinned"}}}"#;
    /// A registration the grammar refuses.
    const BAD: &[u8] =
        br#"{"vendor": {"url": "ftp://vendor.example", "pin": {"mechanism": "unpinned"}}}"#;
    /// The grammar's own sentence for [`BAD`].
    const BAD_SENTENCE: &str =
        "`agents.vendor`: `url:` must be an http:// or https:// endpoint, got `ftp://vendor.example`";
    /// The deployment's public base URL.
    const PUBLIC: &[u8] = b"https://gw.example";

    /// A message sent on the JSON-RPC line, in a conversation.
    const SEND: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","messageId":"m1","contextId":"ctx-7","parts":[{"text":"hi"}]}}}"#;
    /// The same message on the HTTP+JSON line: the body is the params.
    const REST_SEND: &[u8] = br#"{"message":{"role":"ROLE_USER","messageId":"m2","contextId":"ctx-9","parts":[{"text":"hi"}]}}"#;
    /// A method the vocabulary does not list.
    const UNLISTED: &[u8] = br#"{"jsonrpc":"2.0","id":2,"method":"vendor/Thing"}"#;
    /// A redacting hook's rewrite, in the hook stage's `{"messages", "tools"}` reply.
    const REWRITE: &[u8] = br#"{"messages":[{"role":"user","content":"{\"message\":{\"role\":\"user\",\"messageId\":\"m1\",\"parts\":[{\"text\":\"[redacted]\"}]}}"}],"tools":null}"#;
    /// A rewrite with no usable params object: not applied.
    const UNUSABLE: &[u8] =
        br#"{"messages":[{"role":"user","content":"plain words"}],"tools":null}"#;

    /// The route index of `(verb, target)` in the door's table, the claim an arrival carries.
    fn claim(verb: &str, target: &str) -> u32 {
        let i = door::ROUTES
            .iter()
            .position(|r| r.verb == verb && r.target == target)
            .unwrap_or_else(|| panic!("the door routes {verb} {target}"));
        u32::try_from(i).expect("a small table")
    }

    fn mounted(path: &str) -> String {
        format!("{MOUNT_PATH}{path}")
    }

    fn snapshot(s: Option<OwnedSnapshot>) -> String {
        let Some(s) = s else {
            return "no snapshot".to_string();
        };
        let mut out = format!(
            "gen={} audience={} metadata={} openapi_bytes={}",
            s.generation,
            s.audience.as_deref().unwrap_or("-"),
            s.resource_metadata.as_deref().unwrap_or("-"),
            s.openapi.as_ref().map_or(0, Vec::len)
        );
        for c in &s.claims {
            out.push_str(&format!(
                " | {} {} {} flags={} dialect={}",
                c.verb, c.target, c.carrier, c.flags, c.refusal_dialect
            ));
        }
        for r in &s.admin_routes {
            out.push_str(&format!(
                " | admin {} {} flags={}",
                r.verb, r.target, r.flags
            ));
        }
        out
    }

    // ── one step of the script ───────────────────────────────────────────────────────────────────

    /// `arrive` of `body` at `target` on claim `(verb, route)` with `fields`: one line, and the
    /// refused arrival's own words.
    fn arrive(
        p: &Plugin<Plane>,
        unit: u64,
        (verb, route): (&str, &str),
        target: &str,
        body: &[u8],
        fields: &[Field],
    ) -> (String, Vec<u8>) {
        let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(z(), z());
        (a.input.head, a.out.head) = (in_head(), out_head());
        a.input.unit = unit;
        a.input.claim = claim(verb, route);
        (a.input.method, a.input.target) = (text(verb.as_bytes()), text(target.as_bytes()));
        a.input.body = octets(body);
        (a.input.fields, a.input.fields_len) = (fields.as_ptr(), fields.len());
        let c = p.call(slot::ARRIVE, &mut a);
        let words = c.error.clone().unwrap_or_default();
        (
            format!(
                "arrive {unit} {verb} {target} {:?} op={} dialect={} principal={} refusal={} \
                 status={} route={} {}",
                c.outcome,
                a.out.op_class,
                a.out.dialect,
                a.out.principal_need,
                a.out.refusal,
                a.out.refusal_status,
                a.out.route,
                String::from_utf8_lossy(&words)
            ),
            words,
        )
    }

    /// `refusal` of `words` for `cause` at `status` in `dialect`: one line.
    fn refuse(p: &Plugin<Plane>, cause: u32, status: u32, dialect: u32, words: &[u8]) -> String {
        let none = Span { offset: 0, len: 0 };
        let (mut reply, mut arena) = (vec![0_u8; 4096], vec![0_u8; 256]);
        let mut fields = vec![
            OutField {
                name: none,
                value: none,
            };
            4
        ];
        let mut r: Frame<RefusalIn, RefusalOut> = Frame::new(z(), z());
        (r.input.head, r.out.head) = (in_head(), out_head());
        (r.input.cause, r.input.status, r.input.dialect) = (cause, status, dialect);
        r.input.text = text(words);
        (r.input.reply_buf, r.input.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (r.input.fields_buf, r.input.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (r.input.arena_buf, r.input.arena_cap) = (arena.as_mut_ptr(), arena.len());
        let c = p.call(slot::REFUSAL, &mut r);
        let named: Vec<String> = fields[..r.out.fields_written as usize]
            .iter()
            .map(|f| format!("{}: {}", at(&arena, f.name), at(&arena, f.value)))
            .collect();
        format!(
            "refusal cause={cause} dialect={dialect} {:?} status={} marker={} [{}] {}",
            c.outcome,
            r.out.status,
            r.out.marker,
            named.join(", "),
            String::from_utf8_lossy(&reply[..r.out.reply_written as usize])
        )
    }

    /// `project` of `body` at `target` on claim `(verb, route)`, with a request-stage `rewrite`:
    /// one line of the view's scalars and strings, its session, the projected body, the prompt
    /// view's turns and the rewritten body.
    fn project(
        p: &Plugin<Plane>,
        unit: u64,
        (verb, route): (&str, &str),
        target: &str,
        body: &[u8],
        rewrite: Option<&[u8]>,
    ) -> String {
        let mut arena = vec![0_u8; 8192];
        let mut turns = vec![
            busbar_contract::abi::hook::MessageView {
                role: abi_str(""),
                text: abi_str(""),
            };
            4
        ];
        let mut j: Frame<ProjectIn, ProjectOut> = Frame::new(z(), z());
        (j.input.head, j.out.head) = (in_head(), out_head());
        j.input.unit = unit;
        j.input.claim = claim(verb, route);
        j.input.target = text(target.as_bytes());
        j.input.body = octets(body);
        if let Some(rewrite) = rewrite {
            j.input.rewrite = octets(rewrite);
        }
        (j.input.arena_buf, j.input.arena_cap) = (arena.as_mut_ptr(), arena.len());
        (j.input.messages_buf, j.input.messages_cap) = (turns.as_mut_ptr(), turns.len());
        let c = p.call(slot::PROJECT, &mut j);
        if c.outcome != Outcome::Ready {
            return format!("project {unit} {:?}", c.outcome);
        }
        let v = j.out.view;
        let session = if v.session.ptr.is_null() {
            "-".to_string()
        } else {
            in_arena(
                &arena,
                AbiStr {
                    ptr: v.session.ptr,
                    len: v.session.len,
                },
            )
        };
        let turns: Vec<String> = turns
            .iter()
            .take(j.out.prompt.messages_len)
            .map(|t| format!("{}: {}", in_arena(&arena, t.role), in_arena(&arena, t.text)))
            .collect();
        let rewritten = if j.out.rewritten.len == 0 {
            "-".to_string()
        } else {
            at(&arena, j.out.rewritten)
        };
        format!(
            "project {unit} {:?} messages={} chars={} flags={} pool={:?} dialect={} session={} \
             body={} turns=[{}] rewritten={}",
            c.outcome,
            v.message_count,
            v.total_chars,
            v.flags,
            in_arena(&arena, v.pool),
            in_arena(&arena, v.ingress_dialect),
            session,
            at(&arena, j.out.body),
            turns.join(" | "),
            rewritten
        )
    }

    fn generation(generation: u64) -> Frame<GenIn, busbar_contract::abi::mechanism::call::OutHead> {
        Frame::new(
            GenIn {
                head: in_head(),
                generation,
            },
            out_head(),
        )
    }

    /// THE SCRIPT: the lifecycle, then the request path, each answer one line.
    fn script(p: &Plugin<Plane>) -> Vec<String> {
        let mut t = Vec::new();

        let mut reason = vec![0_u8; 1024];
        let mut v = Frame::new(
            ValidateIn {
                head: in_head(),
                settings: octets(BAD),
                err_buf: reason.as_mut_ptr(),
                err_cap: reason.len(),
            },
            out_head(),
        );
        let c = p.call(life::VALIDATE, &mut v);
        t.push(format!(
            "validate bad {:?} {}",
            c.outcome,
            String::from_utf8_lossy(&c.error.unwrap_or_default())
        ));
        v.input.settings = octets(GOOD);
        t.push(format!(
            "validate {:?}",
            p.call(life::VALIDATE, &mut v).outcome
        ));

        let mut o: Frame<PlaneOpenIn, PlaneOpenOut> = Frame::new(z(), z());
        (o.input.open.head, o.out.open.head) = (in_head(), out_head());
        (o.input.open.generation, o.input.open.settings) = (1, octets(GOOD));
        o.input.public_url = text(PUBLIC);
        let (c, s) = p.open(&mut o);
        t.push(format!("open {:?} {}", c.outcome, snapshot(s)));

        let mut r: Frame<RefreshIn, PlaneRefreshOut> = Frame::new(z(), z());
        (r.input.head, r.out.head) = (in_head(), out_head());
        (r.input.generation, r.input.settings) = (2, octets(GOOD));
        let (c, s) = p.refresh(&mut r);
        t.push(format!("refresh {:?} {}", c.outcome, snapshot(s)));
        t.push(format!(
            "retire 1 {:?}",
            p.call(life::RETIRE, &mut generation(1)).outcome
        ));
        for (what, op) in [("hydrate", slot::HYDRATE), ("start", slot::START)] {
            t.push(format!(
                "{what} {:?}",
                p.call(op, &mut generation(2)).outcome
            ));
        }

        let mut k = Frame::new(
            TickIn {
                head: in_head(),
                now_ns: 5,
            },
            TickOut {
                head: out_head(),
                next_tick_ns: 0,
            },
        );
        let c = p.call(life::TICK, &mut k);
        t.push(format!("tick {:?} next={}", c.outcome, k.out.next_tick_ns));
        let mut d: Frame<PlaneDriveIn, PlaneDriveOut> = Frame::new(z(), z());
        (d.input.drive.head, d.out.head) = (in_head(), out_head());
        let c = p.call(life::DRIVE, &mut d);
        t.push(format!(
            "drive {:?} sessions={}",
            c.outcome, d.out.sessions_written
        ));
        let mut x: Frame<PlaneCancelIn, PlaneCancelOut> = Frame::new(z(), z());
        (x.input.cancel.head, x.out.cancel.head) = (in_head(), out_head());
        let c = p.call(life::CANCEL, &mut x);
        t.push(format!(
            "cancel {:?} disposition={}",
            c.outcome, x.out.cancel.disposition
        ));

        // THE REQUEST PATH.
        let document = ("POST", MOUNT_PATH);
        let agent_route = mounted("/agents/{agent_id}");
        let agent = ("POST", agent_route.as_str());
        let agent_target = mounted("/agents/vendor");
        let send_route = mounted(busbar_plane_a2a::ROUTE_MESSAGE_SEND);
        let rest_send = ("POST", send_route.as_str());
        t.push(arrive(p, 1, document, MOUNT_PATH, SEND, &[]).0);
        t.push(arrive(p, 2, agent, &agent_target, SEND, &[]).0);
        t.push(arrive(p, 3, document, MOUNT_PATH, UNLISTED, &[]).0);
        t.push(arrive(p, 4, rest_send, &send_route, REST_SEND, &[]).0);
        let tasks_route = mounted(busbar_plane_a2a::ROUTE_TASKS);
        let tasks_target = mounted("/tasks?pageSize=5&status=working");
        t.push(arrive(p, 5, ("GET", tasks_route.as_str()), &tasks_target, b"", &[]).0);
        let task_route = mounted(busbar_plane_a2a::ROUTE_TASK);
        let bogus = mounted("/tasks/t-1:bogus");
        let (line, rest_words) = arrive(p, 6, ("POST", task_route.as_str()), &bogus, b"", &[]);
        t.push(line);
        t.push(refuse(p, REFUSAL_ARRIVE, 0, DIALECT_TARGET, &rest_words));
        // A media type the line does not read: refused in the plane's own words.
        let plain = [Field {
            name: abi_str("content-type"),
            value: abi_str("text/plain"),
        }];
        let (line, words) = arrive(p, 7, document, MOUNT_PATH, SEND, &plain);
        t.push(line);
        t.push(refuse(p, REFUSAL_ARRIVE, 0, DIALECT_DOCUMENT, &words));
        t.push(refuse(
            p,
            REFUSAL_KERNEL,
            403,
            DIALECT_TARGET,
            b"this key may not reach that agent",
        ));
        t.push(refuse(
            p,
            REFUSAL_GATE,
            451,
            DIALECT_DOCUMENT,
            b"a gate said no",
        ));

        // THE gRPC LINE: a call's one request message, the rpc its target names.
        let service = format!("{}/{{method}}", busbar_plane_a2a::framed::SERVICE_PATH);
        let grpc = ("POST", service.as_str());
        let rpc = |name: &str| format!("{}/{name}", busbar_plane_a2a::framed::SERVICE_PATH);
        let call = [Field {
            name: abi_str("content-type"),
            value: abi_str("application/grpc"),
        }];
        t.push(arrive(p, 8, grpc, &rpc("SendMessage"), &grpc_send(), &call).0);
        let (line, words) = arrive(p, 9, grpc, &rpc("Nope"), b"", &call);
        t.push(line);
        t.push(refuse(p, REFUSAL_ARRIVE, 0, DIALECT_FRAMED, &words));
        let (line, words) = arrive(p, 10, grpc, &rpc("GetTask"), &[0xff, 0xff, 0xff], &call);
        t.push(line);
        t.push(refuse(p, REFUSAL_ARRIVE, 0, DIALECT_FRAMED, &words));
        t.push(refuse(
            p,
            REFUSAL_KERNEL,
            429,
            DIALECT_FRAMED,
            b"this key is over its budget",
        ));

        // THE HOOK VIEW.
        t.push(project(p, 2, agent, &agent_target, SEND, None));
        t.push(project(p, 4, rest_send, &send_route, REST_SEND, None));
        t.push(project(p, 2, agent, &agent_target, SEND, Some(REWRITE)));
        t.push(project(
            p,
            4,
            rest_send,
            &send_route,
            REST_SEND,
            Some(REWRITE),
        ));
        t.push(project(p, 2, agent, &agent_target, SEND, Some(UNUSABLE)));
        t.push(project(
            p,
            5,
            ("GET", tasks_route.as_str()),
            &tasks_target,
            b"",
            None,
        ));
        t.push(project(p, 8, grpc, &rpc("SendMessage"), &grpc_send(), None));
        t
    }

    /// A `SendMessage` call's request message, as a gRPC client encodes it.
    fn grpc_send() -> Vec<u8> {
        use busbar_plane_a2a::proto::pb;
        use prost::Message as _;
        pb::SendMessageRequest {
            message: Some(pb::Message {
                message_id: "m3".into(),
                context_id: "ctx-11".into(),
                role: pb::Role::User as i32,
                parts: vec![pb::Part {
                    content: Some(pb::part::Content::Text("hi".into())),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec()
    }

    // ── the doors ────────────────────────────────────────────────────────────────────────────────

    fn linked(d: &Dispatcher) -> Plugin<Plane> {
        let row = LinkedRow::of(plane_door::door).expect("the linked door states its Statement");
        load_linked(&row, bind(d)).expect("the linked door loads")
    }

    /// This crate's dropped-in image, the `a2a_door` example `cargo test` builds. A missing
    /// artifact is a failure, never a skip: this test IS the dropped-in door's proof.
    fn dropped(d: &Dispatcher) -> Plugin<Plane> {
        let exe = std::env::current_exe().expect("the test binary has a path");
        let examples = exe
            .parent()
            .and_then(|d| d.parent())
            .expect("target/<profile>")
            .join("examples");
        let file = busbar_plugin_loader::plugin_library_filename("a2a_door");
        let path = [examples.join(&file), examples.join("deps").join(&file)]
            .into_iter()
            .find(|p| p.exists())
            .unwrap_or_else(|| panic!("the a2a_door example ({file}) is not built"));
        let stated = rendering_of(plane_door::door).expect("the door renders its Statement");
        load_dropped(&path, &stated, bind(d)).expect("the dropped door loads")
    }

    fn line<'a>(t: &'a [String], prefix: &str) -> &'a str {
        t.iter()
            .find(|l| l.starts_with(prefix))
            .unwrap_or_else(|| panic!("no `{prefix}` line in {t:#?}"))
    }

    fn body_of(line: &str) -> Value {
        let body = line
            .split(" body=")
            .nth(1)
            .and_then(|b| b.split(" turns=").next())
            .expect("a body");
        serde_json::from_str(body).expect("the projected body is JSON")
    }

    #[test]
    fn the_linked_and_the_dropped_in_door_answer_every_op_the_same() {
        let d = Dispatcher::new(DispatchConfig::default());
        let linked = script(&linked(&d));
        assert_eq!(script(&dropped(&d)), linked, "the dropped-in door");
    }

    /// THE gRPC NEED, AS THE DOOR STATES IT (spec line 2026-09-30, the a2a door's third need): the
    /// agents reached over grpc are the same member route as over http (each at its own `url`, an
    /// upstream, its client identity the same anchors), only the transport differs. Read off the
    /// door's own rendered Statement. RED: the door stated two needs and no grpc transport.
    #[test]
    fn the_door_states_its_agents_over_http_and_over_grpc_alike() {
        let rendered = rendering_of(plane_door::door).expect("the door renders its Statement");
        let read =
            busbar_contract::abi::mechanism::rendering::read(&rendered).expect("it reads back");
        let needs = read.needs;
        assert_eq!(needs.len(), 3);
        let (http, grpc) = (
            &needs[door::NEED_AGENT as usize],
            &needs[door::NEED_GRPC as usize],
        );
        assert_eq!(http.transport, "http");
        assert_eq!(grpc.transport, busbar_plane_a2a::claims::FRAMED_TRANSPORT);
        assert_eq!(grpc.transport, "grpc");
        assert_eq!(
            (grpc.direction, grpc.egress_class, grpc.auth.as_str()),
            (http.direction, http.egress_class, http.auth.as_str())
        );
        assert_eq!(grpc.target_from, door::MEMBER_TARGET);
        assert_eq!(grpc.target_from, http.target_from);
        assert_eq!(grpc.trust_from, door::CLIENT_IDENTITY_FROM);
        assert_eq!(grpc.trust_from, http.trust_from);
    }

    /// The linked transcript says what the plane's own functions say the door answers.
    #[test]
    fn the_door_answers_what_the_plane_says() {
        let d = Dispatcher::new(DispatchConfig::default());
        let t = script(&linked(&d));
        assert_eq!(
            t[0],
            format!("validate bad {:?} {BAD_SENTENCE}", Outcome::Refused),
            "the door refuses in the grammar's own sentence"
        );
        assert_eq!(t[1], format!("validate {:?}", Outcome::Ready));
        assert!(
            t[2].starts_with(&format!(
                "open {:?} gen=1 audience=https://gw.example{MOUNT_PATH}",
                Outcome::Ready
            )),
            "{}",
            t[2]
        );
        assert!(
            t[3].starts_with(&format!("refresh {:?} gen=2", Outcome::Ready)),
            "{}",
            t[3]
        );
        assert!(
            line(&t, "arrive 7 ").contains(&format!("{:?}", Outcome::Refused)),
            "a media type the line does not read is refused: {}",
            line(&t, "arrive 7 ")
        );
        for l in t.iter().filter(|l| l.starts_with("refusal")) {
            assert!(
                l.contains(" marker=0 "),
                "the plane never sets the gate marker: {l}"
            );
        }
        assert!(
            line(&t, "refusal cause=1 ").contains("a gate said no"),
            "a gate's veto wears the hook's own words: {}",
            line(&t, "refusal cause=1 ")
        );
        // THE gRPC LINE: a call arrives on the framed dialect; a method the service does not have
        // is UNIMPLEMENTED with no message, a message that does not read INTERNAL, a kernel
        // refusal the status the engine's bridge read off its envelope (`-32004`, UNIMPLEMENTED),
        // each with no media type.
        let sent = line(&t, "arrive 8 ");
        assert!(
            sent.contains(&format!("{:?}", Outcome::Ready))
                && sent.contains(&format!("dialect={DIALECT_FRAMED} ")),
            "{sent}"
        );
        let framed: Vec<&String> = t
            .iter()
            .filter(|l| {
                l.starts_with("refusal cause=")
                    && l.contains(&format!(" dialect={DIALECT_FRAMED} "))
            })
            .collect();
        assert_eq!(framed.len(), 3, "{framed:#?}");
        assert!(
            framed[0].contains(" status=12 ") && framed[0].ends_with("[] "),
            "{}",
            framed[0]
        );
        assert!(
            framed[1].contains(" status=13 ") && framed[1].contains("[] "),
            "{}",
            framed[1]
        );
        assert!(
            framed[2].contains(" status=12 ") && framed[2].ends_with("this key is over its budget"),
            "{}",
            framed[2]
        );
    }

    /// `project` on the gRPC line: the view of the JSON-RPC request the call's message composed.
    #[test]
    fn project_on_the_grpc_line_views_the_composed_request() {
        let d = Dispatcher::new(DispatchConfig::default());
        let t = script(&linked(&d));
        let projected = line(&t, "project 8 ");
        let body = body_of(projected);
        assert_eq!(body["tool"], "SendMessage", "{projected}");
        assert_eq!(
            body["arguments"]["message"]["messageId"], "m3",
            "{projected}"
        );
        assert!(projected.contains("session=ctx-11"), "{projected}");
    }

    /// `project`: the `{tool, arguments}` view of the request (the envelope the HTTP+JSON line's
    /// request spells), the plane's key as the dialect, the addressed agent as the pool, the
    /// message's `contextId` as the session, and one `user` turn of the params as the prompt view.
    #[test]
    fn project_writes_the_hook_view_of_the_request() {
        let d = Dispatcher::new(DispatchConfig::default());
        let t = script(&linked(&d));
        let send: Value = serde_json::from_slice(SEND).expect("json");
        let jsonrpc = line(&t, "project 2 ");
        assert!(
            jsonrpc.contains(&format!("{:?} messages=1 chars=", Outcome::Ready))
                && jsonrpc.contains(r#"pool="vendor" dialect=a2a session=ctx-7 "#),
            "{jsonrpc}"
        );
        assert_eq!(
            body_of(jsonrpc),
            json!({ "tool": "message/send", "arguments": send["params"] })
        );
        assert!(
            jsonrpc.contains(&format!("turns=[user: {}]", send["params"])),
            "{jsonrpc}"
        );
        assert!(jsonrpc.ends_with("rewritten=-"), "{jsonrpc}");
        let rest = line(&t, "project 4 ");
        assert!(
            rest.contains(r#"pool="" dialect=a2a session=ctx-9 "#),
            "{rest}"
        );
        assert_eq!(body_of(rest)["tool"], json!("SendMessage"));
        assert_eq!(
            line(&t, "project 5 "),
            line(&t, "project 5 "),
            "a listing projects its envelope too"
        );
    }

    /// A REQUEST-STAGE HOOK'S REWRITE (BUSBAR-1.6.0.md Part 3 section 12, "Hooks"; the served
    /// engine's invoke rewrite contract): the params are replaced, every other member of the
    /// request is the caller's, the rewritten request is answered as the body the kernel keeps (the
    /// envelope on the JSON-RPC line, the params on the HTTP+JSON line) and is the request
    /// projected; a rewrite with no usable params object is not applied.
    #[test]
    fn a_rewrite_replaces_the_params_and_the_rewritten_request_is_projected() {
        let d = Dispatcher::new(DispatchConfig::default());
        let t = script(&linked(&d));
        let redacted = json!({
            "message": { "role": "user", "messageId": "m1", "parts": [{ "text": "[redacted]" }] }
        });
        let rewrites: Vec<&String> = t
            .iter()
            .filter(|l| l.starts_with("project ") && !l.ends_with("rewritten=-"))
            .collect();
        assert_eq!(rewrites.len(), 2, "{t:#?}");
        let jsonrpc = rewrites[0];
        assert_eq!(body_of(jsonrpc)["arguments"], redacted);
        let kept: Value = serde_json::from_str(
            jsonrpc
                .split(" rewritten=")
                .nth(1)
                .expect("the rewritten body"),
        )
        .expect("json");
        assert_eq!(
            kept,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "message/send", "params": redacted })
        );
        assert!(
            jsonrpc.contains(" session=- "),
            "the rewritten message names no context: {jsonrpc}"
        );
        let rest = rewrites[1];
        let kept: Value = serde_json::from_str(
            rest.split(" rewritten=")
                .nth(1)
                .expect("the rewritten body"),
        )
        .expect("json");
        assert_eq!(
            kept, redacted,
            "the HTTP+JSON line keeps the params as its body"
        );
        let unusable = t
            .iter()
            .filter(|l| l.starts_with("project 2 "))
            .nth(2)
            .expect("the unusable rewrite's line");
        assert_eq!(
            unusable,
            line(&t, "project 2 "),
            "an unusable rewrite is not applied: the request projects as it came"
        );
    }
}
