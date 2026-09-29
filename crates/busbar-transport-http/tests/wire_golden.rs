// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE 1.5.5 WIRE GOLDEN: step 20's exit test (THE DESIGN §11.11, M4/parity).
//!
//! The golden is what the PUBLISHED 1.5.5 binary put on the wire. The C0 capture cells
//! (`testing/shadow-oracle/golden/1.5.5/cells/`) were recorded from it by busbar-release's `capture`
//! driver: a mock upstream kept every HTTP/1.1 request byte for byte, and every HTTP/2 connection's
//! frames, with each request header field's HPACK representation and bytes.
//!
//! This test reads every such cell and drives the door with the same logical request, as a plane
//! hands it over: the verb, the target, the plane's own header fields in their order, and the body.
//! What the door adds itself is taken OUT of the fields first (`host`, `content-length`, and a
//! trailing `accept: */*`, the client default), so the door must put each back exactly where 1.5.5
//! did. Then the door's bytes are compared with the recording:
//!
//! * HTTP/1.1: the whole request message, byte for byte;
//! * HTTP/2: the connection preface, every frame the client sent up to the request's end (type,
//!   flags, stream, length, and the SETTINGS and WINDOW_UPDATE values), and the request's header
//!   block, field by field, as the HPACK bytes 1.5.5 wrote.
//!
//! The recording masks the run's port. The door is sans-IO and dials nothing, so it is handed a
//! fixed port and its bytes are masked the same way; the one HPACK field that carries the port
//! (`:authority`) is compared by its representation (literal with incremental indexing, name index
//! 1, Huffman) rather than its bytes, exactly as the recording masks it.
//!
//! A missing golden is a FAILURE, never a skip: a wire suite that found nothing to compare proves
//! nothing.

use std::mem::{size_of, zeroed};
use std::path::PathBuf;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, InHead, Op, OutHead, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::transport::{
    slot, BeginIn, ConnFacts, EmitIn, EncodeIn, Field, FramePiece, FramerOut, FramerSink, IngestIn,
    Ops, SIDE_DIAL,
};
use serde_json::Value;

/// The port the door is handed; the recording's `<PORT>` stands for whatever port the run bound.
const PORT: u16 = 40123;

/// The cells this suite must find, at the least: the h1 dialect set, the h2 bearer, the token
/// mint, a GET, the header-order pair. A golden dir missing any of them fails the suite.
const REQUIRED: &[&str] = &[
    "egress.auth__cred-identity__anthropic",
    "egress.auth__cred-identity__openai",
    "egress.auth__cred-identity__gemini",
    "egress.auth__h2__bearer",
    "egress.auth__oauth-cc__mint-refresh",
    "egress.fetch__plugins__url",
    "ops.raw__header-order",
];

fn z<T>() -> T {
    // SAFETY: plain C data; all-zero is valid.
    unsafe { zeroed() }
}

fn s(text: &str) -> AbiStr {
    AbiStr {
        ptr: text.as_ptr(),
        len: text.len(),
    }
}

fn call<I, O>(op: Option<Op>, inst: *mut std::ffi::c_void, i: &mut I, o: &mut O, index: u32) {
    // SAFETY: `I`/`O` lead with their heads.
    unsafe {
        let ih = std::ptr::from_mut(i).cast::<InHead>();
        (*ih).size = size_of::<I>() as u32;
        (*ih).op = index;
        (*std::ptr::from_mut(o).cast::<OutHead>()).size = size_of::<O>() as u32;
    }
    let r = (op.expect("slot"))(
        inst,
        std::ptr::from_ref(i).cast(),
        std::ptr::from_mut(o).cast(),
    );
    assert_eq!(
        r.outcome(),
        busbar_contract::abi::mechanism::call::Outcome::Ready,
        "door op {index} did not answer READY"
    );
}

// ── the golden ───────────────────────────────────────────────────────────────────────────────────

fn golden_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("BUSBAR_WIRE_GOLDEN_DIR") {
        return PathBuf::from(d);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testing/shadow-oracle/golden/1.5.5/cells")
}

/// One request the 1.5.5 binary sent, as the capture recorded it.
struct Recorded {
    cell: String,
    proto: String,
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    raw: Option<String>,
    h2: Option<Value>,
}

fn recorded() -> Vec<Recorded> {
    let dir = golden_dir();
    let mut out = Vec::new();
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("the 1.5.5 wire golden is missing at {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    names.sort();
    for p in names {
        let cell = p.file_stem().unwrap().to_string_lossy().into_owned();
        let v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        if !v
            .get("applied")
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().any(|x| x == "capture"))
        {
            continue;
        }
        let Some(ups) = v.pointer("/body/json/upstream").and_then(Value::as_array) else {
            continue;
        };
        for u in ups {
            let proto = u["proto"].as_str().unwrap_or_default().to_string();
            if proto != "h1" && proto != "h2c" {
                continue;
            }
            out.push(Recorded {
                cell: cell.clone(),
                proto,
                method: u["method"].as_str().unwrap_or_default().to_string(),
                path: u["path"].as_str().unwrap_or_default().to_string(),
                headers: u["headers"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|h| {
                                (
                                    h[0].as_str().unwrap_or_default().to_string(),
                                    h[1].as_str().unwrap_or_default().to_string(),
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                body: u["body"].as_str().unwrap_or_default().as_bytes().to_vec(),
                raw: u.get("raw").and_then(Value::as_str).map(str::to_string),
                h2: u.get("h2").filter(|x| !x.is_null()).cloned(),
            });
        }
    }
    out
}

/// The plane's own fields: what 1.5.5's client added itself is taken out, so the door has to add
/// it back. `host`/`:authority`, `content-length`, the pseudo-fields, and a TRAILING `accept: */*`
/// (the client default; one a caller set earlier in its list is the caller's, and stays).
fn plane_fields(r: &Recorded) -> Vec<(String, String)> {
    let mut f: Vec<(String, String)> = r
        .headers
        .iter()
        .filter(|(n, _)| {
            let n = n.to_ascii_lowercase();
            !n.starts_with(':') && n != "host" && n != "content-length"
        })
        .cloned()
        .collect();
    if f.last()
        .is_some_and(|(n, v)| n.eq_ignore_ascii_case("accept") && v == "*/*")
    {
        f.pop();
    }
    f
}

// ── the door ─────────────────────────────────────────────────────────────────────────────────────

const WIRE_CAP: usize = 1 << 20;

/// The door, opened with a settings blob, framing one dialled connection.
struct Door {
    ops: &'static Ops,
    inst: *mut std::ffi::c_void,
    framing: u64,
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
    now_ns: u64,
    /// Every byte the door handed the host for the far end, in order.
    sent: Vec<u8>,
}

impl Door {
    fn open(settings: &str, agreed: &str) -> Self {
        Self::open_at(settings, agreed, &format!("http://127.0.0.1:{PORT}"))
    }

    fn open_at(settings: &str, agreed: &str, target: &str) -> Self {
        let d = busbar_transport_http::door::door();
        // SAFETY: the door's `'static` table.
        let ops: &'static Ops = unsafe { &*(*d).ops.cast::<Ops>() };
        let mut i: OpenIn = z();
        i.settings = Blob {
            ptr: settings.as_ptr(),
            len: settings.len(),
            fmt: BLOB_JSON,
            flags: 0,
        };
        let mut o: OpenOut = z();
        call(
            ops.head.open,
            std::ptr::null_mut(),
            &mut i,
            &mut o,
            life::OPEN,
        );
        let mut door = Self {
            ops,
            inst: o.instance,
            framing: 0,
            wire: vec![0; WIRE_CAP],
            frame: vec![0; WIRE_CAP],
            pieces: vec![z(); 64],
            now_ns: 5_000_000_000,
            sent: Vec::new(),
        };
        let mut facts: ConnFacts = z();
        facts.size = size_of::<ConnFacts>() as u32;
        facts.agreed_protocol = s(agreed);
        let mut b: BeginIn = z();
        b.side = SIDE_DIAL;
        b.target = s(target);
        b.facts = &facts;
        b.sink = door.sink();
        let mut fo: FramerOut = z();
        call(door.ops.begin, door.inst, &mut b, &mut fo, slot::BEGIN);
        door.framing = fo.framing;
        door.take(&fo);
        door
    }

    fn sink(&mut self) -> FramerSink {
        FramerSink {
            wire: self.wire.as_mut_ptr(),
            wire_cap: WIRE_CAP,
            frame: self.frame.as_mut_ptr(),
            frame_cap: WIRE_CAP,
            pieces: self.pieces.as_mut_ptr(),
            pieces_cap: self.pieces.len(),
            now_monotonic_ns: self.now_ns,
            now_unix_ns: 1_790_000_000_000_000_000,
        }
    }

    fn take(&mut self, o: &FramerOut) {
        let n = o.yielded.wire_len as usize;
        self.sent.extend_from_slice(&self.wire[..n]);
    }

    /// Render `fields` + `body` as the one request message, and send it on `stream`.
    fn request(
        &mut self,
        stream: u64,
        method: &str,
        path: &str,
        fields: &[(String, String)],
        body: &[u8],
    ) {
        let mut all = vec![
            Field {
                name: s("method"),
                value: s(method),
            },
            Field {
                name: s("path"),
                value: s(path),
            },
        ];
        all.extend(fields.iter().map(|(n, v)| Field {
            name: s(n),
            value: s(v),
        }));
        let mut e: EncodeIn = z();
        e.fields = all.as_ptr();
        e.fields_len = all.len();
        e.body = body.as_ptr();
        e.body_len = body.len();
        e.sink = self.sink();
        let mut eo: FramerOut = z();
        call(self.ops.encode, self.inst, &mut e, &mut eo, slot::ENCODE);
        let message = self.wire[..eo.yielded.wire_len as usize].to_vec();
        let mut m: EmitIn = z();
        m.framing = self.framing;
        m.stream = stream;
        m.bytes = message.as_ptr();
        m.len = message.len();
        m.end_of_frame = 1;
        m.sink = self.sink();
        let mut mo: FramerOut = z();
        call(self.ops.emit, self.inst, &mut m, &mut mo, slot::EMIT);
        self.take(&mo);
    }

    /// The far end sent `bytes`.
    #[allow(dead_code)]
    fn ingest(&mut self, bytes: &[u8]) {
        let mut i: IngestIn = z();
        i.framing = self.framing;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.sink = self.sink();
        let mut o: FramerOut = z();
        call(self.ops.ingest, self.inst, &mut i, &mut o, slot::INGEST);
        self.take(&o);
    }
}

impl Drop for Door {
    fn drop(&mut self) {
        let mut c: InHead = z();
        let mut co: OutHead = z();
        call(self.ops.head.close, self.inst, &mut c, &mut co, life::CLOSE);
    }
}

// ── h1 ───────────────────────────────────────────────────────────────────────────────────────────

fn door_h1(r: &Recorded) -> String {
    let mut door = Door::open(r#"{"advanced.upstream_http1_only":true}"#, "http/1.1");
    door.request(1, &r.method, &r.path, &plane_fields(r), &r.body);
    String::from_utf8_lossy(&door.sent).replace(&format!(":{PORT}"), ":<PORT>")
}

// ── h2 ───────────────────────────────────────────────────────────────────────────────────────────

/// One HTTP/2 frame: `(type, flags, stream, payload)`.
type H2Frame = (u8, u8, u32, Vec<u8>);

fn h2_frames(b: &[u8]) -> (Vec<u8>, Vec<H2Frame>) {
    let mut out = Vec::new();
    let mut i = 24.min(b.len());
    while i + 9 <= b.len() {
        let len = usize::from(b[i]) << 16 | usize::from(b[i + 1]) << 8 | usize::from(b[i + 2]);
        let stream = u32::from_be_bytes([b[i + 5], b[i + 6], b[i + 7], b[i + 8]]) & 0x7fff_ffff;
        out.push((b[i + 3], b[i + 4], stream, b[i + 9..i + 9 + len].to_vec()));
        i += 9 + len;
    }
    (b[..24.min(b.len())].to_vec(), out)
}

fn frame_name(t: u8) -> &'static str {
    match t {
        0 => "DATA",
        1 => "HEADERS",
        2 => "PRIORITY",
        3 => "RST_STREAM",
        4 => "SETTINGS",
        5 => "PUSH_PROMISE",
        6 => "PING",
        7 => "GOAWAY",
        8 => "WINDOW_UPDATE",
        9 => "CONTINUATION",
        _ => "OTHER",
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The door's frame, in the recording's shape (the capture mock's `frames_before_end` entry).
fn frame_view((t, flags, stream, p): &H2Frame) -> Value {
    let mut v = serde_json::json!({
        "type": frame_name(*t), "flags": flags, "stream": stream, "length": p.len(),
    });
    if *t == 4 && flags & 1 == 0 {
        v["settings"] = Value::Array(
            p.chunks(6)
                .map(|c| {
                    serde_json::json!([
                        u16::from_be_bytes([c[0], c[1]]),
                        u32::from_be_bytes([c[2], c[3], c[4], c[5]])
                    ])
                })
                .collect(),
        );
    }
    if *t == 8 && p.len() == 4 {
        v["increment"] =
            serde_json::json!(u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff);
    }
    v
}

/// Compare one recorded h2 request's header block with the door's, field by field.
fn compare_block(cell: &str, want_fields: &[Value], block: &[u8]) -> Result<(), String> {
    let mut at = 0usize;
    for f in want_fields {
        let name = f["name"].as_str().unwrap_or_default();
        let bytes = f["bytes"].as_str().unwrap_or_default();
        if bytes == "<PORT-BEARING>" {
            // Literal with incremental indexing, name index 1 (`:authority`): 0x41, then the
            // Huffman bit and a one-byte length.
            let idx = f["index"].as_u64().unwrap_or(0);
            let huff = f["huffman_value"].as_bool().unwrap_or(false);
            if f["repr"] != "literal-incremental" || idx != 1 {
                return Err(format!(
                    "{cell}: a masked field other than :authority ({f})"
                ));
            }
            let (Some(&b0), Some(&b1)) = (block.get(at), block.get(at + 1)) else {
                return Err(format!("{cell}: the door's block ends before {name}"));
            };
            if b0 != 0x41 || (b1 & 0x80 != 0) != huff || b1 & 0x7f == 0x7f {
                return Err(format!(
                    "{cell}: {name}: the door wrote {b0:#04x} {b1:#04x}, 1.5.5 wrote literal-incremental index 1 huffman={huff}"
                ));
            }
            at += 2 + usize::from(b1 & 0x7f);
            continue;
        }
        let want: Vec<u8> = (0..bytes.len() / 2)
            .map(|i| u8::from_str_radix(&bytes[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        let got = block.get(at..at + want.len()).unwrap_or(&[]);
        if got != want.as_slice() {
            return Err(format!(
                "{cell}: field {name}: 1.5.5 wrote {} ({}), the door wrote {}",
                bytes,
                f["repr"],
                hex(&block[at.min(block.len())..(at + want.len()).min(block.len())])
            ));
        }
        at += want.len();
    }
    if at != block.len() {
        return Err(format!(
            "{cell}: the door's block carries {} bytes past 1.5.5's fields: {}",
            block.len() - at,
            hex(&block[at..])
        ));
    }
    Ok(())
}

/// Every recorded request on ONE h2 connection, driven through ONE door framing.
fn check_h2_connection(cell: &str, reqs: &[&Recorded]) -> Result<(), String> {
    let mut door = Door::open(r#"{"advanced.upstream_h2_prior_knowledge":true}"#, "");
    for r in reqs {
        let h2 =
            r.h2.as_ref()
                .ok_or_else(|| format!("{cell}: an h2c entry with no h2 detail"))?;
        let stream = h2["stream"].as_u64().unwrap_or(1);
        door.request(stream, &r.method, &r.path, &plane_fields(r), &r.body);
        let (preface, frames) = h2_frames(&door.sent);
        if preface != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
            return Err(format!("{cell}: the door's preface is {}", hex(&preface)));
        }
        let want = h2["frames_before_end"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let got: Vec<Value> = frames.iter().map(frame_view).collect();
        let port_bearing = |w: &Value| w["length"] == "<PORT-BEARING>";
        let lines = |fs: &[Value]| {
            fs.iter()
                .map(|f| {
                    format!(
                        "{}(flags={},stream={},len={})",
                        f["type"], f["flags"], f["stream"], f["length"]
                    )
                })
                .collect::<Vec<_>>()
                .join(" ")
        };
        let same = want.len() == got.len()
            && want.iter().zip(&got).all(|(w, g)| {
                if port_bearing(w) {
                    let mut w = w.clone();
                    w["length"] = g["length"].clone();
                    &w == g
                } else {
                    w == g
                }
            });
        if !same {
            return Err(format!(
                "{cell} stream {stream}: frames differ\n  1.5.5: {}\n  door:  {}",
                lines(&want),
                lines(&got)
            ));
        }
        // This request's header block: the HEADERS (+CONTINUATION) on its stream.
        let block: Vec<u8> = frames
            .iter()
            .filter(|(t, _, st, _)| (*t == 1 || *t == 9) && u64::from(*st) == stream)
            .flat_map(|(_, _, _, p)| p.clone())
            .collect();
        let fields = h2["fields"].as_array().cloned().unwrap_or_default();
        compare_block(cell, &fields, &block)?;
    }
    Ok(())
}

/// The value of an HTTP/1.1 message's `content-length` field.
fn content_length(msg: &str) -> Option<String> {
    let head = msg.split("\r\n\r\n").next()?;
    head.split("\r\n")
        .find_map(|l| l.strip_prefix("content-length: "))
        .map(str::to_string)
}

/// Whether a recorded body carries one of the recorder's masks (`<JWT>`, `<PKCE>`, `<REQUEST-ID>`…).
fn has_mask(body: &[u8]) -> bool {
    let t = String::from_utf8_lossy(body);
    let mut rest = t.as_ref();
    while let Some(i) = rest.find('<') {
        rest = &rest[i + 1..];
        let Some(j) = rest.find('>') else { break };
        if j > 0
            && rest[..j]
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b == b'-')
        {
            return true;
        }
        rest = &rest[j..];
    }
    false
}

// ── the suite ────────────────────────────────────────────────────────────────────────────────────

#[test]
fn the_door_puts_1_5_5_s_recorded_wire_bytes_on_the_wire() {
    let all = recorded();
    let cells: std::collections::BTreeSet<&str> = all.iter().map(|r| r.cell.as_str()).collect();
    for want in REQUIRED {
        assert!(
            cells.contains(want),
            "the 1.5.5 wire golden has no `{want}` cell in {}",
            golden_dir().display()
        );
    }
    let mut failures = Vec::new();
    let (mut h1, mut h2) = (0, 0);
    let mut length_masked = 0;
    for r in all.iter().filter(|r| r.proto == "h1") {
        let want = r.raw.as_deref().expect("an h1 capture keeps its raw bytes");
        let mut got = door_h1(r);
        // Where the recording masked part of the BODY (a signed assertion, a PKCE verifier, a
        // run-varying id), the door is handed the masked body, so its `content-length` counts the
        // mask; the recording's own (numeric, or `<LEN>`) stands. Only that header's value is
        // taken over: its name, case and position are still the door's to get right.
        if let (Some(w), Some(g)) = (content_length(want), content_length(&got)) {
            if w != g && (w == "<LEN>" || has_mask(&r.body)) {
                got = got.replacen(
                    &format!("content-length: {g}\r\n"),
                    &format!("content-length: {w}\r\n"),
                    1,
                );
                length_masked += 1;
            }
        }
        if got == want {
            h1 += 1;
        } else {
            failures.push(format!(
                "{} {} {}:\n  1.5.5: {want:?}\n  door:  {got:?}",
                r.cell, r.method, r.path
            ));
        }
    }
    let mut by_cell: std::collections::BTreeMap<&str, Vec<&Recorded>> = Default::default();
    for r in all.iter().filter(|r| r.proto == "h2c") {
        by_cell.entry(r.cell.as_str()).or_default().push(r);
    }
    for (cell, reqs) in by_cell {
        match check_h2_connection(cell, &reqs) {
            Ok(()) => h2 += reqs.len(),
            Err(e) => failures.push(e),
        }
    }
    println!(
        "PROOF wire golden: {h1} h1 requests ({length_masked} with a masked body length) and {h2} h2 requests byte-identical to 1.5.5"
    );
    assert!(
        failures.is_empty(),
        "{} differ from 1.5.5:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Over a secured connection that agreed `h2`, the request is 1.5.5's h2c request with ONE byte
/// different: `:scheme` is `https`, HPACK static index 7 (`0x87`), where cleartext is index 6
/// (`0x86`). The recorded h2c bearer cell is the rest of the proof; this pins that byte.
#[test]
fn an_h2_request_over_a_secured_connection_says_scheme_https() {
    let mut door = Door::open_at("{}", "h2", "https://api.example.com");
    let fields = vec![
        ("authorization".to_string(), "Bearer x".to_string()),
        ("content-type".to_string(), "application/json".to_string()),
    ];
    door.request(1, "POST", "/v1/chat/completions", &fields, b"{}");
    let (preface, frames) = h2_frames(&door.sent);
    assert_eq!(preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    let block = &frames
        .iter()
        .find(|(t, _, st, _)| *t == 1 && *st == 1)
        .expect("a HEADERS frame on stream 1")
        .3;
    assert_eq!(
        &block[..2],
        &[0x83, 0x87],
        ":method POST then :scheme https, both indexed"
    );
}
