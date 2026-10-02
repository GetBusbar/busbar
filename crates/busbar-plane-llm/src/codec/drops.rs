// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE DROP PATH (design F3 "Drops"; spec Part 2 #76: "Cross-protocol no-equivalent = drop +
//! warn + covered by a test"; the LLM DIALECT FIDELITY rule: "translate what maps, drop what
//! cannot").
//!
//! A TRANSLATE attempt (the caller's dialect is not the far end's) carries what maps and drops what
//! does not. Every drop, in either direction and from every dialect, goes through [`note`] inside
//! the attempt's [`scope`]: ONE warn naming the wire path that did not cross (wire-lock notation A,
//! e.g. `messages[].content[].type=document`), once per path per attempt, and the path kept for the
//! seam, which records one audit row per path (`egress.control_unrepresentable`,
//! `<path> on <dialect>`, degraded). Nothing is substituted for a dropped member, and a clamp or a
//! cap keeps its behaviour but always warns. Wrong-typed input to a MAPPED field stays the
//! dialect's native error envelope (the readers' refusals), never a drop.
//!
//! WHAT IS UNMAPPED is computed at runtime by walking the input against what the dialect declares:
//! its map file's modelled top-level members (the reader parks every other one in `extra`,
//! [`crate::codec::carry::keep_unmodelled`]), the members its reader parks or carries by code
//! ([`Parked`]) and its content-block grammar ([`Blocks`]).
//!
//! A same-dialect RELAY carries every member by construction and never opens a scope, so a reader
//! running there as the relay's tap drops nothing and says nothing: [`note`] outside a scope is a
//! no-op.

use std::borrow::Cow;
use std::cell::RefCell;

use busbar_contract::diagnostic::Diagnostic;
use serde_json::{Map, Value};

/// Which way a TRANSLATE attempt runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// The caller's request, written for the far end.
    Request,
    /// The far end's answer, written for the caller.
    Response,
}

impl Direction {
    /// The word the warn carries.
    pub const fn as_str(self) -> &'static str {
        match self {
            Direction::Request => "request",
            Direction::Response => "response",
        }
    }
}

/// One TRANSLATE attempt: its direction, the caller's dialect and the far end's.
#[derive(Clone, Copy, Debug)]
pub struct Seam<'a> {
    pub direction: Direction,
    pub ingress: &'a str,
    pub egress: &'a str,
}

/// One member that did not cross: its wire path, the diagnostic its warn carries, and the warn's
/// text.
#[derive(Clone, Debug)]
pub struct Dropped {
    pub path: Cow<'static, str>,
    pub diag: &'static Diagnostic,
    pub message: Cow<'static, str>,
}

impl Dropped {
    pub fn new(
        path: impl Into<Cow<'static, str>>,
        diag: &'static Diagnostic,
        message: impl Into<Cow<'static, str>>,
    ) -> Dropped {
        Dropped {
            path: path.into(),
            diag,
            message: message.into(),
        }
    }
}

/// The open attempt on this thread.
struct Open {
    direction: Direction,
    ingress: String,
    egress: String,
    paths: Vec<String>,
}

thread_local! {
    static OPEN: RefCell<Option<Open>> = const { RefCell::new(None) };
}

/// Puts the enclosing attempt back when a scope ends, by return or by unwind.
struct Restore {
    outer: Option<Option<Open>>,
}

impl Restore {
    fn close(mut self) -> Option<Open> {
        let outer = self.outer.take().unwrap_or(None);
        OPEN.with(|o| o.replace(outer))
    }
}

impl std::ops::Drop for Restore {
    fn drop(&mut self) {
        if let Some(outer) = self.outer.take() {
            OPEN.with(|o| o.replace(outer));
        }
    }
}

/// Run `f` as one TRANSLATE attempt: every [`note`] inside it warns once per path, and the paths
/// come back in the order they were first dropped, for the seam's audit.
pub fn scope<T>(seam: Seam<'_>, f: impl FnOnce() -> T) -> (T, Vec<String>) {
    let open = Open {
        direction: seam.direction,
        ingress: seam.ingress.to_string(),
        egress: seam.egress.to_string(),
        paths: Vec::new(),
    };
    let restore = Restore {
        outer: Some(OPEN.with(|o| o.replace(Some(open)))),
    };
    let out = f();
    let paths = restore.close().map(|o| o.paths).unwrap_or_default();
    (out, paths)
}

/// Drop one member on the open TRANSLATE attempt: one warn naming its wire path (the first time
/// the attempt drops that path) and the path kept for the attempt's audit. Outside an attempt
/// nothing is dropped, so nothing is said.
pub fn note(d: Dropped) {
    OPEN.with(|o| {
        let mut o = o.borrow_mut();
        let Some(open) = o.as_mut() else {
            return;
        };
        if open.paths.iter().any(|p| p.as_str() == d.path.as_ref()) {
            return;
        }
        busbar_contract::diag_warn!(
            d.diag,
            direction = open.direction.as_str(),
            ingress = %open.ingress,
            egress = %open.egress,
            path = %d.path,
            "{}",
            d.message
        );
        open.paths.push(d.path.into_owned());
    });
}

/// What a member a reader parks in `extra` holds of the caller's request, beside the members it
/// parks because its map file does not model them (which are named by their own key).
#[derive(Clone, Copy, Debug)]
pub enum Holds {
    /// Nothing that is dropped: a spelling hint, a member the dialect carries by its own code, or a
    /// stash whose content another declaration names (the block grammar).
    Nothing,
    /// The caller's member at this wire path.
    Path(&'static str),
    /// An object only partly carried by the dialect's code: each member is named `<key>.<member>`,
    /// except the listed ones and those the map file maps.
    Members(&'static [&'static str]),
    /// An object of per-item objects (keyed by item index): each item member is named
    /// `<path>.<member>`, except the listed ones.
    Items(&'static str, &'static [&'static str]),
}

/// A member a dialect's reader parks in `extra` and what it holds of the caller's request.
#[derive(Clone, Copy, Debug)]
pub struct Parked {
    pub key: &'static str,
    pub holds: Holds,
}

/// The wire paths of the request members `extra` holds, none of which a TRANSLATE attempt carries:
/// an unmodelled member by its own key, a parked one as `parked` declares. `mapped` answers whether
/// the dialect's map file maps a nested path (`["generationConfig", "topK"]`).
pub fn extra_paths(
    extra: &Map<String, Value>,
    parked: &[Parked],
    mapped: impl Fn(&[&str]) -> bool,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |p: String| {
        if !out.contains(&p) {
            out.push(p);
        }
    };
    for (key, value) in extra {
        match parked.iter().find(|p| p.key == key).map(|p| p.holds) {
            None => push(key.clone()),
            Some(Holds::Nothing) => {}
            Some(Holds::Path(path)) => push(path.to_string()),
            Some(Holds::Members(except)) => {
                for member in value.as_object().into_iter().flat_map(Map::keys) {
                    if !except.contains(&member.as_str())
                        && !mapped(&[key.as_str(), member.as_str()])
                    {
                        push(format!("{key}.{member}"));
                    }
                }
            }
            Some(Holds::Items(path, except)) => {
                let items = value.as_object().into_iter().flat_map(Map::values);
                for member in items.flat_map(|i| i.as_object().into_iter().flat_map(Map::keys)) {
                    if !except.contains(&member.as_str()) {
                        push(format!("{path}.{member}"));
                    }
                }
            }
        }
    }
    out
}

/// A dialect's content-block grammar, as data: where its blocks are, how a block names its kind,
/// and the kinds its reader models. A block of any other kind does not cross a TRANSLATE attempt.
#[derive(Clone, Copy, Debug)]
pub struct Blocks {
    /// Where the blocks are, in notation-A steps: `["messages[]", "content[]"]`.
    pub at: &'static [&'static str],
    /// The member naming a block's kind (`{"type": "text", ...}`); `None` for a union keyed by its
    /// one kind member (`{"text": ...}`).
    pub tag: Option<&'static str>,
    /// The kinds the reader models.
    pub modelled: &'static [&'static str],
    /// Members a keyed block carries beside its kind (`thoughtSignature`); never a kind.
    pub companions: &'static [&'static str],
}

impl Blocks {
    /// The kind of `block` the reader does not model (`""` for a tagged block that names no kind);
    /// `None` when it models it, or when `block` is not an object at all (wrong-typed input the
    /// reader refuses in its own error envelope).
    fn unmodelled_kind<'v>(&self, block: &'v Value) -> Option<&'v str> {
        let obj = block.as_object()?;
        match self.tag {
            Some(tag) => match obj.get(tag).and_then(Value::as_str) {
                Some(kind) if self.modelled.contains(&kind) => None,
                Some(kind) => Some(kind),
                None => Some(""),
            },
            None => {
                if obj.keys().any(|k| self.modelled.contains(&k.as_str())) {
                    return None;
                }
                obj.keys()
                    .map(String::as_str)
                    .find(|k| !self.companions.contains(k))
            }
        }
    }

    /// Whether the reader models `block`.
    pub fn models(&self, block: &Value) -> bool {
        self.unmodelled_kind(block).is_none()
    }

    /// The notation-A path of every block kind in `body` the reader does not model, each once, in
    /// the order met: `messages[].content[].type=document`, or `contents[].parts[].toolCall` for a
    /// keyed block.
    pub fn unmodelled(&self, body: &Value) -> Vec<String> {
        let mut blocks = Vec::new();
        collect(body, self.at, &mut blocks);
        let at = self.at.join(".");
        let mut out: Vec<String> = Vec::new();
        for kind in blocks.into_iter().filter_map(|b| self.unmodelled_kind(b)) {
            let path = match self.tag {
                Some(_) if kind.is_empty() => at.clone(),
                Some(tag) => format!("{at}.{tag}={kind}"),
                None => format!("{at}.{kind}"),
            };
            if !out.contains(&path) {
                out.push(path);
            }
        }
        out
    }
}

/// Every value at the notation-A steps `at` below `v` (`name[]` walks an array member, `name` an
/// object member).
fn collect<'v>(v: &'v Value, at: &[&str], out: &mut Vec<&'v Value>) {
    let Some((step, rest)) = at.split_first() else {
        out.push(v);
        return;
    };
    match step.strip_suffix("[]") {
        Some(key) => {
            for item in v.get(key).and_then(Value::as_array).into_iter().flatten() {
                collect(item, rest, out);
            }
        }
        None => {
            if let Some(inner) = v.get(*step) {
                collect(inner, rest, out);
            }
        }
    }
}

/// The warn of a request block the far end's dialect has no form for.
pub const UNMODELLED_REQUEST_BLOCK: &str =
    "dropping a request content block on the cross-protocol seam: the source dialect's block \
     kind has no form in the target dialect, so it is NOT forwarded to the backend (nothing is \
     put in its place). Route the request to a same-protocol lane if the block is load-bearing";

/// The warn of an answer block the caller's dialect has no form for.
pub const UNMODELLED_ANSWER_BLOCK: &str =
    "dropping an answer content block on the cross-protocol seam: the upstream dialect's block \
     kind has no form in the caller's dialect, so it is NOT delivered (nothing is put in its \
     place). Route the request to a same-protocol lane if the block is load-bearing";

/// Drop, on the open attempt, every block of `body` that `grammar` does not model, with `message`.
pub fn note_unmodelled_blocks(grammar: &[Blocks], body: &Value, message: &'static str) {
    for path in grammar.iter().flat_map(|g| g.unmodelled(body)) {
        note(Dropped::new(
            path,
            &crate::codec::diagnostics::IR_DROP_UNMODELED_KEYS,
            message,
        ));
    }
}

/// Run `f` as one more piece of a TRANSLATE attempt that spans calls (a stream, one frame per
/// call): a path in `seen` was already dropped and warned on this attempt, so it is not warned
/// again; a path `f` drops for the first time is warned and appended to `seen`, for the audit at
/// the attempt's end.
pub fn scope_more<T>(seam: Seam<'_>, seen: &mut Vec<String>, f: impl FnOnce() -> T) -> T {
    let open = Open {
        direction: seam.direction,
        ingress: seam.ingress.to_string(),
        egress: seam.egress.to_string(),
        paths: std::mem::take(seen),
    };
    let restore = Restore {
        outer: Some(OPEN.with(|o| o.replace(Some(open)))),
    };
    let out = f();
    *seen = restore.close().map(|o| o.paths).unwrap_or_default();
    out
}

/// What a dialect's answers carry in one direction (design F3 "Drops", DF-MAP-IR-GAPS section E):
/// the wire paths its map file lists (`map`, generated) and the ones its code carries that no row
/// names (`code`: a structural member, a keepalive, a terminal error). A member of an answer that
/// is neither, nor under one, does not cross a TRANSLATE attempt, and the walk names it.
#[derive(Clone, Copy, Debug)]
pub struct Carried {
    pub map: &'static [&'static str],
    pub code: &'static [&'static str],
}

/// Where a wire path stands against what a dialect carries.
enum Cover {
    /// It, or a path above it, is carried: its whole subtree crosses.
    Carried,
    /// A carried path lies below it: walk into it.
    Above,
    /// Nothing at or below it is carried: it is dropped.
    Unmapped,
}

/// `path` lies under `top` (`top.x`, `top[]...`, `top.type=x`).
fn under(path: &str, top: &str) -> bool {
    path.len() > top.len()
        && path.starts_with(top)
        && matches!(path.as_bytes()[top.len()], b'.' | b'[')
}

fn join(path: &str, step: &str) -> String {
    if path.is_empty() {
        step.to_string()
    } else {
        format!("{path}.{step}")
    }
}

impl Carried {
    fn all(&self) -> impl Iterator<Item = &&'static str> {
        self.map.iter().chain(self.code.iter())
    }

    fn cover(&self, path: &str) -> Cover {
        let mut above = false;
        for q in self.all() {
            if path == *q || under(path, q) {
                return Cover::Carried;
            }
            above |= under(q, path);
        }
        if above {
            Cover::Above
        } else {
            Cover::Unmapped
        }
    }

    /// The objects at `path` are a union keyed by their `type` member (notation A `type=<arm>`).
    fn uses_arms(&self, path: &str) -> bool {
        let arm = join(path, "type=");
        self.all().any(|q| q.starts_with(&arm))
    }

    /// The notation-A path of every member of `body` (read at `root`, `""` for the document's
    /// root) that this dialect does not carry, the shallowest only, each once, in the order met. A
    /// `null` member carries nothing and is not named.
    pub fn unmapped(&self, root: &str, body: &Value) -> Vec<String> {
        let mut out = Vec::new();
        self.walk(body, root, &mut out);
        out
    }

    fn walk(&self, v: &Value, path: &str, out: &mut Vec<String>) {
        fn push(p: String, out: &mut Vec<String>) {
            if !out.contains(&p) {
                out.push(p);
            }
        }
        match v {
            Value::Array(items) => {
                let p = format!("{path}[]");
                for item in items {
                    self.walk(item, &p, out);
                }
            }
            Value::Object(obj) => {
                let arm = obj
                    .get(crate::codec::keys::TYPE)
                    .and_then(Value::as_str)
                    .filter(|_| self.uses_arms(path));
                let base = match arm {
                    Some(kind) => {
                        let b = join(path, &format!("type={kind}"));
                        match self.cover(&b) {
                            Cover::Carried => return,
                            Cover::Unmapped => return push(b, out),
                            Cover::Above => b,
                        }
                    }
                    None => path.to_string(),
                };
                for (key, child) in obj {
                    if child.is_null() || (arm.is_some() && key == crate::codec::keys::TYPE) {
                        continue;
                    }
                    let p = join(&base, key);
                    match self.cover(&p) {
                        Cover::Carried => {}
                        Cover::Unmapped => push(p, out),
                        Cover::Above => self.walk(child, &p, out),
                    }
                }
            }
            _ => {}
        }
    }
}

/// The warn of an answer member the caller's dialect has no form for.
pub const UNMAPPED_ANSWER_MEMBER: &str =
    "dropping an answer member on the cross-protocol seam: the far end's dialect carries it and \
     the caller's has no form for it, so it is NOT delivered (nothing is put in its place). Route \
     the request to a same-protocol lane if the member is load-bearing";

/// Drop, on the open attempt, every member of `body` (read at `root`) that `carried` does not
/// carry.
pub fn note_unmapped(carried: &Carried, root: &str, body: &Value) {
    for path in carried.unmapped(root, body) {
        note(Dropped::new(
            path,
            &crate::codec::diagnostics::IR_DROP_UNMODELED_KEYS,
            UNMAPPED_ANSWER_MEMBER,
        ));
    }
}

/// Read ONE far-end stream frame on a TRANSLATE attempt, for either host (the engine's stream
/// translator, the plane's own crossing; design F7): the far end's `reader` decodes it, and the
/// drop walk names what the caller's dialect will not get, once per path per STREAM (the paths
/// already dropped ride `state.dropped`, read for the audit at the stream's end).
pub fn read_stream_frame(
    seam: Seam<'_>,
    reader: &dyn crate::codec::proto_codec::ProtocolReader,
    event_type: &str,
    data: &Value,
    state: &mut crate::codec::ir::StreamDecodeState,
) -> Vec<crate::codec::ir::IrStreamEvent> {
    // A same-dialect stream is a relay: its reader is a tap and drops nothing.
    if seam.ingress == seam.egress {
        return reader.read_response_events(event_type, data, state);
    }
    let mut seen = std::mem::take(&mut state.dropped);
    let events = scope_more(seam, &mut seen, || {
        let events = reader.read_response_events(event_type, data, state);
        if let Some(carried) = reader.stream_carried() {
            let root = if reader.stream_keyed_by_event() {
                event_type
            } else {
                ""
            };
            note_unmapped(&carried, root, data);
        }
        events
    });
    state.dropped = seen;
    events
}

#[cfg(test)]
#[path = "tests/drops_tests.rs"]
mod tests;
