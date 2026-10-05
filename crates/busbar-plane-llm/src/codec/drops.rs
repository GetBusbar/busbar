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
    /// How [`note`] names the drop: by `path` as given, or by the source dialect's wire path for
    /// an IR member or a content block.
    pub at: At,
    pub diag: &'static Diagnostic,
    pub message: Cow<'static, str>,
}

impl Dropped {
    /// A drop named by its wire path.
    pub fn new(
        path: impl Into<Cow<'static, str>>,
        diag: &'static Diagnostic,
        message: impl Into<Cow<'static, str>>,
    ) -> Dropped {
        Dropped {
            path: path.into(),
            at: At::Wire,
            diag,
            message: message.into(),
        }
    }

    /// A drop of the IR slot `name`, named on the open attempt by the caller's wire path for it
    /// (by `name` itself when the caller's map file has no row for it).
    pub fn slot(
        name: &'static str,
        diag: &'static Diagnostic,
        message: impl Into<Cow<'static, str>>,
    ) -> Dropped {
        Dropped {
            path: Cow::Borrowed(name),
            at: At::Slot(&[]),
            diag,
            message: message.into(),
        }
    }

    /// The IR names whose rows spell this slot drop's wire path, first found wins (default: the
    /// slot's own name). The reasoning gate names an effort ask by the effort rows and a budget ask
    /// by the budget rows.
    pub fn rows(mut self, rows: &'static [&'static str]) -> Dropped {
        self.at = At::Slot(rows);
        self
    }

    /// A writer's drop of `member` ([`writer_drop!`]).
    pub fn member(
        member: Member,
        diag: &'static Diagnostic,
        message: impl Into<Cow<'static, str>>,
    ) -> Dropped {
        match member {
            Member::Slot(name, rows) => Dropped::slot(name, diag, message).rows(rows),
            Member::Block(kind) => Dropped {
                path: Cow::Borrowed(kind),
                at: At::Block,
                diag,
                message: message.into(),
            },
            Member::Wire(path) => Dropped::new(path, diag, message),
        }
    }
}

/// How a [`Dropped`] is named.
#[derive(Clone, Copy, Debug)]
pub enum At {
    /// `path` is the wire path.
    Wire,
    /// `path` is an IR member's name: on a request, the caller's wire path for it ([`wire_path`],
    /// read from the listed IR names' rows, or `path`'s own when the list is empty).
    Slot(&'static [&'static str]),
    /// `path` is an IR block kind: the source dialect's content-block container
    /// ([`Blocks::at`]), the block's kind in the source dialect's spelling as the warn's `kind`.
    Block,
}

/// What a writer drops ([`writer_drop!`]): an IR member, or a content block of an IR kind.
#[derive(Clone, Copy, Debug)]
pub enum Member {
    /// The IR member `name`, named by the first of the listed IR names the source dialect has a row
    /// for (empty: `name` itself).
    Slot(&'static str, &'static [&'static str]),
    /// A content block of the IR kind (`image`, `document`, `audio`, `video`, `thinking`, `text`,
    /// `tool_use`, `tool_result`), named by the source dialect's block container.
    Block(&'static str),
    /// A member of the SOURCE dialect's own wire at this path (notation A): what a READER drops of
    /// the bytes it reads (the caller's on a request, the far end's on an answer) because the IR has
    /// no place for it.
    Wire(&'static str),
}

/// The IR member `name`, by its own rows.
pub const fn member(name: &'static str) -> Member {
    Member::Slot(name, &[])
}

/// The reasoning ask: named by the caller's effort row, else its budget row.
pub const REASONING: Member = Member::Slot(
    "reasoning",
    &["reasoning_effort", "reasoning", "thinking_budget"],
);

/// A content block of the IR kind `kind`.
pub const fn block(kind: &'static str) -> Member {
    Member::Block(kind)
}

/// A member of the reading dialect's own wire at `path` (a reader's drop).
pub const fn wire(path: &'static str) -> Member {
    Member::Wire(path)
}

/// The IR's content-block kinds ([`crate::codec::ir::IrBlock::kind_name`]), spelled once: the
/// dialects' `IR_BLOCK_KINDS` tables and their writers' block drops name them from here.
pub mod kind {
    pub const TEXT: &str = "text";
    pub const IMAGE: &str = "image";
    pub const DOCUMENT: &str = "document";
    pub const AUDIO: &str = "audio";
    pub const VIDEO: &str = "video";
    pub const THINKING: &str = "thinking";
    pub const TOOL_USE: &str = "tool_use";
    pub const TOOL_RESULT: &str = "tool_result";
    pub const HOSTED_TOOL: &str = "hosted_tool";
}

/// A text block.
pub const TEXT: Member = block(kind::TEXT);
/// An image block.
pub const IMAGE: Member = block(kind::IMAGE);
/// A document block.
pub const DOCUMENT: Member = block(kind::DOCUMENT);
/// An audio block.
pub const AUDIO: Member = block(kind::AUDIO);
/// A video block.
pub const VIDEO: Member = block(kind::VIDEO);
/// A thinking (reasoning) block; the reasoning ASK is [`REASONING`].
pub const THINKING: Member = block(kind::THINKING);
/// A provider-run tool's record.
pub const HOSTED_TOOL: Member = block(kind::HOSTED_TOOL);

/// The IR request members a drop names, spelled once (the dialects' `REQUEST_CODE_NAMES` and
/// `UNREAD` tables name them from here).
pub mod name {
    pub const N: &str = "n";
    pub const REASONING: &str = "reasoning";
    pub const THINKING_BUDGET: &str = "thinking_budget";
    pub const CACHE_CONTROL: &str = "cache_control";
    pub const STOP: &str = "stop";
    pub const TOOLS: &str = "tools";
    pub const TOOL_CHOICE: &str = "tool_choice";
    pub const PARALLEL_TOOL_CALLS: &str = "parallel_tool_calls";
    pub const RESPONSE_FORMAT: &str = "response_format";
    pub const METADATA: &str = "metadata";
    pub const OUTPUT_MODALITIES: &str = "output_modalities";
    pub const TOP_LOGPROBS: &str = "top_logprobs";
    pub const TOP_K: &str = "top_k";
    pub const SERVICE_TIER: &str = "service_tier";
    pub const LOGPROBS: &str = "logprobs";
    pub const STRICT: &str = "strict";
}

/// The IR members a writer drops by name.
pub const TOOLS: Member = member(name::TOOLS);
pub const TOOL_CHOICE: Member = member(name::TOOL_CHOICE);
pub const PARALLEL_TOOL_CALLS: Member = member(name::PARALLEL_TOOL_CALLS);
pub const RESPONSE_FORMAT: Member = member(name::RESPONSE_FORMAT);
pub const METADATA: Member = member(name::METADATA);
pub const OUTPUT_MODALITIES: Member = member(name::OUTPUT_MODALITIES);
pub const TOP_LOGPROBS: Member = member(name::TOP_LOGPROBS);
pub const TOP_K: Member = member(name::TOP_K);
pub const SERVICE_TIER: Member = member(name::SERVICE_TIER);
pub const LOGPROBS: Member = member(name::LOGPROBS);
pub const STRICT: Member = member(name::STRICT);

/// Whether a TRANSLATE attempt is open on this thread.
pub fn is_open() -> bool {
    OPEN.with(|o| o.borrow().is_some())
}

/// THE WRITER DROP (and a reader's, by [`wire`]): a member or block that does not cross. Inside a
/// TRANSLATE attempt it is [`note`]d (one warn per path naming the source dialect's wire path, and
/// the audit); outside one (a same-dialect write, a direct writer call, a relay's tap) the
/// writer's own warn is emitted unchanged and nothing is audited. `fields` are the writer warn's own fields (each followed by a comma).
///
/// `writer_drop!(member("tool_choice"), &DIAG, [count = n,], "dropping ... {x}", x = 1)`
macro_rules! writer_drop {
    ($member:expr, $diag:expr, [$($field:tt)*], $($msg:tt)+) => {{
        if $crate::codec::drops::is_open() {
            $crate::codec::drops::note($crate::codec::drops::Dropped::member(
                $member,
                $diag,
                format!($($msg)+),
            ));
        } else {
            tracing::warn!($($field)* $($msg)+);
        }
    }};
}
pub(crate) use writer_drop;

/// THE NAME RESOLVER: the wire path (notation A, as its map file's rows spell it) at which the
/// request dialect `dialect` carries the IR name `name` ([`crate::codec::carry::wire_path`]; the
/// first of `rows` it has a row for, when `rows` lists any), else `name` itself. Gemini's `n` is
/// `generationConfig.candidateCount`, OpenAI's `n` is `n`.
pub fn wire_path(dialect: &str, name: &str, rows: &[&str]) -> String {
    resolve(dialect, name, rows).unwrap_or_else(|| name.to_string())
}

/// [`wire_path`]: a map-file row for it, else the path the dialect's reader carries it from by code
/// ([`crate::codec::proto_codec::ProtocolReader::request_code_names`]); `None` when it has neither
/// (the drop is then named by the IR name, which the drop-names census holds at 0).
pub fn resolve(dialect: &str, name: &str, rows: &[&str]) -> Option<String> {
    let rows = if rows.is_empty() { &[name][..] } else { rows };
    crate::codec::proto_codec::with_reader(dialect, |r| {
        rows.iter().find_map(|n| {
            crate::codec::carry::wire_path(r.request_map(), n).or_else(|| {
                r.request_code_names()
                    .iter()
                    .find(|(ir, _)| ir == n)
                    .map(|(_, path)| path.to_string())
            })
        })
    })
    .flatten()
}

/// A content block of the IR kind `kind` in the dialect `dialect`'s `direction` grammar: its
/// container path (notation A) and its kind as the dialect spells it; `None` for either the
/// dialect does not declare.
pub fn block_path(
    dialect: &str,
    direction: Direction,
    kind: &str,
) -> (Option<String>, Option<&'static str>) {
    crate::codec::proto_codec::with_reader(dialect, |r| {
        let grammar = match direction {
            Direction::Request => r.request_blocks(),
            Direction::Response => r.response_blocks(),
        };
        let at = grammar.first().map(|g| g.at.join("."));
        let spelled = r
            .block_kinds()
            .iter()
            .find(|(ir, _)| *ir == kind)
            .map(|(_, wire)| *wire);
        (at, spelled)
    })
    .unwrap_or((None, None))
}

/// The CALLER's wire path for the IR name `name`, for a drop warned outside [`note`] (a writer's
/// control warn): on an open request attempt, [`wire_path`] in the caller's dialect; else `name`.
pub fn caller_path(name: &str) -> String {
    let ingress = OPEN.with(|o| {
        o.borrow()
            .as_ref()
            .filter(|o| o.direction == Direction::Request)
            .map(|o| o.ingress.clone())
    });
    match ingress {
        Some(ingress) => wire_path(&ingress, name, &[]),
        None => name.to_string(),
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
        // The source side: the caller's bytes on a request, the far end's on an answer.
        let source = match open.direction {
            Direction::Request => open.ingress.as_str(),
            Direction::Response => open.egress.as_str(),
        };
        let mut kind = None;
        let d = match d.at {
            At::Slot(rows) if open.direction == Direction::Request => Dropped {
                path: Cow::Owned(wire_path(source, &d.path, rows)),
                ..d
            },
            At::Block => {
                let (at, spelled) = block_path(source, open.direction, &d.path);
                kind = Some(spelled.map(Cow::Borrowed).unwrap_or_else(|| d.path.clone()));
                Dropped {
                    path: at.map(Cow::Owned).unwrap_or_else(|| d.path.clone()),
                    ..d
                }
            }
            _ => d,
        };
        if open.paths.iter().any(|p| p.as_str() == d.path.as_ref()) {
            return;
        }
        match kind {
            Some(kind) => busbar_contract::diag_warn!(
                d.diag,
                direction = open.direction.as_str(),
                ingress = %open.ingress,
                egress = %open.egress,
                path = %d.path,
                kind = %kind,
                "{}",
                d.message
            ),
            None => busbar_contract::diag_warn!(
                d.diag,
                direction = open.direction.as_str(),
                ingress = %open.ingress,
                egress = %open.egress,
                path = %d.path,
                "{}",
                d.message
            ),
        }
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
    /// Paths INSIDE a carried subtree that the dialect's code does not carry (a member of a block
    /// the dialect models, a vendor detail under a member it reads): named like any other drop.
    /// Sorted ascending: the walk asks it of every member of every stream frame, so it is searched,
    /// never scanned (Responses lists 763 stream paths; test
    /// `every_drop_list_is_sorted_for_the_walks_search`).
    pub drops: &'static [&'static str],
    /// The request defaults the far end ECHOES in its answer, each a member's key and its default
    /// as JSON text (`("tool_choice", "\"auto\"")`). A member equal to its default carries nothing
    /// the caller set, so its drop is no unrepresentable control and the walk does not name it;
    /// any other value of it is named like every drop (ARCHITECT RULING 2026-10-04: a dropped value
    /// equal to the protocol default, or an echoed default, writes no audit row).
    pub defaults: &'static [(&'static str, &'static str)],
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

/// The run of the sorted `table` that starts with `prefix` (one contiguous run in a sorted table).
fn prefixed<'t>(
    table: &'t [&'static str],
    prefix: &'t str,
) -> impl Iterator<Item = &'t &'static str> {
    let start = table.partition_point(|q| *q < prefix);
    table[start..]
        .iter()
        .take_while(move |q| q.starts_with(prefix))
}

impl Carried {
    /// The carried rows: the map file's and the code's (a few dozen; scanned).
    fn rows(&self) -> impl Iterator<Item = &&'static str> {
        self.map.iter().chain(self.code.iter())
    }

    fn cover(&self, path: &str) -> Cover {
        // ONE search of the drop list: the run of drops that start with `path` begins with `path`
        // itself when it is listed (the list is sorted, and `path` sorts before every longer path
        // it begins), so the exact test and the held-drop test read the same run.
        let mut run = prefixed(self.drops, path).peekable();
        if run.next_if(|d| **d == path).is_some() {
            return Cover::Unmapped;
        }
        let holds_drop = run.any(|d| under(d, path));
        let carried = self.rows().any(|q| path == *q || under(path, q));
        if carried {
            return if holds_drop {
                Cover::Above
            } else {
                Cover::Carried
            };
        }
        if holds_drop || self.rows().any(|q| under(q, path)) {
            Cover::Above
        } else {
            Cover::Unmapped
        }
    }

    /// `value`, under `key`, is the default the dialect declares the far end echoes for it.
    fn echoes_default(&self, key: &str, value: &Value) -> bool {
        self.defaults.iter().any(|(k, default)| {
            *k == key && serde_json::from_str::<Value>(default).is_ok_and(|d| d == *value)
        })
    }

    /// The objects at `path` are a union keyed by their `type` member (notation A `type=<arm>`).
    fn uses_arms(&self, path: &str) -> bool {
        let arm = join(path, "type=");
        self.rows().any(|q| q.starts_with(&arm)) || prefixed(self.drops, &arm).next().is_some()
    }

    /// Whether the walk names the member at `path` (or the member above it that holds it) when an
    /// answer carries it: the walk's own decision, asked of one wire path.
    pub fn names_path(&self, path: &str) -> bool {
        let cuts = path
            .char_indices()
            .filter(|(_, c)| matches!(c, '.' | '['))
            .map(|(i, _)| i)
            .chain(std::iter::once(path.len()));
        for end in cuts {
            match self.cover(&path[..end]) {
                Cover::Unmapped => return true,
                Cover::Carried => return false,
                Cover::Above => {}
            }
        }
        false
    }

    /// The notation-A path of every member of `body` (read at `root`, `""` for the document's
    /// root) that this dialect does not carry, the shallowest only, each once, in the order met. A
    /// `null` member carries nothing and is not named.
    pub fn unmapped(&self, root: &str, body: &Value) -> Vec<String> {
        // A frame keyed by its event name: an event the dialect does not carry is named whole, and
        // one it carries whole names nothing below it.
        if !root.is_empty() {
            match self.cover(root) {
                Cover::Carried => return Vec::new(),
                Cover::Unmapped => return vec![root.to_string()],
                Cover::Above => {}
            }
        }
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
                    if child.is_null()
                        || (arm.is_some() && key == crate::codec::keys::TYPE)
                        || self.echoes_default(key, child)
                    {
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

#[cfg(test)]
#[path = "tests/drop_names_tests.rs"]
mod names_tests;

#[cfg(test)]
#[path = "tests/drop_writer_tests.rs"]
mod writer_tests;

#[cfg(test)]
#[path = "tests/drop_census_tests.rs"]
mod census_tests;
