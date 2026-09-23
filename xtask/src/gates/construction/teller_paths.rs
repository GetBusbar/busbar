//! BRANCH-AWARE EXPANSION FOR `teller-step-order`: EVERY PATH, NOT THE CONCATENATION OF THEM.
//!
//! The first expansion this rule shipped walked the loop's body in SOURCE ORDER and spliced the
//! bodies of the helpers it called, producing ONE flat list of step names. That reading cannot tell
//! a SEQUENCE from a CHOICE, and the Teller has a choice in it:
//!
//! ```ignore
//! match authenticated {
//!     Authenticated::Challenge(_)         => { approve(&anonymous, &nowhere); admit(…) }
//!     Authenticated::Principal(principal) => { verify(…); approve(…); admit(…) }
//! }
//! ```
//!
//! Flattened, that reads `… approve, admit, verify, approve, admit …` — the loop appears to admit
//! before it verifies and to run approve and admit twice. NO EXECUTION DOES EITHER. The arms are
//! mutually exclusive, and the six findings the flat reading raised were six findings about the
//! reader. (The flat reader had already met this once and papered over it: a bare call that was a
//! match arm's WHOLE tail expression was skipped, precisely because source order could not tell it
//! was exclusive with its sibling. That special case is gone from here — a walker that forks does
//! not need it, and skipping the call meant an arm whose body is one helper call went unread.)
//!
//! So this module models the body as a TREE and enumerates the paths through it. Every path is
//! judged on its own, and the rule stays a rule because the judgement is three things at once:
//!
//! 1. **Per path, the steps are a SUBSEQUENCE of the canonical order.** The indices of the steps a
//!    path calls, in the canonical list, strictly increase — which is "in order" and "at most once"
//!    in one sentence. An out-of-order pair inside ONE arm is still RED; so is a duplicate.
//! 2. **Per path, nothing is SKIPPED and then carried past.** A path may STOP early — that is a
//!    refusal, and refusals are the point of the chain — but if it calls a step, every EARLIER
//!    canonical step must be on that path too, unless an arm the path went through is DECLARED to
//!    omit it ([`Allowance`], written in `qa/construction.toml` with its reason). The challenge arm
//!    legitimately omits `verify`; an arm that omitted `admit` is a defect and this is what still
//!    catches it. Nothing is excused by "there was a branch here".
//! 3. **Across all paths, every canonical step is still CALLED somewhere.** A step that no path
//!    runs has left the loop, which the per-path rules alone would read as everyone stopping early.
//!
//! WHAT THIS MODELS AND WHAT IT DOES NOT. It forks at `match` arms and at `if`/`else if`/`else`,
//! which is every branch the Teller loop has. It does NOT model loops (`for`/`while`/`loop`), `?`,
//! or `return` — the loop file has none of those on a step path by design ("no `?` and no early
//! return anywhere in it"), and pretending otherwise would be a reading nothing checks. A step call
//! the structure walk cannot PLACE inside a span is reported rather than dropped, so a shape this
//! parser does not understand shows up as a finding instead of as silence.

use std::collections::{BTreeMap, BTreeSet};

use crate::gates::construction::model::py_list;
use crate::gates::construction::tree::{Fnc, Tree};
use crate::rx::{self, Regex};

/// How many distinct paths one entry point may fan out to before the walk stops widening. Every
/// fork dedupes, so the real Teller sits in the low tens; a tree that blew past this is one the
/// gate must say it could not read rather than one it quietly under-reads.
const MAX_PATHS: usize = 512;

// ── WHAT AN ARM MAY LEGITIMATELY NOT RUN ─────────────────────────────────────────────────────────

/// ONE DECLARED OMISSION, and the only thing that excuses a step a path walked past.
///
/// `function` + `arm` name a branch arm exactly: the function whose body holds the `match`/`if`,
/// and a substring of the arm's own pattern (or condition) text. `steps` is what that arm may not
/// run, and `why` is the reason, which lives beside the declaration rather than in a reviewer's
/// memory. A declaration that matches no arm the walk reaches is STALE and is itself a finding —
/// otherwise a refactor that deleted the arm would leave the licence behind it.
#[derive(Debug, Clone)]
pub struct Allowance {
    pub function: String,
    pub arm: String,
    pub steps: Vec<String>,
    pub why: String,
}

impl Allowance {
    pub fn names(&self) -> String {
        format!("`{}`'s `{}` arm", self.function, self.arm)
    }
}

// ── THE BODY AS A TREE ───────────────────────────────────────────────────────────────────────────

/// One node of a function body's control structure.
#[derive(Debug, Clone)]
enum Node {
    /// A byte range of the body buffer whose events run in source order, one after the other.
    Span(usize, usize),
    /// Mutually exclusive alternatives: exactly one arm runs.
    Fork(Vec<ArmNode>),
}

#[derive(Debug, Clone)]
struct ArmNode {
    /// The arm's own text — a `match` pattern, or an `if` condition — whitespace squashed, which
    /// is what an [`Allowance`] names it by.
    label: String,
    body: Vec<Node>,
}

fn ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Whether `w` sits at `i` as a whole keyword — not inside an identifier, not after a `.` or `::`
/// (which would make it a method or a path segment rather than the keyword).
fn is_word_at(buf: &[u8], i: usize, w: &[u8]) -> bool {
    if i + w.len() > buf.len() || &buf[i..i + w.len()] != w {
        return false;
    }
    if i > 0 && (ident_byte(buf[i - 1]) || buf[i - 1] == b'.' || buf[i - 1] == b':') {
        return false;
    }
    match buf.get(i + w.len()) {
        Some(&b) => !ident_byte(b),
        None => true,
    }
}

fn skip_ws(buf: &[u8], mut i: usize, hi: usize) -> usize {
    while i < hi && buf[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// The first `{` at paren/bracket depth zero at or after `from` — the block a `match` scrutinee or
/// an `if` condition opens. `None` when a `;`, a `}` or an unbalanced closer comes first, which is
/// how a `match` this parser cannot read declines to guess.
fn find_block_open(buf: &[u8], from: usize, hi: usize) -> Option<usize> {
    let (mut paren, mut brack) = (0i32, 0i32);
    let mut i = from;
    while i < hi {
        match buf[i] {
            b'(' => paren += 1,
            b')' => {
                paren -= 1;
                if paren < 0 {
                    return None;
                }
            }
            b'[' => brack += 1,
            b']' => {
                brack -= 1;
                if brack < 0 {
                    return None;
                }
            }
            b'{' if paren == 0 && brack == 0 => return Some(i),
            b'}' | b';' if paren == 0 && brack == 0 => return None,
            _ => {}
        }
        i += 1;
    }
    None
}

/// The `}` that matches the `{` at `open`.
fn matching_brace(buf: &[u8], open: usize, hi: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut i = open;
    while i < hi {
        match buf[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// An arm's label: the source text between `lo` and `hi` with every whitespace run squashed to one
/// space, so a pattern written across four lines is named the same way a one-line one is.
fn label_of(buf: &[u8], lo: usize, hi: usize) -> String {
    let (lo, hi) = (lo.min(buf.len()), hi.min(buf.len()));
    if lo >= hi {
        return String::new();
    }
    String::from_utf8_lossy(&buf[lo..hi])
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The byte just past a whole `if` / `else if` / `else` chain starting at `i`.
fn if_chain_end(buf: &[u8], i: usize, hi: usize) -> Option<usize> {
    let open = find_block_open(buf, i + 2, hi)?;
    let close = matching_brace(buf, open, hi)?;
    let j = skip_ws(buf, close + 1, hi);
    if !is_word_at(buf, j, b"else") {
        return Some(close + 1);
    }
    let k = skip_ws(buf, j + 4, hi);
    if k < hi && buf[k] == b'{' {
        return Some(matching_brace(buf, k, hi)? + 1);
    }
    if is_word_at(buf, k, b"if") {
        return if_chain_end(buf, k, hi);
    }
    Some(close + 1)
}

/// Parse a straight-line region into spans and forks.
///
/// The scan is linear and only ever special-cases the two keywords that BRANCH. An ordinary block
/// (a closure body, a `let` with a block initialiser) is walked straight through, because it runs
/// in sequence and its contents are in source order; a `match` or an `if` is consumed whole and the
/// scan resumes after it, which is what keeps arm patterns from being re-read as statements.
fn parse_block(buf: &[u8], lo: usize, hi: usize) -> Vec<Node> {
    let mut out: Vec<Node> = Vec::new();
    let mut span_start = lo;
    let mut i = lo;
    while i < hi {
        if is_word_at(buf, i, b"match") {
            if let Some(open) = find_block_open(buf, i + 5, hi) {
                if let Some(close) = matching_brace(buf, open, hi) {
                    // The scrutinee runs BEFORE the choice: `match units.meter(…) { … }` meters on
                    // every arm, so its steps belong to the span, not to one arm.
                    out.push(Node::Span(span_start, open));
                    out.push(Node::Fork(split_match_arms(buf, open + 1, close)));
                    i = close + 1;
                    span_start = i;
                    continue;
                }
            }
            i += 5;
            continue;
        }
        if is_word_at(buf, i, b"if") {
            if let Some(open) = find_block_open(buf, i + 2, hi) {
                if let Some(close) = matching_brace(buf, open, hi) {
                    let cond = label_of(buf, i, open);
                    // The condition runs on both arms, exactly as a scrutinee does.
                    out.push(Node::Span(span_start, open));
                    let mut arms = vec![ArmNode {
                        label: cond.clone(),
                        body: parse_block(buf, open + 1, close),
                    }];
                    let mut end = close + 1;
                    let j = skip_ws(buf, close + 1, hi);
                    if is_word_at(buf, j, b"else") {
                        let k = skip_ws(buf, j + 4, hi);
                        if k < hi && buf[k] == b'{' {
                            if let Some(ec) = matching_brace(buf, k, hi) {
                                arms.push(ArmNode {
                                    label: "else".to_string(),
                                    body: parse_block(buf, k + 1, ec),
                                });
                                end = ec + 1;
                            }
                        } else if is_word_at(buf, k, b"if") {
                            if let Some(ce) = if_chain_end(buf, k, hi) {
                                // The whole `else if …` tail is ONE alternative; parsing it as a
                                // block lets its own `if` fork inside it.
                                arms.push(ArmNode {
                                    label: "else".to_string(),
                                    body: parse_block(buf, k, ce),
                                });
                                end = ce;
                            }
                        }
                    } else {
                        // An `if` with no `else` still branches: the path that does not take it
                        // runs nothing, and that path is exactly where a step goes missing.
                        arms.push(ArmNode {
                            label: format!("not taken: {cond}"),
                            body: Vec::new(),
                        });
                    }
                    out.push(Node::Fork(arms));
                    i = end;
                    span_start = i;
                    continue;
                }
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    out.push(Node::Span(span_start, hi));
    out
}

/// Split a `match` body into its arms. An arm is `pattern => body`, where the body is either a
/// braced block or an expression running to the next `,` at depth zero.
fn split_match_arms(buf: &[u8], lo: usize, hi: usize) -> Vec<ArmNode> {
    let mut arms: Vec<ArmNode> = Vec::new();
    let (mut brace, mut paren, mut brack) = (0i32, 0i32, 0i32);
    let mut pat_start = lo;
    let mut i = lo;
    while i < hi {
        match buf[i] {
            b'{' => brace += 1,
            b'}' => brace -= 1,
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => brack += 1,
            b']' => brack -= 1,
            b'=' if brace == 0
                && paren == 0
                && brack == 0
                && buf.get(i + 1) == Some(&b'>')
                && buf.get(i.wrapping_sub(1)) != Some(&b'=') =>
            {
                let label = label_of(buf, pat_start, i);
                let b = skip_ws(buf, i + 2, hi);
                let (blo, bhi, after) = if b < hi && buf[b] == b'{' {
                    match matching_brace(buf, b, hi) {
                        Some(c) => (b + 1, c, c + 1),
                        None => (b + 1, hi, hi),
                    }
                } else {
                    let e = arm_expr_end(buf, b, hi);
                    (b, e, (e + 1).min(hi))
                };
                arms.push(ArmNode {
                    label,
                    body: parse_block(buf, blo, bhi),
                });
                i = after;
                pat_start = i;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    arms
}

/// Where a non-braced arm body ends: the next `,` at depth zero, or the end of the match body.
fn arm_expr_end(buf: &[u8], from: usize, hi: usize) -> usize {
    let (mut brace, mut paren, mut brack) = (0i32, 0i32, 0i32);
    let mut i = from;
    while i < hi {
        match buf[i] {
            b'{' => brace += 1,
            b'}' => brace -= 1,
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => brack += 1,
            b']' => brack -= 1,
            b',' if brace == 0 && paren == 0 && brack == 0 => return i,
            _ => {}
        }
        i += 1;
    }
    hi
}

/// Every byte range a [`Node`] tree reads, so a step call that fell between them can be named.
fn covered(nodes: &[Node], out: &mut Vec<(usize, usize)>) {
    for n in nodes {
        match n {
            Node::Span(a, b) => out.push((*a, *b)),
            Node::Fork(arms) => {
                for a in arms {
                    covered(&a.body, out);
                }
            }
        }
    }
}

// ── THE PATHS ────────────────────────────────────────────────────────────────────────────────────

/// One execution path through an entry function: the steps it calls, in the order it calls them,
/// and the indices of the [`Allowance`]s its arms granted it along the way.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Path {
    pub steps: Vec<String>,
    pub excused: BTreeSet<usize>,
}

/// What one expansion found.
pub struct StepPaths {
    pub paths: Vec<Path>,
    /// [`Allowance`] indices some arm on some path actually granted.
    pub hits: BTreeSet<usize>,
    /// Step calls the structure walk could not place in any span, by `function: step`.
    pub unplaced: Vec<String>,
    /// Whether the fan-out hit [`MAX_PATHS`] and the reading is therefore partial.
    pub overflowed: bool,
}

#[derive(Debug)]
enum Ev {
    Step(String),
    Call(String),
}

struct Event {
    pos: usize,
    kind: Ev,
}

struct Body {
    events: Vec<Event>,
    nodes: Vec<Node>,
    unplaced: Vec<String>,
}

#[derive(Default)]
struct State {
    hits: BTreeSet<usize>,
    /// The bodies this walk actually read. A blind spot in a function nothing on the path calls is
    /// not this entry point's blind spot.
    visited: BTreeSet<String>,
    overflowed: bool,
}

struct Walker<'a> {
    bodies: BTreeMap<String, Body>,
    allow: &'a [Allowance],
    depth: usize,
}

impl Walker<'_> {
    fn walk(
        &self,
        name: &str,
        incoming: Vec<Path>,
        d: usize,
        stack: &[String],
        st: &mut State,
    ) -> Vec<Path> {
        let Some(body) = self.bodies.get(name) else {
            return incoming;
        };
        if d > self.depth || stack.iter().any(|s| s == name) {
            return incoming;
        }
        st.visited.insert(name.to_string());
        self.run(name, &body.nodes, &body.events, incoming, d, stack, st)
    }

    #[allow(clippy::too_many_arguments)]
    fn run(
        &self,
        fname: &str,
        nodes: &[Node],
        evs: &[Event],
        mut paths: Vec<Path>,
        d: usize,
        stack: &[String],
        st: &mut State,
    ) -> Vec<Path> {
        for node in nodes {
            match node {
                Node::Span(lo, hi) => {
                    for e in evs.iter().filter(|e| e.pos >= *lo && e.pos < *hi) {
                        match &e.kind {
                            Ev::Step(s) => {
                                for p in paths.iter_mut() {
                                    p.steps.push(s.clone());
                                }
                            }
                            Ev::Call(c) => {
                                let mut next: Vec<String> = stack.to_vec();
                                next.push(fname.to_string());
                                paths = self.walk(c, paths, d + 1, &next, st);
                            }
                        }
                    }
                }
                Node::Fork(arms) => {
                    let mut out: Vec<Path> = Vec::new();
                    for a in arms {
                        let mut seeded = paths.clone();
                        for (i, al) in self.allow.iter().enumerate() {
                            if al.function == fname && a.label.contains(al.arm.as_str()) {
                                st.hits.insert(i);
                                for p in seeded.iter_mut() {
                                    p.excused.insert(i);
                                }
                            }
                        }
                        out.extend(self.run(fname, &a.body, evs, seeded, d, stack, st));
                    }
                    out.sort();
                    out.dedup();
                    if out.len() > MAX_PATHS {
                        st.overflowed = true;
                        out.truncate(MAX_PATHS);
                    }
                    paths = out;
                }
            }
        }
        paths
    }
}

/// Enumerate every path through `entry`, splicing the file's own helpers where they are called.
///
/// A step only counts when it is dispatched off one of `step_receivers` (the door driver's own
/// `units` handle, spelled either `units` directly or `self.0` inside the `Blocking` leg that wraps
/// it) — NOT any method of that name on some unrelated type. `HoldCell::admit`, for example,
/// textually collides with the `Units::admit` step but is called as `run.cell.admit(...)`, off a
/// receiver this scan never treats as a step site.
///
/// `dispatch_methods` names trait-object indirections the walker must follow by METHOD call, not
/// just by bare call: `RouteAwait::route_leg` is invoked as `route.route_leg(...)`, and the actual
/// `Units::route` step it forwards to (`self.0.route(...)`, inside the one local impl of that
/// trait) is otherwise invisible to a scanner that only recurses into bare-call sites.
///
/// THE SCAN READS THE LITERAL-BLANKED TEXT, which is the same text the brace structure is read
/// from. One buffer for both is what keeps "where the arms are" and "where the calls are" from
/// drifting a column apart — and a step name that only appears inside a string literal is not a
/// call, so losing it is the right answer too.
#[allow(clippy::too_many_arguments)]
pub fn expanded_paths(
    tree: &Tree,
    rel: &str,
    entry: &str,
    steps: &[String],
    step_receivers: &[String],
    dispatch_methods: &[String],
    allow: &[Allowance],
    depth: usize,
) -> Result<StepPaths, String> {
    let local: BTreeMap<&str, &Fnc> = tree
        .fns
        .get(rel)
        .into_iter()
        .flat_map(|v| v.iter())
        .filter(|f| !f.intest)
        .map(|f| (f.name.as_str(), f))
        .collect();
    let alt = |xs: &[String]| {
        xs.iter()
            .map(|s| rx::escape(s))
            .collect::<Vec<_>>()
            .join("|")
    };
    let step_rx = Regex::new(&format!(
        r"(?<![A-Za-z0-9_])(?:{})\.({})\s*\(",
        alt(step_receivers),
        alt(steps)
    ))?;
    let call_rx = Regex::new(r"(?<![A-Za-z0-9_.:])([a-z_][a-z0-9_]*)\s*\(")?;
    // The door driver writes its step chain as `units\n    .arrival(...)\n    .into_result(...)`
    // (see `open_to_door`) — the receiver and the step live on DIFFERENT lines, so `step_rx` above
    // (which only matches a receiver and a step on the SAME line) never sees them. These two
    // patterns recover that: a step opening a line right after a line that is bare `units` (or
    // `self.0`) still counts, because the earlier line is exactly what the chain read as the
    // receiver.
    let step_leading_rx = Regex::new(&format!(r"^\s*\.({})\s*\(", alt(steps)))?;
    let receiver_tail_rx = Regex::new(&format!(
        r"(?<![A-Za-z0-9_])(?:{})\s*$",
        alt(step_receivers)
    ))?;
    // Method calls to a locally-defined function, but ONLY the ones named in `dispatch_methods` —
    // widening this to every `.foo(` in the file would let the walker splice in the body of any
    // same-named method on any receiver, which is exactly the kind of textual collision the step
    // scan itself has to refuse.
    let method_rx = (!dispatch_methods.is_empty())
        .then(|| Regex::new(&format!(r"\.({})\s*\(", alt(dispatch_methods))))
        .transpose()?;

    let empty: Vec<crate::gates::construction::tree::Line> = Vec::new();
    let lines: &[crate::gates::construction::tree::Line] = match tree.files.get(rel) {
        Some(l) => l,
        None => &empty,
    };

    let mut bodies: BTreeMap<String, Body> = BTreeMap::new();
    for (name, f) in &local {
        if f.body_start == 0 || f.end > lines.len() || f.body_start > f.end {
            continue;
        }
        let mut buf: Vec<u8> = Vec::new();
        let mut events: Vec<Event> = Vec::new();
        let mut receiver_pending = false;
        for l in &lines[f.body_start - 1..f.end] {
            let base = buf.len();
            let bytes = l.blank.as_bytes();
            // (offset, kind, name) — `0` is a call and `1` a step, so a call at the same column is
            // spliced before the step is counted, exactly as the flat reader ordered them.
            let mut per: Vec<(usize, u8, String)> = step_rx
                .find_iter(bytes)
                .iter()
                .filter_map(|m| m.str_of(bytes, 1).map(|n| (m.start, 1u8, n)))
                .collect();
            if receiver_pending {
                if let Some(m) = step_leading_rx.search(bytes) {
                    if let Some(n) = m.str_of(bytes, 1) {
                        per.push((m.start, 1u8, n));
                    }
                }
            }
            per.extend(call_rx.find_iter(bytes).iter().filter_map(|m| {
                let n = m.str_of(bytes, 1)?;
                (local.contains_key(n.as_str()) && &n != name).then_some((m.start, 0u8, n))
            }));
            if let Some(mrx) = &method_rx {
                per.extend(mrx.find_iter(bytes).iter().filter_map(|m| {
                    let n = m.str_of(bytes, 1)?;
                    (local.contains_key(n.as_str()) && &n != name).then_some((m.start, 0u8, n))
                }));
            }
            per.sort();
            for (off, kind, nm) in per {
                events.push(Event {
                    pos: base + off,
                    kind: if kind == 1 {
                        Ev::Step(nm)
                    } else {
                        Ev::Call(nm)
                    },
                });
            }
            receiver_pending = receiver_tail_rx.is_match(bytes);
            buf.extend_from_slice(bytes);
            buf.push(b'\n');
        }
        let nodes = parse_block(&buf, 0, buf.len());
        let mut spans: Vec<(usize, usize)> = Vec::new();
        covered(&nodes, &mut spans);
        let unplaced: Vec<String> = events
            .iter()
            .filter_map(|e| match &e.kind {
                Ev::Step(s) if !spans.iter().any(|(a, b)| e.pos >= *a && e.pos < *b) => Some(
                    format!("`{name}` calls step `{s}` somewhere this walk cannot place"),
                ),
                _ => None,
            })
            .collect();
        bodies.insert(
            (*name).to_string(),
            Body {
                events,
                nodes,
                unplaced,
            },
        );
    }

    let w = Walker {
        bodies,
        allow,
        depth,
    };
    let mut st = State::default();
    let paths = w.walk(entry, vec![Path::default()], 0, &[], &mut st);
    let unplaced = w
        .bodies
        .iter()
        .filter(|(n, _)| st.visited.contains(*n))
        .flat_map(|(_, b)| b.unplaced.iter().cloned())
        .collect();
    Ok(StepPaths {
        paths,
        hits: st.hits,
        unplaced,
        overflowed: st.overflowed,
    })
}

// ── THE JUDGEMENT ────────────────────────────────────────────────────────────────────────────────

/// Judge one entry point's paths against `canon`, its canonical step order.
///
/// `who` names the function in every finding. `canon` is the whole nine for the loop and the
/// door-plus-closing-step list for the session opener, so "a step outside this entry point's
/// territory" and "a step out of order" are the same question asked of one list.
pub fn judge(who: &str, found: &StepPaths, canon: &[String], allow: &[Allowance]) -> Vec<String> {
    let mut findings: Vec<String> = Vec::new();
    let at = |s: &String| canon.iter().position(|c| c == s);

    if found.overflowed {
        findings.push(format!(
            "`{who}` fans out past {MAX_PATHS} paths; this reading is partial and the rule cannot \
             claim every path was judged"
        ));
    }
    findings.extend(found.unplaced.iter().cloned());

    if found.paths.iter().all(|p| p.steps.is_empty()) {
        findings.push(format!("`{who}` calls no step at all"));
    }

    for p in &found.paths {
        // A step outside this entry point's territory: the session opener has no Route leg and no
        // spend to meter, so calling one is not a matter of order at all.
        for s in &p.steps {
            if at(s).is_none() {
                let f = format!(
                    "`{who}` has a path that calls step `{s}`, which is not a step it may run: {}",
                    py_list(canon)
                );
                if !findings.contains(&f) {
                    findings.push(f);
                }
            }
        }
        let idx: Vec<usize> = p.steps.iter().filter_map(at).collect();
        // ONE PATH, ONE PASS THROUGH THE ORDER. The two ways to break that are asked separately so
        // each says what it is: a step run TWICE on one path, and a pair of steps run OUT OF
        // ORDER on one path. `firsts` is the order question with the repeats taken out, so a
        // duplicate does not also print as a phantom order violation.
        let mut dup_seen: BTreeSet<&String> = BTreeSet::new();
        for s in canon {
            let n = p.steps.iter().filter(|x| *x == s).count();
            if n > 1 && dup_seen.insert(s) {
                let f = format!(
                    "`{who}` calls step `{s}` {n} times; it must run exactly once — on the path {}",
                    py_list(&p.steps)
                );
                if !findings.contains(&f) {
                    findings.push(f);
                }
            }
        }
        let mut firsts: Vec<usize> = Vec::new();
        for i in &idx {
            if !firsts.contains(i) {
                firsts.push(*i);
            }
        }
        if firsts.windows(2).any(|w| w[0] > w[1]) {
            let f = format!(
                "`{who}` (expanded through its helpers) calls the steps as {}; the canonical order \
                 is {} — one path through it, judged on its own",
                py_list(&p.steps),
                py_list(canon)
            );
            if !findings.contains(&f) {
                findings.push(f);
            }
            continue;
        }
        // A path may STOP early. It may not walk PAST a step it never ran, unless an arm it went
        // through is declared to omit that step.
        let Some(&last) = firsts.last() else { continue };
        for s in canon.iter().take(last) {
            if p.steps.iter().any(|x| x == s) {
                continue;
            }
            let excused = p
                .excused
                .iter()
                .any(|a| allow.get(*a).is_some_and(|al| al.steps.contains(s)));
            if excused {
                continue;
            }
            let f = format!(
                "`{who}` (expanded through its helpers) calls the steps as {} on one path, which \
                 never calls `{s}` and then runs on past it; no arm on that path is declared to \
                 omit it (see [[rules.teller-step-order.arm_may_omit]])",
                py_list(&p.steps)
            );
            if !findings.contains(&f) {
                findings.push(f);
            }
        }
    }

    // ACROSS ALL PATHS: a step no path runs has left the loop. The per-path rules alone would read
    // that as every path stopping early, which is the one way "judge each path on its own" could
    // have become a way to lose a step.
    for s in canon {
        if !found.paths.iter().any(|p| p.steps.iter().any(|x| x == s)) {
            findings.push(format!(
                "`{who}` never calls step `{s}` on any path; it is in the canonical order {}",
                py_list(canon)
            ));
        }
    }
    findings
}

/// The one-line summary a green row prints: how many paths, and the longest of them.
pub fn summary(who: &str, found: &StepPaths) -> String {
    let longest = found
        .paths
        .iter()
        .max_by_key(|p| p.steps.len())
        .map(|p| p.steps.join(" \u{2192} "))
        .unwrap_or_default();
    format!(
        "`{who}` runs {} path(s), the longest {longest}",
        found.paths.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arms(src: &str) -> Vec<String> {
        let b = src.as_bytes();
        let nodes = parse_block(b, 0, b.len());
        let mut out = Vec::new();
        fn go(nodes: &[Node], out: &mut Vec<String>) {
            for n in nodes {
                if let Node::Fork(a) = n {
                    for x in a {
                        out.push(x.label.clone());
                        go(&x.body, out);
                    }
                }
            }
        }
        go(&nodes, &mut out);
        out
    }

    /// The shape that caused the six false findings: two exclusive arms, read as two arms.
    #[test]
    fn a_match_is_two_arms_not_one_sequence() {
        let got = arms("{\n  match a {\n    A(_) => { x(); }\n    B(p) => y(),\n  }\n}\n");
        assert_eq!(got, vec!["A(_)".to_string(), "B(p)".to_string()]);
    }

    /// An `if` with no `else` still branches — the not-taken path is where a step goes missing.
    #[test]
    fn an_if_without_an_else_has_a_path_that_skips_it() {
        let got = arms("{\n  if ok.is_ok() {\n    draw();\n  }\n}\n");
        assert_eq!(
            got,
            vec![
                "if ok.is_ok()".to_string(),
                "not taken: if ok.is_ok()".to_string()
            ]
        );
    }

    #[test]
    fn an_else_if_chain_nests_rather_than_flattening() {
        let got = arms(
            "{\n  if a {\n    p();\n  } else if b {\n    q();\n  } else {\n    r();\n  }\n}\n",
        );
        assert_eq!(
            got,
            vec![
                "if a".to_string(),
                "else".to_string(),
                "if b".to_string(),
                "else".to_string(),
            ]
        );
    }

    /// The per-path judgement: exclusive arms are not a sequence, but a genuine skip is still a
    /// skip.
    #[test]
    fn a_skip_is_only_excused_by_a_declared_arm() {
        let canon: Vec<String> = ["verify", "approve", "admit"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let allow = vec![Allowance {
            function: "open_to_door".to_string(),
            arm: "Challenge".to_string(),
            steps: vec!["verify".to_string()],
            why: "a challenge has no principal to seal a destination set for".to_string(),
        }];
        let excused = StepPaths {
            paths: vec![
                Path {
                    steps: vec!["approve".into(), "admit".into()],
                    excused: [0].into_iter().collect(),
                },
                Path {
                    steps: vec!["verify".into(), "approve".into(), "admit".into()],
                    excused: BTreeSet::new(),
                },
            ],
            hits: [0].into_iter().collect(),
            unplaced: vec![],
            overflowed: false,
        };
        assert!(judge("run_unit", &excused, &canon, &allow).is_empty());

        let bare = StepPaths {
            paths: vec![
                Path {
                    steps: vec!["verify".into(), "admit".into()],
                    excused: BTreeSet::new(),
                },
                Path {
                    steps: vec!["verify".into(), "approve".into(), "admit".into()],
                    excused: BTreeSet::new(),
                },
            ],
            hits: BTreeSet::new(),
            unplaced: vec![],
            overflowed: false,
        };
        let f = judge("run_unit", &bare, &canon, &allow);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].contains("never calls `approve`"), "{f:?}");
    }

    /// A duplicate inside ONE path is still a duplicate; the same step on two exclusive paths is
    /// not.
    #[test]
    fn duplicates_are_counted_per_path() {
        let canon: Vec<String> = ["verify", "approve", "admit"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let twice = StepPaths {
            paths: vec![Path {
                steps: vec![
                    "verify".into(),
                    "approve".into(),
                    "admit".into(),
                    "admit".into(),
                ],
                excused: BTreeSet::new(),
            }],
            hits: BTreeSet::new(),
            unplaced: vec![],
            overflowed: false,
        };
        let f = judge("run_unit", &twice, &canon, &[]);
        assert!(
            f.iter()
                .any(|x| x.contains("calls step `admit` 2 times; it must run exactly once")),
            "{f:?}"
        );
    }
}
