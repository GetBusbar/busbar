//! THE TELLER LOOP'S STEP ORDER, READ IN THE ORDER THE LOOP EVALUATES.
//!
//! WHY EVALUATION ORDER IS THE TRUTH, AND SOURCE ORDER IS NOT.
//!
//! The rule this module serves says one thing: a unit meets the ten named steps once each, in one
//! fixed order, and no arm of the loop meets them in any other. The scanner that used to answer it
//! read a function's LINES from top to bottom and called the step names it met on the way "the
//! order". That worked only for as long as the loop was written as a straight run of statements,
//! and it stopped being true the moment the loop became what it is: ONE `match` whose refused arm
//! is written above its admitted arm, a tail whose audit-and-encode lives in a helper called from
//! two arms, and a Route dispatched through a leg so the loop has exactly one await. Read by lines,
//! that loop "calls" encode before route and admit twice — a reading that describes the FILE'S
//! LAYOUT and says nothing whatever about the order a request meets the steps in. A rule that
//! judged that reading would be judging where a author pressed return.
//!
//! So this scanner reads the loop the way the machine does. Arguments are evaluated before the call
//! they are arguments to, so a step nested inside another call happens FIRST — inner before outer.
//! A `match` or an `if` is not a sequence of its arms, it is a CHOICE of exactly one of them, so
//! each arm is a separate path a request can take and the steps of two arms never sit on one path.
//! A step dispatched through a leg (`route.route_leg`) is still that step being performed, so the
//! table below names, per step, the calls that PERFORM it — receiver-qualified, so the hold cell's
//! own `cell.admit` is not mistaken for the door's `units.admit`. A helper the loop calls is spliced
//! in where it is called, because that is where its steps happen.
//!
//! What comes out is not one list but the SET OF PATHS through the loop. The judgement over that
//! set is deliberately stronger than the line reading ever was, and it is three parts:
//!
//! 1. Some path — the ADMITTED path, the one a request that reaches the wire takes — meets every
//!    one of the ten steps, once each, in the canonical order.
//! 2. EVERY path meets its steps in the canonical order. A refusal arm is allowed to be short; it
//!    is not allowed to meter before it admits.
//! 3. No path meets a step twice. A step run twice on one request is the double-charge this loop
//!    exists to make unspellable.
//!
//! Part 2 is what keeps this honest. Narrowing the rule to "the steps the scanner can see on the
//! door path" would have let the loop land and quietly stopped gating the tail; judging every path
//! instead means the arms the old reader was confused by are now each judged on their own.

use crate::gates::construction::tree::Tree;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

/// The canonical steps, and the calls that perform each of them.
pub struct StepTable {
    pub steps: Vec<String>,
    /// Parallel to `steps`: the call spellings that perform that step. An entry is either a bare
    /// call name (`run_the_step`) or a receiver-qualified one (`units.admit`), matched against the
    /// call's own last-two path segments.
    pub performed_by: Vec<Vec<String>>,
}

impl StepTable {
    fn step_of(&self, name: &str, recv: Option<&str>) -> Option<usize> {
        let qualified = recv.map(|r| format!("{r}.{name}"));
        self.performed_by.iter().position(|spellings| {
            spellings
                .iter()
                .any(|s| s == name || Some(s.as_str()) == qualified.as_deref())
        })
    }
}

/// One node of the loop as it is evaluated: a step, a helper to splice, a run of things in order,
/// or a choice of exactly one branch.
#[derive(Debug, Clone)]
enum Node {
    Step(usize),
    Call(String),
    Seq(Vec<Node>),
    Alt(Vec<Node>),
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

/// One file, as bytes, with its non-test function bodies located.
pub struct Source {
    text: Vec<u8>,
    /// name -> (index of the body's `{`, index of its `}`)
    bodies: BTreeMap<String, (usize, usize)>,
    memo: RefCell<BTreeMap<String, Node>>,
}

impl Source {
    /// Build from the gate's own lexed tree, using the literal-blanked text so a brace inside a
    /// string cannot disturb the structure.
    pub fn load(tree: &Tree, rel: &str) -> Option<Source> {
        let lines = tree.files.get(rel)?;
        let mut text = String::new();
        let mut offset_of_line: Vec<usize> = vec![0; lines.len() + 2];
        for l in lines.iter() {
            if l.no < offset_of_line.len() {
                offset_of_line[l.no] = text.len();
            }
            text.push_str(&l.blank);
            text.push('\n');
        }
        let text = text.into_bytes();
        let mut bodies = BTreeMap::new();
        for f in tree.fns.get(rel).into_iter().flat_map(|v| v.iter()) {
            if f.intest || f.body_start >= offset_of_line.len() {
                continue;
            }
            let from = offset_of_line[f.body_start];
            let Some(open) = (from..text.len()).find(|&i| text[i] == b'{') else {
                continue;
            };
            let close = match_brace(&text, open);
            // First definition wins: a second non-test body under one name is a shape this file
            // does not have, and splicing either of two is a guess.
            bodies.entry(f.name.clone()).or_insert((open, close));
        }
        Some(Source {
            text,
            bodies,
            memo: RefCell::new(BTreeMap::new()),
        })
    }

    pub fn has_fn(&self, name: &str) -> bool {
        self.bodies.contains_key(name)
    }

    /// Every path through `entry`, as lists of canonical step indices, in evaluation order.
    pub fn paths(&self, tbl: &StepTable, entry: &str, depth: usize) -> Vec<Vec<usize>> {
        let Some(&(open, close)) = self.bodies.get(entry) else {
            return Vec::new();
        };
        let node = self.body_node(tbl, entry, open, close);
        let mut stack = vec![entry.to_string()];
        let flat = self.expand(tbl, &node, &mut stack, depth);
        let mut out: Vec<Vec<usize>> = walk_paths(&flat).into_iter().collect();
        out.sort();
        out
    }

    fn body_node(&self, tbl: &StepTable, name: &str, open: usize, close: usize) -> Node {
        if let Some(n) = self.memo.borrow().get(name) {
            return n.clone();
        }
        let n = self.parse_seq(tbl, open + 1, close);
        self.memo.borrow_mut().insert(name.to_string(), n.clone());
        n
    }

    /// Splice every helper call into the place it is called from, innermost first, stopping at the
    /// depth budget and never re-entering a function already on the stack.
    fn expand(&self, tbl: &StepTable, n: &Node, stack: &mut Vec<String>, depth: usize) -> Node {
        match n {
            Node::Step(i) => Node::Step(*i),
            Node::Seq(xs) => Node::Seq(
                xs.iter()
                    .map(|x| self.expand(tbl, x, stack, depth))
                    .collect(),
            ),
            Node::Alt(xs) => Node::Alt(
                xs.iter()
                    .map(|x| self.expand(tbl, x, stack, depth))
                    .collect(),
            ),
            Node::Call(name) => {
                if depth == 0 || stack.iter().any(|s| s == name) {
                    return Node::Seq(Vec::new());
                }
                let Some(&(open, close)) = self.bodies.get(name) else {
                    return Node::Seq(Vec::new());
                };
                let body = self.body_node(tbl, name, open, close);
                stack.push(name.clone());
                let out = self.expand(tbl, &body, stack, depth - 1);
                stack.pop();
                out
            }
        }
    }

    fn parse_seq(&self, tbl: &StepTable, lo: usize, hi: usize) -> Node {
        let t = &self.text;
        let mut out: Vec<Node> = Vec::new();
        let mut i = lo;
        while i < hi {
            let c = t[i];
            if c == b'{' || c == b'(' || c == b'[' {
                let k = closing(t, i).min(hi);
                out.push(self.parse_seq(tbl, i + 1, k));
                i = k + 1;
                continue;
            }
            if !is_ident_start(c) {
                i += 1;
                continue;
            }
            let s = i;
            let mut e = i;
            while e < hi && is_ident(t[e]) {
                e += 1;
            }
            let w = std::str::from_utf8(&t[s..e]).unwrap_or("");
            if w == "match" {
                if let Some(b) = brace_after(t, e, hi) {
                    let k = closing(t, b).min(hi);
                    // The scrutinee runs before any arm does.
                    out.push(self.parse_seq(tbl, e, b));
                    out.push(self.parse_arms(tbl, b + 1, k));
                    i = k + 1;
                    continue;
                }
            }
            if w == "if" {
                if let Some(b) = brace_after(t, e, hi) {
                    let k = closing(t, b).min(hi);
                    out.push(self.parse_seq(tbl, e, b));
                    let taken = self.parse_seq(tbl, b + 1, k);
                    let ext = self.if_extent(s, hi);
                    let mut q = k + 1;
                    while q < hi && t[q].is_ascii_whitespace() {
                        q += 1;
                    }
                    let other = if is_word_at(t, q, b"else", hi) {
                        let mut r = q + 4;
                        while r < hi && t[r].is_ascii_whitespace() {
                            r += 1;
                        }
                        self.parse_seq(tbl, r, ext.min(hi))
                    } else {
                        // A bare `if` is a branch too: the body may not run at all.
                        Node::Seq(Vec::new())
                    };
                    out.push(Node::Alt(vec![taken, other]));
                    i = ext.max(k + 1);
                    continue;
                }
            }
            let mut j = e;
            while j < hi && t[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < hi && t[j] == b'(' {
                let k = closing(t, j).min(hi);
                // ARGUMENTS FIRST: they are evaluated before the call they are handed to.
                out.push(self.parse_seq(tbl, j + 1, k));
                let recv = receiver_before(t, s);
                if let Some(ix) = tbl.step_of(w, recv.as_deref()) {
                    out.push(Node::Step(ix));
                } else if self.bodies.contains_key(w) {
                    out.push(Node::Call(w.to_string()));
                }
                i = k + 1;
                continue;
            }
            i = e;
        }
        Node::Seq(out)
    }

    /// The arms of one `match`: exactly one of them runs, so they are alternatives.
    fn parse_arms(&self, tbl: &StepTable, lo: usize, hi: usize) -> Node {
        let t = &self.text;
        let mut alts: Vec<Node> = Vec::new();
        let mut i = lo;
        while i < hi {
            match t[i] {
                b'(' | b'[' | b'{' => {
                    i = closing(t, i).min(hi) + 1;
                }
                b'=' if i + 1 < hi && t[i + 1] == b'>' => {
                    let mut q = i + 2;
                    while q < hi && t[q].is_ascii_whitespace() {
                        q += 1;
                    }
                    if q < hi && t[q] == b'{' {
                        let k = closing(t, q).min(hi);
                        alts.push(self.parse_seq(tbl, q + 1, k));
                        i = k + 1;
                    } else {
                        let mut p = q;
                        while p < hi {
                            match t[p] {
                                b'(' | b'[' | b'{' => {
                                    p = closing(t, p).min(hi) + 1;
                                }
                                b',' => break,
                                _ => p += 1,
                            }
                        }
                        alts.push(self.parse_seq(tbl, q, p.min(hi)));
                        i = p;
                    }
                }
                _ => i += 1,
            }
        }
        if alts.is_empty() {
            Node::Seq(Vec::new())
        } else {
            Node::Alt(alts)
        }
    }

    /// One past the end of the whole `if`/`else if`/`else` chain starting at `at`.
    fn if_extent(&self, at: usize, hi: usize) -> usize {
        let t = &self.text;
        let mut p = at + 2;
        loop {
            let Some(b) = brace_after(t, p, hi) else {
                return hi;
            };
            let k = closing(t, b).min(hi);
            let mut q = k + 1;
            while q < hi && t[q].is_ascii_whitespace() {
                q += 1;
            }
            if !is_word_at(t, q, b"else", hi) {
                return k + 1;
            }
            let mut r = q + 4;
            while r < hi && t[r].is_ascii_whitespace() {
                r += 1;
            }
            if r < hi && t[r] == b'{' {
                return closing(t, r).min(hi) + 1;
            }
            if is_word_at(t, r, b"if", hi) {
                p = r + 2;
                continue;
            }
            return k + 1;
        }
    }
}

fn is_word_at(t: &[u8], at: usize, w: &[u8], hi: usize) -> bool {
    at + w.len() <= hi
        && &t[at..at + w.len()] == w
        && (at + w.len() >= t.len() || !is_ident(t[at + w.len()]))
}

/// `units` in `units.admit(`, `cell` in `run.cell.admit(` — the segment the call is dispatched on.
fn receiver_before(t: &[u8], start: usize) -> Option<String> {
    let mut p = start;
    while p > 0 && t[p - 1].is_ascii_whitespace() {
        p -= 1;
    }
    if p == 0 || t[p - 1] != b'.' {
        return None;
    }
    p -= 1;
    while p > 0 && t[p - 1].is_ascii_whitespace() {
        p -= 1;
    }
    let end = p;
    while p > 0 && is_ident(t[p - 1]) {
        p -= 1;
    }
    (p < end).then(|| String::from_utf8_lossy(&t[p..end]).into_owned())
}

fn brace_after(t: &[u8], from: usize, hi: usize) -> Option<usize> {
    let mut d: i64 = 0;
    let mut p = from;
    while p < hi {
        match t[p] {
            b'(' | b'[' => d += 1,
            b')' | b']' => d -= 1,
            b'{' if d == 0 => return Some(p),
            b';' if d == 0 => return None,
            _ => {}
        }
        p += 1;
    }
    None
}

fn match_brace(t: &[u8], open: usize) -> usize {
    closing(t, open)
}

/// The index of the delimiter closing the one at `open`, or the end of the text.
fn closing(t: &[u8], open: usize) -> usize {
    let (o, c) = match t[open] {
        b'{' => (b'{', b'}'),
        b'(' => (b'(', b')'),
        _ => (b'[', b']'),
    };
    let mut d: i64 = 0;
    let mut p = open;
    while p < t.len() {
        if t[p] == o {
            d += 1;
        } else if t[p] == c {
            d -= 1;
            if d == 0 {
                return p;
            }
        }
        p += 1;
    }
    t.len().saturating_sub(1)
}

/// The distinct step sequences a request can meet, one per path through the node.
fn walk_paths(n: &Node) -> BTreeSet<Vec<usize>> {
    match n {
        Node::Step(i) => BTreeSet::from([vec![*i]]),
        Node::Call(_) => BTreeSet::from([Vec::new()]),
        Node::Alt(xs) => {
            let mut out = BTreeSet::new();
            if xs.is_empty() {
                out.insert(Vec::new());
            }
            for x in xs {
                out.extend(walk_paths(x));
            }
            out
        }
        Node::Seq(xs) => {
            let mut acc: BTreeSet<Vec<usize>> = BTreeSet::from([Vec::new()]);
            for x in xs {
                let next = walk_paths(x);
                if next.len() == 1 && next.iter().next().is_some_and(|v| v.is_empty()) {
                    continue;
                }
                let mut grown = BTreeSet::new();
                for a in &acc {
                    for b in &next {
                        let mut v = a.clone();
                        v.extend_from_slice(b);
                        grown.insert(v);
                    }
                }
                // A loop body with many independent branches can multiply without bound; the
                // canonical order is ten steps long, so a path set this large is a parse gone
                // wrong rather than a shape to judge. Collapsing to the distinct sequences keeps
                // the judgement finite and never drops a sequence that is actually reachable.
                acc = grown;
                if acc.len() > PATH_CAP {
                    let trimmed: BTreeSet<Vec<usize>> = acc.into_iter().take(PATH_CAP).collect();
                    acc = trimmed;
                }
            }
            acc
        }
    }
}

const PATH_CAP: usize = 4096;

/// True when `path` meets its steps in strictly ascending canonical order, no step twice.
pub fn ascending(path: &[usize]) -> bool {
    path.windows(2).all(|w| w[0] < w[1])
}

pub fn names(path: &[usize], steps: &[String]) -> Vec<String> {
    path.iter()
        .map(|&i| steps.get(i).cloned().unwrap_or_else(|| i.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tbl() -> StepTable {
        let steps: Vec<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        let performed_by = vec![
            vec!["units.a".to_string()],
            vec!["units.b".to_string()],
            vec!["units.c".to_string(), "leg.c_leg".to_string()],
        ];
        StepTable {
            steps,
            performed_by,
        }
    }

    fn src(text: &str) -> Source {
        // A Source built straight from text, as the tree would hand it over.
        let mut bodies = BTreeMap::new();
        let bytes = text.as_bytes().to_vec();
        let mut p = 0;
        while let Some(rel) = text[p..].find("fn ") {
            let at = p + rel + 3;
            let mut e = at;
            while e < bytes.len() && is_ident(bytes[e]) {
                e += 1;
            }
            let name = text[at..e].to_string();
            if let Some(open) = brace_after(&bytes, e, bytes.len()) {
                let close = closing(&bytes, open);
                bodies.entry(name).or_insert((open, close));
                p = open + 1;
            } else {
                p = e;
            }
        }
        Source {
            text: bytes,
            bodies,
            memo: RefCell::new(BTreeMap::new()),
        }
    }

    #[test]
    fn arguments_are_evaluated_before_the_call_they_feed() {
        let s = src(
            "fn f() { outer(units.a(x), units.b(y)); }\nfn outer(p: u8, q: u8) { units.c(z); }\n",
        );
        assert_eq!(s.paths(&tbl(), "f", 4), vec![vec![0, 1, 2]]);
    }

    #[test]
    fn each_match_arm_is_its_own_path_and_the_refusal_arm_may_be_short() {
        let s = src(
            "fn f() { units.a(x); match d { Err(e) => { units.c(e); } Ok(v) => { units.b(v); units.c(v); } } }\n",
        );
        let mut p = s.paths(&tbl(), "f", 4);
        p.sort();
        assert_eq!(p, vec![vec![0, 1, 2], vec![0, 2]]);
    }

    #[test]
    fn a_leg_dispatched_step_is_that_step_being_performed() {
        let s = src("fn f() { units.a(x); units.b(x); leg.c_leg(x); }\n");
        assert_eq!(s.paths(&tbl(), "f", 4), vec![vec![0, 1, 2]]);
    }

    #[test]
    fn a_same_named_call_on_another_receiver_is_not_the_step() {
        let s = src("fn f() { units.a(x); cell.b(x); units.c(x); }\n");
        assert_eq!(s.paths(&tbl(), "f", 4), vec![vec![0, 2]]);
    }

    #[test]
    fn a_reordered_arm_is_visible_as_a_descending_path() {
        let s = src("fn f() { units.c(x); units.a(x); }\n");
        let p = s.paths(&tbl(), "f", 4);
        assert_eq!(p, vec![vec![2, 0]]);
        assert!(!ascending(&p[0]));
    }

    #[test]
    fn recursion_terminates_and_a_missing_helper_contributes_nothing() {
        let s = src("fn f() { units.a(x); g(); }\nfn g() { units.b(x); f(); nowhere(); }\n");
        assert_eq!(s.paths(&tbl(), "f", 4), vec![vec![0, 1]]);
    }
}
