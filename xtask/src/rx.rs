//! `rx` — a small backtracking regular-expression engine, over BYTES.
//!
//! WHY THIS EXISTS AND WHY IT IS NOT A DEPENDENCY. The construction gate's rules are not written in
//! Rust: they are written in `qa/construction.toml`, as data, and several of them are regular
//! expressions the owner tightens without touching code (`send_verb`, `seam_name_pattern`,
//! `forget_or_drop_pattern`, `pattern` for the seal-impl scan). A port that hard-coded those
//! patterns as hand-rolled matchers would move the rule out of the file the owner edits and into
//! the file the owner does not, which is the opposite of what the ceilings file is for. So the
//! patterns stay data and this reads them.
//!
//! It is not a dependency because `xtask`'s whole point is auditing dependencies (see
//! `xtask/Cargo.toml`): one crate whose job is to make the audit cheaper is one more crate in the
//! closure the audit has to explain. The subset here is exactly what `qa/construction.toml` and
//! `scripts/construction-gate/rules.py` between them spell, no more:
//!
//! * literals, `.`, character classes with ranges/negation, the `\d \D \s \S \w \W` shorthands;
//! * `*`, `+`, `?`, `{n}`, `{n,}`, `{n,m}`, each greedy or lazy;
//! * alternation, groups (capturing, `(?:…)` non-capturing, `(?P<name>…)` named);
//! * anchors `^` `$`, word boundaries `\b` `\B`;
//! * lookahead `(?=…)` / `(?!…)`, FIXED-WIDTH lookbehind `(?<=…)` / `(?<!…)` (the only kind
//!   Python's own `re` accepts, and the only kind the ported patterns use);
//! * backreferences `\1` and `(?P=name)` — load-bearing for the raw-string-literal scanner, whose
//!   closing delimiter is "the same run of hashes it opened with";
//! * the `(?i)` inline flag.
//!
//! BYTES, NOT CHARS, and that is a deliberate equivalence rather than a shortcut. Every class the
//! ported rules spell is an explicit ASCII range, so a non-ASCII character is "outside the class"
//! byte-wise exactly as it is char-wise; `.` and `\\.` consume one byte where Python consumes one
//! character, and both land on the same end position because the bytes in between match the same
//! negated ASCII classes. Working in bytes also means an offset returned here is an offset INTO
//! THE SAME `&[u8]` the caller sliced, so the line-offset arithmetic the function finder does
//! (`len(blank) + 1` per line) stays self-consistent without a char/byte conversion anywhere.

use std::collections::BTreeMap;

#[derive(Debug, Clone)]
enum Node {
    Empty,
    Byte(u8),
    Any,
    Class(Box<Class>),
    Start,
    End,
    WordBoundary(bool),
    Group(Option<usize>, Box<Node>),
    Look {
        behind: bool,
        neg: bool,
        width: usize,
        node: Box<Node>,
    },
    BackRef(usize),
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    Repeat {
        node: Box<Node>,
        min: usize,
        max: usize,
        greedy: bool,
        /// The width one iteration always consumes, when it is fixed and non-zero and the body
        /// captures nothing.
        ///
        /// THIS IS NOT AN OPTIMISATION, IT IS A STACK BOUND. The general repeat recurses once per
        /// iteration, so `(?:[^"]|"(?!…))*` over a 3000-character string literal is 3000 nested
        /// frames — fine on the 8 MiB main stack, an abort on the 2 MiB one `libtest` gives a test
        /// thread. That is not a limit anybody should have to know about to run the gates. Where
        /// the body's width is fixed, the run of iterations is found by a LOOP and the backtrack
        /// walks the recorded end positions, so depth stops depending on the subject's length.
        fixed: Option<usize>,
    },
}

/// A byte class as a 256-bit membership table. Negation and case folding are folded in at compile
/// time, so matching is one array read and never a second pass over the class's ranges.
#[derive(Clone)]
struct Class {
    bits: [bool; 256],
}

impl std::fmt::Debug for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Class")
    }
}

impl Class {
    fn empty() -> Class {
        Class { bits: [false; 256] }
    }

    fn add(&mut self, b: u8) {
        self.bits[b as usize] = true;
    }

    fn add_range(&mut self, lo: u8, hi: u8) {
        let mut b = lo;
        loop {
            self.bits[b as usize] = true;
            if b == hi {
                break;
            }
            b = b.wrapping_add(1);
        }
    }

    fn negate(&mut self) {
        for b in self.bits.iter_mut() {
            *b = !*b;
        }
    }

    fn fold_case(&mut self) {
        for b in b'a'..=b'z' {
            let u = b - 32;
            let any = self.bits[b as usize] || self.bits[u as usize];
            self.bits[b as usize] = any;
            self.bits[u as usize] = any;
        }
    }

    fn has(&self, b: u8) -> bool {
        self.bits[b as usize]
    }
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

// ── Parsing ──────────────────────────────────────────────────────────────────────────────────────

struct Parser<'a> {
    pat: &'a [u8],
    i: usize,
    ngroups: usize,
    names: BTreeMap<String, usize>,
    ci: bool,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.pat.get(self.i).copied()
    }

    fn eat(&mut self, b: u8) -> bool {
        if self.peek() == Some(b) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn err<T>(&self, msg: &str) -> Result<T, String> {
        Err(format!(
            "rx: {msg} at offset {} in `{}`",
            self.i,
            String::from_utf8_lossy(self.pat)
        ))
    }

    fn alt(&mut self) -> Result<Node, String> {
        let mut branches = vec![self.concat()?];
        while self.eat(b'|') {
            branches.push(self.concat()?);
        }
        Ok(if branches.len() == 1 {
            branches.pop().expect("one branch")
        } else {
            Node::Alt(branches)
        })
    }

    fn concat(&mut self) -> Result<Node, String> {
        let mut items = Vec::new();
        while let Some(b) = self.peek() {
            if b == b'|' || b == b')' {
                break;
            }
            let atom = self.atom()?;
            items.push(self.quantify(atom)?);
        }
        Ok(match items.len() {
            0 => Node::Empty,
            1 => items.pop().expect("one item"),
            _ => Node::Concat(items),
        })
    }

    fn quantify(&mut self, atom: Node) -> Result<Node, String> {
        let (min, max) = match self.peek() {
            Some(b'*') => {
                self.i += 1;
                (0, usize::MAX)
            }
            Some(b'+') => {
                self.i += 1;
                (1, usize::MAX)
            }
            Some(b'?') => {
                self.i += 1;
                (0, 1)
            }
            Some(b'{') => match self.try_counted()? {
                Some(mm) => mm,
                None => return Ok(atom),
            },
            _ => return Ok(atom),
        };
        let greedy = !self.eat(b'?');
        // A body that captures is excluded: the loop below would leave the LAST iteration's groups
        // set where the recursive form leaves the one that survived backtracking, and a group's
        // value is something a caller reads.
        let fixed = match fixed_width(&atom) {
            Some(w) if w > 0 && !has_capture(&atom) => Some(w),
            _ => None,
        };
        Ok(Node::Repeat {
            node: Box::new(atom),
            min,
            max,
            greedy,
            fixed,
        })
    }

    /// `{n}` / `{n,}` / `{n,m}`. A `{` that is not one of those is a literal brace — the ported
    /// patterns spell `\{` sometimes and a bare `{` others, and treating a bare one as a broken
    /// quantifier would refuse a pattern Python accepts.
    fn try_counted(&mut self) -> Result<Option<(usize, usize)>, String> {
        let save = self.i;
        self.i += 1; // '{'
        let lo = self.digits();
        let Some(lo) = lo else {
            self.i = save;
            return Ok(None);
        };
        if self.eat(b'}') {
            return Ok(Some((lo, lo)));
        }
        if !self.eat(b',') {
            self.i = save;
            return Ok(None);
        }
        let hi = self.digits().unwrap_or(usize::MAX);
        if !self.eat(b'}') {
            self.i = save;
            return Ok(None);
        }
        Ok(Some((lo, hi)))
    }

    fn digits(&mut self) -> Option<usize> {
        let start = self.i;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.i += 1;
        }
        if self.i == start {
            return None;
        }
        String::from_utf8_lossy(&self.pat[start..self.i])
            .parse()
            .ok()
    }

    fn atom(&mut self) -> Result<Node, String> {
        let Some(b) = self.peek() else {
            return Ok(Node::Empty);
        };
        match b {
            b'(' => self.group(),
            b'[' => self.class_node(),
            b'.' => {
                self.i += 1;
                Ok(Node::Any)
            }
            b'^' => {
                self.i += 1;
                Ok(Node::Start)
            }
            b'$' => {
                self.i += 1;
                Ok(Node::End)
            }
            b'\\' => self.escape(),
            _ => {
                self.i += 1;
                Ok(self.byte_node(b))
            }
        }
    }

    fn byte_node(&self, b: u8) -> Node {
        if self.ci && b.is_ascii_alphabetic() {
            let mut c = Class::empty();
            c.add(b);
            c.fold_case();
            Node::Class(Box::new(c))
        } else {
            Node::Byte(b)
        }
    }

    fn group(&mut self) -> Result<Node, String> {
        self.i += 1; // '('
        if self.eat(b'?') {
            match self.peek() {
                Some(b':') => {
                    self.i += 1;
                    let inner = self.alt()?;
                    if !self.eat(b')') {
                        return self.err("unclosed group");
                    }
                    return Ok(inner);
                }
                Some(b'=') | Some(b'!') => {
                    let neg = self.peek() == Some(b'!');
                    self.i += 1;
                    let inner = self.alt()?;
                    if !self.eat(b')') {
                        return self.err("unclosed lookahead");
                    }
                    return Ok(Node::Look {
                        behind: false,
                        neg,
                        width: 0,
                        node: Box::new(inner),
                    });
                }
                Some(b'<') => {
                    // `(?<=…)` / `(?<!…)`; `(?<name>…)` is not a spelling the ported patterns use.
                    let save = self.i;
                    self.i += 1;
                    let neg = match self.peek() {
                        Some(b'=') => false,
                        Some(b'!') => true,
                        _ => {
                            self.i = save;
                            return self.err("unsupported `(?<…` construct");
                        }
                    };
                    self.i += 1;
                    let inner = self.alt()?;
                    if !self.eat(b')') {
                        return self.err("unclosed lookbehind");
                    }
                    let Some(width) = fixed_width(&inner) else {
                        return self.err(
                            "look-behind requires a fixed-width pattern (the same refusal Python's \
                             own `re` makes)",
                        );
                    };
                    return Ok(Node::Look {
                        behind: true,
                        neg,
                        width,
                        node: Box::new(inner),
                    });
                }
                Some(b'P') => {
                    self.i += 1;
                    if self.eat(b'=') {
                        let name = self.take_until(b')')?;
                        let Some(idx) = self.names.get(&name).copied() else {
                            return self.err("backreference to an unopened named group");
                        };
                        return Ok(Node::BackRef(idx));
                    }
                    if !self.eat(b'<') {
                        return self.err("expected `(?P<name>` or `(?P=name)`");
                    }
                    let name = self.take_until(b'>')?;
                    self.ngroups += 1;
                    let idx = self.ngroups;
                    self.names.insert(name, idx);
                    let inner = self.alt()?;
                    if !self.eat(b')') {
                        return self.err("unclosed named group");
                    }
                    return Ok(Node::Group(Some(idx), Box::new(inner)));
                }
                Some(b'i') => {
                    // `(?i)` — a global flag wherever it is written, as in Python.
                    self.i += 1;
                    if !self.eat(b')') {
                        return self.err("only the bare `(?i)` flag group is supported");
                    }
                    self.ci = true;
                    return Ok(Node::Empty);
                }
                _ => return self.err("unsupported `(?…` construct"),
            }
        }
        self.ngroups += 1;
        let idx = self.ngroups;
        let inner = self.alt()?;
        if !self.eat(b')') {
            return self.err("unclosed group");
        }
        Ok(Node::Group(Some(idx), Box::new(inner)))
    }

    fn take_until(&mut self, end: u8) -> Result<String, String> {
        let start = self.i;
        while self.peek().is_some_and(|b| b != end) {
            self.i += 1;
        }
        if !self.eat(end) {
            return self.err("unterminated group name");
        }
        Ok(String::from_utf8_lossy(&self.pat[start..self.i - 1]).into_owned())
    }

    /// A character class, as a node rather than a table — because a class may hold a NON-ASCII
    /// CHARACTER, and that is the one place "bytes are equivalent to chars" is not true.
    ///
    /// `[/,–—-]` read as bytes is a set holding `0xE2`, `0x80`, `0x93` and `0x94`, which matches
    /// ONE CONTINUATION BYTE of an en dash — a match Python never makes, at an offset that is not a
    /// character boundary. So a class whose members are all ASCII stays one table read, and a class
    /// with a multi-byte member becomes an alternation of the table and each member's byte
    /// sequence, which matches the whole character or nothing.
    fn class_node(&mut self) -> Result<Node, String> {
        let (c, multi, neg) = self.class()?;
        if multi.is_empty() {
            return Ok(Node::Class(Box::new(c)));
        }
        if neg {
            // `[^…–…]` in bytes would have to mean "any byte sequence that is not one of these
            // characters", which is not a class at all. No pattern in this tree spells one, and
            // guessing at it would be a rule nobody wrote.
            return self.err("a NEGATED character class containing a non-ASCII character");
        }
        let mut branches: Vec<Node> = multi
            .into_iter()
            .map(|seq| Node::Concat(seq.into_iter().map(Node::Byte).collect()))
            .collect();
        branches.insert(0, Node::Class(Box::new(c)));
        Ok(Node::Alt(branches))
    }

    /// The ASCII members as a table, the non-ASCII members as byte sequences, and whether the class
    /// was negated.
    fn class(&mut self) -> Result<(Class, Vec<Vec<u8>>, bool), String> {
        self.i += 1; // '['
        let mut c = Class::empty();
        let mut multi: Vec<Vec<u8>> = Vec::new();
        let neg = self.eat(b'^');
        let mut first = true;
        loop {
            let Some(b) = self.peek() else {
                return self.err("unterminated character class");
            };
            if b == b']' && !first {
                self.i += 1;
                break;
            }
            first = false;
            if b >= 0x80 {
                // The whole UTF-8 sequence is one member.
                let start = self.i;
                self.i += 1;
                while self.peek().is_some_and(|x| (0x80..0xC0).contains(&x)) {
                    self.i += 1;
                }
                multi.push(self.pat[start..self.i].to_vec());
                continue;
            }
            let lo = if b == b'\\' {
                self.i += 1;
                let Some(e) = self.peek() else {
                    return self.err("trailing backslash in class");
                };
                self.i += 1;
                match shorthand(e) {
                    Some(sh) => {
                        for (i, on) in sh.bits.iter().enumerate() {
                            if *on {
                                c.add(i as u8);
                            }
                        }
                        continue;
                    }
                    None => unescape(e),
                }
            } else {
                self.i += 1;
                b
            };
            if self.peek() == Some(b'-') && self.pat.get(self.i + 1).is_some_and(|x| *x != b']') {
                self.i += 1;
                let Some(hb) = self.peek() else {
                    return self.err("unterminated range");
                };
                self.i += 1;
                let hi = if hb == b'\\' {
                    let Some(e) = self.peek() else {
                        return self.err("trailing backslash in range");
                    };
                    self.i += 1;
                    unescape(e)
                } else {
                    hb
                };
                if hi < lo {
                    return self.err("reversed character range");
                }
                c.add_range(lo, hi);
            } else {
                c.add(lo);
            }
        }
        if neg {
            c.negate();
        }
        if self.ci {
            c.fold_case();
        }
        Ok((c, multi, neg))
    }

    fn escape(&mut self) -> Result<Node, String> {
        self.i += 1; // '\\'
        let Some(e) = self.peek() else {
            return self.err("trailing backslash");
        };
        self.i += 1;
        if let Some(c) = shorthand(e) {
            return Ok(Node::Class(Box::new(c)));
        }
        match e {
            b'b' => Ok(Node::WordBoundary(true)),
            b'B' => Ok(Node::WordBoundary(false)),
            b'A' => Ok(Node::Start),
            b'z' => Ok(Node::End),
            b'1'..=b'9' => Ok(Node::BackRef((e - b'0') as usize)),
            _ => Ok(self.byte_node(unescape(e))),
        }
    }
}

fn unescape(e: u8) -> u8 {
    match e {
        b'n' => b'\n',
        b't' => b'\t',
        b'r' => b'\r',
        b'f' => 0x0c,
        b'v' => 0x0b,
        b'0' => 0,
        other => other,
    }
}

fn shorthand(e: u8) -> Option<Class> {
    let mut c = Class::empty();
    match e {
        b'd' | b'D' => c.add_range(b'0', b'9'),
        b'w' | b'W' => {
            c.add_range(b'a', b'z');
            c.add_range(b'A', b'Z');
            c.add_range(b'0', b'9');
            c.add(b'_');
        }
        b's' | b'S' => {
            for b in [b' ', b'\t', b'\n', b'\r', 0x0b, 0x0c] {
                c.add(b);
            }
        }
        _ => return None,
    }
    if e.is_ascii_uppercase() {
        c.negate();
    }
    Some(c)
}

/// Does this node set a capture group anywhere inside it?
fn has_capture(node: &Node) -> bool {
    match node {
        Node::Group(Some(_), _) => true,
        Node::Group(None, inner) | Node::Repeat { node: inner, .. } => has_capture(inner),
        Node::Look { node: inner, .. } => has_capture(inner),
        Node::Concat(items) | Node::Alt(items) => items.iter().any(has_capture),
        _ => false,
    }
}

/// The number of bytes a node always consumes, or `None` when it is not fixed. Needed for
/// look-behind, which is exactly where Python refuses a variable width too, and for the
/// stack-bounded repeat above.
fn fixed_width(node: &Node) -> Option<usize> {
    match node {
        Node::Empty | Node::Start | Node::End | Node::WordBoundary(_) => Some(0),
        Node::Look { .. } => Some(0),
        Node::Byte(_) | Node::Any | Node::Class(_) => Some(1),
        Node::Group(_, inner) => fixed_width(inner),
        Node::Concat(items) => items.iter().try_fold(0, |a, n| Some(a + fixed_width(n)?)),
        Node::Alt(branches) => {
            let mut it = branches.iter().map(fixed_width);
            let first = it.next()??;
            for w in it {
                if w? != first {
                    return None;
                }
            }
            Some(first)
        }
        Node::Repeat { node, min, max, .. } if min == max => Some(fixed_width(node)? * min),
        Node::Repeat { .. } | Node::BackRef(_) => None,
    }
}

// ── Matching ─────────────────────────────────────────────────────────────────────────────────────

type Caps = Vec<Option<(usize, usize)>>;

enum Cont<'a> {
    Done,
    Seq(&'a [Node], &'a Cont<'a>),
    Save(usize, usize, &'a Cont<'a>),
    Rep {
        node: &'a Node,
        min: usize,
        max: usize,
        greedy: bool,
        count: usize,
        prev: usize,
        k: &'a Cont<'a>,
    },
}

/// One match: the span and every group's span, all as byte offsets into the subject.
#[derive(Debug, Clone)]
pub struct Match {
    pub start: usize,
    pub end: usize,
    groups: Caps,
}

impl Match {
    /// Group `n`'s span, or `None` when the group did not participate. Group 0 is the whole match.
    pub fn group(&self, n: usize) -> Option<(usize, usize)> {
        if n == 0 {
            return Some((self.start, self.end));
        }
        self.groups.get(n).copied().flatten()
    }

    /// Group `n`'s text out of the subject it was matched against.
    pub fn text<'t>(&self, subject: &'t [u8], n: usize) -> Option<&'t [u8]> {
        self.group(n).map(|(a, b)| &subject[a..b])
    }

    /// Group `n` as a `String`, for the many rules that print `m.group(0)` into a detail column.
    pub fn str_of(&self, subject: &[u8], n: usize) -> Option<String> {
        self.text(subject, n)
            .map(|b| String::from_utf8_lossy(b).into_owned())
    }
}

#[derive(Debug, Clone)]
pub struct Regex {
    node: Node,
    ngroups: usize,
    names: BTreeMap<String, usize>,
    /// A literal every match must contain, used to skip a subject outright. Purely an optimisation
    /// — a wrong hint would change the answer, so it is derived only from a concatenation's own
    /// mandatory literal run.
    required: Option<Vec<u8>>,
    anchored: bool,
    src: String,
}

impl Regex {
    pub fn new(pattern: &str) -> Result<Regex, String> {
        let mut p = Parser {
            pat: pattern.as_bytes(),
            i: 0,
            ngroups: 0,
            names: BTreeMap::new(),
            ci: false,
        };
        let node = p.alt()?;
        if p.i != p.pat.len() {
            return p.err("unexpected trailing input (an unbalanced `)`?)");
        }
        // `(?i)` may be written anywhere and applies to the whole pattern; a byte already parsed
        // under the case-sensitive reading has to be re-parsed once the flag is known.
        let (node, ngroups, names) = if p.ci {
            let mut q = Parser {
                pat: pattern.as_bytes(),
                i: 0,
                ngroups: 0,
                names: BTreeMap::new(),
                ci: true,
            };
            let n = q.alt()?;
            (n, q.ngroups, q.names)
        } else {
            (node, p.ngroups, p.names)
        };
        let required = required_literal(&node);
        let anchored = first_is_start(&node);
        Ok(Regex {
            node,
            ngroups,
            names,
            required,
            anchored,
            src: pattern.to_string(),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.src
    }

    pub fn group_index(&self, name: &str) -> Option<usize> {
        self.names.get(name).copied()
    }

    /// `re.search`: the leftmost match at or after `from`.
    pub fn search_at(&self, subject: &[u8], from: usize) -> Option<Match> {
        if let Some(req) = &self.required {
            if !contains(&subject[from.min(subject.len())..], req) {
                return None;
            }
        }
        let last = if self.anchored { from } else { subject.len() };
        // ONE capture buffer for the whole left-to-right sweep, reset per start position rather
        // than allocated per start position. This engine is asked roughly one question per byte of
        // the 660k-line tree the construction gate reads; a fresh `Vec` at each of those was most
        // of the gate's running time.
        let mut caps: Caps = vec![None; self.ngroups + 1];
        for start in from..=last {
            // A MATCH NEVER STARTS INSIDE A CHARACTER. Python scans character positions, so it
            // never tries one; this engine scans bytes, and a start on a UTF-8 continuation byte
            // could only ever produce a match Python does not make — at an offset that is not a
            // char boundary, which is also an offset no caller can slice a `&str` at.
            if subject.get(start).is_some_and(|b| (0x80..0xC0).contains(b)) {
                continue;
            }
            caps.iter_mut().for_each(|c| *c = None);
            if let Some(end) = self.m_one(&self.node, subject, start, &mut caps, &Cont::Done) {
                return Some(Match {
                    start,
                    end,
                    groups: caps,
                });
            }
        }
        None
    }

    pub fn search(&self, subject: &[u8]) -> Option<Match> {
        self.search_at(subject, 0)
    }

    pub fn search_str(&self, subject: &str) -> Option<Match> {
        self.search(subject.as_bytes())
    }

    pub fn is_match(&self, subject: &[u8]) -> bool {
        self.search(subject).is_some()
    }

    pub fn is_match_str(&self, subject: &str) -> bool {
        self.search(subject.as_bytes()).is_some()
    }

    /// `re.match`: anchored at `from`, but not required to reach the end.
    pub fn match_at(&self, subject: &[u8], from: usize) -> Option<Match> {
        let mut caps: Caps = vec![None; self.ngroups + 1];
        self.m_one(&self.node, subject, from, &mut caps, &Cont::Done)
            .map(|end| Match {
                start: from,
                end,
                groups: caps,
            })
    }

    pub fn match_str(&self, subject: &str) -> Option<Match> {
        self.match_at(subject.as_bytes(), 0)
    }

    /// `re.fullmatch`, which several ported rules spell as `^…$` and one (`seam_name_pattern`)
    /// spells as an anchored `re.match` over a whole identifier.
    pub fn full_match(&self, subject: &[u8]) -> bool {
        let mut caps: Caps = vec![None; self.ngroups + 1];
        self.m_one(&self.node, subject, 0, &mut caps, &Cont::Done) == Some(subject.len())
    }

    /// `re.finditer`: non-overlapping matches left to right, an empty match advancing by one.
    pub fn find_iter(&self, subject: &[u8]) -> Vec<Match> {
        let mut out = Vec::new();
        let mut at = 0;
        while at <= subject.len() {
            let Some(m) = self.search_at(subject, at) else {
                break;
            };
            at = if m.end > m.start { m.end } else { m.end + 1 };
            out.push(m);
        }
        out
    }

    pub fn find_iter_str(&self, subject: &str) -> Vec<Match> {
        self.find_iter(subject.as_bytes())
    }

    fn k_run(&self, k: &Cont, subject: &[u8], pos: usize, caps: &mut Caps) -> Option<usize> {
        match k {
            Cont::Done => Some(pos),
            Cont::Seq(nodes, kk) => self.m_seq(nodes, subject, pos, caps, kk),
            Cont::Save(idx, start, kk) => {
                let prev = caps[*idx];
                caps[*idx] = Some((*start, pos));
                match self.k_run(kk, subject, pos, caps) {
                    Some(e) => Some(e),
                    None => {
                        caps[*idx] = prev;
                        None
                    }
                }
            }
            Cont::Rep {
                node,
                min,
                max,
                greedy,
                count,
                prev,
                k,
            } => {
                if pos == *prev {
                    // An iteration that consumed nothing; repeating it forever is the one way a
                    // backtracking engine hangs, so the loop ends here and the rest decides.
                    return self.k_run(k, subject, pos, caps);
                }
                self.rep(node, *min, *max, *greedy, *count, subject, pos, caps, k)
            }
        }
    }

    fn m_seq(
        &self,
        nodes: &[Node],
        subject: &[u8],
        pos: usize,
        caps: &mut Caps,
        k: &Cont,
    ) -> Option<usize> {
        match nodes.split_first() {
            None => self.k_run(k, subject, pos, caps),
            Some((head, rest)) => self.m_one(head, subject, pos, caps, &Cont::Seq(rest, k)),
        }
    }

    /// A repeat whose body always consumes `w > 0` bytes and captures nothing: the run of
    /// iterations is found by a loop, and the backtrack walks the recorded end positions. Depth is
    /// then a property of the PATTERN, not of the subject — see [`Node::Repeat::fixed`].
    #[allow(clippy::too_many_arguments)]
    fn rep_fixed(
        &self,
        node: &Node,
        min: usize,
        max: usize,
        greedy: bool,
        w: usize,
        subject: &[u8],
        pos: usize,
        caps: &mut Caps,
        k: &Cont,
    ) -> Option<usize> {
        let mut ends = vec![pos];
        let mut at = pos;
        while ends.len() - 1 < max {
            if self.m_one(node, subject, at, caps, &Cont::Done) != Some(at + w) {
                break;
            }
            at += w;
            ends.push(at);
        }
        let n = ends.len() - 1;
        if n < min {
            return None;
        }
        let order: Vec<usize> = if greedy {
            (min..=n).rev().collect()
        } else {
            (min..=n).collect()
        };
        for i in order {
            if let Some(e) = self.k_run(k, subject, ends[i], caps) {
                return Some(e);
            }
        }
        None
    }

    #[allow(clippy::too_many_arguments)]
    fn rep(
        &self,
        node: &Node,
        min: usize,
        max: usize,
        greedy: bool,
        count: usize,
        subject: &[u8],
        pos: usize,
        caps: &mut Caps,
        k: &Cont,
    ) -> Option<usize> {
        let more = |s: &Self, caps: &mut Caps| -> Option<usize> {
            if count >= max {
                return None;
            }
            let cont = Cont::Rep {
                node,
                min,
                max,
                greedy,
                count: count + 1,
                prev: pos,
                k,
            };
            s.m_one(node, subject, pos, caps, &cont)
        };
        let stop = |s: &Self, caps: &mut Caps| -> Option<usize> {
            if count < min {
                return None;
            }
            s.k_run(k, subject, pos, caps)
        };
        let saved = caps.clone();
        if greedy {
            if let Some(e) = more(self, caps) {
                return Some(e);
            }
            caps.clone_from(&saved);
            let r = stop(self, caps);
            if r.is_none() {
                caps.clone_from(&saved);
            }
            r
        } else {
            if let Some(e) = stop(self, caps) {
                return Some(e);
            }
            caps.clone_from(&saved);
            let r = more(self, caps);
            if r.is_none() {
                caps.clone_from(&saved);
            }
            r
        }
    }

    fn m_one(
        &self,
        node: &Node,
        subject: &[u8],
        pos: usize,
        caps: &mut Caps,
        k: &Cont,
    ) -> Option<usize> {
        match node {
            Node::Empty => self.k_run(k, subject, pos, caps),
            Node::Byte(b) => {
                if subject.get(pos) == Some(b) {
                    self.k_run(k, subject, pos + 1, caps)
                } else {
                    None
                }
            }
            Node::Any => match subject.get(pos) {
                Some(b) if *b != b'\n' => self.k_run(k, subject, pos + 1, caps),
                _ => None,
            },
            Node::Class(c) => match subject.get(pos) {
                Some(b) if c.has(*b) => self.k_run(k, subject, pos + 1, caps),
                _ => None,
            },
            Node::Start => {
                if pos == 0 {
                    self.k_run(k, subject, pos, caps)
                } else {
                    None
                }
            }
            Node::End => {
                let at_end =
                    pos == subject.len() || (pos + 1 == subject.len() && subject[pos] == b'\n');
                if at_end {
                    self.k_run(k, subject, pos, caps)
                } else {
                    None
                }
            }
            Node::WordBoundary(want) => {
                let before = pos > 0 && is_word(subject[pos - 1]);
                let after = pos < subject.len() && is_word(subject[pos]);
                if (before != after) == *want {
                    self.k_run(k, subject, pos, caps)
                } else {
                    None
                }
            }
            Node::Group(idx, inner) => match idx {
                Some(i) => self.m_one(inner, subject, pos, caps, &Cont::Save(*i, pos, k)),
                None => self.m_one(inner, subject, pos, caps, k),
            },
            Node::Look {
                behind,
                neg,
                width,
                node,
            } => {
                let hit = if *behind {
                    if pos < *width {
                        false
                    } else {
                        let mut probe = caps.clone();
                        self.m_one(node, subject, pos - width, &mut probe, &Cont::Done) == Some(pos)
                    }
                } else {
                    let mut probe = caps.clone();
                    let got = self.m_one(node, subject, pos, &mut probe, &Cont::Done);
                    if got.is_some() && !*neg {
                        caps.clone_from(&probe);
                    }
                    got.is_some()
                };
                if hit != *neg {
                    self.k_run(k, subject, pos, caps)
                } else {
                    None
                }
            }
            Node::BackRef(i) => {
                let Some((a, b)) = caps.get(*i).copied().flatten() else {
                    // An unset group backreferences the empty string, which is what makes
                    // `r"…"` (no hashes) close on a bare quote.
                    return self.k_run(k, subject, pos, caps);
                };
                let want = &subject[a..b];
                if subject.len() >= pos + want.len() && &subject[pos..pos + want.len()] == want {
                    self.k_run(k, subject, pos + want.len(), caps)
                } else {
                    None
                }
            }
            Node::Concat(items) => self.m_seq(items, subject, pos, caps, k),
            Node::Alt(branches) => {
                let saved = caps.clone();
                for b in branches {
                    if let Some(e) = self.m_one(b, subject, pos, caps, k) {
                        return Some(e);
                    }
                    caps.clone_from(&saved);
                }
                None
            }
            Node::Repeat {
                node,
                min,
                max,
                greedy,
                fixed: Some(w),
            } => self.rep_fixed(node, *min, *max, *greedy, *w, subject, pos, caps, k),
            Node::Repeat {
                node,
                min,
                max,
                greedy,
                fixed: None,
            } => self.rep(node, *min, *max, *greedy, 0, subject, pos, caps, k),
        }
    }
}

fn first_is_start(node: &Node) -> bool {
    match node {
        Node::Start => true,
        Node::Concat(items) => items.first().is_some_and(first_is_start),
        Node::Group(_, inner) => first_is_start(inner),
        Node::Alt(branches) => branches.iter().all(first_is_start),
        _ => false,
    }
}

/// The longest run of mandatory literal bytes in a top-level concatenation. Conservative by
/// construction: anything that is not a plain byte ends the run, and an alternation contributes
/// nothing.
fn required_literal(node: &Node) -> Option<Vec<u8>> {
    let items: &[Node] = match node {
        Node::Concat(items) => items,
        other => std::slice::from_ref(other),
    };
    let mut best: Vec<u8> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    for it in items {
        match it {
            Node::Byte(b) => cur.push(*b),
            Node::Group(_, inner) => {
                if let Node::Byte(b) = &**inner {
                    cur.push(*b);
                } else {
                    if cur.len() > best.len() {
                        best = std::mem::take(&mut cur);
                    }
                    cur.clear();
                }
            }
            _ => {
                if cur.len() > best.len() {
                    best = std::mem::take(&mut cur);
                }
                cur.clear();
            }
        }
    }
    if cur.len() > best.len() {
        best = cur;
    }
    if best.len() >= 2 {
        Some(best)
    } else {
        None
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// `re.escape` for the many rules that take a literal out of the ceilings file and build a pattern
/// around it. Escapes exactly the ASCII punctuation Python's own `re.escape` does.
pub fn escape(literal: &str) -> String {
    let mut out = String::with_capacity(literal.len() * 2);
    for ch in literal.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || !ch.is_ascii() {
            out.push(ch);
        } else {
            out.push('\\');
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pat: &str, subject: &str) -> bool {
        Regex::new(pat).expect("compiles").is_match_str(subject)
    }

    #[test]
    fn literals_classes_and_quantifiers() {
        assert!(m(r"ab+c", "xxabbbcyy"));
        assert!(!m(r"ab+c", "xxacyy"));
        assert!(m(r"[A-Za-z_][A-Za-z0-9_]*", "_x9"));
        assert!(m(r"a{2,3}b", "aaab"));
        assert!(!m(r"a{4}b", "aaab"));
        assert!(m(r"\d+\.\d+", "v1.25"));
    }

    /// The lookbehind idiom every ported rule uses to mean "a whole token": `run_unit` must not
    /// match inside `rerun_unit`.
    #[test]
    fn negative_lookbehind_makes_a_word() {
        let r = Regex::new(r"(?<![A-Za-z0-9_])run_unit\s*\(").expect("compiles");
        assert!(r.is_match_str("    run_unit(cx)"));
        assert!(!r.is_match_str("    rerun_unit(cx)"));
        assert!(r.is_match_str("run_unit ("));
    }

    #[test]
    fn negative_lookahead_and_anchors() {
        let r = Regex::new(r"fn\s+attempt(?![A-Za-z0-9_])").expect("compiles");
        assert!(r.is_match_str("pub fn attempt(&self)"));
        assert!(!r.is_match_str("pub fn attempt_once(&self)"));
        let anchored = Regex::new(r"^(install_[a-z0-9_]+|set_[a-z0-9_]+_factory)$").expect("ok");
        assert!(anchored.full_match(b"install_protocols"));
        assert!(anchored.full_match(b"set_stream_translator_factory"));
        assert!(!anchored.full_match(b"xinstall_protocols"));
        assert!(!anchored.full_match(b"install_protocols_extra_UPPER"));
    }

    /// THE RAW-STRING LITERAL. A `br#"…"#` read without backreference support is not one literal
    /// but a short one ending at the first inner quote, and the braces after it unbalance the
    /// `#[cfg(test)]` depth counter — the exact fault `rules.py`'s own comment describes.
    #[test]
    fn raw_string_literal_closes_on_its_own_hash_run() {
        let r = Regex::new(
            r#"(?<![A-Za-z0-9_])b?r(?P<hashes>#*)"(?P<rawbody>(?:[^"]|"(?!(?P=hashes)))*)"(?P=hashes)|(?<![A-Za-z0-9_])b?"(?P<body>(?:\\.|[^"\\])*)""#,
        )
        .expect("compiles");
        let full = br##"    let s = br#"{"a": "{{"}"#;"##;
        let hit = r.search(full).expect("the raw literal is one match");
        assert_eq!(
            String::from_utf8_lossy(&full[hit.start..hit.end]),
            r##"br#"{"a": "{{"}"#"##
        );
        // and the brace count over the blanked body is balanced, which is the property the
        // `#[cfg(test)]` depth counter downstream actually depends on.
        assert_eq!(
            hit.str_of(full, r.group_index("rawbody").expect("named"))
                .as_deref(),
            Some(r#"{"a": "{{"}"#)
        );
    }

    #[test]
    fn alternation_and_case_insensitivity() {
        assert!(m(r"(?i)\b(anthropic|openai)\b", "the OpenAI dialect"));
        assert!(!m(r"\b(anthropic|openai)\b", "the OpenAI dialect"));
        assert!(m(
            r"(?:mem::forget|drop)\(\s*&?\s*[A-Za-z_][A-Za-z0-9_]*[Hh]old[A-Za-z0-9_]*",
            "mem::forget( &myHoldThing"
        ));
    }

    #[test]
    fn groups_are_captured_and_named() {
        let r = Regex::new(r"(?<![A-Za-z0-9_])fn\s+([A-Za-z_][A-Za-z0-9_]*)").expect("ok");
        let s = b"pub async fn run_unit(" as &[u8];
        let hit = r.search(s).expect("match");
        assert_eq!(hit.str_of(s, 1).as_deref(), Some("run_unit"));
    }

    #[test]
    fn find_iter_walks_every_occurrence() {
        let r = Regex::new(r"[A-Za-z_][A-Za-z0-9_]*").expect("ok");
        let s = b"a bb ccc" as &[u8];
        let all: Vec<String> = r
            .find_iter(s)
            .iter()
            .filter_map(|h| h.str_of(s, 0))
            .collect();
        assert_eq!(all, vec!["a", "bb", "ccc"]);
    }

    /// A pattern the engine cannot honour must be an error, never a matcher that quietly means
    /// something else — a gate whose rule silently changed shape is worse than one that refused.
    #[test]
    fn unsupported_constructs_are_refused() {
        assert!(Regex::new(r"(?<foo>x)").is_err());
        assert!(Regex::new(r"a)").is_err());
        assert!(
            Regex::new(r"(?<=a+)b").is_err(),
            "variable-width lookbehind"
        );
    }

    #[test]
    fn escape_matches_pythons_own() {
        assert_eq!(escape("Decision::proceed("), r"Decision\:\:proceed\(");
        assert_eq!(escape("busbar_core::"), r"busbar_core\:\:");
    }
}
