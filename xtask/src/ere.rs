//! A POSIX-ERE SUBSET MATCHER, because the rule tables are the gate.
//!
//! `structure-lint.sh` is not N bespoke scanners; it is four generic scanners driven by declarative
//! tables whose cells are awk EREs (`fs::rename\(`, `[Oo]peration(\(\))?[[:space:]]*==`,
//! `matches!\([^)]*OpShape::`). That shape is the reason adding a choke point is a one-row edit, and
//! it is the property worth keeping across the port. Translating each cell into a hand-written Rust
//! predicate would keep the verdicts and lose the table: forty bespoke matchers nobody can diff
//! against the row they came from, each free to disagree with its ERE in a way only a tree that
//! already violates the rule would reveal.
//!
//! So the ERE stays data and this module reads it. The subset is exactly what those tables use:
//! literals and escapes, `.`, bracket expressions (negation, ranges, POSIX classes), groups with
//! `|` alternation, the three postfix repeats, and the two anchors. NO backreferences, no
//! lazy quantifiers, no lookaround — none appear in a POSIX ERE and a pattern that reaches for one
//! is refused at construction rather than silently matching something else.
//!
//! MATCHING IS GREEDY-BACKTRACKING, NOT LEFTMOST-LONGEST. The difference is unobservable for every
//! pattern in the tables (each one's variable-length parts are pinned by a following literal), and
//! the two places that read the matched SPAN rather than its existence — the declaration scanner's
//! `RSTART`/`RLENGTH` — take the greedy answer, which is the longest one there.
//!
//! ZERO-WIDTH REPETITION TERMINATES BY CONSTRUCTION: an iteration of `*`/`+` that consumed nothing
//! ends the repeat rather than being tried again, so a nullable group under a star cannot hang the
//! scanner over a file nobody would think to test.
//!
//! [`Ere::required_literal`] is the prefilter, and it is not an optimisation detail: the census
//! alone runs twenty patterns over every production line in the tree, and a backtracking matcher
//! asked to try every start offset of every line is the difference between a gate that runs on every
//! push and one people learn to skip. The literal it extracts is MANDATORY — taken only from the
//! top-level sequence, never from inside a group or an optional repeat — so a line the prefilter
//! rejects cannot match the pattern.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Posix {
    Alpha,
    Digit,
    Alnum,
    Space,
    Upper,
    Lower,
    Punct,
    Xdigit,
}

impl Posix {
    fn parse(name: &str) -> Option<Posix> {
        match name {
            "alpha" => Some(Posix::Alpha),
            "digit" => Some(Posix::Digit),
            "alnum" => Some(Posix::Alnum),
            "space" => Some(Posix::Space),
            "upper" => Some(Posix::Upper),
            "lower" => Some(Posix::Lower),
            "punct" => Some(Posix::Punct),
            "xdigit" => Some(Posix::Xdigit),
            _ => None,
        }
    }

    fn holds(&self, c: char) -> bool {
        match self {
            Posix::Alpha => c.is_ascii_alphabetic(),
            Posix::Digit => c.is_ascii_digit(),
            Posix::Alnum => c.is_ascii_alphanumeric(),
            Posix::Space => c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\x0b',
            Posix::Upper => c.is_ascii_uppercase(),
            Posix::Lower => c.is_ascii_lowercase(),
            Posix::Punct => c.is_ascii_punctuation(),
            Posix::Xdigit => c.is_ascii_hexdigit(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ClassItem {
    Ch(char),
    Range(char, char),
    Class(Posix),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Char(char),
    Any,
    Class {
        negated: bool,
        items: Vec<ClassItem>,
    },
    /// `(a|b|c)` — and the whole pattern's top level, which is one alternation of one branch.
    Group(Vec<Vec<Node>>),
    Repeat {
        node: Box<Node>,
        min: u32,
        max: Option<u32>,
    },
    Start,
    End,
}

/// A compiled expression. Construction is fallible and the error NAMES the pattern, because a
/// pattern that fails to compile is a rule that scans nothing, and zero hits is every ban's pass.
#[derive(Debug, Clone)]
pub struct Ere {
    seq: Vec<Node>,
    src: String,
    literal: Option<String>,
}

impl fmt::Display for Ere {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.src)
    }
}

impl Ere {
    pub fn new(pattern: &str) -> Result<Ere, String> {
        let chars: Vec<char> = pattern.chars().collect();
        let mut p = Parser { chars, i: 0 };
        let alts = p.alternation()?;
        if p.i != p.chars.len() {
            return Err(format!(
                "`{pattern}`: unbalanced `)` at offset {} — a pattern that does not compile is a \
                 rule that scans nothing, and nothing found is every ban's pass",
                p.i
            ));
        }
        let seq = if alts.len() == 1 {
            alts.into_iter().next().expect("len == 1")
        } else {
            vec![Node::Group(alts)]
        };
        let literal = mandatory_literal(&seq);
        Ok(Ere {
            seq,
            src: pattern.to_string(),
            literal,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.src
    }

    /// The longest literal run every match MUST contain, taken from the top-level sequence only.
    pub fn required_literal(&self) -> Option<&str> {
        self.literal.as_deref()
    }

    pub fn is_match(&self, hay: &str) -> bool {
        if let Some(lit) = &self.literal {
            if !hay.contains(lit.as_str()) {
                return false;
            }
        }
        let chars: Vec<char> = hay.chars().collect();
        (0..=chars.len()).any(|start| match_seq(&self.seq, &chars, start, &mut |_| true))
    }

    /// The leftmost match as `(start, len)` in CHARACTERS — awk's `RSTART`/`RLENGTH`, zero-based.
    pub fn find(&self, hay: &str) -> Option<(usize, usize)> {
        if let Some(lit) = &self.literal {
            if !hay.contains(lit.as_str()) {
                return None;
            }
        }
        let chars: Vec<char> = hay.chars().collect();
        for start in 0..=chars.len() {
            let mut end = None;
            if match_seq(&self.seq, &chars, start, &mut |p| {
                end = Some(p);
                true
            }) {
                return end.map(|e| (start, e - start));
            }
        }
        None
    }

    /// The leftmost match's text.
    pub fn find_str(&self, hay: &str) -> Option<String> {
        let (start, len) = self.find(hay)?;
        Some(hay.chars().skip(start).take(len).collect())
    }

    /// `sub(/re/, "", s)` — remove the leftmost match, or hand back the string unchanged.
    pub fn remove_first(&self, hay: &str) -> String {
        match self.find(hay) {
            Some((start, len)) => {
                let chars: Vec<char> = hay.chars().collect();
                let mut out: String = chars[..start].iter().collect();
                out.extend(chars[start + len..].iter());
                out
            }
            None => hay.to_string(),
        }
    }
}

struct Parser {
    chars: Vec<char>,
    i: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.i).copied()
    }

    fn alternation(&mut self) -> Result<Vec<Vec<Node>>, String> {
        let mut alts = vec![self.sequence()?];
        while self.peek() == Some('|') {
            self.i += 1;
            alts.push(self.sequence()?);
        }
        Ok(alts)
    }

    fn sequence(&mut self) -> Result<Vec<Node>, String> {
        let mut out = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            let atom = self.atom()?;
            out.push(self.postfix(atom)?);
        }
        Ok(out)
    }

    fn postfix(&mut self, atom: Node) -> Result<Node, String> {
        let (min, max) = match self.peek() {
            Some('*') => (0, None),
            Some('+') => (1, None),
            Some('?') => (0, Some(1)),
            _ => return Ok(atom),
        };
        self.i += 1;
        if matches!(atom, Node::Start | Node::End) {
            return Err("a repeat applied to an anchor".to_string());
        }
        Ok(Node::Repeat {
            node: Box::new(atom),
            min,
            max,
        })
    }

    fn atom(&mut self) -> Result<Node, String> {
        let c = self.peek().ok_or("unexpected end of pattern")?;
        self.i += 1;
        match c {
            '^' => Ok(Node::Start),
            '$' => Ok(Node::End),
            '.' => Ok(Node::Any),
            '(' => {
                let alts = self.alternation()?;
                if self.peek() != Some(')') {
                    return Err("unclosed `(`".to_string());
                }
                self.i += 1;
                Ok(Node::Group(alts))
            }
            '[' => self.bracket(),
            '\\' => {
                let e = self.peek().ok_or("a trailing `\\`")?;
                self.i += 1;
                Ok(Node::Char(e))
            }
            other => Ok(Node::Char(other)),
        }
    }

    /// A bracket expression. The two POSIX quirks are honoured because the tables use both: a `]`
    /// FIRST is a literal `]` (`[]([:space:]]`, the inline-test attribute's terminator class), and a
    /// `^` first negates.
    fn bracket(&mut self) -> Result<Node, String> {
        let mut negated = false;
        if self.peek() == Some('^') {
            negated = true;
            self.i += 1;
        }
        let mut items = Vec::new();
        let mut first = true;
        loop {
            let c = self.peek().ok_or("unclosed `[`")?;
            if c == ']' && !first {
                self.i += 1;
                break;
            }
            first = false;
            if c == '[' && self.chars.get(self.i + 1) == Some(&':') {
                let close = (self.i + 2..self.chars.len())
                    .find(|k| self.chars[*k] == ':' && self.chars.get(k + 1) == Some(&']'))
                    .ok_or("unclosed POSIX class")?;
                let name: String = self.chars[self.i + 2..close].iter().collect();
                let class =
                    Posix::parse(&name).ok_or_else(|| format!("unknown class `[:{name}:]`"))?;
                items.push(ClassItem::Class(class));
                self.i = close + 2;
                continue;
            }
            self.i += 1;
            // A `-` between two characters is a range; a `-` last is a literal.
            if self.peek() == Some('-')
                && self.chars.get(self.i + 1).is_some_and(|n| *n != ']')
                && c != '-'
            {
                let hi = self.chars[self.i + 1];
                self.i += 2;
                items.push(ClassItem::Range(c, hi));
            } else {
                items.push(ClassItem::Ch(c));
            }
        }
        Ok(Node::Class { negated, items })
    }
}

fn class_holds(negated: bool, items: &[ClassItem], c: char) -> bool {
    let hit = items.iter().any(|it| match it {
        ClassItem::Ch(x) => *x == c,
        ClassItem::Range(lo, hi) => *lo <= c && c <= *hi,
        ClassItem::Class(p) => p.holds(c),
    });
    hit != negated
}

fn match_seq(nodes: &[Node], hay: &[char], pos: usize, k: &mut dyn FnMut(usize) -> bool) -> bool {
    let Some((first, rest)) = nodes.split_first() else {
        return k(pos);
    };
    match first {
        Node::Start => pos == 0 && match_seq(rest, hay, pos, k),
        Node::End => pos == hay.len() && match_seq(rest, hay, pos, k),
        Node::Char(c) => hay.get(pos) == Some(c) && match_seq(rest, hay, pos + 1, k),
        Node::Any => pos < hay.len() && match_seq(rest, hay, pos + 1, k),
        Node::Class { negated, items } => match hay.get(pos) {
            Some(c) if class_holds(*negated, items, *c) => match_seq(rest, hay, pos + 1, k),
            _ => false,
        },
        Node::Group(alts) => {
            for alt in alts {
                let mut tail = |p: usize| match_seq(rest, hay, p, k);
                if match_seq(alt, hay, pos, &mut tail) {
                    return true;
                }
            }
            false
        }
        Node::Repeat { node, min, max } => repeat(node, 0, *min, *max, rest, hay, pos, k),
    }
}

#[allow(clippy::too_many_arguments)]
fn repeat(
    node: &Node,
    taken: u32,
    min: u32,
    max: Option<u32>,
    rest: &[Node],
    hay: &[char],
    pos: usize,
    k: &mut dyn FnMut(usize) -> bool,
) -> bool {
    // GREEDY: one more iteration first, and an iteration that consumed nothing ends the repeat
    // rather than being tried again — the guard that makes a nullable group under a `*` terminate.
    if max.is_none_or(|m| taken < m) {
        let one = std::slice::from_ref(node);
        let mut more = |p: usize| p != pos && repeat(node, taken + 1, min, max, rest, hay, p, k);
        if match_seq(one, hay, pos, &mut more) {
            return true;
        }
    }
    taken >= min && match_seq(rest, hay, pos, k)
}

/// The longest run of literal characters every match must contain. Only the TOP-LEVEL sequence
/// contributes: a character inside a group or under a repeat may be optional, and a prefilter that
/// rejected a line the pattern would have matched is a ban that stopped scanning.
fn mandatory_literal(seq: &[Node]) -> Option<String> {
    let mut best = String::new();
    let mut cur = String::new();
    for node in seq {
        match node {
            Node::Char(c) => cur.push(*c),
            Node::Repeat { node, min, max: _ } if *min >= 1 => {
                // `x+` guarantees one `x`, which is a literal run of one and then a break.
                if let Node::Char(c) = node.as_ref() {
                    cur.push(*c);
                }
                if cur.len() > best.len() {
                    best = cur.clone();
                }
                cur.clear();
            }
            _ => {
                if cur.len() > best.len() {
                    best = cur.clone();
                }
                cur.clear();
            }
        }
    }
    if cur.len() > best.len() {
        best = cur;
    }
    if best.is_empty() {
        None
    } else {
        Some(best)
    }
}
