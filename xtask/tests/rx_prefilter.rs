//! THE MATCHER'S SKIPS NEVER CHANGE AN ANSWER.
//!
//! `rx::Regex::search_at` skips work two ways before it enters the backtracking matcher: a subject
//! that holds none of the literals every match must contain is refused outright, and a start
//! position whose byte no match can begin with is passed over. Both are optimisations and nothing
//! else, so `search` must return exactly what trying every start position with the unskipped
//! matcher (`match_at`) returns — the same start, end and capture spans — for every pattern shape
//! the construction gate's rules and its lexer spell, over subjects built to sit on the skips'
//! edges: alternations with an empty or a class branch, nullable patterns, lookarounds at the
//! start, anchors, case folding, backreferences, multi-byte UTF-8.

use xtask::rx::{Match, Regex};

const PATTERNS: &[&str] = &[
    // The lexer's own patterns (construction/tree.rs).
    r#"(?<![A-Za-z0-9_])b?r(?P<hashes>#*)"(?P<rawbody>(?:[^"]|"(?!(?P=hashes)))*)"(?P=hashes)|(?<![A-Za-z0-9_])b?"(?P<body>(?:\\.|[^"\\])*)""#,
    r"'(?:\\.|[^'\\])'",
    r"[^a-z0-9_]test[^a-z0-9_]",
    r"(^|[^A-Za-z0-9_])mod([^A-Za-z0-9_])",
    r"(?<![A-Za-z0-9_])fn\s+([A-Za-z_][A-Za-z0-9_]*)",
    // Shapes the ceilings file spells.
    r"^(install_[a-z0-9_]+|set_[a-z0-9_]+_factory)$",
    r"(?<![A-Za-z0-9_])(Pass|Grant)::mint_bound\(",
    r"(?<![A-Za-z0-9_])(?:[A-Za-z0-9_]+::)*CallId>?::seal(_bound)?\(",
    r"::settle\(|\.settle\(|::release\(|\.release\(",
    r"(?:mem::forget|drop)\(\s*&?\s*[A-Za-z_][A-Za-z0-9_]*[Hh]old[A-Za-z0-9_]*",
    r"Hold::open|HoldCell|\blet\s+(?:mut\s+)?\w*[Hh]old\w*\s*[:=]",
    r"busbar_kernel_ledger::cost::[A-Za-z0-9_:]*price|busbar_kernel_ledger::cost::apply_tier",
    r"impl(<[^>]*>)?\s+(busbar_contract::)?(plugin::)?KernelSeal\s+for",
    // Edges of the two skips.
    r"ab|",
    r"(?:ab|[xy])cd",
    r"x*",
    r"x+yz",
    r"(?=ab)abc|zz",
    r"\bword\b",
    r"(?i)MiNt\(",
    r"(a)\1bc",
    r"(?:foo){0,2}bar",
    r"(?:foo){2}bar",
    r"é+x",
    r".mint",
    r"$",
    r"^$",
    r"(?:a|b)?",
];

const SUBJECTS: &[&str] = &[
    "",
    "ab",
    "abcd xcd ycd",
    "let x = r#\"a \"quoted\" b\"#; let y = \"esc \\\" q\";",
    "b\"bytes\" br##\"raw \"# still\"##",
    "pub fn attempt_once(&self) -> u32 { 'a' }",
    "#[cfg(test)] mod tests { use super::*; }",
    "install_protocols",
    "set_stream_translator_factory",
    "xinstall_protocols",
    "let k = Pass::mint_bound(&x); Grant::mint_bound(y)",
    "a::b::CallId::seal(x); CallId>::seal_bound(y)",
    "h.settle(); x::release(z)",
    "mem::forget(my_hold); drop( &theHoldCell )",
    "let mut big_hold = Hold::open(); HoldCell::new()",
    "busbar_kernel_ledger::cost::list_price(x) busbar_kernel_ledger::cost::apply_tier(y)",
    "impl<T: X> busbar_contract::plugin::KernelSeal for Thing {}",
    "aaaxxxyz xyz",
    "abc zz",
    "a word, words, sword word",
    "MINT( mint( Mint(",
    "aabc abc aaabc",
    "foofoobar foobar bar fobar",
    "ééx éx x",
    "— é unicode .mint xmint",
    "\u{2014}\u{2014}ab",
];

fn oracle(r: &Regex, subject: &[u8]) -> Option<Match> {
    (0..=subject.len())
        .filter(|&p| !subject.get(p).is_some_and(|b| (0x80..0xC0).contains(b)))
        .find_map(|p| r.match_at(subject, p))
}

fn spans(m: &Option<Match>, groups: usize) -> Option<Vec<Option<(usize, usize)>>> {
    m.as_ref()
        .map(|m| (0..=groups).map(|g| m.group(g)).collect())
}

#[test]
fn search_finds_exactly_what_every_start_position_finds() {
    for pat in PATTERNS {
        let r = Regex::new(pat).unwrap_or_else(|e| panic!("{pat}: {e}"));
        for subject in SUBJECTS {
            let s = subject.as_bytes();
            for from in 0..=s.len() {
                if s.get(from).is_some_and(|b| (0x80..0xC0).contains(b)) {
                    continue;
                }
                let got = r.search_at(s, from);
                let want = (from..=s.len())
                    .filter(|&p| !s.get(p).is_some_and(|b| (0x80..0xC0).contains(b)))
                    .find_map(|p| r.match_at(s, p));
                let (g, w) = (spans(&got, 6), spans(&want, 6));
                assert_eq!(
                    g, w,
                    "pattern {pat:?} over {subject:?} from {from}: search {g:?}, every start {w:?}"
                );
            }
            assert_eq!(
                r.is_match(s),
                oracle(&r, s).is_some(),
                "pattern {pat:?} over {subject:?}"
            );
        }
    }
}

#[test]
fn find_iter_walks_the_same_matches_the_unskipped_matcher_finds() {
    for pat in PATTERNS {
        let r = Regex::new(pat).unwrap_or_else(|e| panic!("{pat}: {e}"));
        for subject in SUBJECTS {
            let s = subject.as_bytes();
            let got: Vec<(usize, usize)> =
                r.find_iter(s).iter().map(|m| (m.start, m.end)).collect();
            let mut want = Vec::new();
            let mut at = 0;
            while at <= s.len() {
                let Some(m) = (at..=s.len())
                    .filter(|&p| !s.get(p).is_some_and(|b| (0x80..0xC0).contains(b)))
                    .find_map(|p| r.match_at(s, p))
                else {
                    break;
                };
                at = if m.end > m.start { m.end } else { m.end + 1 };
                want.push((m.start, m.end));
            }
            assert_eq!(got, want, "pattern {pat:?} over {subject:?}");
        }
    }
}
