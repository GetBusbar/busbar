//! `kind-isolation:matrix` — THE FULL KIND × CRATE VOCABULARY MATRIX.
//!
//! > "it's not just planes, it's everything. core is core, plugins are plugins, transport,
//! > everything. HAS TO BE PERFECT AND CLEAN." — owner, 2026-09-08
//!
//! The four rows this module joins hold the line for the WIRES: `:vocab` proves a transport never
//! says `a2a`, and a plane never says `hyper`. What none of them measured is the COMPOSITION ROOT.
//! `crates/busbar/src/root/**` hand-wires one file per plane — `units_llm.rs`, `units_mcp.rs`,
//! `units_a2a.rs`, `units_voice.rs` — and every one of them slipped past CI, because nothing
//! counted it. A gate that measures the wires and not the place the wires are joined is a gate that
//! reports the tidy half of the tree.
//!
//! ## THE MATRIX
//!
//! For EVERY kind `K` in the kind table and EVERY crate `C` under `crates/`, this row counts how
//! many times `C` names `K`'s vocabulary. `K`'s vocabulary is DERIVED, never listed: it is the
//! package names of `K`'s member crates plus each member's INSTANCE ID (the name segments after the
//! kind marker) and, for a plane, its alias. Registering a plane, a transport or a store teaches
//! this row a new word in every other crate, on the same commit — the same derivation the rest of
//! the gate already runs on.
//!
//! A crate is never measured against its own spellings, and when `kind(C) == K` the crate's OWN id
//! is struck from the needles first: what is left is the other instances of its own kind, which is
//! the cross-instance leak `busbar-plane-llm` naming `mcp` would be.
//!
//! ## TWO INDEPENDENT SCANNERS, AND DISAGREEMENT IS RED
//!
//! > "I'd rather have it false-fail than not." — owner, 2026-09-08
//!
//! One scanner is a SEGMENT scanner: it reduces a line to a stream of lowercase alphanumeric
//! segments, splitting at every non-alphanumeric byte and at both camel-case transitions, and
//! matches a needle's own segment run inside that stream. The other is a WINDOW scanner: it walks
//! the raw line, compares bytes case-insensitively, and accepts a hit only when the characters on
//! both sides are boundaries — a non-alphanumeric, or a case transition. They share the needles and
//! share nothing else.
//!
//! The scored count is the HIGHER of the two, never the lower, and a cell where the two disagree is
//! RED unless the cell's row in `qa/kind-isolation.toml` records the disagreement and why. A name
//! written in a spelling one scanner cannot see is exactly the leak that must not pass at the lower
//! number.
//!
//! A boundary rule rather than a raw byte substring, and the reason is measurable rather than
//! aesthetic: `sse` is a transport instance and also the middle of `assert`, `ws` is a transport
//! instance and also the middle of `rows`. A raw substring scan of this tree answers 35 306 for
//! `sse` and 5 671 for `ws`, numbers made almost entirely of English, and a ceiling pinned to them
//! moves whenever somebody writes an assertion. That is not a stricter gate, it is a line counter
//! wearing one. The boundary rule keeps every spelling a human would recognise as the name —
//! `a2a_session`, `mcpFrame`, `root-voice-serve`, `busbar_transport_http`, `VoiceServe`, the
//! filename, the feature, the comment — and refuses the ones that are not names at all.
//!
//! ## WHAT IS SCANNED: EVERYTHING, INCLUDING COMMENTS, INCLUDING TESTS
//!
//! Every `.rs` and every `.toml` under the crate, whole text — identifiers, string literals, doc
//! comments, ordinary comments, `#[cfg(feature = …)]` attributes, Cargo dependency names, Cargo
//! feature names — AND the file's own path, so `root/voice_serve.rs` is a hit before a byte of it
//! is read. Nothing is stripped: a plane named in a doc comment of the kernel is the kernel's
//! reader being taught a plane, and the incident that motivated this row (`root-voice-serve`, a
//! plane-named accept loop behind a plane-named feature) named its plane in the filename, the
//! feature, the identifiers AND the doc comments at once.
//!
//! Tests are NOT excluded. A transport's own test that names a plane is that transport's source
//! naming a plane; the only place tests may legitimately name planes is the composition root's,
//! because the root's tests drive the assembly — and that is a LISTED cell with a citation and a
//! ceiling, not a silent `continue` in this file.
//!
//! ## NO SILENT EXEMPTIONS: `qa/kind-isolation.toml` IS THE WHOLE ALLOWANCE
//!
//! There is no allow-list in this source, and there is no second reader either: these rows go
//! through the SAME hand reader the `[[transitional]]`, `[[registered]]` and `[[announced]]` tables
//! do ([`super::parse_registry`]), on the same terms — a missing field, an empty field or an
//! unknown field is REFUSED AT LOAD rather than skipped. Three tables:
//!
//! * `[[edge]]` — one per kind → kind CLASS, carrying `cite` (the `ARCHITECTURE.md` clause that
//!   grants it, or the words that say none does), `why` (what the number is made of) and `drain`
//!   (the line that deletes it; a ceiling with no route to zero is a ceiling nobody drains). The
//!   prose belongs to the class because that is what a reader is reading.
//! * `[[cell]]` — one per crate × kind, carrying `count`: TODAY'S MEASURED NUMBER, exactly, not a
//!   budget. The number belongs to the crate because that is what the ratchet moves.
//! * `[[disagreement]]` — one per cell whose two scanners return different totals, carrying the
//!   `note` that says which spelling they read differently.
//!
//! The RATCHET IS EXACT IN BOTH DIRECTIONS. A count above its row is the landing that grew the
//! coupling. A count BELOW its row is stale slack, and stale slack is how drift hides: the row must
//! come down on the commit that drained it, or the gate is red. A row whose cell now measures zero
//! is a dead allowance and must be struck. A cell above zero with no row at all is an UNLISTED
//! EDGE — refused, whatever `ARCHITECTURE.md` may or may not grant, because an edge nobody wrote
//! down is an edge nobody reviewed.
//!
//! The ship twin owes the same row at ZERO everywhere, and owes it without consulting the ledger:
//! `qa/kind-isolation.toml` is a record of what 1.6.0 still has to delete, not a shape it is
//! allowed to keep.

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::{Ctx, WalkSpec};
use crate::ledger::Row;

use super::{canon_plane, CrateInfo, Family, PLANE_ALIASES};

pub const ROW_MATRIX: &str = "kind-isolation:matrix";

/// The ledger this row shares with the rest of the gate — named in `PLUGIN-TREE.md` before either
/// existed, which is why neither invents a second place.
pub const LEDGER: &str = "qa/kind-isolation.toml";

/// A scan set below this is not a tree this row can be a row over. `.rs` and `.toml` together.
const MIN_SCANNED: usize = 600;

// ------------------------------------------------------------------------------------------------
// the vocabulary, derived
// ------------------------------------------------------------------------------------------------

/// One needle: a spelling of a kind's member, and which member it came from.
#[derive(Debug, Clone)]
struct Needle {
    /// The canonical spelling, dash-joined and lowercase.
    word: String,
    /// The crate whose name or id this spells — so a crate is never measured against itself.
    owner: String,
    /// The instance id this spells, or the empty string when the needle is a package name.
    id: String,
    /// THE CARVE-OUT SHADOW. The segment forms of every LONGER crate name that extends this
    /// spelling and belongs to a `core`-kind crate — `busbar-core-policy` over `busbar-core`. A
    /// hit that one of these extends is that crate's own name, not the legacy crate's, and both
    /// scanners skip it. Empty for every needle nothing extends.
    shadows: Vec<Vec<String>>,
}

/// Split a dash/underscore-joined spelling into its lowercase segments.
fn needle_segments(word: &str) -> Vec<String> {
    word.split(['-', '_'])
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// The instance a crate is an instance OF, spelled as this row's needles spell it.
fn own_id(c: &CrateInfo) -> Option<String> {
    match c.family {
        // A DIALECT'S ID IS ITS PLANE'S. `busbar-plane-streams-voice` is the streams plane's
        // dialect; counting `voice` as a fifth plane would invent an instance the tree has not.
        Family::Plane => c.remainder.first().map(|p| canon_plane(p)),
        _ => (!c.remainder.is_empty()).then(|| c.remainder.join("-")),
    }
}

/// Whether two ids are the two spellings of one plane.
fn alias_of(a: &str, b: &str) -> bool {
    PLANE_ALIASES
        .iter()
        .any(|(from, to, _)| (a == *from && b == *to) || (a == *to && b == *from))
}

/// EVERY KIND'S VOCABULARY, READ OFF THE CENSUS.
///
/// A member contributes three spellings, and which of them apply is the KIND TABLE'S OWN ANSWER
/// rather than a judgement made here:
///
/// * its PACKAGE NAME — `busbar-store-memory` — for every kind without exception;
/// * its KIND-QUALIFIED id — `store-memory`, `unit-cost`, `plane-llm` — likewise for every kind:
///   the marker and the id together are a name and cannot be anything else;
/// * its BARE id — `llm`, `mcp`, `voice`, `http`, `ws` — only for a kind whose [`Family`] is not
///   [`Family::Neutral`]. That is not an exemption invented here. `Family::Neutral` is the kind
///   table's own words for "a kind with NO INSTANCE VOCABULARY OF ITS OWN", and it is already
///   load-bearing in the `:name` and `:vocab` rows: a neutral kind's members are named for the step
///   of the loop they run, not for an instance, so `cost`, `wal`, `ledger`, `memory` and `usage`
///   are domain words the whole tree shares rather than a kind's private vocabulary. Counting them
///   would report the Teller loop talking about money as the cost unit leaking into the ledger
///   unit. The plane and transport families ARE instance vocabularies — that is what the split is
///   about — so their bare ids count everywhere, which is how `root/units_llm.rs` and
///   `root-voice-serve` are caught.
///
/// A plane contributes its alias too, because `voice` and `streams` are one instance until the
/// rename lands.
///
/// One spelling is struck: a needle that is a PROPER SEGMENT PREFIX of another crate's package name
/// names nothing in particular. `busbar`, the composition root's package name, is the prefix of
/// every crate in the workspace, and counting it would report every `busbar_kernel::` path in the
/// tree as a crate naming the root.
///
/// EXCEPT THE CARVE-OUT. `busbar-core` is the proper prefix of every `busbar-core-*` crate, and
/// those crates exist BECAUSE `busbar-core` is being drained into them. Struck on that rule, the
/// legacy needle vanished the day the first core-kind crate landed and every `× legacy` cell in the
/// ledger measured zero — the retirement ratchet reported as done by the landing that had barely
/// begun it (measured on `busbar-core-policy`: 28 `dead-cell` and 16 `dead-edge` findings, all of
/// them the ratchet disappearing). So a needle whose ONLY extenders are `core`-kind crates is
/// KEPT, and it carries those names as its [`Needle::shadows`]: a hit that a longer core-crate
/// name extends is that crate's name, not the legacy crate's, and is not counted. Any other
/// extender still strikes the needle, exactly as before.
fn vocabulary(crates: &[CrateInfo]) -> BTreeMap<&'static str, Vec<Needle>> {
    let mut out: BTreeMap<&'static str, Vec<Needle>> = BTreeMap::new();
    for c in crates {
        let Some(kind) = c.kind else { continue };
        let entry = out.entry(kind).or_default();
        entry.push(Needle {
            word: c.name.to_lowercase(),
            owner: c.name.clone(),
            id: String::new(),
            shadows: Vec::new(),
        });
        let Some(id) = own_id(c) else { continue };
        let mut ids = vec![id.clone()];
        for (from, to, _) in PLANE_ALIASES {
            if id == *from {
                ids.push((*to).to_string());
            } else if id == *to {
                ids.push((*from).to_string());
            }
        }
        for id in ids {
            entry.push(Needle {
                word: format!("{kind}-{id}"),
                owner: c.name.clone(),
                id: id.clone(),
                shadows: Vec::new(),
            });
            if c.family != Family::Neutral {
                entry.push(Needle {
                    word: id.clone(),
                    owner: c.name.clone(),
                    id,
                    shadows: Vec::new(),
                });
            }
        }
    }
    let names: Vec<(Vec<String>, bool)> = crates
        .iter()
        .map(|c| {
            (
                needle_segments(&c.name.to_lowercase()),
                c.kind == Some("core"),
            )
        })
        .collect();
    for v in out.values_mut() {
        v.retain_mut(|n| {
            let segs = needle_segments(&n.word);
            let extenders: Vec<&(Vec<String>, bool)> = names
                .iter()
                .filter(|(full, _)| full.len() > segs.len() && full[..segs.len()] == segs[..])
                .collect();
            if extenders.is_empty() {
                return true;
            }
            if extenders.iter().all(|(_, core)| *core) {
                n.shadows = extenders.iter().map(|(full, _)| full.clone()).collect();
                return true;
            }
            false
        });
        v.sort_by(|a, b| a.word.cmp(&b.word).then(a.owner.cmp(&b.owner)));
        v.dedup_by(|a, b| a.word == b.word);
    }
    out.retain(|_, v| !v.is_empty());
    out
}

/// The needles kind `k` puts to crate `c` — its own spellings and its own instance struck out
/// first, plus the aliases of its own instance.
fn needles_for<'a>(vocab: &'a [Needle], c: &CrateInfo) -> Vec<&'a Needle> {
    let mine = own_id(c);
    vocab
        .iter()
        .filter(|n| n.owner != c.name)
        .filter(|n| match (&mine, n.id.is_empty()) {
            (Some(own), false) => &n.id != own && !alias_of(own, &n.id),
            _ => true,
        })
        .collect()
}

// ------------------------------------------------------------------------------------------------
// scanner one — the segment stream
// ------------------------------------------------------------------------------------------------

/// Reduce a line to lowercase alphanumeric segments, splitting at every non-alphanumeric byte and
/// at BOTH camel-case transitions (`voiceServe` and `HTTPTransport` both split).
fn line_segments(line: &str) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    for i in 0..chars.len() {
        let ch = chars[i];
        if !ch.is_ascii_alphanumeric() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        let prev = if i == 0 { None } else { Some(chars[i - 1]) };
        let next = chars.get(i + 1).copied();
        // lower -> upper is `voiceServe`; upper -> upper -> lower is `HTTPTransport`. A DIGIT NEVER
        // opens a segment: `A2A` is one word, and splitting it would leave the window scanner
        // seeing the plane where the segment scanner does not.
        let camel = prev
            .map(|p| p.is_ascii_lowercase() && ch.is_ascii_uppercase())
            .unwrap_or(false);
        let acronym_end = prev.map(|p| p.is_ascii_uppercase()).unwrap_or(false)
            && ch.is_ascii_uppercase()
            && next.map(|n| n.is_ascii_lowercase()).unwrap_or(false);
        if (camel || acronym_end) && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        cur.push(ch.to_ascii_lowercase());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// The two-letter buckets a line offers, one per position a segment OPENS at — the only positions
/// either scanner can match at.
fn line_buckets(chars: &[char]) -> Vec<Bucket> {
    let mut out: Vec<Bucket> = Vec::new();
    let mut open = false;
    for i in 0..chars.len() {
        let ch = chars[i];
        if !ch.is_ascii_alphanumeric() {
            open = false;
            continue;
        }
        let prev = if i == 0 { None } else { Some(chars[i - 1]) };
        let next = chars.get(i + 1).copied();
        let camel = prev
            .map(|p| p.is_ascii_lowercase() && ch.is_ascii_uppercase())
            .unwrap_or(false);
        let acronym_end = prev.map(|p| p.is_ascii_uppercase()).unwrap_or(false)
            && ch.is_ascii_uppercase()
            && next.map(|n| n.is_ascii_lowercase()).unwrap_or(false);
        if !open || camel || acronym_end {
            let a = ch.to_ascii_lowercase();
            out.push((a, '\0'));
            if let Some(b) = next {
                out.push((a, b.to_ascii_lowercase()));
            }
        }
        open = true;
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// How many times `needle`'s segment run appears in the segment stream.
fn count_by_segments(segs: &[String], needle: &[String], shadows: &[Vec<String>]) -> usize {
    if needle.is_empty() || needle.len() > segs.len() {
        return 0;
    }
    (0..=(segs.len() - needle.len()))
        .filter(|&i| segs[i..i + needle.len()] == *needle)
        // A hit a longer core-crate name extends at the same position is THAT crate's name.
        .filter(|&i| {
            !shadows
                .iter()
                .any(|sh| segs.len() >= i + sh.len() && segs[i..i + sh.len()] == sh[..])
        })
        .count()
}

// ------------------------------------------------------------------------------------------------
// scanner two — the raw window
// ------------------------------------------------------------------------------------------------

/// A boundary between `prev` and `here`: no character, a non-alphanumeric one, or a case
/// transition. Written against the raw characters, with no segment model anywhere near it.
fn is_boundary(prev: Option<char>, here: Option<char>) -> bool {
    match (prev, here) {
        (None, _) | (_, None) => true,
        (Some(p), Some(h)) => {
            if !p.is_ascii_alphanumeric() || !h.is_ascii_alphanumeric() {
                return true;
            }
            p.is_ascii_lowercase() && h.is_ascii_uppercase()
        }
    }
}

/// The end index of `needle` matched at `start`, or `None`. The needle's own joints match a run of
/// non-alphanumerics, or nothing at all when the raw text runs the parts together at a case joint,
/// so `busbar-transport-http`, `busbar_transport_http` and `BusbarTransportHttp` are one needle.
fn window_at(chars: &[char], start: usize, needle: &[String]) -> Option<usize> {
    let mut i = start;
    for (n, part) in needle.iter().enumerate() {
        if n > 0 {
            let sep_start = i;
            while i < chars.len() && !chars[i].is_ascii_alphanumeric() {
                i += 1;
            }
            if i == sep_start
                && !is_boundary(
                    if i == 0 { None } else { Some(chars[i - 1]) },
                    chars.get(i).copied(),
                )
            {
                return None;
            }
        }
        for pc in part.chars() {
            let c = *chars.get(i)?;
            if !c.eq_ignore_ascii_case(&pc) {
                return None;
            }
            i += 1;
        }
    }
    Some(i)
}

/// How many times `needle` appears in `chars` as a bounded, case-insensitive window. `chars` is the
/// raw line, decoded once by the caller: decoding it per needle made the row minutes long.
fn count_by_windows(chars: &[char], needle: &[String], shadows: &[Vec<String>]) -> usize {
    let mut hits = 0usize;
    let mut i = 0usize;
    while i < chars.len() {
        if let Some(end) = window_at(chars, i, needle) {
            let before = if i == 0 { None } else { Some(chars[i - 1]) };
            if is_boundary(before, Some(chars[i]))
                && is_boundary(Some(chars[end - 1]), chars.get(end).copied())
            {
                // A window a longer core-crate name fills from the same start is THAT crate's
                // name, not the legacy crate's: skip the whole of it.
                let shadowed = shadows.iter().find_map(|sh| {
                    window_at(chars, i, sh)
                        .filter(|&e| is_boundary(Some(chars[e - 1]), chars.get(e).copied()))
                });
                if let Some(e) = shadowed {
                    i = e;
                    continue;
                }
                hits += 1;
                i = end;
                continue;
            }
        }
        i += 1;
    }
    hits
}

// ------------------------------------------------------------------------------------------------
// the measurement
// ------------------------------------------------------------------------------------------------

/// One cell of the matrix.
#[derive(Debug, Default, Clone)]
struct Cell {
    /// The higher of the two scanners, never the lower.
    count: usize,
    by_segments: usize,
    by_windows: usize,
    /// `word\tfile:line\tNx` for every hit, in scan order — the drain list.
    hits: Vec<String>,
}

impl Cell {
    fn disagrees(&self) -> bool {
        self.by_segments != self.by_windows
    }
}

/// Which crate directory a scanned path belongs to.
fn owning_dir(rel: &str) -> Option<String> {
    let parts: Vec<&str> = rel.split('/').collect();
    (parts.len() >= 3 && parts[0] == "crates").then(|| format!("crates/{}", parts[1]))
}

type Matrix = BTreeMap<(String, &'static str), Cell>;

/// The two-letter bucket a needle is filed under, and the buckets a line offers.
///
/// EVERY MATCH OF EITHER SCANNER BEGINS AT A SEGMENT START. The window scanner accepts a hit only
/// when `is_boundary` holds before it, and `is_boundary` is true exactly where the segment splitter
/// opens a segment (after a non-alphanumeric, or at a lower→upper joint) — the splitter opens a few
/// MORE, at acronym joints, which only widens the candidate set. So a needle whose first two
/// letters appear at no segment start of a line cannot be found on that line by either scanner, and
/// skipping it there is a superset filter rather than a hole.
///
/// Without it the row is O(lines × every needle in the tree) and the SELF-TEST is the thing that
/// pays: every planted case re-runs the whole gate, so a scan that takes ten seconds takes ten
/// minutes across the battery.
type Bucket = (char, char);

fn bucket_of(part: &str) -> Bucket {
    let mut it = part.chars();
    (
        it.next().unwrap_or('\0').to_ascii_lowercase(),
        it.next().unwrap_or('\0').to_ascii_lowercase(),
    )
}

/// One needle, resolved: which kind it belongs to, its spelling, and its segments.
struct Resolved {
    kind: &'static str,
    word: String,
    parts: Vec<String>,
    shadows: Vec<Vec<String>>,
}

/// A crate's needles, plus the two-letter index into them and the fingerprint the per-file memo is
/// keyed on — every spelling this crate is measured against, in order.
#[derive(Default)]
struct Plan {
    needles: Vec<Resolved>,
    by_bucket: BTreeMap<Bucket, Vec<usize>>,
    fingerprint: String,
}

fn measure(cx: &Ctx, crates: &[CrateInfo]) -> Result<(Matrix, usize), String> {
    let vocab = vocabulary(crates);
    let by_dir: BTreeMap<&str, &CrateInfo> = crates.iter().map(|c| (c.dir.as_str(), c)).collect();

    let mut plan: BTreeMap<&str, Plan> = BTreeMap::new();
    for c in crates {
        let mut p = Plan::default();
        for (kind, words) in &vocab {
            for n in needles_for(words, c) {
                let parts = needle_segments(&n.word);
                if parts.is_empty() {
                    continue;
                }
                p.by_bucket
                    .entry(bucket_of(&parts[0]))
                    .or_default()
                    .push(p.needles.len());
                p.fingerprint.push_str(kind);
                p.fingerprint.push(':');
                p.fingerprint.push_str(&n.word);
                for sh in &n.shadows {
                    p.fingerprint.push_str(" !");
                    p.fingerprint.push_str(&sh.join("-"));
                }
                p.fingerprint.push('\n');
                p.needles.push(Resolved {
                    kind,
                    word: n.word.clone(),
                    parts,
                    shadows: n.shadows.clone(),
                });
            }
        }
        plan.insert(c.dir.as_str(), p);
    }

    let mut files = cx
        .walk(&WalkSpec::new(["crates"]).ext("rs"))
        .map_err(|e| e.to_string())?;
    files.extend(
        cx.walk(&WalkSpec::new(["crates"]).ext("toml"))
            .map_err(|e| e.to_string())?,
    );
    if files.len() < MIN_SCANNED {
        return Err(format!(
            "{} file(s) under crates/, below the floor of {MIN_SCANNED}",
            files.len()
        ));
    }

    let mut matrix: Matrix = BTreeMap::new();
    for f in &files {
        let rel = f.rel_str();
        let Some(dir) = owning_dir(&rel) else {
            continue;
        };
        let Some(c) = by_dir.get(dir.as_str()) else {
            continue;
        };
        let Some(per_kind) = plan.get(dir.as_str()) else {
            continue;
        };
        for h in scan_file(per_kind, &dir, &rel, &f.text).iter() {
            let cell = matrix.entry((c.name.clone(), h.kind)).or_default();
            cell.by_segments += h.by_segments;
            cell.by_windows += h.by_windows;
            let n = h.by_segments.max(h.by_windows);
            cell.count += n;
            let mark = if h.by_segments == h.by_windows {
                ""
            } else {
                "\t[scanners disagree]"
            };
            cell.hits
                .push(format!("{}\t{rel}:{}\t{n}x{mark}", h.word, h.line));
        }
    }
    Ok((matrix, files.len()))
}

/// One needle found once, on one line.
struct Hit {
    kind: &'static str,
    word: String,
    line: usize,
    by_segments: usize,
    by_windows: usize,
}

/// THE PER-FILE MEMO, and the reason it exists is the SELF-TEST.
///
/// Every planted case re-runs the whole gate, and a plant changes ONE file. Re-measuring 1 558 of
/// them for each of thirty plants is the difference between a battery that runs in seconds and one
/// that runs for ten minutes — and a battery nobody waits for is a battery somebody stops running.
///
/// The key is a hash of everything the answer depends on: the crate's needle set (so a plant that
/// registers a new plane invalidates every entry), the path, and the file's bytes. The scan is a
/// pure function of those three, so a hit is a memo and never a stale reading.
static FILE_MEMO: std::sync::OnceLock<std::sync::Mutex<BTreeMap<u64, std::sync::Arc<Vec<Hit>>>>> =
    std::sync::OnceLock::new();

fn scan_file(plan: &Plan, dir: &str, rel: &str, text: &str) -> std::sync::Arc<Vec<Hit>> {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    plan.fingerprint.hash(&mut h);
    rel.hash(&mut h);
    text.hash(&mut h);
    let key = h.finish();
    let memo = FILE_MEMO.get_or_init(Default::default);
    if let Some(found) = memo
        .lock()
        .expect("the memo mutex is never poisoned")
        .get(&key)
    {
        return std::sync::Arc::clone(found);
    }

    // THE PATH IS SCANNED FIRST, at line 0. `root/voice_serve.rs` names its plane before a byte of
    // it is read, and a filename is the first thing a reader of the tree sees. The crate's OWN
    // directory is stripped: it is the crate naming itself.
    let tail = rel.strip_prefix(dir).unwrap_or(rel);
    let subject = std::iter::once((0usize, tail)).chain(
        text.lines()
            .enumerate()
            .map(|(i, l): (usize, &str)| (i + 1, l)),
    );
    let mut out: Vec<Hit> = Vec::new();
    for (line, raw) in subject {
        let chars: Vec<char> = raw.chars().collect();
        let mut candidates: Vec<usize> = Vec::new();
        for b in line_buckets(&chars) {
            if let Some(idxs) = plan.by_bucket.get(&b) {
                candidates.extend(idxs);
            }
        }
        if candidates.is_empty() {
            continue;
        }
        candidates.sort_unstable();
        candidates.dedup();
        let segs = line_segments(raw);
        for i in candidates {
            let n = &plan.needles[i];
            let by_segments = count_by_segments(&segs, &n.parts, &n.shadows);
            let by_windows = count_by_windows(&chars, &n.parts, &n.shadows);
            if by_segments == 0 && by_windows == 0 {
                continue;
            }
            out.push(Hit {
                kind: n.kind,
                word: n.word.clone(),
                line,
                by_segments,
                by_windows,
            });
        }
    }
    let out = std::sync::Arc::new(out);
    memo.lock()
        .expect("the memo mutex is never poisoned")
        .insert(key, std::sync::Arc::clone(&out));
    out
}

// ------------------------------------------------------------------------------------------------
// the ledger
// ------------------------------------------------------------------------------------------------

/// The ledger in its two halves, projected out of the ONE registry reader in the parent module.
///
/// The numbers, per crate × kind; the SENTENCES, per kind → kind class; and the recorded scanner
/// disagreements. The prose belongs to the class because that is what a reader is reading — the same
/// split `[[transitional]]` already makes — and the number belongs to the cell because that is what
/// the ratchet moves. Every field is required and validated at LOAD by [`super::take_row`], so a
/// row that reaches here is a row a human could read.
#[derive(Default)]
struct Ledger {
    cells: BTreeMap<(String, String), i64>,
    /// class -> `cite`/`why`/`drain`, kept rather than discarded so `--report` can hand a reader
    /// the citation and the deleting line beside the number instead of a bare count.
    edges: BTreeMap<(String, String), (String, String, String)>,
    disagreements: BTreeMap<(String, String), String>,
}

/// TWO ROWS FOR ONE CELL IS TWO ANSWERS. The maps below would keep the last, which is a ceiling
/// chosen by file order — so a repeated key is reported instead, by name.
fn duplicates(reg: &super::KindRegistry) -> Vec<String> {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for c in &reg.matrix_cells {
        *seen
            .entry(format!("cell\t{} × {}", c.krate, c.kind))
            .or_default() += 1;
    }
    for e in &reg.matrix_edges {
        *seen
            .entry(format!("edge\t{} -> {}", e.from, e.to))
            .or_default() += 1;
    }
    for d in &reg.matrix_disagreements {
        *seen
            .entry(format!("disagreement\t{} × {}", d.krate, d.kind))
            .or_default() += 1;
    }
    // TWO ADMISSIONS FOR ONE CRATE IS TWO MINTS. The admission map below keys by crate name and
    // would keep one of them, so the second row would be a mint nothing counted — which is the
    // exact manoeuvre `cells` is a number for.
    for m in &reg.minted {
        *seen.entry(format!("minted\t{}", m.krate)).or_default() += 1;
    }
    seen.into_iter()
        .filter(|(_, n)| *n > 1)
        .map(|(k, n)| {
            let (table, what) = k.split_once('\t').unwrap_or(("", k.as_str()));
            format!(
                "duplicate-row\t{what}\t{n} `[[{table}]]` rows name it. Two rows for one thing are \
                 two answers, and which one binds would be decided by file order."
            )
        })
        .collect()
}

fn read_ledger(reg: &super::KindRegistry) -> Ledger {
    Ledger {
        cells: reg
            .matrix_cells
            .iter()
            .map(|c| ((c.krate.clone(), c.kind.clone()), c.count))
            .collect(),
        edges: reg
            .matrix_edges
            .iter()
            .map(|e| {
                (
                    (e.from.clone(), e.to.clone()),
                    (e.cite.clone(), e.why.clone(), e.drain.clone()),
                )
            })
            .collect(),
        disagreements: reg
            .matrix_disagreements
            .iter()
            .map(|d| ((d.krate.clone(), d.kind.clone()), d.note.clone()))
            .collect(),
    }
}

/// Every listed class, with the sentences that justify it — the `--report` half a reader acts on.
fn render_classes(listed: &Ledger) -> String {
    let mut out = String::new();
    for ((from, to), (cite, why, drain)) in &listed.edges {
        out.push_str(&format!(
            "--- {from} -> {to}\n  cite : {cite}\n  why  : {why}\n  drain: {drain}\n"
        ));
    }
    for ((krate, kind), note) in &listed.disagreements {
        out.push_str(&format!(
            "--- {krate} × {kind} (scanners disagree)\n  {note}\n"
        ));
    }
    out
}

/// The whole matrix, one line per non-zero cell — printed in `--report` so the integrator reads the
/// table without having to re-derive it.
fn render_matrix(matrix: &Matrix) -> String {
    matrix
        .iter()
        .map(|((krate, kind), cell)| {
            format!(
                "{krate}\t{kind}\t{}\t(segments {}, windows {})",
                cell.count, cell.by_segments, cell.by_windows
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The drain list: every hit, `file:line`, grouped by cell.
fn render_drain(matrix: &Matrix) -> String {
    let mut out = String::new();
    for ((krate, kind), cell) in matrix {
        out.push_str(&format!("--- {krate} × {kind} ({})\n", cell.count));
        for h in &cell.hits {
            out.push_str(&format!("  {h}\n"));
        }
    }
    out
}

/// EVERY CELL'S MEASURED COUNT, for the one caller that needs the numbers without the verdict:
/// `--write`, which re-pins a `[[cell]]` row DOWNWARD to what the tree measures today.
pub fn measured_cells(
    cx: &Ctx,
    crates: &[CrateInfo],
) -> Result<BTreeMap<(String, String), usize>, String> {
    let (matrix, _) = measure(cx, crates)?;
    Ok(matrix
        .into_iter()
        .map(|((krate, kind), cell)| ((krate, kind.to_string()), cell.count))
        .collect())
}

/// THE ROWS THIS BRANCH MINTED — a `[[cell]]`, `[[edge]]` or `[[disagreement]]` that is in no
/// merge-base copy of the ledger at all.
///
/// `ceiling-rose` cannot see one, and that is not an oversight in it: it walks the numbers the BASE
/// carries and asks whether they went up, so a key the base does not have has no `before` to be
/// higher than and is skipped in silence. A red team walked straight through the gap — a
/// `pub struct WSFrame;` planted in a store plugin went red twice (`unlisted-cell` and
/// `unlisted-edge`), and three hand-written rows, one of them a `[[disagreement]]` note the author
/// composed themselves, made the whole gate green.
///
/// A new row is a `0 -> N` raise wearing the clothes of a first measurement. It is refused here,
/// and the refusal is the transaction the ceiling machinery is built on everywhere else: the number
/// moves in a commit that says so, and a reviewer reads the sentence rather than the diff's
/// arithmetic.
///
/// AND THE DOOR HAS ONE HINGE, because a door that never opens is a wall. The refusal above is
/// right about every row except the ones a crate that does not exist yet must arrive with: the
/// FIRST crate of any kind — `busbar-core-config`, the dialect crates, a new secret plugin — has no
/// rows at any base, so under the rule as written it could never land, and the only way past it was
/// to weaken the rule. The hinge is data and it is [`super::Minted`]: a crate the BASE's own
/// `[[announced]]` table names may mint its row set ONCE, in a `[[minted]]` row that says which
/// crate, at which commit, how many cells, and — for a carve-out — which crate the vocabulary was
/// moved from. Every one of those is checked against history rather than against the branch, which
/// is the same reading the rest of this module gives every other row.
fn minted_rows(cx: &Ctx, reg: &super::KindRegistry) -> Vec<String> {
    let base = match super::base::read(cx) {
        Ok(b) => b,
        Err(why) => {
            return vec![format!(
                "no-base\t{LEDGER}\tno merge-base could be read, so no row could be shown to \
                 pre-date this branch ({why}). A ratchet that cannot read its own history reports \
                 nothing, and reporting nothing is not passing."
            )]
        }
    };
    // A BRANCH THAT ADDS THE LEDGER ADDS EVERY ROW IN IT, and that landing is the file's own
    // review. Refusing 515 rows there would be refusing the commit that created the instrument.
    if !base.registry_present {
        return Vec::new();
    }
    let now = cx.read(LEDGER).unwrap_or_default();
    let short = &base.commit[..8.min(base.commit.len())];
    let at_base = super::ledger_at(&base.registry);

    let mut out = Vec::new();

    // ── WHICH `[[minted]]` ROWS ADMIT ANYTHING ──────────────────────────────────────────────────
    //
    // Read FIRST, and refused here rather than downstream, because an admission that is itself
    // unadmitted must not quietly widen anything: a row that fails one of these three tests admits
    // nothing at all, so every row it was written for stays `minted-row`.
    // A RENAMED CRATE MINTS AGAINST THE NAME THE BASE ANNOUNCED. `[[renamed]]` is the translation
    // every rule that asks the base a question keyed by crate name reads through, and this is one:
    // the base announced `busbar-core-hooks`, the crate landed as `busbar-core-policy`, and the
    // announcement is the same announcement.
    let base_names = reg.base_names();
    let announced_as = |name: &str| -> String {
        base_names
            .get(name)
            .map_or_else(|| name.to_string(), |from| (*from).to_string())
    };
    let mut admits: BTreeMap<&str, &super::Minted> = BTreeMap::new();
    for m in &reg.minted {
        if !at_base.announced.contains_key(&announced_as(&m.krate)) {
            out.push(format!(
                "unannounced-mint\t[[minted]] {}\t`{}` is in no `[[announced]]` row of {LEDGER} at \
                 the merge-base {short}, so this branch is minting rows for a crate whose landing \
                 nobody announced. Announcing a crate and admitting its ledger rows in one commit \
                 is the same signature twice: land the `[[announced]]` row first, on the \
                 integration line, and mint against it afterwards.",
                m.krate, m.krate
            ));
            continue;
        }
        if at_base.minted.contains(&m.krate) {
            out.push(format!(
                "second-mint\t[[minted]] {}\tthe merge-base {short} already carries a `[[minted]]` \
                 row for `{}`: its row set was minted once, at {}, and is HISTORY now, so this row \
                 admits nothing. A crate mints its rows on the branch that creates it; every \
                 ceiling after that moves through `ceiling-rose`, in a commit that says which \
                 number went up.",
                m.krate, m.krate, m.commit
            ));
            continue;
        }
        admits.insert(m.krate.as_str(), m);
    }
    // kind -> the crate whose announcement mints it, for the `[[edge]]` half. An edge class is
    // named by KINDS, not crates, so the row a first-of-its-kind crate needs is admitted through
    // the kind the BASE announced it as — never through a kind this branch assigned it.
    let mut minting_kind: BTreeMap<&str, &str> = BTreeMap::new();
    for name in admits.keys() {
        if let Some(kind) = at_base.announced.get(&announced_as(name)) {
            minting_kind.insert(kind.as_str(), name);
        }
    }

    // ── THE MINTED ROWS THEMSELVES ──────────────────────────────────────────────────────────────
    //
    // old name -> new name, the direction the BASE's keys have to be read in.
    let renamed_to: BTreeMap<&str, &str> =
        reg.base_names().into_iter().map(|(k, v)| (v, k)).collect();
    let mut minted_cells: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for (table, ids, what) in [
        (
            "cell",
            &["crate", "kind"][..],
            "a ceiling for one crate's naming of one kind",
        ),
        (
            "edge",
            &["from", "to"][..],
            "an allowance for one kind naming another",
        ),
        (
            "disagreement",
            &["crate", "kind"][..],
            "an excuse for the two scanners reading one cell differently",
        ),
    ] {
        // A RENAMED CRATE'S ROWS ARE NOT MINTED ROWS — the base carries them under the OLD name.
        let was = super::base::row_keys_as_now(&base.registry, table, ids, &renamed_to);
        for key in super::base::row_keys(&now, table, ids) {
            if was.contains(&key) {
                continue;
            }
            let (left, right) = key.split_once(" \u{d7} ").unwrap_or((key.as_str(), ""));
            let admitted = match table {
                // A `[[cell]]`/`[[disagreement]]` row is about ONE crate, by name.
                "cell" | "disagreement" => admits.contains_key(left),
                // An `[[edge]]` row is about a CLASS, so either end may be the kind being minted.
                _ => minting_kind.contains_key(left) || minting_kind.contains_key(right),
            };
            if admitted {
                if table == "cell" {
                    minted_cells
                        .entry(left.to_string())
                        .or_default()
                        .push((left.to_string(), right.to_string()));
                }
                continue;
            }
            out.push(format!(
                "minted-row\t[[{table}]] {key}\tthis row is in no copy of {LEDGER} at the \
                 merge-base {short}: this branch MINTED it. It is {what}, and a row that did not \
                 exist is a 0 -> N raise wearing the clothes of a first measurement — the one raise \
                 `ceiling-rose` cannot see, because a key with no `before` has nothing to be higher \
                 than. Delete the coupling instead, land the row in a commit whose message says why \
                 the tree now needs it, or — if this is the FIRST crate of its kind landing — add \
                 the `[[minted]]` row that admits it, against an `[[announced]]` row the base \
                 already carries."
            ));
        }
    }

    // ── WHAT EACH ADMISSION ACTUALLY MINTED, AGAINST WHAT ITS ROW SAYS ──────────────────────────
    let listed: BTreeMap<(&str, &str), i64> = reg
        .matrix_cells
        .iter()
        .map(|c| ((c.krate.as_str(), c.kind.as_str()), c.count))
        .collect();
    for (name, m) in &admits {
        let minted = minted_cells.get(*name).map(Vec::as_slice).unwrap_or(&[]);
        if minted.len() as i64 != m.cells {
            out.push(format!(
                "mint-count\t[[minted]] {name}\tthe row is recorded at {} and says `cells = {}`, \
                 and this branch minted {} `[[cell]]` row(s) for `{name}` ({}). The number is the \
                 size of the set the admission covers, so a branch that minted a different number \
                 of cells than it wrote down has an admission nobody priced: write the number the \
                 branch actually mints.",
                m.commit,
                m.cells,
                minted.len(),
                if minted.is_empty() {
                    "none".to_string()
                } else {
                    minted
                        .iter()
                        .map(|(k, kind)| format!("{k} × {kind}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ));
        }
        // A MOVE CANNOT RAISE THE UNION OF THE TWO ROWS. `busbar-core-config` is cut out of
        // `busbar-core`; the vocabulary it carries is the old crate's vocabulary under a new name,
        // and the base's own pinned count for the source crate is the ceiling over it. Without
        // this, a carve-out is a laundry: move one hit, mint a row for fifty, and `ceiling-rose`
        // sees only a number going DOWN in the crate that was drained.
        let Some(from) = m.moved_from.as_deref() else {
            continue;
        };
        for (krate, kind) in minted {
            let n = listed.get(&(krate.as_str(), kind.as_str())).copied();
            let ceiling = at_base
                .cells
                .get(&(from.to_string(), kind.clone()))
                .copied()
                .unwrap_or(0);
            if n.unwrap_or(0) > ceiling {
                out.push(format!(
                    "mint-over-source\t[[cell]] {krate} × {kind} = {}\tthe `[[minted]]` row says \
                     `moved_from = \"{from}\"`, and the merge-base {short} pins `{from}` × {kind} \
                     at {ceiling}. A move carries vocabulary across, it does not create it: a \
                     minted cell above the count its source crate was pinned at is a raise wearing \
                     a move's clothes, and the only thing `ceiling-rose` would see is `{from}` \
                     going DOWN. Move the hits, or raise `{from}`'s ceiling on the integration line \
                     first and say why.",
                    n.unwrap_or(0)
                ));
            }
        }
    }

    out
}

pub fn rule_matrix(cx: &Ctx, crates: &[CrateInfo], reg: &super::KindRegistry, ship: bool) -> Row {
    let (matrix, scanned) = match measure(cx, crates) {
        Ok(m) => m,
        Err(e) => {
            return Row::fail(
                ROW_MATRIX,
                "the kind × crate scan could not run",
                format!(
                    "{e} — a scan of no files names no coupling, which is indistinguishable from a \
                     tree that has none."
                ),
            )
        }
    };

    let total: usize = matrix.values().map(|c| c.count).sum();

    // THE SHIP TWIN OWES ZERO EVERYWHERE, and owes it without consulting the ledger.
    if ship {
        if total == 0 {
            return Row::pass(
                ROW_MATRIX,
                "no crate names another kind's vocabulary anywhere",
                format!("{scanned} file(s) scanned, every cell of the matrix is 0"),
            );
        }
        let worst: Vec<String> = matrix
            .iter()
            .map(|((k, kind), c)| format!("{k} × {kind} = {}", c.count))
            .collect();
        return Row::fail(
            ROW_MATRIX,
            "a crate still names another kind's vocabulary",
            format!(
                "ship-ceiling 0: {total} hit(s) over {} cell(s): {}",
                matrix.len(),
                worst.join(" | ")
            ),
        );
    }

    let listed = read_ledger(reg);

    let mut offenders: Vec<String> = duplicates(reg);
    offenders.extend(minted_rows(cx, reg));
    let kind_of: BTreeMap<&str, &'static str> = crates
        .iter()
        .filter_map(|c| c.kind.map(|k| (c.name.as_str(), k)))
        .collect();

    for ((krate, kind), cell) in &matrix {
        let src = kind_of.get(krate.as_str()).copied().unwrap_or("?");
        let edge = (src.to_string(), (*kind).to_string());
        if !listed.edges.contains_key(&edge) {
            offenders.push(format!(
                "unlisted-edge\t{src} -> {kind}\t{krate} names {kind} vocabulary {} time(s) and \
                 there is no `[[edge]] from = \"{src}\", to = \"{kind}\"` in {LEDGER}. An edge \
                 nobody wrote down is an edge nobody reviewed: add the class with its ARCHITECTURE \
                 citation and the line that deletes it, or delete the hits.",
                cell.count
            ));
        }

        let key = (krate.clone(), (*kind).to_string());
        let Some(&listed_count) = listed.cells.get(&key) else {
            offenders.push(format!(
                "unlisted-cell\t{krate} × {kind} = {}\tno `[[cell]] crate = \"{krate}\", kind = \
                 \"{kind}\"` in {LEDGER}. Every cell above zero carries its own number: add `count \
                 = \"{}\"`.",
                cell.count, cell.count
            ));
            continue;
        };
        // NO `listed_count >= 0` GUARD. It was here, and it was the hole: a `count = "-1"` row
        // parsed, reached this line, failed the guard and skipped the comparison — a per-cell off
        // switch nothing reported. A negative count is now refused at LOAD (`bad-count`), so a
        // count that arrives here is a number a measurement can equal, and the comparison is
        // unconditional. Two rules, one claim: the reader refuses what it cannot compare, and the
        // comparison compares everything it is handed.
        if listed_count as usize != cell.count {
            let verb = if (listed_count as usize) < cell.count {
                "RAISED — this landing grew the coupling"
            } else {
                "STALE SLACK — the count fell and the ceiling did not; slack is how drift hides"
            };
            // THE FILES THE NUMBER IS MADE OF, HEAVIEST FIRST, named in the row itself. A ratchet
            // finding that says only "2881 vs 2891" sends the reader to `--report`; one that says
            // `root/units_llm.rs` hands them the file. The whole list is in `--report`.
            let mut per_file: BTreeMap<&str, usize> = BTreeMap::new();
            for h in &cell.hits {
                let mut f = h.split('\t');
                let Some(at) = f.nth(1).and_then(|p| p.rsplit_once(':').map(|(f, _)| f)) else {
                    continue;
                };
                let n = f
                    .next()
                    .and_then(|n| n.trim_end_matches('x').parse::<usize>().ok())
                    .unwrap_or(1);
                *per_file.entry(at).or_default() += n;
            }
            let total_files = per_file.len();
            let mut files: Vec<(&str, usize)> = per_file.into_iter().collect();
            files.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
            files.truncate(6);
            offenders.push(format!(
                "ratchet\t{krate} × {kind}\tceiling {} vs measured {} ({verb}). The ceiling must \
                 equal the count, exactly. {total_files} file(s), heaviest first: {}",
                listed_count,
                cell.count,
                files
                    .iter()
                    .map(|(f, n)| format!("{f} ({n})"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if cell.disagrees() && !listed.disagreements.contains_key(&key) {
            offenders.push(format!(
                "measurement-disagreement\t{krate} × {kind}\tsegment scanner {} vs window scanner \
                 {}; the scored count is the higher, {}. Record a `[[disagreement]]` row for this \
                 cell, or drain the spellings one scanner cannot see.",
                cell.by_segments, cell.by_windows, cell.count
            ));
        }
    }

    // A ROW WHOSE CELL IS GONE IS A DEAD ALLOWANCE. The exemption cannot outlive the coupling.
    for (krate, kind) in listed.cells.keys() {
        let live = matrix
            .iter()
            .any(|((k, kd), c)| k == krate && kd == kind && c.count > 0);
        if !live {
            offenders.push(format!(
                "dead-cell\t{krate} × {kind}\tthe `[[cell]]` row covers nothing: the cell measures \
                 0. Strike it — an allowance that outlives what it allowed is a hole nobody \
                 re-reads."
            ));
        }
    }
    for (krate, kind) in listed.disagreements.keys() {
        let live = matrix
            .iter()
            .any(|((k, kd), c)| k == krate && kd == kind && c.disagrees());
        if !live {
            offenders.push(format!(
                "dead-disagreement\t{krate} × {kind}\tthe `[[disagreement]]` row covers nothing: \
                 the two scanners agree on this cell now. Strike it."
            ));
        }
    }
    // A KIND WHOSE FIRST CRATE HAS NOT LANDED MEASURES NOTHING, so every class naming it would be
    // scored dead the moment it was written — and the class has to be written FIRST, because the
    // branch that lands the crate is the branch that would otherwise have to mint the row and open
    // the class in one edit. This is the same window `[[announced]]` already opens for the
    // dead-kind and dead-waiver ratchets, on the same terms and with the same expiry: the ship twin
    // refuses an announcement that has outlived its landing, so the day a `core` crate exists the
    // announcement is struck and `dead-edge` reads this class like every other.
    //
    // NARROW ON PURPOSE: an announced kind that ALREADY has a crate in the tree is not in this set,
    // so `control` — announced, and live since before the announcement — keeps its classes scored.
    let unlanded: BTreeSet<&str> = reg
        .announced_kinds()
        .into_iter()
        .filter(|k| !crates.iter().any(|c| c.kind == Some(*k)))
        .collect();
    for (src, dst) in listed.edges.keys() {
        if unlanded.contains(src.as_str()) || unlanded.contains(dst.as_str()) {
            continue;
        }
        let live = matrix.iter().any(|((k, kd), c)| {
            kd == dst && c.count > 0 && kind_of.get(k.as_str()).copied() == Some(src.as_str())
        });
        if !live {
            offenders.push(format!(
                "dead-edge\t{src} -> {dst}\tthe `[[edge]]` row covers nothing: no crate of kind \
                 {src} names {dst} vocabulary any more. Strike the class."
            ));
        }
    }

    let headline = format!(
        "{total} hit(s) over {} cell(s), {scanned} file(s) scanned",
        matrix.len()
    );

    // `--report` PRINTS, rather than filling the row's detail. A ledger row is one TSV line and
    // `Row::tsv` flattens every newline in it to a space, so a drain list carried in the detail
    // arrives as one unreadable line — and a PASS row's detail is not printed at all. The whole
    // point of this list is that a reader can hand each file its deleting line, so in report mode
    // it goes to stdout, where a reader is.
    if cx.env().report_only {
        println!(
            "\nTHE MATRIX (crate, kind, count, per scanner):\n{}",
            render_matrix(&matrix)
        );
        println!(
            "\nTHE LISTED CLASSES (cite, why, the line that deletes it):\n{}",
            render_classes(&listed)
        );
        println!(
            "\nTHE DRAIN LIST (word, file:line, hits):\n{}",
            render_drain(&matrix)
        );
    }

    if !offenders.is_empty() {
        offenders.sort();
        return Row::fail(
            ROW_MATRIX,
            "the kind × crate vocabulary matrix does not match its ledger",
            format!("{headline}: {}", offenders.join(" | ")),
        );
    }

    Row::pass(
        ROW_MATRIX,
        "every crate's naming of every other kind is at its recorded ceiling",
        format!("every cell equals its {LEDGER} row; {headline}"),
    )
}

// ------------------------------------------------------------------------------------------------
// the self-test — the incident, planted
// ------------------------------------------------------------------------------------------------

/// THE FILE THAT SLIPPED, in its own shape.
///
/// `keep-streams-3` `dd96a04f3` added `crates/busbar/src/root/voice_serve.rs` — a plane-named accept
/// loop, behind a plane-named feature — and CI was green, because nothing counted the composition
/// root. The head of the real file is reproduced here rather than a toy: the plane is named in the
/// PATH, in the `#![cfg(feature = "root-voice-serve")]`, in the prose of the module header and in
/// the plane import — four spellings, which is what a plant has to carry to prove the row would
/// have caught it.
///
/// THE IMPORT LINE IS ASSEMBLED RATHER THAN WRITTEN, and the reason is a sibling gate:
/// `segregation:xtask-src-imports` refuses a product-crate `use` at the head of a line in
/// `xtask/src`, and it is right to — it cannot tell a fixture's bytes from the runner's own. Two
/// pieces joined here are still one plant, and the gate reading this file sees no such line.
fn the_accept_loop_that_named_its_plane() -> String {
    format!(
        "{}{}_{}::claims::{{Dialect, DIALECT_CLAIMS}};\n\n{}",
        r#"// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// THE SERVING SWITCH, ON THE WHOLE FILE.
#![cfg(feature = "root-voice-serve")]

//! THE PRODUCTION COMPOSITION OF THE DUPLEX DRIVER: the streams plane's own node, its own declared
//! surface, and the one accept path that runs a session on a real socket.
//!
//! It is DECLARED in `root/mod.rs` under `root-voice` — the plane's own feature — because
//! everything here reaches into that plane's units.

"#,
        "use busbar",
        "plane_voice",
        "use crate::root::units_voice::{ProviderEndpoints, VoiceNode, VoiceUnit};\n",
    )
}

/// A one-file plant under `dir`, without disturbing anything else in the tree.
fn plant(rel: &str, body: &str) -> crate::ctx::Overlay {
    let mut ov = crate::ctx::Overlay::new();
    ov.set(rel, body.to_string());
    ov
}

/// The ledger with one row rewritten, so a case can raise a ceiling, leave slack in one, or knock a
/// whole class out. The anchors below quote the row's own lines: a fixture that pins a number goes
/// LOUDLY red when the tree is re-measured, which is what a fixture is for.
fn ledger_with(cx: &Ctx, from: &str, to: &str) -> crate::ctx::Overlay {
    let text = cx.read(LEDGER).unwrap_or_default();
    plant(LEDGER, &text.replacen(from, to, 1))
}

/// The three lines of one `[[cell]]` row.
fn cell_row(krate: &str, kind: &str, count: &str) -> String {
    format!("crate = \"{krate}\"\nkind = \"{kind}\"\ncount = \"{count}\"")
}

/// The ledger with rows APPENDED, for the cases whose subject is a row that does not exist yet.
fn ledger_plus(cx: &Ctx, rows: &str) -> crate::ctx::Overlay {
    let text = cx.read(LEDGER).unwrap_or_default();
    plant(LEDGER, &format!("{}\n\n{}\n", text.trim_end(), rows.trim()))
}

/// One `[[edge]]` class row, with the three sentences its reader owes.
fn edge_row(from: &str, to: &str) -> String {
    format!(
        "[[edge]]\nfrom = \"{from}\"\nto = \"{to}\"\ncite = \"ARCHITECTURE.md 1.1 — the \
         composition root names every axis\"\nwhy = \"crates of kind {from} naming {to} \
         vocabulary\"\ndrain = \"the class falls when the root mounts the crate off the registry \
         rather than by name\"\n"
    )
}

/// One `[[minted]]` row, with or without its carve-out ceiling.
fn minted_row(krate: &str, cells: usize, moved_from: Option<&str>) -> String {
    let mut out =
        format!("[[minted]]\ncrate = \"{krate}\"\ncommit = \"468bad131\"\ncells = \"{cells}\"\n");
    if let Some(from) = moved_from {
        out.push_str(&format!("moved_from = \"{from}\"\n"));
    }
    out
}

/// A crate on disk that names one other kind's vocabulary once — the shape a FIRST-OF-ITS-KIND
/// crate arrives in, which is the only tree a `[[minted]]` row is honest over.
fn landed_crate(name: &str, body: &str) -> crate::ctx::Overlay {
    let mut ov = crate::ctx::Overlay::new();
    ov.set(
        format!("crates/{name}/Cargo.toml"),
        format!("[package]\nname = \"{name}\"\nversion = \"0.0.0\"\n"),
    );
    ov.set(format!("crates/{name}/src/lib.rs"), body.to_string());
    ov
}

/// Every RED case this row owes, and the GREEN one it is measured against.
pub fn selftest(
    cx: &Ctx,
    gate: &dyn crate::gates::Gate,
    ship: bool,
    report: &mut crate::gates::Report,
) {
    use crate::gates::{prove_rows_green, prove_rows_red};

    // THE SHIP TWIN OWES A DIFFERENT PROOF, because it is RED on this tree ON PURPOSE. Every case
    // below is about the LEDGER, and the ship twin does not read the ledger — planting a raised
    // ceiling against it would produce the same red it already produces, and "the gate went red"
    // is the answer this battery exists to refuse. So the ship twin gets one case, and it makes a
    // NAMED, NEW deviation: a cell that measures ZERO today and does not after the plant.
    if ship {
        report.push(prove_rows_red(
            cx,
            gate,
            "at the ship ceiling of zero, a plane named inside a transport is a NEW cell",
            &[ROW_MATRIX],
            plant(
                "crates/busbar-transport-tcp/src/leak.rs",
                "//! The llm plane's frames arrive here first.\n",
            ),
            &["ship-ceiling 0", "busbar-transport-tcp × plane"],
        ));
        return;
    }

    // A CORE-KIND CRATE LANDING DOES NOT STRIKE THE LEGACY VOCABULARY. `busbar-core` is the proper
    // segment prefix of every `busbar-core-*` name, and the prefix rule that strikes `busbar`
    // struck it too: with one core-kind crate on disk every `× legacy` cell measured 0 and the
    // ledger's retirement ratchet reported as done (28 dead cells, 16 dead classes, measured). The
    // plant is a core crate that names nothing; the row must still read every legacy cell at its
    // ledgered number, and the planted crate's own name — which the `busbar-core` needle matches
    // as a prefix — must not be counted as busbar-core being named.
    report.push(prove_rows_green(
        cx,
        gate,
        "a core-kind crate on disk does not strike the legacy vocabulary: the × legacy cells still measure",
        &[ROW_MATRIX],
        landed_crate("busbar-core-planted", "//! Names nothing of any kind.\n"),
    ));

    // A ROW THIS BRANCH MINTED IS A `0 -> N` RAISE, and it is the raise `ceiling-rose` cannot see:
    // that rule walks the numbers the BASE carries and asks whether they went up, so a key with no
    // `before` has nothing to be higher than and is skipped in silence. A red team walked straight
    // through the gap — `pub struct WSFrame;` planted in a store plugin went red twice, and three
    // hand-written rows (a `[[cell]]`, an `[[edge]]` and a `[[disagreement]]` whose note the author
    // composed themselves) made the whole gate green.
    //
    // The plant is a `[[cell]]` for a crate × kind that measures zero, so `dead-cell` fires too and
    // the naming assertion is what separates the two claims: the row is refused for being NEW,
    // before anything asks what it covers.
    report.push(prove_rows_red(
        cx,
        gate,
        "a `[[cell]]` row this branch minted is a 0 -> N raise, not a first measurement",
        &[ROW_MATRIX],
        plant(
            LEDGER,
            &format!(
                "{}\n\n[[cell]]\n{}\n",
                cx.read(LEDGER).unwrap_or_default().trim_end(),
                cell_row("busbar-store-memory", "transport", "1")
            ),
        ),
        &[
            "minted-row",
            "busbar-store-memory \u{d7} transport",
            "this branch MINTED it",
        ],
    ));

    // ── THE DOOR'S ONE HINGE: `[[minted]]` ──────────────────────────────────────────────────────
    //
    // The refusal above is right about every row except the ones a crate that does not exist yet
    // must arrive with. The FIRST crate of any kind has no rows at any base, so under `minted-row`
    // alone `busbar-core-config`, the dialect crates and every future secret plugin could never
    // land — and the only way past a rule like that is to weaken it. So the hinge is data, and the
    // four cases below are the four things the data has to be checked against.

    // THE GREEN ARM. A crate the BASE announced, LANDED on this branch and really naming one other
    // kind's vocabulary — with the `[[cell]]` that prices the hit and the `[[minted]]` row that
    // admits the cell. This is the landing the gate has to permit, and it is the ONLY shape it does:
    // the crate is on disk, the count is a measurement, and the admission answers to an
    // announcement the branch cannot have written.
    report.push(prove_rows_green(
        cx,
        gate,
        "an [[announced]] crate mints its row set once, and the [[minted]] row is what admits it",
        &[ROW_MATRIX],
        {
            let mut ov = landed_crate(
                "busbar-control-oauth2",
                "//! The tcp transport is named once here, so this crate has a cell to mint.\n",
            );
            // A CRATE LANDING ADDS ITS OWN NAME TO ITS KIND'S VOCABULARY, and two cells that
            // already exist measure higher for it — `busbar-core` and `busbar-substrate` both name
            // the issuer this crate is being extracted from. Those are ORDINARY raises with
            // ordinary `[[cell]]` rows at the base, so the fixture re-pins them to what the planted
            // tree measures; leaving them stale would red this case on a claim it is not about,
            // and — worse — would let a reader think the mint had been refused.
            let text = cx
                .read(LEDGER)
                .unwrap_or_default()
                .replacen(
                    &cell_row("busbar-core", "control", "5200"),
                    &cell_row("busbar-core", "control", "5203"),
                    1,
                )
                .replacen(
                    &cell_row("busbar-substrate", "control", "352"),
                    &cell_row("busbar-substrate", "control", "361"),
                    1,
                );
            ov.set(
                LEDGER,
                format!(
                    "{}\n\n[[cell]]\n{}\n\n{}",
                    text.trim_end(),
                    cell_row("busbar-control-oauth2", "transport", "1"),
                    minted_row("busbar-control-oauth2", 1, None),
                ),
            );
            ov
        },
    ));

    // …AND THE `[[edge]]` HALF OF THE SAME LANDING, which is the one a FIRST-of-its-kind crate
    // needs: `busbar-core-config` is the first `core` crate, so the class rows naming `core` are in
    // no base either. They are admitted through the KIND the base announced the crate as, and the
    // class is not scored DEAD while that kind has no crate — the same window `[[announced]]`
    // already opens for the dead-kind ratchet, with the same expiry.
    //
    // This is `root -> core`: the composition root names every axis, and `core` is the carve-out of
    // the crate it already names as `legacy`. `PENDING_EDGES` grants the dependency class; this row
    // is the vocabulary class beside it.
    report.push(prove_rows_green(
        cx,
        gate,
        "the first crate of a kind mints its [[edge]] class too, and the class is not scored dead",
        &[ROW_MATRIX],
        ledger_plus(
            cx,
            &format!(
                "{}\n{}",
                edge_row("root", "core"),
                minted_row("busbar-core-config", 0, None),
            ),
        ),
    ));

    // A CRATE THE BASE DID NOT ANNOUNCE MINTS NOTHING. Announcing a crate and admitting its ledger
    // rows in the same commit is the same signature twice — the forgery the whole provenance module
    // exists to refuse — so the announcement is read out of the BASE's copy of the file and a
    // `[[minted]]` row that answers to no announcement admits nothing at all.
    report.push(prove_rows_red(
        cx,
        gate,
        "a [[minted]] row for a crate the merge-base never announced admits nothing",
        &[ROW_MATRIX],
        ledger_plus(
            cx,
            &format!(
                "[[cell]]\n{}\n\n{}",
                cell_row("busbar-store-memory", "transport", "1"),
                minted_row("busbar-store-memory", 1, None),
            ),
        ),
        &[
            "unannounced-mint",
            "busbar-store-memory",
            "minted-row",
            "busbar-store-memory \u{d7} transport",
        ],
    ));

    // ONCE MEANS ONCE. Two `[[minted]]` rows for one crate are two admissions, and the map that
    // reads them keys by crate name — so the second would be a mint nothing counted, which is the
    // exact manoeuvre `cells` is a number for.
    report.push(prove_rows_red(
        cx,
        gate,
        "a second [[minted]] row for the same crate is two admissions, not one",
        &[ROW_MATRIX],
        ledger_plus(
            cx,
            &format!(
                "{}\n{}",
                minted_row("busbar-control-oauth2", 0, None),
                minted_row("busbar-control-oauth2", 1, None),
            ),
        ),
        &["duplicate-row", "busbar-control-oauth2", "two answers"],
    ));

    // A MOVE CANNOT RAISE THE UNION OF THE TWO ROWS. A carve-out's cells are the old crate's cells
    // under a new name; a minted cell above the count the BASE pinned for the source crate is a
    // raise wearing a move's clothes, and the only thing `ceiling-rose` would see is the SOURCE
    // crate going down. `busbar-core` is pinned at 24 transport hits at the base; the plant asks
    // for 999999 under a row that says the vocabulary was moved out of it.
    report.push(prove_rows_red(
        cx,
        gate,
        "a minted cell above the count its `moved_from` crate was pinned at is a raise, not a move",
        &[ROW_MATRIX],
        ledger_plus(
            cx,
            &format!(
                "[[cell]]\n{}\n\n{}",
                cell_row("busbar-control-oauth2", "transport", "999999"),
                minted_row("busbar-control-oauth2", 1, Some("busbar-core")),
            ),
        ),
        &[
            "mint-over-source",
            "busbar-control-oauth2 \u{d7} transport",
            "moved_from",
        ],
    ));

    // THE INCIDENT, PLANTED — and its green twin, which is the same tree with the file absent.
    report.push(prove_rows_red(
        cx,
        gate,
        "the accept loop that named its plane (`root/voice_serve.rs`, keep-streams-3 dd96a04f3)",
        &[ROW_MATRIX],
        plant(
            "crates/busbar/src/root/voice_serve.rs",
            &the_accept_loop_that_named_its_plane(),
        ),
        &["ratchet", "busbar × plane", "RAISED"],
    ));
    report.push(prove_rows_green(
        cx,
        gate,
        "the same tree with that accept loop absent, at the ceiling it is recorded at",
        &[ROW_MATRIX],
        crate::ctx::Overlay::new(),
    ));

    // THE ROOT THAT HAND-WIRED FOUR PLANES. Drop the cell to what a registry-driven root would
    // measure and the row names the four files by name.
    report.push(prove_rows_red(
        cx,
        gate,
        "the root that hand-wired four planes, held to the zero a registry-driven root would measure",
        &[ROW_MATRIX],
        ledger_with(
            cx,
            &cell_row("busbar", "plane", "1798"),
            &cell_row("busbar", "plane", "0"),
        ),
        &["ratchet", "busbar × plane", "RAISED", "units_voice.rs"],
    ));

    // A CEILING WITH SLACK IS THE OTHER HALF OF THE RATCHET.
    report.push(prove_rows_red(
        cx,
        gate,
        "a ceiling left above the count it measures — stale slack is how drift hides",
        &[ROW_MATRIX],
        ledger_with(
            cx,
            &cell_row("busbar-kernel", "plane", "1"),
            &cell_row("busbar-kernel", "plane", "99999"),
        ),
        &["ratchet", "busbar-kernel × plane", "STALE SLACK"],
    ));

    // A PLANE NAMED INSIDE A TRANSPORT — the wire learning what it carries.
    report.push(prove_rows_red(
        cx,
        gate,
        "a plane named inside a transport (`busbar-transport-tcp` says `llm`)",
        &[ROW_MATRIX],
        plant(
            "crates/busbar-transport-tcp/src/leak.rs",
            "//! The llm plane's frames arrive here first.\n",
        ),
        &["busbar-transport-tcp", "plane"],
    ));

    // THE SAME NAME, IN THE TRANSPORT'S OWN TESTS. Tests are not excluded, and this is the case
    // that proves it: a fixture that names a plane is that crate's source naming a plane.
    report.push(prove_rows_red(
        cx,
        gate,
        "a plane named inside a transport's own tests — tests are not excluded",
        &[ROW_MATRIX],
        plant(
            "crates/busbar-transport-tcp/src/tests/leak.rs",
            "#[test]\nfn mcp_frames_round_trip() {}\n",
        ),
        &["busbar-transport-tcp", "plane"],
    ));

    // A TRANSPORT NAMED INSIDE A PLANE — the same fusion, the other way up.
    report.push(prove_rows_red(
        cx,
        gate,
        "a transport named inside a plane (`busbar-plane-admin` says `grpc`)",
        &[ROW_MATRIX],
        plant(
            "crates/busbar-plane-admin/src/leak.rs",
            "//! The grpc wire delivers these.\n",
        ),
        &["ratchet", "busbar-plane-admin × transport", "RAISED"],
    ));

    // A STORE NAMED INSIDE THE KERNEL — core is core.
    report.push(prove_rows_red(
        cx,
        gate,
        "a store named inside the kernel (`busbar-kernel` says `busbar_store_memory`)",
        &[ROW_MATRIX],
        plant(
            "crates/busbar-kernel/src/leak.rs",
            "use busbar_store_memory::MemoryStore;\n",
        ),
        &["busbar-kernel", "store"],
    ));

    // A HIT THAT IS ONLY A COMMENT. Nothing is stripped: a plane named in a doc comment of the
    // kernel is the kernel's reader being taught a plane.
    report.push(prove_rows_red(
        cx,
        gate,
        "a plane named in nothing but a comment inside the kernel",
        &[ROW_MATRIX],
        plant(
            "crates/busbar-kernel/src/leak.rs",
            "// mcp, a2a and llm all come through here.\n",
        ),
        &["ratchet", "busbar-kernel × plane", "RAISED"],
    ));

    // THE TWO SCANNERS DISAGREEING. `gRPC` reads whole to the window scanner and splits at its own
    // camel joint for the segment scanner; the scored count is the higher, and the cell must say so.
    report.push(prove_rows_red(
        cx,
        gate,
        "the two scanners disagreeing on a spelling, on a cell that does not record it",
        &[ROW_MATRIX],
        plant(
            "crates/busbar-kernel/src/leak.rs",
            "// gRPC status codes are not the kernel's business.\n",
        ),
        &["measurement-disagreement", "busbar-kernel × transport"],
    ));

    // AN EDGE CLASS NOBODY WROTE DOWN.
    report.push(prove_rows_red(
        cx,
        gate,
        "an edge class with no row at all is refused, whatever ARCHITECTURE.md may grant",
        &[ROW_MATRIX],
        ledger_with(
            cx,
            "from = \"root\"\nto = \"plane\"\n",
            "from = \"root\"\nto = \"plane-was-struck\"\n",
        ),
        &["unlisted-edge", "root -> plane"],
    ));

    // TWO ROWS FOR ONE CELL. The maps would keep the last, so which ceiling binds would be decided
    // by file order — and a ceiling nobody chose is not a ceiling.
    report.push(prove_rows_red(
        cx,
        gate,
        "a second `[[cell]]` row for one cell is two answers, not a tighter one",
        &[ROW_MATRIX],
        ledger_with(
            cx,
            &cell_row("busbar-kernel", "plane", "1"),
            &format!(
                "{}\n\n[[cell]]\n{}",
                cell_row("busbar-kernel", "plane", "1"),
                cell_row("busbar-kernel", "plane", "0")
            ),
        ),
        &["duplicate-row", "busbar-kernel × plane"],
    ));

    // THE LEDGER ITSELF GONE. A row that cannot read its allowance is not a row that found nothing.
    let mut gone = crate::ctx::Overlay::new();
    gone.remove(LEDGER);
    report.push(prove_rows_red(
        cx,
        gate,
        "the allowance ledger absent is a refusal, never an empty allowance",
        &[ROW_MATRIX],
        gone,
        &["the kind registry file did not read"],
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn both(line: &str, needle: &str) -> (usize, usize) {
        shadowed(line, needle, &[])
    }

    fn shadowed(line: &str, needle: &str, shadows: &[&str]) -> (usize, usize) {
        let n = needle_segments(needle);
        let sh: Vec<Vec<String>> = shadows.iter().map(|s| needle_segments(s)).collect();
        (
            count_by_segments(&line_segments(line), &n, &sh),
            count_by_windows(&line.chars().collect::<Vec<char>>(), &n, &sh),
        )
    }

    /// THE CARVE-OUT SHADOW. `busbar-core-policy` extends `busbar-core`; a spelling of the longer
    /// name is that crate's and not the legacy crate's, in both scanners, in every spelling —
    /// while a bare `busbar-core` beside it still counts.
    #[test]
    fn a_core_crate_name_is_not_the_legacy_crate_being_named() {
        let sh = ["busbar-core-policy"];
        assert_eq!(
            shadowed("use busbar_core_policy::HookEnv;", "busbar-core", &sh),
            (0, 0)
        );
        assert_eq!(
            shadowed("busbar-core-policy = { path = \"..\" }", "busbar-core", &sh),
            (0, 0)
        );
        assert_eq!(
            shadowed("crates/busbar-core-policy/src/lib.rs", "busbar-core", &sh),
            (0, 0)
        );
        assert_eq!(
            shadowed(
                "busbar_core::hooks and busbar_core_policy",
                "busbar-core",
                &sh
            ),
            (1, 1)
        );
        // Without the shadow the same line is two hits: the rule is the shadow, not the scanner.
        assert_eq!(
            both("busbar_core::hooks and busbar_core_policy", "busbar-core"),
            (2, 2)
        );
    }

    #[test]
    fn camel_and_acronym_both_split() {
        assert_eq!(line_segments("voiceServe"), vec!["voice", "serve"]);
        assert_eq!(line_segments("HTTPTransport"), vec!["http", "transport"]);
        assert_eq!(
            line_segments("root-voice-serve"),
            vec!["root", "voice", "serve"]
        );
    }

    #[test]
    fn english_never_yields_a_short_id() {
        // `assert` must never read as the `sse` transport, and `rows` never as `ws`.
        for line in ["assert!(x);", "the rows answer", "windows", "passes"] {
            assert_eq!(both(line, "sse"), (0, 0), "{line}");
            assert_eq!(both(line, "ws"), (0, 0), "{line}");
        }
    }

    #[test]
    fn both_scanners_see_a_comment_a_feature_and_an_identifier() {
        for line in [
            "/// The voice accept loop.",
            "#[cfg(feature = \"root-voice-serve\")]",
            "// voice",
            "let voice_serve = 1;",
            "root-voice-serve = []",
            "/src/root/voice_serve.rs",
        ] {
            let (a, b) = both(line, "voice");
            assert!(a > 0, "segment scanner missed {line}");
            assert!(b > 0, "window scanner missed {line}");
        }
    }

    #[test]
    fn a_full_crate_name_matches_in_every_spelling() {
        for line in [
            "busbar-transport-http = { workspace = true }",
            "use busbar_transport_http::Http;",
            "struct BusbarTransportHttp;",
        ] {
            let (a, b) = both(line, "busbar-transport-http");
            assert!(a > 0, "segment scanner missed {line}");
            assert!(b > 0, "window scanner missed {line}");
        }
    }

    #[test]
    fn a_camel_spelling_is_seen_by_both() {
        let (a, b) = both("let VoiceServe = 1;", "voice");
        assert_eq!((a, b), (1, 1));
    }
}
