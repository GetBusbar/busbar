//! `kind-isolation:matrix` — THE FULL KIND × CRATE VOCABULARY MATRIX.
//!
//! > "it's not just planes, it's everything. core is core, plugins are plugins, transport,
//! > everything. HAS TO BE PERFECT AND CLEAN." — owner, 2026-09-08
//!
//! The four rows this module joins hold the line for the WIRES: `:vocab` proves a transport never
//! says `a2a`, and a plane never says `hyper`. What none of them measured is the COMPOSITION ROOT.
//! `crates/busbar/src/root/**` hand-wired one file per plane — `units_llm.rs` (now the plane-free
//! node, `plane_node.rs`), `units_mcp.rs`, `units_a2a.rs`, `units_voice.rs` — and every one of them
//! slipped past CI, because nothing
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
//! ONE COLUMN IS NOT MEASURED, AND IT IS A RULE RATHER THAN AN ALLOWANCE: a crate of one of the
//! seven plugin kinds is not counted in the `contract` column. #40(a) makes `busbar-contract` the
//! only crate a plugin may name, so that column in a plugin crate measures the wall standing, not a
//! coupling; the exemption is the kind table's own `is_the_wall`, it covers no other pair, and a
//! ledger row that still records such a cell or class is RED (`rule-granted-cell`/`-edge`).
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

/// A scan set below this is not a tree this row can be a row over. EVERY file under `crates/`
/// whose extension is not on [`BINARY_EXTS`], which is 1 707 of them today.
const MIN_SCANNED: usize = 600;

mod instances;
mod vendors;

/// LAW 0/1: the plugin-INSTANCE vocabularies a NEUTRAL crate may name ZERO times — ALL SEVEN plugin
/// kinds (DECISIONS #3), read off `truths::PLUGIN_KINDS` rather than restated here.
///
/// IT WAS `["plane", "transport"]`, AND THAT WAS THE RELEASE'S BIGGEST INSTRUMENT HOLE (item 118 /
/// C1-KIND): C1 — "core names no instance" — was asserted over seven kinds and measured over two,
/// and the counter-example sat in the kernel (`EXPORT_MODULES`, a closed list of export plugin
/// instance names). `plane` and `transport` are measured by the ordinary columns, whose bare ids
/// count everywhere; the other five by [`instances`], whose vocabulary is derived from the census
/// and the tree's own module-name constants, and whose cells are the `[[instance]]` table.
fn instance_vocab_kinds() -> &'static [&'static str] {
    super::truths::PLUGIN_KINDS
}

/// The five axes [`instances`] measures — for the registry reader's load-time refusal.
pub(super) fn instance_axes() -> Vec<&'static str> {
    instances::axes()
}

/// Every neutral crate's naming of the five axes, `(crate, kind) -> count` — for `--write`.
pub fn measured_instances(
    cx: &Ctx,
    crates: &[CrateInfo],
) -> Result<BTreeMap<(String, String), usize>, String> {
    let (files, _) = scan_set(cx)?;
    let vocab = instances::vocabulary(crates, &files);
    Ok(instances::measure(crates, &files, &vocab)
        .into_iter()
        .map(|((k, kind), c)| ((k, kind.to_string()), c.count))
        .collect())
}

/// LAW 0/1 readiness: the neutral crates ENFORCED at ceiling 0 in the EVERYDAY
/// (`ship: false`) gate. Starts empty. A crate belongs here the moment its measured
/// `source_count` for every [`instance_vocab_kinds`] cell reaches 0 — adding it PINS that
/// crate at 0 permanently: from then on the everyday gate reds again the instant the
/// count rises above zero, even though the ordinary `[[cell]]` ratchet would otherwise
/// let it float back up. A neutral crate NOT yet listed here still drains through the
/// ordinary ratchet above (raised/stale-slack against its `[[cell]]` row) — this list
/// does not exempt it, it just does not yet BLOCK the push gate on it, so crates still
/// draining do not brick every other push. The ship twin (`ship: true`) ignores this
/// list entirely and enforces EVERY neutral crate unconditionally, because the ship SHA
/// owes zero everywhere regardless of what the everyday gate has caught up to.
const LAW0_ENFORCED_NEUTRAL_CRATES: &[&str] = &[];

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
///   about — so their bare ids count everywhere, which is how the root's hand-wired
///   plane files and `root-voice-serve` were caught.
///
/// A plane contributes its aliases too, because `streaming`, `voice` and `streams` are one instance
/// (`PLANE_ALIASES`).
///
/// One spelling is struck: a needle that is a PROPER SEGMENT PREFIX of another crate's package name
/// names nothing in particular. `busbar`, the composition root's package name, is the prefix of
/// every crate in the workspace, and counting it would report every `busbar_kernel::` path in the
/// tree as a crate naming the root.
fn vocabulary(crates: &[CrateInfo]) -> BTreeMap<&'static str, Vec<Needle>> {
    let mut out: BTreeMap<&'static str, Vec<Needle>> = BTreeMap::new();
    for c in crates {
        let Some(kind) = c.kind else { continue };
        let entry = out.entry(kind).or_default();
        entry.push(Needle {
            word: c.name.to_lowercase(),
            owner: c.name.clone(),
            id: String::new(),
        });
        // A WIRE A CRATE DECLARES IS VOCABULARY LIKE ONE IT IS NAMED FOR (#50). `http` holds
        // `grpc` and `sse` as modules since they folded into it, each registering under its own
        // key, so each key is a transport instance's bare and kind-qualified id, owned by the crate
        // that declares it — exactly the needles a crate named for that wire contributed.
        for key in &c.declared_keys {
            if own_id(c).as_deref() == Some(key.as_str()) {
                continue;
            }
            entry.push(Needle {
                word: format!("{kind}-{key}"),
                owner: c.name.clone(),
                id: key.clone(),
            });
            entry.push(Needle {
                word: key.clone(),
                owner: c.name.clone(),
                id: key.clone(),
            });
        }
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
            });
            if c.family != Family::Neutral {
                entry.push(Needle {
                    word: id.clone(),
                    owner: c.name.clone(),
                    id,
                });
            }
        }
    }
    // DIALECT IS NOT A KIND (DECISIONS #4), so the matrix measures no `dialect` column. The
    // vendor-name confinement — a plane may name its own dialects' vendor names, nothing else may —
    // is `plane-purity`'s vocabulary and scanner, handed by [`vendors`] the neutral crates that
    // gate's listed roots do not reach. Not a column: a ceiling of zero with no ledger row.

    let names: Vec<Vec<String>> = crates
        .iter()
        .map(|c| needle_segments(&c.name.to_lowercase()))
        .collect();
    for v in out.values_mut() {
        v.retain(|n| {
            let segs = needle_segments(&n.word);
            !names
                .iter()
                .any(|full| full.len() > segs.len() && full[..segs.len()] == segs[..])
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
fn count_by_segments(segs: &[String], needle: &[String]) -> usize {
    if needle.is_empty() || needle.len() > segs.len() {
        return 0;
    }
    (0..=(segs.len() - needle.len()))
        .filter(|&i| segs[i..i + needle.len()] == *needle)
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
fn count_by_windows(chars: &[char], needle: &[String]) -> usize {
    let mut hits = 0usize;
    let mut i = 0usize;
    while i < chars.len() {
        if let Some(end) = window_at(chars, i, needle) {
            let before = if i == 0 { None } else { Some(chars[i - 1]) };
            if is_boundary(before, Some(chars[i]))
                && is_boundary(Some(chars[end - 1]), chars.get(end).copied())
            {
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
    /// The HIGHEST of the scanners, never the lowest.
    count: usize,
    /// The slice of `count` that landed inside a `Cargo.toml`. Manifest edges are already
    /// governed by `kind-isolation:deps`; `count - manifest` is the SOURCE-only count the
    /// law0-neutral-instance class measures, so a dependency name does not double-count
    /// against a ceiling that dependency scanning already owns.
    manifest: usize,
    by_segments: usize,
    by_windows: usize,
    /// The third scanner: the line as the COMPILER sees it, escapes decoded and adjacent literals
    /// joined. See [`decoded_line`].
    by_decoded: usize,
    /// `word\tfile:line\tNx` for every hit, in scan order — the drain list.
    hits: Vec<String>,
    /// Every homoglyph hit, `word\tfile:line`. See [`folded_line`]: the ceiling on this list is
    /// ZERO and no row raises it.
    confusables: Vec<String>,
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
}

/// A crate's needles — every spelling this crate is measured against, in order. The two-letter
/// prefilter index is built per scan over the spellings that scan is for (see [`scan_needles`]).
#[derive(Default)]
struct Plan {
    needles: Vec<Resolved>,
    /// A hash of every `(kind, spelling)` in `needles`, in order — the key under which a file's
    /// ASSEMBLED answer for this exact plan is remembered (see [`PLAN_MEMO`]).
    key: u64,
}

type Measured = (Matrix, usize, Vec<String>);

fn measure(cx: &Ctx, crates: &[CrateInfo]) -> Result<Measured, String> {
    let vocab = vocabulary(crates);
    let by_dir: BTreeMap<&str, &CrateInfo> = crates.iter().map(|c| (c.dir.as_str(), c)).collect();

    let mut plan: BTreeMap<&str, Plan> = BTreeMap::new();
    for c in crates {
        let mut p = Plan::default();
        for (kind, words) in &vocab {
            // `dialect` is not a kind (DECISIONS #4) and no longer a column; the vendor-name
            // confinement is [`vendors`]'. Every column here comes from the census.
            //
            // THE ONE COLUMN A PLUGIN CRATE IS NOT MEASURED IN is the contract's: #40(a) makes
            // `busbar-contract` the one crate a plugin may name, so a plugin naming it on every
            // `use` line is the wall standing, not a coupling to ratchet ([`super::is_the_wall`]).
            // Every other kind's column is still counted in that crate.
            if c.kind.is_some_and(|k| super::is_the_wall(k, kind)) {
                continue;
            }
            for n in needles_for(words, c) {
                let parts = needle_segments(&n.word);
                if parts.is_empty() {
                    continue;
                }
                p.needles.push(Resolved {
                    kind,
                    word: n.word.clone(),
                    parts,
                });
            }
        }
        p.key = {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            for n in &p.needles {
                n.kind.hash(&mut h);
                n.word.hash(&mut h);
            }
            h.finish()
        };
        plan.insert(c.dir.as_str(), p);
    }

    let (files, skipped) = scan_set(cx)?;

    let mut matrix: Matrix = BTreeMap::new();
    for (rel, text) in &files {
        let rel = rel.clone();
        let Some(dir) = owning_dir(&rel) else {
            continue;
        };
        let Some(c) = by_dir.get(dir.as_str()) else {
            continue;
        };
        let Some(per_kind) = plan.get(dir.as_str()) else {
            continue;
        };
        for h in scan_file(per_kind, &dir, &rel, text).iter() {
            let cell = matrix.entry((c.name.clone(), h.kind)).or_default();
            cell.by_segments += h.by_segments;
            cell.by_windows += h.by_windows;
            cell.by_decoded += h.by_decoded;
            let n = h.by_segments.max(h.by_windows).max(h.by_decoded);
            cell.count += n;
            if rel.ends_with("Cargo.toml") {
                cell.manifest += n;
            }
            let mut mark = String::new();
            if h.by_segments != h.by_windows {
                mark.push_str("\t[scanners disagree]");
            }
            if h.by_decoded > h.by_segments.max(h.by_windows) {
                mark.push_str("\t[only the decoded reading sees it]");
            }
            if h.confusable {
                mark.push_str("\t[CONFUSABLE]");
                cell.confusables
                    .push(format!("{}\t{rel}:{}", h.word, h.line));
            }
            cell.hits
                .push(format!("{}\t{rel}:{}\t{n}x{mark}", h.word, h.line));
        }
    }
    Ok((matrix, files.len(), skipped))
}

/// EVERY BYTE A CRATE SHIPS, and the ones that are not bytes a reader reads.
///
/// The scan set used to be two extensions — `crates/**/*.rs` and `crates/**/*.toml` — and a red
/// team walked out through the gap five separate ways on one afternoon: a `README.md` that named a
/// plane and a transport in one sentence, a `.json` routing fixture pulled in with `include_str!`,
/// a `.yaml` twin of it, a `.inc` of real generated Rust pulled in with `include!`, and a `.txt`.
/// None of them was reached BY a scanner; every one of them went AROUND the scan set. An extension
/// list is a promise that the only text a crate ships is text somebody thought of in advance, and
/// this repository already ships `snap`, `sse`, `golden`, `waivers` and `html` files that no such
/// list had.
///
/// So the set is now EVERYTHING under a crate directory, whatever it is called. The only files left
/// out are the ones whose extension says they are not text at all — and they are not left out
/// silently: [`BINARY_EXTS`] is a short, closed list, and every path it drops is NAMED in
/// `--report`, so a crate that starts shipping its plane names inside a `.png` is a line a reader
/// sees rather than a hole nobody counted. A file with no extension is TEXT, not binary: the
/// default is to read it.
/// The scan set: every readable file as (path, text), and every path the binary list dropped.
type ScanSet = (Vec<(String, String)>, Vec<String>);

fn scan_set(cx: &Ctx) -> Result<ScanSet, String> {
    let all = cx
        .list(&WalkSpec::new(["crates"]))
        .map_err(|e| e.to_string())?;
    let mut files: Vec<(String, String)> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for rel in all {
        let rel = rel.to_string_lossy().replace('\\', "/");
        if let Some(ext) = binary_ext(&rel) {
            skipped.push(format!("{rel}\t[{ext}: a binary extension, not scanned]"));
            continue;
        }
        // A FILE THIS ROW CANNOT READ IS A REFUSAL, never a file with nothing in it. The only
        // reason a path under `crates/` that is not on the binary list fails to read as UTF-8 is
        // that it is binary and unlisted, which is exactly the case a reader must be told about.
        let text = cx.read(&rel).map_err(|e| {
            format!(
                "{rel}: {e} — a file under crates/ that is not on the binary extension list and                  does not read as text is a file this row cannot measure, and an unmeasured file                  is not an empty one. Add its extension to BINARY_EXTS, with a reason."
            )
        })?;
        files.push((rel, text));
    }
    if files.len() < MIN_SCANNED {
        return Err(format!(
            "{} file(s) under crates/, below the floor of {MIN_SCANNED}",
            files.len()
        ));
    }
    files.sort();
    skipped.sort();
    Ok((files, skipped))
}

/// The extensions whose contents are not text a scanner can read. SHORT AND CLOSED ON PURPOSE:
/// every entry here is a hole in the scan set, so the list is the thing a reviewer reads, and
/// `--report` prints every path each entry dropped.
const BINARY_EXTS: &[&str] = &[
    "a", "bin", "bmp", "bz2", "class", "dll", "dylib", "exe", "gif", "gz", "ico", "jar", "jpeg",
    "jpg", "mov", "mp3", "mp4", "o", "otf", "parquet", "pdf", "png", "rlib", "so", "sqlite", "tar",
    "tgz", "tiff", "ttf", "wasm", "wav", "webp", "woff", "woff2", "xz", "zip", "zst",
];

/// The binary extension a path carries, if any — lowercased, and only the final one, so
/// `wire_map.json.gz` is `gz` and `notes.png.txt` is text.
fn binary_ext(rel: &str) -> Option<&'static str> {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    let ext = name.rsplit_once('.')?.1.to_ascii_lowercase();
    BINARY_EXTS.iter().copied().find(|b| *b == ext)
}

/// One needle found once, on one line.
struct Hit {
    kind: &'static str,
    word: String,
    line: usize,
    by_segments: usize,
    by_windows: usize,
    /// The reading of the line with `\u{…}`/`\x..` decoded and adjacent literals joined.
    by_decoded: usize,
    /// True when the ASCII FOLD of this line finds the needle and no unfolded scanner does — a
    /// homoglyph, which is never a spelling anybody meant.
    confusable: bool,
}

/// THE PER-FILE, PER-NEEDLE MEMO, and the reason it exists is the SELF-TEST.
///
/// Every planted case re-runs the whole gate, and a plant changes ONE file. Re-measuring 1 558 of
/// them for each of thirty plants is the difference between a battery that runs in seconds and one
/// that runs for ten minutes — and a battery nobody waits for is a battery somebody stops running.
///
/// IT IS KEYED PER NEEDLE, NOT PER NEEDLE SET. It used to be keyed on the crate's whole needle set,
/// so a plant that ADDS A CRATE — and a census that walks the whole repository is proven by
/// planting crates in it — added one spelling to every crate's set, changed every key, and re-ran
/// every needle over every file under `crates/`: 24 cases of the `kind-isolation` battery paid a
/// full cold scan each (706 s of the matrix's 948 s), to re-derive hits for spellings that had not
/// changed in files that had not changed. What one needle finds on one line is a function of that
/// line and that needle alone — the two-letter prefilter admits a needle on its own bucket, and
/// every scanner reads only the line and the needle's segments — so the memo holds, per file
/// `(path, bytes)`, one entry per SPELLING, and a new spelling costs a scan for that spelling only.
static FILE_MEMO: std::sync::OnceLock<SpellingMemo> = std::sync::OnceLock::new();

/// `(path, bytes)` key -> spelling -> what that spelling finds in that file.
type SpellingMemo = std::sync::Mutex<BTreeMap<u64, BTreeMap<String, std::sync::Arc<Vec<WordHit>>>>>;

/// What one spelling finds on one line of one file — a [`Hit`] without the kind, which is the
/// plan's to say, not the file's.
#[derive(Clone)]
struct WordHit {
    line: usize,
    by_segments: usize,
    by_windows: usize,
    by_decoded: usize,
    confusable: bool,
}

/// THE ASSEMBLED ANSWER for one file under one exact plan — the fast path, and the only one a case
/// that did not change the vocabulary ever takes. Beneath it, [`FILE_MEMO`] is what a NEW plan is
/// assembled from.
static PLAN_MEMO: std::sync::OnceLock<PlanMemo> = std::sync::OnceLock::new();

/// `((path, bytes) key, plan key)` -> the file's hits under that plan, in single-pass order.
type PlanMemo = std::sync::Mutex<BTreeMap<(u64, u64), std::sync::Arc<Vec<Hit>>>>;

fn scan_file(plan: &Plan, dir: &str, rel: &str, text: &str) -> std::sync::Arc<Vec<Hit>> {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    rel.hash(&mut h);
    dir.hash(&mut h);
    text.hash(&mut h);
    let key = h.finish();
    let assembled = PLAN_MEMO.get_or_init(Default::default);
    if let Some(found) = assembled
        .lock()
        .expect("the memo mutex is never poisoned")
        .get(&(key, plan.key))
    {
        return std::sync::Arc::clone(found);
    }
    let memo = FILE_MEMO.get_or_init(Default::default);

    // THE SPELLINGS THIS FILE HAS NEVER BEEN PUT TO, one needle index per spelling.
    let missing: Vec<usize> = {
        let guard = memo.lock().expect("the memo mutex is never poisoned");
        let known = guard.get(&key);
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        (0..plan.needles.len())
            .filter(|&i| {
                let w = plan.needles[i].word.as_str();
                seen.insert(w) && !known.is_some_and(|k| k.contains_key(w))
            })
            .collect()
    };
    if !missing.is_empty() {
        let fresh = scan_needles(plan, &missing, dir, rel, text);
        let mut guard = memo.lock().expect("the memo mutex is never poisoned");
        let entry = guard.entry(key).or_default();
        for (word, hits) in fresh {
            entry
                .entry(word)
                .or_insert_with(|| std::sync::Arc::new(hits));
        }
    }

    // ASSEMBLED IN THE ORDER THE SINGLE PASS PRODUCED: by line, then by needle index.
    let guard = memo.lock().expect("the memo mutex is never poisoned");
    let known = guard.get(&key);
    let mut out: Vec<(usize, usize, Hit)> = Vec::new();
    for (i, n) in plan.needles.iter().enumerate() {
        let Some(hits) = known.and_then(|k| k.get(&n.word)) else {
            continue;
        };
        for w in hits.iter() {
            out.push((
                w.line,
                i,
                Hit {
                    kind: n.kind,
                    word: n.word.clone(),
                    line: w.line,
                    by_segments: w.by_segments,
                    by_windows: w.by_windows,
                    by_decoded: w.by_decoded,
                    confusable: w.confusable,
                },
            ));
        }
    }
    drop(guard);
    out.sort_by_key(|(line, i, _)| (*line, *i));
    let out: std::sync::Arc<Vec<Hit>> =
        std::sync::Arc::new(out.into_iter().map(|(_, _, h)| h).collect());
    assembled
        .lock()
        .expect("the memo mutex is never poisoned")
        .insert((key, plan.key), std::sync::Arc::clone(&out));
    out
}

// How many spellings THIS THREAD has put to a file through [`scan_needles`] — the exit test's
// probe for "a new spelling is scanned alone". Thread-local, so parallel tests cannot see each
// other's scans.
#[cfg(test)]
thread_local! {
    static SPELLINGS_SCANNED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The single pass over one file, for the needles named by `only` (indices into `plan.needles`, one
/// per spelling). Every spelling in `only` gets an entry, found or not, so an empty answer is
/// remembered as the answer it is.
fn scan_needles(
    plan: &Plan,
    only: &[usize],
    dir: &str,
    rel: &str,
    text: &str,
) -> BTreeMap<String, Vec<WordHit>> {
    #[cfg(test)]
    SPELLINGS_SCANNED.with(|n| n.set(n.get() + only.len()));
    let mut by_bucket: BTreeMap<Bucket, Vec<usize>> = BTreeMap::new();
    for &i in only {
        by_bucket
            .entry(bucket_of(&plan.needles[i].parts[0]))
            .or_default()
            .push(i);
    }
    let mut out: BTreeMap<String, Vec<WordHit>> = only
        .iter()
        .map(|&i| (plan.needles[i].word.clone(), Vec::new()))
        .collect();

    // THE PATH IS SCANNED FIRST, at line 0. `root/voice_serve.rs` names its plane before a byte of
    // it is read, and a filename is the first thing a reader of the tree sees. The crate's OWN
    // directory is stripped: it is the crate naming itself.
    let tail = rel.strip_prefix(dir).unwrap_or(rel);
    let subject = std::iter::once((0usize, tail)).chain(
        text.lines()
            .enumerate()
            .map(|(i, l): (usize, &str)| (i + 1, l)),
    );
    for (line, raw) in subject {
        let chars: Vec<char> = raw.chars().collect();
        // THE OTHER TWO READINGS OF THE SAME LINE, each computed only when the line carries the
        // thing it is about — a line with no backslash and no `concat!` has nothing to decode, and
        // an ASCII line has nothing to fold.
        let decoded = decoded_line(raw).map(|t| {
            let c: Vec<char> = t.chars().collect();
            (line_segments(&t), c)
        });
        let folded = folded_line(raw).map(|t| {
            let c: Vec<char> = t.chars().collect();
            (line_segments(&t), c)
        });

        let mut candidates: Vec<usize> = Vec::new();
        // THE PREFILTER MUST SEE EVERY READING. A two-letter index built from the raw bytes of
        // `"\x6dcp"` contains no `mc`, so a prefilter over the raw line alone would discard the
        // needle before either new scanner ever ran — the decode would be a decode of nothing.
        for c in [
            Some(&chars),
            decoded.as_ref().map(|d| &d.1),
            folded.as_ref().map(|f| &f.1),
        ]
        .into_iter()
        .flatten()
        {
            for b in line_buckets(c) {
                if let Some(idxs) = by_bucket.get(&b) {
                    candidates.extend(idxs);
                }
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
            let by_segments = count_by_segments(&segs, &n.parts);
            let by_windows = count_by_windows(&chars, &n.parts);
            let by_decoded = decoded
                .as_ref()
                .map(|(s, c)| count_by_segments(s, &n.parts).max(count_by_windows(c, &n.parts)))
                .unwrap_or(0);
            let by_folded = folded
                .as_ref()
                .map(|(s, c)| count_by_segments(s, &n.parts).max(count_by_windows(c, &n.parts)))
                .unwrap_or(0);
            let plain = by_segments.max(by_windows).max(by_decoded);
            if plain == 0 && by_folded == 0 {
                continue;
            }
            if let Some(v) = out.get_mut(&n.word) {
                v.push(WordHit {
                    line,
                    by_segments,
                    by_windows,
                    by_decoded: by_decoded.max(by_folded),
                    confusable: by_folded > plain,
                });
            }
        }
    }
    out
}

// ------------------------------------------------------------------------------------------------
// the ledger
// ------------------------------------------------------------------------------------------------

// ------------------------------------------------------------------------------------------------
// the third scanner, and the fold
// ------------------------------------------------------------------------------------------------

/// THE LINE AS THE COMPILER SEES IT — the third scanner's subject.
///
/// The two original scanners read the BYTES an author typed. Rust does not: `"\x6dcp"` is `mcp`,
/// `"\u{6c}\u{6c}m"` is `llm`, and `concat!("m", "cp")` is `mcp` before the first pass of macro
/// expansion is over. A red team wrote all three into a store plugin and every gate stayed green,
/// because a scanner that reads source bytes and a compiler that reads source meaning are looking
/// at two different strings and only one of them is what ships.
///
/// So this returns the line with `\u{…}` and `\x..` decoded and every run of ADJACENT string
/// literals joined — `"a", "b"` and `"a" "b"` both become `"ab"`, whether or not they sit inside a
/// `concat!`, because a scanner that first has to decide it is inside a `concat!` is a scanner with
/// a parser in it and a parser is a thing that can be walked around. `None` when the line has
/// nothing to decode: the common case is every line in the tree, and it costs one `contains`.
fn decoded_line(raw: &str) -> Option<String> {
    if !raw.contains('\\') && !raw.contains('"') {
        return None;
    }
    let ch: Vec<char> = raw.chars().collect();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0usize;
    while i < ch.len() {
        if ch[i] == '\\' && i + 1 < ch.len() {
            // `\u{H…}` — any number of hex digits, the form rustc itself accepts.
            if ch[i + 1] == 'u' && i + 2 < ch.len() && ch[i + 2] == '{' {
                if let Some(close) = (i + 3..ch.len()).find(|&j| ch[j] == '}') {
                    let hex: String = ch[i + 3..close].iter().collect();
                    if let Some(c) = u32::from_str_radix(hex.trim(), 16)
                        .ok()
                        .and_then(char::from_u32)
                    {
                        out.push(c);
                        i = close + 1;
                        continue;
                    }
                }
            }
            // `\xHH` — exactly two hex digits.
            if ch[i + 1] == 'x' && i + 3 < ch.len() {
                let hex: String = ch[i + 2..i + 4].iter().collect();
                if let Some(c) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    out.push(c);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(ch[i]);
        i += 1;
    }
    let joined = join_adjacent_literals(&out);
    (joined != raw).then_some(joined)
}

/// `"a", "b"` -> `"ab"`. Two string literals with nothing between them but commas and whitespace
/// are ONE string to the compiler, in a `concat!`, in a `format!`, and wherever else rustc's own
/// adjacent-literal rule applies.
fn join_adjacent_literals(s: &str) -> String {
    let ch: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < ch.len() {
        if ch[i] == '"' {
            let mut j = i + 1;
            while j < ch.len() && (ch[j] == ',' || ch[j].is_whitespace()) {
                j += 1;
            }
            if j > i + 1 && j < ch.len() && ch[j] == '"' {
                i = j + 1;
                continue;
            }
        }
        out.push(ch[i]);
        i += 1;
    }
    out
}

/// THE ASCII FOLD — the line with every character that is DRAWN as a Latin letter written as that
/// letter.
///
/// `"vоice"` with a Cyrillic `о` is not `voice` to any byte scanner ever written, and it is `voice`
/// to every human who reads it and to every log line that prints it. That is the whole attack: the
/// reviewer's eye and the gate's scanner disagree, and the reviewer is the one being trusted.
///
/// The fold does three things, in this order: combining marks (U+0300–U+036F) are DROPPED, which is
/// the decomposition half of NFKD that matters here; the Cyrillic and Greek homoglyph sets for
/// `a`–`z` are mapped to the letter they are drawn as; and the fullwidth and mathematical Latin
/// ranges are mapped arithmetically, because they are contiguous alphabets and a hand list of them
/// would be 1 000 entries somebody would maintain badly.
///
/// `None` for an ASCII line, which is very nearly every line.
fn folded_line(raw: &str) -> Option<String> {
    if raw.is_ascii() {
        return None;
    }
    let mut out = String::with_capacity(raw.len());
    let mut folded_any = false;
    for c in raw.chars() {
        let u = c as u32;
        // Combining marks: `e` + U+0301 is `é` is `e`.
        if (0x0300..=0x036F).contains(&u) {
            folded_any = true;
            continue;
        }
        match fold_char(c) {
            Some(f) => {
                folded_any = true;
                out.push(f);
            }
            None => out.push(c),
        }
    }
    folded_any.then_some(out)
}

/// The Cyrillic and Greek letters that are DRAWN as a Latin `a`–`z`, plus the Latin-1 accented
/// letters, plus the contiguous fullwidth and mathematical alphabets.
fn fold_char(c: char) -> Option<char> {
    let u = c as u32;
    // Fullwidth Latin: `Ａ`–`Ｚ`, `ａ`–`ｚ`.
    if (0xFF21..=0xFF3A).contains(&u) {
        return char::from_u32(u - 0xFF21 + u32::from(b'a'));
    }
    if (0xFF41..=0xFF5A).contains(&u) {
        return char::from_u32(u - 0xFF41 + u32::from(b'a'));
    }
    // Mathematical Alphanumeric Symbols: blocks of 52, upper then lower. The block has holes
    // (letter-like symbols live elsewhere); a hole folds to a letter that is not quite the right
    // one, which is a FALSE POSITIVE in a rule whose finding is "this is not ASCII and it looks
    // like a name", and a false positive here is the bias the owner asked for.
    if (0x1D400..=0x1D7A8).contains(&u) {
        let i = (u - 0x1D400) % 52;
        let base = if i < 26 { i } else { i - 26 };
        return char::from_u32(base + u32::from(b'a'));
    }
    HOMOGLYPHS
        .iter()
        .find(|(from, _)| *from == c)
        .map(|(_, to)| *to)
}

/// The hand-written half of the fold. Every entry is a character whose GLYPH is a Latin letter in
/// the fonts a reviewer reads code in.
#[rustfmt::skip]
const HOMOGLYPHS: &[(char, char)] = &[
    // Cyrillic, lower case.
    ('\u{0430}', 'a'), ('\u{0432}', 'b'), ('\u{0435}', 'e'), ('\u{0437}', 'z'),
    ('\u{043A}', 'k'), ('\u{043C}', 'm'), ('\u{043D}', 'h'), ('\u{043E}', 'o'),
    ('\u{0440}', 'p'), ('\u{0441}', 'c'), ('\u{0442}', 't'), ('\u{0443}', 'y'),
    ('\u{0445}', 'x'), ('\u{0455}', 's'), ('\u{0456}', 'i'), ('\u{0458}', 'j'),
    ('\u{04BB}', 'h'), ('\u{04CF}', 'l'), ('\u{0501}', 'd'), ('\u{051B}', 'q'),
    ('\u{051D}', 'w'), ('\u{04AF}', 'y'), ('\u{04BD}', 'e'), ('\u{0475}', 'v'),
    // Cyrillic, upper case.
    ('\u{0410}', 'a'), ('\u{0412}', 'b'), ('\u{0415}', 'e'), ('\u{041A}', 'k'),
    ('\u{041C}', 'm'), ('\u{041D}', 'h'), ('\u{041E}', 'o'), ('\u{0420}', 'p'),
    ('\u{0421}', 'c'), ('\u{0422}', 't'), ('\u{0423}', 'y'), ('\u{0425}', 'x'),
    ('\u{0405}', 's'), ('\u{0406}', 'i'), ('\u{0408}', 'j'), ('\u{0500}', 'd'),
    // Greek, lower case.
    ('\u{03B1}', 'a'), ('\u{03B2}', 'b'), ('\u{03B3}', 'y'), ('\u{03B5}', 'e'),
    ('\u{03B6}', 'z'), ('\u{03B7}', 'n'), ('\u{03B9}', 'i'), ('\u{03BA}', 'k'),
    ('\u{03BC}', 'u'), ('\u{03BD}', 'v'), ('\u{03BF}', 'o'), ('\u{03C1}', 'p'),
    ('\u{03C3}', 'o'), ('\u{03C4}', 't'), ('\u{03C5}', 'u'), ('\u{03C7}', 'x'),
    ('\u{03C9}', 'w'), ('\u{03BF}', 'o'),
    // Greek, upper case.
    ('\u{0391}', 'a'), ('\u{0392}', 'b'), ('\u{0395}', 'e'), ('\u{0396}', 'z'),
    ('\u{0397}', 'h'), ('\u{0399}', 'i'), ('\u{039A}', 'k'), ('\u{039C}', 'm'),
    ('\u{039D}', 'n'), ('\u{039F}', 'o'), ('\u{03A1}', 'p'), ('\u{03A4}', 't'),
    ('\u{03A5}', 'y'), ('\u{03A7}', 'x'), ('\u{0392}', 'b'),
    // Latin, precomposed — the accents an editor writes without being asked.
    ('\u{00E0}', 'a'), ('\u{00E1}', 'a'), ('\u{00E2}', 'a'), ('\u{00E3}', 'a'),
    ('\u{00E4}', 'a'), ('\u{00E5}', 'a'), ('\u{00E7}', 'c'), ('\u{00E8}', 'e'),
    ('\u{00E9}', 'e'), ('\u{00EA}', 'e'), ('\u{00EB}', 'e'), ('\u{00EC}', 'i'),
    ('\u{00ED}', 'i'), ('\u{00EE}', 'i'), ('\u{00EF}', 'i'), ('\u{00F1}', 'n'),
    ('\u{00F2}', 'o'), ('\u{00F3}', 'o'), ('\u{00F4}', 'o'), ('\u{00F5}', 'o'),
    ('\u{00F6}', 'o'), ('\u{00F8}', 'o'), ('\u{00F9}', 'u'), ('\u{00FA}', 'u'),
    ('\u{00FB}', 'u'), ('\u{00FC}', 'u'), ('\u{00FD}', 'y'), ('\u{00FF}', 'y'),
    ('\u{0107}', 'c'), ('\u{010D}', 'c'), ('\u{0111}', 'd'), ('\u{0142}', 'l'),
    ('\u{0144}', 'n'), ('\u{0161}', 's'), ('\u{017E}', 'z'), ('\u{0131}', 'i'),
];

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
    let (matrix, _, _) = measure(cx, crates)?;
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
fn minted_rows(cx: &Ctx) -> Vec<String> {
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
    let mut out = Vec::new();
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
        (
            instances::TABLE,
            &["crate", "kind"][..],
            "a ceiling for one neutral crate naming one plugin kind's instances as a value",
        ),
    ] {
        let was = super::base::row_keys(&base.registry, table, ids);
        // A WHOLE COLUMN THAT DID NOT EXIST IS THE RULE ARRIVING, NOT A CEILING RISING.
        //
        // Every key here is `<row> \u{d7} <column>` — a crate and the kind it names, or an edge's two
        // ends — and the mint rule is about the ROW: a second `[[cell]]` in a column that already
        // has some is a coupling somebody grew, and it is refused. A column with NO row at the base
        // at all is a different event: it is the commit that taught this rule to measure something
        // it could not measure before, and every cell of it is a FIRST measurement by construction.
        // The `dialect` column arrived exactly that way — the vendor names were unmeasurable until
        // the vocabulary was derived from the DIALECT list rather than from a census with no dialect
        // crate in it — and refusing 25 rows there is refusing the instrument, the same reason
        // `registry_present` above exempts the branch that adds the ledger itself. The carve-out is
        // narrow on purpose: it fires once per column, ever, and every later row in that column is
        // a mint like any other.
        let columns: std::collections::BTreeSet<&str> = was
            .iter()
            .filter_map(|k| k.rsplit_once(" \u{d7} ").map(|(_, col)| col))
            .collect();
        for key in super::base::row_keys(&now, table, ids) {
            if was.contains(&key) {
                continue;
            }
            if key
                .rsplit_once(" \u{d7} ")
                .is_some_and(|(_, col)| !columns.contains(col))
            {
                continue;
            }
            out.push(format!(
                "minted-row\t[[{table}]] {key}\tthis row is in no copy of {LEDGER} at the \
                 merge-base {}: this branch MINTED it. It is {what}, and a row that did not exist \
                 is a 0 -> N raise wearing the clothes of a first measurement — the one raise \
                 `ceiling-rose` cannot see, because a key with no `before` has nothing to be higher \
                 than. Delete the coupling instead, or land the row in a commit whose message says \
                 why the tree now needs it.",
                &base.commit[..8.min(base.commit.len())]
            ));
        }
    }
    out
}

/// THE LAW 0/1 ARMED CLASS — evaluated UNCONDITIONALLY of the `[[cell]]` ledger: a NEUTRAL
/// crate's ceiling against [`instance_vocab_kinds`] is 0, and no ratchet row can raise it.
/// Cargo.toml is excepted (`cell.manifest`) because a manifest edge is already governed by
/// `kind-isolation:deps`; arming it here too would double-count the same dependency name.
///
/// `enforced` is the readiness gate: `None` means every `Family::Neutral` crate is checked
/// (the ship twin, which owes zero everywhere unconditionally); `Some(list)` restricts the
/// findings to crates named in `list` (the everyday push gate, gated on
/// [`LAW0_ENFORCED_NEUTRAL_CRATES`] so crates still draining do not brick the push gate).
fn law0_offenders(matrix: &Matrix, crates: &[CrateInfo], enforced: Option<&[&str]>) -> Vec<String> {
    let mut offenders = Vec::new();
    for ((krate, kind), cell) in matrix {
        let is_neutral = crates
            .iter()
            .any(|c| &c.name == krate && c.family == Family::Neutral);
        if !is_neutral || !instance_vocab_kinds().contains(kind) {
            continue;
        }
        let source_count = cell.count - cell.manifest; // Cargo-exempt
        if source_count == 0 {
            continue;
        }
        if let Some(list) = enforced {
            if !list.contains(&krate.as_str()) {
                continue;
            }
        }
        offenders.push(format!(
            "law0-neutral-instance\t{krate} \u{d7} {kind}\t{source_count} source hit(s) (Cargo.toml \
             excluded). A NEUTRAL crate may name NO plugin-instance vocabulary: ceiling 0, ARMED — \
             no [[cell]] row raises it. Drain the names, or the crate is not neutral."
        ));
    }
    offenders
}

pub fn rule_matrix(cx: &Ctx, crates: &[CrateInfo], reg: &super::KindRegistry, ship: bool) -> Row {
    let (matrix, scanned, skipped) = match measure(cx, crates) {
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

    // THE FIVE INSTANCE AXES (item 118). Same scan set, read a second way — see [`instances`].
    let (files, _) = match scan_set(cx) {
        Ok(f) => f,
        Err(e) => {
            return Row::fail(
                ROW_MATRIX,
                "the kind × crate scan could not run",
                format!("{e} — the instance axes read the same scan set, and it did not read."),
            )
        }
    };
    let ivocab = instances::vocabulary(crates, &files);
    let inst = instances::measure(crates, &files, &ivocab);
    let inst_total: usize = inst.values().map(|c| c.count).sum();

    // LAW 1 OVER THE NEUTRAL CENSUS (item 203) — a vendor name in a neutral crate plane-purity does
    // not list. Ceiling 0 in both twins; see [`vendors`].
    let vendor = match vendors::offenders(cx, crates, &files) {
        Ok(v) => v,
        Err(e) => {
            return Row::fail(
                ROW_MATRIX,
                "the kind × crate scan could not run",
                format!(
                    "{e} — the vendor-name scan did not run, and an unrun scan is not a clean one."
                ),
            )
        }
    };

    // THE SHIP TWIN OWES ZERO EVERYWHERE, and owes it without consulting the ledger.
    if ship {
        if total == 0 && inst_total == 0 && ivocab.unattributed.is_empty() && vendor.is_empty() {
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
        // THE ARMED LAW 0/1 CLASS, UNCONDITIONALLY, over every `Family::Neutral` crate — the
        // ship twin does not consult [`LAW0_ENFORCED_NEUTRAL_CRATES`], it owes zero everywhere.
        let mut law0 = law0_offenders(&matrix, crates, None);
        law0.extend(instances::law0(&inst, None));
        law0.extend(ivocab.unattributed.iter().cloned());
        law0.extend(vendor.iter().cloned());
        return Row::fail(
            ROW_MATRIX,
            "a crate still names another kind's vocabulary",
            format!(
                "ship-ceiling 0: {total} hit(s) over {} cell(s): {}{}",
                matrix.len(),
                worst.join(" | "),
                if law0.is_empty() {
                    String::new()
                } else {
                    format!(" || {}", law0.join(" || "))
                }
            ),
        );
    }

    let listed = read_ledger(reg);

    let mut offenders: Vec<String> = duplicates(reg);
    offenders.extend(minted_rows(cx));
    offenders.extend(instances::offenders(&inst, &ivocab, reg));
    offenders.extend(instances::law0(&inst, Some(LAW0_ENFORCED_NEUTRAL_CRATES)));
    // Law 1 is armed at 0 on the everyday gate too: no ledger row exists that could raise it.
    offenders.extend(vendor.iter().cloned());
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
            // `root/plane_node.rs` hands them the file. The whole list is in `--report`.
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
        // A PLUGIN CRATE'S CONTRACT CELL IS NOT GONE, IT IS THE RULE: the column is not measured
        // for a plugin kind (see [`measure`]), so the row is an exception to a rule that excepts
        // nothing, and it says so rather than reading as a coupling that drained.
        let src = kind_of.get(krate.as_str()).copied().unwrap_or("?");
        if super::is_the_wall(src, kind) {
            offenders.push(format!(
                "rule-granted-cell\t{krate} \u{d7} {kind}\t#40(a) grants every plugin kind the \
                 contract's vocabulary as the RULE, so a {src} crate's contract column is not \
                 measured and a `[[cell]]` row for it is an exception to a rule that excepts \
                 nothing. Strike it."
            ));
            continue;
        }
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
    for (src, dst) in listed.edges.keys() {
        if super::is_the_wall(src, dst) {
            offenders.push(format!(
                "rule-granted-edge\t{src} -> {dst}\t#40(a) grants every plugin kind the contract's \
                 vocabulary as the RULE; an `[[edge]]` class for it is an exception to a rule that \
                 excepts nothing. Strike the class."
            ));
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

    // A HOMOGLYPH IS NEVER A SPELLING ANYBODY MEANT, AND ITS CEILING IS ZERO.
    //
    // Every other number in this row is a ratchet against a `[[cell]]` row, because every other
    // number counts a word somebody wrote on purpose and the question is whether there are MORE of
    // them than last week. This one is different in kind: a token whose ASCII fold is a plane's
    // name and whose raw bytes are not is a token that reads as that name to the reviewer and to
    // nothing else. There is no count of those that is the right count, so there is no row that
    // raises it — the ceiling is zero, exactly, and it is measured at zero on this tree today.
    for ((krate, kind), cell) in &matrix {
        for c in &cell.confusables {
            offenders.push(format!(
                "confusable\t{krate} \u{d7} {kind}\t{c}\ta token whose ASCII fold is this \
                 kind's vocabulary and whose raw bytes are not — a homoglyph reads as the name to \
                 every reviewer and to no scanner. The ceiling is 0 and no `[[cell]]` row raises it."
            ));
        }
    }

    // LAW 0/1, EVERYDAY BRANCH: armed unconditionally of the `[[cell]]` ledger, but BLOCKING
    // only for the crates [`LAW0_ENFORCED_NEUTRAL_CRATES`] has caught up to — the readiness
    // gate that lets the list ratchet down to 0 and STAY there without bricking the push gate
    // on neutral crates still draining. A crate not yet listed still shows up on the ordinary
    // ratchet above (raised / stale-slack against its `[[cell]]` row); it is only exempt from
    // being blocked TWICE for the same hits.
    offenders.extend(law0_offenders(
        &matrix,
        crates,
        Some(LAW0_ENFORCED_NEUTRAL_CRATES),
    ));

    let headline = format!(
        "{total} hit(s) over {} cell(s), {inst_total} instance name(s) written as a value over {} \
         `[[{}]]` cell(s), {scanned} file(s) scanned",
        matrix.len(),
        inst.len(),
        instances::TABLE
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
            "\nTHE FIVE INSTANCE AXES (vocab kind name from | cell crate kind count | hit):\n{}",
            instances::render(&inst, &ivocab)
        );
        println!(
            "\nLAW 1 — VENDOR NAMES IN THE NEUTRAL CRATES PLANE-PURITY DOES NOT LIST ({}):\n{}",
            vendor.len(),
            vendor.join("\n")
        );
        println!(
            "\nTHE LISTED CLASSES (cite, why, the line that deletes it):\n{}",
            render_classes(&listed)
        );
        println!(
            "\nTHE DRAIN LIST (word, file:line, hits):\n{}",
            render_drain(&matrix)
        );
        // EVERY HOLE IN THE SCAN SET, BY NAME. A file this row did not read is a file nobody read,
        // and the only defence against that is that a reader sees the list.
        println!(
            "\nNOT SCANNED ({} file(s), binary extensions):\n{}",
            skipped.len(),
            skipped.join("\n")
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

/// THE HAND-WIRED ROOT, as a fixture this battery owns: a composition-root module that names four
/// planes' crates, nodes, units and sections by hand. Read at run time and planted at
/// [`HAND_WIRED_ROOT_PLANT`]; stored as `.txt` so no crate, compiler or source scanner reads it
/// where it lives.
const HAND_WIRED_ROOT_FIXTURE: &str = "xtask/fixtures/kind-isolation-root/units_hand_wired.txt";

/// A synthetic `[[edge]]` row whose class no crate has, appended to the ledger by the dead-edge case.
/// Stored under `xtask/fixtures/`, which this gate treats as off-tree.
const DEAD_EDGE_FIXTURE: &str = "xtask/fixtures/kind-isolation-root/dead_edge_row.txt";

/// Where the hand-wired root is planted: inside the composition root, where the drained
/// `root/units_*.rs` files lived.
// qa-names: crates/busbar/src/root/units_hand_wired.rs -- xtask/src/gates/kind_isolation/matrix.rs -- a PLANT TARGET, not a scan root: the case writes the fixture to this path in its own overlay, so the path is absent from the tree by design, and this declaration reds the day a real file lands there
const HAND_WIRED_ROOT_PLANT: &str = "crates/busbar/src/root/units_hand_wired.rs";

/// A one-file plant under `dir`, without disturbing anything else in the tree.
///
/// A PLANT UNDER A DIRECTORY NO MANIFEST GOVERNS IS REFUSED, LOUDLY (item 175). Every rule of this
/// row keys on the crate census: `measure` attributes a file to the crate whose directory holds a
/// `Cargo.toml`, and `continue`s past one it cannot attribute. Four cases once planted under
/// `crates/busbar-plane-admin/` after that crate had folded away — the file was scanned, owned by
/// nothing, and every assertion it carried was dead. So a path under `crates/<dir>/` is only
/// plantable when `crates/<dir>/Cargo.toml` is on the tree, or IS the file being planted (a case
/// that lands a new crate plants its manifest first). A fixture that cannot move the row is a bug
/// in the battery, and a panic is how the battery says so.
fn plant(cx: &Ctx, rel: &str, body: &str) -> crate::ctx::Overlay {
    if let Some(dir) = owning_dir(rel) {
        let manifest = format!("{dir}/Cargo.toml");
        assert!(
            rel == manifest || cx.exists(&manifest),
            "{rel}: planted under `{dir}`, which holds no Cargo.toml — no crate of the census owns \
             it, so the plant is scanned and attributed to nothing and the case proves nothing"
        );
    }
    let mut ov = crate::ctx::Overlay::new();
    ov.set(rel, body.to_string());
    ov
}

/// The ledger with one row rewritten, so a case can raise a ceiling, leave slack in one, or knock a
/// whole class out.
///
/// THE SENTENCE THAT USED TO BE HERE WAS THE OPPOSITE OF TRUE. It read: *"a fixture that pins a
/// number goes LOUDLY red when the tree is re-measured, which is what a fixture is for."* It did
/// not. This was a bare `replacen`, and `replacen` over a needle that is not in the string returns
/// the string: a fixture pinning `count = "1798"` against a cell the ratchet had re-pinned to
/// `1942` wrote the ledger back BYTE-FOR-BYTE, the gate read the unplanted tree, and the case
/// scored whatever that tree scores — quietly, for as long as it took anyone to check. Three cases
/// in this file were doing it. A needle that is no longer in the ledger is an UNPLANTABLE CASE
/// now, and [`cell_anchor`] reads the number off the file so a re-pin cannot cause it in the first
/// place.
fn ledger_with(cx: &Ctx, from: &str, to: &str) -> Result<crate::ctx::Overlay, String> {
    let text = cx.read(LEDGER)?;
    if !text.contains(from) {
        return Err(format!(
            "`{}` is not in {LEDGER} to plant over",
            from.replace('\n', " / ")
        ));
    }
    Ok(plant(cx, LEDGER, &text.replacen(from, to, 1)))
}

/// [`prove_rows_red`](crate::gates::prove_rows_red) over a one-substitution plant into the real
/// ledger, with the substitution given as the `(anchor, replacement)` the caller worked out.
fn plant_ledger<'a>(
    cx: &'a Ctx,
    gate: &'a dyn crate::gates::Gate,
    name: &str,
    covers: &[&str],
    subst: Result<(String, String), String>,
    naming: &[&str],
) -> crate::gates::CasePlan<'a> {
    match subst.and_then(|(from, to)| ledger_with(cx, &from, &to)) {
        Ok(ov) => crate::gates::prove_rows_red(cx, gate, name, covers, ov, naming),
        Err(why) => super::unplantable(name, covers, naming, why).into(),
    }
}

/// THE TREE WITH ALMOST EVERY FILE UNDER `crates/` GONE, for this row's own floor.
///
/// `:matrix` does not walk one extension: it LISTS `crates/` whole, because a plane's name in a
/// `.json` fixture or a `README.md` is the crate's text just as much as its `.rs` is. So the only
/// honest fixture for "this scan collapsed" is a tree that really has almost nothing under
/// `crates/` at all — `keep` files survive, and a scan of four files finds no coupling, which is
/// indistinguishable from a tree that has none.
fn all_but_scanned(cx: &Ctx, keep: usize) -> crate::ctx::Overlay {
    let mut ov = crate::ctx::Overlay::new();
    let Ok(rels) = cx.list(&WalkSpec::new(["crates"])) else {
        return ov;
    };
    for rel in rels.iter().skip(keep) {
        ov.remove(rel.to_string_lossy().replace('\\', "/"));
    }
    ov
}

/// The three lines of one `[[cell]]` row.
pub(super) fn cell_row(krate: &str, kind: &str, count: &str) -> String {
    format!("crate = \"{krate}\"\nkind = \"{kind}\"\ncount = \"{count}\"")
}

/// THE `[[cell]]` ROW FOR `crate × kind` AS THE LEDGER SPELLS IT TODAY, count included.
///
/// A FIXTURE MAY NOT HARD-CODE A RATCHET VALUE. Every `count` in this file is TODAY'S MEASUREMENT
/// by construction, and `cargo xtask gate kind-isolation --write` re-pins it whenever the tree
/// moves down; a plant that quotes one is a plant that stops planting on the next re-pin and says
/// nothing when it does. `busbar × plane` was `1798` when the cases below were written and is
/// `1942` now; `busbar-kernel × plane` was `1` and is four figures. The anchor is read off the
/// file every run instead.
pub(super) fn cell_anchor(cx: &Ctx, krate: &str, kind: &str) -> Result<String, String> {
    let text = cx.read(LEDGER)?;
    let head = format!("crate = \"{krate}\"\nkind = \"{kind}\"\ncount = \"");
    let at = text.find(&head).ok_or_else(|| {
        format!("no `[[cell]]` row for {krate} × {kind} in {LEDGER} to plant over")
    })?;
    let rest = &text[at + head.len()..];
    let end = rest.find('"').ok_or_else(|| {
        format!("the `[[cell]]` row for {krate} × {kind} has an unterminated `count`")
    })?;
    Ok(format!("{head}{}\"", &rest[..end]))
}

/// That row, and the same row with `count` moved to `count`.
pub(super) fn cell_subst(
    cx: &Ctx,
    krate: &str,
    kind: &str,
    count: &str,
) -> Result<(String, String), String> {
    Ok((cell_anchor(cx, krate, kind)?, cell_row(krate, kind, count)))
}

/// Every RED case this row owes, and the GREEN one it is measured against.
pub fn selftest<'a>(
    cx: &'a Ctx,
    gate: &'a dyn crate::gates::Gate,
    ship: bool,
    report: &mut crate::gates::Report<'a>,
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
                cx,
                "crates/busbar-transport-tcp/src/leak.rs",
                "//! The llm plane's frames arrive here first.\n",
            ),
            &["ship-ceiling 0", "busbar-transport-tcp × plane"],
        ));
        instances::selftest(cx, gate, true, report);
        return;
    }

    // THE FIVE INSTANCE AXES (item 118) — every one planted in core, plus the ratchet both ways.
    instances::selftest(cx, gate, false, report);

    // THIS ROW'S SCAN HAS A FLOOR, AND NOTHING PROVED IT. A mutation campaign turned
    // `files.len() < MIN_SCANNED` into `false && …` and the whole battery stayed green: every other
    // case here plants a coupling and asserts the ledger's answer to it, and a scan that reached
    // four files still answers every one of them the same way. A floor nobody proves is a floor a
    // later reader deletes as dead code — and the tree it then reads as "every cell of the matrix
    // is 0" is the tree that has nothing under `crates/` at all.
    report.push(prove_rows_red(
        cx,
        gate,
        "a :matrix scan below its floor is refused, not read as a matrix of zeroes",
        &[ROW_MATRIX],
        move || all_but_scanned(cx, 4),
        &["below the floor of", &MIN_SCANNED.to_string()],
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
            cx,
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

    // THE INCIDENT, PLANTED — and its green twin, which is the same tree with the file absent.
    report.push(prove_rows_red(
        cx,
        gate,
        "the accept loop that named its plane (`root/voice_serve.rs`, keep-streams-3 dd96a04f3)",
        &[ROW_MATRIX],
        plant(
            cx,
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
    // measure and the row names the file the planes are wired in.
    //
    // THE FILE IS A FIXTURE, NOT A LIVE ONE. The case used to name `root/units_voice.rs`, the
    // heaviest of the root's hand-wired units files; that file is deleted, and a case that
    // names a live file breaks the day the drain it is measuring succeeds. The hand-wired module is
    // now [`HAND_WIRED_ROOT_FIXTURE`], planted under the root, so the row is asked to name bytes this
    // battery owns.
    let hand_wired = match cx.read(HAND_WIRED_ROOT_FIXTURE) {
        Ok(body) => cell_subst(cx, "busbar", "plane", "0")
            .and_then(|(from, to)| ledger_with(cx, &from, &to))
            .map(|mut ov| {
                ov.set(HAND_WIRED_ROOT_PLANT, body);
                ov
            }),
        Err(e) => Err(format!("{HAND_WIRED_ROOT_FIXTURE}: {e}")),
    };
    let name =
        "the root that hand-wired four planes, held to the zero a registry-driven root would measure";
    let naming = ["ratchet", "busbar × plane", "RAISED", "units_hand_wired.rs"];
    match hand_wired {
        Ok(ov) => report.push(prove_rows_red(cx, gate, name, &[ROW_MATRIX], ov, &naming)),
        Err(why) => report.push(super::unplantable(name, &[ROW_MATRIX], &naming, why)),
    }

    // A CEILING WITH SLACK IS THE OTHER HALF OF THE RATCHET.
    report.push(plant_ledger(
        cx,
        gate,
        "a ceiling left above the count it measures — stale slack is how drift hides",
        &[ROW_MATRIX],
        cell_subst(cx, "busbar-kernel", "plane", "99999"),
        &["ratchet", "busbar-kernel × plane", "STALE SLACK"],
    ));

    // A PLANE NAMED INSIDE A TRANSPORT — the wire learning what it carries.
    report.push(prove_rows_red(
        cx,
        gate,
        "a plane named inside a transport (`busbar-transport-tcp` says `llm`)",
        &[ROW_MATRIX],
        plant(
            cx,
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
            cx,
            "crates/busbar-transport-tcp/src/tests/leak.rs",
            "#[test]\nfn mcp_frames_round_trip() {}\n",
        ),
        &["busbar-transport-tcp", "plane"],
    ));

    // A TRANSPORT NAMED INSIDE A PLANE — the same fusion, the other way up.
    report.push(prove_rows_red(
        cx,
        gate,
        "a transport named inside a plane (`busbar-plane-mcp` says `grpc`)",
        &[ROW_MATRIX],
        plant(
            cx,
            "crates/busbar-plane-mcp/src/leak.rs",
            "//! The grpc wire delivers these.\n",
        ),
        &["ratchet", "busbar-plane-mcp × transport", "RAISED"],
    ));

    // A STORE NAMED INSIDE THE KERNEL — core is core.
    report.push(prove_rows_red(
        cx,
        gate,
        "a store named inside the kernel (`busbar-kernel` says `busbar_store_memory`)",
        &[ROW_MATRIX],
        plant(
            cx,
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
            cx,
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
            cx,
            "crates/busbar-kernel/src/leak.rs",
            "// gRPC status codes are not the kernel's business.\n",
        ),
        &["measurement-disagreement", "busbar-kernel × transport"],
    ));

    // AN EDGE CLASS NOBODY WROTE DOWN.
    report.push(plant_ledger(
        cx,
        gate,
        "an edge class with no row at all is refused, whatever ARCHITECTURE.md may grant",
        &[ROW_MATRIX],
        Ok((
            "from = \"root\"\nto = \"plane\"\n".to_string(),
            "from = \"root\"\nto = \"plane-was-struck\"\n".to_string(),
        )),
        &["unlisted-edge", "root -> plane"],
    ));

    // TWO ROWS FOR ONE CELL. The maps would keep the last, so which ceiling binds would be decided
    // by file order — and a ceiling nobody chose is not a ceiling.
    report.push(plant_ledger(
        cx,
        gate,
        "a second `[[cell]]` row for one cell is two answers, not a tighter one",
        &[ROW_MATRIX],
        cell_anchor(cx, "busbar-kernel", "plane").map(|anchor| {
            let doubled = format!(
                "{anchor}\n\n[[cell]]\n{}",
                cell_row("busbar-kernel", "plane", "0")
            );
            (anchor, doubled)
        }),
        &["duplicate-row", "busbar-kernel × plane"],
    ));

    // -- THE SCAN SET IS EVERYTHING A CRATE SHIPS ------------------------------------------------
    //
    // Six plants that went AROUND the two scanners rather than through them, on the afternoon the
    // scan set was two extensions. None of them is a cleverer spelling; every one of them is a file
    // the old walk never opened. See [`scan_set`].

    // A README IS THE FIRST THING A READER OF A CRATE READS, and it was the one file under the
    // crate directory nothing counted.
    report.push(prove_rows_red(
        cx,
        gate,
        "a plane named in a transport's own README -- a crate ships its prose too",
        &[ROW_MATRIX],
        plant(
            cx,
            "crates/busbar-transport-tcp/README.md",
            "# busbar-transport-tcp\n\nUsed by the llm plane over this wire.\n",
        ),
        &["busbar-transport-tcp", "plane"],
    ));

    // A JSON FIXTURE, COMPILED IN. `include_str!` makes it the crate's own bytes; the extension is
    // the only thing that ever made it invisible.
    report.push(prove_rows_red(
        cx,
        gate,
        "a plane routing table in a `.json` fixture under the crate is the crate's text",
        &[ROW_MATRIX],
        plant(
            cx,
            "crates/busbar-transport-tcp/src/fixtures/leak.json",
            "{\"planes\": [\"busbar-plane-llm\", \"busbar-plane-mcp\"]}\n",
        ),
        &["busbar-transport-tcp", "plane"],
    ));

    // THE SAME FIXTURE IN THE OTHER SERIALISATION. Two extensions was a list; a list is what the
    // next fixture format is not on.
    report.push(prove_rows_red(
        cx,
        gate,
        "the same table in `.yaml` -- the scan set is not an extension list",
        &[ROW_MATRIX],
        plant(
            cx,
            "crates/busbar-transport-tcp/src/fixtures/leak.yaml",
            "plane: busbar-plane-voice\n",
        ),
        &["busbar-transport-tcp", "plane"],
    ));

    // AN `include!` OF A NON-`.rs` FILE IS REAL COMPILED CODE. The compiled-set rule resolves the
    // include; this case proves the SCANNER reads the target whatever it is called.
    report.push(prove_rows_red(
        cx,
        gate,
        "generated Rust in a `.inc` file -- compiled code the old scan set never opened",
        &[ROW_MATRIX],
        plant(
            cx,
            "crates/busbar-transport-tcp/src/gen/names.inc",
            "pub const GEN: &str = \"busbar-plane-voice\";\n",
        ),
        &["busbar-transport-tcp", "plane"],
    ));

    // A FILE WITH NO EXTENSION AT ALL IS TEXT. The default must be to read, never to skip: a skip
    // list that grows by accident is the hole this whole section closed.
    report.push(prove_rows_red(
        cx,
        gate,
        "a file with no extension under a crate is scanned -- the default is text, not skip",
        &[ROW_MATRIX],
        plant(
            cx,
            "crates/busbar-transport-tcp/src/NOTES",
            "the a2a plane and the mcp plane both arrive here\n",
        ),
        &["busbar-transport-tcp", "plane"],
    ));

    // THE CARGO PROSE FIELDS. `description`, `keywords` and `readme` are shipped to the registry
    // under the crate's name, and they are read on exactly the same terms as its source.
    report.push(prove_rows_red(
        cx,
        gate,
        "a plane named in a transport's Cargo `description`/`keywords` -- shipped prose is scanned",
        &[ROW_MATRIX],
        {
            let rel = "crates/busbar-transport-tcp/Cargo.toml";
            let text = cx.read(rel).unwrap_or_default();
            plant(cx,
                rel,
                &text.replacen(
                    "[package]\n",
                    "[package]\ndescription = \"the wire the llm plane rides\"\nkeywords = [\"mcp\"]\n",
                    1,
                ),
            )
        },
        &["busbar-transport-tcp", "plane"],
    ));

    // -- THE SPELLING THE COMPILER READS AND THE SCANNER DID NOT --------------------------------

    // `"\x6dcp"` IS `mcp`. Three plants, three green gates, on the afternoon the scanners read
    // source bytes and the compiler read source meaning. See [`decoded_line`].
    report.push(prove_rows_red(
        cx,
        gate,
        "an escape-encoded plane name in a transport -- the compiler reads `\\x6dcp` as `mcp`",
        &[ROW_MATRIX],
        plant(
            cx,
            "crates/busbar-transport-tcp/src/leak.rs",
            "pub const HX: &str = \"\\x6dcp\";\n",
        ),
        &["busbar-transport-tcp", "plane"],
    ));

    report.push(prove_rows_red(
        cx,
        gate,
        "the `\\u{…}` spelling of the same name is the same name",
        &[ROW_MATRIX],
        plant(
            cx,
            "crates/busbar-transport-tcp/src/leak.rs",
            "pub const UN: &str = \"\\u{6c}\\u{6c}m\";\n",
        ),
        &["busbar-transport-tcp", "plane"],
    ));

    // A NAME SPLIT ACROSS TWO ADJACENT LITERALS IS ONE NAME.
    report.push(prove_rows_red(
        cx,
        gate,
        "a plane name split across a `concat!` of two literals is one name",
        &[ROW_MATRIX],
        plant(
            cx,
            "crates/busbar-transport-tcp/src/leak.rs",
            "pub const CS: &str = concat!(\"m\", \"cp\");\n",
        ),
        &["busbar-transport-tcp", "plane"],
    ));

    // A HOMOGLYPH. The `o` below is U+043E, Cyrillic. It reads as `voice` to every human being who
    // looks at it and to no byte scanner ever written, which is the whole of the attack.
    report.push(prove_rows_red(
        cx,
        gate,
        "a Cyrillic homoglyph inside a plane name is refused as a confusable, at a ceiling of zero",
        &[ROW_MATRIX],
        plant(
            cx,
            "crates/busbar-transport-tcp/src/leak.rs",
            "pub const UC: &str = \"v\u{43e}ice\";\n",
        ),
        &["confusable", "busbar-transport-tcp"],
    ));

    // -- THE VENDOR NAME IN A NEUTRAL CRATE — THE RED TEAM'S PLANT, RED AGAIN (item 203) --------
    //
    // A red team put `const VD = "anthropic";` and `fn openai_shim()` into `busbar-store-memory`
    // with every gate green. This case used to assert a `dialect` COLUMN went red; DECISIONS #4
    // struck that column, and the case was turned into a GREEN absence on the word that the
    // vendor rule was `plane-purity`'s — whose listed roots do not include `crates/store-memory`,
    // so the plant was green on every gate in the tree. The vendor rule now reaches every neutral
    // crate of the census through [`vendors`], and the incident's own bytes are RED on this row,
    // named by crate, file and the dialect it names.
    report.push(prove_rows_red(
        cx,
        gate,
        "a vendor name in a neutral plugin crate (`busbar-store-memory` says `anthropic`) is Law 1 RED",
        &[ROW_MATRIX],
        plant(
            cx,
            // THE DIRECTORY, NOT THE PACKAGE NAME: `busbar-store-memory` lives at
            // `crates/store-memory`, or the plant lands under no crate at all.
            "crates/store-memory/src/vendor.rs",
            "pub const VD: &str = \"anthropic\";\npub fn openai_shim() {}\n",
        ),
        &[
            "vendor-name",
            "busbar-store-memory",
            "crates/store-memory/src/vendor.rs:1",
        ],
    ));

    // THE COMPOSITION ROOT IS NEUTRAL TOO, and `plane-purity` does not list it either.
    report.push(prove_rows_red(
        cx,
        gate,
        "a vendor name in the composition root's own source is Law 1 RED",
        &[ROW_MATRIX],
        plant(
            cx,
            "crates/busbar/src/root/planted_vendor.rs",
            "pub fn pick() -> &'static str { \"bedrock\" }\n",
        ),
        &["vendor-name", "busbar\t", "planted_vendor.rs:1"],
    ));

    // A TEST IS NOT EXCLUDED. A neutral crate's fixture naming a vendor is that crate naming one.
    report.push(prove_rows_red(
        cx,
        gate,
        "a vendor name in a neutral plugin crate's own tests is Law 1 RED, in test scope",
        &[ROW_MATRIX],
        plant(
            cx,
            "crates/store-memory/src/tests/planted_vendor.rs",
            "#[test]\nfn t() { let _ = \"gemini\"; }\n",
        ),
        &["vendor-name", "busbar-store-memory", "\ttest\t"],
    ));

    // THE SCANNER'S ONE CARVE-OUT IS NOT AN OFF SWITCH HERE. With the pragma the vendor line is
    // exempt from the vocabulary rules, and no row outside plane-purity's roots checks its claim —
    // so the pragma itself is the finding.
    report.push(prove_rows_red(
        cx,
        gate,
        "a frozen-wire pragma in a neutral crate plane-purity does not list is refused, not honoured",
        &[ROW_MATRIX],
        plant(
            cx,
            "crates/store-memory/src/vendor.rs",
            "pub const VD: &str = \"anthropic\"; // plane-purity: frozen-wire frozen since 1.5.5 key: vd\n",
        ),
        &["vendor-frozen-wire", "busbar-store-memory", "vendor.rs:1"],
    ));

    // A PLANE NAMING ITS OWN DIALECT IS LAW 5, NOT A LEAK — the population stops at the neutral
    // family, and the same bytes in a plane crate move nothing on this row.
    report.push(prove_rows_green(
        cx,
        gate,
        "a plane naming a dialect is not a vendor-name finding (a plane may name its own)",
        &[ROW_MATRIX],
        plant(
            cx,
            "crates/busbar-plane-llm/src/planted_vendor.rs",
            "pub const VD: &str = \"anthropic\";\n",
        ),
    ));

    // ── THE THREE DEAD-ROW RULES, ONE PLANT EACH ─────────────────────────────────────────────────
    //
    // THE RATCHET ONLY HALF RAN. Every case above is about a number going UP; these three are the
    // half that TIGHTENS, and a mutation campaign found all three unproven — `dead-cell`,
    // `dead-disagreement` and `dead-edge` each had their `offenders.push` replaced with a `drop`
    // and the battery stayed green. An allowance that outlives what it allowed is the most durable
    // kind of hole there is: nothing goes red when the coupling is drained, so the row stays,
    // and the next crate to grow that coupling back finds the ceiling already written for it.
    //
    // The honest fixture for "this row covers nothing" is a tree in which the thing it covered is
    // GONE, and a crate leaves the measurement the way it leaves the census: its manifest goes.

    // A `[[cell]]` ROW WHOSE CRATE IS NOT THERE. `busbar-auth-static-plugin` carries live cells;
    // every one of them measures nothing the moment the crate stops being one.
    //
    // RE-TARGETED: the subject was `busbar-auth-admin-tokens × api`, and that row went dead on the
    // real tree when the crate's last `busbar-api` name moved to the contract — so its red became
    // standing debt the debt-free base subtracts, and the case came back green. `busbar-auth-static-plugin × plugin-tooling` is a live row (the SDK edge
    // stays until F6), and removing the crate's manifest kills it exactly as it did the old one.
    let mut ov = crate::ctx::Overlay::new();
    ov.remove("crates/auth-static-plugin/Cargo.toml");
    report.push(prove_rows_red(
        cx,
        gate,
        "a `[[cell]]` row whose cell measures nothing is a dead allowance, not a tight one",
        &[ROW_MATRIX],
        ov,
        &[
            "dead-cell",
            "busbar-auth-static-plugin \u{d7} plugin-tooling",
        ],
    ));

    // A `[[disagreement]]` ROW WHOSE TWO SCANNERS HAVE NOTHING LEFT TO DISAGREE ABOUT. The note is
    // a hand-written sentence about a spelling; when the cell it excuses is gone the sentence is a
    // standing licence for the next disagreement nobody reads.
    let mut ov = crate::ctx::Overlay::new();
    ov.remove("crates/busbar-llm-codec/Cargo.toml");
    report.push(prove_rows_red(
        cx,
        gate,
        "a `[[disagreement]]` row whose cell is gone is a standing licence, and is struck",
        &[ROW_MATRIX],
        ov,
        &["dead-disagreement", "busbar-llm-codec \u{d7} transport"],
    ));

    // AN `[[edge]]` ROW WHOSE WHOLE CLASS IS GONE. The case used to delete the one crate of kind
    // `api`, which the fold retired, so it now plants a synthetic row this battery owns
    // ([`DEAD_EDGE_FIXTURE`]): a `timing -> store` class that no crate of kind timing has. A class
    // that covers nothing is an edge the next crate of that kind would inherit, and is struck.
    let dead_edge = match (cx.read(LEDGER), cx.read(DEAD_EDGE_FIXTURE)) {
        (Ok(ledger), Ok(row)) => {
            let mut ov = crate::ctx::Overlay::new();
            ov.set(LEDGER, format!("{}\n{row}", ledger.trim_end()));
            Ok(ov)
        }
        (Err(e), _) => Err(format!("{LEDGER}: {e}")),
        (_, Err(e)) => Err(format!("{DEAD_EDGE_FIXTURE}: {e}")),
    };
    let name = "an `[[edge]]` row whose class no crate has any more is struck, not left standing";
    let naming = ["dead-edge", "timing -> store"];
    match dead_edge {
        Ok(ov) => report.push(prove_rows_red(cx, gate, name, &[ROW_MATRIX], ov, &naming)),
        Err(why) => report.push(super::unplantable(name, &[ROW_MATRIX], &naming, why)),
    }

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

    fn plan_of(words: &[(&'static str, &str)]) -> Plan {
        let mut p = Plan::default();
        for (kind, word) in words {
            p.needles.push(Resolved {
                kind,
                word: (*word).to_string(),
                parts: needle_segments(word),
            });
        }
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        for n in &p.needles {
            n.kind.hash(&mut h);
            n.word.hash(&mut h);
        }
        p.key = h.finish();
        p
    }

    fn readable(hits: &[Hit]) -> Vec<(&'static str, String, usize, usize, usize, usize, bool)> {
        hits.iter()
            .map(|h| {
                (
                    h.kind,
                    h.word.clone(),
                    h.line,
                    h.by_segments,
                    h.by_windows,
                    h.by_decoded,
                    h.confusable,
                )
            })
            .collect()
    }

    const MEMO_TEXT: &str = "use busbar_plane_llm::Thing;\n\
                             let a = \"\\x6dcp\"; // mcp, llm and a2a\n\
                             fn voiceServe() { concat!(\"a2\", \"a\"); }\n\
                             let grpc = HTTPTransport::new(\"llm-grpc\");\n";

    /// THE MEMO IS PER SPELLING: a plant that adds ONE spelling to a crate's plan — which every
    /// crate-adding plant in the battery does, to every crate at once — costs a scan for that
    /// spelling alone. It used to cost a scan for all of them: the memo was keyed on the whole
    /// needle set, so 24 cases paid a cold scan of every file under `crates/` each.
    #[test]
    fn a_new_spelling_is_scanned_alone_and_the_rest_are_remembered() {
        let dir = "crates/zz-memo-probe-one";
        let rel = "crates/zz-memo-probe-one/src/lib.rs";
        let before = plan_of(&[("plane", "llm"), ("plane", "mcp")]);
        let after = plan_of(&[("plane", "llm"), ("plane", "mcp"), ("plane", "a2a")]);

        let start = SPELLINGS_SCANNED.with(|n| n.get());
        let _ = scan_file(&before, dir, rel, MEMO_TEXT);
        let first = SPELLINGS_SCANNED.with(|n| n.get()) - start;
        let _ = scan_file(&after, dir, rel, MEMO_TEXT);
        let second = SPELLINGS_SCANNED.with(|n| n.get()) - start - first;
        let _ = scan_file(&after, dir, rel, MEMO_TEXT);
        let third = SPELLINGS_SCANNED.with(|n| n.get()) - start - first - second;

        assert_eq!(
            first, 2,
            "a cold file is scanned for every spelling in the plan"
        );
        assert_eq!(
            second, 1,
            "a plan that gained ONE spelling scans that spelling and nothing else"
        );
        assert_eq!(
            third, 0,
            "an unchanged file under an unchanged plan is not scanned"
        );
    }

    /// AND WHAT IT REMEMBERS IS THE SINGLE PASS'S ANSWER, EXACTLY: a plan assembled from spellings
    /// learned across three different plans reads the same hits, in the same order, as the same
    /// bytes scanned cold in one pass — including a spelling two kinds share.
    #[test]
    fn a_plan_assembled_from_the_memo_reads_exactly_what_a_cold_pass_reads() {
        let full = plan_of(&[
            ("plane", "llm"),
            ("transport", "grpc"),
            ("plane", "mcp"),
            ("plane", "a2a"),
            ("transport", "llm"),
            ("transport", "http-transport"),
        ]);
        let warm_dir = "crates/zz-memo-probe-warm";
        let warm_rel = "crates/zz-memo-probe-warm/src/lib.rs";
        let _ = scan_file(&plan_of(&[("plane", "mcp")]), warm_dir, warm_rel, MEMO_TEXT);
        let _ = scan_file(
            &plan_of(&[("plane", "a2a"), ("transport", "grpc")]),
            warm_dir,
            warm_rel,
            MEMO_TEXT,
        );
        let warm = scan_file(&full, warm_dir, warm_rel, MEMO_TEXT);

        let cold_dir = "crates/zz-memo-probe-cold";
        let cold_rel = "crates/zz-memo-probe-cold/src/lib.rs";
        let cold = scan_file(&full, cold_dir, cold_rel, MEMO_TEXT);

        assert!(
            !cold.is_empty(),
            "the probe text names the spellings it is scanned for"
        );
        assert_eq!(readable(&warm), readable(&cold));
    }

    fn both(line: &str, needle: &str) -> (usize, usize) {
        let n = needle_segments(needle);
        (
            count_by_segments(&line_segments(line), &n),
            count_by_windows(&line.chars().collect::<Vec<char>>(), &n),
        )
    }

    #[test]
    fn the_third_scanner_reads_what_the_compiler_reads() {
        assert_eq!(
            decoded_line(r#"let s = "\x6dcp";"#).as_deref(),
            Some(r#"let s = "mcp";"#)
        );
        assert_eq!(
            decoded_line(r#"let s = "\u{6c}\u{6c}m";"#).as_deref(),
            Some(r#"let s = "llm";"#)
        );
        assert_eq!(
            decoded_line(r#"concat!("m", "cp")"#).as_deref(),
            Some(r#"concat!("mcp")"#)
        );
        // Nothing to decode is `None`, which is the whole tree and must cost one `contains`.
        assert_eq!(decoded_line("let x = 1;"), None);
    }

    #[test]
    fn the_fold_maps_every_homoglyph_and_leaves_ascii_alone() {
        assert_eq!(
            folded_line("let s = \"v\u{43e}ice\";").as_deref(),
            Some("let s = \"voice\";")
        );
        assert_eq!(folded_line("\u{3bf}pen\u{430}i").as_deref(), Some("openai"));
        assert_eq!(
            folded_line("\u{ff4d}\u{ff43}\u{ff50}").as_deref(),
            Some("mcp")
        );
        // Combining marks are dropped, so `e` + U+0301 folds to `e`.
        assert_eq!(folded_line("voice\u{301}").as_deref(), Some("voice"));
        assert_eq!(folded_line("plain ascii"), None);
    }

    #[test]
    fn the_binary_skip_list_is_the_only_hole_and_it_is_exact() {
        // Only the FINAL extension counts, the compare is case-insensitive, and no extension at
        // all is text. A `.md`, a `.json`, a `.yaml`, a `.inc` and a `.snap` are all read.
        assert_eq!(binary_ext("crates/x/assets/logo.PNG"), Some("png"));
        assert_eq!(binary_ext("crates/x/tests/wire.json.gz"), Some("gz"));
        assert_eq!(binary_ext("crates/x/notes.png.txt"), None);
        assert_eq!(binary_ext("crates/x/src/NOTES"), None);
        for text in [
            "a.md", "a.json", "a.yaml", "a.inc", "a.snap", "a.html", "a.golden",
        ] {
            assert_eq!(binary_ext(text), None, "{text} must be scanned");
        }
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

    /// A PLANT OF A FILE THE TREE HAS NOT GOT REACHES THE SCAN SET, AND REACHES IT UNDER THE CRATE
    /// THAT OWNS IT — the two claims the `dialect` fixture was silently failing.
    ///
    /// `crates/busbar-store-memory/src/vendor.rs` is a path no manifest sits above: `owning_dir`
    /// answers `crates/busbar-store-memory`, `by_dir` has no entry for it, [`measure`] `continue`s,
    /// and the case asserting RED went GREEN while the same bytes written to disk at
    /// `crates/store-memory/src/vendor.rs` went red as they should. The fixture was corrected to
    /// name the directory the tree really has; this is the unit-speed guard that says so, because
    /// the only other instrument that could was a twenty-six-minute self-test.
    ///
    /// The three steps are asserted separately on purpose — a plant can be dropped by the walker,
    /// by the ignore filter, or by the crate lookup, and a single end-to-end assertion cannot say
    /// which. NO VENDOR WORD IS PLANTED HERE: what is under test is the path, not the scanner.
    #[test]
    fn a_planted_new_file_reaches_the_scan_set_under_the_crate_that_owns_it() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let rel = "crates/store-memory/src/vendor.rs";
        let body = "pub const PLANTED: &str = \"planted\";\n";
        let cx = cx.with_overlay(plant(&cx, rel, body));

        // THE WALKER, and the ignore filter it ends in.
        let listed = cx.list(&WalkSpec::new(["crates"])).expect("the walk lists");
        assert!(
            listed.iter().any(|p| p.to_string_lossy() == rel),
            "{rel}: planted and not listed — a plant the walk drops is a fixture that proves \
             nothing, whatever the case asserts"
        );

        // THE SCAN SET, which is the walk plus the read and the binary-extension skip.
        let (files, _skipped) = scan_set(&cx).expect("the scan set builds");
        let found = files.iter().find(|(p, _)| p == rel);
        assert_eq!(
            found.map(|(_, t)| t.as_str()),
            Some(body),
            "{rel}: listed and not scanned"
        );

        // THE CRATE THAT OWNS IT. This is the step the old fixture failed: a path under a directory
        // no manifest governs is scanned and then attributed to nothing.
        let dir = owning_dir(rel).expect("a path under crates/ has an owning directory");
        let crates = crate::gates::kind_isolation::census(&cx).expect("the census reads");
        let owner = crates.iter().find(|c| c.dir == dir);
        assert_eq!(
            owner.map(|c| c.name.as_str()),
            Some("busbar-store-memory"),
            "{rel}: scanned under `{dir}`, which no crate of the census owns — every hit in it \
             would be counted against no cell at all"
        );
    }

    /// ITEM 203's EXIT TEST, at unit speed: the red team's own bytes in `busbar-store-memory` add a
    /// `vendor-name` finding to this row that the unplanted tree does not carry. They added
    /// nothing while the vendor rule's only population was `plane-purity`'s listed roots.
    #[test]
    fn the_red_team_vendor_plant_in_a_neutral_plugin_crate_moves_the_row() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let reg = super::super::load_registry(&cx).expect("the ledger reads");
        let crates = super::super::census(&cx).expect("the census reads");
        let rel = "crates/store-memory/src/vendor.rs";
        let base = rule_matrix(&cx, &crates, &reg, false);
        assert!(
            !base.detail.contains(rel),
            "the unplanted tree already names {rel}"
        );
        let planted = cx.with_overlay(plant(
            &cx,
            rel,
            "pub const VD: &str = \"anthropic\";\npub fn openai_shim() {}\n",
        ));
        let crates = super::super::census(&planted).expect("the census reads");
        let row = rule_matrix(&planted, &crates, &reg, false);
        let finding = format!("vendor-name\tbusbar-store-memory\t{rel}:1");
        assert!(
            row.detail.contains(&finding),
            "the red team's vendor plant moved nothing on {ROW_MATRIX}: {}",
            row.detail.chars().take(400).collect::<String>()
        );
    }

    /// ITEM 175's EXIT TEST. The four plants that went under `crates/busbar-plane-admin/` after the
    /// crate folded away were scanned and owned by nothing; the helper every case plants through
    /// now refuses such a path before a case can be built on it.
    #[test]
    #[should_panic(expected = "holds no Cargo.toml")]
    fn a_plant_under_a_directory_no_manifest_governs_is_refused() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let _ = plant(
            &cx,
            "crates/busbar-plane-admin/src/leak.rs",
            "//! The grpc wire delivers these.\n",
        );
    }

    /// The same helper still plants a NEW crate's manifest, and a file of a crate that has one.
    #[test]
    fn a_plant_under_a_governed_directory_or_of_a_new_manifest_is_accepted() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let _ = plant(&cx, "crates/store-memory/src/vendor.rs", "pub fn f() {}\n");
        let _ = plant(
            &cx,
            "crates/busbar-store-zanzibar/Cargo.toml",
            "[package]\n",
        );
        let _ = plant(&cx, LEDGER, "");
    }

    #[test]
    fn a_camel_spelling_is_seen_by_both() {
        let (a, b) = both("let VoiceServe = 1;", "voice");
        assert_eq!((a, b), (1, 1));
    }
}
