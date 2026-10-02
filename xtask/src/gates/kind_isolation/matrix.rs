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
//! For EVERY kind `K` in the kind table and EVERY crate `C` under `crates/`, this row measures
//! whether `C` names `K`'s vocabulary at all — a crate-level cross-kind EDGE. `K`'s vocabulary is
//! DERIVED, never listed: it is the package names of `K`'s member crates plus each member's
//! INSTANCE ID (the name segments after the kind marker) and, for a plane, its alias. Registering a
//! plane, a transport or a store teaches this row a new word in every other crate, on the same
//! commit — the same derivation the rest of the gate already runs on.
//!
//! A crate is never measured against its own spellings, and when `kind(C) == K` the crate's OWN id
//! is struck from the needles first: what is left is the other instances of its own kind, which is
//! the cross-instance leak `busbar-plane-llm` naming `mcp` would be.
//!
//! ## TWO INDEPENDENT SCANNERS, AND THE HIGHER ONE DECIDES
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
//! The cell's count is the HIGHER of the two (and of the decoded reading), never the lower, so a
//! name written in a spelling one scanner cannot see still makes the cell non-zero — exactly the
//! leak that must not pass. With the counts gone from the ledger (below) a disagreement between the
//! scanners decides nothing a row could record, so the `[[disagreement]]` table went with them;
//! `--report` still prints both scanners' numbers per cell.
//!
//! A boundary rule rather than a raw byte substring, and the reason is measurable rather than
//! aesthetic: `sse` is a transport instance and also the middle of `assert`, `ws` is a transport
//! instance and also the middle of `rows`. A raw substring scan of this tree answers 35 306 for
//! `sse` and 5 671 for `ws`, numbers made almost entirely of English, and a cell made of them is
//! non-zero in every crate that writes an assertion. That is not a stricter gate, it is a line
//! counter wearing one. The boundary rule keeps every spelling a human would recognise as the
//! name — `a2a_session`, `mcpFrame`, `root-voice-serve`, `busbar_transport_http`, `VoiceServe`,
//! the filename, the feature, the comment — and refuses the ones that are not names at all.
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
//! because the root's tests drive the assembly — and that is a LISTED cell with a citation, not a
//! silent `continue` in this file.
//!
//! ## NO SILENT EXEMPTIONS: `qa/kind-isolation.toml` IS THE WHOLE ALLOWANCE
//!
//! There is no allow-list in this source, and there is no second reader either: these rows go
//! through the SAME hand reader the `[[transitional]]`, `[[registered]]` and `[[announced]]` tables
//! do ([`super::parse_registry`]), on the same terms — a missing field, an empty field or an
//! unknown field is REFUSED AT LOAD rather than skipped. Two tables:
//!
//! * `[[edge]]` — one per kind → kind CLASS, carrying `cite` (the `BUSBAR-1.6.0.md` clause that
//!   grants it, or the words that say none does), `why` (what the class is made of) and `drain`
//!   (the line that deletes it; an allowance with no route to zero is one nobody drains). The prose
//!   belongs to the class because that is what a reader is reading.
//! * `[[cell]]` — one per crate × kind: `crate` and `kind`, and NOTHING ELSE. A row says this
//!   crate-level edge exists and was reviewed. It carries no count, and a `count` field is refused
//!   at load.
//!
//! PRESENCE, NOT SIZE. Size is not a CI check (owner 2026-10-02): how MANY times a crate names a
//! kind is read at perf time with the hash tool, not here. What CI holds is the EDGE, and it holds
//! it HARD. A cell above zero with no row is a NEW crate-level cross-kind edge (`unlisted-cell`),
//! refused whatever `BUSBAR-1.6.0.md` may or may not grant, because an edge nobody wrote down is an
//! edge nobody reviewed; a class with no `[[edge]]` row is `unlisted-edge`. A row whose cell now
//! measures zero is a dead allowance and must be struck. A row this branch MINTED is refused
//! ([`minted_rows`]) — that is the rule that stops a branch legitimising a new edge by writing its
//! row in the same commit. More hits inside a listed cell change nothing here, and no finding of
//! this row carries a hit count, so a red row's figure is the number of findings it holds.
//!
//! ONE SPAN IS NOT READ, BY ARCHITECT RULING (2026-10-02, DF-MAP): a plane crate's dialect mapping
//! file (`<plane crate>/dialects/<d>.toml`) quotes its rows' wire paths verbatim from the provider's
//! pinned spec, and a provider's own vocabulary (OpenAI's hosted tool type `mcp`) is protocol, not a
//! coupling. So a quoted map KEY is masked ONLY when it resolves EXACTLY to a path of the wire lock
//! the file names (`[dialect] wire`, `testing/llm-conformance/wire/<lock>.wire.json`). The same word
//! in a value, a comment, or a key the lock does not have is counted as before
//! ([`mask_dialect_wire_keys`]).
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

/// The ledger this row shares with the rest of the gate — named in `BUSBAR-1.6.0.md` THE DESIGN, §2 before either
/// existed, which is why neither invents a second place.
pub const LEDGER: &str = "qa/kind-isolation.toml";

/// A scan set below this is not a tree this row can be a row over. EVERY file under `crates/`
/// whose extension is not on [`BINARY_EXTS`], which is 1 707 of them today.
const MIN_SCANNED: usize = 600;

mod auth_words;
mod instances;
mod os_words;
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

/// LAW 0/1 readiness: the neutral crates ENFORCED at ceiling 0 in the EVERYDAY
/// (`ship: false`) gate. Starts empty. A crate belongs here the moment its measured
/// `source_count` for every [`instance_vocab_kinds`] cell reaches 0 — adding it PINS that
/// crate at 0 permanently: from then on the everyday gate reds again the instant the
/// count rises above zero, even though its listed `[[cell]]` row (presence only) would
/// otherwise let it float back up. A neutral crate NOT yet listed here is still held to
/// its `[[cell]]` rows (a new cell with no row is `unlisted-cell`) — this list
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

/// PLANE SPELLINGS THAT ARE NEVER A BARE-WORD NEEDLE, each with the neutral primitive it collides
/// with. The spelling still canonicalises onto its plane (`PLANE_ALIASES`) and still counts in its
/// package name and its kind-qualified id (`busbar-plane-decisions`, `plane-decisions`); only the
/// bare word is not a needle, because the bare word already names something neutral.
///
/// * `decisions` — the owner's rename of the fifth plane's crate (`busbar-plane-decisions`, #17/#48;
///   its declared `KEY` stays `decision`, which is still a bare needle as it was before the rename).
///   `decisions` is also the 1.5.x export stream (`ExportStream::Decisions`, `streams: [logs,
///   identity, decisions, …]`), a frozen wire word the kernel's export projection and the contract's
///   export ABI spell as the stream's own name. Counting it would report the export stream as the
///   plane, which is the collision `plane-purity` and `plane-abi-neutrality` exempt for the same
///   plane.
const BARE_WORD_COLLISIONS: &[&str] = &["decisions"];

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
            if c.family != Family::Neutral && !BARE_WORD_COLLISIONS.contains(&id.as_str()) {
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
            // The core tiers' contract column is not measured either (#83/#83a): see
            // [`super::names_contract_by_design`].
            if c.kind
                .is_some_and(|k| super::names_contract_by_design(k, kind))
            {
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
    let contract = contract_identifiers(&files, &vocab);
    // The auth ABI's own `decision` field (continue/stop) is masked in auth crates while the
    // contract declares it ([`auth_words`]).
    let auth_decision = auth_words::declared(&files);
    // A plugin's own conformance test naming the loader it is granted is the witness, not a
    // coupling ([`super::conformance_witness_edges`]).
    let granted = super::conformance_witness_edges(cx, crates);

    let mut matrix: Matrix = BTreeMap::new();
    let mut wire_locks: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
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
        // `BUSBAR-1.6.0.md` §11.5 "One place for every ABI shape": every ABI shape lives in ONE place,
        // `busbar-contract/src/abi/` — the seven kinds' operations, data shapes and versions
        // legitimately live and cross-reference each other there (`abi/store/` naming `abi/auth/`'s
        // shapes is the mechanism working, not a coupling). So the MATRIX — this row's crate × kind
        // vocabulary count — never attributes a hit inside that directory to any cell. The exemption
        // is scoped to THIS counting alone: `contract_identifiers` above still reads `abi/` to learn
        // the contract's own exported shapes, and the neutrality gates
        // (instance-noun-neutrality, plane-abi-neutrality, c1-literals) still scan every byte of
        // `abi/` exactly as before — only the kind-isolation MATRIX stops filing it into a cell. Code
        // in `busbar-contract` OUTSIDE `abi/` is still counted, same as any other crate, except the
        // three mirrors that restate `abi/`'s shapes ([`CONTRACT_ABI_LAYOUT_MIRRORS`]).
        if c.name == CONTRACT_PACKAGE && is_contract_abi_shape(&rel) {
            continue;
        }
        // The contract's own identifiers are masked everywhere EXCEPT in the contract, whose
        // vocabulary is its own row's to measure (see [`contract_identifiers`]).
        let masked = if c.name == CONTRACT_PACKAGE {
            std::borrow::Cow::Borrowed(text.as_str())
        } else {
            mask_identifiers(text, &contract)
        };
        // English words that are also instance names are not counted as English prose.
        let masked = mask_english_prose(&rel, &masked);
        // Instance ids that are also a crate's or an abbreviation's name count only as references.
        let masked = mask_colliding_words(&rel, &masked);
        // `unix` as the operating system (a cfg, `std::os::unix`, the clock) is not the carrier.
        // Its context is read off the ORIGINAL text: an earlier mask's filler must not change what
        // a neighbouring word says ("the unix socket" with `socket` masked as a contract name).
        let masked = os_words::mask_os_words_in(&rel, text, &masked);
        let masked = match auth_words::scope(c.kind, &dir, &rel).filter(|_| auth_decision) {
            Some(with_type) => std::borrow::Cow::Owned(
                auth_words::mask_auth_decision(&rel, &masked, with_type).into_owned(),
            ),
            None => masked,
        };
        // A dialect mapping file's wire-lock keys are the provider's words (ruling above).
        let masked = if c.kind == Some("plane") {
            mask_dialect_wire_keys(cx, &dir, &rel, text, &masked, &mut wire_locks)
        } else {
            std::borrow::Cow::Borrowed(&*masked)
        };
        for h in scan_file(per_kind, &dir, &rel, &masked).iter() {
            let line = h
                .line
                .checked_sub(1)
                .and_then(|i| text.lines().nth(i))
                .unwrap_or("");
            if super::is_witness_hit(&granted, c, h.kind, &rel, line) {
                continue;
            }
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

/// Where the wire locks live, one `<lock>.wire.json` per dialect (see [`crate::wire_lock`]).
const WIRE_LOCK_DIR: &str = "testing/llm-conformance/wire";

/// THE ONE SPAN THE MATRIX DOES NOT READ (ARCHITECT ruling 2026-10-02, DF-MAP): in a plane crate's
/// `dialects/<d>.toml`, a line's quoted KEY that is EXACTLY a path of the wire lock the file names
/// (`[dialect] wire = "<lock>"`) is masked. Nothing else is: not the value, not a comment, not a key
/// the lock lacks, not a file outside `<plane crate>/dialects/`. A file whose lock is missing or
/// unreadable masks nothing. The keys are read off the ORIGINAL `text` (an earlier mask may have
/// filled a word of it) and filled in `masked`, which every earlier mask keeps byte-aligned with it.
/// `locks` caches each lock's path set across files.
fn mask_dialect_wire_keys<'a>(
    cx: &Ctx,
    dir: &str,
    rel: &str,
    text: &str,
    masked: &'a str,
    locks: &mut BTreeMap<String, BTreeSet<String>>,
) -> std::borrow::Cow<'a, str> {
    let in_dialects = rel
        .strip_prefix(dir)
        .and_then(|r| r.strip_prefix("/dialects/"))
        .is_some_and(|f| f.ends_with(".toml") && !f.contains('/'));
    if !in_dialects || masked.len() != text.len() {
        return std::borrow::Cow::Borrowed(masked);
    }
    let Some(wire) = crate::toml_lite::parse_text(text)
        .table("dialect")
        .get_one("wire")
        .map(String::from)
    else {
        return std::borrow::Cow::Borrowed(masked);
    };
    let paths = locks.entry(wire.clone()).or_insert_with(|| {
        cx.read(format!("{WIRE_LOCK_DIR}/{wire}.wire.json"))
            .ok()
            .and_then(|t| crate::wire_lock::Lock::parse(&t).ok())
            .map(|l| l.dirs.into_values().flat_map(|d| d.into_keys()).collect())
            .unwrap_or_default()
    });
    let mut out: Option<Vec<u8>> = None;
    let mut at = 0usize;
    for line in text.split_inclusive('\n') {
        let lead = line.len() - line.trim_start().len();
        let rest = &line[lead..];
        if let Some(body) = rest.strip_prefix('"') {
            if let Some(end) = body.find('"') {
                let key = &body[..end];
                let after = body[end + 1..].trim_start();
                if after.starts_with('=') && key.is_ascii() && paths.contains(key) {
                    let start = at + lead + 1;
                    let buf = out.get_or_insert_with(|| masked.as_bytes().to_vec());
                    buf[start..start + key.len()].fill(b'x');
                }
            }
        }
        at += line.len();
    }
    match out {
        // Only ASCII key bytes were replaced by ASCII, so the buffer is still UTF-8.
        Some(buf) => std::borrow::Cow::Owned(String::from_utf8(buf).expect("ascii-for-ascii")),
        None => std::borrow::Cow::Borrowed(masked),
    }
}

/// The contract crate's package name: the one crate whose exported identifiers are shapes every
/// other crate may name.
const CONTRACT_PACKAGE: &str = "busbar-contract";

/// THE ONE DESIGNATED HOME OF EVERY ABI SHAPE (`BUSBAR-1.6.0.md` THE DESIGN, §11.5, "One place for
/// every ABI shape" — "Every ABI shape lives only in `busbar-contract/src/abi/`"). ARCHITECT ruling
/// 2026-09-27 scopes the MATRIX's crate × kind counting to exclude this directory in the
/// `busbar-contract` row: the seven kinds' shapes legitimately live and cross-reference one another
/// there, so a hit inside it is the mechanism, not a leak. See the call site in [`measure`] for what
/// this does and does not touch.
const CONTRACT_ABI_PREFIX: &str = "crates/busbar-contract/src/abi/";

/// THE THREE MIRRORS of [`CONTRACT_ABI_PREFIX`]: the layout golden, the test that writes it, and
/// the generated C header (`BUSBAR-1.6.0.md` §11.5, "a generated C header"; the `abi-header` gate
/// pins it to `src/abi/`, ARCHITECT ruling 2026-09-30). They exist only to restate, field by field,
/// the shapes that live in `src/abi/` (the export tail's `streams`/`streams_len` fields, for one),
/// so the same ARCHITECT ruling that scopes `src/abi/` covers them. Named exactly, three files and
/// nothing else: every other file under `busbar-contract/tests/` or any `include/` is still
/// counted, and no word is exempted anywhere.
const CONTRACT_ABI_LAYOUT_MIRRORS: &[&str] = &[
    "crates/busbar-contract/tests/golden/abi-layout.golden",
    "crates/busbar-contract/tests/layout_golden.rs",
    "crates/busbar-contract/include/busbar_plugin.h",
];

/// Whether `rel` (a path under `crates/`) is inside [`CONTRACT_ABI_PREFIX`] or is one of its
/// [`CONTRACT_ABI_LAYOUT_MIRRORS`] — the MATRIX's one carve-out, and the only place this gate
/// calls it.
fn is_contract_abi_shape(rel: &str) -> bool {
    rel.starts_with(CONTRACT_ABI_PREFIX) || CONTRACT_ABI_LAYOUT_MIRRORS.contains(&rel)
}

/// THE CONTRACT'S OWN IDENTIFIERS — every item `busbar-contract` declares `pub` (struct, enum,
/// trait, type, union, fn, const, static) in its `src/` — measured by nobody's column but the
/// contract's own (ARCHITECT ruling 2026-09-27, the Q77a measurement-correction class).
///
/// An identifier the contract exports is the contract's SHAPE, not a plugin instance's vocabulary.
/// `busbar_contract::hooks::RoutingDecision` is the hook kind's answer type; a crate that names it
/// is naming the hook contract, and reading its camel-case half `Decision` as the `decision`
/// plane's bare id charged every hook caller with a plane coupling it does not have. So such an
/// identifier, written as a whole token, is masked before the scanners read the line. Everything
/// else still counts: the same word in prose, in a string, or inside ANY identifier the contract
/// does not export (a crate's own `LocalDecision`) is a hit exactly as before.
///
/// An identifier that IS a needle on its own (a contract `fn mcp`, were there one) is never masked:
/// that would strike the bare instance word everywhere, which is the vocabulary itself.
fn contract_identifiers(
    files: &[(String, String)],
    vocab: &BTreeMap<&'static str, Vec<Needle>>,
) -> BTreeSet<String> {
    let needles: BTreeSet<String> = vocab
        .values()
        .flatten()
        .map(|n| n.word.replace('-', "_"))
        .collect();
    let mut out = BTreeSet::new();
    let prefix = format!("crates/{CONTRACT_PACKAGE}/src/");
    for (rel, text) in files {
        if !rel.starts_with(&prefix) || !rel.ends_with(".rs") {
            continue;
        }
        for line in text.lines() {
            let Some(rest) = line.trim_start().strip_prefix("pub ") else {
                continue;
            };
            let mut words = rest
                .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                .filter(|w| !w.is_empty());
            let mut declared = None;
            while let Some(w) = words.next() {
                match w {
                    "unsafe" | "async" | "extern" | "C" => continue,
                    "const" | "struct" | "enum" | "trait" | "type" | "union" | "fn" | "static" => {
                        match words.next() {
                            Some("fn") => declared = words.next(),
                            other => declared = other,
                        }
                        break;
                    }
                    _ => break,
                }
            }
            if let Some(id) = declared {
                if !needles.contains(&id.to_lowercase()) {
                    out.insert(id.to_string());
                }
            }
        }
    }
    out
}

/// THE INSTANCE NAMES THAT ARE ALSO ORDINARY ENGLISH WORDS (ARCHITECT ruling 2026-09-27, the owner
/// law of that day: the gate measures INSTANCE knowledge, not English). `streams` is the streaming
/// plane's section-key alias and `decision` the decisions plane's bare id, and both are words a
/// sentence uses with no plane in mind ("the reply buffer, which streams"; "the hook's decision").
/// In PROSE — a `//` comment of a `.rs` file, or a line of a `.md` — such a word standing on its own
/// is masked before the scanners read the line. It still counts everywhere else: in code (an
/// identifier, a string literal), in section-key position (`streams:`, followed by a colon), when
/// quoted as a name (`` `decision` ``), and when joined into a longer name (`plane-decisions`,
/// `decision_plane`). Instance ids that are not English words (`llm`, `mcp`, `a2a`, `voice`, every
/// registry alias) are never masked.
pub(super) const ENGLISH_INSTANCE_WORDS: &[&str] = &["streams", "decision", "decisions"];

/// `text` with every PROSE occurrence of an [`ENGLISH_INSTANCE_WORDS`] word masked (same-length word
/// filler, so lines and columns hold). Prose is the part of a `.rs` line after a `//` that is not
/// inside a string literal, and the whole of a `.md` line; nothing else is touched.
fn mask_english_prose<'a>(rel: &str, text: &'a str) -> std::borrow::Cow<'a, str> {
    let rs = rel.ends_with(".rs");
    if !rs && !rel.ends_with(".md") {
        return std::borrow::Cow::Borrowed(text);
    }
    let lower = text.to_ascii_lowercase();
    if !ENGLISH_INSTANCE_WORDS.iter().any(|w| lower.contains(w)) {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let start = if rs {
            match comment_start(line) {
                Some(at) => at,
                None => {
                    out.push_str(line);
                    continue;
                }
            }
        } else {
            0
        };
        let (code, prose) = line.split_at(start);
        out.push_str(code);
        out.push_str(&mask_prose_words(prose));
    }
    std::borrow::Cow::Owned(out)
}

/// The byte offset of a `//` comment on `line` that is not inside a `"…"` string literal.
fn comment_start(line: &str) -> Option<usize> {
    let b = line.as_bytes();
    let mut in_str = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' if in_str => i += 1,
            b'"' => in_str = !in_str,
            b'/' if !in_str && b.get(i + 1) == Some(&b'/') => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// `prose` with each standalone [`ENGLISH_INSTANCE_WORDS`] word masked. Standalone: not joined to
/// a neighbouring name by `-`, `_`, `.`, `::` or a letter, not quoted in backticks, and not followed
/// by `:` (section-key position).
fn mask_prose_words(prose: &str) -> String {
    let b = prose.as_bytes();
    let mut out = prose.as_bytes().to_vec();
    // A `.` joins only between name characters (`decision.rs`, `cfg.streams`); a sentence's full
    // stop is followed by a space or the end of the line and joins nothing.
    let joins = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'`');
    let name_char = |c: Option<&u8>| c.is_some_and(|c| c.is_ascii_alphanumeric());
    let mut i = 0;
    while i < b.len() {
        let joined_before = i > 0
            && (joins(b[i - 1])
                || (b[i - 1] == b'.' && name_char(i.checked_sub(2).and_then(|k| b.get(k)))));
        if !b[i].is_ascii_alphabetic() || joined_before {
            i += 1;
            continue;
        }
        let mut j = i;
        while j < b.len() && b[j].is_ascii_alphabetic() {
            j += 1;
        }
        let word = prose[i..j].to_ascii_lowercase();
        let after = b.get(j).copied();
        let joined_after =
            after.is_some_and(|c| joins(c) || c == b':' || (c == b'.' && name_char(b.get(j + 1))));
        if ENGLISH_INSTANCE_WORDS.contains(&word.as_str()) && !joined_after {
            out[i..j].fill(b'x');
        }
        i = j;
    }
    String::from_utf8(out).expect("ascii-for-ascii")
}

/// THE INSTANCE IDS THAT ARE ALSO SOMEBODY ELSE'S NAME: the sibling of [`ENGLISH_INSTANCE_WORDS`]
/// for crate names and abbreviations. `http` is the
/// transport's bare id and also the `http` crate (`http::Method`, `axum::http::StatusCode`, the
/// `http-body` dependency), a URL scheme (`http://`), and the protocol's name in a sentence. `ws` is
/// the transport's bare id and also whitespace (`skip_ws`), a local's name (`let ws = …`) and a URL
/// scheme. Counted as instance knowledge, those spellings made `busbar-kernel × transport` 1 811,
/// of which 1 539 were these two words.
///
/// So a bare occurrence of one of these words counts ONLY where it is a real reference to the
/// instance:
///
/// * joined to its kind marker (`transport-ws`, `busbar_transport_http`, `TransportWs`), which is
///   the crate's own name and still counts everywhere, prose included;
/// * in code, as a whole token that is a Rust PATH SEGMENT (`crate::ingress::ws`, `mod ws`,
///   `Transport::Http`) — but never a path rooted at the external crate of the same name
///   (`http::Method`) or at a third-party library ([`EXTERNAL_PATH_HEADS`], `axum::http`);
/// * as a string literal that IS the id (`"ws"`, `"http"`: a registry or config key);
/// * in a `Cargo.toml`, as a key or header outside a dependency table (a feature named `ws`), or a
///   dependency key that is not the external crate of the same name;
/// * in any other text file (`.json`, `.yaml`, fixtures), as a whole token (`transport: ws`);
/// * in the file's own path, as a whole directory or file stem (`ws.rs`, `http/`).
///
/// Everything else is masked before the scanners read the line: prose (a `.rs` `//` comment, a
/// `.toml` `#` comment, a `.md` line), a URL scheme (`http://`, `ws://`), a segment of a longer
/// identifier (`skip_ws`, `split_ws_url`, `http_status`, `WsArrival`), a local variable, and a
/// path of the external crate. Instance ids that collide with nothing (`llm`, `mcp`, `a2a`, `tcp`,
/// `sse`, …) are never touched here.
pub(super) const COLLIDING_INSTANCE_WORDS: &[(&str, bool)] = &[
    // (the word, whether it is ALSO an external crate's name, so `word::…` is that crate's path)
    ("http", true),
    ("ws", false),
];

/// Third-party library path heads: a colliding word inside a path rooted at one of these is that
/// library's module (`axum::http`, `hyper::http`), not the instance.
const EXTERNAL_PATH_HEADS: &[&str] = &[
    "axum",
    "hyper",
    "hyper_util",
    "tonic",
    "tungstenite",
    "tokio_tungstenite",
    "reqwest",
    "h2",
    "http_body",
    "http_body_util",
    "tower_http",
];

/// The Cargo tables whose keys are dependency names.
fn is_dependency_table(header: &str) -> bool {
    let h = header
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();
    h.ends_with("dependencies") || h.contains("dependencies.")
}

/// Whether the occurrence of a word at `b[i..j]` is a SEGMENT the scanners can see: its start and
/// end are each a non-alphanumeric, a line edge, or a case transition either scanner splits at.
fn segment_bounded(b: &[u8], i: usize, j: usize) -> bool {
    let lo = |k: usize| b.get(k).is_some_and(|c| c.is_ascii_lowercase());
    let up = |k: usize| b.get(k).is_some_and(|c| c.is_ascii_uppercase());
    let alnum = |k: usize| b.get(k).is_some_and(|c| c.is_ascii_alphanumeric());
    let start =
        i == 0 || !alnum(i - 1) || (lo(i - 1) && up(i)) || (up(i - 1) && up(i) && lo(i + 1));
    let end =
        j >= b.len() || !alnum(j) || (lo(j - 1) && up(j)) || (up(j - 1) && up(j) && lo(j + 1));
    start && end
}

/// Whether the word at `b[i..]` is JOINED to its kind marker: the bytes before it, after a run of
/// `-`, `_` or `:` (or nothing, at a case joint), spell `transport`.
fn joined_to_marker(b: &[u8], i: usize) -> bool {
    let mut k = i;
    while k > 0 && matches!(b[k - 1], b'-' | b'_' | b':') {
        k -= 1;
    }
    const MARKER: &[u8] = b"transport";
    k >= MARKER.len() && b[k - MARKER.len()..k].eq_ignore_ascii_case(MARKER)
}

/// The head of the Rust path the token at `b[i..j]` sits in. On a `use` line it is the first
/// segment after `use` (so `use axum::{http, …}` is rooted at `axum`); elsewhere it is found by
/// walking back over `ident::` links.
fn path_head(line: &[u8], i: usize) -> String {
    let text = String::from_utf8_lossy(line);
    let trimmed = text.trim_start();
    let after_vis = trimmed
        .strip_prefix("pub(crate) ")
        .or_else(|| trimmed.strip_prefix("pub(super) "))
        .or_else(|| trimmed.strip_prefix("pub "))
        .unwrap_or(trimmed);
    if let Some(rest) = after_vis.strip_prefix("use ") {
        return rest
            .trim_start_matches("::")
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .next()
            .unwrap_or("")
            .to_string();
    }
    let is_id = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut start = i;
    loop {
        if start >= 2 && &line[start - 2..start] == b"::" {
            let mut k = start - 2;
            while k > 0 && is_id(line[k - 1]) {
                k -= 1;
            }
            if k == start - 2 {
                break;
            }
            start = k;
        } else {
            break;
        }
    }
    let mut end = start;
    while end < line.len() && is_id(line[end]) {
        end += 1;
    }
    String::from_utf8_lossy(&line[start..end]).into_owned()
}

/// `text` with every NON-REFERENCE occurrence of a [`COLLIDING_INSTANCE_WORDS`] word masked (same
/// length `x` filler, so lines and columns hold). See that constant for what is kept.
fn mask_colliding_words<'a>(rel: &str, text: &'a str) -> std::borrow::Cow<'a, str> {
    let lower = text.to_ascii_lowercase();
    if !COLLIDING_INSTANCE_WORDS
        .iter()
        .any(|(w, _)| lower.contains(w))
    {
        return std::borrow::Cow::Borrowed(text);
    }
    let rs = rel.ends_with(".rs");
    let toml = rel.ends_with(".toml");
    let md = rel.ends_with(".md");
    let mut out = String::with_capacity(text.len());
    let mut table = String::new();
    for line in text.split_inclusive('\n') {
        let b = line.as_bytes();
        let t = line.trim_start();
        if toml && t.starts_with('[') {
            table = t.trim_end().to_string();
        }
        // WHERE PROSE STARTS on this line: all of a `.md`, a `.rs` `//` comment, a `.toml` `#`.
        let prose_at = if md {
            Some(0)
        } else if rs {
            comment_start(line)
        } else if toml {
            toml_comment_start(line)
        } else {
            None
        };
        let mut buf = b.to_vec();
        let low = line.to_ascii_lowercase();
        for (word, external) in COLLIDING_INSTANCE_WORDS {
            let mut from = 0;
            while let Some(off) = low[from..].find(word) {
                let i = from + off;
                let j = i + word.len();
                from = j;
                if !segment_bounded(b, i, j) {
                    continue;
                }
                if !keeps_reference(b, i, j, prose_at, rs, toml, &table, word, *external) {
                    buf[i..j].fill(b'x');
                }
            }
        }
        out.push_str(&String::from_utf8(buf).expect("ascii-for-ascii"));
    }
    std::borrow::Cow::Owned(out)
}

/// Whether the colliding word at `b[i..j]` is a real reference to the instance (see
/// [`COLLIDING_INSTANCE_WORDS`]).
#[allow(clippy::too_many_arguments)]
fn keeps_reference(
    b: &[u8],
    i: usize,
    j: usize,
    prose_at: Option<usize>,
    rs: bool,
    toml: bool,
    table: &str,
    word: &str,
    external: bool,
) -> bool {
    if joined_to_marker(b, i) {
        return true;
    }
    if prose_at.is_some_and(|p| i >= p) {
        return false;
    }
    // A URL scheme names a protocol on the wire, not the plugin.
    if b[j..].starts_with(b"://") || b[j..].starts_with(b"s://") {
        return false;
    }
    let tok =
        |c: Option<&u8>| c.is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-');
    let whole = !tok(i.checked_sub(1).and_then(|k| b.get(k))) && !tok(b.get(j));
    if !whole {
        return false;
    }
    let quoted = i > 0 && b[i - 1] == b'"' && b.get(j) == Some(&b'"');
    if quoted {
        return true;
    }
    if rs {
        let before = String::from_utf8_lossy(&b[..i]);
        if before.trim_end().ends_with("mod") {
            return true;
        }
        let path_after = b[j..].starts_with(b"::");
        let path_before = i >= 2 && &b[i - 2..i] == b"::";
        let in_use_group = {
            let t = String::from_utf8_lossy(b);
            let t = t.trim_start();
            (t.starts_with("use ") || t.starts_with("pub use ") || t.starts_with("pub(crate) use "))
                && matches!(b.get(i.wrapping_sub(1)), Some(b'{' | b' ' | b','))
        };
        if !(path_after || path_before || in_use_group) {
            return false;
        }
        let head = path_head(b, i);
        if external && head.eq_ignore_ascii_case(word) {
            return false;
        }
        return !EXTERNAL_PATH_HEADS.contains(&head.as_str());
    }
    if toml {
        let t = String::from_utf8_lossy(b);
        let t = t.trim_start();
        if t.starts_with('[') {
            // `[dependencies.http]` is the external crate's table; any other header keeps it.
            return !(external && is_dependency_table(t));
        }
        let is_key = t.len() == b.len() - i || String::from_utf8_lossy(&b[..i]).trim().is_empty();
        if is_key {
            return !(external && is_dependency_table(table));
        }
        return false;
    }
    true
}

/// The byte offset of a `.toml` `#` comment on `line` that is not inside a `"…"` string.
fn toml_comment_start(line: &str) -> Option<usize> {
    let b = line.as_bytes();
    let mut in_str = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' if in_str => i += 1,
            b'"' => in_str = !in_str,
            b'#' if !in_str => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// A file's own path (the scanners' line 0) with every colliding word that is not a whole
/// directory or file stem masked: `egress/duplex_ws.rs` names no instance, `ingress/ws.rs` does.
fn mask_colliding_path(tail: &str) -> std::borrow::Cow<'_, str> {
    let lower = tail.to_ascii_lowercase();
    if !COLLIDING_INSTANCE_WORDS
        .iter()
        .any(|(w, _)| lower.contains(w))
    {
        return std::borrow::Cow::Borrowed(tail);
    }
    let b = tail.as_bytes();
    let mut buf = b.to_vec();
    for (word, _) in COLLIDING_INSTANCE_WORDS {
        let mut from = 0;
        while let Some(off) = lower[from..].find(word) {
            let i = from + off;
            let j = i + word.len();
            from = j;
            if !segment_bounded(b, i, j) || joined_to_marker(b, i) {
                continue;
            }
            let lead = i == 0 || b[i - 1] == b'/';
            let trail = j == b.len() || b[j] == b'/' || b[j] == b'.';
            if !(lead && trail) {
                buf[i..j].fill(b'x');
            }
        }
    }
    std::borrow::Cow::Owned(String::from_utf8(buf).expect("ascii-for-ascii"))
}

/// `text` with every whole-token occurrence of an identifier in `idents` replaced by a run of `x` of
/// the same length, so lines and columns are unchanged. The filler is a WORD, not separators: a run
/// of `_` would let a multi-part needle's joint (which matches any run of non-alphanumerics) reach
/// across the masked token and join the words on either side of it into a hit neither made.
fn mask_identifiers<'a>(text: &'a str, idents: &BTreeSet<String>) -> std::borrow::Cow<'a, str> {
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let bytes = text.as_bytes();
    let mut out: Option<Vec<u8>> = None;
    let mut i = 0;
    while i < bytes.len() {
        if !is_ident(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_ident(bytes[i]) {
            i += 1;
        }
        if idents.contains(&text[start..i]) {
            let buf = out.get_or_insert_with(|| bytes.to_vec());
            buf[start..i].fill(b'x');
        }
    }
    match out {
        // Only ASCII identifier bytes were replaced by ASCII, so the buffer is still UTF-8.
        Some(buf) => std::borrow::Cow::Owned(String::from_utf8(buf).expect("ascii-for-ascii")),
        None => std::borrow::Cow::Borrowed(text),
    }
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
    one_needle_per_span(plan, &mut out);
    let out: std::sync::Arc<Vec<Hit>> =
        std::sync::Arc::new(out.into_iter().map(|(_, _, h)| h).collect());
    assembled
        .lock()
        .expect("the memo mutex is never poisoned")
        .insert((key, plan.key), std::sync::Arc::clone(&out));
    out
}

/// ONE WRITTEN NAME, ONE HIT: THE LONGEST NEEDLE WINS.
///
/// Needles nest. `busbar_kernel_ledger::` is the package name `busbar-kernel-ledger` and, inside
/// it, the kind-qualified id `kernel-ledger`. `busbar_plane_llm` holds `plane-llm` and `llm`. Each
/// needle is scanned alone, so one written name scored once per needle it contains: a crate naming
/// `busbar_plane_llm` once was charged three plane hits.
///
/// So on each line a needle's count is what is LEFT after every longer needle containing it has
/// taken its occurrences: `residual(A) = raw(A) - Σ residual(M) × occurrences(A in M)`, over the
/// needles `M` on the same line whose segments contain `A`'s as a contiguous run, taken longest
/// first. The subtraction runs per reading (segments, windows, decoded), so a disagreement between
/// the scanners survives it. A needle nothing longer contains is untouched, and a hit whose
/// residual is zero in every reading is dropped. `llm` written on its own beside `busbar_plane_llm`
/// still counts once.
fn one_needle_per_span(plan: &Plan, out: &mut Vec<(usize, usize, Hit)>) {
    fn occurrences(inner: &[String], outer: &[String]) -> usize {
        if inner.len() >= outer.len() {
            return 0;
        }
        outer.windows(inner.len()).filter(|w| *w == inner).count()
    }
    let mut k = 0;
    while k < out.len() {
        let line = out[k].0;
        let mut e = k;
        while e < out.len() && out[e].0 == line {
            e += 1;
        }
        if e - k > 1 {
            let mut order: Vec<usize> = (k..e).collect();
            order.sort_by_key(|&x| std::cmp::Reverse(plan.needles[out[x].1].parts.len()));
            for pos in 0..order.len() {
                let a = order[pos];
                let inner = &plan.needles[out[a].1].parts;
                let (mut seg, mut win, mut dec) = (0usize, 0usize, 0usize);
                for &m in &order[..pos] {
                    let n = occurrences(inner, &plan.needles[out[m].1].parts);
                    if n > 0 {
                        seg += out[m].2.by_segments * n;
                        win += out[m].2.by_windows * n;
                        dec += out[m].2.by_decoded * n;
                    }
                }
                let h = &mut out[a].2;
                h.by_segments = h.by_segments.saturating_sub(seg);
                h.by_windows = h.by_windows.saturating_sub(win);
                h.by_decoded = h.by_decoded.saturating_sub(dec);
            }
        }
        k = e;
    }
    out.retain(|(_, _, h)| h.by_segments + h.by_windows + h.by_decoded > 0);
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
    let tail = mask_colliding_path(tail);
    let tail = tail.as_ref();
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
/// The crate × kind EDGES that exist, per cell; the SENTENCES, per kind → kind class. The prose
/// belongs to the class because that is what a reader is reading — the same split
/// `[[transitional]]` already makes. A cell row carries no number: presence, not size (owner
/// 2026-10-02). Every field is required and validated at LOAD by [`super::take_row`], so a row that
/// reaches here is a row a human could read.
#[derive(Default)]
struct Ledger {
    cells: BTreeSet<(String, String)>,
    /// class -> `cite`/`why`/`drain`, kept rather than discarded so `--report` can hand a reader
    /// the citation and the deleting line beside the class.
    edges: BTreeMap<(String, String), (String, String, String)>,
}

/// TWO ROWS FOR ONE CELL IS TWO ANSWERS. The maps below would keep the last, which is a row chosen
/// by file order — so a repeated key is reported instead, by name.
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
            .map(|c| (c.krate.clone(), c.kind.clone()))
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

/// THE ROWS THIS BRANCH MINTED — a `[[cell]]`, `[[edge]]` or `[[instance]]` that is in no
/// merge-base copy of the ledger at all.
///
/// The rows are presence only (size is not a CI check, owner 2026-10-02), so a row is the whole of
/// what legitimises a cross-kind edge — and THIS is the rule that refuses a branch legitimising a
/// NEW edge by writing its row in the same commit as the coupling. A red team walked straight
/// through the gap before it existed: a `pub struct WSFrame;` planted in a store plugin went red
/// twice (`unlisted-cell` and `unlisted-edge`), and hand-written rows made the whole gate green.
///
/// A new row is a new edge wearing the clothes of a first measurement. It is refused here: the edge
/// lands in a commit that says why the tree now needs it, and a reviewer reads that sentence.
fn minted_rows(cx: &Ctx) -> Vec<String> {
    let base = match super::base::read(cx) {
        Ok(b) => b,
        Err(why) => {
            return vec![format!(
                "no-base\t{LEDGER}\tno merge-base could be read, so no row could be shown to \
                 pre-date this branch ({why}). A rule that cannot read its own history reports \
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
            "an allowance for one crate naming one kind",
        ),
        (
            "edge",
            &["from", "to"][..],
            "an allowance for one kind naming another",
        ),
        (
            instances::TABLE,
            &["crate", "kind"][..],
            "an allowance for one neutral crate naming one plugin kind's instances as a value",
        ),
    ] {
        let was = super::base::row_keys(&base.registry, table, ids);
        // A WHOLE COLUMN THAT DID NOT EXIST IS THE RULE ARRIVING, NOT A NEW EDGE.
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
                 is a NEW cross-kind edge legitimised in the same branch that grew it. Delete the \
                 coupling instead, or land the row in a commit whose message says why the tree now \
                 needs it.",
                &base.commit[..8.min(base.commit.len())]
            ));
        }
    }
    out
}

/// THE LAW 0/1 ARMED CLASS — evaluated UNCONDITIONALLY of the `[[cell]]` ledger: a NEUTRAL
/// crate's ceiling against [`instance_vocab_kinds`] is 0, and no ledger row can raise it.
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
    let ivocab = instances::vocabulary(crates, &files, &reg.core_names);
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

    // PRESENCE, NOT SIZE (owner 2026-10-02: size is not a CI check). A cell above zero is a
    // crate-level cross-kind EDGE, and the only question asked of it is whether a row says it may
    // exist. No finding here carries a hit count: a count in the text would make every extra hit
    // inside an already-listed (or already-standing) cell read as a new or larger finding, which is
    // the line counter the ruling deleted. The numbers stay in `--report`.
    for ((krate, kind), cell) in &matrix {
        if cell.count == 0 {
            continue;
        }
        let src = kind_of.get(krate.as_str()).copied().unwrap_or("?");
        let edge = (src.to_string(), (*kind).to_string());
        if !listed.edges.contains_key(&edge) {
            offenders.push(format!(
                "unlisted-edge\t{src} -> {kind}\t{krate} names {kind} vocabulary and there is no \
                 `[[edge]] from = \"{src}\", to = \"{kind}\"` in {LEDGER}. An edge nobody wrote \
                 down is an edge nobody reviewed: add the class with its ARCHITECTURE citation and \
                 the line that deletes it, or delete the hits."
            ));
        }
        if !listed.cells.contains(&(krate.clone(), (*kind).to_string())) {
            offenders.push(format!(
                "unlisted-cell\t{krate} \u{d7} {kind}\tno `[[cell]] crate = \"{krate}\", kind = \
                 \"{kind}\"` in {LEDGER}: this is a NEW crate-level cross-kind edge. Delete the \
                 hits (`--report` lists them, file:line), or add the row in a commit that says why \
                 the tree now needs the edge."
            ));
        }
    }

    // A ROW WHOSE CELL IS GONE IS A DEAD ALLOWANCE. The exemption cannot outlive the coupling.
    for (krate, kind) in &listed.cells {
        // A PLUGIN CRATE'S CONTRACT CELL IS NOT GONE, IT IS THE RULE: the column is not measured
        // for a plugin kind (see [`measure`]), so the row is an exception to a rule that excepts
        // nothing, and it says so rather than reading as a coupling that drained.
        let src = kind_of.get(krate.as_str()).copied().unwrap_or("?");
        if super::names_contract_by_design(src, kind) {
            offenders.push(format!(
                "rule-granted-cell\t{krate} \u{d7} {kind}\t#40(a) (a plugin kind) and #83/#83a (a \
                 core tier) grant the contract's vocabulary as the RULE, so a {src} crate's \
                 contract column is not measured and a `[[cell]]` row for it is an exception to a \
                 rule that excepts nothing. Strike it."
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
    for (src, dst) in listed.edges.keys() {
        if super::names_contract_by_design(src, dst) {
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
    // Every other cell in this row is held to a `[[cell]]` row, because every other hit is a word
    // somebody wrote on purpose and the question is whether the edge it makes was reviewed. This
    // one is different in kind: a token whose ASCII fold is a plane's name and whose raw bytes are
    // not is a token that reads as that name to the reviewer and to nothing else. There is no row
    // that allows it — the ceiling is zero, exactly, and it is measured at zero on this tree today.
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
    // gate that lets the list reach 0 and STAY there without bricking the push gate on neutral
    // crates still draining. A crate not yet listed is still held to its `[[cell]]` row above
    // (a new cell with no row is `unlisted-cell`); it is only exempt from being blocked TWICE.
    offenders.extend(law0_offenders(
        &matrix,
        crates,
        Some(LAW0_ENFORCED_NEUTRAL_CRATES),
    ));

    // THE HIT TOTALS ARE THE PASS DETAIL'S AND `--report`'s, NEVER THE FAIL DETAIL'S. The release
    // turnstile reads a standing-red row's figure as the detail's LEADING integer, and a FAIL
    // detail that opened with the hit total turned every extra hit in an already-listed cell into
    // a higher figure and a DENY. A red row's figure is the number of findings it carries.
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
            format!(
                "{} finding(s) over {} cell(s), {scanned} file(s) scanned: {}",
                offenders.len(),
                matrix.len(),
                offenders.join(" | ")
            ),
        );
    }

    Row::pass(
        ROW_MATRIX,
        "every crate's naming of every other kind is a listed edge",
        format!("every non-zero cell has its {LEDGER} row; {headline}"),
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
/// planes' crates, nodes, units and sections by hand. Read at run time and planted into the fixture
/// crate ([`fixture_files`]); stored as `.txt` so no crate, compiler or source scanner reads it
/// where it lives.
const HAND_WIRED_ROOT_FIXTURE: &str = "xtask/fixtures/kind-isolation-root/units_hand_wired.txt";

/// A synthetic `[[edge]]` row whose class no crate has, appended to the ledger by the dead-edge case.
/// Stored under `xtask/fixtures/`, which this gate treats as off-tree.
const DEAD_EDGE_FIXTURE: &str = "xtask/fixtures/kind-isolation-root/dead_edge_row.txt";

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

/// The ledger with one row rewritten, so a case can double a row or knock a whole class out.
///
/// THE SENTENCE THAT USED TO BE HERE WAS THE OPPOSITE OF TRUE. It read: *"a fixture that pins a
/// number goes LOUDLY red when the tree is re-measured, which is what a fixture is for."* It did
/// not. This was a bare `replacen`, and `replacen` over a needle that is not in the string returns
/// the string: a fixture pinning `count = "1798"` against a cell the ratchet had re-pinned to
/// `1942` wrote the ledger back BYTE-FOR-BYTE, the gate read the unplanted tree, and the case
/// scored whatever that tree scores — quietly, for as long as it took anyone to check. Three cases
/// in this file were doing it. A needle that is no longer in the ledger is an UNPLANTABLE CASE
/// now, and [`cell_anchor`] reads the row off the file rather than restating it.
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

/// THE FIXTURE CRATE ([`instances::FIXTURE_CRATE`]) with `files` under its `src/`, and NO ledger
/// row: a neutral kernel-kind crate that exists only in the overlay, so a case measures a cell no
/// live crate owns and no fold can take away.
///
/// THE SCANNER PROPERTIES ARE PROVEN THROUGH PRESENCE. The cells carry no count (size is not a CI
/// check, owner 2026-10-02), so "this spelling does not count" is the fixture holding ONLY that
/// spelling and the row GREEN — the cell is zero, there is no edge — and "this spelling counts" is
/// the same plant plus the spelling and the row RED, `unlisted-cell` naming `<fixture> × <kind>`.
fn fixture_files(files: &[(&str, &str)]) -> crate::ctx::Overlay {
    let mut ov = instances::fixture_crate();
    for (name, body) in files {
        ov.set(
            format!("{}/src/{name}", instances::FIXTURE_DIR),
            (*body).to_string(),
        );
    }
    ov
}

/// [`fixture_files`] plus a `[[cell]]` row for `fixture × kind` appended to the ledger. `inherited`
/// plants the base's copy of the ledger with the row in it as well, so the row pre-dates the
/// branch and `minted-row` has nothing to say about it; without it the row is one this branch
/// wrote.
fn fixture_cell(
    cx: &Ctx,
    kind: &str,
    files: &[(&str, &str)],
    inherited: bool,
) -> crate::ctx::Overlay {
    let mut ov = fixture_files(files);
    let ledger = format!(
        "{}\n\n[[cell]]\n{}\n",
        cx.read(LEDGER).unwrap_or_default().trim_end(),
        cell_row(instances::FIXTURE_CRATE, kind)
    );
    if inherited {
        if let Some(sha) = super::debt_free::pinned_base(cx) {
            ov.set_command(format!("git-show:{sha}:{LEDGER}"), ledger.clone());
        }
    }
    ov.set(LEDGER, ledger);
    ov
}

/// THE OS SPELLINGS OF `unix` THE FIXTURE PLANTS — its cfg predicate, `std::os::unix`, the standard
/// socket type, the clock and "non-unix" prose — none of which is the carrier ([`os_words`]).
const UNIX_OS_FILE: (&str, &str) = (
    "os.rs",
    "#[cfg(unix)]\n\
     use std::os::unix::fs::PermissionsExt;\n\
     #[cfg(all(unix, not(target_os = \"macos\")))]\n\
     pub fn mode(l: &tokio::net::UnixListener) -> u64 { now_unix_ns() }\n\
     fn now_unix_ns() -> u64 { std::time::UNIX_EPOCH.elapsed().map_or(0, |d| d.as_secs()) }\n\
     // Non-unix builds have no mode bits; Unix seconds since the epoch.\n",
);

/// The subject a fixture cell is named by in its findings: `<fixture> × <kind>`.
fn fixture_subject(kind: &str) -> String {
    format!("{} \u{d7} {kind}", instances::FIXTURE_CRATE)
}

/// [`prove_rows_red`](crate::gates::prove_rows_red) over a one-substitution plant into the real
/// ledger, with the substitution given as the `(anchor, replacement)` the caller worked out.
/// The transport crate the plane-in-a-wire cases plant into, spelled once ([`WIRE_PLANT`]).
macro_rules! wire_plant_name {
    () => {
        "busbar-transport-planted"
    };
}

/// The transport crate the plane-in-a-wire cases plant into. It is planted WITH its manifest: the
/// transports leave this tree for their own repos one by one, and a case aimed at a wire the census
/// no longer holds is refused by [`plant`] before it proves anything.
const WIRE_PLANT: &str = wire_plant_name!();

/// `body` at `tail` under the planted wire [`WIRE_PLANT`], its manifest planted first. A `tail` of
/// `Cargo.toml` is that manifest, with `body` as its package fields.
fn wire_plant(cx: &Ctx, tail: &str, body: &str) -> crate::ctx::Overlay {
    let manifest = format!("crates/{WIRE_PLANT}/Cargo.toml");
    let fields = if tail == "Cargo.toml" { body } else { "" };
    let mut ov = plant(
        cx,
        &manifest,
        &format!("[package]\n{fields}name = \"{WIRE_PLANT}\"\nversion = \"0.0.0\"\n"),
    );
    if tail != "Cargo.toml" {
        ov.set(format!("crates/{WIRE_PLANT}/{tail}"), body.to_string());
    }
    ov
}

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

/// The two lines of one `[[cell]]` row.
pub(super) fn cell_row(krate: &str, kind: &str) -> String {
    format!("crate = \"{krate}\"\nkind = \"{kind}\"")
}

/// THE `[[cell]]` ROW FOR `crate × kind` AS THE LEDGER SPELLS IT TODAY.
///
/// Read off the file rather than restated: a fixture that quotes a row the ledger no longer
/// carries is a plant that stops planting and says nothing when it does. The two lines are only an
/// anchor when the `[[cell]]` header sits directly above them, because `crate`/`kind` is also the
/// shape of an `[[instance]]` row.
pub(super) fn cell_anchor(cx: &Ctx, krate: &str, kind: &str) -> Result<String, String> {
    let text = cx.read(LEDGER)?;
    let row = format!("[[cell]]\n{}", cell_row(krate, kind));
    if !text.contains(&row) {
        return Err(format!(
            "no `[[cell]]` row for {krate} × {kind} in {LEDGER} to plant over"
        ));
    }
    Ok(row)
}

/// That row, and the same row with `extra` (one more `key = "value"` line) written into it.
pub(super) fn cell_subst(
    cx: &Ctx,
    krate: &str,
    kind: &str,
    extra: &str,
) -> Result<(String, String), String> {
    let anchor = cell_anchor(cx, krate, kind)?;
    let planted = format!("{anchor}\n{extra}");
    Ok((anchor, planted))
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
    // below is about the LEDGER, and the ship twin does not read the ledger — planting a row
    // against it would produce the same red it already produces, and "the gate went red"
    // is the answer this battery exists to refuse. So the ship twin gets one case, and it makes a
    // NAMED, NEW deviation: a cell that measures ZERO today and does not after the plant.
    if ship {
        report.push(prove_rows_red(
            cx,
            gate,
            "at the ship ceiling of zero, a plane named inside a transport is a NEW cell",
            &[ROW_MATRIX],
            wire_plant(
                cx,
                "src/leak.rs",
                "//! The llm plane's frames arrive here first.\n",
            ),
            &["ship-ceiling 0", concat!(wire_plant_name!(), " × plane")],
        ));
        instances::selftest(cx, gate, true, report);
        return;
    }

    // THE FIVE INSTANCE AXES (item 118) — every one planted in core, plus the listed/unlisted pair.
    instances::selftest(cx, gate, false, report);

    // THE DIALECT WIRE-KEY SPAN (ARCHITECT ruling 2026-10-02, DF-MAP) is a COUNT property inside a
    // listed cell (`busbar-plane-llm × plane`), which presence cannot observe; it is proven on the
    // cell itself in `tests::a_dialect_wire_key_is_the_providers_word_and_the_same_word_elsewhere_counts`.
    // THE AUTH ABI'S `decision` FIELD IS NOT THE DECISIONS PLANE ([`auth_words`]), and the mask is
    // not a hole: an auth crate reading and naming the continue/stop field is green; the same crate
    // writing the decisions plane's registry key `"decision"` is still a `× plane` cell. The plant
    // files' own paths carry no plane word: a file's path is scanned as its line 0, unmasked.
    let auth = super::census(cx).ok().and_then(|cs| {
        cs.into_iter()
            .filter(|c| c.kind == Some(auth_words::KIND))
            .map(|c| (c.name, c.dir))
            .min()
    });
    match auth {
        Some((name, dir)) => {
            let field = || {
                plant(
                    cx,
                    &format!("{dir}/src/planted_verdict_field.rs"),
                    "pub fn names_a_decision(out: &Out) -> u32 {\n    let decision = \
                     out.decision;\n    decision\n}\n",
                )
            };
            report.push(prove_rows_green(
                cx,
                gate,
                "an auth crate naming its own ABI's `decision` field is no decisions-plane cell",
                &[ROW_MATRIX],
                field(),
            ));
            let mut plane = field();
            plane.set(
                format!("{dir}/src/planted_plane_key.rs"),
                "pub const KEY: &str = \"decision\";\n".to_string(),
            );
            report.push(prove_rows_red(
                cx,
                gate,
                "an auth crate writing the decisions plane's key is still a `× plane` cell",
                &[ROW_MATRIX],
                plane,
                &[&format!("{name} \u{d7} plane")],
            ));
        }
        None => report.push(crate::gates::CasePlan::from(super::unplantable(
            "an auth-kind crate to plant the `decision` field in",
            &[ROW_MATRIX],
            &["decision"],
            "the census holds no auth-kind crate".to_string(),
        ))),
    }

    const LOADER_PACKAGE: &str = "busbar-plugin-loader";
    // …and on the LOADER'S side of the auth ABI: a plugin-tooling file whose path names `auth`
    // reading the field and the contract's `Decision` type is green; the same file's crate writing
    // the decisions plane's key in an auth file is still a `× plane` cell.
    let loader = super::census(cx).ok().and_then(|cs| {
        cs.into_iter()
            .find(|c| c.kind == Some(auth_words::LOADER_KIND) && c.name == LOADER_PACKAGE)
            .map(|c| (c.name, c.dir))
    });
    match loader {
        Some((name, dir)) => {
            let field = || {
                plant(
                    cx,
                    &format!("{dir}/src/planted_auth_verdict.rs"),
                    "use busbar_contract::auth_calls::Decision;\n\
                     pub fn read(out: &Out) -> Decision {\n    let decision = out.decision;\n    \
                     if decision == 0 { Decision::Continue } else { Decision::Stop }\n}\n",
                )
            };
            report.push(prove_rows_green(
                cx,
                gate,
                "the loader's auth file naming the auth ABI's `decision` and `Decision` is no \
                 decisions-plane cell",
                &[ROW_MATRIX],
                field(),
            ));
            let mut plane = field();
            plane.set(
                format!("{dir}/src/planted_auth_key.rs"),
                "pub const KEY: &str = \"decision\";\n".to_string(),
            );
            report.push(prove_rows_red(
                cx,
                gate,
                "the loader's auth file writing the `decision` key is still a `× plane` cell",
                &[ROW_MATRIX],
                plane,
                &[&format!("{name} \u{d7} plane")],
            ));
        }
        None => report.push(crate::gates::CasePlan::from(super::unplantable(
            "the loader crate to plant its auth `decision` in",
            &[ROW_MATRIX],
            &["decision"],
            format!("the census holds no plugin-tooling `{LOADER_PACKAGE}`"),
        ))),
    }

    // THE DIALECT WIRE-KEY SPAN (ARCHITECT ruling 2026-10-02, DF-MAP): a quoted map key that IS a
    // path of the file's wire lock is the provider's word; the same word anywhere else still counts.
    // Every arm runs on the plane crate's row re-pinned to its measurement, so the plant alone moves it.
    let dialect_case = |line: &'static str| {
        let cx = cx.clone();
        move || {
            let file = "crates/busbar-plane-llm/dialects/openai_responses.toml";
            let body = cx.read(file).unwrap_or_default();
            row_at_measurement(&cx, "busbar-plane-llm", "plane").layered(&plant(
                &cx,
                file,
                &format!("{body}\n{line}\n"),
            ))
        }
    };
    let llm_raised = ["ratchet", "busbar-plane-llm × plane", "RAISED"];
    report.push(prove_rows_green(
        cx,
        gate,
        "a dialect map key that is a wire-lock path (`input[].type=mcp_call.arguments`) is the \
         provider's word, not a plane coupling",
        &[ROW_MATRIX],
        dialect_case(
            "[unmapped.stream]\n\"input[].type=mcp_call.arguments\" = { no-equivalent = \"x\" }",
        ),
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "the same plane word in a dialect map VALUE still counts",
        &[ROW_MATRIX],
        dialect_case("[unmapped.stream]\n\"input[].type=function_call.arguments\" = { no-equivalent = \"an mcp call\" }"),
        &llm_raised,
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "the same plane word in a dialect map comment still counts",
        &[ROW_MATRIX],
        dialect_case("# the mcp tool"),
        &llm_raised,
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "a dialect map key the wire lock does not have still counts",
        &[ROW_MATRIX],
        dialect_case(
            "[unmapped.stream]\n\"tools[].type=mcp.no_such_member\" = { no-equivalent = \"x\" }",
        ),
        &llm_raised,
    ));

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

    // A ROW THIS BRANCH MINTED IS A NEW EDGE LEGITIMISED IN THE BRANCH THAT GREW IT, and with the
    // counts gone it is the ONLY thing standing between a branch and a new cross-kind edge it wrote
    // its own row for. A red team walked straight through the gap before this rule existed —
    // `pub struct WSFrame;` planted in a store plugin went red twice, and hand-written rows (a
    // `[[cell]]` and an `[[edge]]` the author composed themselves) made the whole gate green.
    //
    // The plant is the fixture crate naming one transport, and a `[[cell]]` row for that cell:
    // nothing about the row is wrong except that it is new, so the refusal the case asserts is the
    // one it is about.
    report.push(prove_rows_red(
        cx,
        gate,
        "a `[[cell]]` row this branch minted is a new edge, not a first measurement",
        &[ROW_MATRIX],
        fixture_cell(
            cx,
            "transport",
            &[("wire.rs", "pub const WIRE: &str = \"tcp\";\n")],
            false,
        ),
        &[
            "minted-row",
            &format!("{} \u{d7} transport", instances::FIXTURE_CRATE),
            "this branch MINTED it",
        ],
    ));
    // …and the SAME row, inherited from the base, is GREEN: the row is what makes the edge
    // reviewed, and a listed cell is green whatever its size.
    report.push(prove_rows_green(
        cx,
        gate,
        "the same `[[cell]]` row inherited from the base is a listed edge, and green",
        &[ROW_MATRIX],
        fixture_cell(
            cx,
            "transport",
            &[("wire.rs", "pub const WIRE: &str = \"tcp\";\n")],
            true,
        ),
    ));

    // THE INCIDENT, PLANTED — and its green twin, which is the same crate with the file absent.
    //
    // `keep-streams-3` `dd96a04f3` landed a plane-named accept loop in the composition root, and
    // CI was green because nothing measured the root. The root's `busbar × plane` cell is a listed
    // edge today, and more plane names inside it are not a CI finding any more (size is not a CI
    // check, owner 2026-10-02) — so the case proves the SCANNER, through presence: the incident's
    // own bytes, planted into the fixture crate whose plane cell has no row, make that cell a NEW
    // edge (RED), and the same crate without them is GREEN. The plane is named in the path, the
    // `cfg(feature)`, the module prose and the import; the case asserts the scan sees it.
    report.push(prove_rows_red(
        cx,
        gate,
        "the accept loop that named its plane (`root/voice_serve.rs`, keep-streams-3 dd96a04f3)",
        &[ROW_MATRIX],
        fixture_files(&[(
            "voice_serve.rs",
            the_accept_loop_that_named_its_plane().as_str(),
        )]),
        &["unlisted-cell", &fixture_subject("plane")],
    ));
    report.push(prove_rows_green(
        cx,
        gate,
        "the same crate with that accept loop absent",
        &[ROW_MATRIX],
        fixture_files(&[]),
    ));

    // THE ROOT THAT HAND-WIRED FOUR PLANES. The module is a fixture this battery owns
    // ([`HAND_WIRED_ROOT_FIXTURE`]), planted into the fixture crate, whose plane cell has no row:
    // a hand-wired module is a plane edge a registry-driven crate would not have.
    let name = "the root that hand-wired four planes is a plane edge where none is listed";
    let subject = fixture_subject("plane");
    let naming = ["unlisted-cell", subject.as_str()];
    match cx.read(HAND_WIRED_ROOT_FIXTURE) {
        Ok(body) => report.push(prove_rows_red(
            cx,
            gate,
            name,
            &[ROW_MATRIX],
            fixture_files(&[("units_hand_wired.rs", body.as_str())]),
            &naming,
        )),
        Err(e) => report.push(super::unplantable(
            name,
            &[ROW_MATRIX],
            &naming,
            format!("{HAND_WIRED_ROOT_FIXTURE}: {e}"),
        )),
    }

    // A PLANE NAMED INSIDE A TRANSPORT — the wire learning what it carries.
    report.push(prove_rows_red(
        cx,
        gate,
        "a plane named inside a transport (the planted wire says `llm`)",
        &[ROW_MATRIX],
        wire_plant(
            cx,
            "src/leak.rs",
            "//! The llm plane's frames arrive here first.\n",
        ),
        &[WIRE_PLANT, "plane"],
    ));

    // THE SAME NAME, IN THE TRANSPORT'S OWN TESTS. Tests are not excluded, and this is the case
    // that proves it: a fixture that names a plane is that crate's source naming a plane.
    report.push(prove_rows_red(
        cx,
        gate,
        "a plane named inside a transport's own tests — tests are not excluded",
        &[ROW_MATRIX],
        wire_plant(
            cx,
            "src/tests/leak.rs",
            "#[test]\nfn mcp_frames_round_trip() {}\n",
        ),
        &[WIRE_PLANT, "plane"],
    ));

    // A TRANSPORT NAMED INSIDE A PLANE — the same fusion, the other way up.
    //
    // EVERY LIVE PLANE ALREADY CARRIES A TRANSPORT CELL (listed or standing), and more hits inside
    // one are not a CI finding (size is not a CI check, owner 2026-10-02). So the plane is a
    // battery-owned one that exists only in the overlay, and the transport name is its first: the
    // cell goes from no edge to an edge, which is the thing the row holds.
    report.push(prove_rows_red(
        cx,
        gate,
        "a transport named inside a plane (`busbar-plane-quokka` says `grpc`)",
        &[ROW_MATRIX],
        {
            let mut ov = plant(
                cx,
                "crates/busbar-plane-quokka/Cargo.toml",
                "[package]\nname = \"busbar-plane-quokka\"\nversion = \"0.0.0\"\n",
            );
            ov.set(
                "crates/busbar-plane-quokka/src/lib.rs",
                "//! The grpc wire delivers these.\n".to_string(),
            );
            ov
        },
        &["unlisted-cell", "busbar-plane-quokka × transport"],
    ));

    // A STORE NAMED INSIDE A KERNEL CRATE — core is core. The fixture crate is kernel-kind and
    // names nothing, so the store name is its first: `busbar-kernel × store` already stands red on
    // the tree, and more hits inside a standing cell are not a new finding.
    report.push(prove_rows_red(
        cx,
        gate,
        "a store named inside a kernel crate (the fixture says `busbar_store_memory`)",
        &[ROW_MATRIX],
        fixture_files(&[("leak.rs", "use busbar_store_memory::MemoryStore;\n")]),
        &["unlisted-cell", &fixture_subject("store")],
    ));

    // `BUSBAR-1.6.0.md` §11.5's SCOPED EXEMPTION, BOTH WAYS. ARCHITECT ruling 2026-09-27: the MATRIX never files a hit
    // inside `busbar-contract/src/abi/` into any cell, because that directory is the ONE designated
    // home every kind's ABI shapes legitimately cross-reference (`is_contract_abi_shape`). The
    // exemption is scoped to THIS counting, not to `busbar-contract` wholesale — the same noun one
    // path segment outside `abi/` still counts, exactly like it would in any other crate.
    //
    // THE NOUN IS A HOOK INSTANCE'S (`hooks-ranking`), because the contract names no hooks
    // vocabulary today: its plane and transport cells are listed edges and more hits inside them
    // are not a finding (size is not a CI check, owner 2026-10-02), so only a kind the contract
    // does not name yet can show a hit being filed — or not filed — into a cell.
    report.push(prove_rows_red(
        cx,
        gate,
        "a kind noun planted in `busbar-contract/src/<non-abi>.rs` still counts",
        &[ROW_MATRIX],
        plant(
            cx,
            "crates/busbar-contract/src/leak.rs",
            "//! Not an ABI shape: the hooks-ranking hook's verdicts are described here.\n",
        ),
        &["unlisted-cell", "busbar-contract × hooks"],
    ));
    report.push(prove_rows_green(
        cx,
        gate,
        "the same noun under `busbar-contract/src/abi/<kind>/` does not count",
        &[ROW_MATRIX],
        plant(
            cx,
            "crates/busbar-contract/src/abi/plane/leak.rs",
            "//! Not an ABI shape: the hooks-ranking hook's verdicts are described here.\n",
        ),
    ));

    // THE LAYOUT MIRRORS, BOTH WAYS. `tests/golden/abi-layout.golden`, `tests/layout_golden.rs`
    // and `include/busbar_plugin.h` restate `src/abi/`'s shapes and are named, exactly, as part of
    // the carve-out ([`CONTRACT_ABI_LAYOUT_MIRRORS`]). The carve-out is three files, not `tests/`
    // or `include/`: the same noun in any other `busbar-contract` test file or header still counts.
    report.push(prove_rows_red(
        cx,
        gate,
        "a hook word planted in any other `busbar-contract` test file still counts",
        &[ROW_MATRIX],
        plant(
            cx,
            "crates/busbar-contract/tests/planted_hook_word.rs",
            "//! Not a layout mirror: the hooks-ranking hook's verdicts are described here.\n",
        ),
        &["unlisted-cell", "busbar-contract × hooks"],
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "a hook word in a hand-written header beside the generated one still counts",
        &[ROW_MATRIX],
        plant(
            cx,
            "crates/busbar-contract/include/hand_written.h",
            "/* Not the generated header: the hooks-ranking hook's verdicts are here. */\n",
        ),
        &["unlisted-cell", "busbar-contract × hooks"],
    ));
    // The mirror keeps every line it has and GAINS one, so the only thing the plant changes is a
    // hook word added to a mirror.
    let mirror = "crates/busbar-contract/tests/golden/abi-layout.golden";
    let mirror_text = cx.read(mirror).unwrap_or_default();
    report.push(prove_rows_green(
        cx,
        gate,
        "the same noun in a layout mirror of `src/abi/` does not count",
        &[ROW_MATRIX],
        plant(
            cx,
            mirror,
            &format!("{}\nHookTail.hooks_ranking=8\n", mirror_text.trim_end()),
        ),
    ));

    // THE OTHER GATE STILL BITES — proved in `mod tests`'
    // [`tests::a_noun_under_contract_abi_still_fails_instance_noun_neutrality`], not here. Running
    // `InstanceNounNeutralityGate` through the `prove_rows_red` machinery costs THREE full `crates/`
    // walks per case (baseline + inert-check + planted) on top of its own unmemoized scan, and one
    // planted case alone measured 51.8s against this row's whole selftest budget of 204854 work
    // units — the exact "a self-test that grew a whole-tree scan per plant" failure mode item 89's
    // rule and [`super::census_holding`]'s doc comment both warn about. So, like those, it runs
    // through `cargo test`, calling the gate's `run` directly, ONCE, over `Ctx::workspace()`.

    // A HIT THAT IS ONLY A COMMENT. Nothing is stripped: a plane named in a doc comment of a
    // kernel crate is the kernel's reader being taught a plane.
    //
    // THE CELL IS THE FIXTURE'S OWN, AND PROVEN THROUGH PRESENCE. The fixture crate holds one
    // comment and no `[[cell]]` row: a comment that names no plane leaves its plane cell at zero
    // (GREEN), and the same file naming two planes makes the cell an edge nobody listed (RED). The
    // comment is the only thing the red case adds.
    let comment_fixture = |comment: bool| {
        fixture_files(&[(
            "leak.rs",
            if comment {
                "// mcp and a2a come through here too.\n"
            } else {
                "// nothing comes through here.\n"
            },
        )])
    };
    report.push(prove_rows_green(
        cx,
        gate,
        "a kernel crate whose only comment names no plane has no plane edge (the control)",
        &[ROW_MATRIX],
        comment_fixture(false),
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "a plane named in nothing but a comment inside the kernel",
        &[ROW_MATRIX],
        comment_fixture(true),
        &["unlisted-cell", &fixture_subject("plane")],
    ));

    // AN ENGLISH WORD THAT IS ALSO AN INSTANCE NAME, IN PROSE, IS NOT THE INSTANCE (ARCHITECT ruling
    // 2026-09-27; [`ENGLISH_INSTANCE_WORDS`]). The fixture holds only the prose and no row: a
    // comment that says "which streams" leaves its plane cell at zero (GREEN). The same word as a
    // config section key, and the decisions plane's id as a code identifier, are each a hit, and
    // the cell becomes an edge nobody listed (RED).
    let english_fixture = |extra: Option<(&'static str, &'static str)>| {
        let mut files = vec![(
            "prose.rs",
            "// first a buffered answer, then one over the reply buffer, which streams.\n\
             // the hook's decision is final.\n",
        )];
        files.extend(extra);
        fixture_files(&files)
    };
    report.push(prove_rows_green(
        cx,
        gate,
        "an English word that is also an instance name, in a comment, is not the instance",
        &[ROW_MATRIX],
        english_fixture(None),
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "`streams:` in section-key position in a fixture still counts",
        &[ROW_MATRIX],
        english_fixture(Some(("fixture.yaml", "streams:\n  gw: {}\n"))),
        &["unlisted-cell", &fixture_subject("plane")],
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "`decision` as a code identifier naming the plane still counts",
        &[ROW_MATRIX],
        english_fixture(Some(("route.rs", "pub fn route_to_decision() {}\n"))),
        &["unlisted-cell", &fixture_subject("plane")],
    ));

    // AN INSTANCE ID THAT IS ALSO A CRATE'S OR AN ABBREVIATION'S NAME COUNTS ONLY AS A REFERENCE
    // ([`COLLIDING_INSTANCE_WORDS`]). The fixture holds only the non-references and no row: the
    // `http` crate's paths, `axum::http`, HTTP in a comment, a URL scheme, whitespace called `ws`,
    // and a file named `skip_ws.rs` leave its transport cell at zero (GREEN). A crate-rooted path
    // to a `ws` module, and the transport crate's own path, are each a hit (RED).
    let colliding_fixture = |extra: Option<(&'static str, &'static str)>| {
        let mut files = vec![(
            "skip_ws.rs",
            "// speaks HTTP; a WS peer never reaches this.\n\
             use http::Method;\n\
             use axum::{http, Router};\n\
             pub fn status() -> axum::http::StatusCode { axum::http::StatusCode::OK }\n\
             pub fn skip_ws(s: &str) -> &str { let ws = s.trim_start(); ws }\n\
             pub const URL: &str = \"http://example.com/ws\";\n\
             pub fn is_http(m: &Method) -> bool { m == Method::GET }\n",
        )];
        files.extend(extra);
        fixture_files(&files)
    };
    report.push(prove_rows_green(
        cx,
        gate,
        "`http` as the http crate, in prose or a URL, and `ws` as whitespace are not the instance",
        &[ROW_MATRIX],
        colliding_fixture(None),
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "a crate-rooted path to a `ws` module still counts",
        &[ROW_MATRIX],
        colliding_fixture(Some(("accept.rs", "pub use crate::ingress::ws::accept;\n"))),
        &["unlisted-cell", &fixture_subject("transport")],
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "the http transport crate's own path still counts",
        &[ROW_MATRIX],
        colliding_fixture(Some(("dial.rs", "use busbar_transport_http::Dial;\n"))),
        &["unlisted-cell", &fixture_subject("transport")],
    ));

    // ONE WRITTEN NAME, ONE HIT ([`one_needle_per_span`]) IS A CLAIM ABOUT A COUNT (1, not 3), and
    // a row that holds presence cannot observe a count. It is proven where a count can be read:
    // `tests::a_package_name_scores_once_and_the_bare_id_beside_it_scores_again`, which measures
    // the fixture cell directly. Here, only what presence can see: the package name alone is a hit.
    report.push(prove_rows_red(
        cx,
        gate,
        "a plane's package name in a kernel crate is a plane edge",
        &[ROW_MATRIX],
        fixture_files(&[("wiring.rs", "use busbar_plane_llm::Codec;\n")]),
        &["unlisted-cell", &fixture_subject("plane")],
    ));

    // `unix` AS THE OPERATING SYSTEM IS NOT THE CARRIER ([`os_words`]). A `busbar-transport-unix`
    // crate is planted so `unix` is a transport needle at all. The fixture's OS spellings — its
    // cfg predicate, `std::os::unix`, the standard socket type, the clock and "non-unix" prose —
    // are not hits; the carrier's crate path, a `unix://` target, "the unix socket" in prose and a
    // carrier identifier each are.
    //
    // THE MASK'S OWN PROOF IS A COUNT and lives in
    // `tests::unix_as_the_operating_system_is_not_the_carrier`, which measures the fixture cell at
    // exactly the claim literal's one hit. (A GREEN arm cannot be written here: with a unix carrier
    // planted, the real tree's own carrier mentions make new cells in crates that never had one.)
    // The red arms below therefore plant the OS spellings beside each real reference, so each is
    // the one reference the test has shown the OS spellings are not.
    let unix_fixture = |extra: (&'static str, &'static str)| {
        let mut ov = fixture_files(&[(UNIX_OS_FILE.0, UNIX_OS_FILE.1), extra]);
        ov.set(
            "crates/busbar-transport-unix/Cargo.toml",
            "[package]\nname = \"busbar-transport-unix\"\nversion = \"0.0.0\"\n".to_string(),
        );
        ov.set(
            "crates/busbar-transport-unix/src/lib.rs",
            "//! Fixture.\n".to_string(),
        );
        ov
    };
    report.push(prove_rows_red(
        cx,
        gate,
        "the unix carrier's crate path still counts",
        &[ROW_MATRIX],
        unix_fixture(("dial.rs", "use busbar_transport_unix::Carrier;\n")),
        &["unlisted-cell", &fixture_subject("transport")],
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "a `unix://` target still counts",
        &[ROW_MATRIX],
        unix_fixture((
            "target.rs",
            "pub const SOCK: &str = \"unix:///run/busbar.sock\";\n",
        )),
        &["unlisted-cell", &fixture_subject("transport")],
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "\"the unix socket\" in prose still counts",
        &[ROW_MATRIX],
        unix_fixture(("prose.rs", "// dial the unix socket first.\n")),
        &["unlisted-cell", &fixture_subject("transport")],
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "an identifier naming the carrier (`UnixCarrier`, `connect_unix`) still counts",
        &[ROW_MATRIX],
        unix_fixture((
            "carrier.rs",
            "pub struct UnixCarrier;\npub fn connect_unix() {}\n",
        )),
        &["unlisted-cell", &fixture_subject("transport")],
    ));

    // AN OS SOCKET TYPE IS NOT THE CARRIER ([`os_words`]; ARCHITECT ruling 2026-09-30, option A,
    // a measurement correction). The connector owns every listener and every dialled socket
    // (BUSBAR-1.6.0.md THE DESIGN, section 8), so its listener file names the standard library's
    // and tokio's `TcpStream`, `TcpListener` and `UdpSocket` as `UnixStream` is named: the
    // operating system's socket, not the `tcp` transport. The fixture holds only the socket types
    // and no row, and its transport cell stays at zero (GREEN). The carrier's crate path and an
    // identifier naming the carrier each make it an edge nobody listed (RED).
    let socket_fixture = |extra: Option<(&'static str, &'static str)>| {
        let mut files = vec![(
            "listen.rs",
            "use std::net::{TcpListener, TcpStream, UdpSocket};\n\
             pub fn accept(l: &tokio::net::TcpListener) -> Option<std::net::TcpStream> { None }\n\
             pub fn bound(l: TcpListener, s: TcpStream, u: UdpSocket) {}\n",
        )];
        files.extend(extra);
        fixture_files(&files)
    };
    report.push(prove_rows_green(
        cx,
        gate,
        "a connector file naming `TcpStream`, `TcpListener` or `UdpSocket` is not naming the tcp transport",
        &[ROW_MATRIX],
        socket_fixture(None),
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "beside the socket types, the tcp carrier's crate path still counts",
        &[ROW_MATRIX],
        socket_fixture(Some(("dial.rs", "use busbar_transport_tcp::Carrier;\n"))),
        &["unlisted-cell", &fixture_subject("transport")],
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "beside the socket types, an identifier naming the tcp carrier (`TcpCarrier`) still counts",
        &[ROW_MATRIX],
        socket_fixture(Some(("carrier.rs", "pub struct TcpCarrier;\n"))),
        &["unlisted-cell", &fixture_subject("transport")],
    ));

    // A CONTRACT IDENTIFIER IS THE CONTRACT'S SHAPE, NOT A PLANE'S NAME (the Q77a measurement
    // correction, [`contract_identifiers`]). The fixture names the hook contract's
    // `RoutingDecision` — whose camel half reads as the `decision` plane's bare id — and nothing
    // else, and its plane cell stays at zero (GREEN). A crate's OWN identifier carrying the same
    // word is a hit exactly as any other spelling is (RED): the half that proves the mask is no
    // wider than the contract's exports.
    let contract_ident_fixture = |own: bool| {
        let mut files = vec![(
            "hook.rs",
            "use busbar_contract::hooks::RoutingDecision;\n\
             pub fn verdict(d: RoutingDecision) -> RoutingDecision { d }\n",
        )];
        if own {
            files.push(("own.rs", "pub struct LocalDecision;\n"));
        }
        fixture_files(&files)
    };
    report.push(prove_rows_green(
        cx,
        gate,
        "a crate naming the contract's `RoutingDecision` is not naming the decision plane",
        &[ROW_MATRIX],
        contract_ident_fixture(false),
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "the same word in an identifier the contract does not export still counts",
        &[ROW_MATRIX],
        contract_ident_fixture(true),
        &["unlisted-cell", &fixture_subject("plane")],
    ));

    // THE SPELLING THE TWO SCANNERS READ DIFFERENTLY IS STILL A HIT. `gRPC` reads whole to the
    // window scanner and splits at its own camel joint for the segment scanner; the cell takes the
    // higher, so whichever scanner sees it, the name makes the cell an edge.
    report.push(prove_rows_red(
        cx,
        gate,
        "a `gRPC` spelling the two scanners read differently still makes a transport edge",
        &[ROW_MATRIX],
        fixture_files(&[(
            "leak.rs",
            "// gRPC status codes are not the kernel's business.\n",
        )]),
        &["unlisted-cell", &fixture_subject("transport")],
    ));

    // AN EDGE CLASS NOBODY WROTE DOWN.
    report.push(plant_ledger(
        cx,
        gate,
        "an edge class with no row at all is refused, whatever BUSBAR-1.6.0.md may grant",
        &[ROW_MATRIX],
        Ok((
            "from = \"root\"\nto = \"plane\"\n".to_string(),
            "from = \"root\"\nto = \"plane-was-struck\"\n".to_string(),
        )),
        &["unlisted-edge", "root -> plane"],
    ));

    // TWO ROWS FOR ONE CELL. The maps would keep the last, so which row binds would be decided by
    // file order — and a row nobody chose is not a reviewed one.
    report.push(plant_ledger(
        cx,
        gate,
        "a second `[[cell]]` row for one cell is two answers, not a tighter one",
        &[ROW_MATRIX],
        cell_anchor(cx, "busbar-kernel", "plane").map(|anchor| {
            let doubled = format!(
                "{anchor}\n\n[[cell]]\n{}",
                cell_row("busbar-kernel", "plane")
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
        wire_plant(
            cx,
            "README.md",
            concat!(
                "# ",
                wire_plant_name!(),
                "\n\nUsed by the llm plane over this wire.\n"
            ),
        ),
        &[WIRE_PLANT, "plane"],
    ));

    // A JSON FIXTURE, COMPILED IN. `include_str!` makes it the crate's own bytes; the extension is
    // the only thing that ever made it invisible.
    report.push(prove_rows_red(
        cx,
        gate,
        "a plane routing table in a `.json` fixture under the crate is the crate's text",
        &[ROW_MATRIX],
        wire_plant(
            cx,
            "src/fixtures/leak.json",
            "{\"planes\": [\"busbar-plane-llm\", \"busbar-plane-mcp\"]}\n",
        ),
        &[WIRE_PLANT, "plane"],
    ));

    // THE SAME FIXTURE IN THE OTHER SERIALISATION. Two extensions was a list; a list is what the
    // next fixture format is not on.
    report.push(prove_rows_red(
        cx,
        gate,
        "the same table in `.yaml` -- the scan set is not an extension list",
        &[ROW_MATRIX],
        wire_plant(cx, "src/fixtures/leak.yaml", "plane: busbar-plane-voice\n"),
        &[WIRE_PLANT, "plane"],
    ));

    // AN `include!` OF A NON-`.rs` FILE IS REAL COMPILED CODE. The compiled-set rule resolves the
    // include; this case proves the SCANNER reads the target whatever it is called.
    report.push(prove_rows_red(
        cx,
        gate,
        "generated Rust in a `.inc` file -- compiled code the old scan set never opened",
        &[ROW_MATRIX],
        wire_plant(
            cx,
            "src/gen/names.inc",
            "pub const GEN: &str = \"busbar-plane-voice\";\n",
        ),
        &[WIRE_PLANT, "plane"],
    ));

    // A FILE WITH NO EXTENSION AT ALL IS TEXT. The default must be to read, never to skip: a skip
    // list that grows by accident is the hole this whole section closed.
    report.push(prove_rows_red(
        cx,
        gate,
        "a file with no extension under a crate is scanned -- the default is text, not skip",
        &[ROW_MATRIX],
        wire_plant(
            cx,
            "src/NOTES",
            "the a2a plane and the mcp plane both arrive here\n",
        ),
        &[WIRE_PLANT, "plane"],
    ));

    // THE CARGO PROSE FIELDS. `description`, `keywords` and `readme` are shipped to the registry
    // under the crate's name, and they are read on exactly the same terms as its source.
    report.push(prove_rows_red(
        cx,
        gate,
        "a plane named in a transport's Cargo `description`/`keywords` -- shipped prose is scanned",
        &[ROW_MATRIX],
        wire_plant(
            cx,
            "Cargo.toml",
            "description = \"the wire the llm plane rides\"\nkeywords = [\"mcp\"]\n",
        ),
        &[WIRE_PLANT, "plane"],
    ));

    // -- THE SPELLING THE COMPILER READS AND THE SCANNER DID NOT --------------------------------

    // `"\x6dcp"` IS `mcp`. Three plants, three green gates, on the afternoon the scanners read
    // source bytes and the compiler read source meaning. See [`decoded_line`].
    report.push(prove_rows_red(
        cx,
        gate,
        "an escape-encoded plane name in a transport -- the compiler reads `\\x6dcp` as `mcp`",
        &[ROW_MATRIX],
        wire_plant(cx, "src/leak.rs", "pub const HX: &str = \"\\x6dcp\";\n"),
        &[WIRE_PLANT, "plane"],
    ));

    report.push(prove_rows_red(
        cx,
        gate,
        "the `\\u{…}` spelling of the same name is the same name",
        &[ROW_MATRIX],
        wire_plant(
            cx,
            "src/leak.rs",
            "pub const UN: &str = \"\\u{6c}\\u{6c}m\";\n",
        ),
        &[WIRE_PLANT, "plane"],
    ));

    // A NAME SPLIT ACROSS TWO ADJACENT LITERALS IS ONE NAME.
    report.push(prove_rows_red(
        cx,
        gate,
        "a plane name split across a `concat!` of two literals is one name",
        &[ROW_MATRIX],
        wire_plant(
            cx,
            "src/leak.rs",
            "pub const CS: &str = concat!(\"m\", \"cp\");\n",
        ),
        &[WIRE_PLANT, "plane"],
    ));

    // A HOMOGLYPH. The `o` below is U+043E, Cyrillic. It reads as `voice` to every human being who
    // looks at it and to no byte scanner ever written, which is the whole of the attack.
    report.push(prove_rows_red(
        cx,
        gate,
        "a Cyrillic homoglyph inside a plane name is refused as a confusable, at a ceiling of zero",
        &[ROW_MATRIX],
        wire_plant(cx, "src/leak.rs", "pub const UC: &str = \"v\u{43e}ice\";\n"),
        &["confusable", WIRE_PLANT],
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

    // ── THE DEAD-ROW RULES, ONE PLANT EACH ───────────────────────────────────────────────────
    //
    // THE RULE ONLY HALF RAN. Every case above is about an edge APPEARING; these are the half that
    // TIGHTENS, and a mutation campaign found them unproven — `dead-cell` and `dead-edge` each had
    // their `offenders.push` replaced with a `drop` and the battery stayed green. An allowance that
    // outlives what it allowed is the most durable kind of hole there is: nothing goes red when the
    // coupling is drained, so the row stays, and the next crate to grow that coupling back finds
    // the allowance already written for it.
    //
    // The honest fixture for "this row covers nothing" is a tree in which the thing it covered is
    // GONE, and a crate leaves the measurement the way it leaves the census: its manifest goes.

    // A `[[cell]]` ROW WHOSE CRATE IS NOT THERE. `busbar-kernel-ledger` carries a live cell; it
    // measures nothing the moment the crate stops being one.
    //
    // RE-TARGETED TWICE. The subject was `busbar-auth-admin-tokens × api`, and that row went dead
    // on the real tree when the crate's last `busbar-api` name moved to the contract; then
    // `busbar-auth-static-plugin × plugin-tooling`, which went dead when the SDK merged into the
    // contract (#84) and the plugin stopped naming `busbar-plugin-sdk`. Each time its red became
    // standing debt the debt-free base subtracts and the case came back green. A kernel workflow
    // crate's cell is not a fixture's and not an edge a fold retires: removing the crate's manifest
    // kills it exactly as it did the old ones. Re-targeted a third time: the subject was
    // `busbar-kernel-scope × transport`, whose every hit was an `http` spelling that
    // [`COLLIDING_INSTANCE_WORDS`] no longer counts, so that row went dead on the real tree.
    let mut ov = crate::ctx::Overlay::new();
    ov.remove("crates/busbar-kernel-ledger/Cargo.toml");
    report.push(prove_rows_red(
        cx,
        gate,
        "a `[[cell]]` row whose cell measures nothing is a dead allowance, not a tight one",
        &[ROW_MATRIX],
        ov,
        &["dead-cell", "busbar-kernel-ledger \u{d7} kernel"],
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

    #[test]
    fn a_nested_name_scores_once() {
        let plan = plan_of(&[
            ("plane", "busbar-plane-llm"),
            ("plane", "plane-llm"),
            ("plane", "llm"),
        ]);
        let hits = scan_file(
            &plan,
            "crates/x",
            "crates/x/src/nested_once.rs",
            "use busbar_plane_llm::A;\nuse busbar_plane_llm::B; // llm\n",
        );
        let total = |line: usize| -> usize {
            hits.iter()
                .filter(|h| h.line == line)
                .map(|h| h.by_segments.max(h.by_windows).max(h.by_decoded))
                .sum()
        };
        assert_eq!(total(1), 1, "one package name is one hit");
        assert_eq!(total(2), 2, "the bare id written again is a second hit");
    }

    #[test]
    fn colliding_words_count_only_as_references() {
        let kept = |rel: &str, line: &str| {
            let m = mask_colliding_words(rel, line);
            let l = m.to_ascii_lowercase();
            l.matches("http").count() + l.matches("ws").count()
        };
        // not references
        assert_eq!(kept("a.rs", "use http::Method;"), 0);
        assert_eq!(kept("a.rs", "use axum::{http, Router};"), 0);
        assert_eq!(kept("a.rs", "let s = axum::http::StatusCode::OK;"), 0);
        assert_eq!(kept("a.rs", "fn skip_ws() { let ws = 1; }"), 0);
        assert_eq!(kept("a.rs", "let u = \"http://x/ws\";"), 0);
        assert_eq!(kept("a.rs", "// speaks HTTP to a ws peer"), 0);
        assert_eq!(kept("a.rs", "struct WsArrival; fn http_status() {}"), 0);
        assert_eq!(
            kept(
                "Cargo.toml",
                "[dependencies]\nhttp = { workspace = true }\nhttp-body = \"1\"\n"
            ),
            0
        );
        assert_eq!(
            kept("Cargo.toml", "rt = [\"axum/ws\"] # the ws accept\n"),
            0
        );
        assert_eq!(kept("README.md", "The http transport and ws."), 0);
        // references
        assert_eq!(kept("a.rs", "use crate::ingress::ws;"), 1);
        assert_eq!(kept("a.rs", "mod ws;"), 1);
        assert_eq!(kept("a.rs", "let t = Transport::Http;"), 1);
        assert_eq!(kept("a.rs", "let k = \"ws\";"), 1);
        assert_eq!(kept("a.rs", "use busbar_transport_http::X;"), 1);
        assert_eq!(kept("a.rs", "// see busbar-transport-ws"), 1);
        assert_eq!(kept("Cargo.toml", "[features]\nws = []\n"), 1);
        assert_eq!(kept("x.yaml", "transport: ws\n"), 1);
        // the path line
        assert_eq!(
            mask_colliding_path("src/egress/duplex_ws.rs"),
            "src/egress/duplex_xx.rs"
        );
        assert_eq!(
            mask_colliding_path("src/ingress/ws.rs"),
            "src/ingress/ws.rs"
        );
        assert_eq!(mask_colliding_path("src/http/mod.rs"), "src/http/mod.rs");
    }

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

    /// THE OTHER GATE STILL BITES. The `BUSBAR-1.6.0.md` §11.5 exemption [`super::is_contract_abi_shape`] adds is
    /// `:matrix`'s alone — instance-noun-neutrality reads nothing this module writes, and this is
    /// the proof rather than the assumption: a code reference (not a comment — that gate strips
    /// comments before matching, unlike `:matrix`, which is why the plant is a real `const`) to
    /// `postgres`, a store noun with no family crate in this tree (`FAM_NONE`, so ANY reference is a
    /// leak), planted under `crates/busbar-contract/src/abi/store/` — exactly the directory `:matrix`
    /// now exempts — still fails `instance-noun-neutrality:postgres`.
    ///
    /// AT UNIT SPEED, NOT THE SELFTEST BATTERY'S: this used to be a `prove_rows_red` case in
    /// [`super::selftest`], and one planted case alone cost 51.8s of the row's whole self-test
    /// budget (three full unmemoized `crates/` walks — baseline, inert-check, planted — for a
    /// single-shot proof). Called directly, once, it is one walk.
    #[test]
    fn a_noun_under_contract_abi_still_fails_instance_noun_neutrality() {
        use crate::gates::instance_noun_neutrality::{row_id, InstanceNounNeutralityGate};
        use crate::gates::Gate as _;
        use crate::ledger::Status;

        let cx = Ctx::workspace().expect("the workspace opens");
        let rel = "crates/busbar-contract/src/abi/store/leak.rs";
        let planted = cx.with_overlay(plant(
            &cx,
            rel,
            "pub const NOT_AN_ABI_SHAPE: &str = \"postgres\";\n",
        ));

        let row = row_id("postgres");
        let verdict = InstanceNounNeutralityGate::check().run(&planted);
        let found = verdict.rows.iter().find(|r| r.id == row);
        assert_eq!(
            found.map(|r| &r.status),
            Some(&Status::Fail),
            "{row}: expected FAIL for a `postgres` reference planted under {rel}, got {:?}",
            found.map(|r| &r.status)
        );
        let detail = found.map(|r| r.detail.as_str()).unwrap_or_default();
        assert!(
            detail.contains(rel),
            "{row} failed but did not name the plant at {rel}: {detail}"
        );
    }

    /// The census exactly as the gate's own `run` builds it: instances assigned, so a wire a crate
    /// declares is a needle here as it is there.
    fn crates_of(cx: &Ctx) -> Vec<CrateInfo> {
        let mut crates = super::super::census(cx).expect("the census reads");
        let (planes, ports) = super::super::vocabularies(&crates);
        super::super::assign_instances(&mut crates, &planes, &ports);
        crates
    }

    /// One cell's measured count over the real workspace with `ov` laid over it.
    fn cell_count(ov: crate::ctx::Overlay, krate: &str, kind: &'static str) -> usize {
        let cx = Ctx::workspace()
            .expect("the workspace opens")
            .with_overlay(ov);
        let crates = crates_of(&cx);
        let (matrix, _, _) = measure(&cx, &crates).expect("the matrix measures");
        matrix
            .get(&(krate.to_string(), kind))
            .map_or(0, |c| c.count)
    }

    /// THE DIALECT WIRE-KEY SPAN (ARCHITECT ruling 2026-10-02, DF-MAP), measured on the cell: a
    /// quoted map key that IS a path of the file's wire lock is the provider's word and adds nothing
    /// to `busbar-plane-llm × plane`; the same plane word in a value, a comment, or a key the lock
    /// does not have still counts.
    #[test]
    fn a_dialect_wire_key_is_the_providers_word_and_the_same_word_elsewhere_counts() {
        let file = "crates/busbar-plane-llm/dialects/openai_responses.toml";
        let body = Ctx::workspace()
            .expect("the workspace opens")
            .read(file)
            .expect("the dialect map");
        let with = |line: &str| {
            let mut ov = crate::ctx::Overlay::new();
            ov.set(file, format!("{body}\n{line}\n"));
            cell_count(ov, "busbar-plane-llm", "plane")
        };
        let base = cell_count(crate::ctx::Overlay::new(), "busbar-plane-llm", "plane");
        assert_eq!(
            with("[unmapped.stream]\n\"input[].type=mcp_call.arguments\" = { no-equivalent = \"x\" }"),
            base,
            "a wire-lock key is the provider's word, not a plane coupling"
        );
        for (what, line) in [
            (
                "a map VALUE",
                "[unmapped.stream]\n\"input[].type=function_call.arguments\" = { no-equivalent = \"an mcp call\" }",
            ),
            ("a comment", "# the mcp tool"),
            (
                "a key the wire lock does not have",
                "[unmapped.stream]\n\"tools[].type=mcp.no_such_member\" = { no-equivalent = \"x\" }",
            ),
        ] {
            assert!(with(line) > base, "the plane word in {what} must still count");
        }
    }

    /// ONE WRITTEN NAME, ONE HIT ([`one_needle_per_span`]), measured on the cell itself. The row
    /// holds presence, so this count is not something the selftest battery can observe any more:
    /// `busbar_plane_llm::` is the package name, and inside it `plane-llm` and `llm` — it scored 3
    /// before the span rule and scores 1. The bare id written again on the same line is a second
    /// name and scores again.
    #[test]
    fn a_package_name_scores_once_and_the_bare_id_beside_it_scores_again() {
        let fixture = instances::FIXTURE_CRATE;
        assert_eq!(
            cell_count(
                fixture_files(&[("wiring.rs", "use busbar_plane_llm::Codec;\n")]),
                fixture,
                "plane"
            ),
            1,
            "a package name must score once, not once per shorter needle inside it"
        );
        assert_eq!(
            cell_count(
                fixture_files(&[(
                    "wiring.rs",
                    "use busbar_plane_llm::Codec; // an llm codec\n"
                )]),
                fixture,
                "plane"
            ),
            2,
            "the bare id written beside the package name is a second name"
        );
    }

    /// `unix` AS THE OPERATING SYSTEM IS NOT THE CARRIER ([`os_words`]), measured on the cell
    /// itself. With a `busbar-transport-unix` crate planted so `unix` is a transport needle at
    /// all, the fixture's OS spellings ([`UNIX_OS_FILE`]) score NOTHING on their own and add
    /// nothing beside the claim literal `"unix"`, which is a real reference and scores.
    #[test]
    fn unix_as_the_operating_system_is_not_the_carrier() {
        let with_carrier = |files: &[(&str, &str)]| {
            let mut ov = fixture_files(files);
            ov.set(
                "crates/busbar-transport-unix/Cargo.toml",
                "[package]\nname = \"busbar-transport-unix\"\nversion = \"0.0.0\"\n".to_string(),
            );
            ov.set(
                "crates/busbar-transport-unix/src/lib.rs",
                "//! Fixture.\n".to_string(),
            );
            ov
        };
        let fixture = instances::FIXTURE_CRATE;
        let claim = ("wiring.rs", "pub const CLAIM: &str = \"unix\";\n");
        let os_only = cell_count(with_carrier(&[UNIX_OS_FILE]), fixture, "transport");
        let claim_only = cell_count(with_carrier(&[claim]), fixture, "transport");
        let both = cell_count(with_carrier(&[claim, UNIX_OS_FILE]), fixture, "transport");
        assert_eq!(
            os_only, 0,
            "an OS spelling of `unix` was counted as the carrier"
        );
        assert!(
            claim_only >= 1,
            "the claim literal `\"unix\"` is the carrier and must count"
        );
        assert_eq!(
            both, claim_only,
            "the OS spellings beside the claim literal added hits"
        );
    }

    /// THE RED ARM OF THE OWNER'S RULING (2026-10-02: "line count shouldnt halt ci"), and the arm
    /// that keeps the ruling from deleting the gate with it.
    ///
    /// (a) A NEW CROSS-KIND EDGE IS STILL DENIED: a plane named in `busbar-kernel-wal`, a cell
    ///     with no `[[cell]]` row, turns the row FAIL with `unlisted-cell` naming it, and the
    ///     row's figure (the leading integer the release turnstile reads) rises. The plant was a
    ///     transport naming a plane until the tcp transport moved to its own repo; both
    ///     transports left on the tree carry a listed `× plane` cell, and the WAL names no plane.
    /// (b) MORE HITS IN A LISTED CELL ARE NOT: five hundred lines of plane vocabulary in the
    ///     composition root, whose `busbar × plane` cell is listed, measurably grow the cell and
    ///     add NO finding — the findings, tag + subject and whole text alike, are the ones the
    ///     unplanted tree carries, and the figure does not move.
    #[test]
    fn a_new_cross_kind_edge_is_still_denied_and_more_hits_in_a_listed_cell_are_not() {
        use crate::ledger::Status;

        fn figure(row: &Row) -> usize {
            if row.status != Status::Fail {
                return 0;
            }
            let digits: String = row
                .detail
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            digits.parse().unwrap_or_else(|_| {
                panic!(
                    "a FAIL :matrix detail must lead with its finding count: {}",
                    row.detail
                )
            })
        }
        fn keys(row: &Row) -> BTreeSet<String> {
            crate::gates::standing_snapshot::findings(row)
                .into_iter()
                .map(|(k, _, _)| k)
                .collect()
        }

        let cx = Ctx::workspace().expect("the workspace opens");
        let reg = super::super::load_registry(&cx).expect("the ledger reads");
        let base = rule_matrix(&cx, &crates_of(&cx), &reg, false);
        let (_, base_findings) = super::super::debt_free::split_detail(&base.detail);

        // (a) A NEW EDGE.
        let edge = "kind-isolation:matrix\tunlisted-cell\tbusbar-kernel-wal \u{d7} plane";
        assert!(
            !keys(&base).contains(edge),
            "the unplanted tree already carries {edge}; the plant would prove nothing"
        );
        let planted = cx.with_overlay(plant(
            &cx,
            "crates/busbar-kernel-wal/src/leak.rs",
            "//! The llm plane's frames arrive here first.\n",
        ));
        let row = rule_matrix(&planted, &crates_of(&planted), &reg, false);
        assert_eq!(
            row.status,
            Status::Fail,
            "a new cross-kind edge passed: {}",
            row.detail
        );
        assert!(
            keys(&row).contains(edge),
            "a new cross-kind edge was not named `unlisted-cell`: {}",
            row.detail.chars().take(600).collect::<String>()
        );
        assert!(
            figure(&row) > figure(&base),
            "a new cross-kind edge did not raise the row's figure ({} -> {})",
            figure(&base),
            figure(&row)
        );

        // (b) MORE HITS IN A LISTED CELL.
        assert!(
            reg.matrix_cells
                .iter()
                .any(|c| c.krate == "busbar" && c.kind == "plane"),
            "`busbar \u{d7} plane` is no longer a listed cell; pick another listed cell"
        );
        let rel = "crates/busbar/src/root/planted_bulk_plane_words.rs";
        let bulk = "// the llm plane, the mcp plane and the a2a plane all pass through here.\n"
            .repeat(500);
        let before = cell_count(crate::ctx::Overlay::new(), "busbar", "plane");
        let after = cell_count(plant(&cx, rel, &bulk), "busbar", "plane");
        assert!(
            after >= before + 500,
            "the bulk plant did not grow the listed cell ({before} -> {after}); it proves nothing"
        );
        let planted = cx.with_overlay(plant(&cx, rel, &bulk));
        let row = rule_matrix(&planted, &crates_of(&planted), &reg, false);
        let (_, findings) = super::super::debt_free::split_detail(&row.detail);
        assert_eq!(
            row.status, base.status,
            "more hits in a listed cell moved the row's status"
        );
        assert_eq!(
            keys(&row),
            keys(&base),
            "more hits in a listed cell changed the row's findings (tag + subject)"
        );
        assert_eq!(
            findings, base_findings,
            "more hits in a listed cell changed a finding's text"
        );
        assert_eq!(
            figure(&row),
            figure(&base),
            "more hits in a listed cell moved the row's figure"
        );
    }
}
