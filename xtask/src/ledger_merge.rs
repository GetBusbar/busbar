//! `cargo xtask ledger-merge <BASE> <OURS> <THEIRS>` — the git merge driver for the count rows of
//! `qa/kind-isolation.toml` (`.gitattributes`: `merge=ledger-count`).
//!
//! WHY A DRIVER AND NOT A HAND. A `count` row in that file is a MEASUREMENT of the tree. Two lanes
//! that each move the same row from the merge-base value B — theirs to T, ours to O — conflict
//! textually, and a human settling it by picking one side's number drops the other side's delta.
//! Both deltas are real, so the merged tree measures `T + O − B`, and that is what this writes.
//! Nothing here is trusted beyond that sum: the gates re-measure every merged tree (Law 9, exact
//! in both directions), so a wrong sum is a red on the merge, never a hidden one.
//!
//! THE CONTRACT is git's (`merge.<driver>.driver = "… %O %A %B"`): OURS is overwritten in place
//! with the result and the exit is 0, or OURS is left byte-for-byte untouched and the exit is
//! non-zero with every reason on stderr, so git leaves the conflict for a person. The codes follow
//! [`crate::cli`]: 1 the merge refused, 2 the arguments were wrong, 3 a file could not be read or
//! written.
//!
//! THE RULE, row by row, with THEIRS (the integration line) as the frame:
//!
//! * changed on one side only, or not at all → that side's row text, verbatim;
//! * both sides moved `count` to the SAME number → refused: a shared change or a coincidence, and
//!   `T + O − B` would count a shared change twice;
//! * both sides changed it identically → kept once;
//! * otherwise field by field: a field changed on one side takes that side; `count` changed on
//!   both is `T + O − B` (integers; negative refused); `cite` is theirs, then `"; "` and the clause
//!   ours appended to base, its first `B -> O` rewritten to `T -> result`; `why` follows the count
//!   when the only change either side made to it is the count's own number; any other field
//!   changed differently on both sides is refused, by row and field;
//! * added on one side → kept, after the row it followed there; added on both → kept once if the
//!   text is identical, refused otherwise;
//! * deleted on one side and unchanged on the other → deleted; deleted and changed → refused;
//! * the text after the last row, changed differently on both sides → refused.
//!
//! A row is the comment lines above its `[[table]]` header, the header, and its `key = "value"`
//! lines — read on the terms `kind_isolation::parse_registry` reads them. Its identity is the
//! field set the gate keys it by ([`IDENTITY`]).

use std::collections::{BTreeMap, BTreeSet};

/// The file this driver is registered for.
pub const LEDGER: &str = crate::gates::kind_isolation::REGISTRY_FILE;

/// THE FIELDS THAT NAME A ROW, per table — read off the gate, not chosen here:
///
/// * `dep`, `question` — `from`, `to`, `half`: `kind-isolation:deps`/`:test-deps` key the ledger
///   by `(from, to)` within one `half` (`duplicate-dep`).
/// * `law0` — `crate`, `axis`: `law0-duplicate`, "two `[[law0]]` rows for one crate and axis".
/// * `face` — `crate`, `face`: the `:faces` lookup and `dead-face` (`f.krate`, `f.face`).
/// * `cell`, `instance` — `crate`, `kind`: `duplicate-row` (`crate × kind`).
/// * `edge`, `transitional` — `from`, `to`: `duplicate-row` (`from -> to`); the drain rule reads a
///   transitional row as the edge `from -> to`.
/// * `core-name` — `kind`, `name`: `duplicate-core-name`.
/// * `patch` — `file`, `entry`: the redirect allowance matches `a.file == rel && a.entry == entry`.
/// * `shape-word` — `word`, `file`, `holder`: `duplicate-shape-word` (one reservation is one word,
///   in one file, on the line its holder names).
/// * `announced`, `registered` — `crate`: one row says what one crate is.
pub const IDENTITY: &[(&str, &[&str])] = &[
    ("transitional", &["from", "to"]),
    ("announced", &["crate"]),
    ("registered", &["crate"]),
    ("dep", &["from", "to", "half"]),
    ("question", &["from", "to", "half"]),
    ("face", &["crate", "face"]),
    ("law0", &["crate", "axis"]),
    ("edge", &["from", "to"]),
    ("cell", &["crate", "kind"]),
    ("instance", &["crate", "kind"]),
    ("core-name", &["kind", "name"]),
    ("patch", &["file", "entry"]),
    ("shape-word", &["word", "file", "holder"]),
];

const USAGE: &str =
    "usage: cargo xtask ledger-merge <BASE> <OURS> <THEIRS> [<PATH> [<MARKER-SIZE>]]   \
                     (git: %O %A %B [%P [%L]])";

/// One `key = "value"` line and the comment or blank lines directly above it inside the row.
#[derive(Debug, Clone)]
struct Field {
    key: String,
    lead: String,
    line: String,
}

impl Field {
    fn text(&self) -> String {
        format!("{}{}", self.lead, self.line)
    }

    fn value(&self) -> &str {
        value_of(&self.line)
    }
}

/// One `[[table]]` row, as text.
#[derive(Debug, Clone)]
struct Record {
    /// What a refusal names the row by: `[[law0]] crate = "busbar", axis = "auth"`.
    id: String,
    preamble: String,
    header: String,
    fields: Vec<Field>,
}

impl Record {
    fn text(&self) -> String {
        let mut s = format!("{}{}", self.preamble, self.header);
        for f in &self.fields {
            s.push_str(&f.text());
        }
        s
    }

    fn field(&self, key: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.key == key)
    }
}

#[derive(Debug, Clone)]
struct Ledger {
    records: Vec<Record>,
    /// Everything after the last row's last field.
    trailer: String,
}

/// The value between the line's outer quotes (exactly one each side: an escaped `\"` at the end
/// of a value is the value's).
fn value_of(line: &str) -> &str {
    line.split_once('=').map_or("", |(_, v)| {
        let v = v.trim();
        v.strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(v)
    })
}

/// `line` with its value replaced by `new`, every other byte (alignment, quotes, line end) kept.
fn with_value(line: &str, new: &str) -> String {
    let Some(eq) = line.find('=') else {
        return line.to_string();
    };
    let (head, rest) = line.split_at(eq + 1);
    let body = rest.trim_end_matches(['\n', '\r']);
    let eol = &rest[body.len()..];
    let lead_ws = &body[..body.len() - body.trim_start().len()];
    let trail_ws = &body[body.trim_end().len()..];
    let core = body.trim();
    if core.len() >= 2 && core.starts_with('"') && core.ends_with('"') {
        format!("{head}{lead_ws}\"{new}\"{trail_ws}{eol}")
    } else {
        format!("{head}{lead_ws}{new}{trail_ws}{eol}")
    }
}

fn identity(table: &str, fields: &[Field]) -> Result<String, String> {
    let Some((_, keys)) = IDENTITY.iter().find(|(t, _)| *t == table) else {
        return Err(format!(
            "`[[{table}]]` is not a table the kind-isolation gate reads, so no field set names its \
             rows"
        ));
    };
    let mut parts = Vec::new();
    for k in keys.iter() {
        match fields.iter().find(|f| f.key == *k) {
            Some(f) => parts.push(format!("{k} = \"{}\"", f.value())),
            None => {
                return Err(format!(
                    "a `[[{table}]]` row has no `{k}`, so it cannot be told from another row"
                ))
            }
        }
    }
    Ok(format!("[[{table}]] {}", parts.join(", ")))
}

/// The file as rows, losslessly: the rows' texts and the trailer concatenate back to `text`.
fn parse(text: &str, side: &str) -> Result<Ledger, Vec<String>> {
    struct Open {
        table: String,
        preamble: String,
        header: String,
        fields: Vec<Field>,
    }
    let mut errors = Vec::new();
    let mut records: Vec<Record> = Vec::new();
    let mut pending = String::new();
    let mut open: Option<Open> = None;
    let close = |o: Open, errors: &mut Vec<String>, records: &mut Vec<Record>| match identity(
        &o.table, &o.fields,
    ) {
        Ok(id) => records.push(Record {
            id,
            preamble: o.preamble,
            header: o.header,
            fields: o.fields,
        }),
        Err(e) => errors.push(format!("{side}: {e}")),
    };
    for (i, line) in text.split_inclusive('\n').enumerate() {
        let t = line.trim();
        if let Some(head) = t.strip_prefix("[[").and_then(|s| s.strip_suffix("]]")) {
            if let Some(o) = open.take() {
                close(o, &mut errors, &mut records);
            }
            open = Some(Open {
                table: head.trim().to_string(),
                preamble: std::mem::take(&mut pending),
                header: line.to_string(),
                fields: Vec::new(),
            });
        } else if t.is_empty() || t.starts_with('#') {
            pending.push_str(line);
        } else if t.starts_with('[') {
            errors.push(format!(
                "{side}:{}: `{t}` is a table header the kind-isolation gate does not read",
                i + 1
            ));
        } else if let (Some(o), Some((k, _))) = (open.as_mut(), t.split_once('=')) {
            o.fields.push(Field {
                key: k.trim().to_string(),
                lead: std::mem::take(&mut pending),
                line: line.to_string(),
            });
        } else {
            errors.push(format!(
                "{side}:{}: `{t}` is not a `key = \"value\"` line under a `[[table]]` header",
                i + 1
            ));
        }
    }
    if let Some(o) = open.take() {
        close(o, &mut errors, &mut records);
    }
    let mut seen = BTreeSet::new();
    for r in &records {
        if !seen.insert(r.id.as_str()) {
            errors.push(format!(
                "{side}: {} appears twice; two rows for one thing cannot be merged as one",
                r.id
            ));
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(Ledger {
        records,
        trailer: pending,
    })
}

/// The ordinary three-way choice: whichever side moved, or both when they agree.
fn three<T: PartialEq + Clone>(b: &T, o: &T, t: &T) -> Option<T> {
    if o == b || o == t {
        Some(t.clone())
    } else if t == b {
        Some(o.clone())
    } else {
        None
    }
}

fn int(v: &str) -> Option<i64> {
    v.trim().parse::<i64>().ok()
}

/// `text` with every standalone number equal to `from` replaced by `to`. Standalone: not part of a
/// word (`a2a`), a version (`1.6.0`), a path or an issue number — a digit run touching a letter,
/// `.`, `_`, `/`, `#` or `-` on either side is left alone.
fn subst_number(text: &str, from: i64, to: i64) -> String {
    let from = from.to_string();
    let to = to.to_string();
    let bytes = text.as_bytes();
    let joined = |c: u8| c.is_ascii_alphanumeric() || b"._/#-".contains(&c);
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() && (i == 0 || !joined(bytes[i - 1])) {
            let end = i + bytes[i..].iter().take_while(|c| c.is_ascii_digit()).count();
            let run = &text[i..end];
            let standalone = end == bytes.len() || !joined(bytes[end]);
            out.push_str(if standalone && run == from {
                to.as_str()
            } else {
                run
            });
            i = end;
        } else {
            let ch = text[i..].chars().next().unwrap_or_default();
            out.push(ch);
            i += ch.len_utf8().max(1);
        }
    }
    out
}

/// A move's byte spans of X and Y in its clause, then X's and Y's values.
type Move = ((usize, usize), (usize, usize), i64, i64);

/// The first `X -> Y` in `clause`, as the byte spans of X and Y and their values.
fn first_move(clause: &str) -> Option<Move> {
    let bytes = clause.as_bytes();
    let mut from = 0;
    while let Some(at) = clause[from..].find("->").map(|p| p + from) {
        from = at + 2;
        let mut l_end = at;
        while l_end > 0 && bytes[l_end - 1] == b' ' {
            l_end -= 1;
        }
        let mut l_start = l_end;
        while l_start > 0 && bytes[l_start - 1].is_ascii_digit() {
            l_start -= 1;
        }
        let mut r_start = at + 2;
        while r_start < bytes.len() && bytes[r_start] == b' ' {
            r_start += 1;
        }
        let mut r_end = r_start;
        while r_end < bytes.len() && bytes[r_end].is_ascii_digit() {
            r_end += 1;
        }
        if l_start < l_end && r_start < r_end {
            let x = int(&clause[l_start..l_end])?;
            let y = int(&clause[r_start..r_end])?;
            return Some(((l_start, l_end), (r_start, r_end), x, y));
        }
    }
    None
}

/// The counts of one row on the three sides, and the merged one.
#[derive(Clone, Copy)]
struct Counts {
    b: i64,
    o: i64,
    t: i64,
    r: i64,
}

/// THEIRS' cite, then `"; "` and the clause OURS added to BASE's, its first move renumbered.
fn merge_cite(bc: &str, oc: &str, tc: &str, n: Counts) -> Result<String, String> {
    let Some(added) = oc.strip_prefix(bc) else {
        return Err(
            "ours rewrote base's text instead of appending a clause to it, so there is no clause \
             of ours to carry onto theirs"
                .to_string(),
        );
    };
    let clause = added.trim_start_matches(|c: char| c == ';' || c == ',' || c.is_whitespace());
    if clause.is_empty() {
        return Ok(tc.to_string());
    }
    let mut clause = clause.to_string();
    if n.o != n.b {
        if let Some(((xs, xe), (ys, ye), x, y)) = first_move(&clause) {
            if (x, y) != (n.b, n.o) {
                return Err(format!(
                    "ours' clause first reads `{x} -> {y}`, not this row's move `{} -> {}`, so it \
                     cannot be renumbered onto theirs",
                    n.b, n.o
                ));
            }
            clause = format!(
                "{}{}{}{}{}",
                &clause[..xs],
                n.t,
                &clause[xe..ys],
                n.r,
                &clause[ye..]
            );
        }
    }
    Ok(format!("{tc}; {clause}"))
}

/// One row present on all three sides.
fn merge_record(b: &Record, o: &Record, t: &Record) -> Result<String, Vec<String>> {
    let (bt, ot, tt) = (b.text(), o.text(), t.text());
    if ot == bt {
        return Ok(tt);
    }
    if tt == bt {
        return Ok(ot);
    }
    let id = &t.id;
    let count = |r: &Record| r.field("count").map(|f| f.value().to_string());
    let (bc, oc, tc) = (count(b), count(o), count(t));
    if let (Some(bc), Some(oc), Some(tc)) = (&bc, &oc, &tc) {
        let same = match (int(oc), int(tc)) {
            (Some(ov), Some(tv)) => ov == tv,
            _ => oc == tc,
        };
        if oc != bc && tc != bc && same {
            return Err(vec![format!(
                "both sides moved {id} from {bc} to the same count {oc} — a shared change or a \
                 coincidence; settle by hand (take theirs if it is the same change)"
            )]);
        }
    }
    if ot == tt {
        return Ok(tt);
    }

    let mut refusals = Vec::new();
    let mut refuse = |field: &str, why: String| refusals.push(format!("{id}: {field}: {why}"));
    let mut out = String::new();
    match three(&b.preamble, &o.preamble, &t.preamble) {
        Some(p) => out.push_str(&p),
        None => refuse(
            "the comment above it",
            "changed differently on both sides".to_string(),
        ),
    }
    match three(&b.header, &o.header, &t.header) {
        Some(h) => out.push_str(&h),
        None => refuse(
            "the header line",
            "changed differently on both sides".to_string(),
        ),
    }

    // THE COUNT FIRST: `cite` and `why` are renumbered to it.
    let mut counts: Option<Counts> = None;
    let mut arithmetic = false;
    if let (Some(bc), Some(oc), Some(tc)) = (&bc, &oc, &tc) {
        match (int(bc), int(oc), int(tc)) {
            (Some(bv), Some(ov), Some(tv)) => {
                let r = if ov != bv && tv != bv {
                    arithmetic = true;
                    tv + ov - bv
                } else if ov != bv {
                    ov
                } else {
                    tv
                };
                if r < 0 {
                    refuse(
                        "count",
                        format!(
                            "theirs {tv} + ours {ov} − base {bv} = {r}, and a measured count is \
                             never negative"
                        ),
                    );
                }
                counts = Some(Counts {
                    b: bv,
                    o: ov,
                    t: tv,
                    r,
                });
            }
            _ if oc != bc && tc != bc => refuse(
                "count",
                format!(
                    "base \"{bc}\", ours \"{oc}\", theirs \"{tc}\": a count that is not an \
                     integer cannot be summed"
                ),
            ),
            _ => {}
        }
    }

    let mut keys: Vec<&str> = t.fields.iter().map(|f| f.key.as_str()).collect();
    for f in &o.fields {
        if t.field(&f.key).is_none() && b.field(&f.key).is_none() {
            keys.push(f.key.as_str());
        }
    }
    let mut seen_keys = BTreeSet::new();
    for key in keys {
        if !seen_keys.insert(key) {
            continue;
        }
        let (bf, of, tf) = (b.field(key), o.field(key), t.field(key));
        let text = |f: Option<&Field>| f.map(Field::text);
        // The plain three-way choice is the answer for every field the count rule does not own.
        let plain = three(&text(bf), &text(of), &text(tf));
        let owned = matches!(key, "count" | "cite" | "why") && counts.is_some();
        let (Some(bf), Some(of), Some(tf), true) = (bf, of, tf, owned) else {
            match plain {
                Some(Some(s)) => out.push_str(&s),
                Some(None) => {}
                None => refuse(key, "changed differently on both sides".to_string()),
            }
            continue;
        };
        let Some(n) = counts else { continue };
        let Some(lead) = three(&bf.lead, &of.lead, &tf.lead) else {
            refuse(
                key,
                "the comment inside the row above it changed differently on both sides".to_string(),
            );
            continue;
        };
        let value: Result<String, String> = match key {
            "count" => Ok(n.r.to_string()),
            "cite" => {
                if arithmetic || (of.value() != bf.value() && tf.value() != bf.value()) {
                    merge_cite(bf.value(), of.value(), tf.value(), n)
                } else {
                    Ok(three(&bf.value(), &of.value(), &tf.value())
                        .unwrap_or_default()
                        .to_string())
                }
            }
            _ => {
                // `why`: renumbered with the count only where the count's number is ALL either
                // side changed in it; any other edit is an ordinary field.
                let (bw, ow, tw) = (bf.value(), of.value(), tf.value());
                let o_num = ow == bw || ow == subst_number(bw, n.b, n.o);
                let t_num = tw == bw || tw == subst_number(bw, n.b, n.t);
                if ow == bw && tw == bw {
                    Ok(bw.to_string())
                } else if arithmetic && o_num && t_num {
                    Ok(subst_number(bw, n.b, n.r))
                } else {
                    match three(&bw, &ow, &tw) {
                        Some(w) => Ok(w.to_string()),
                        None => Err("changed differently on both sides".to_string()),
                    }
                }
            }
        };
        match value {
            Ok(v) => {
                out.push_str(&lead);
                out.push_str(&with_value(&tf.line, &v));
            }
            Err(why) => refuse(key, why),
        }
    }
    if refusals.is_empty() {
        Ok(out)
    } else {
        Err(refusals)
    }
}

/// THE MERGE: the settled file, or every reason it could not be settled.
pub fn merge(base: &str, ours: &str, theirs: &str) -> Result<String, Vec<String>> {
    let parsed = [
        parse(base, "base"),
        parse(ours, "ours"),
        parse(theirs, "theirs"),
    ];
    let mut errors = Vec::new();
    for p in &parsed {
        if let Err(e) = p {
            errors.extend(e.iter().cloned());
        }
    }
    let [Ok(b), Ok(o), Ok(t)] = parsed else {
        return Err(errors);
    };
    let index = |l: &Ledger| -> BTreeMap<String, Record> {
        l.records
            .iter()
            .map(|r| (r.id.clone(), r.clone()))
            .collect()
    };
    let (bi, oi, ti) = (index(&b), index(&o), index(&t));

    let mut out: Vec<(String, String)> = Vec::new();
    for r in &t.records {
        match (bi.get(&r.id), oi.get(&r.id)) {
            (Some(br), Some(or)) => match merge_record(br, or, r) {
                Ok(text) => out.push((r.id.clone(), text)),
                Err(e) => errors.extend(e),
            },
            (Some(br), None) => {
                if br.text() != r.text() {
                    errors.push(format!(
                        "{}: ours deleted the row and theirs changed it; settle by hand",
                        r.id
                    ));
                }
            }
            (None, Some(or)) => {
                if or.text() == r.text() {
                    out.push((r.id.clone(), r.text()));
                } else {
                    errors.push(format!(
                        "{}: added on both sides with different text; settle by hand",
                        r.id
                    ));
                }
            }
            (None, None) => out.push((r.id.clone(), r.text())),
        }
    }
    for br in &b.records {
        if ti.contains_key(&br.id) {
            continue;
        }
        if let Some(or) = oi.get(&br.id) {
            if or.text() != br.text() {
                errors.push(format!(
                    "{}: theirs deleted the row and ours changed it; settle by hand",
                    br.id
                ));
            }
        }
    }
    // OURS' NEW ROWS, each after the row it followed in ours (or before the one it preceded).
    for (i, or) in o.records.iter().enumerate() {
        if bi.contains_key(&or.id) || ti.contains_key(&or.id) {
            continue;
        }
        let at = |id: &str| out.iter().position(|(k, _)| k == id);
        let pos = o.records[..i]
            .iter()
            .rev()
            .find_map(|p| at(p.id.as_str()).map(|x| x + 1))
            .or_else(|| o.records[i + 1..].iter().find_map(|n| at(n.id.as_str())))
            .unwrap_or(out.len());
        out.insert(pos, (or.id.clone(), or.text()));
    }
    let trailer = match three(&b.trailer, &o.trailer, &t.trailer) {
        Some(s) => s,
        None => {
            errors.push(
                "the text after the last row changed differently on both sides; settle by hand"
                    .to_string(),
            );
            String::new()
        }
    };
    if !errors.is_empty() {
        return Err(errors);
    }
    let mut text: String = out.into_iter().map(|(_, s)| s).collect();
    text.push_str(&trailer);
    Ok(text)
}

/// `cargo xtask ledger-merge <BASE> <OURS> <THEIRS>`.
pub fn main(args: &[String]) -> i32 {
    // The three paths are the contract; git's optional `%P` (the path) and `%L` (the conflict
    // marker size) are accepted after them and not needed: the driver never writes markers.
    let [base, ours, theirs, ..] = args else {
        eprintln!("xtask ledger-merge: three paths, got {}", args.len());
        eprintln!("{USAGE}");
        return 2;
    };
    if args.len() > 5 {
        eprintln!(
            "xtask ledger-merge: at most five arguments (%O %A %B %P %L), got {}",
            args.len()
        );
        eprintln!("{USAGE}");
        return 2;
    }
    let read = |p: &str| std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"));
    let texts = match (
        read(base.as_str()),
        read(ours.as_str()),
        read(theirs.as_str()),
    ) {
        (Ok(b), Ok(o), Ok(t)) => (b, o, t),
        (b, o, t) => {
            for e in [b.err(), o.err(), t.err()].into_iter().flatten() {
                eprintln!("xtask ledger-merge: could not read {e}");
            }
            return 3;
        }
    };
    match merge(&texts.0, &texts.1, &texts.2) {
        Ok(text) => {
            if text == texts.1 {
                return 0;
            }
            // OURS is the one file this writes, and the text is whole before a byte of it is.
            match std::fs::write(ours, &text) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("xtask ledger-merge: could not write {ours}: {e}");
                    3
                }
            }
        }
        Err(reasons) => {
            for r in &reasons {
                eprintln!("xtask ledger-merge: {r}");
            }
            eprintln!(
                "xtask ledger-merge: {LEDGER} left as a conflict ({} reason(s)); ours is untouched",
                reasons.len()
            );
            1
        }
    }
}

#[cfg(test)]
#[path = "tests/ledger_merge_tests.rs"]
mod tests;
