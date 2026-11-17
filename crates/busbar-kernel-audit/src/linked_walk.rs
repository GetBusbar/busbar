// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LINKED WINDOWS (SEALING-FIX r20 §3.7): the walked lines, the page stamps and break notices, the
//! notary key certificates and the node's seal row, checked under one independently trusted
//! deployment Bootstrap key.
//!
//! The rules read their input only through the source traits below ([`LinkedRange`],
//! [`WalkedLine`], [`Evidence`], [`TrustedHead`]). Every accessor returns `Result<_, &'static str>`
//! and is called in one fixed order, so the first refusal does not depend on where the input came
//! from: the offline verifier implements them over a published range (JSON), and a declared
//! restore (DES-331 §B3.1) over the journal record bodies of an exported tail. [`verify`] returns a
//! typed [`Verdict`]; each caller renders it.

use std::collections::{BTreeMap, BTreeSet};

use busbar_contract::crypto::{self, PublicKey, SigAlg};

use crate::{
    AuditVerifyingKey, BreakNotice, Fingerprint, NotaryKeyRecord, Stamp, StampKind, LINK_RECIPE,
    NOTARY_KEY_RECORD_DOMAIN,
};

/// One accessor's result: the value, or the refusal the verifier reports.
pub type Read<T> = Result<T, &'static str>;

/// ONE WALKED LINE (a requested record, a cover line or a certificate line).
pub trait WalkedLine {
    /// The line's chain sequence.
    fn seq(&self) -> Read<u64>;
    /// The node whose chain holds the line.
    fn node(&self) -> Read<u64>;
    /// The predecessor fingerprint as published (lowercase hex; empty at genesis).
    fn prev_hash(&self) -> Read<&str>;
    /// The line's own fingerprint or digest as published (lowercase hex).
    fn hash(&self) -> Read<&str>;
    /// The line's recipe name.
    fn recipe(&self) -> Read<&str>;
    /// The line as a `notary_key` certificate, with the journal position a stamp's `key_cert`
    /// names.
    fn certificate(&self) -> Read<(u64, NotaryKeyRecord)>;
    /// The line's digest recomputed by its own recipe (a unit line; lowercase hex).
    fn digest(&self) -> Read<String>;
    /// A legacy line's signature (lowercase hex).
    fn signature(&self) -> Read<&str>;
    /// The identifier of the key that signed a legacy line.
    fn key_id(&self) -> Read<&str>;
}

/// ONE PIECE OF SEALING EVIDENCE: a page stamp or a break notice. Equality is exact equality of
/// the supplied evidence (the anchor must be one of the supplied stamps).
pub trait Evidence: PartialEq {
    /// Whether the evidence is a break notice rather than a page stamp.
    fn is_break(&self) -> Read<bool>;
    /// The evidence as a break notice.
    fn notice(&self) -> Read<BreakNotice>;
    /// The journal position the evidence was read at; `None` for evidence read elsewhere.
    fn node_seq(&self) -> Read<Option<u64>>;
    /// The evidence as a page stamp.
    fn stamp(&self) -> Read<Stamp>;
}

/// The node's seal row, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealRow {
    /// The node shut down cleanly through `through`.
    Clean {
        /// The node that wrote the row.
        sealer: u64,
        /// The last sealed position.
        through: u64,
    },
    /// A restart page sealed the node's unsealed suffix.
    Stamp {
        /// The node that wrote the row.
        sealer: u64,
        /// The restart page.
        stamp: Stamp,
    },
    /// A break notice names the node's unsealed suffix.
    Break {
        /// The node that wrote the row.
        sealer: u64,
        /// The break notice.
        notice: BreakNotice,
    },
}

impl SealRow {
    /// The row's outcome as reported.
    #[must_use]
    pub fn outcome(&self) -> SealOutcome {
        match self {
            Self::Clean { .. } => SealOutcome::Clean,
            Self::Stamp { .. } => SealOutcome::Stamp,
            Self::Break { .. } => SealOutcome::Break,
        }
    }
}

/// A seal row's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealOutcome {
    /// `clean`.
    Clean,
    /// `stamp`.
    Stamp,
    /// `break`.
    Break,
}

impl SealOutcome {
    /// The outcome's tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Stamp => "stamp",
            Self::Break => "break",
        }
    }
}

/// THE WINDOW AND ITS EVIDENCE: one node's requested lines, their cover, the certificates, the
/// stamps and breaks, the seal row and the source anchor.
pub trait LinkedRange {
    /// A walked line.
    type Line: WalkedLine;
    /// A stamp or break.
    type Evidence: Evidence;
    /// The first requested chain position.
    fn from(&self) -> Read<u64>;
    /// The last requested chain position.
    fn to(&self) -> Read<u64>;
    /// The requested lines, in chain order.
    fn records(&self) -> Read<Vec<Self::Line>>;
    /// The lines after the requested window that reach the stamps covering it.
    fn cover(&self) -> Read<Vec<Self::Line>>;
    /// The certificates the stamps name, when supplied apart from the walk.
    fn certs(&self) -> Read<Option<Vec<Self::Line>>>;
    /// The stamps and breaks, in journal order.
    fn stamps(&self) -> Read<Vec<Self::Evidence>>;
    /// The node's seal row, when there is one.
    fn seal_row(&self) -> Read<Option<SealRow>>;
    /// The source anchor, when there is one.
    fn anchor(&self) -> Read<Option<Self::Evidence>>;
}

/// AN INDEPENDENTLY RETAINED TERMINAL HEAD (rule 6).
pub trait TrustedHead {
    /// The head's recipe, checked against its envelope.
    fn recipe(&self) -> Read<&str>;
    /// The terminal stamp.
    fn head(&self) -> Read<Stamp>;
    /// The chain position after the head.
    fn next_seq(&self) -> Read<u64>;
}

/// How far a window is established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// Every requested line is authenticated through the independently retained head.
    CompleteThroughTrustedHead,
    /// At least one requested line is authenticated.
    SignedConsistentWindow,
}

impl Standing {
    /// The standing as reported.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CompleteThroughTrustedHead => "complete-through-trusted-head",
            Self::SignedConsistentWindow => "signed-consistent-window",
        }
    }
}

/// A restart page overlapping the window, clipped to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartSealed {
    /// The first position, within the window.
    pub from: u64,
    /// The last position, within the window.
    pub to: u64,
    /// When the node went down.
    pub down_from_ms: u64,
    /// When the restart sealed it.
    pub down_to_ms: u64,
    /// The node that sealed it.
    pub sealer: u64,
}

/// THE VERDICT on a linked window that passed every rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// How far the window is established; `None` when no requested line is authenticated.
    pub standing: Option<Standing>,
    /// The first requested position.
    pub from: u64,
    /// The last requested position.
    pub to: u64,
    /// How many lines were requested.
    pub records: usize,
    /// Whether the window ends at the independently retained head.
    pub trusted_terminal_head: bool,
    /// Live pages overlapping the window.
    pub live_pages: usize,
    /// Final pages overlapping the window.
    pub final_pages: usize,
    /// Restart pages overlapping the window.
    pub restart_sealed: Vec<RestartSealed>,
    /// Every break notice, as supplied.
    pub breaks: Vec<BreakNotice>,
    /// The first position of the unauthenticated tail, when the window ends unsealed.
    pub unauthenticated_tail: Option<u64>,
    /// Pages whose endpoint was not walked.
    pub unchecked_stamps: usize,
    /// Legacy lines authenticated by their own signature.
    pub legacy_signed_lines: usize,
    /// The crypto backends of the pages overlapping the window.
    pub crypto: BTreeSet<String>,
    /// Requested lines authenticated.
    pub authenticated_records: usize,
    /// Whether every requested line is authenticated with no break and no unchecked page.
    pub all_requested_records_authenticated: bool,
    /// Pages a certified notary key signed.
    pub certified_pages: usize,
    /// The seal row's outcome, when there is one.
    pub seal_row: Option<SealOutcome>,
}

fn hex(text: &str, bytes: usize) -> bool {
    text.len() == bytes * 2
        && text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// A legacy line's own signature under a trusted key.
fn signed<L: WalkedLine>(line: &L, keys: &BTreeMap<String, AuditVerifyingKey>) -> Read<()> {
    let hash = line.hash()?;
    let signature = line.signature()?;
    if !hex(hash, 32) || !hex(signature, 64) {
        return Err("a digest or signature is not canonical lowercase hex");
    }
    let key = keys
        .get(line.key_id()?)
        .ok_or("a signing key is not trusted")?;
    key.verify_digest(hash, signature)
        .map_err(|_| "an audit signature is invalid")
}

fn overlaps(a: u64, b: u64, c: u64, d: u64) -> bool {
    a <= b && c <= d && a <= d && c <= b
}

fn explained_gap(from: u64, to: u64, breaks: &BTreeMap<u64, BreakNotice>) -> bool {
    let mut next = from;
    for notice in breaks.values() {
        if notice.unsealed_to < next || notice.unsealed_from > notice.unsealed_to {
            continue;
        }
        if notice.unsealed_from > next {
            return false;
        }
        if notice.unsealed_to >= to {
            return true;
        }
        let Some(after) = notice.unsealed_to.checked_add(1) else {
            return false;
        };
        next = after;
    }
    false
}

/// The break notices seen so far: by `unsealed_from` (non-empty ranges only, which can account
/// for a missing position) and as reported.
#[derive(Default)]
struct Breaks {
    ranges: BTreeMap<u64, BreakNotice>,
    rows: Vec<BreakNotice>,
}

impl Breaks {
    /// RULE 4: a break notice is signed by the Bootstrap key, names this node and a sane range,
    /// and overlaps no other.
    fn add(&mut self, notice: BreakNotice, node: u64, key: &AuditVerifyingKey) -> Read<()> {
        let empty = notice.unsealed_to.checked_add(1) == Some(notice.unsealed_from);
        if notice.node != node
            || notice.unsealed_from == 0
            || notice.last_good >= notice.unsealed_from
            || (notice.unsealed_to < notice.unsealed_from && !empty)
            || (!empty && notice.journal_from > notice.journal_to)
        {
            return Err("invalid break range or node");
        }
        notice
            .verify(key)
            .map_err(|_| "a break signature is invalid")?;
        if self.ranges.values().any(|prior| {
            overlaps(
                prior.unsealed_from,
                prior.unsealed_to,
                notice.unsealed_from,
                notice.unsealed_to,
            )
        }) {
            return Err("break intervals overlap");
        }
        self.rows.push(notice.clone());
        // Empty intervals remain reported, but cannot account for any missing position.
        if !empty {
            self.ranges.insert(notice.unsealed_from, notice);
        }
        Ok(())
    }
}

/// RULE 3, which key may sign which page (decision 159; CRYPTO-SEAM §2.5 key map), applied in
/// journal order. A page with `key_cert = 0` verifies under the Bootstrap key. Only a `live` or
/// `final` page may name a certificate, and then only the current one: the newest valid
/// certificate read before the page, not ended by a valid `final` or `after_restart` page read
/// between them. Its key id and algorithm are the certificate's, the certificate's line is at or
/// before the page's `to`, and the page verifies under the certified key. Evidence with no journal
/// position (the seal row) comes after every journal row. Returns how many pages a certified key
/// signed.
fn check_keys(
    pages: &[(Option<u64>, Stamp)],
    certs: &BTreeMap<u64, NotaryKeyRecord>,
    key: &AuditVerifyingKey,
) -> Read<usize> {
    #[derive(Clone, Copy)]
    enum Event {
        Cert(u64),
        Page(usize),
    }
    let mut events: Vec<(u64, u8, Event)> = certs
        .keys()
        .map(|&at| (at, 0, Event::Cert(at)))
        .chain(
            pages
                .iter()
                .enumerate()
                .map(|(index, (at, _))| (at.unwrap_or(u64::MAX), 1, Event::Page(index))),
        )
        .collect();
    events.sort_by_key(|&(at, rank, _)| (at, rank));
    let mut current = None;
    let mut certified = 0;
    for (_, _, event) in events {
        let index = match event {
            Event::Cert(at) => {
                current = Some(at);
                continue;
            }
            Event::Page(index) => index,
        };
        let (at, page) = &pages[index];
        if page.key_cert == 0 {
            page.verify(key)
                .map_err(|_| "a stamp signature is invalid")?;
        } else {
            let cert = certs
                .get(&page.key_cert)
                .filter(|_| current == Some(page.key_cert))
                .filter(|_| at.is_some_and(|at| at > page.key_cert))
                .filter(|cert| {
                    matches!(page.kind, StampKind::Live | StampKind::Final)
                        && cert.seq <= page.to
                        && page.key_id == cert.certificate.key_id
                        && page.sig_alg == cert.certificate.sig_alg
                })
                .ok_or("stamp key not certified")?;
            let delegated = cert
                .certificate
                .key()
                .map_err(|_| "stamp key not certified")?;
            crypto::verify(&delegated, &page.preimage(), &page.signature)
                .map_err(|_| "a stamp signature is invalid")?;
            certified += 1;
        }
        if matches!(page.kind, StampKind::Final | StampKind::AfterRestart) {
            current = None;
        }
    }
    Ok(certified)
}

/// Check one node's linked window: rule 1 (every walked line recomputes and links), certificate
/// retention, rules 3 and 4 (the stamps, the break-interval book, the key map, no overlaps, every
/// gap explained by a signed break), the anchor, rule 5 (coverage) and rule 6 (the trusted head).
/// `keys` is the caller's trusted key set; exactly one key, the deployment Bootstrap key, is
/// accepted.
pub fn verify<R: LinkedRange, H: TrustedHead>(
    keys: &BTreeMap<String, AuditVerifyingKey>,
    range: &R,
    head: Option<&H>,
) -> Read<Verdict> {
    if keys.len() != 1 {
        return Err(
            "linked verification requires one independently trusted deployment Bootstrap key",
        );
    }
    let key = keys.values().next().ok_or("the trusted key set is empty")?;
    let bootstrap = PublicKey::new(
        SigAlg::Ed25519,
        &hex::decode(key.public_key_hex()).map_err(|_| "invalid audit public key")?,
    );
    let from = range.from()?;
    let to = range.to()?;
    if from == 0 || to < from {
        return Err("requested range must start at one or later and end at or after its start");
    }
    let records = range.records()?;
    if u64::try_from(records.len()).ok() != Some(to - from + 1) {
        return Err("the requested fetch is incomplete or contains extra records");
    }
    let cover = range.cover()?;
    let walked: Vec<&R::Line> = records.iter().chain(cover.iter()).collect();

    // RULE 1: every walked line recomputes by its own recipe and links to its predecessor.
    let mut previous = None;
    let node = records[0].node()?;
    let mut authenticated = vec![false; records.len()];
    let mut legacy_signed = 0;
    let mut walked_certs: BTreeMap<u64, (u64, Fingerprint)> = BTreeMap::new();
    let mut certs: BTreeMap<u64, NotaryKeyRecord> = BTreeMap::new();
    for (index, line) in walked.iter().enumerate() {
        let seq = line.seq()?;
        if from.checked_add(u64::try_from(index).map_err(|_| "record position overflow")?)
            != Some(seq)
        {
            return Err("records and cover are not consecutive");
        }
        if line.node()? != node {
            return Err("a line names another node");
        }
        let prev = line.prev_hash()?;
        if let Some(expected) = previous {
            if prev != expected {
                return Err("a record does not link to its predecessor");
            }
        } else if (seq == 1 && !prev.is_empty()) || (seq > 1 && !hex(prev, 32)) {
            return Err("the first record's predecessor is invalid");
        }
        let hash = line.hash()?;
        let recipe = line.recipe()?;
        if recipe == NOTARY_KEY_RECORD_DOMAIN {
            let (at, cert) = line.certificate()?;
            if cert.fingerprint != cert.recompute_fingerprint() {
                return Err("a record does not hash to its published fields");
            }
            walked_certs.insert(seq, (at, cert.fingerprint));
            if certs
                .insert(at, cert.clone())
                .is_some_and(|prior| prior != cert)
            {
                return Err("a certificate line is reported twice with different content");
            }
        } else {
            if !hex(hash, 32) || line.digest()? != hash {
                return Err("a record does not hash to its published fields");
            }
            if recipe != LINK_RECIPE {
                signed(*line, keys)?;
                if let Some(checked) = authenticated.get_mut(index) {
                    *checked = true;
                    legacy_signed += 1;
                }
            }
        }
        previous = Some(hash);
    }
    let walked_from = from;
    let walked_to = from + (walked.len() as u64) - 1;

    // The certificates the stamps name. One that fails its own checks certifies nothing: a stamp
    // naming it is "stamp key not certified", and it ends no other key.
    if let Some(values) = range.certs()? {
        for value in &values {
            let (at, cert) = value.certificate()?;
            if certs
                .insert(at, cert.clone())
                .is_some_and(|prior| prior != cert)
            {
                return Err("a certificate line is reported twice with different content");
            }
        }
    }
    certs.retain(|at, cert| {
        let in_place = if (walked_from..=walked_to).contains(&cert.seq) {
            walked_certs.get(&cert.seq) == Some(&(*at, cert.fingerprint))
        } else {
            true
        };
        in_place && cert.node == node && cert.verify(&bootstrap).is_ok()
    });

    // RULES 3 AND 4: the stamps and break notices, from the journal and from the seal row.
    let values = range.stamps()?;
    let mut pages: Vec<(Option<u64>, Stamp)> = Vec::new();
    let mut breaks = Breaks::default();
    let mut admit = |at: Option<u64>, page: Stamp| -> Read<()> {
        if page.from == 0 || page.to < page.from || page.node != node {
            return Err("invalid stamp range or node");
        }
        if page.kind != StampKind::AfterRestart && page.sealer != page.node {
            return Err("a live or final stamp names another sealer");
        }
        if page.kind == StampKind::AfterRestart && page.key_cert != 0 {
            return Err("stamp key not certified");
        }
        pages.push((at, page));
        Ok(())
    };
    for value in &values {
        if value.is_break()? {
            breaks.add(value.notice()?, node, key)?;
            continue;
        }
        admit(value.node_seq()?, value.stamp()?)?;
    }
    let mut seal_row = None;
    if let Some(row) = range.seal_row()? {
        let outcome = row.outcome();
        match row {
            SealRow::Clean { .. } => {}
            SealRow::Stamp {
                sealer,
                stamp: page,
            } => {
                if page.kind != StampKind::AfterRestart || page.sealer != sealer {
                    return Err("the node's seal row does not verify");
                }
                admit(None, page)?;
            }
            SealRow::Break { sealer, notice } => {
                if notice.sealer != sealer {
                    return Err("the node's seal row does not verify");
                }
                breaks.add(notice, node, key)?;
            }
        }
        seal_row = Some(outcome);
    }
    let certified = check_keys(&pages, &certs, key)?;
    let mut pages: Vec<Stamp> = pages.into_iter().map(|(_, page)| page).collect();
    pages.sort_by_key(|page| (page.from, page.to));
    if pages.windows(2).any(|pair| pair[1].from <= pair[0].to) {
        return Err("stamp pages overlap");
    }
    let breaks_by_from = breaks.ranges;
    for page in &pages {
        if breaks_by_from
            .values()
            .any(|notice| overlaps(page.from, page.to, notice.unsealed_from, notice.unsealed_to))
        {
            return Err("a break overlaps a signed page");
        }
    }
    for pair in pages.windows(2) {
        let next = pair[0].to.checked_add(1).ok_or("page position overflow")?;
        if next < pair[1].from && !explained_gap(next, pair[1].from - 1, &breaks_by_from) {
            return Err("a gap between stamp pages has no signed break");
        }
    }
    if let Some(anchor) = range.anchor()? {
        anchor.stamp()?;
        if !values.iter().any(|value| value == &anchor) {
            return Err("the source anchor is not an exact supplied page stamp");
        }
    }

    // RULE 3 (coverage) AND RULE 5: a page authenticates the walked lines from its `from` to its
    // `to` when its fingerprint is line `to`'s hash; a page whose `to` is not walked is unchecked.
    let mut accepted = Vec::new();
    let mut live = 0;
    let mut finals = 0;
    let mut restarts = Vec::new();
    let mut unchecked = 0;
    let mut crypto_backends = BTreeSet::new();
    for page in pages {
        let endpoint = page
            .to
            .checked_sub(from)
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| walked.get(index));
        let Some(endpoint) = endpoint else {
            unchecked += 1;
            continue;
        };
        if endpoint.hash()? != page.fingerprint.to_string() {
            return Err("a stamp fingerprint differs from its endpoint");
        }
        for (index, line) in walked.iter().enumerate() {
            let seq = line.seq()?;
            if page.from <= seq && seq <= page.to {
                let recipe = line.recipe()?;
                if recipe != LINK_RECIPE && recipe != NOTARY_KEY_RECORD_DOMAIN {
                    return Err("a page covers a legacy line");
                }
                if let Some(checked) = authenticated.get_mut(index) {
                    *checked = true;
                }
            }
        }
        if overlaps(from, to, page.from, page.to) {
            match page.kind {
                StampKind::Live => live += 1,
                StampKind::Final => finals += 1,
                StampKind::AfterRestart => restarts.push(RestartSealed {
                    from: page.from.max(from),
                    to: page.to.min(to),
                    down_from_ms: page.down_from_ms,
                    down_to_ms: page.down_to_ms,
                    sealer: page.sealer,
                }),
            }
            crypto_backends.insert(page.crypto.clone());
        }
        accepted.push(page);
    }
    let last_authenticated = accepted.last().map_or(0, |page| page.to);
    let mut tail_from = None;
    let mut authenticated_records = 0;
    for (index, checked) in authenticated.iter().enumerate() {
        if *checked {
            authenticated_records += 1;
            continue;
        }
        let seq = records[index].seq()?;
        if breaks_by_from
            .values()
            .any(|notice| notice.unsealed_from <= seq && seq <= notice.unsealed_to)
        {
            continue;
        }
        if seq <= last_authenticated {
            return Err("an interior line is covered by neither a stamp nor a signed break");
        }
        tail_from.get_or_insert(seq);
    }
    let complete = authenticated.iter().all(|checked| *checked)
        && !breaks_by_from
            .values()
            .any(|notice| overlaps(from, to, notice.unsealed_from, notice.unsealed_to))
        && unchecked == 0;

    // RULE 6: the independently retained head.
    let trusted = if let Some(head) = head {
        if head.recipe()? != LINK_RECIPE {
            return Err("a linked window requires a stamp head");
        }
        let terminal = head.head()?;
        if terminal.to != to
            || head.next_seq()? != to.checked_add(1).ok_or("head position overflow")?
        {
            return Err("the requested range does not end at the independently trusted head");
        }
        if !complete || !accepted.iter().any(|page| page == &terminal) {
            return Err("trusted head has incomplete coverage or is not a checked covering stamp");
        }
        true
    } else {
        false
    };
    let standing = if trusted {
        Some(Standing::CompleteThroughTrustedHead)
    } else if authenticated_records != 0 {
        Some(Standing::SignedConsistentWindow)
    } else {
        None
    };
    Ok(Verdict {
        standing,
        from,
        to,
        records: records.len(),
        trusted_terminal_head: trusted,
        live_pages: live,
        final_pages: finals,
        restart_sealed: restarts,
        breaks: breaks.rows,
        unauthenticated_tail: tail_from,
        unchecked_stamps: unchecked,
        legacy_signed_lines: legacy_signed,
        crypto: crypto_backends,
        authenticated_records,
        all_requested_records_authenticated: complete,
        certified_pages: certified,
        seal_row,
    })
}

#[cfg(test)]
#[path = "tests/linked_walk_tests.rs"]
mod tests;
