// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::json::{self, json, Value};
use busbar_core_admin::GovernanceError;
use busbar_kernel::persistence::boot_identity::{read_seal_row, SealOutcome, SealRow};
use busbar_kernel_audit::journal::head_from_journal_body;
use busbar_kernel_audit::{
    break_from_journal_body, expose, notary_key_from_journal_body, stamp_from_journal_body,
    BreakNotice, NotaryKeyRecord, Stamp,
};
use std::collections::BTreeMap;

/// Positions projected into one response after native whole-history verification
/// within the configured memory budget. The ring holds at most AUDIT_RING records.
const SCAN_POSITIONS: u64 = 64;

/// At most this many lines after a page's last record are returned as `cover`, the walk from the
/// page to its covering stamp (SEALING-FIX §3.5 "Reads"). A covering stamp farther away leaves
/// the page's trailing lines unauthenticated at verify, never sealed.
const COVER_LINES: u64 = AUDIT_RING as u64;

struct Cursor {
    node: u64,
    incarnation: u64,
    from: u64,
    to: u64,
    snapshot_to: u64,
    journal_end: u64,
    next_journal: u64,
    next_audit: u64,
    incomplete: bool,
}

impl Cursor {
    fn decode(token: &str) -> Option<Self> {
        if token.len() > 256 {
            return None;
        }
        let rest = token.strip_prefix("ar1.")?;
        let numbers: Vec<u64> = rest
            .split('.')
            .map(str::parse)
            .collect::<Result<_, _>>()
            .ok()?;
        let [node, incarnation, from, to, snapshot_to, journal_end, next_journal, next_audit, incomplete] =
            numbers.as_slice()
        else {
            return None;
        };
        if *incomplete > 1
            || *next_journal == 0
            || next_journal > journal_end
            || next_audit < &(*from).max(1)
            || snapshot_to > to
        {
            return None;
        }
        Some(Self {
            node: *node,
            incarnation: *incarnation,
            from: *from,
            to: *to,
            snapshot_to: *snapshot_to,
            journal_end: *journal_end,
            next_journal: *next_journal,
            next_audit: *next_audit,
            incomplete: *incomplete == 1,
        })
    }

    fn encode(&self) -> String {
        format!(
            "ar1.{}.{}.{}.{}.{}.{}.{}.{}.{}",
            self.node,
            self.incarnation,
            self.from,
            self.to,
            self.snapshot_to,
            self.journal_end,
            self.next_journal,
            self.next_audit,
            u8::from(self.incomplete)
        )
    }
}

/// One chain line of a page: a unit line, or a `notary_key` certificate line with its WAL
/// `node_seq`. Both take a chain `seq`; a range read that dropped certificate lines would show a
/// hole in the chain.
#[derive(Clone)]
enum Line {
    Unit(AuditRecord),
    NotaryKey(u64, NotaryKeyRecord),
}

impl Line {
    fn seq(&self) -> u64 {
        match self {
            Line::Unit(record) => record.seq,
            Line::NotaryKey(_, record) => record.seq,
        }
    }

    fn json(&self) -> Result<Value, GovernanceError> {
        let text = match self {
            Line::Unit(record) => expose::record_json(record),
            Line::NotaryKey(at, record) => expose::notary_key_json(*at, record),
        };
        parse(&text)
    }
}

fn parse(text: &str) -> Result<Value, GovernanceError> {
    json::parse_value(text.as_bytes()).map_err(|_| GovernanceError::Store)
}

/// What the node's journal holds besides its unit lines, read once per page: its stamps, break
/// notices and certificate lines, each with its WAL `node_seq`.
#[derive(Default)]
struct Evidence {
    stamps: Vec<(u64, Stamp)>,
    breaks: Vec<(u64, BreakNotice)>,
    certs: BTreeMap<u64, NotaryKeyRecord>,
}

impl Evidence {
    /// Sort every stamp, notice and certificate out of the journal rows. A body that names one of
    /// their tags but does not decode is left out: it authenticates nothing, so the lines it would
    /// have vouched for stay unauthenticated at verify.
    fn read(rows: &[JournalRecord]) -> Self {
        let mut evidence = Evidence::default();
        for row in rows {
            if row.class != RecordClass::Transaction {
                continue;
            }
            if let Ok(Some(stamp)) = stamp_from_journal_body(&row.body) {
                evidence.stamps.push((row.node_seq, stamp));
            } else if let Ok(Some(notice)) = break_from_journal_body(&row.body) {
                evidence.breaks.push((row.node_seq, notice));
            } else if let Ok(Some(cert)) = notary_key_from_journal_body(&row.body) {
                evidence.certs.insert(row.node_seq, cert);
            }
        }
        evidence
    }

    /// The certificate lines whose chain `seq` lies in `from..=to`, as lines.
    fn cert_lines(&self, from: u64, to: u64) -> impl Iterator<Item = Line> + '_ {
        self.certs
            .iter()
            .filter(move |(_, cert)| cert.seq >= from && cert.seq <= to)
            .map(|(at, cert)| Line::NotaryKey(*at, cert.clone()))
    }
}

/// THE COVER (SEALING-FIX §3.5 "Reads"): the lines `after ..= to`, oldest first, from the journal
/// rows, stopping at the first position the journal does not hold. Authentication evidence, not
/// part of the range.
fn cover_lines(
    rows: &[JournalRecord],
    evidence: &Evidence,
    after: u64,
    to: u64,
) -> Result<Vec<Line>, GovernanceError> {
    let mut lines: BTreeMap<u64, Line> = evidence
        .cert_lines(after.saturating_add(1), to)
        .map(|line| (line.seq(), line))
        .collect();
    for row in rows {
        if row.class != RecordClass::Transaction {
            continue;
        }
        let Ok(Some(head)) = head_from_journal_body(&row.body) else {
            continue;
        };
        if head.head.seq <= after || head.head.seq > to {
            continue;
        }
        if let Some(unit) = decode_audit(row).map_err(|_| GovernanceError::Store)? {
            lines.insert(unit.seq, Line::Unit(unit));
        }
    }
    let mut cover = Vec::new();
    let mut next = after.saturating_add(1);
    while next <= to {
        let Some(line) = lines.remove(&next) else {
            break;
        };
        cover.push(line);
        next = next.saturating_add(1);
    }
    Ok(cover)
}

/// THE NODE'S SEAL ROW as the range read prints it (§3.5 "Reads", §3.7 rule 4): `null` when there
/// is none; its sealer and outcome when it decodes, the signed stamp or break notice it holds
/// printed as the stamps are; `undecodable` when it does not, which verify refuses.
fn seal_row_json(row: Option<&[u8]>) -> Result<Value, GovernanceError> {
    let Some(bytes) = row else {
        return Ok(Value::new());
    };
    let Ok(row) = SealRow::parse(bytes) else {
        return Ok(json!({"outcome": "undecodable"}));
    };
    Ok(match row.outcome {
        SealOutcome::Clean { through } => {
            json!({"sealer": row.sealer, "outcome": "clean", "through": through})
        }
        SealOutcome::Stamp(body) => match stamp_from_journal_body(&body) {
            Ok(Some(stamp)) => json!({"sealer": row.sealer, "outcome": "stamp",
                "stamp": parse(&expose::stamp_json(None, &stamp))?}),
            _ => json!({"sealer": row.sealer, "outcome": "undecodable"}),
        },
        SealOutcome::Break(body) => match break_from_journal_body(&body) {
            Ok(Some(notice)) => json!({"sealer": row.sealer, "outcome": "break",
                "break": parse(&expose::break_json(None, &notice))?}),
            _ => json!({"sealer": row.sealer, "outcome": "undecodable"}),
        },
    })
}

/// Captured under the durability lock; all Store calls run after releasing it.
pub(crate) struct AuditPagePlan {
    body: Value,
    cursor: Cursor,
    records: Vec<Line>,
    chain: ChainAt,
    journal: Arc<RuntimeJournal>,
    scan: bool,
    scan_end: u64,
    exhausted: bool,
}

impl Durability {
    pub(crate) fn prepare_audit_page(
        &self,
        from: u64,
        to: u64,
        token: Option<&str>,
    ) -> Result<AuditPagePlan, GovernanceError> {
        if from > to {
            return Err(GovernanceError::Validation);
        }
        let cursor = if let Some(token) = token {
            let cursor = Cursor::decode(token).ok_or(GovernanceError::Validation)?;
            if cursor.node != self.journal.node()
                || cursor.incarnation != self.incarnation
                || cursor.from != from
                || cursor.to != to
                || cursor.journal_end > self.journal.next_seq()
                || cursor.snapshot_to > self.record.next_seq().saturating_sub(1)
            {
                return Err(GovernanceError::Validation);
            }
            cursor
        } else {
            Cursor {
                node: self.journal.node(),
                incarnation: self.incarnation,
                from,
                to,
                snapshot_to: to.min(self.record.next_seq().saturating_sub(1)),
                journal_end: self.journal.next_seq(),
                next_journal: 1,
                next_audit: from.max(1),
                incomplete: false,
            }
        };
        let mut body = parse(&expose::range_envelope(from, to))?;
        // The upper bound is fixed by the first page; later appends cannot move it.
        body["snapshot_to"] = json!(cursor.snapshot_to.to_string());
        body["semantics"] = json!("bounded_live_range");
        body["retention"] = json!({
            "ring_from": self.audit_records().first().map(|r| r.seq.to_string()),
            "ring_to": self.audit_records().last().map(|r| r.seq.to_string()),
            "durable_from": null,
            "durable_from_known": false,
        });
        let covered = self
            .audit_records()
            .first()
            .is_some_and(|r| r.seq <= cursor.next_audit);
        let exhausted = cursor.next_audit > cursor.snapshot_to;
        let scan_end = cursor
            .next_journal
            .saturating_add(SCAN_POSITIONS)
            .min(cursor.journal_end);
        let scan = !(exhausted || covered);
        let records = if scan {
            Vec::new()
        } else {
            self.audit_records()
                .iter()
                .filter(|r| r.seq >= cursor.next_audit && r.seq <= cursor.snapshot_to)
                .cloned()
                .map(Line::Unit)
                .collect()
        };
        Ok(AuditPagePlan {
            body,
            cursor,
            records,
            chain: self.chain_at(),
            journal: self.journal.clone(),
            scan,
            scan_end,
            exhausted,
        })
    }
}

impl AuditPagePlan {
    pub async fn finish(mut self) -> Result<Vec<u8>, GovernanceError> {
        // One read of the node's journal serves the page's scan and its evidence.
        let rows = self
            .chain
            .read()
            .await
            .map_err(|_| GovernanceError::Store)?
            .map_err(|_| GovernanceError::Store)?;
        let evidence = Evidence::read(&rows);
        let first_audit = self.cursor.next_audit;
        let scanned = if self.scan {
            let window: Vec<_> = rows
                .iter()
                .filter(|record| {
                    record.node_seq >= self.cursor.next_journal && record.node_seq < self.scan_end
                })
                .collect();
            let incomplete =
                window.len() as u64 != self.scan_end.saturating_sub(self.cursor.next_journal);
            let scanned = self.scan_end.saturating_sub(self.cursor.next_journal);
            self.cursor.incomplete |= incomplete;
            for record in window {
                if let Some(audit) = decode_audit(record).map_err(|_| GovernanceError::Store)? {
                    if audit.seq >= self.cursor.next_audit && audit.seq <= self.cursor.snapshot_to {
                        self.records.push(Line::Unit(audit));
                    }
                } else if let Some(cert) = evidence.certs.get(&record.node_seq) {
                    if cert.seq >= self.cursor.next_audit && cert.seq <= self.cursor.snapshot_to {
                        self.records
                            .push(Line::NotaryKey(record.node_seq, cert.clone()));
                    }
                }
            }
            self.cursor.next_journal = self.scan_end;
            self.exhausted |= self.scan_end >= self.cursor.journal_end;
            scanned
        } else {
            // The ring holds unit lines only: a certificate line in the window comes from the
            // journal read.
            let certs: Vec<_> = evidence
                .cert_lines(first_audit, self.cursor.snapshot_to)
                .collect();
            self.records.extend(certs);
            self.records.sort_by_key(Line::seq);
            self.exhausted = true;
            0
        };
        // Audit positions are monotonic even though the journal also carries non-audit records.
        let mut gaps = Vec::new();
        for record in &self.records {
            let seq = record.seq();
            if seq < self.cursor.next_audit {
                return Err(GovernanceError::Store);
            }
            if seq > self.cursor.next_audit {
                gaps.push(json!({"from": self.cursor.next_audit.to_string(), "to": (seq - 1).to_string()}));
            }
            self.cursor.next_audit = seq.checked_add(1).ok_or(GovernanceError::Store)?;
        }
        self.exhausted |= self.cursor.next_audit > self.cursor.snapshot_to;
        if self.exhausted && self.cursor.next_audit <= self.cursor.to {
            gaps.push(json!({"from": self.cursor.next_audit.to_string(), "to": self.cursor.to.to_string()}));
        }
        self.cursor.incomplete |= !gaps.is_empty();
        let records = self
            .records
            .iter()
            .filter(|line| line.seq() >= self.cursor.from && line.seq() <= self.cursor.to)
            .map(Line::json)
            .collect::<Result<Vec<_>, _>>()?;
        self.body["records"] = Value::from(records);
        page_evidence(
            &mut self.body,
            &self.records,
            &self.journal,
            &rows,
            &evidence,
        )
        .await?;
        self.body["returned_from"] = json!(self.records.first().map(|r| r.seq().to_string()));
        self.body["returned_to"] = json!(self.records.last().map(|r| r.seq().to_string()));
        self.body["next_cursor"] = json!((!self.exhausted).then(|| self.cursor.encode()));
        self.body["truncated"] = json!(!self.exhausted);
        self.body["complete"] = json!(self.exhausted && !self.cursor.incomplete);
        self.body["incomplete"] = json!(self.cursor.incomplete);
        self.body["gaps"] = json!(gaps);
        self.body["scanned_positions"] = json!(scanned.to_string());
        self.body["scan_limit"] = json!(SCAN_POSITIONS.to_string());
        json::to_vec(&self.body).map_err(|_| GovernanceError::Store)
    }
}

/// THE PAGE'S AUTHENTICATION EVIDENCE (SEALING-FIX §3.5 "Reads", per page): for the page's
/// returned lines `[first, last]`, every stamp overlapping them plus the covering stamp of
/// `last` (the first stamp whose `to` is at or after it), as `stamps`; that covering stamp as
/// `anchor`; the lines `last+1 ..= covering.to` as `cover` (bounded by [`COVER_LINES`]); every
/// break notice over the walked lines; the certificate line each returned stamp's `key_cert`
/// names, as `certs`; and the node's seal row. A page with no lines carries no stamps.
async fn page_evidence(
    body: &mut Value,
    records: &[Line],
    journal: &RuntimeJournal,
    rows: &[JournalRecord],
    evidence: &Evidence,
) -> Result<(), GovernanceError> {
    let seal_row = read_seal_row(journal)
        .await
        .map_err(|_| GovernanceError::Store)?;
    body["seal_row"] = seal_row_json(seal_row.as_deref())?;
    let (Some(first), Some(last)) = (
        records.first().map(Line::seq),
        records.last().map(Line::seq),
    ) else {
        body["stamps"] = json!([]);
        body["cover"] = json!([]);
        body["certs"] = json!([]);
        body["anchor"] = Value::new();
        return Ok(());
    };
    let covering = evidence
        .stamps
        .iter()
        .filter(|(_, stamp)| stamp.to >= last)
        .min_by_key(|(_, stamp)| stamp.to);
    let walked_to = covering.map_or(last, |(_, stamp)| {
        stamp.to.min(last.saturating_add(COVER_LINES))
    });
    let cover = cover_lines(rows, evidence, last, walked_to)?;
    let walked_to = cover.last().map_or(last, Line::seq);
    let mut stamps = Vec::new();
    let mut certs = BTreeMap::new();
    for (at, stamp) in &evidence.stamps {
        let overlaps = stamp.from <= last && stamp.to >= first;
        let is_covering = covering.is_some_and(|(covering_at, _)| covering_at == at);
        if !(overlaps || is_covering) {
            continue;
        }
        if stamp.key_cert != 0 {
            if let Some(cert) = evidence.certs.get(&stamp.key_cert) {
                certs.insert(stamp.key_cert, cert);
            }
        }
        stamps.push(parse(&expose::stamp_json(Some(*at), stamp))?);
    }
    for (at, notice) in &evidence.breaks {
        let empty = notice.unsealed_to.checked_add(1) == Some(notice.unsealed_from);
        let relevant = if empty {
            notice.unsealed_from >= first && notice.unsealed_from <= walked_to.saturating_add(1)
        } else {
            notice.unsealed_from <= walked_to && notice.unsealed_to >= first
        };
        if relevant {
            stamps.push(parse(&expose::break_json(Some(*at), notice))?);
        }
    }
    body["stamps"] = Value::from(stamps);
    body["cover"] = Value::from(
        cover
            .iter()
            .map(Line::json)
            .collect::<Result<Vec<_>, _>>()?,
    );
    body["certs"] = Value::from(
        certs
            .into_iter()
            .map(|(at, cert)| parse(&expose::notary_key_json(at, cert)))
            .collect::<Result<Vec<_>, _>>()?,
    );
    body["anchor"] = match covering {
        Some((at, stamp)) => parse(&expose::stamp_json(Some(*at), stamp))?,
        None => Value::new(),
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::durability::tests::{seal, NativeFixture};
    use crate::root::units_admin::{AuditView, NodeAudit};
    use busbar_contract::json::JsonValueTrait;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    async fn seal_records(book: &Arc<Mutex<Durability>>, units: std::ops::RangeInclusive<u64>) {
        for unit in units {
            seal(book, unit).await;
        }
    }

    async fn book(fixture: &NativeFixture, count: u64) -> Arc<Mutex<Durability>> {
        let book = Arc::new(Mutex::new(fixture.book().await));
        seal_records(&book, 1..=count).await;
        fixture.journal.flush().await.unwrap();
        book
    }

    async fn page(view: &NodeAudit, from: u64, to: u64, cursor: Option<&str>) -> Value {
        json::parse_value(&view.range_page(from, to, cursor).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn audit_range_pages_reconstruct_pinned_range_during_concurrent_appends() {
        let fixture = NativeFixture::new(47).await;
        let count = AUDIT_RING as u64 + 200;
        let book = book(&fixture, count).await;
        let view = NodeAudit::new(Arc::clone(&book));
        let scans = Arc::new(AtomicUsize::new(0));
        let appended = Arc::new(AtomicBool::new(false));
        let (observed, flag, held) = (
            Arc::clone(&scans),
            Arc::clone(&appended),
            Arc::downgrade(&book),
        );
        *fixture.faults.on_read.lock().unwrap() = Some(Arc::new(move |request| {
            let (observed, flag, held) = (observed.clone(), flag.clone(), held.clone());
            Box::pin(async move {
                if request
                    .addresses
                    .iter()
                    .any(|at| at.key.get(24) == Some(&b'R'))
                {
                    observed.fetch_add(1, Ordering::Relaxed);
                    let book = held.upgrade().unwrap();
                    // Native reads must cross the Store boundary outside the book lock.
                    drop(
                        book.try_lock()
                            .expect("Store reads run outside durability lock"),
                    );
                    if !flag.swap(true, Ordering::SeqCst) {
                        seal_records(&book, (count + 1)..=(count + 1)).await;
                    }
                }
                Ok(())
            })
        }));
        let mut cursor = None;
        let mut positions = Vec::new();
        let mut pages = 0;
        loop {
            let before = scans.load(Ordering::Relaxed);
            let body = page(&view, 1, count, cursor.as_deref()).await;
            if body["scanned_positions"] != "0" {
                assert!(
                    scans.load(Ordering::Relaxed) > before,
                    "a durable page verifies the selected native history"
                );
            }
            assert!(
                body["scanned_positions"]
                    .as_str()
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
                    <= SCAN_POSITIONS
            );
            assert_eq!(body["snapshot_to"], count.to_string());
            assert_eq!(body["incomplete"], false);
            for record in body["records"].as_array().unwrap() {
                positions.push(record["seq"].as_str().unwrap().parse::<u64>().unwrap());
            }
            pages += 1;
            cursor = body["next_cursor"].as_str().map(str::to_string);
            if cursor.is_none() {
                assert_eq!(body["complete"], true);
                break;
            }
            assert_eq!(body["complete"], false);
            assert!(pages < 100, "bounded progress even under writes");
        }
        assert!(appended.load(Ordering::SeqCst));
        assert!(pages > 1);
        assert_eq!(positions, (1..=count).collect::<Vec<_>>());
        *fixture.faults.on_read.lock().unwrap() = None;
    }

    #[tokio::test]
    async fn audit_range_reports_actual_bounds_gaps_and_unsealed_tail() {
        let fixture = NativeFixture::new(47).await;
        let book = book(&fixture, 5).await;
        book.lock()
            .unwrap()
            .retain_audit_for_tamper_test(|r| r.seq != 3);
        let view = NodeAudit::new(book);
        let body = page(&view, 1, 7, None).await;
        assert_eq!(body["returned_from"], "1");
        assert_eq!(body["returned_to"], "5");
        assert_eq!(body["snapshot_to"], "5");
        assert_eq!(
            body["gaps"],
            json!([{"from":"3", "to":"3"}, {"from":"6", "to":"7"}])
        );
        assert_eq!(body["complete"], false);
        assert_eq!(body["incomplete"], true);
        assert!(body["next_cursor"].is_null());
        assert_eq!(body["retention"]["ring_from"], "1");
        assert_eq!(body["retention"]["durable_from_known"], false);
    }

    #[tokio::test]
    async fn audit_range_continues_empty_scan_pages_and_rejects_changed_scope() {
        let fixture = NativeFixture::new(47).await;
        let book = book(&fixture, AUDIT_RING as u64 + 200).await;
        let view = NodeAudit::new(Arc::clone(&book));
        // First 64 journal positions precede the requested audit range.
        let body = page(&view, 100, 150, None).await;
        assert!(body["records"].as_array().unwrap().is_empty());
        assert!(body["returned_from"].is_null());
        assert_eq!(body["truncated"], true);
        assert_eq!(body["complete"], false);
        let cursor = body["next_cursor"].as_str().unwrap();
        assert!(matches!(
            view.range_page(101, 150, Some(cursor)).await,
            Err(GovernanceError::Validation)
        ));
        book.lock().unwrap().incarnation += 1;
        assert!(matches!(
            view.range_page(100, 150, Some(cursor)).await,
            Err(GovernanceError::Validation)
        ));
        assert!(matches!(
            view.range_page(100, 150, Some("6f3a31")).await,
            Err(GovernanceError::Validation)
        ));
    }

    #[tokio::test]
    async fn audit_range_retention_loss_between_pages_is_explicit() {
        let fixture = NativeFixture::new(47).await;
        let book = book(&fixture, AUDIT_RING as u64 + 200).await;
        let view = NodeAudit::new(Arc::clone(&book));
        let first = page(&view, 1, 1200, None).await;
        assert_eq!(first["incomplete"], false);
        let mut cursor = first["next_cursor"].as_str().map(str::to_string);
        // Change the live retained set after the first page. The later ring page
        // must expose this missing position, even though the initial capture saw it.
        book.lock()
            .unwrap()
            .retain_audit_for_tamper_test(|r| r.seq != 300);
        let mut gap_seen = false;
        for _ in 0..100 {
            let body = page(&view, 1, 1200, cursor.as_deref()).await;
            gap_seen |= body["gaps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|gap| gap == &json!({"from": "300", "to": "300"}));
            cursor = body["next_cursor"].as_str().map(str::to_string);
            if cursor.is_none() {
                assert!(gap_seen);
                assert_eq!(body["incomplete"], true);
                assert_eq!(body["complete"], false);
                return;
            }
        }
        panic!("the fixed upper bound must terminate");
    }

    /// A hand-framed journal body: text and bytes as a big-endian u32 length and the bytes,
    /// numbers as big-endian u64, the journal's own framing, independent of any encoder.
    #[derive(Default)]
    struct Body(Vec<u8>);

    impl Body {
        fn bytes(mut self, bytes: &[u8]) -> Self {
            self.0
                .extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
            self.0.extend_from_slice(bytes);
            self
        }

        fn num(mut self, n: u64) -> Self {
            self.0.extend_from_slice(&n.to_be_bytes());
            self
        }
    }

    /// The `u64`-length framing the certificate preimage and fingerprint use.
    fn framed(fields: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for field in fields {
            out.extend_from_slice(&(field.len() as u64).to_be_bytes());
            out.extend_from_slice(field);
        }
        out
    }

    /// A Bootstrap-signed `audit.notary_key.v2` certificate line for `delegate`, linked after
    /// `prev` at chain `seq` of `node`: its journal body and its fingerprint.
    fn certificate_line(
        node: u64,
        seq: u64,
        prev: [u8; 32],
        bootstrap: &busbar_contract::crypto::LocalSigner,
        delegate: &busbar_contract::crypto::LocalSigner,
    ) -> (Vec<u8>, [u8; 32]) {
        use busbar_contract::crypto::Signer;
        let public = delegate.public_key();
        let (key_id, sig_alg) = (public.key_id.as_bytes(), public.alg.as_str().as_bytes());
        let mut preimage = b"busbar.audit.notary_key.v2\0".to_vec();
        preimage.extend(framed(&[
            &node.to_be_bytes(),
            &seq.to_be_bytes(),
            &prev,
            key_id,
            sig_alg,
            &public.bytes,
        ]));
        let mut signature = Vec::new();
        bootstrap.sign(&preimage, &mut signature).unwrap();
        let signed_by = bootstrap.public_key().key_id.as_bytes();
        let linked_ms = 1_700_000_000_000u64;
        let fingerprint = busbar_contract::crypto::sha256(&framed(&[
            b"busbar.audit.notary_key.record.v2",
            &node.to_be_bytes(),
            key_id,
            sig_alg,
            &public.bytes,
            signed_by,
            &signature,
            &linked_ms.to_be_bytes(),
            &seq.to_be_bytes(),
            &prev,
        ]));
        let body = Body::default()
            .bytes(b"audit.notary_key.v2")
            .bytes(busbar_kernel_audit::LINK_RECIPE.as_bytes())
            .num(seq)
            .bytes(&prev)
            .bytes(&fingerprint)
            .num(linked_ms)
            .num(node)
            .bytes(key_id)
            .bytes(sig_alg)
            .bytes(&public.bytes)
            .bytes(signed_by)
            .bytes(&signature);
        (body.0, fingerprint)
    }

    /// SEALING-FIX §3.5 "Reads": the range read carries, beside its records, the stamps over them
    /// and the covering stamp of `to` (also as `anchor`), the `cover` lines from `to + 1` to that
    /// stamp's `to`, the `notary_key` line each stamp's `key_cert` names (`certs`), and the node's
    /// seal row, under the link recipe's envelope.
    #[tokio::test]
    async fn audit_range_carries_stamps_cover_certs_and_seal_row() {
        use busbar_contract::crypto::LocalSigner;
        use busbar_kernel_audit::{
            stamp_body, AuditSigningKey, Fingerprint, LiveSigner, Notary, Stamp, StampKind,
            LINK_RECIPE, STAMP_DOMAIN,
        };
        let fixture = NativeFixture::new(47).await;
        let book = book(&fixture, 3).await;
        let node = fixture.journal.node();
        let seed = [0x31; 32];
        let delegate_seed = [0x09; 32];
        let third = {
            let held = book.lock().unwrap();
            Fingerprint::from_hex(&held.audit_records().last().unwrap().hash).unwrap()
        };
        let (cert_body, cert_fp) = certificate_line(
            node,
            4,
            third.0,
            &LocalSigner::from_seed(&seed).unwrap(),
            &LocalSigner::from_seed(&delegate_seed).unwrap(),
        );
        let cert_at = book
            .lock()
            .unwrap()
            .stage_entries(&[Entry::new(RecordClass::Transaction, cert_body)])
            .unwrap()
            .records()[0]
            .node_seq;
        let (notary, _) = AuditSigningKey::from_seed(&seed)
            .into_grants(LiveSigner::Delegated(Box::new(
                LocalSigner::from_seed(&delegate_seed).unwrap(),
            )))
            .unwrap();
        let stamp = Notary::new(notary)
            .sign_stamp(Stamp {
                node,
                from: 1,
                to: 4,
                fingerprint: Fingerprint(cert_fp),
                kind: StampKind::Live,
                sealer: node,
                host: "range-host".into(),
                every: 1000,
                stamped_ms: 1_700_000_000_001,
                down_from_ms: 0,
                down_to_ms: 0,
                crypto: String::new(),
                sig_alg: String::new(),
                key_id: String::new(),
                key_cert: cert_at,
                signature: Vec::new(),
            })
            .unwrap();
        let stamp_at = book
            .lock()
            .unwrap()
            .stage_entries(&[Entry::new(
                RecordClass::Transaction,
                stamp_body(&stamp).unwrap(),
            )])
            .unwrap()
            .records()[0]
            .node_seq;
        fixture.journal.flush().await.unwrap();

        let view = NodeAudit::new(Arc::clone(&book));
        let body = page(&view, 1, 3, None).await;
        assert_eq!(body["recipe"], LINK_RECIPE, "{body}");
        assert_eq!(body["signature_domain"], STAMP_DOMAIN);
        assert_eq!(body["records"].as_array().unwrap().len(), 3);
        let stamps = body["stamps"].as_array().expect("stamps are carried");
        assert_eq!(stamps.len(), 1, "{body}");
        let carried = &body["stamps"][0];
        assert_eq!(carried["node_seq"], stamp_at);
        assert_eq!(carried["from"], 1);
        assert_eq!(carried["to"], 4);
        assert_eq!(carried["kind"], "live");
        assert_eq!(carried["key_cert"], cert_at);
        assert_eq!(carried["fingerprint"], Fingerprint(cert_fp).to_string());
        assert_eq!(carried["signature"], hex::encode(&stamp.signature));
        assert_eq!(
            &body["anchor"], carried,
            "the anchor is the covering stamp of `to`"
        );
        let cover = &body["cover"];
        assert_eq!(
            cover.as_array().expect("cover is carried").len(),
            1,
            "line 4 walks from `to` to the stamp"
        );
        assert_eq!(cover[0]["kind"], "notary_key");
        assert_eq!(cover[0]["seq"], "4");
        assert_eq!(cover[0]["node_seq"], cert_at);
        assert_eq!(cover[0]["hash"], Fingerprint(cert_fp).to_string());
        assert_eq!(cover[0]["prev_hash"], third.to_string());
        assert_eq!(
            body["certs"],
            json!([cover[0].clone()]),
            "the certificate the stamp's key_cert names"
        );
        assert!(body["seal_row"].is_null(), "a live node has no seal row");
        assert!(body.get("seal_row").is_some(), "the seal row is reported");
    }

    /// §3.7 rule 4's input: the seal row as the range read prints it, by outcome.
    #[test]
    fn audit_range_seal_row_reports_its_outcome() {
        use busbar_kernel_audit::{
            break_body, AuditSigningKey, BootstrapSigner, BreakNotice, BreakReason, LiveSigner,
        };
        assert!(seal_row_json(None).unwrap().is_null());
        let clean = SealRow {
            sealer: 9,
            outcome: SealOutcome::Clean { through: 12 },
        }
        .bytes();
        assert_eq!(
            seal_row_json(Some(&clean)).unwrap(),
            json!({"sealer": 9u64, "outcome": "clean", "through": 12u64})
        );
        let garbled = SealRow {
            sealer: 9,
            outcome: SealOutcome::Stamp(b"not a stamp".to_vec()),
        }
        .bytes();
        assert_eq!(
            seal_row_json(Some(&garbled)).unwrap(),
            json!({"sealer": 9u64, "outcome": "undecodable"})
        );
        assert_eq!(
            seal_row_json(Some(b"BBSEAL01")).unwrap(),
            json!({"outcome": "undecodable"})
        );
        let (_, bootstrap) = AuditSigningKey::from_seed(&[0x31; 32])
            .into_grants(LiveSigner::SameAsBootstrap)
            .unwrap();
        let notice = BootstrapSigner::new(bootstrap)
            .sign_break(BreakNotice {
                node: 47,
                sealer: 9,
                last_good: 3,
                unsealed_from: 4,
                unsealed_to: 6,
                journal_from: 11,
                journal_to: 13,
                reason: BreakReason::Unsigned,
                detected_ms: 1_700_000_000_002,
                host: "range-host".into(),
                crypto: String::new(),
                sig_alg: String::new(),
                key_id: String::new(),
                signature: Vec::new(),
            })
            .unwrap();
        let row = SealRow {
            sealer: 9,
            outcome: SealOutcome::Break(break_body(&notice).unwrap()),
        }
        .bytes();
        let printed = seal_row_json(Some(&row)).unwrap();
        assert_eq!(printed["sealer"], 9u64);
        assert_eq!(printed["outcome"], "break");
        assert_eq!(printed["break"]["kind"], "break");
        assert_eq!(printed["break"]["unsealed_from"], 4u64);
        assert_eq!(
            printed["break"]["signature"],
            hex::encode(&notice.signature)
        );
        assert!(
            printed["break"].get("node_seq").is_none(),
            "a seal row is not a journal position"
        );
    }
}
