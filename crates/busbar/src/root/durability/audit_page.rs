// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::json::{self, json, Value};
use busbar_core_admin::GovernanceError;
use busbar_kernel_audit::expose;

/// Positions projected into one response after native whole-history verification
/// within the configured memory budget. The ring holds at most AUDIT_RING records.
const SCAN_POSITIONS: u64 = 64;

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

/// Captured under the durability lock; all Store calls run after releasing it.
pub(crate) struct AuditPagePlan {
    body: Value,
    cursor: Cursor,
    records: Vec<AuditRecord>,
    stored: Option<ChainAt>,
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
        let mut body: Value =
            json::parse_value(expose::range_body(&self.record, &[], from, to).as_bytes())
                .map_err(|_| GovernanceError::Store)?;
        // The upper bound is fixed by the first page; later appends cannot move it.
        body["snapshot_to"] = json!(cursor.snapshot_to.to_string());
        body["semantics"] = json!("bounded_live_range");
        body["retention"] = json!({
            "ring_from": self.audit_records().first().map(|r| r.seq.to_string()),
            "ring_to": self.audit_records().last().map(|r| r.seq.to_string()),
            "durable_from": null,
            "durable_from_known": false,
        });
        // Keep the legacy anchor field, but bind it to the pinned observation.
        let snapshot_body: Value = json::parse_value(
            expose::range_body(&self.record, &[], from, cursor.snapshot_to).as_bytes(),
        )
        .map_err(|_| GovernanceError::Store)?;
        body["anchor"] = snapshot_body["anchor"].clone();
        let covered = self
            .audit_records()
            .first()
            .is_some_and(|r| r.seq <= cursor.next_audit);
        let exhausted = cursor.next_audit > cursor.snapshot_to;
        let scan_end = cursor
            .next_journal
            .saturating_add(SCAN_POSITIONS)
            .min(cursor.journal_end);
        let (records, stored) = if exhausted || covered {
            (
                self.audit_records()
                    .iter()
                    .filter(|r| r.seq >= cursor.next_audit && r.seq <= cursor.snapshot_to)
                    .cloned()
                    .collect(),
                None,
            )
        } else {
            (Vec::new(), Some(self.chain_at()))
        };
        Ok(AuditPagePlan {
            body,
            cursor,
            records,
            stored,
            scan_end,
            exhausted,
        })
    }
}

impl AuditPagePlan {
    pub async fn finish(mut self) -> Result<Vec<u8>, GovernanceError> {
        let journal_page = if let Some(stored) = self.stored.take() {
            let records = stored
                .read()
                .await
                .map_err(|_| GovernanceError::Store)?
                .map_err(|_| GovernanceError::Store)?;
            let records: Vec<_> = records
                .into_iter()
                .filter(|record| {
                    record.node_seq >= self.cursor.next_journal && record.node_seq < self.scan_end
                })
                .collect();
            let incomplete =
                records.len() as u64 != self.scan_end.saturating_sub(self.cursor.next_journal);
            Some((records, incomplete))
        } else {
            None
        };
        let scanned = if let Some((records, incomplete)) = journal_page {
            let scanned = self.scan_end.saturating_sub(self.cursor.next_journal);
            self.cursor.incomplete |= incomplete;
            for record in records {
                if let Some(audit) = decode_audit(&record).map_err(|_| GovernanceError::Store)? {
                    if audit.seq >= self.cursor.next_audit && audit.seq <= self.cursor.snapshot_to {
                        self.records.push(audit);
                    }
                }
            }
            self.cursor.next_journal = self.scan_end;
            self.exhausted |= self.scan_end >= self.cursor.journal_end;
            scanned
        } else {
            self.exhausted = true;
            0
        };
        // Audit positions are monotonic even though the journal also carries non-audit records.
        let mut gaps = Vec::new();
        for record in &self.records {
            if record.seq < self.cursor.next_audit {
                return Err(GovernanceError::Store);
            }
            if record.seq > self.cursor.next_audit {
                gaps.push(json!({"from": self.cursor.next_audit.to_string(), "to": (record.seq - 1).to_string()}));
            }
            self.cursor.next_audit = record.seq.checked_add(1).ok_or(GovernanceError::Store)?;
        }
        self.exhausted |= self.cursor.next_audit > self.cursor.snapshot_to;
        if self.exhausted && self.cursor.next_audit <= self.cursor.to {
            gaps.push(json!({"from": self.cursor.next_audit.to_string(), "to": self.cursor.to.to_string()}));
        }
        self.cursor.incomplete |= !gaps.is_empty();
        self.body["records"] = json::parse_value(
            expose::range_records_body(&self.records, self.cursor.from, self.cursor.to).as_bytes(),
        )
        .map_err(|_| GovernanceError::Store)?;
        self.body["returned_from"] = json!(self.records.first().map(|r| r.seq.to_string()));
        self.body["returned_to"] = json!(self.records.last().map(|r| r.seq.to_string()));
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
}
