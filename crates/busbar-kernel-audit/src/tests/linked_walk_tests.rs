// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The linked-window rules over an in-memory source: a tampered stamp, a certificate the trusted
//! key did not sign, an unsealed end and a broken link.

use super::*;
use crate::{
    AuditSigningKey, BreakReason, LiveSigner, Notary, NotaryKeyCertificate, NotaryKeyRecord,
};
use busbar_contract::crypto::{LocalSigner, Signer};

const NODE: u64 = 21;

/// One walked line: a unit line whose digest is recomputed from its fields, or a certificate line.
#[derive(Clone, Debug, PartialEq)]
struct Line {
    seq: u64,
    prev: String,
    hash: String,
    payload: u64,
    cert: Option<(u64, NotaryKeyRecord)>,
}

impl Line {
    fn recompute(&self) -> String {
        let preimage = format!("{}|{}|{}", self.prev, self.seq, self.payload);
        hex::encode(busbar_contract::abi::sdk::digest::sha256(
            preimage.as_bytes(),
        ))
    }
}

impl WalkedLine for Line {
    fn seq(&self) -> Read<u64> {
        Ok(self.seq)
    }
    fn node(&self) -> Read<u64> {
        Ok(NODE)
    }
    fn prev_hash(&self) -> Read<&str> {
        Ok(&self.prev)
    }
    fn hash(&self) -> Read<&str> {
        Ok(&self.hash)
    }
    fn recipe(&self) -> Read<&str> {
        Ok(if self.cert.is_some() {
            NOTARY_KEY_RECORD_DOMAIN
        } else {
            LINK_RECIPE
        })
    }
    fn certificate(&self) -> Read<(u64, NotaryKeyRecord)> {
        self.cert.clone().ok_or("not a certificate line")
    }
    fn digest(&self) -> Read<String> {
        Ok(self.recompute())
    }
    fn signature(&self) -> Read<&str> {
        Err("a link line carries no signature")
    }
    fn key_id(&self) -> Read<&str> {
        Err("a link line carries no key")
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Ev {
    Page(Option<u64>, Stamp),
    Break(BreakNotice),
}

impl Evidence for Ev {
    fn is_break(&self) -> Read<bool> {
        Ok(matches!(self, Ev::Break(_)))
    }
    fn notice(&self) -> Read<BreakNotice> {
        match self {
            Ev::Break(notice) => Ok(notice.clone()),
            Ev::Page(..) => Err("not a break"),
        }
    }
    fn node_seq(&self) -> Read<Option<u64>> {
        match self {
            Ev::Page(at, _) => Ok(*at),
            Ev::Break(_) => Ok(None),
        }
    }
    fn stamp(&self) -> Read<Stamp> {
        match self {
            Ev::Page(_, stamp) => Ok(stamp.clone()),
            Ev::Break(_) => Err("not a stamp"),
        }
    }
}

struct Window {
    from: u64,
    to: u64,
    records: Vec<Line>,
    cover: Vec<Line>,
    certs: Option<Vec<Line>>,
    stamps: Vec<Ev>,
}

impl LinkedRange for Window {
    type Line = Line;
    type Evidence = Ev;
    fn from(&self) -> Read<u64> {
        Ok(self.from)
    }
    fn to(&self) -> Read<u64> {
        Ok(self.to)
    }
    fn records(&self) -> Read<Vec<Line>> {
        Ok(self.records.clone())
    }
    fn cover(&self) -> Read<Vec<Line>> {
        Ok(self.cover.clone())
    }
    fn certs(&self) -> Read<Option<Vec<Line>>> {
        Ok(self.certs.clone())
    }
    fn stamps(&self) -> Read<Vec<Ev>> {
        Ok(self.stamps.clone())
    }
    fn seal_row(&self) -> Read<Option<SealRow>> {
        Ok(None)
    }
    fn anchor(&self) -> Read<Option<Ev>> {
        Ok(None)
    }
}

struct Head(Stamp);

impl TrustedHead for Head {
    fn recipe(&self) -> Read<&str> {
        Ok(LINK_RECIPE)
    }
    fn head(&self) -> Read<Stamp> {
        Ok(self.0.clone())
    }
    fn next_seq(&self) -> Read<u64> {
        Ok(self.0.to + 1)
    }
}

/// The deployment Bootstrap key.
fn signer() -> AuditSigningKey {
    AuditSigningKey::from_seed(&[42; 32])
}

fn keys() -> BTreeMap<String, AuditVerifyingKey> {
    let key = AuditVerifyingKey::from_hex(&signer().public_key_hex()).unwrap();
    BTreeMap::from([(key.key_id().to_owned(), key)])
}

/// Unit lines `from .. from + count` linked after `prev`.
fn units_after(prev: &str, from: u64, count: u64) -> Vec<Line> {
    let mut previous = prev.to_owned();
    (from..from + count)
        .map(|seq| {
            let mut line = Line {
                seq,
                prev: previous.clone(),
                hash: String::new(),
                payload: seq * 7,
                cert: None,
            };
            line.hash = line.recompute();
            previous = line.hash.clone();
            line
        })
        .collect()
}

fn unsigned_page(lines: &[Line], from: u64, to: u64) -> Stamp {
    let endpoint = lines.iter().find(|line| line.seq == to).unwrap();
    Stamp {
        node: NODE,
        from,
        to,
        fingerprint: Fingerprint::from_hex(&endpoint.hash).unwrap(),
        kind: StampKind::Live,
        sealer: NODE,
        host: "host-a".into(),
        every: 1,
        stamped_ms: 1_700_000_000_001,
        down_from_ms: 0,
        down_to_ms: 0,
        crypto: String::new(),
        sig_alg: String::new(),
        key_id: String::new(),
        key_cert: 0,
        signature: Vec::new(),
    }
}

/// A live page over `from ..= to` signed under the Bootstrap key.
fn page(lines: &[Line], from: u64, to: u64) -> Stamp {
    let (notary, _) = signer().into_grants(LiveSigner::SameAsBootstrap).unwrap();
    Notary::new(notary)
        .sign_stamp(unsigned_page(lines, from, to))
        .unwrap()
}

/// Lines 1..=3 from genesis, the whole window requested.
fn genesis_window(stamps: Vec<Ev>) -> Window {
    Window {
        from: 1,
        to: 3,
        records: units_after("", 1, 3),
        cover: Vec::new(),
        certs: None,
        stamps,
    }
}

#[test]
fn a_covering_stamp_authenticates_the_window_and_a_tampered_one_is_refused() {
    let lines = units_after("", 1, 3);
    let good = page(&lines, 1, 3);
    let verdict = verify::<_, Head>(
        &keys(),
        &genesis_window(vec![Ev::Page(Some(4), good.clone())]),
        None,
    )
    .unwrap();
    assert_eq!(verdict.standing, Some(Standing::SignedConsistentWindow));
    assert_eq!(verdict.authenticated_records, 3);
    assert!(verdict.all_requested_records_authenticated);
    assert_eq!(verdict.unauthenticated_tail, None);
    assert_eq!(verdict.live_pages, 1);
    assert_eq!(verdict.last_sealed, 3);

    let mut tampered = good;
    tampered.host = "rewritten".into();
    assert_eq!(
        verify::<_, Head>(
            &keys(),
            &genesis_window(vec![Ev::Page(Some(4), tampered)]),
            None
        ),
        Err("a stamp signature is invalid")
    );
}

/// The per-boot notary key a certificate delegates to.
fn delegate() -> LocalSigner {
    LocalSigner::from_seed(&[9; 32]).unwrap()
}

/// A certificate line of node 21 at chain seq 1 (WAL 1, genesis), certifying [`delegate`], signed
/// by `by`.
fn certificate(by: &LocalSigner) -> Line {
    let delegate = delegate();
    let public = delegate.public_key();
    let mut certificate = NotaryKeyCertificate {
        key_id: public.key_id.to_string(),
        sig_alg: public.alg.as_str().to_owned(),
        public_key: public.bytes.to_vec(),
        signed_by: by.public_key().key_id.to_string(),
        signature: Vec::new(),
    };
    by.sign(
        &certificate.preimage(NODE, 1, Fingerprint::ZERO),
        &mut certificate.signature,
    )
    .unwrap();
    let mut record = NotaryKeyRecord {
        node: NODE,
        seq: 1,
        linked_ms: 1_700_000_000_000,
        prev_link: Fingerprint::ZERO,
        fingerprint: Fingerprint::ZERO,
        certificate,
    };
    record.fingerprint = record.recompute_fingerprint();
    Line {
        seq: 1,
        prev: String::new(),
        hash: record.fingerprint.to_string(),
        payload: 0,
        cert: Some((1, record)),
    }
}

/// The certificate line at seq 1 (supplied with the certificates), unit lines 2..=4; [2, 3]
/// requested with 4 as cover; one live page over 1..=4 under the delegated key naming the
/// certificate (read at WAL 5).
fn certified(by: &LocalSigner) -> Window {
    let cert = certificate(by);
    let units = units_after(&cert.hash, 2, 3);
    let mut lines = vec![cert.clone()];
    lines.extend(units.iter().cloned());
    let mut stamp = unsigned_page(&lines, 1, 4);
    stamp.key_cert = 1;
    let (notary, _) = signer()
        .into_grants(LiveSigner::Delegated(Box::new(delegate())))
        .unwrap();
    let stamp = Notary::new(notary).sign_stamp(stamp).unwrap();
    Window {
        from: 2,
        to: 3,
        records: units[..2].to_vec(),
        cover: units[2..].to_vec(),
        certs: Some(vec![cert]),
        stamps: vec![Ev::Page(Some(5), stamp)],
    }
}

#[test]
fn a_page_under_a_key_the_trusted_bootstrap_did_not_certify_is_refused() {
    let bootstrap = LocalSigner::from_seed(&[42; 32]).unwrap();
    let verdict = verify::<_, Head>(&keys(), &certified(&bootstrap), None).unwrap();
    assert_eq!(verdict.certified_pages, 1);
    assert_eq!(verdict.authenticated_records, 2);
    assert!(verdict.all_requested_records_authenticated);

    // The same certificate signed by a key the caller does not trust certifies nothing.
    let other = LocalSigner::from_seed(&[7; 32]).unwrap();
    let forged = certified(&other);
    assert_eq!(
        verify::<_, Head>(&keys(), &forged, None),
        Err("stamp key not certified")
    );
}

#[test]
fn an_unsealed_end_is_reported_and_never_complete_through_a_trusted_head() {
    let lines = units_after("", 1, 3);
    let window = genesis_window(vec![Ev::Page(Some(4), page(&lines, 1, 2))]);
    let verdict = verify::<_, Head>(&keys(), &window, None).unwrap();
    assert_eq!(verdict.unauthenticated_tail, Some(3));
    assert_eq!(verdict.last_sealed, 2);
    assert!(!verdict.all_requested_records_authenticated);
    assert_eq!(verdict.authenticated_records, 2);
    assert_eq!(verdict.standing, Some(Standing::SignedConsistentWindow));

    // A head over the whole window that is not among the checked stamps proves nothing.
    let head = Head(page(&lines, 1, 3));
    assert_eq!(
        verify(&keys(), &window, Some(&head)),
        Err("trusted head has incomplete coverage or is not a checked covering stamp")
    );
}

#[test]
fn a_broken_link_is_refused_even_when_each_line_hashes() {
    let lines = units_after("", 1, 3);
    let stamp = page(&lines, 1, 3);
    let mut window = genesis_window(vec![Ev::Page(Some(4), stamp)]);
    window.records[2].prev = "ab".repeat(32);
    window.records[2].hash = window.records[2].recompute();
    assert_eq!(
        verify::<_, Head>(&keys(), &window, None),
        Err("a record does not link to its predecessor")
    );
}

#[test]
fn a_signed_break_explains_a_gap_and_is_reported() {
    let lines = units_after("", 1, 3);
    let (_, grant) = signer().into_grants(LiveSigner::SameAsBootstrap).unwrap();
    let notice = crate::BootstrapSigner::new(grant)
        .sign_break(BreakNotice {
            node: NODE,
            sealer: 22,
            last_good: 1,
            unsealed_from: 2,
            unsealed_to: 2,
            journal_from: 5,
            journal_to: 6,
            reason: BreakReason::Unsigned,
            detected_ms: 1_700_000_000_001,
            host: "host-b".into(),
            crypto: String::new(),
            sig_alg: String::new(),
            key_id: String::new(),
            signature: Vec::new(),
        })
        .unwrap();
    let window = genesis_window(vec![
        Ev::Page(Some(4), page(&lines, 1, 1)),
        Ev::Break(notice.clone()),
        Ev::Page(Some(6), page(&lines, 3, 3)),
    ]);
    let verdict = verify::<_, Head>(&keys(), &window, None).unwrap();
    assert_eq!(verdict.breaks, vec![notice]);
    assert_eq!(verdict.authenticated_records, 2);
    assert!(!verdict.all_requested_records_authenticated);
}
