// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The trust book as the plane sees it: SIGHT, TRUST_SERVES, TRUST_STATE, TGT_SIGHT, TRUST_VERIFY and the operator's
//! approve/revoke/release (IF §12.14). The frozen contract is the [`TrustBook`] trait; W1-K10's implementation is
//! [`CoreTrustBook`], the kernel judge (`trust::book`) over durable rows, with today's `trust.verify` body for
//! TRUST_VERIFY and [`approval_entry`] reading one `trust.<plane instance>.<upstream>` approval.

// W0-ABI: IF §12.14 names this trait `TrustBook` in module `trust`; `trust/book.rs` already holds the kernel's
// concrete `TrustBook` struct, so the trait lives in this new file (`crate::trust::plane_book::TrustBook`).

use std::sync::Arc;

use busbar_contract::json::{self, JsonContainerTrait as _, JsonValueTrait as _, Value};
use busbar_plugin_abi::host_side::caller::{BoxFut, CallStack, Caller, InstanceLimits};
use busbar_plugin_abi::plane::{
    DISTRUST_CHANGED, DISTRUST_NONE, DISTRUST_NOT_APPROVED, DISTRUST_QUARANTINED, DISTRUST_UNKNOWN,
    DISTRUST_UNKNOWN_ITEM, DISTRUST_UNSIGHTED, SIGNED_MALFORMED_ROOT, SIGNED_MALFORMED_SIGNATURE,
    SIGNED_VERIFIED,
};
use busbar_plugin_abi::types::KindCode;
use busbar_ports::plane::TrustItem;

use super::book::{self as kernel_book, Distrust, Effect, Reviewed, Ruling, RulingRow, TrustFacts};
use super::section::{DeclaredPin, TrustEntry};
use crate::plane_grants::core_name;
use crate::plugin_records::{PluginRecords, RecordsDenied, Scope};

/// Keyed by (plane plugin, plane instance name, configured upstream name): durable, replica-shared.
pub trait TrustBook: Send + Sync + 'static {
    /// SIGHT: record the observation (catalogue hash stamps the re-verification clock; each item digest is
    /// compared with the approval; drift quarantines the counterparty and is audited `trust_drift`).
    fn sight<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        party: &'a str,
        catalog: Option<[u8; 32]>,
        items: &'a [(&'a str, [u8; 32])],
    ) -> BoxFut<'a, Result<(), RecordsDenied>>;
    /// TRUST_SERVES: DISTRUST_NONE or the DISTRUST_* that refuses (digest None = the last sighting). Never pends.
    fn serves(
        &self,
        plane: &Caller<'_>,
        party: &str,
        item: Option<(&str, Option<[u8; 32]>)>,
    ) -> u32;
    /// TRUST_STATE: the counterparty verdict and per-item state, for the plane's admin views.
    fn state(
        &self,
        plane: &Caller<'_>,
        party: &str,
        sink: &mut dyn FnMut(TrustItem<'_>),
    ) -> (u32, Option<[u8; 32]>);
    /// Upstreams of this plane instance whose re-verification is due; K8 runs `probe(TGT_SIGHT)` for each
    /// (and on DX_RESIGHT), with RetrySite::PlaneProbe.
    fn due(&self, plane: &Caller<'_>, now_s: u64) -> Vec<Box<str>>;
    /// Round 7. TRUST_VERIFY: verify `signatures` (JSON array of `{protected, signature}`; empty = none) over
    /// `payload` with the authenticity root configured for (`plane.name`, `party`) in TRUST_APPROVAL. The root's
    /// key selects the algorithm (through `busbar-crypto`'s JWS verify, I12); a header naming another algorithm
    /// is SIGNED_ALGORITHM, an unknown `crit` member SIGNED_CRITICAL (both write the name into `named`, ≤ 128
    /// bytes). No root configured => SIGNED_MALFORMED_ROOT, audited `trust_root_missing`. Returns SIGNED_*
    /// (§8.6). Never pends, never allocates beyond `named`; audited `trust_verify` with the verdict. Today's
    /// kernel `trust.verify` body moves here unchanged.
    fn verify(
        &self,
        plane: &Caller<'_>,
        party: &str,
        payload: &[u8],
        signatures: &[u8],
        named: &mut String,
    ) -> u32;
    /// Operator actions (core admin API only, never ABI, never a plane verb; round 7): approve an item digest
    /// or the counterparty, revoke an approval, clear a quarantine.
    fn approve<'a>(
        &'a self,
        plane_name: &'a str,
        party: &'a str,
        item: &'a str,
        digest: [u8; 32],
    ) -> BoxFut<'a, Result<(), RecordsDenied>>;
    fn revoke<'a>(
        &'a self,
        plane_name: &'a str,
        party: &'a str,
        item: &'a str,
    ) -> BoxFut<'a, Result<(), RecordsDenied>>;
    fn release<'a>(
        &'a self,
        plane_name: &'a str,
        party: &'a str,
    ) -> BoxFut<'a, Result<(), RecordsDenied>>;
}

/// Audit action: a sighting moved from its approval (the counterparty's catalogue or one item); the detail names
/// the item, empty for the catalogue.
pub const AUDIT_TRUST_DRIFT: &str = "trust_drift";
/// Audit action: a TRUST_VERIFY verdict; the detail is the `SIGNED_*` number.
pub const AUDIT_TRUST_VERIFY: &str = "trust_verify";
/// Audit action: a TRUST_VERIFY with no authenticity root configured for the counterparty.
pub const AUDIT_TRUST_ROOT_MISSING: &str = "trust_root_missing";
/// `named` is at most this many bytes (IF §12.14).
pub const MAX_NAMED: usize = 128;
/// The approval digests' text form: `sha256:` and 64 lowercase hex digits (IF §12.10 TRUST_APPROVAL).
pub const DIGEST_PREFIX: &str = "sha256:";

/// Where the book's trust actions are audited. Core text only: names and verdict numbers, never a payload.
pub trait TrustAudit: Send + Sync + 'static {
    fn record(&self, action: &'static str, plane: &str, party: &str, detail: &str);
}

/// The default audit sink: one `busbar::audit` event per action.
pub struct TracingAudit;

impl TrustAudit for TracingAudit {
    fn record(&self, action: &'static str, plane: &str, party: &str, detail: &str) {
        tracing::info!(target: "busbar::audit", action, plane, party, detail, "trust");
    }
}

/// The core-only namespace the book keeps its durable rows in: a stamp name no plugin can hold (it starts with
/// NUL), and the plane instance name with core's `trust` tag. Rows: `R`-keyed operator decisions and drift
/// demotions of items ([`RulingRow`]), `D`-keyed counterparty quarantines (the epoch-ms they were recorded at).
const BOOK_PLUGIN: &str = "\0busbar";
const TAG: &str = "trust";
/// The most rows of one kind an admission reads back.
const MAX_ROWS: u32 = 4_096;

/// `sha256:<hex>` of a digest.
#[must_use]
pub fn digest_text(digest: &[u8; 32]) -> String {
    format!("{DIGEST_PREFIX}{}", hex::encode(digest))
}

/// The digest of a `sha256:<hex>` text, `None` for any other text.
#[must_use]
pub fn digest_of(text: &str) -> Option<[u8; 32]> {
    let hex_part = text.strip_prefix(DIGEST_PREFIX)?;
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_part, &mut out).ok()?;
    Some(out)
}

fn distrust_code(why: Distrust) -> u32 {
    match why {
        Distrust::Unknown => DISTRUST_UNKNOWN,
        Distrust::Unsighted => DISTRUST_UNSIGHTED,
        Distrust::Quarantined => DISTRUST_QUARANTINED,
        Distrust::NotApproved => DISTRUST_NOT_APPROVED,
        Distrust::Changed => DISTRUST_CHANGED,
        Distrust::UnknownItem => DISTRUST_UNKNOWN_ITEM,
    }
}

fn decision_key(party: &str, item: Option<&str>) -> Vec<u8> {
    let mut key = Vec::with_capacity(4 + party.len() + item.map_or(0, str::len));
    key.push(b'R');
    key.extend_from_slice(&u16::try_from(party.len()).unwrap_or(u16::MAX).to_be_bytes());
    key.extend_from_slice(party.as_bytes());
    if let Some(item) = item {
        key.extend_from_slice(item.as_bytes());
    }
    key
}

fn demotion_key(party: &str) -> Vec<u8> {
    [b"D".as_slice(), party.as_bytes()].concat()
}

/// One `trust.<plane instance>.<upstream>` value (IF §12.10 CORE_CFG(TRUST_APPROVAL), §12.14): `root` =
/// `{mechanism, key}` (the authenticity root `verify` checks signatures with, e.g. plane-a2a's `jws_issuer_key`),
/// `fingerprint` = the catalogue hash the operator approved, `items` = item name → its approved `sha256:` digest.
/// Every key is optional; any other key, or a digest in another form, is refused with core's text.
pub fn approval_entry(at: &str, value: &Value) -> Result<TrustEntry, String> {
    let map = value
        .as_object()
        .ok_or_else(|| format!("`{at}` must be a mapping"))?;
    for (key, _) in map {
        if !matches!(key, "root" | "fingerprint" | "items") {
            return Err(format!(
                "`{at}.{key}` is not a trust approval key; the keys are root, fingerprint, items"
            ));
        }
    }
    let text = |v: Option<&Value>, name: &str| -> Result<Option<String>, String> {
        match v {
            None => Ok(None),
            Some(v) if v.is_null() => Ok(None),
            Some(v) => match v.as_str() {
                Some(s) if s.trim().is_empty() => Ok(None),
                Some(s) => Ok(Some(s.to_owned())),
                None => Err(format!("`{at}.{name}` must be text")),
            },
        }
    };
    let fingerprint = text(map.get(&"fingerprint"), "fingerprint")?;
    let pin = match map.get(&"root") {
        None => fingerprint.clone().map(fingerprint_pin),
        Some(v) if v.is_null() => fingerprint.clone().map(fingerprint_pin),
        Some(v) => {
            let root = v
                .as_object()
                .ok_or_else(|| format!("`{at}.root` must be a mapping"))?;
            let mechanism = text(root.get(&"mechanism"), "root.mechanism")?
                .ok_or_else(|| format!("`{at}.root.mechanism` is required"))?;
            let key = text(root.get(&"key"), "root.key")?
                .ok_or_else(|| format!("`{at}.root.key` is required"))?;
            // The one decoder TRUST_VERIFY uses, run where the approval loads (DES-QE-PLANE-ROOT r2).
            super::signed::root_key(&key).map_err(|_| {
                format!(
                    "`{at}.root.key` is not an Ed25519 public key (RFC 8410 SubjectPublicKeyInfo, \
                     standard base64), which `root.mechanism: {mechanism}` verifies signatures with"
                )
            })?;
            Some(DeclaredPin {
                mechanism,
                root: true,
                peer_key: false,
                key: Some(key),
                fingerprint: fingerprint.clone(),
            })
        }
    };
    let mut approved = std::collections::BTreeMap::new();
    match map.get(&"items") {
        None => {}
        Some(v) if v.is_null() => {}
        Some(v) => {
            let items = v
                .as_object()
                .ok_or_else(|| format!("`{at}.items` must be a mapping"))?;
            for (item, digest) in items {
                let digest = text(Some(digest), &format!("items.{item}"))?;
                let Some(digest) = digest else {
                    continue;
                };
                if digest_of(&digest).is_none() {
                    return Err(format!(
                        "`{at}.items.{item}` must be `sha256:` and 64 hex digits"
                    ));
                }
                approved.insert(item.to_owned(), digest.to_ascii_lowercase());
            }
        }
    }
    Ok(TrustEntry {
        pin,
        policy: super::reverify::Policy {
            ttl_ms: 0,
            recovery_backoff_ms: 0,
        },
        approved,
    })
}

/// The pin of an approval that names only a catalogue fingerprint.
fn fingerprint_pin(fingerprint: String) -> DeclaredPin {
    DeclaredPin {
        mechanism: "fingerprint".to_owned(),
        root: false,
        peer_key: false,
        key: None,
        fingerprint: Some(fingerprint),
    }
}

/// The trust book planes run on (IF §12.14): the kernel's judge ([`kernel_book::TrustBook`], shared, so the core
/// admin trust API lists and decides the same keys) over durable rows in `R`, keyed by the plane instance name
/// and the configured upstream name, so every replica and every restart reads the same decisions.
pub struct CoreTrustBook<R> {
    book: Arc<kernel_book::TrustBook>,
    records: R,
    audit: Arc<dyn TrustAudit>,
    clock_ms: fn() -> u64,
}

impl<R: PluginRecords> CoreTrustBook<R> {
    /// A book over the kernel judge `book`, keeping its rows in `records`, auditing to `audit`, timed by
    /// `clock_ms` (UNIX milliseconds).
    pub fn new(
        book: Arc<kernel_book::TrustBook>,
        records: R,
        audit: Arc<dyn TrustAudit>,
        clock_ms: fn() -> u64,
    ) -> Self {
        Self {
            book,
            records,
            audit,
            clock_ms,
        }
    }

    /// The kernel judge this book runs on.
    #[must_use]
    pub fn judge(&self) -> &Arc<kernel_book::TrustBook> {
        &self.book
    }

    fn rows_ns<'a>(name: &'a str) -> Caller<'a> {
        Caller {
            plugin: BOOK_PLUGIN,
            kind: KindCode::Plane,
            name,
            instance: 0,
            slot: 0,
            chain: 0,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(30),
            stack: CallStack::default(),
            out_of_process: false,
            limits: InstanceLimits::default(),
        }
    }

    /// Admits plane instance `plane_name` with its approvals (one per configured upstream, from
    /// [`approval_entry`]), replaying the decisions and quarantines its durable rows hold. A reload admits again;
    /// a counterparty whose declaration did not change keeps its state.
    pub async fn admit(
        &self,
        plane_name: &str,
        entries: Vec<(String, TrustEntry)>,
    ) -> Result<(), RecordsDenied> {
        let name = core_name(plane_name, TAG);
        let ns = Self::rows_ns(&name);
        let mut decided: Vec<RulingRow> = Vec::new();
        self.records
            .list(&ns, Scope::default(), b"R", MAX_ROWS, &mut |_, value| {
                if let Ok(row) = json::parse::<RulingRow>(value) {
                    decided.push(row);
                }
            })
            .await?;
        let mut demoted: Vec<(String, u64)> = Vec::new();
        self.records
            .list(&ns, Scope::default(), b"D", MAX_ROWS, &mut |key, value| {
                let party = key.get(1..).and_then(|p| std::str::from_utf8(p).ok());
                let at = value.try_into().ok().map(u64::from_be_bytes);
                if let (Some(party), Some(at)) = (party, at) {
                    demoted.push((party.to_owned(), at));
                }
            })
            .await?;
        self.book.admit_with_decisions(
            &Arc::from(plane_name),
            entries,
            demoted.iter().map(|(party, at)| (party.as_str(), *at)),
            &decided,
        );
        Ok(())
    }

    async fn keep_decision(&self, row: &RulingRow) -> Result<(), RecordsDenied> {
        let value = json::to_vec(row).map_err(|_| RecordsDenied::Invalid)?;
        let name = core_name(&row.instance, TAG);
        let ns = Self::rows_ns(&name);
        self.records
            .put(
                &ns,
                Scope::default(),
                &decision_key(&row.counterparty, row.item.as_deref()),
                &value,
                0,
            )
            .await
    }

    async fn keep_quarantine(
        &self,
        plane_name: &str,
        party: &str,
        at_ms: Option<u64>,
    ) -> Result<(), RecordsDenied> {
        let name = core_name(plane_name, TAG);
        let ns = Self::rows_ns(&name);
        let key = demotion_key(party);
        match at_ms {
            Some(at) => {
                self.records
                    .put(&ns, Scope::default(), &key, &at.to_be_bytes(), 0)
                    .await
            }
            None => self.records.del(&ns, Scope::default(), &key).await,
        }
    }

    /// One operator decision: rule it under the book's permit, keep it durably, then apply it.
    async fn decide(
        &self,
        plane_name: &str,
        party: &str,
        item: Option<&str>,
        ruling: Ruling,
        reviewed: Option<Reviewed<'_>>,
    ) -> Result<(), RecordsDenied> {
        let permit = self
            .book
            .begin_decision(plane_name, party, item)
            .map_err(|_| RecordsDenied::Invalid)?;
        let fact = self
            .book
            .rule(plane_name, party, item, ruling, reviewed)
            .map_err(|_| RecordsDenied::Invalid)?;
        self.keep_decision(&fact).await?;
        permit.apply(&fact).map_err(|_| RecordsDenied::Invalid)?;
        Ok(())
    }

    fn judged(
        &self,
        plane_name: &str,
        party: &str,
        item: Option<&str>,
        digest: Option<&str>,
    ) -> u32 {
        let facts = TrustFacts {
            counterparty: party,
            item,
            digest,
        };
        match self.book.judge(plane_name, &facts) {
            Ok(()) => DISTRUST_NONE,
            Err(why) => distrust_code(why),
        }
    }
}

impl<R: PluginRecords> TrustBook for CoreTrustBook<R> {
    fn sight<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        party: &'a str,
        catalog: Option<[u8; 32]>,
        items: &'a [(&'a str, [u8; 32])],
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(async move {
            let label = plane.name;
            if let Some(catalog) = catalog {
                let _permit = self
                    .book
                    .begin_sighting(label, party, None)
                    .map_err(|_| RecordsDenied::Invalid)?;
                let (_, effect) = self
                    .book
                    .sight(label, party, &digest_text(&catalog), (self.clock_ms)())
                    .map_err(|_| RecordsDenied::Invalid)?;
                match effect {
                    Effect::Demote => {
                        self.audit.record(AUDIT_TRUST_DRIFT, label, party, "");
                        self.keep_quarantine(label, party, Some((self.clock_ms)()))
                            .await?;
                    }
                    Effect::Clear => self.keep_quarantine(label, party, None).await?,
                    Effect::None => {}
                }
            }
            for (item, digest) in items {
                let mut permit = self
                    .book
                    .begin_sighting(label, party, Some(*item))
                    .map_err(|_| RecordsDenied::Invalid)?;
                let (_, demotion) = self
                    .book
                    .sight_item_kept(label, party, item, &digest_text(digest))
                    .map_err(|_| RecordsDenied::Invalid)?;
                if let Some(fact) = demotion {
                    permit.demoted();
                    self.audit.record(AUDIT_TRUST_DRIFT, label, party, item);
                    self.keep_decision(&fact).await?;
                }
            }
            Ok(())
        })
    }

    fn serves(
        &self,
        plane: &Caller<'_>,
        party: &str,
        item: Option<(&str, Option<[u8; 32]>)>,
    ) -> u32 {
        let digest = item.and_then(|(_, d)| d).map(|d| digest_text(&d));
        self.judged(
            plane.name,
            party,
            item.map(|(name, _)| name),
            digest.as_deref(),
        )
    }

    fn state(
        &self,
        plane: &Caller<'_>,
        party: &str,
        sink: &mut dyn FnMut(TrustItem<'_>),
    ) -> (u32, Option<[u8; 32]>) {
        let verdict = self.judged(plane.name, party, None, None);
        if verdict == DISTRUST_UNKNOWN {
            return (verdict, None);
        }
        // One snapshot of the rows: the catalogue digest and every item state come from the same read.
        let mut catalog = None;
        for row in self.book.rows() {
            if row.instance != plane.name || row.counterparty != party {
                continue;
            }
            let Some(item) = row.item.as_deref() else {
                catalog = row.seen.as_deref().and_then(digest_of);
                continue;
            };
            sink(TrustItem {
                name: item,
                verdict: self.judged(plane.name, party, Some(item), None),
                approved: row.approved.as_deref().and_then(digest_of),
                sighted: row.seen.as_deref().and_then(digest_of),
            });
        }
        (verdict, catalog)
    }

    fn due(&self, plane: &Caller<'_>, now_s: u64) -> Vec<Box<str>> {
        self.book
            .due_at(plane.name, now_s.saturating_mul(1_000))
            .unwrap_or_default()
            .into_iter()
            .map(String::into_boxed_str)
            .collect()
    }

    fn verify(
        &self,
        plane: &Caller<'_>,
        party: &str,
        payload: &[u8],
        signatures: &[u8],
        named: &mut String,
    ) -> u32 {
        let verdict = match self.book.root_key(plane.name, party) {
            Ok(Some(key)) => verified(&key, payload, signatures, named),
            Ok(None) | Err(_) => {
                self.audit
                    .record(AUDIT_TRUST_ROOT_MISSING, plane.name, party, "");
                SIGNED_MALFORMED_ROOT
            }
        };
        self.audit
            .record(AUDIT_TRUST_VERIFY, plane.name, party, &verdict.to_string());
        verdict
    }

    fn approve<'a>(
        &'a self,
        plane_name: &'a str,
        party: &'a str,
        item: &'a str,
        digest: [u8; 32],
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(async move {
            let item = (!item.is_empty()).then_some(item);
            let reviewed = digest_text(&digest);
            self.decide(
                plane_name,
                party,
                item,
                Ruling::Approve,
                Some(Reviewed::Seen(&reviewed)),
            )
            .await?;
            if item.is_none() {
                self.keep_quarantine(plane_name, party, None).await?;
            }
            Ok(())
        })
    }

    fn revoke<'a>(
        &'a self,
        plane_name: &'a str,
        party: &'a str,
        item: &'a str,
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(async move {
            let item = (!item.is_empty()).then_some(item);
            self.decide(plane_name, party, item, Ruling::Revoke, None)
                .await
        })
    }

    fn release<'a>(
        &'a self,
        plane_name: &'a str,
        party: &'a str,
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(async move {
            self.decide(plane_name, party, None, Ruling::Approve, None)
                .await?;
            self.keep_quarantine(plane_name, party, None).await
        })
    }
}

/// Today's `trust.verify` body (host_services `trust_verify`), as a TRUST_VERIFY verdict: `signatures` (empty =
/// none) over `payload` under the root `key`. A signatures document that is not JSON is
/// SIGNED_MALFORMED_SIGNATURE (today's service refused it outright; an intent answers a verdict).
fn verified(key: &str, payload: &[u8], signatures: &[u8], named: &mut String) -> u32 {
    let sigs = match signatures {
        [] => Value::new(),
        doc => match json::parse_value(doc) {
            Ok(v) => v,
            Err(_) => return SIGNED_MALFORMED_SIGNATURE,
        },
    };
    match super::signed::root_key(key).and_then(|root| super::signed::verify(payload, &sigs, &root))
    {
        Ok(()) => SIGNED_VERIFIED,
        Err((verdict, name)) => {
            let mut end = name.len().min(MAX_NAMED);
            while !name.is_char_boundary(end) {
                end -= 1;
            }
            named.push_str(&name[..end]);
            u32::try_from(verdict).unwrap_or(SIGNED_MALFORMED_SIGNATURE)
        }
    }
}

#[cfg(test)]
#[path = "tests/plane_book_tests.rs"]
mod plane_book_tests;
